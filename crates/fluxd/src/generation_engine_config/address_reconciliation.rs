use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::{Mutex, RwLock};

use flux_core::{
    AddressBypassRuleBudget, AddressHostSetPlan, AddressHostSetPlanError, AddressHostSetPolicy,
    CaptureApplicationMode, CaptureApplicationPolicy, CaptureProgramDigest, ConfigError,
    FluxConfig, MAX_ADDRESS_BYPASS_RULES, NetworkEpoch, NetworkInventory,
    NetworkInventorySnapshotId, plan_address_host_set,
};
use flux_platform::{
    NetworkInventoryRefreshDisposition, NetworkInventoryRefreshHandle, NetworkInventorySource,
    PlatformError,
};

#[cfg(test)]
use super::DesiredStateCompileErrorKind;
use super::{
    DesiredStateCaptureArtifacts, DesiredStateCompileError, DesiredStateCompileRequest,
    compile_desired_state_capture,
};

trait CompleteNetworkInventorySource: Send + 'static {
    fn snapshot(&self) -> Option<Arc<NetworkInventory>>;
    fn request_refresh(&self) -> Result<NetworkInventoryRefreshDisposition, PlatformError>;
}

impl CompleteNetworkInventorySource for (NetworkInventorySource, NetworkInventoryRefreshHandle) {
    fn snapshot(&self) -> Option<Arc<NetworkInventory>> {
        self.0.snapshot()
    }

    fn request_refresh(&self) -> Result<NetworkInventoryRefreshDisposition, PlatformError> {
        self.1.request_refresh()
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct ReplayNetworkInventorySource {
    current: Arc<RwLock<Option<Arc<NetworkInventory>>>>,
    refresh_requests: Arc<AtomicUsize>,
    refresh_disposition: Arc<Mutex<Option<NetworkInventoryRefreshDisposition>>>,
}

#[cfg(test)]
impl ReplayNetworkInventorySource {
    pub(crate) fn publish(&self, inventory: Option<Arc<NetworkInventory>>) {
        *self.current.write().expect("replay source write lock") = inventory;
    }

    pub(crate) fn refresh_requests(&self) -> usize {
        self.refresh_requests.load(Ordering::Relaxed)
    }

    pub(crate) fn set_refresh_disposition(&self, disposition: NetworkInventoryRefreshDisposition) {
        *self
            .refresh_disposition
            .lock()
            .expect("replay refresh disposition lock") = Some(disposition);
    }
}

#[cfg(test)]
impl CompleteNetworkInventorySource for ReplayNetworkInventorySource {
    fn snapshot(&self) -> Option<Arc<NetworkInventory>> {
        self.current
            .read()
            .expect("replay source read lock")
            .clone()
    }

    fn request_refresh(&self) -> Result<NetworkInventoryRefreshDisposition, PlatformError> {
        self.refresh_requests.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .refresh_disposition
            .lock()
            .expect("replay refresh disposition lock")
            .unwrap_or(NetworkInventoryRefreshDisposition::Requested))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AddressReconciliationInspection {
    snapshot_id: NetworkInventorySnapshotId,
    epoch: NetworkEpoch,
    host_count: usize,
    capture_digest: CaptureProgramDigest,
}

impl AddressReconciliationInspection {
    #[must_use]
    pub(crate) const fn snapshot_id(self) -> NetworkInventorySnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub(crate) const fn epoch(self) -> NetworkEpoch {
        self.epoch
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn host_count(self) -> usize {
        self.host_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressReconciliationOutcome {
    AwaitingCompleteSnapshot,
    Invalidated(AddressReconciliationInspection),
    Unchanged(AddressReconciliationInspection),
    Blocked {
        snapshot_id: NetworkInventorySnapshotId,
        epoch: NetworkEpoch,
    },
    Reconciled(AddressReconciliationInspection),
}

/// Generation-ready address inputs with no activation or mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AddressReconciledGenerationInputs {
    inventory: Arc<NetworkInventory>,
    host_bypass: AddressHostSetPlan,
    capture: DesiredStateCaptureArtifacts,
}

impl AddressReconciledGenerationInputs {
    #[must_use]
    pub(crate) fn inventory(&self) -> &NetworkInventory {
        &self.inventory
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn host_bypass(&self) -> &AddressHostSetPlan {
        &self.host_bypass
    }

    #[must_use]
    pub(crate) const fn desired_state(&self) -> &FluxConfig {
        self.capture.desired_state()
    }

    #[must_use]
    pub(crate) const fn capture(&self) -> &DesiredStateCaptureArtifacts {
        &self.capture
    }

    #[must_use]
    pub(crate) fn inspection(&self) -> AddressReconciliationInspection {
        AddressReconciliationInspection {
            snapshot_id: self.inventory.snapshot_id(),
            epoch: self.inventory.epoch(),
            host_count: self.host_bypass.hosts().len(),
            capture_digest: self.capture.capture().program().digest(),
        }
    }

    #[allow(
        dead_code,
        reason = "A3 prepares exact inputs for later A2 assembly without production mutation"
    )]
    pub(crate) fn into_parts(
        self,
    ) -> (
        Arc<NetworkInventory>,
        AddressHostSetPlan,
        DesiredStateCaptureArtifacts,
    ) {
        (self.inventory, self.host_bypass, self.capture)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressReconciliationErrorKind {
    DesiredState,
    UnresolvedApplicationPackages {
        mode: CaptureApplicationMode,
        count: usize,
    },
    HostPlan,
    Compile(DesiredStateCompileErrorKind),
}

#[derive(Debug)]
pub(crate) enum AddressReconciliationError {
    DesiredState {
        path: PathBuf,
        source: ConfigError,
    },
    UnresolvedApplicationPackages {
        mode: CaptureApplicationMode,
        count: usize,
    },
    HostPlan(AddressHostSetPlanError),
    Compile(DesiredStateCompileError),
}

impl AddressReconciliationError {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn kind(&self) -> AddressReconciliationErrorKind {
        match self {
            Self::DesiredState { .. } => AddressReconciliationErrorKind::DesiredState,
            Self::UnresolvedApplicationPackages { mode, count } => {
                AddressReconciliationErrorKind::UnresolvedApplicationPackages {
                    mode: *mode,
                    count: *count,
                }
            }
            Self::HostPlan(_) => AddressReconciliationErrorKind::HostPlan,
            Self::Compile(source) => AddressReconciliationErrorKind::Compile(source.kind()),
        }
    }
}

impl fmt::Display for AddressReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DesiredState { path, source } => write!(
                formatter,
                "cannot load address-reconciliation Desired State {}: {source}",
                path.display()
            ),
            Self::UnresolvedApplicationPackages { mode, count } => write!(
                formatter,
                "cannot compile address reconciliation for {mode:?} policy with {count} unresolved packages"
            ),
            Self::HostPlan(source) => source.fmt(formatter),
            Self::Compile(source) => source.fmt(formatter),
        }
    }
}

impl Error for AddressReconciliationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DesiredState { source, .. } => Some(source),
            Self::HostPlan(source) => Some(source),
            Self::Compile(source) => Some(source),
            Self::UnresolvedApplicationPackages { .. } => None,
        }
    }
}

pub(crate) struct AddressReconciler {
    source: Box<dyn CompleteNetworkInventorySource>,
    desired_state_path: PathBuf,
    current: Option<AddressReconciledGenerationInputs>,
    last_attempted: Option<(NetworkInventorySnapshotId, NetworkEpoch)>,
    last_reconciled: Option<(NetworkInventorySnapshotId, NetworkEpoch)>,
    freshness_barrier: Option<(NetworkInventorySnapshotId, NetworkEpoch)>,
    reconciliation_requested: bool,
}

impl AddressReconciler {
    #[must_use]
    pub(crate) fn for_network_inventory(
        desired_state_path: impl AsRef<Path>,
        source: NetworkInventorySource,
        refresh: NetworkInventoryRefreshHandle,
    ) -> Self {
        Self::new(desired_state_path, Box::new((source, refresh)))
    }

    #[cfg(test)]
    pub(crate) fn replay(
        desired_state_path: impl AsRef<Path>,
    ) -> (ReplayNetworkInventorySource, Self) {
        let source = ReplayNetworkInventorySource::default();
        let reconciler = Self::new(desired_state_path, Box::new(source.clone()));
        (source, reconciler)
    }

    fn new(
        desired_state_path: impl AsRef<Path>,
        source: Box<dyn CompleteNetworkInventorySource>,
    ) -> Self {
        Self {
            source,
            desired_state_path: desired_state_path.as_ref().to_path_buf(),
            current: None,
            last_attempted: None,
            last_reconciled: None,
            freshness_barrier: None,
            reconciliation_requested: true,
        }
    }

    pub(crate) const fn request_reconciliation(&mut self) {
        self.reconciliation_requested = true;
    }

    pub(crate) fn request_fresh_snapshot(
        &mut self,
    ) -> Result<NetworkInventoryRefreshDisposition, PlatformError> {
        let barrier = self
            .source
            .snapshot()
            .map(|inventory| (inventory.snapshot_id(), inventory.epoch()))
            .or_else(|| {
                self.current
                    .as_ref()
                    .map(AddressReconciledGenerationInputs::inspection)
                    .map(|inspection| (inspection.snapshot_id(), inspection.epoch()))
            })
            .or(self.last_reconciled);
        self.current = None;
        self.last_attempted = barrier;
        self.freshness_barrier = barrier;
        self.reconciliation_requested = false;
        self.source.request_refresh()
    }

    #[must_use]
    pub(crate) const fn current(&self) -> Option<&AddressReconciledGenerationInputs> {
        self.current.as_ref()
    }

    pub(crate) fn reconcile(
        &mut self,
    ) -> Result<AddressReconciliationOutcome, AddressReconciliationError> {
        let inventory = match self.source.snapshot() {
            None => {
                self.last_attempted = None;
                self.reconciliation_requested = true;
                return Ok(match self.current.take() {
                    Some(current) => {
                        AddressReconciliationOutcome::Invalidated(current.inspection())
                    }
                    None => AddressReconciliationOutcome::AwaitingCompleteSnapshot,
                });
            }
            Some(inventory) => inventory,
        };
        let identity = (inventory.snapshot_id(), inventory.epoch());
        if self.freshness_barrier == Some(identity) {
            self.current = None;
            self.last_attempted = Some(identity);
            self.reconciliation_requested = false;
            return Ok(AddressReconciliationOutcome::Blocked {
                snapshot_id: identity.0,
                epoch: identity.1,
            });
        }
        self.freshness_barrier = None;
        if !self.reconciliation_requested && self.last_attempted == Some(identity) {
            return Ok(match self.current.as_ref() {
                Some(current) => AddressReconciliationOutcome::Unchanged(current.inspection()),
                None => AddressReconciliationOutcome::Blocked {
                    snapshot_id: identity.0,
                    epoch: identity.1,
                },
            });
        }

        self.current = None;
        self.last_attempted = Some(identity);
        self.reconciliation_requested = false;
        let current = compile_address_reconciliation(&self.desired_state_path, inventory)?;
        let inspection = current.inspection();
        self.last_reconciled = Some((inspection.snapshot_id(), inspection.epoch()));
        self.current = Some(current);
        Ok(AddressReconciliationOutcome::Reconciled(inspection))
    }
}

pub(crate) fn compile_address_reconciliation(
    desired_state_path: &Path,
    inventory: Arc<NetworkInventory>,
) -> Result<AddressReconciledGenerationInputs, AddressReconciliationError> {
    let config = FluxConfig::load(desired_state_path).map_err(|source| {
        AddressReconciliationError::DesiredState {
            path: desired_state_path.to_path_buf(),
            source,
        }
    })?;
    let application_mode = config.applications().mode();
    let application_package_count = config.applications().packages().len();
    if application_package_count != 0 {
        return Err(AddressReconciliationError::UnresolvedApplicationPackages {
            mode: application_mode,
            count: application_package_count,
        });
    }
    let applications = CaptureApplicationPolicy::new(application_mode, [])
        .expect("an empty resolved application policy is always within its resource budget");
    let rule_budget = AddressBypassRuleBudget::new(MAX_ADDRESS_BYPASS_RULES)
        .expect("the address host-set maximum is a valid nonzero rule budget");
    let host_policy = AddressHostSetPolicy::new(config.capture().scope().families(), rule_budget);
    let host_bypass = plan_address_host_set(&inventory, &host_policy)
        .map_err(AddressReconciliationError::HostPlan)?;
    let capture = compile_desired_state_capture(DesiredStateCompileRequest::new(
        config,
        applications,
        Some(host_bypass.clone()),
    ))
    .map_err(AddressReconciliationError::Compile)?;

    Ok(AddressReconciledGenerationInputs {
        inventory,
        host_bypass,
        capture,
    })
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use flux_core::{
        CapturePredicate, InterfaceAddressFlags, InterfaceAddressRecord, InterfaceIndex,
        NetworkInventoryTracker,
    };

    use super::*;

    const PACKAGED_DESIRED_STATE: &str = include_str!("../../../../conf/flux.toml");

    struct ReconcilerFixture {
        _directory: tempfile::TempDir,
        desired_state_path: PathBuf,
        source: ReplayNetworkInventorySource,
        reconciler: AddressReconciler,
    }

    impl ReconcilerFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("address reconciliation fixture");
            let template_path = directory.path().join("template.json");
            let desired_state_path = directory.path().join("flux.toml");
            std::fs::write(&template_path, br#"{"inbounds":[]}"#).expect("write engine template");
            let desired_state = PACKAGED_DESIRED_STATE.replacen(
                "/data/adb/flux/conf/template.json",
                template_path.to_str().expect("UTF-8 template path"),
                1,
            );
            std::fs::write(&desired_state_path, desired_state).expect("write Desired State");
            let source = ReplayNetworkInventorySource::default();
            let reconciler = AddressReconciler::new(&desired_state_path, Box::new(source.clone()));
            Self {
                _directory: directory,
                desired_state_path,
                source,
                reconciler,
            }
        }
    }

    #[test]
    fn complete_snapshot_compiles_pre_mark_host_bypass() {
        let mut fixture = ReconcilerFixture::new();
        let mut tracker = NetworkInventoryTracker::new();
        let inventory = publish_inventory(
            &mut tracker,
            [
                "8.8.8.8",
                "127.0.0.1",
                "169.254.10.20",
                "2001:4860:4860::8888",
            ],
        );
        fixture.source.publish(Some(Arc::clone(&inventory)));

        let outcome = fixture.reconciler.reconcile().expect("reconcile snapshot");
        let AddressReconciliationOutcome::Reconciled(inspection) = outcome else {
            panic!("complete snapshot must reconcile: {outcome:?}");
        };
        assert_eq!(inspection.snapshot_id(), inventory.snapshot_id());
        assert_eq!(inspection.epoch(), inventory.epoch());
        assert_eq!(inspection.host_count(), 1);

        let current = fixture.reconciler.current().expect("reconciled inputs");
        assert_eq!(current.inventory(), inventory.as_ref());
        assert_eq!(
            current.host_bypass().hosts(),
            [IpAddr::from_str("8.8.8.8").expect("global IPv4 address")]
        );
        let provenance = current
            .capture()
            .capture()
            .address_host_set_provenance()
            .expect("host provenance");
        assert_eq!(provenance.snapshot_id(), inventory.snapshot_id());
        assert_eq!(provenance.epoch(), inventory.epoch());
        assert!(
            current
                .capture()
                .capture()
                .program()
                .programs()
                .iter()
                .flat_map(|program| program.clauses())
                .any(|clause| matches!(
                    clause.predicate(),
                    CapturePredicate::DestinationHosts(hosts)
                        if hosts.as_ref() == current.host_bypass().hosts()
                ))
        );
    }

    #[cfg(unix)]
    #[test]
    fn reconciliation_does_not_reopen_the_selected_engine_source() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("address reconciliation fixture");
        let target_directory = directory.path().join("template-target");
        std::fs::create_dir(&target_directory).expect("create template target directory");
        std::fs::write(
            target_directory.join("template.json"),
            br#"{"inbounds":[]}"#,
        )
        .expect("write engine template");
        let linked_directory = directory.path().join("template-source");
        symlink(&target_directory, &linked_directory).expect("link template ancestor");
        let template_path = linked_directory.join("template.json");
        let desired_state_path = directory.path().join("flux.toml");
        let desired_state = PACKAGED_DESIRED_STATE.replacen(
            "/data/adb/flux/conf/template.json",
            template_path.to_str().expect("UTF-8 template path"),
            1,
        );
        std::fs::write(&desired_state_path, desired_state).expect("write Desired State");
        let source = ReplayNetworkInventorySource::default();
        let mut reconciler = AddressReconciler::new(&desired_state_path, Box::new(source.clone()));
        let mut tracker = NetworkInventoryTracker::new();
        source.publish(Some(publish_inventory(&mut tracker, ["8.8.8.8"])));

        let outcome = reconciler
            .reconcile()
            .expect("capture reconciliation must not realize the engine source");

        assert!(matches!(
            outcome,
            AddressReconciliationOutcome::Reconciled(_)
        ));
        assert!(reconciler.current().is_some());
    }

    #[test]
    fn identical_snapshot_is_noop_until_desired_state_requests_refresh() {
        let mut fixture = ReconcilerFixture::new();
        let mut tracker = NetworkInventoryTracker::new();
        let inventory = publish_inventory(&mut tracker, ["8.8.4.4"]);
        fixture.source.publish(Some(inventory));

        let first = fixture
            .reconciler
            .reconcile()
            .expect("first reconciliation");
        let second = fixture
            .reconciler
            .reconcile()
            .expect("idempotent reconciliation");
        assert!(matches!(
            (first, second),
            (
                AddressReconciliationOutcome::Reconciled(first),
                AddressReconciliationOutcome::Unchanged(second)
            ) if first == second
        ));

        fixture.reconciler.request_reconciliation();
        assert!(matches!(
            fixture.reconciler.reconcile(),
            Ok(AddressReconciliationOutcome::Reconciled(_))
        ));
    }

    #[test]
    fn explicit_refresh_blocks_the_previous_inventory_identity() {
        let mut fixture = ReconcilerFixture::new();
        let mut tracker = NetworkInventoryTracker::new();
        let initial = publish_inventory(&mut tracker, ["8.8.4.4"]);
        fixture.source.publish(Some(Arc::clone(&initial)));
        fixture
            .reconciler
            .reconcile()
            .expect("reconcile initial inventory");

        assert_eq!(
            fixture
                .reconciler
                .request_fresh_snapshot()
                .expect("request fresh inventory"),
            NetworkInventoryRefreshDisposition::Requested
        );
        assert_eq!(fixture.source.refresh_requests(), 1);
        assert!(fixture.reconciler.current().is_none());
        assert!(matches!(
            fixture.reconciler.reconcile(),
            Ok(AddressReconciliationOutcome::Blocked { snapshot_id, epoch })
                if snapshot_id == initial.snapshot_id() && epoch == initial.epoch()
        ));

        fixture.source.publish(None);
        assert_eq!(
            fixture
                .reconciler
                .reconcile()
                .expect("await refresh transaction"),
            AddressReconciliationOutcome::AwaitingCompleteSnapshot
        );
        fixture.source.publish(Some(Arc::clone(&initial)));
        assert!(matches!(
            fixture.reconciler.reconcile(),
            Ok(AddressReconciliationOutcome::Blocked { snapshot_id, .. })
                if snapshot_id == initial.snapshot_id()
        ));

        let refreshed = publish_inventory(&mut tracker, ["8.8.4.4"]);
        fixture.source.publish(Some(Arc::clone(&refreshed)));
        assert!(matches!(
            fixture.reconciler.reconcile(),
            Ok(AddressReconciliationOutcome::Reconciled(inspection))
                if inspection.snapshot_id() == refreshed.snapshot_id()
        ));
    }

    #[test]
    fn loss_invalidates_current_and_full_resync_rebuilds_even_equal_facts() {
        let mut fixture = ReconcilerFixture::new();
        let mut tracker = NetworkInventoryTracker::new();
        let inventory = publish_inventory(&mut tracker, ["1.1.1.1"]);
        fixture.source.publish(Some(Arc::clone(&inventory)));
        fixture
            .reconciler
            .reconcile()
            .expect("initial reconciliation");

        fixture.source.publish(None);
        assert!(matches!(
            fixture.reconciler.reconcile(),
            Ok(AddressReconciliationOutcome::Invalidated(previous))
                if previous.snapshot_id() == inventory.snapshot_id()
        ));
        assert!(fixture.reconciler.current().is_none());
        assert_eq!(
            fixture
                .reconciler
                .reconcile()
                .expect("stale source remains bounded"),
            AddressReconciliationOutcome::AwaitingCompleteSnapshot
        );

        fixture.source.publish(Some(inventory));
        assert!(matches!(
            fixture.reconciler.reconcile(),
            Ok(AddressReconciliationOutcome::Reconciled(_))
        ));
    }

    #[test]
    fn material_replacement_discards_the_previous_snapshot() {
        let mut fixture = ReconcilerFixture::new();
        let mut tracker = NetworkInventoryTracker::new();
        let first = publish_inventory(&mut tracker, ["9.9.9.9"]);
        fixture.source.publish(Some(first));
        fixture
            .reconciler
            .reconcile()
            .expect("first reconciliation");

        let replacement = publish_inventory(&mut tracker, ["149.112.112.112"]);
        fixture.source.publish(Some(Arc::clone(&replacement)));
        let outcome = fixture
            .reconciler
            .reconcile()
            .expect("replacement reconciliation");
        assert!(matches!(
            outcome,
            AddressReconciliationOutcome::Reconciled(inspection)
                if inspection.snapshot_id() == replacement.snapshot_id()
                    && inspection.epoch() == replacement.epoch()
        ));
        assert_eq!(
            fixture
                .reconciler
                .current()
                .expect("replacement inputs")
                .host_bypass()
                .hosts(),
            [IpAddr::from_str("149.112.112.112").expect("replacement address")]
        );
    }

    #[test]
    fn named_packages_fail_closed_and_do_not_retry_without_a_new_trigger() {
        let mut fixture = ReconcilerFixture::new();
        let desired_state = std::fs::read_to_string(&fixture.desired_state_path)
            .expect("read fixture Desired State")
            .replacen("mode = \"all\"", "mode = \"allowlist\"", 1)
            .replacen("packages = []", "packages = [\"com.example.client\"]", 1);
        std::fs::write(&fixture.desired_state_path, desired_state)
            .expect("write package-backed Desired State");
        let mut tracker = NetworkInventoryTracker::new();
        let inventory = publish_inventory(&mut tracker, ["8.8.8.8"]);
        let snapshot_id = inventory.snapshot_id();
        let epoch = inventory.epoch();
        fixture.source.publish(Some(inventory));

        let error = fixture
            .reconciler
            .reconcile()
            .expect_err("unresolved packages must fail closed");
        assert_eq!(
            error.kind(),
            AddressReconciliationErrorKind::UnresolvedApplicationPackages {
                mode: CaptureApplicationMode::Allowlist,
                count: 1,
            }
        );
        assert!(fixture.reconciler.current().is_none());
        assert_eq!(
            fixture
                .reconciler
                .reconcile()
                .expect("unchanged failed input is not retried"),
            AddressReconciliationOutcome::Blocked { snapshot_id, epoch }
        );
    }

    fn publish_inventory<const N: usize>(
        tracker: &mut NetworkInventoryTracker,
        addresses: [&str; N],
    ) -> Arc<NetworkInventory> {
        let interface_index = InterfaceIndex::new(7).expect("test interface index");
        let addresses = addresses.into_iter().map(|address| {
            let address = IpAddr::from_str(address).expect("test address");
            let prefix_length = if address.is_ipv4() { 32 } else { 128 };
            InterfaceAddressRecord::new(
                interface_index,
                address,
                prefix_length,
                InterfaceAddressFlags::from_bits(0),
            )
            .expect("test interface address")
        });
        Arc::new(
            tracker
                .publish_complete([], addresses)
                .expect("publish complete inventory")
                .clone(),
        )
    }
}
