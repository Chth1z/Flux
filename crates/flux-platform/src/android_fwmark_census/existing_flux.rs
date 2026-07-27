use std::error::Error;
use std::fmt;

use flux_core::{FwmarkCensusCoverageRecord, OwnershipJournalIdentity, OwnershipJournalRevision};

/// Domain-separated digest of one complete existing-Flux absence proof.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AndroidExistingFluxOwnershipDigest([u8; 32]);

impl AndroidExistingFluxOwnershipDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Privacy-reduced proof that no previous Flux owner remains in any mark plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidExistingFluxOwnershipObservation {
    digest: AndroidExistingFluxOwnershipDigest,
    ownership_journal_identity: OwnershipJournalIdentity,
    ownership_journal_revision: OwnershipJournalRevision,
    coverage: [FwmarkCensusCoverageRecord; 3],
    durable_root_present: bool,
    empty_target_archive_present: bool,
    durable_artifact_count: usize,
    archived_target_count: usize,
    flux_process_count: usize,
    flux_chain_count: usize,
    flux_route_count: usize,
    flux_rule_count: usize,
}

impl AndroidExistingFluxOwnershipObservation {
    #[must_use]
    pub const fn digest(&self) -> AndroidExistingFluxOwnershipDigest {
        self.digest
    }

    #[must_use]
    pub const fn ownership_journal_identity(&self) -> OwnershipJournalIdentity {
        self.ownership_journal_identity
    }

    #[must_use]
    pub const fn ownership_journal_revision(&self) -> OwnershipJournalRevision {
        self.ownership_journal_revision
    }

    #[must_use]
    pub const fn coverage(&self) -> &[FwmarkCensusCoverageRecord; 3] {
        &self.coverage
    }

    #[must_use]
    pub const fn durable_root_present(&self) -> bool {
        self.durable_root_present
    }

    #[must_use]
    pub const fn empty_target_archive_present(&self) -> bool {
        self.empty_target_archive_present
    }

    #[must_use]
    pub const fn durable_artifact_count(&self) -> usize {
        self.durable_artifact_count
    }

    #[must_use]
    pub const fn archived_target_count(&self) -> usize {
        self.archived_target_count
    }

    #[must_use]
    pub const fn flux_process_count(&self) -> usize {
        self.flux_process_count
    }

    #[must_use]
    pub const fn flux_chain_count(&self) -> usize {
        self.flux_chain_count
    }

    #[must_use]
    pub const fn flux_route_count(&self) -> usize {
        self.flux_route_count
    }

    #[must_use]
    pub const fn flux_rule_count(&self) -> usize {
        self.flux_rule_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidExistingFluxOwnershipErrorKind {
    UnsafeDurableRoot,
    CapabilityNamespaceMismatch,
    DurableObservationFailed,
    DurableSnapshotChanged,
    ProcessObservationFailed,
    ProcessSnapshotChanged,
    DurableOwnershipPresent,
    ProcessOwnershipPresent,
    ChainOwnershipPresent,
    PolicyRoutingOwnershipPresent,
    JournalIdentityUnavailable,
}

/// Sanitized failure from existing-Flux ownership observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidExistingFluxOwnershipError {
    kind: AndroidExistingFluxOwnershipErrorKind,
    observed_count: Option<usize>,
}

impl AndroidExistingFluxOwnershipError {
    #[must_use]
    pub const fn kind(self) -> AndroidExistingFluxOwnershipErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn observed_count(self) -> Option<usize> {
        self.observed_count
    }

    const fn new(kind: AndroidExistingFluxOwnershipErrorKind) -> Self {
        Self {
            kind,
            observed_count: None,
        }
    }

    const fn with_count(kind: AndroidExistingFluxOwnershipErrorKind, count: usize) -> Self {
        Self {
            kind,
            observed_count: Some(count),
        }
    }
}

impl fmt::Display for AndroidExistingFluxOwnershipError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            AndroidExistingFluxOwnershipErrorKind::UnsafeDurableRoot => {
                "existing-Flux observation requires an absolute safe durable root"
            }
            AndroidExistingFluxOwnershipErrorKind::CapabilityNamespaceMismatch => {
                "existing-Flux observation namespace differs from the exact capability profile"
            }
            AndroidExistingFluxOwnershipErrorKind::DurableObservationFailed => {
                "existing-Flux durable ownership observation failed"
            }
            AndroidExistingFluxOwnershipErrorKind::DurableSnapshotChanged => {
                "existing-Flux durable ownership changed during observation"
            }
            AndroidExistingFluxOwnershipErrorKind::ProcessObservationFailed => {
                "existing-Flux process observation failed"
            }
            AndroidExistingFluxOwnershipErrorKind::ProcessSnapshotChanged => {
                "existing-Flux process ownership changed during observation"
            }
            AndroidExistingFluxOwnershipErrorKind::DurableOwnershipPresent => {
                "existing Flux durable ownership remains"
            }
            AndroidExistingFluxOwnershipErrorKind::ProcessOwnershipPresent => {
                "an existing Flux process remains"
            }
            AndroidExistingFluxOwnershipErrorKind::ChainOwnershipPresent => {
                "an existing Flux netfilter chain remains"
            }
            AndroidExistingFluxOwnershipErrorKind::PolicyRoutingOwnershipPresent => {
                "existing Flux policy routing remains"
            }
            AndroidExistingFluxOwnershipErrorKind::JournalIdentityUnavailable => {
                "the observed clean-journal identity is unavailable"
            }
        })?;
        if let Some(count) = self.observed_count {
            write!(formatter, " ({count} observed)")?;
        }
        Ok(())
    }
}

impl Error for AndroidExistingFluxOwnershipError {}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::collections::BTreeSet;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};

    use flux_core::{
        CapabilityProfile, FwmarkCensusCoverageRecord, FwmarkCensusCoverageState,
        FwmarkEvidenceSource, FwmarkPlane, NetworkAddressFamily, NetworkInventory,
        NetworkRouteRecord, OwnershipJournalIdentity, OwnershipJournalRevision, RoutePath,
        RoutePrefix,
    };
    use sha2::{Digest, Sha256};

    use crate::xtables::{
        NativeXtablesDurableReadOnlyObservation, NativeXtablesDurableRootIdentity,
        NativeXtablesDurableStore, NativeXtablesTargetArchiveObservation,
        observe_native_xtables_target_archive,
    };

    use super::{
        AndroidExistingFluxOwnershipDigest, AndroidExistingFluxOwnershipError,
        AndroidExistingFluxOwnershipErrorKind, AndroidExistingFluxOwnershipObservation,
    };
    use crate::android_fwmark_census::AndroidXtablesFwmarkObservation;

    const ABSENCE_DIGEST_DOMAIN: &[u8] =
        b"Flux existing ownership absence\0canonical-schema-v1\0sha256-v1\0";
    const CLEAN_JOURNAL_IDENTITY_DOMAIN: &[u8] =
        b"Flux observed missing ownership journal\0canonical-schema-v1\0sha256-v1\0";
    const ABSENCE_COUNT_SIGNATURE: &[u8] = b"durable-artifact-count\0archived-target-count\0\
flux-process-count\0flux-chain-count\0flux-route-count\0flux-rule-count\0";
    const COMPLETE_ABSENCE_COVERAGE_SIGNATURE: &[u8] =
        b"packet=complete-absent\0socket=complete-absent\0conntrack=complete-absent\0";
    const MAX_SYSTEM_PROCESS_ENTRIES: usize = 65_536;
    const MAX_PROC_STAT_BYTES: usize = 4 * 1024;
    const LEGACY_ROUTE_TABLE: u32 = 2_025;
    const LEGACY_RULE_PRIORITY: u32 = 2_025;
    const NATIVE_ROUTE_PROTOCOL: u8 = 4;
    const NATIVE_RULE_PROTOCOL: u8 = 99;
    const NATIVE_ROUTE_METRIC: u32 = 1_024;
    const RT_SCOPE_UNIVERSE: u8 = 0;
    const RT_SCOPE_HOST: u8 = 254;
    const RTN_LOCAL: u8 = 2;
    const IPV6_ROUTE_PREFERENCE_MEDIUM: u8 = 0;

    /// Collects a read-only proof that no native or bridge-era Flux owner remains.
    ///
    /// `durable_root` is the native xtables ownership directory, not the package root. Missing
    /// directories stay missing. The collector never creates a directory, acquires a lock, reads a
    /// command line, signals a process, or mutates kernel state.
    pub fn collect_android_existing_flux_ownership(
        durable_root: impl AsRef<Path>,
        inventory: &NetworkInventory,
        capability_profile: &CapabilityProfile,
        network_namespace: flux_core::NetworkNamespaceIdentity,
        xtables: &AndroidXtablesFwmarkObservation,
    ) -> Result<AndroidExistingFluxOwnershipObservation, AndroidExistingFluxOwnershipError> {
        collect_from_roots(
            durable_root.as_ref(),
            Path::new("/proc"),
            inventory,
            capability_profile,
            network_namespace,
            xtables,
        )
    }

    fn collect_from_roots(
        durable_root: &Path,
        proc_root: &Path,
        inventory: &NetworkInventory,
        capability_profile: &CapabilityProfile,
        network_namespace: flux_core::NetworkNamespaceIdentity,
        xtables: &AndroidXtablesFwmarkObservation,
    ) -> Result<AndroidExistingFluxOwnershipObservation, AndroidExistingFluxOwnershipError> {
        if !durable_root.is_absolute() {
            return Err(AndroidExistingFluxOwnershipError::new(
                AndroidExistingFluxOwnershipErrorKind::UnsafeDurableRoot,
            ));
        }
        if capability_profile
            .device_identity()
            .verified()
            .is_some_and(|identity| identity.network_namespace() != network_namespace)
        {
            return Err(AndroidExistingFluxOwnershipError::new(
                AndroidExistingFluxOwnershipErrorKind::CapabilityNamespaceMismatch,
            ));
        }

        let store = NativeXtablesDurableStore::new(durable_root);
        let durable_before = observe_durable(&store)?;
        let processes_before = observe_flux_processes(proc_root)?;
        let policy_routing = observe_policy_routing(inventory);
        let processes_after = observe_flux_processes(proc_root)?;
        let durable_after = observe_durable(&store)?;

        if durable_before != durable_after {
            return Err(AndroidExistingFluxOwnershipError::new(
                AndroidExistingFluxOwnershipErrorKind::DurableSnapshotChanged,
            ));
        }
        if processes_before != processes_after {
            return Err(AndroidExistingFluxOwnershipError::new(
                AndroidExistingFluxOwnershipErrorKind::ProcessSnapshotChanged,
            ));
        }

        let counts = ExistingFluxOwnershipCounts {
            durable_artifacts: durable_before.ownership_artifact_count(),
            archived_targets: durable_before.archive.target_count(),
            processes: processes_before.flux_processes.len(),
            chains: xtables.flux_owned_chain_count(),
            routes: policy_routing.route_total(),
            rules: policy_routing.rule_total(),
        };
        if counts.durable_artifacts != 0 {
            return Err(AndroidExistingFluxOwnershipError::with_count(
                AndroidExistingFluxOwnershipErrorKind::DurableOwnershipPresent,
                counts.durable_artifacts,
            ));
        }
        if counts.processes != 0 {
            return Err(AndroidExistingFluxOwnershipError::with_count(
                AndroidExistingFluxOwnershipErrorKind::ProcessOwnershipPresent,
                counts.processes,
            ));
        }
        if counts.chains != 0 {
            return Err(AndroidExistingFluxOwnershipError::with_count(
                AndroidExistingFluxOwnershipErrorKind::ChainOwnershipPresent,
                counts.chains,
            ));
        }
        if counts.routes.saturating_add(counts.rules) != 0 {
            return Err(AndroidExistingFluxOwnershipError::with_count(
                AndroidExistingFluxOwnershipErrorKind::PolicyRoutingOwnershipPresent,
                counts.routes.saturating_add(counts.rules),
            ));
        }

        let digest = digest_absence(
            durable_root,
            inventory,
            capability_profile,
            network_namespace,
            xtables,
            &durable_before,
            counts,
        );
        let mut journal_digest = Sha256::new();
        journal_digest.update(CLEAN_JOURNAL_IDENTITY_DOMAIN);
        journal_digest.update(digest.as_bytes());
        let ownership_journal_identity =
            OwnershipJournalIdentity::new(journal_digest.finalize().into()).map_err(|_| {
                AndroidExistingFluxOwnershipError::new(
                    AndroidExistingFluxOwnershipErrorKind::JournalIdentityUnavailable,
                )
            })?;
        let coverage = [
            absent_coverage(FwmarkPlane::Packet),
            absent_coverage(FwmarkPlane::Socket),
            absent_coverage(FwmarkPlane::Conntrack),
        ];
        Ok(AndroidExistingFluxOwnershipObservation {
            digest,
            ownership_journal_identity,
            ownership_journal_revision: OwnershipJournalRevision::INITIAL,
            coverage,
            durable_root_present: durable_before.root_identity.is_some(),
            empty_target_archive_present: durable_before.archive.present(),
            durable_artifact_count: counts.durable_artifacts,
            archived_target_count: counts.archived_targets,
            flux_process_count: counts.processes,
            flux_chain_count: counts.chains,
            flux_route_count: counts.routes,
            flux_rule_count: counts.rules,
        })
    }

    const fn absent_coverage(plane: FwmarkPlane) -> FwmarkCensusCoverageRecord {
        FwmarkCensusCoverageRecord::new(
            FwmarkEvidenceSource::ExistingFluxOwnership,
            plane,
            FwmarkCensusCoverageState::CompleteAbsent,
        )
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DurableSnapshot {
        root_identity: Option<NativeXtablesDurableRootIdentity>,
        journal_present: bool,
        lease_present: bool,
        writer_lock_present: bool,
        archive: NativeXtablesTargetArchiveObservation,
    }

    impl DurableSnapshot {
        fn ownership_artifact_count(self) -> usize {
            usize::from(self.journal_present)
                + usize::from(self.lease_present)
                + usize::from(self.writer_lock_present)
                + self.archive.target_count()
        }
    }

    fn observe_durable(
        store: &NativeXtablesDurableStore,
    ) -> Result<DurableSnapshot, AndroidExistingFluxOwnershipError> {
        let observed = store.observe_read_only().map_err(|_| {
            AndroidExistingFluxOwnershipError::new(
                AndroidExistingFluxOwnershipErrorKind::DurableObservationFailed,
            )
        })?;
        durable_snapshot(&observed)
    }

    fn durable_snapshot(
        observed: &NativeXtablesDurableReadOnlyObservation,
    ) -> Result<DurableSnapshot, AndroidExistingFluxOwnershipError> {
        let archive =
            observe_native_xtables_target_archive(observed.target_archive()).map_err(|_| {
                AndroidExistingFluxOwnershipError::new(
                    AndroidExistingFluxOwnershipErrorKind::DurableObservationFailed,
                )
            })?;
        Ok(DurableSnapshot {
            root_identity: observed.root_identity(),
            journal_present: observed.journal_present(),
            lease_present: observed.lease_present(),
            writer_lock_present: observed.writer_lock_present(),
            archive,
        })
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct PolicyRoutingOwnership {
        legacy_routes: usize,
        native_routes: usize,
        legacy_rules: usize,
        native_rules: usize,
    }

    impl PolicyRoutingOwnership {
        fn route_total(self) -> usize {
            self.legacy_routes.saturating_add(self.native_routes)
        }

        fn rule_total(self) -> usize {
            self.legacy_rules.saturating_add(self.native_rules)
        }
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct ExistingFluxOwnershipCounts {
        durable_artifacts: usize,
        archived_targets: usize,
        processes: usize,
        chains: usize,
        routes: usize,
        rules: usize,
    }

    fn observe_policy_routing(inventory: &NetworkInventory) -> PolicyRoutingOwnership {
        let mut observation = PolicyRoutingOwnership::default();
        for route in inventory.routes() {
            if route.properties().table().get() == LEGACY_ROUTE_TABLE {
                observation.legacy_routes = observation.legacy_routes.saturating_add(1);
            }
            if is_native_flux_route(inventory, route) {
                observation.native_routes = observation.native_routes.saturating_add(1);
            }
        }
        for rule in inventory.rules() {
            if rule.priority().get() == LEGACY_RULE_PRIORITY
                || rule.properties().table().get() == LEGACY_ROUTE_TABLE
            {
                observation.legacy_rules = observation.legacy_rules.saturating_add(1);
            }
            if rule.properties().protocol().raw() == NATIVE_RULE_PROTOCOL {
                observation.native_rules = observation.native_rules.saturating_add(1);
            }
        }
        observation
    }

    fn is_native_flux_route(inventory: &NetworkInventory, route: &NetworkRouteRecord) -> bool {
        let family = route.destination().family();
        let properties = route.properties();
        let expected_scope = match family {
            NetworkAddressFamily::Ipv4 => RT_SCOPE_HOST,
            NetworkAddressFamily::Ipv6 => RT_SCOPE_UNIVERSE,
        };
        let preference_matches = match family {
            NetworkAddressFamily::Ipv4 => route.preference().is_none(),
            NetworkAddressFamily::Ipv6 => route
                .preference()
                .is_some_and(|preference| preference.raw() == IPV6_ROUTE_PREFERENCE_MEDIUM),
        };
        let output_interface = match route.path() {
            RoutePath::Single {
                output_interface: Some(output_interface),
                gateway: None,
            } => *output_interface,
            RoutePath::None | RoutePath::Single { .. } | RoutePath::Multipath(_) => return false,
        };
        properties.protocol().raw() == NATIVE_ROUTE_PROTOCOL
            && properties.table().get() != 0
            && !matches!(properties.table().get(), 252..=255)
            && properties.tos() == 0
            && properties.scope().raw() == expected_scope
            && properties.route_type().raw() == RTN_LOCAL
            && properties.flags().raw() == 0
            && route.destination() == RoutePrefix::unspecified(family)
            && route.source() == RoutePrefix::unspecified(family)
            && route.priority() == NATIVE_ROUTE_METRIC
            && route.preferred_source().is_none()
            && route.nexthop_id().is_none()
            && preference_matches
            && inventory.links().iter().any(|link| {
                link.interface_index() == output_interface && link.name().as_bytes() == b"lo"
            })
    }

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    enum FluxProcessKind {
        Daemon,
        AddressSynchronizer,
        Engine,
    }

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct FluxProcessIdentity {
        kind: FluxProcessKind,
        pid: u32,
        start_time_ticks: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct FluxProcessSnapshot {
        flux_processes: BTreeSet<FluxProcessIdentity>,
    }

    fn observe_flux_processes(
        proc_root: &Path,
    ) -> Result<FluxProcessSnapshot, AndroidExistingFluxOwnershipError> {
        scan_flux_processes(proc_root).map_err(|_| {
            AndroidExistingFluxOwnershipError::new(
                AndroidExistingFluxOwnershipErrorKind::ProcessObservationFailed,
            )
        })
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ProcessScanError {
        Io,
        LimitExceeded,
        Malformed,
    }

    fn scan_flux_processes(proc_root: &Path) -> Result<FluxProcessSnapshot, ProcessScanError> {
        scan_flux_processes_bounded(proc_root, MAX_SYSTEM_PROCESS_ENTRIES)
    }

    fn scan_flux_processes_bounded(
        proc_root: &Path,
        max_entries: usize,
    ) -> Result<FluxProcessSnapshot, ProcessScanError> {
        let root = open_directory(proc_root).map_err(|_| ProcessScanError::Io)?;
        let mut entries =
            std::fs::read_dir(descriptor_path(&root)).map_err(|_| ProcessScanError::Io)?;
        let mut observed_entries = 0_usize;
        let mut flux_processes = BTreeSet::new();
        for entry in &mut entries {
            let entry = entry.map_err(|_| ProcessScanError::Io)?;
            observed_entries = observed_entries.saturating_add(1);
            if observed_entries > max_entries {
                return Err(ProcessScanError::LimitExceeded);
            }
            let Some(pid) = parse_pid(entry.file_name().as_bytes())? else {
                continue;
            };
            let pid_directory = match open_directory(&descriptor_path(&root).join(pid.to_string()))
            {
                Ok(directory) => directory,
                Err(error) if process_disappeared(&error) => continue,
                Err(_) => return Err(ProcessScanError::Io),
            };
            let stat = match read_bounded_stat(&pid_directory) {
                Ok(stat) => stat,
                Err(error) if process_disappeared(&error) => continue,
                Err(_) => return Err(ProcessScanError::Io),
            };
            let parsed = parse_proc_stat(&stat, pid).ok_or(ProcessScanError::Malformed)?;
            if let Some(kind) = flux_process_kind(parsed.command) {
                flux_processes.insert(FluxProcessIdentity {
                    kind,
                    pid,
                    start_time_ticks: parsed.start_time_ticks,
                });
            }
        }
        Ok(FluxProcessSnapshot { flux_processes })
    }

    fn open_directory(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
    }

    fn descriptor_path(file: &File) -> PathBuf {
        Path::new("/proc/self/fd").join(file.as_raw_fd().to_string())
    }

    fn read_bounded_stat(pid_directory: &File) -> io::Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(descriptor_path(pid_directory).join("stat"))?;
        let mut bytes = Vec::with_capacity(256);
        file.take((MAX_PROC_STAT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_PROC_STAT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proc stat exceeds its hard byte limit",
            ));
        }
        Ok(bytes)
    }

    fn process_disappeared(error: &io::Error) -> bool {
        matches!(error.raw_os_error(), Some(code) if code == libc::ENOENT || code == libc::ESRCH)
    }

    fn parse_pid(bytes: &[u8]) -> Result<Option<u32>, ProcessScanError> {
        if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
            return Ok(None);
        }
        if bytes[0] == b'0' {
            return Err(ProcessScanError::Malformed);
        }
        let pid = parse_decimal(bytes)
            .and_then(|pid| u32::try_from(pid).ok())
            .ok_or(ProcessScanError::Malformed)?;
        Ok(Some(pid))
    }

    struct ParsedProcStat<'a> {
        command: &'a [u8],
        start_time_ticks: u64,
    }

    fn parse_proc_stat(bytes: &[u8], expected_pid: u32) -> Option<ParsedProcStat<'_>> {
        if bytes.is_empty() || bytes.len() > MAX_PROC_STAT_BYTES || !bytes.ends_with(b"\n") {
            return None;
        }
        let prefix = format!("{expected_pid} (");
        let prefix = prefix.as_bytes();
        if !bytes.starts_with(prefix) {
            return None;
        }
        let close = bytes.windows(2).rposition(|pair| pair == b") ")?;
        if close < prefix.len() {
            return None;
        }
        let command = &bytes[prefix.len()..close];
        if command.is_empty() || command.contains(&b'\0') || command.contains(&b'\n') {
            return None;
        }
        let mut fields = bytes[close + 2..].split(|byte| byte.is_ascii_whitespace());
        let fields = fields
            .by_ref()
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        if fields.len() < 20 || fields[0].len() != 1 || !fields[0][0].is_ascii_alphabetic() {
            return None;
        }
        let start_time_ticks = parse_decimal(fields[19])?;
        if start_time_ticks == 0 {
            return None;
        }
        Some(ParsedProcStat {
            command,
            start_time_ticks,
        })
    }

    fn parse_decimal(bytes: &[u8]) -> Option<u64> {
        if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
            return None;
        }
        bytes.iter().try_fold(0_u64, |value, byte| {
            value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
        })
    }

    fn flux_process_kind(command: &[u8]) -> Option<FluxProcessKind> {
        match command {
            b"fluxd" => Some(FluxProcessKind::Daemon),
            b"addrsyncd" => Some(FluxProcessKind::AddressSynchronizer),
            b"sing-box" => Some(FluxProcessKind::Engine),
            _ => None,
        }
    }

    fn digest_absence(
        durable_root: &Path,
        inventory: &NetworkInventory,
        capability_profile: &CapabilityProfile,
        network_namespace: flux_core::NetworkNamespaceIdentity,
        xtables: &AndroidXtablesFwmarkObservation,
        durable: &DurableSnapshot,
        counts: ExistingFluxOwnershipCounts,
    ) -> AndroidExistingFluxOwnershipDigest {
        let mut digest = Sha256::new();
        digest.update(ABSENCE_DIGEST_DOMAIN);
        digest.update(capability_profile.digest().as_bytes());
        digest.update(network_namespace.device().to_be_bytes());
        digest.update(network_namespace.inode().to_be_bytes());
        digest.update(inventory.snapshot_id().get().to_be_bytes());
        digest.update(inventory.epoch().get().to_be_bytes());
        digest_count(&mut digest, inventory.links().len());
        digest_count(&mut digest, inventory.addresses().len());
        digest_count(&mut digest, inventory.routes().len());
        digest_count(&mut digest, inventory.rules().len());
        digest_bytes(&mut digest, durable_root.as_os_str().as_bytes());
        digest.update(xtables.digest().as_bytes());
        match durable.root_identity {
            Some(identity) => {
                digest.update([1]);
                digest.update(identity.device().to_be_bytes());
                digest.update(identity.inode().to_be_bytes());
            }
            None => digest.update([0]),
        }
        digest.update([
            u8::from(durable.journal_present),
            u8::from(durable.lease_present),
            u8::from(durable.writer_lock_present),
            u8::from(durable.archive.present()),
        ]);
        digest_count(&mut digest, durable.archive.target_count());
        digest.update(durable.archive.digest());
        digest.update(ABSENCE_COUNT_SIGNATURE);
        for count in [
            counts.durable_artifacts,
            counts.archived_targets,
            counts.processes,
            counts.chains,
            counts.routes,
            counts.rules,
        ] {
            digest_count(&mut digest, count);
        }
        digest.update(COMPLETE_ABSENCE_COVERAGE_SIGNATURE);
        AndroidExistingFluxOwnershipDigest(digest.finalize().into())
    }

    fn digest_count(digest: &mut Sha256, value: usize) {
        digest.update(
            u64::try_from(value)
                .expect("bounded observation count fits u64")
                .to_be_bytes(),
        );
    }

    fn digest_bytes(digest: &mut Sha256, bytes: &[u8]) {
        digest_count(digest, bytes.len());
        digest.update(bytes);
    }

    #[cfg(test)]
    mod tests;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use implementation::collect_android_existing_flux_ownership;
