use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::fs::MetadataExt;

use flux_core::{
    AdministrativeState, CapabilityProfileSource, ConfigError, ConfigurationChangeClient,
    ConfigurationChangeReport, ControlClient, ControlError, ControlObservation,
    ControlObservationIngress, ControlSnapshot, ControlSnapshotSource, FluxConfig,
    LegacyControlBridge, LegacyDispatcher, LegacyIntent, LegacyMutationGate, OperationReport,
    Reason,
};
use flux_platform::{
    CapabilityProfilePaths, DaemonReactor, DispatcherPhaseCommand, FileObservationBatch,
    FileObservationPaths, PhaseDispatcherPaths, ProcessPhaseDispatcher, ShutdownSignal,
};

use crate::generation_engine_config::AddressReconciler;
use crate::inspection::ProcessInspectionSource;
use crate::offline_cleanup::{DaemonLease, DaemonLeaseError};
use crate::runtime_coordinator::{
    ProcessRuntimeWriter, RuntimeCoordinator, RuntimeFunctionalCanary,
};
use crate::subscription::{SubscriptionRefreshRuntime, SubscriptionRuntimePaths};
use crate::{
    AdministrativeIntentStore, ControlConnectionHandler, ControlSocketError, EngineSupervisor,
    IntentStoreError, RuntimeSnapshotSource,
};

const DEFAULT_ROOT: &str = "/data/adb/flux";
const DEFAULT_DISABLE_PATH: &str = "/data/adb/modules/flux/disable";
const DEFAULT_BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const DEFAULT_SELINUX_ENFORCE_PATH: &str = "/sys/fs/selinux/enforce";
const MIN_ENGINE_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(50);
const MAX_ENGINE_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonOptions {
    pub socket_path: PathBuf,
    pub daemon_lease_path: PathBuf,
    pub config_path: PathBuf,
    pub shell: PathBuf,
    pub dispatcher_script: PathBuf,
    pub addrsync_script: PathBuf,
    pub engine_manifest_path: PathBuf,
    pub engine_config_path: PathBuf,
    pub bridge_environment_path: PathBuf,
    pub subscription_store_path: PathBuf,
    pub intent_path: PathBuf,
    pub boot_id_path: PathBuf,
    pub selinux_enforce_path: PathBuf,
    pub disable_path: PathBuf,
}

impl DaemonOptions {
    pub fn from_environment() -> Result<Self, DaemonError> {
        let root = env::var_os("FLUX_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT));
        let socket_path = env::var_os("FLUXD_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("run/fluxd.sock"));
        let daemon_lease_path = env::var_os("FLUXD_LEASE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("run/fluxd.lease"));
        let config_path = env::var_os("FLUXD_CONFIG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("conf/flux.toml"));
        let shell = env::var_os("FLUX_SHELL")
            .map(PathBuf::from)
            .unwrap_or_else(default_shell);
        let intent_path = env::var_os("FLUXD_INTENT_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("state/administrative-intent.json"));
        let boot_id_path = env::var_os("FLUX_BOOT_ID_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_BOOT_ID_PATH));
        let selinux_enforce_path = env::var_os("FLUX_SELINUX_ENFORCE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SELINUX_ENFORCE_PATH));
        let disable_path = env::var_os("FLUX_DISABLE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DISABLE_PATH));

        Ok(Self {
            socket_path,
            daemon_lease_path,
            config_path,
            shell,
            dispatcher_script: root.join("scripts/dispatcher"),
            addrsync_script: root.join("scripts/addrsync"),
            engine_manifest_path: root.join("run/engine.manifest"),
            engine_config_path: root.join("conf/config.json"),
            bridge_environment_path: root.join("run/desired-state.env"),
            subscription_store_path: root.join("state/subscription"),
            intent_path,
            boot_id_path,
            selinux_enforce_path,
            disable_path,
        })
    }

    #[must_use]
    pub fn capability_profile_paths(&self) -> CapabilityProfilePaths {
        CapabilityProfilePaths::new(
            &self.boot_id_path,
            &self.selinux_enforce_path,
            &self.shell,
            &self.dispatcher_script,
            &self.addrsync_script,
        )
    }

    pub(crate) fn phase_dispatcher_paths(&self) -> PhaseDispatcherPaths {
        PhaseDispatcherPaths {
            shell: self.shell.clone(),
            shell_args: Vec::<OsString>::new(),
            dispatcher: self.dispatcher_script.clone(),
        }
    }
}

pub fn run_daemon<S>(profile_source: &S, options: DaemonOptions) -> Result<(), DaemonError>
where
    S: CapabilityProfileSource,
{
    let _daemon_lease =
        DaemonLease::acquire(&options.daemon_lease_path).map_err(DaemonError::Lease)?;
    // Block process-directed termination before any daemon worker can be
    // created. Every in-process thread then inherits the mask, leaving
    // signalfd as the sole shutdown consumer. Phase-dispatcher and Proxy
    // Engine children explicitly restore a clean mask before exec.
    let shutdown = ShutdownSignal::install()
        .map_err(|error| DaemonError::Socket(ControlSocketError::Platform(error)))?;
    let profile = Arc::new(profile_source.collect_capability_profile());
    let (
        control,
        runtime,
        address_reconciliation_attachment,
        subscription_client,
        file_observation,
    ) = match profile.legacy_mutation_gate() {
        LegacyMutationGate::Allowed => {
            let boot_identity =
                profile
                    .boot_identity()
                    .verified()
                    .cloned()
                    .ok_or(DaemonError::Invariant(
                        "legacy mutation gate allowed startup without a verified boot identity",
                    ))?;
            let phase_paths = options.phase_dispatcher_paths();
            let mut startup_recovery = ProcessPhaseDispatcher::new(phase_paths.clone());
            startup_recovery
                .execute(DispatcherPhaseCommand::StartupRecover)
                .map_err(|error| {
                    DaemonError::Control(ControlError::runtime(
                        "recover stale runtime before daemon admission",
                        error,
                        "repair the dispatcher ownership evidence and restart fluxd",
                    ))
                })?;
            // Startup recovery relies only on immutable generation artifacts
            // and ownership records. It must run before parsing the current
            // user configuration so a broken edit cannot strand same-boot
            // capture. Once recovery succeeds, the strict user configuration
            // becomes authoritative for the new runtime.
            let config = FluxConfig::load(&options.config_path).map_err(DaemonError::FluxConfig)?;
            let observation_paths =
                file_observation_paths(&options.config_path, &options.disable_path, &config);
            let observation_baseline = ObservedInputsFingerprint::capture(&observation_paths)
                .map_err(DaemonError::Configuration)?;
            let queue_capacity = usize::try_from(config.daemon().event_queue_capacity().get())
                .map_err(|_| {
                    DaemonError::Configuration(
                        "daemon.event_queue_capacity does not fit this target".to_owned(),
                    )
                })?;
            let store = AdministrativeIntentStore::new(&options.intent_path, boot_identity);
            let disable_present =
                inspect_disable_path(&options.disable_path).map_err(DaemonError::Configuration)?;
            let initial_intent = initial_intent(&store, disable_present)?;
            let subscription_working_directory = options
                .engine_manifest_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .ok_or_else(|| {
                    DaemonError::Configuration(
                        "engine manifest path has no subscription working directory".to_owned(),
                    )
                })?;
            let subscription = SubscriptionRefreshRuntime::start(SubscriptionRuntimePaths::new(
                &options.config_path,
                &options.subscription_store_path,
                subscription_working_directory,
                options
                    .engine_manifest_path
                    .with_file_name("subscription-check.log"),
            ))
            .map_err(|error| {
                DaemonError::Configuration(format!("cannot start subscription runtime: {error}"))
            })?;
            let bootstrap_digest = subscription.bootstrap_digest;
            let subscription_client = subscription.client.clone();
            let writer = ProcessRuntimeWriter::new(
                phase_paths,
                &options.engine_manifest_path,
                &options.config_path,
                &options.engine_config_path,
                &options.bridge_environment_path,
            )
            .with_subscription_source(subscription.active);
            let maintenance_interval =
                engine_maintenance_interval(config.daemon().reconcile_debounce().get());
            let (address_reconciliation_attachment, address_reconciler) =
                AddressReconciler::deferred(&options.config_path);
            let dispatcher = RuntimeCoordinator::with_dependencies(
                writer,
                EngineSupervisor::new(),
                maintenance_interval,
                RuntimeFunctionalCanary::StructuralOnlyCompatibility,
            )
            .with_address_reconciler(address_reconciler)
            .with_subscription_runtime(subscription.runtime);
            let runtime = dispatcher.runtime_snapshot_source();
            let dispatcher = PersistingLegacyDispatcher { dispatcher, store };
            let bridge = LegacyControlBridge::start(dispatcher, queue_capacity)
                .map_err(DaemonError::Control)?;
            let admission = bridge
                .submit(initial_intent)
                .and_then(flux_core::OperationHandle::wait);
            if let Err(admission_error) = admission {
                if let Some(digest) = bootstrap_digest
                    && let Err(rollback_error) = subscription_client.reject_bootstrap(digest)
                {
                    return Err(DaemonError::Configuration(format!(
                        "initial runtime admission failed ({admission_error}); cannot restore the unadmitted subscription snapshot ({rollback_error})"
                    )));
                }
                return Err(DaemonError::Control(admission_error));
            }
            if let Some(digest) = bootstrap_digest {
                subscription_client
                    .accept_bootstrap(digest)
                    .map_err(|error| {
                        DaemonError::Configuration(format!(
                            "initial runtime was admitted but the subscription worker could not commit its startup snapshot: {error}"
                        ))
                    })?;
            }
            let observation_ingress = bridge.observation_ingress().map_err(DaemonError::Control)?;
            let observation_controller = FileObservationController {
                desired_state_path: options.config_path.clone(),
                disable_path: options.disable_path.clone(),
                effective_disabled: disable_present,
                disable_path_invalid: false,
                initial_inputs: Some(observation_baseline),
                ingress: observation_ingress,
            };
            (
                DaemonControl::Bridge(bridge),
                runtime,
                Some(address_reconciliation_attachment),
                Some(subscription_client),
                Some((observation_paths, observation_controller)),
            )
        }
        LegacyMutationGate::ReadOnly { .. } => (
            DaemonControl::ReadOnly,
            RuntimeSnapshotSource::default(),
            None,
            None,
            None,
        ),
    };

    let inspection = Arc::new(ProcessInspectionSource::new(
        &options.config_path,
        &options.engine_manifest_path,
    ));
    let handler = ControlConnectionHandler::with_runtime_subscription_and_inspection(
        Arc::clone(&profile),
        control,
        runtime,
        subscription_client,
        inspection,
    );
    let serve_connection = move |connection| {
        if let Err(error) = handler.serve(connection) {
            eprintln!("fluxd: rejected control connection: {error}");
        }
    };
    let network_inventory_enabled = address_reconciliation_attachment.is_some();
    let (mut reactor, _stop, network_inventory) = if network_inventory_enabled {
        DaemonReactor::bind_with_network_inventory(
            &options.socket_path,
            shutdown,
            serve_connection,
            |degradation| {
                eprintln!("fluxd: network inventory observation disabled: {degradation}");
            },
        )
    } else {
        DaemonReactor::bind(&options.socket_path, shutdown, serve_connection)
            .map(|(reactor, stop)| (reactor, stop, None))
    }
    .map_err(ControlSocketError::Reactor)
    .map_err(DaemonError::Socket)?;
    if let (Some(attachment), Some(source)) = (address_reconciliation_attachment, network_inventory)
    {
        attachment.attach(source).map_err(|_| {
            DaemonError::Invariant(
                "network inventory source was attached more than once before reactor startup",
            )
        })?;
    }
    if let Some((paths, mut controller)) = file_observation {
        reactor
            .attach_file_observation(
                &paths,
                move |observation| controller.observe(observation),
                |error| {
                    eprintln!("fluxd: file observation interrupted; retrying: {error}");
                },
            )
            .map_err(ControlSocketError::Reactor)
            .map_err(DaemonError::Socket)?;
    }
    reactor
        .run()
        .map_err(ControlSocketError::Reactor)
        .map_err(DaemonError::Socket)
}

enum DaemonControl {
    Bridge(LegacyControlBridge),
    ReadOnly,
}

impl ControlClient for DaemonControl {
    fn submit_and_wait(&self, intent: LegacyIntent) -> Result<OperationReport, ControlError> {
        match self {
            Self::Bridge(bridge) => bridge.submit_and_wait(intent),
            Self::ReadOnly => Err(ControlError::BridgeStopped),
        }
    }
}

impl ControlSnapshotSource for DaemonControl {
    fn snapshot(&self) -> Arc<ControlSnapshot> {
        match self {
            Self::Bridge(bridge) => bridge.snapshot(),
            Self::ReadOnly => Arc::new(ControlSnapshot::default()),
        }
    }
}

impl ConfigurationChangeClient for DaemonControl {
    fn configuration_changed(
        &self,
        reason: Reason,
    ) -> Result<ConfigurationChangeReport, ControlError> {
        match self {
            Self::Bridge(bridge) => bridge.configuration_changed(reason),
            Self::ReadOnly => Err(ControlError::BridgeStopped),
        }
    }
}

struct PersistingLegacyDispatcher<D> {
    dispatcher: D,
    store: AdministrativeIntentStore,
}

impl<D> LegacyDispatcher for PersistingLegacyDispatcher<D>
where
    D: LegacyDispatcher,
{
    fn execute(&mut self, intent: &LegacyIntent) -> Result<(), ControlError> {
        let state = match intent {
            LegacyIntent::Running { .. } => Some(AdministrativeState::Running),
            LegacyIntent::Stopped { .. } => Some(AdministrativeState::Stopped),
            LegacyIntent::Reload { .. } | LegacyIntent::ResyncAddresses { .. } => None,
        };
        if let Some(state) = state {
            self.store.persist(state).map_err(|error| {
                ControlError::persistence(
                    "write administrative intent",
                    error,
                    "repair the Flux state directory and restart fluxd",
                )
            })?;
        }
        self.dispatcher.execute(intent)
    }

    fn observation_failed(&mut self, observation: ControlObservation, error: &ControlError) {
        let fact = match observation {
            ControlObservation::ConfigurationInputsChanged => "configuration input change",
            ControlObservation::DisableStateChanged { disabled: true } => "disable activation",
            ControlObservation::DisableStateChanged { disabled: false } => "disable removal",
        };
        eprintln!("fluxd: observed {fact} could not be reconciled: {error}");
    }

    fn configuration_inputs_consumed(&mut self) {
        self.dispatcher.configuration_inputs_consumed();
    }

    fn maintenance_interval(&self) -> Option<Duration> {
        self.dispatcher.maintenance_interval()
    }

    fn maintain(&mut self) {
        self.dispatcher.maintain();
    }

    fn shutdown(&mut self) {
        self.dispatcher.shutdown();
    }
}

struct FileObservationController {
    desired_state_path: PathBuf,
    disable_path: PathBuf,
    effective_disabled: bool,
    disable_path_invalid: bool,
    initial_inputs: Option<ObservedInputsFingerprint>,
    ingress: ControlObservationIngress,
}

impl FileObservationController {
    fn observe(&mut self, observation: FileObservationBatch) -> Option<FileObservationPaths> {
        if observation.disable_state_changed() {
            let disabled = match inspect_disable_path(&self.disable_path) {
                Ok(disabled) => {
                    self.disable_path_invalid = false;
                    disabled
                }
                Err(error) => {
                    if !self.disable_path_invalid {
                        eprintln!("fluxd: {error}; treating the module as disabled");
                    }
                    self.disable_path_invalid = true;
                    true
                }
            };
            if disabled != self.effective_disabled {
                if let Err(error) = self
                    .ingress
                    .submit(ControlObservation::DisableStateChanged { disabled })
                {
                    eprintln!("fluxd: cannot enqueue observed disable state: {error}");
                } else {
                    self.effective_disabled = disabled;
                }
            }
        }

        if !observation.configuration_inputs_changed() {
            return None;
        }
        match FluxConfig::load(&self.desired_state_path) {
            Ok(config) => {
                let paths = FileObservationPaths::new(
                    &self.desired_state_path,
                    config.engine().template(),
                    config.subscription().url_file(),
                    &self.disable_path,
                );
                let changed = self.initial_inputs.take().is_none_or(|baseline| {
                    ObservedInputsFingerprint::capture(&paths)
                        .map_or(true, |current| current != baseline)
                });
                if changed {
                    self.submit_configuration_observation();
                }
                Some(paths)
            }
            Err(error) => {
                self.initial_inputs.take();
                self.submit_configuration_observation();
                eprintln!(
                    "fluxd: cannot refresh observed paths from {}: {error}",
                    self.desired_state_path.display()
                );
                None
            }
        }
    }

    fn submit_configuration_observation(&self) {
        if let Err(error) = self
            .ingress
            .submit(ControlObservation::ConfigurationInputsChanged)
        {
            eprintln!("fluxd: cannot enqueue observed configuration change: {error}");
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedInputsFingerprint {
    desired_state: ObservedFileStamp,
    engine_template: ObservedFileStamp,
    subscription_url: ObservedFileStamp,
}

impl ObservedInputsFingerprint {
    fn capture(paths: &FileObservationPaths) -> Result<Self, String> {
        Ok(Self {
            desired_state: ObservedFileStamp::capture(paths.desired_state())?,
            engine_template: ObservedFileStamp::capture(paths.engine_template())?,
            subscription_url: ObservedFileStamp::capture(paths.subscription_url())?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ObservedFileStamp {
    Missing,
    Present(ObservedFileMetadata),
}

impl ObservedFileStamp {
    fn capture(path: &Path) -> Result<Self, String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => Ok(Self::Present(ObservedFileMetadata::from_metadata(
                &metadata,
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::Missing),
            Err(error) => Err(format!(
                "cannot fingerprint observed input {}: {error}",
                path.display()
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedFileMetadata {
    kind: ObservedFileKind,
    length: u64,
    modified: Option<SystemTime>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    device: u64,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    inode: u64,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    changed_seconds: i64,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    changed_nanoseconds: i64,
}

impl ObservedFileMetadata {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        let file_type = metadata.file_type();
        Self {
            kind: if file_type.is_file() {
                ObservedFileKind::Regular
            } else if file_type.is_dir() {
                ObservedFileKind::Directory
            } else if file_type.is_symlink() {
                ObservedFileKind::SymbolicLink
            } else {
                ObservedFileKind::Other
            },
            length: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            device: metadata.dev(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            inode: metadata.ino(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            changed_seconds: metadata.ctime(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservedFileKind {
    Regular,
    Directory,
    SymbolicLink,
    Other,
}

fn file_observation_paths(
    desired_state_path: &Path,
    disable_path: &Path,
    config: &FluxConfig,
) -> FileObservationPaths {
    FileObservationPaths::new(
        desired_state_path,
        config.engine().template(),
        config.subscription().url_file(),
        disable_path,
    )
}

fn inspect_disable_path(disable_path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(disable_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "disable path {} must not be a symbolic link",
            disable_path.display()
        )),
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(format!(
            "disable path {} exists but is not a file",
            disable_path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "cannot inspect disable path {}: {error}",
            disable_path.display()
        )),
    }
}

fn initial_intent(
    store: &AdministrativeIntentStore,
    disable_present: bool,
) -> Result<LegacyIntent, DaemonError> {
    if disable_present {
        return Ok(LegacyIntent::Stopped {
            reason: Reason::DisableCreated,
        });
    }
    match store.load().map_err(DaemonError::Intent)? {
        AdministrativeState::Running => Ok(LegacyIntent::Running {
            reason: Reason::DaemonRecovery,
        }),
        AdministrativeState::Stopped => Ok(LegacyIntent::Stopped {
            reason: Reason::DaemonRecovery,
        }),
        AdministrativeState::Unknown => Ok(LegacyIntent::Running {
            reason: Reason::Boot,
        }),
    }
}

#[derive(Debug)]
pub enum DaemonError {
    Configuration(String),
    FluxConfig(ConfigError),
    Invariant(&'static str),
    Intent(IntentStoreError),
    Lease(DaemonLeaseError),
    Control(ControlError),
    Socket(ControlSocketError),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => write!(formatter, "daemon configuration: {message}"),
            Self::FluxConfig(error) => write!(formatter, "daemon configuration: {error}"),
            Self::Invariant(message) => write!(formatter, "daemon invariant: {message}"),
            Self::Intent(error) => write!(formatter, "administrative intent: {error}"),
            Self::Lease(error) => write!(formatter, "daemon exclusion: {error}"),
            Self::Control(error) => write!(formatter, "control bridge: {error}"),
            Self::Socket(error) => error.fmt(formatter),
        }
    }
}

impl Error for DaemonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FluxConfig(error) => Some(error),
            Self::Control(error) => Some(error),
            Self::Intent(error) => Some(error),
            Self::Lease(error) => Some(error),
            Self::Socket(error) => Some(error),
            Self::Configuration(_) | Self::Invariant(_) => None,
        }
    }
}

fn default_shell() -> PathBuf {
    if cfg!(target_os = "android") {
        PathBuf::from("/system/bin/sh")
    } else {
        PathBuf::from("/bin/sh")
    }
}

fn engine_maintenance_interval(configured: Duration) -> Duration {
    configured.clamp(
        MIN_ENGINE_MAINTENANCE_INTERVAL,
        MAX_ENGINE_MAINTENANCE_INTERVAL,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_maintenance_interval_is_bounded_independently_of_config_debounce() {
        assert_eq!(
            engine_maintenance_interval(Duration::from_millis(1)),
            MIN_ENGINE_MAINTENANCE_INTERVAL
        );
        assert_eq!(
            engine_maintenance_interval(Duration::from_secs(u64::from(u32::MAX))),
            MAX_ENGINE_MAINTENANCE_INTERVAL
        );
    }
}
