use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use flux_core::{
    AdministrativeState, CapabilityProfileSource, ConfigError, ConfigurationChangeClient,
    ConfigurationChangeReport, ControlClient, ControlError, ControlSnapshot, ControlSnapshotSource,
    FluxConfig, LegacyControlBridge, LegacyDispatcher, LegacyIntent, LegacyMutationGate,
    OperationReport, Reason,
};
use flux_platform::{
    CapabilityProfilePaths, DaemonReactor, DispatcherPhaseCommand, PhaseDispatcherPaths,
    ProcessPhaseDispatcher, ShutdownSignal,
};

use crate::runtime_coordinator::{ProcessRuntimeWriter, RuntimeCoordinator};
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
    pub config_path: PathBuf,
    pub shell: PathBuf,
    pub dispatcher_script: PathBuf,
    pub addrsync_script: PathBuf,
    pub engine_manifest_path: PathBuf,
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
            config_path,
            shell,
            dispatcher_script: root.join("scripts/dispatcher"),
            addrsync_script: root.join("scripts/addrsync"),
            engine_manifest_path: root.join("run/engine.manifest"),
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
}

pub fn run_daemon<S>(profile_source: &S, options: DaemonOptions) -> Result<(), DaemonError>
where
    S: CapabilityProfileSource,
{
    // Block process-directed termination before any daemon worker can be
    // created. Every in-process thread then inherits the mask, leaving
    // signalfd as the sole shutdown consumer. Phase-dispatcher and Proxy
    // Engine children explicitly restore a clean mask before exec.
    let shutdown = ShutdownSignal::install()
        .map_err(|error| DaemonError::Socket(ControlSocketError::Platform(error)))?;
    let profile = Arc::new(profile_source.collect_capability_profile());
    let (control, runtime) = match profile.legacy_mutation_gate() {
        LegacyMutationGate::Allowed => {
            let boot_identity =
                profile
                    .boot_identity()
                    .verified()
                    .cloned()
                    .ok_or(DaemonError::Invariant(
                        "legacy mutation gate allowed startup without a verified boot identity",
                    ))?;
            let phase_paths = PhaseDispatcherPaths {
                shell: options.shell,
                shell_args: Vec::<OsString>::new(),
                dispatcher: options.dispatcher_script,
            };
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
            let queue_capacity = usize::try_from(config.daemon().event_queue_capacity().get())
                .map_err(|_| {
                    DaemonError::Configuration(
                        "daemon.event_queue_capacity does not fit this target".to_owned(),
                    )
                })?;
            let store = AdministrativeIntentStore::new(&options.intent_path, boot_identity);
            let initial_intent = initial_intent(&store, &options.disable_path)?;
            let writer = ProcessRuntimeWriter::new(phase_paths, &options.engine_manifest_path);
            let maintenance_interval =
                engine_maintenance_interval(config.daemon().reconcile_debounce().get());
            let dispatcher = RuntimeCoordinator::with_dependencies(
                writer,
                EngineSupervisor::new(),
                maintenance_interval,
            );
            let runtime = dispatcher.runtime_snapshot_source();
            let dispatcher = PersistingLegacyDispatcher { dispatcher, store };
            let bridge = LegacyControlBridge::start(dispatcher, queue_capacity)
                .map_err(DaemonError::Control)?;
            bridge
                .submit(initial_intent)
                .map_err(DaemonError::Control)?
                .wait()
                .map_err(DaemonError::Control)?;
            (DaemonControl::Bridge(bridge), runtime)
        }
        LegacyMutationGate::ReadOnly { .. } => {
            (DaemonControl::ReadOnly, RuntimeSnapshotSource::default())
        }
    };

    let handler = ControlConnectionHandler::with_runtime_snapshot_source(
        Arc::clone(&profile),
        control,
        runtime,
    );
    let (reactor, _stop) = DaemonReactor::bind(&options.socket_path, shutdown, move |connection| {
        if let Err(error) = handler.serve(connection) {
            eprintln!("fluxd: rejected control connection: {error}");
        }
    })
    .map_err(ControlSocketError::Reactor)
    .map_err(DaemonError::Socket)?;
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

fn initial_intent(
    store: &AdministrativeIntentStore,
    disable_path: &PathBuf,
) -> Result<LegacyIntent, DaemonError> {
    match fs::symlink_metadata(disable_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(DaemonError::Configuration(format!(
                "disable path {} must not be a symbolic link",
                disable_path.display()
            )));
        }
        Ok(metadata) if metadata.is_file() => {
            return Ok(LegacyIntent::Stopped {
                reason: Reason::DisableCreated,
            });
        }
        Ok(_) => {
            return Err(DaemonError::Configuration(format!(
                "disable path {} exists but is not a file",
                disable_path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(DaemonError::Configuration(format!(
                "cannot inspect disable path {}: {error}",
                disable_path.display()
            )));
        }
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
