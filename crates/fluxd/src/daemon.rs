use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use flux_core::{
    AdministrativeState, ConfigurationChangeClient, ConfigurationChangeReport, ControlClient,
    ControlError, ControlSnapshot, ControlSnapshotSource, KernelSupport, LegacyControlBridge,
    LegacyDispatcher, LegacyIntent, OperationReport, Reason,
};
use flux_platform::{
    DaemonReactor, KernelReleaseSource, LegacyScriptPaths, ProcessLegacyDispatcher, ShutdownSignal,
};

use crate::{
    AdministrativeIntentStore, ControlConnectionHandler, ControlSocketError, IntentStoreError,
};

const DEFAULT_ROOT: &str = "/data/adb/flux";
const DEFAULT_DISABLE_PATH: &str = "/data/adb/modules/flux/disable";
const DEFAULT_BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonOptions {
    pub socket_path: PathBuf,
    pub shell: PathBuf,
    pub dispatcher_script: PathBuf,
    pub addrsync_script: PathBuf,
    pub intent_path: PathBuf,
    pub boot_id_path: PathBuf,
    pub disable_path: PathBuf,
    pub queue_capacity: usize,
}

impl DaemonOptions {
    pub fn from_environment() -> Result<Self, DaemonError> {
        let root = env::var_os("FLUX_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT));
        let socket_path = env::var_os("FLUXD_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("run/fluxd.sock"));
        let shell = env::var_os("FLUX_SHELL")
            .map(PathBuf::from)
            .unwrap_or_else(default_shell);
        let intent_path = env::var_os("FLUXD_INTENT_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("state/administrative-intent.json"));
        let boot_id_path = env::var_os("FLUX_BOOT_ID_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_BOOT_ID_PATH));
        let disable_path = env::var_os("FLUX_DISABLE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DISABLE_PATH));
        let queue_capacity = env::var("FLUXD_QUEUE_CAPACITY")
            .ok()
            .map(|value| {
                value.parse::<usize>().map_err(|_| {
                    DaemonError::Configuration(format!(
                        "FLUXD_QUEUE_CAPACITY '{value}' is not a positive integer"
                    ))
                })
            })
            .transpose()?
            .unwrap_or(64);
        if queue_capacity == 0 {
            return Err(DaemonError::Configuration(
                "FLUXD_QUEUE_CAPACITY must be greater than zero".to_owned(),
            ));
        }

        Ok(Self {
            socket_path,
            shell,
            dispatcher_script: root.join("scripts/dispatcher"),
            addrsync_script: root.join("scripts/addrsync"),
            intent_path,
            boot_id_path,
            disable_path,
            queue_capacity,
        })
    }
}

pub fn run_daemon<S>(kernel_source: &S, options: DaemonOptions) -> Result<(), DaemonError>
where
    S: KernelReleaseSource,
{
    // Block process-directed termination before any daemon worker can be
    // created. Every in-process thread then inherits the mask, leaving
    // signalfd as the sole shutdown consumer. Legacy children explicitly
    // restore a clean mask in ProcessLegacyDispatcher before exec.
    let shutdown = ShutdownSignal::install()
        .map_err(|error| DaemonError::Socket(ControlSocketError::Platform(error)))?;
    let release = kernel_source
        .kernel_release()
        .map_err(|error| DaemonError::Kernel(error.to_string()))?;
    let kernel_support = KernelSupport::evaluate(&release)
        .map_err(|error| DaemonError::Kernel(error.to_string()))?;
    let control = match kernel_support {
        KernelSupport::Supported(_) => {
            let store = AdministrativeIntentStore::new(&options.intent_path, &options.boot_id_path);
            let initial_intent = initial_intent(&store, &options.disable_path)?;
            let dispatcher = ProcessLegacyDispatcher::new(LegacyScriptPaths {
                shell: options.shell,
                shell_args: Vec::<OsString>::new(),
                dispatcher: options.dispatcher_script,
                addrsync: options.addrsync_script,
            });
            let dispatcher = PersistingLegacyDispatcher { dispatcher, store };
            let bridge = LegacyControlBridge::start(dispatcher, options.queue_capacity)
                .map_err(DaemonError::Control)?;
            bridge
                .submit(initial_intent)
                .map_err(DaemonError::Control)?
                .wait()
                .map_err(DaemonError::Control)?;
            DaemonControl::Bridge(bridge)
        }
        KernelSupport::Unsupported { .. } => DaemonControl::Unsupported,
    };

    let handler = ControlConnectionHandler::new(kernel_support, control);
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
    Unsupported,
}

impl ControlClient for DaemonControl {
    fn submit_and_wait(&self, intent: LegacyIntent) -> Result<OperationReport, ControlError> {
        match self {
            Self::Bridge(bridge) => bridge.submit_and_wait(intent),
            Self::Unsupported => Err(ControlError::BridgeStopped),
        }
    }
}

impl ControlSnapshotSource for DaemonControl {
    fn snapshot(&self) -> Arc<ControlSnapshot> {
        match self {
            Self::Bridge(bridge) => bridge.snapshot(),
            Self::Unsupported => Arc::new(ControlSnapshot::default()),
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
            Self::Unsupported => Err(ControlError::BridgeStopped),
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
    Kernel(String),
    Intent(IntentStoreError),
    Control(ControlError),
    Socket(ControlSocketError),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => write!(formatter, "daemon configuration: {message}"),
            Self::Kernel(message) => write!(formatter, "kernel capability: {message}"),
            Self::Intent(error) => write!(formatter, "administrative intent: {error}"),
            Self::Control(error) => write!(formatter, "control bridge: {error}"),
            Self::Socket(error) => error.fmt(formatter),
        }
    }
}

impl Error for DaemonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Control(error) => Some(error),
            Self::Intent(error) => Some(error),
            Self::Socket(error) => Some(error),
            Self::Configuration(_) | Self::Kernel(_) => None,
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
