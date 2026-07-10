use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use flux_core::{
    ControlClient, ControlError, KernelSupport, LegacyControlBridge, LegacyIntent, OperationReport,
};
use flux_platform::{KernelReleaseSource, LegacyScriptPaths, ProcessLegacyDispatcher};

use crate::{ControlSocketError, ControlSocketServer};

const DEFAULT_ROOT: &str = "/data/adb/flux";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonOptions {
    pub socket_path: PathBuf,
    pub shell: PathBuf,
    pub dispatcher_script: PathBuf,
    pub addrsync_script: PathBuf,
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
            queue_capacity,
        })
    }
}

pub fn run_daemon<S>(kernel_source: &S, options: DaemonOptions) -> Result<(), DaemonError>
where
    S: KernelReleaseSource,
{
    let release = kernel_source
        .kernel_release()
        .map_err(|error| DaemonError::Kernel(error.to_string()))?;
    let kernel_support = KernelSupport::evaluate(&release)
        .map_err(|error| DaemonError::Kernel(error.to_string()))?;
    let control = match kernel_support {
        KernelSupport::Supported(_) => {
            let dispatcher = ProcessLegacyDispatcher::new(LegacyScriptPaths {
                shell: options.shell,
                shell_args: Vec::<OsString>::new(),
                dispatcher: options.dispatcher_script,
                addrsync: options.addrsync_script,
            });
            DaemonControl::Bridge(
                LegacyControlBridge::start(dispatcher, options.queue_capacity)
                    .map_err(DaemonError::Control)?,
            )
        }
        KernelSupport::Unsupported { .. } => DaemonControl::Unsupported,
    };

    let server = ControlSocketServer::bind(&options.socket_path, kernel_support, control)
        .map_err(DaemonError::Socket)?;
    server.serve_forever().map_err(DaemonError::Socket)
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

#[derive(Debug)]
pub enum DaemonError {
    Configuration(String),
    Kernel(String),
    Control(ControlError),
    Socket(ControlSocketError),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => write!(formatter, "daemon configuration: {message}"),
            Self::Kernel(message) => write!(formatter, "kernel capability: {message}"),
            Self::Control(error) => write!(formatter, "control bridge: {error}"),
            Self::Socket(error) => error.fmt(formatter),
        }
    }
}

impl Error for DaemonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Control(error) => Some(error),
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
