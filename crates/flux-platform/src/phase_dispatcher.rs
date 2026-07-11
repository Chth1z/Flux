use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_PHASE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_PHASE_TIMEOUT: Duration = Duration::from_secs(60);
const CLEANUP_GRACE: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatcherPhaseCommand {
    StartupRecover,
    Prepare,
    CaptureStart,
    CaptureStop,
    CaptureVerify,
    AddressResync,
    StateRunning,
    StateStopped,
    StateFailed,
}

impl DispatcherPhaseCommand {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StartupRecover => "startup-recover",
            Self::Prepare => "prepare",
            Self::CaptureStart => "capture-start",
            Self::CaptureStop => "capture-stop",
            Self::CaptureVerify => "capture-verify",
            Self::AddressResync => "address-resync",
            Self::StateRunning => "state-running",
            Self::StateStopped => "state-stopped",
            Self::StateFailed => "state-failed",
        }
    }
}

impl fmt::Display for DispatcherPhaseCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseDispatcherPaths {
    pub shell: PathBuf,
    pub shell_args: Vec<OsString>,
    pub dispatcher: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseDispatcherErrorKind {
    InvalidTimeout,
    ChildSetup,
    Spawn,
    Wait,
    NonZeroExit,
    TimedOut,
}

#[derive(Debug)]
pub enum PhaseDispatcherError {
    InvalidTimeout {
        command: DispatcherPhaseCommand,
        timeout: Duration,
        maximum: Duration,
    },
    ChildSetup {
        command: DispatcherPhaseCommand,
        source: io::Error,
    },
    Spawn {
        command: DispatcherPhaseCommand,
        shell: PathBuf,
        dispatcher: PathBuf,
        source: io::Error,
    },
    Wait {
        command: DispatcherPhaseCommand,
        pid: u32,
        source: io::Error,
    },
    NonZeroExit {
        command: DispatcherPhaseCommand,
        status: ExitStatus,
    },
    TimedOut {
        command: DispatcherPhaseCommand,
        timeout: Duration,
        cleanup_error: Option<io::Error>,
    },
}

impl PhaseDispatcherError {
    #[must_use]
    pub const fn kind(&self) -> PhaseDispatcherErrorKind {
        match self {
            Self::InvalidTimeout { .. } => PhaseDispatcherErrorKind::InvalidTimeout,
            Self::ChildSetup { .. } => PhaseDispatcherErrorKind::ChildSetup,
            Self::Spawn { .. } => PhaseDispatcherErrorKind::Spawn,
            Self::Wait { .. } => PhaseDispatcherErrorKind::Wait,
            Self::NonZeroExit { .. } => PhaseDispatcherErrorKind::NonZeroExit,
            Self::TimedOut { .. } => PhaseDispatcherErrorKind::TimedOut,
        }
    }
}

impl fmt::Display for PhaseDispatcherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimeout {
                command,
                timeout,
                maximum,
            } => write!(
                formatter,
                "dispatcher phase {command} timeout {timeout:?} must be nonzero and at most {maximum:?}"
            ),
            Self::ChildSetup { command, source } => write!(
                formatter,
                "cannot initialize child process for dispatcher phase {command}: {source}"
            ),
            Self::Spawn {
                command,
                shell,
                dispatcher,
                source,
            } => write!(
                formatter,
                "cannot execute dispatcher phase {command} using {} {}: {source}",
                shell.display(),
                dispatcher.display()
            ),
            Self::Wait {
                command,
                pid,
                source,
            } => write!(
                formatter,
                "cannot poll dispatcher phase {command} child {pid}: {source}"
            ),
            Self::NonZeroExit { command, status } => {
                write!(formatter, "dispatcher phase {command} exited with {status}")
            }
            Self::TimedOut {
                command,
                timeout,
                cleanup_error: None,
            } => write!(
                formatter,
                "dispatcher phase {command} timed out after {timeout:?}"
            ),
            Self::TimedOut {
                command,
                timeout,
                cleanup_error: Some(cleanup_error),
            } => write!(
                formatter,
                "dispatcher phase {command} timed out after {timeout:?}; cleanup failed: {cleanup_error}"
            ),
        }
    }
}

impl Error for PhaseDispatcherError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ChildSetup { source, .. }
            | Self::Spawn { source, .. }
            | Self::Wait { source, .. } => Some(source),
            Self::TimedOut {
                cleanup_error: Some(source),
                ..
            } => Some(source),
            Self::InvalidTimeout { .. } | Self::NonZeroExit { .. } | Self::TimedOut { .. } => None,
        }
    }
}

#[derive(Debug)]
pub struct ProcessPhaseDispatcher {
    paths: PhaseDispatcherPaths,
}

impl ProcessPhaseDispatcher {
    #[must_use]
    pub const fn new(paths: PhaseDispatcherPaths) -> Self {
        Self { paths }
    }

    pub fn execute(&mut self, command: DispatcherPhaseCommand) -> Result<(), PhaseDispatcherError> {
        self.execute_with_arguments(command, DEFAULT_PHASE_TIMEOUT, &[])
    }

    pub fn execute_for_generation(
        &mut self,
        command: DispatcherPhaseCommand,
        generation: NonZeroU32,
    ) -> Result<(), PhaseDispatcherError> {
        self.execute_with_arguments(
            command,
            DEFAULT_PHASE_TIMEOUT,
            &[OsString::from(generation.get().to_string())],
        )
    }

    pub fn execute_with_timeout(
        &mut self,
        command: DispatcherPhaseCommand,
        timeout: Duration,
    ) -> Result<(), PhaseDispatcherError> {
        self.execute_with_arguments(command, timeout, &[])
    }

    fn execute_with_arguments(
        &mut self,
        command: DispatcherPhaseCommand,
        timeout: Duration,
        arguments: &[OsString],
    ) -> Result<(), PhaseDispatcherError> {
        if timeout.is_zero() || timeout > MAX_PHASE_TIMEOUT {
            return Err(PhaseDispatcherError::InvalidTimeout {
                command,
                timeout,
                maximum: MAX_PHASE_TIMEOUT,
            });
        }
        let mut process = Command::new(&self.paths.shell);
        process
            .args(&self.paths.shell_args)
            .arg(&self.paths.dispatcher)
            .arg(command.as_str())
            .args(arguments)
            .env("FLUXD_BRIDGE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        crate::child_process::configure_child_process(
            &mut process,
            crate::child_process::ChildProcessConfig {
                new_process_group: true,
                // PDEATHSIG applies to this direct shell child only; commands
                // that it forks do not inherit the setting. Group-wide crash
                // containment remains a separate process-cgroup hardening
                // step, while timeout cleanup already targets the group.
                kill_on_parent_death: true,
                ..crate::child_process::ChildProcessConfig::default()
            },
        )
        .map_err(|source| PhaseDispatcherError::ChildSetup { command, source })?;

        let mut child = process
            .spawn()
            .map_err(|source| PhaseDispatcherError::Spawn {
                command,
                shell: self.paths.shell.clone(),
                dispatcher: self.paths.dispatcher.clone(),
                source,
            })?;
        let pid = child.id();
        let deadline = Instant::now().checked_add(timeout);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if deadline.is_some_and(|deadline| Instant::now() < deadline) => {
                    sleep_until_poll(deadline.expect("checked above"));
                }
                Ok(None) => {
                    let cleanup_error = cleanup_timed_out_child(child);
                    return Err(PhaseDispatcherError::TimedOut {
                        command,
                        timeout,
                        cleanup_error,
                    });
                }
                Err(source) => {
                    let _ = cleanup_timed_out_child(child);
                    return Err(PhaseDispatcherError::Wait {
                        command,
                        pid,
                        source,
                    });
                }
            }
        };
        if status.success() {
            Ok(())
        } else {
            Err(PhaseDispatcherError::NonZeroExit { command, status })
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn cleanup_timed_out_child(mut child: Child) -> Option<io::Error> {
    use crate::child_process::ProcessSignal;

    let process_group = child.id();
    let _ = signal_process_group_if_present(process_group, ProcessSignal::Terminate);
    if matches!(
        wait_for_process_group_cleanup(&mut child, process_group, CLEANUP_GRACE),
        Ok(true)
    ) {
        return None;
    }

    let kill_error = signal_process_group_if_present(process_group, ProcessSignal::Kill).err();
    match wait_for_process_group_cleanup(&mut child, process_group, CLEANUP_GRACE) {
        Ok(true) => None,
        Ok(false) => {
            defer_reap(child);
            Some(kill_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "dispatcher process group {process_group} remained live after SIGKILL for {CLEANUP_GRACE:?}"
                    ),
                )
            }))
        }
        Err(source) => {
            defer_reap(child);
            Some(kill_error.unwrap_or(source))
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn signal_process_group_if_present(
    process_group: u32,
    signal: crate::child_process::ProcessSignal,
) -> io::Result<()> {
    match crate::child_process::signal_process_group(process_group, signal) {
        Ok(()) => Ok(()),
        Err(source) if crate::child_process::is_no_such_process(&source) => Ok(()),
        Err(source) => Err(source),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn wait_for_process_group_cleanup(
    child: &mut Child,
    process_group: u32,
    timeout: Duration,
) -> io::Result<bool> {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        let child_reaped = child.try_wait()?.is_some();
        let process_group_absent = !crate::child_process::process_group_exists(process_group)?;
        if child_reaped && process_group_absent {
            return Ok(true);
        }
        if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
            return Ok(false);
        }
        sleep_until_poll(deadline.expect("checked above"));
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn cleanup_timed_out_child(mut child: Child) -> Option<io::Error> {
    let kill_error = child.kill().err();
    let deadline = Instant::now().checked_add(CLEANUP_GRACE);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return kill_error,
            Ok(None) if deadline.is_some_and(|deadline| Instant::now() < deadline) => {
                sleep_until_poll(deadline.expect("checked above"));
            }
            Ok(None) => {
                defer_reap(child);
                return Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("child was not reaped within {CLEANUP_GRACE:?}"),
                ));
            }
            Err(source) => {
                defer_reap(child);
                return Some(source);
            }
        }
    }
}

fn sleep_until_poll(deadline: Instant) {
    thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
}

fn defer_reap(mut child: Child) {
    if let Ok(handle) = thread::Builder::new()
        .name(format!("flux-phase-reap-{}", child.id()))
        .spawn(move || {
            let _ = child.wait();
        })
    {
        drop(handle);
    }
}
