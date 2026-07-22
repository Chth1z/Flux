use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::child_process::{self, ChildProcessConfig, ProcessSignal};
use crate::process::{ProcessHandle, ProcessHandleError, ProcessIdentity};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::collections::HashSet;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsRawFd;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::process::ExitStatusExt;

const DIAGNOSTIC_LIMIT: usize = 16 * 1024;
const CAPTURE_STREAM_LIMIT: usize = DIAGNOSTIC_LIMIT / 2;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const CLEANUP_GRACE: Duration = Duration::from_millis(250);
const INTERFACE_NAME_MAX_BYTES: usize = 15;

#[derive(Clone, Copy, Debug, Default)]
pub struct SingBoxProcessAdapter;

pub struct PinnedSingBoxLaunch {
    binary: File,
    config: File,
    busybox: Option<File>,
}

impl PinnedSingBoxLaunch {
    pub fn new(
        binary: File,
        config: File,
        busybox: Option<File>,
    ) -> Result<Self, SingBoxProcessError> {
        validate_pinned_descriptor("binary", &binary)?;
        validate_pinned_descriptor("config", &config)?;
        if let Some(busybox) = &busybox {
            validate_pinned_descriptor("busybox", busybox)?;
        }
        Ok(Self {
            binary,
            config,
            busybox,
        })
    }

    #[must_use]
    pub const fn binary(&self) -> &File {
        &self.binary
    }

    #[must_use]
    pub const fn config(&self) -> &File {
        &self.config
    }

    #[must_use]
    pub const fn busybox(&self) -> Option<&File> {
        self.busybox.as_ref()
    }
}

impl fmt::Debug for PinnedSingBoxLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedSingBoxLaunch")
            .field("binary", &self.binary)
            .field("config", &self.config)
            .field("busybox", &self.busybox)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingBoxLaunchSpec {
    pub binary: PathBuf,
    pub config: PathBuf,
    pub working_directory: PathBuf,
    pub log: PathBuf,
    pub launcher: SingBoxLauncher,
    pub readiness: SingBoxReadiness,
    pub startup_timeout: Duration,
    pub stop_timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SingBoxLauncher {
    Direct,
    BusyBoxSetuidgid {
        busybox: PathBuf,
        identity: OsString,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SingBoxReadiness {
    Listener { port: NonZeroU16 },
    TunInterface { name: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SingBoxChildIdentity {
    pid: u32,
    start_time_ticks: u64,
}

impl SingBoxChildIdentity {
    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }

    #[must_use]
    pub const fn start_time_ticks(self) -> u64 {
        self.start_time_ticks
    }
}

pub struct SingBoxChild {
    child: Option<Child>,
    identity: SingBoxChildIdentity,
    reaped_exit: Option<SingBoxExit>,
    log: File,
    log_path: PathBuf,
}

impl SingBoxChild {
    #[must_use]
    pub const fn identity(&self) -> &SingBoxChildIdentity {
        &self.identity
    }

    /// Open an exact child-origin process handle without transferring the
    /// supervisor's signaling or reap authority.
    ///
    /// The retained [`Child`] is the only accepted origin. The resulting
    /// pidfd/procfs identity is rechecked against the identity recorded when
    /// Sing-Box was spawned, so a copied PID or changed start time cannot be
    /// promoted into child authority.
    pub fn open_process_handle(&self) -> Result<ProcessHandle, ProcessHandleError> {
        let pid =
            NonZeroU32::new(self.identity.pid).ok_or(ProcessHandleError::InvalidChildPid {
                pid: self.identity.pid,
            })?;
        let child = self
            .child
            .as_ref()
            .ok_or(ProcessHandleError::Exited { pid })?;
        let handle = ProcessHandle::open_child(child)?;
        let start_time_ticks =
            NonZeroU64::new(self.identity.start_time_ticks).ok_or_else(|| {
                ProcessHandleError::MalformedProcStat {
                    path: PathBuf::from(format!("/proc/{pid}/stat")),
                }
            })?;
        let expected = ProcessIdentity::new(pid, start_time_ticks);
        let observed = handle.identity();
        if observed != expected {
            return Err(ProcessHandleError::ProcessIdentityMismatch { expected, observed });
        }
        Ok(handle)
    }
}

impl fmt::Debug for SingBoxChild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SingBoxChild")
            .field("identity", &self.identity)
            .field("reaped_exit", &self.reaped_exit)
            .field("log_path", &self.log_path)
            .finish_non_exhaustive()
    }
}

impl Drop for SingBoxChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _ = signal_identity(self.identity, ProcessSignal::Kill);
                defer_reap(child, self.identity.pid);
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProcessDiagnostics {
    stdout_tail: String,
    stderr_tail: String,
    log_tail: String,
}

impl ProcessDiagnostics {
    #[must_use]
    pub fn stdout_tail(&self) -> &str {
        &self.stdout_tail
    }

    #[must_use]
    pub fn stderr_tail(&self) -> &str {
        &self.stderr_tail
    }

    #[must_use]
    pub fn log_tail(&self) -> &str {
        &self.log_tail
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stdout_tail.is_empty() && self.stderr_tail.is_empty() && self.log_tail.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationReport {
    pub exit: SingBoxExit,
    pub diagnostics: ProcessDiagnostics,
}

/// Exact bounded output from `sing-box version` executed through pinned launch artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingBoxVersionReport {
    stdout: Box<[u8]>,
    stderr: Box<[u8]>,
}

impl SingBoxVersionReport {
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadinessEvidence {
    Listener { port: NonZeroU16, table: PathBuf },
    TunInterface { name: String, path: PathBuf },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SingBoxExit {
    Code(i32),
    Signal(i32),
    Unknown,
}

impl fmt::Display for SingBoxExit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code(code) => write!(formatter, "exit code {code}"),
            Self::Signal(signal) => write!(formatter, "signal {signal}"),
            Self::Unknown => formatter.write_str("unknown exit status"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminationOutcome {
    AlreadyExited { exit: SingBoxExit },
    Terminated { exit: SingBoxExit },
    Killed { exit: SingBoxExit },
}

#[derive(Debug)]
pub enum SingBoxProcessError {
    UnsupportedPlatform {
        platform: &'static str,
    },
    InvalidSpec {
        field: &'static str,
        detail: String,
    },
    OpenLog {
        path: PathBuf,
        source: io::Error,
    },
    Spawn {
        program: PathBuf,
        source: io::Error,
    },
    ReadChildIdentity {
        pid: u32,
        source: io::Error,
    },
    PinnedDescriptor {
        role: &'static str,
        source: io::Error,
    },
    Wait {
        pid: u32,
        source: io::Error,
    },
    Signal {
        pid: u32,
        signal: i32,
        source: io::Error,
    },
    Capture {
        stream: &'static str,
        source: io::Error,
    },
    CaptureWorkerSpawn {
        stream: &'static str,
        source: io::Error,
    },
    CaptureThreadPanicked {
        stream: &'static str,
    },
    ValidationGroupSignal {
        process_group: u32,
        signal: i32,
        source: io::Error,
        diagnostics: ProcessDiagnostics,
    },
    ValidationGroupCleanupTimedOut {
        process_group: u32,
        timeout: Duration,
        diagnostics: ProcessDiagnostics,
    },
    CheckFailed {
        exit: SingBoxExit,
        diagnostics: ProcessDiagnostics,
    },
    CheckTimedOut {
        timeout: Duration,
        diagnostics: ProcessDiagnostics,
    },
    VersionFailed {
        exit: SingBoxExit,
        diagnostics: ProcessDiagnostics,
    },
    VersionTimedOut {
        timeout: Duration,
        diagnostics: ProcessDiagnostics,
    },
    VersionOutputTooLarge {
        stream: &'static str,
        maximum: usize,
        actual: usize,
    },
    ExitedBeforeReady {
        exit: SingBoxExit,
        diagnostics: ProcessDiagnostics,
    },
    ReadinessTimedOut {
        timeout: Duration,
        diagnostics: ProcessDiagnostics,
    },
    PostSignalReapTimedOut {
        identity: SingBoxChildIdentity,
        signal: i32,
        timeout: Duration,
        diagnostics: ProcessDiagnostics,
    },
    ReadinessProbe {
        path: PathBuf,
        source: io::Error,
    },
}

impl SingBoxProcessError {
    #[must_use]
    pub const fn diagnostics(&self) -> Option<&ProcessDiagnostics> {
        match self {
            Self::CheckFailed { diagnostics, .. }
            | Self::CheckTimedOut { diagnostics, .. }
            | Self::VersionFailed { diagnostics, .. }
            | Self::VersionTimedOut { diagnostics, .. }
            | Self::ExitedBeforeReady { diagnostics, .. }
            | Self::ReadinessTimedOut { diagnostics, .. }
            | Self::PostSignalReapTimedOut { diagnostics, .. }
            | Self::ValidationGroupSignal { diagnostics, .. }
            | Self::ValidationGroupCleanupTimedOut { diagnostics, .. } => Some(diagnostics),
            Self::UnsupportedPlatform { .. }
            | Self::InvalidSpec { .. }
            | Self::OpenLog { .. }
            | Self::Spawn { .. }
            | Self::ReadChildIdentity { .. }
            | Self::PinnedDescriptor { .. }
            | Self::Wait { .. }
            | Self::Signal { .. }
            | Self::Capture { .. }
            | Self::CaptureWorkerSpawn { .. }
            | Self::CaptureThreadPanicked { .. }
            | Self::VersionOutputTooLarge { .. }
            | Self::ReadinessProbe { .. } => None,
        }
    }
}

impl fmt::Display for SingBoxProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform { platform } => {
                write!(
                    formatter,
                    "Sing-Box process control is unsupported on '{platform}'"
                )
            }
            Self::InvalidSpec { field, detail } => {
                write!(
                    formatter,
                    "invalid Sing-Box launch field '{field}': {detail}"
                )
            }
            Self::OpenLog { path, source } => {
                write!(
                    formatter,
                    "cannot open Sing-Box log {}: {source}",
                    path.display()
                )
            }
            Self::Spawn { program, source } => {
                write!(formatter, "cannot spawn {}: {source}", program.display())
            }
            Self::ReadChildIdentity { pid, source } => {
                write!(
                    formatter,
                    "cannot establish identity for child {pid}: {source}"
                )
            }
            Self::PinnedDescriptor { role, source } => {
                write!(
                    formatter,
                    "invalid pinned Sing-Box {role} descriptor: {source}"
                )
            }
            Self::Wait { pid, source } => write!(formatter, "cannot poll child {pid}: {source}"),
            Self::Signal {
                pid,
                signal,
                source,
            } => write!(
                formatter,
                "cannot send signal {signal} to child {pid}: {source}"
            ),
            Self::Capture { stream, source } => {
                write!(formatter, "cannot capture Sing-Box {stream}: {source}")
            }
            Self::CaptureWorkerSpawn { stream, source } => {
                write!(
                    formatter,
                    "cannot start Sing-Box {stream} capture worker: {source}"
                )
            }
            Self::CaptureThreadPanicked { stream } => {
                write!(formatter, "Sing-Box {stream} capture worker panicked")
            }
            Self::ValidationGroupSignal {
                process_group,
                signal,
                source,
                ..
            } => write!(
                formatter,
                "cannot send signal {signal} to validation process group {process_group}: {source}"
            ),
            Self::ValidationGroupCleanupTimedOut {
                process_group,
                timeout,
                ..
            } => write!(
                formatter,
                "validation process group {process_group} still exists after {timeout:?}"
            ),
            Self::CheckFailed { exit, .. } => {
                write!(formatter, "Sing-Box configuration check failed with {exit}")
            }
            Self::CheckTimedOut { timeout, .. } => {
                write!(
                    formatter,
                    "Sing-Box configuration check exceeded {timeout:?}"
                )
            }
            Self::VersionFailed { exit, .. } => {
                write!(formatter, "Sing-Box version query failed with {exit}")
            }
            Self::VersionTimedOut { timeout, .. } => {
                write!(formatter, "Sing-Box version query exceeded {timeout:?}")
            }
            Self::VersionOutputTooLarge {
                stream,
                maximum,
                actual,
            } => write!(
                formatter,
                "Sing-Box version {stream} is {actual} bytes, exceeding {maximum}"
            ),
            Self::ExitedBeforeReady { exit, .. } => {
                write!(
                    formatter,
                    "Sing-Box exited with {exit} before becoming ready"
                )
            }
            Self::ReadinessTimedOut { timeout, .. } => {
                write!(
                    formatter,
                    "Sing-Box did not become ready within {timeout:?}"
                )
            }
            Self::PostSignalReapTimedOut {
                identity,
                signal,
                timeout,
                ..
            } => write!(
                formatter,
                "child {} remained unreaped {timeout:?} after signal {signal}",
                identity.pid
            ),
            Self::ReadinessProbe { path, source } => {
                write!(
                    formatter,
                    "cannot inspect readiness source {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl Error for SingBoxProcessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OpenLog { source, .. }
            | Self::Spawn { source, .. }
            | Self::ReadChildIdentity { source, .. }
            | Self::PinnedDescriptor { source, .. }
            | Self::Wait { source, .. }
            | Self::Signal { source, .. }
            | Self::Capture { source, .. }
            | Self::CaptureWorkerSpawn { source, .. }
            | Self::ValidationGroupSignal { source, .. }
            | Self::ReadinessProbe { source, .. } => Some(source),
            Self::UnsupportedPlatform { .. }
            | Self::InvalidSpec { .. }
            | Self::CaptureThreadPanicked { .. }
            | Self::CheckFailed { .. }
            | Self::CheckTimedOut { .. }
            | Self::VersionFailed { .. }
            | Self::VersionTimedOut { .. }
            | Self::VersionOutputTooLarge { .. }
            | Self::ValidationGroupCleanupTimedOut { .. }
            | Self::ExitedBeforeReady { .. }
            | Self::ReadinessTimedOut { .. }
            | Self::PostSignalReapTimedOut { .. } => None,
        }
    }
}

impl SingBoxProcessAdapter {
    pub fn query_version_pinned(
        &self,
        pinned: &PinnedSingBoxLaunch,
        spec: &SingBoxLaunchSpec,
    ) -> Result<SingBoxVersionReport, SingBoxProcessError> {
        ensure_supported()?;
        validate_spec(spec)?;
        let prepared = pinned_version_command(pinned, spec)?;
        let completed = self.run_pinned_probe(prepared, spec, PinnedProbe::Version)?;
        exact_version_report(completed.output)
    }

    pub fn validate_pinned(
        &self,
        pinned: &PinnedSingBoxLaunch,
        spec: &SingBoxLaunchSpec,
    ) -> Result<ValidationReport, SingBoxProcessError> {
        ensure_supported()?;
        validate_spec(spec)?;
        let prepared = pinned_command(pinned, spec, "check")?;
        let completed = self.run_pinned_probe(prepared, spec, PinnedProbe::Check)?;
        let exit = classify_exit(completed.status);
        Ok(ValidationReport {
            exit,
            diagnostics: completed.output.diagnostics(),
        })
    }

    fn run_pinned_probe(
        &self,
        mut prepared: PreparedCommand,
        spec: &SingBoxLaunchSpec,
        probe: PinnedProbe,
    ) -> Result<CompletedProbe, SingBoxProcessError> {
        let deadline = deadline_after(spec.startup_timeout, "startup_timeout")?;
        prepared
            .command
            .current_dir(&spec.working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_child(&mut prepared.command, true, prepared.inherited_fds)?;

        let mut child = prepared
            .command
            .spawn()
            .map_err(|source| SingBoxProcessError::Spawn {
                program: prepared.program,
                source,
            })?;
        let pid = child.id();
        let stdout = child.stdout.take().expect("piped stdout is present");
        let stderr = child.stderr.take().expect("piped stderr is present");
        if let Err(source) = set_pipe_nonblocking(&stdout) {
            let error = SingBoxProcessError::Capture {
                stream: "stdout",
                source,
            };
            return Err(cleanup_validation_child(child, pid).unwrap_or(error));
        }
        if let Err(source) = set_pipe_nonblocking(&stderr) {
            let error = SingBoxProcessError::Capture {
                stream: "stderr",
                source,
            };
            return Err(cleanup_validation_child(child, pid).unwrap_or(error));
        }
        let capture_stop = Arc::new(AtomicBool::new(false));
        let stdout_reader = match capture_stream(stdout, Arc::clone(&capture_stop), "stdout") {
            Ok(reader) => reader,
            Err(error) => {
                capture_stop.store(true, Ordering::Release);
                return Err(cleanup_validation_child(child, pid).unwrap_or(error));
            }
        };
        let stderr_reader = match capture_stream(stderr, Arc::clone(&capture_stop), "stderr") {
            Ok(reader) => reader,
            Err(error) => {
                capture_stop.store(true, Ordering::Release);
                let cleanup_error = cleanup_validation_child(child, pid);
                let _ = join_capture(stdout_reader, "stdout");
                return Err(cleanup_error.unwrap_or(error));
            }
        };

        let result = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => sleep_until_poll(deadline),
                Ok(None) => break Err(None),
                Err(source) => {
                    break Err(Some(SingBoxProcessError::Wait { pid, source }));
                }
            }
        };
        let group_signal_error = signal_validation_group(pid).err();
        let status = match result {
            Ok(status) => status,
            Err(error) => {
                kill_and_reap_bounded(child, CLEANUP_GRACE);
                let group_cleanup_error = group_signal_error
                    .or_else(|| wait_validation_group_exit(pid, CLEANUP_GRACE).err());
                if group_cleanup_error.is_some() {
                    capture_stop.store(true, Ordering::Release);
                }
                let output = collect_capture(stdout_reader, stderr_reader)?;
                let diagnostics = output.diagnostics();
                if let Some(source) = group_cleanup_error {
                    return Err(validation_group_cleanup_error(pid, source, diagnostics));
                }
                if let Some(error) = error {
                    return Err(error);
                }
                return Err(probe.timed_out(spec.startup_timeout, diagnostics));
            }
        };
        let group_cleanup_error =
            group_signal_error.or_else(|| wait_validation_group_exit(pid, CLEANUP_GRACE).err());
        if group_cleanup_error.is_some() {
            capture_stop.store(true, Ordering::Release);
        }
        let output = collect_capture(stdout_reader, stderr_reader)?;
        if let Some(source) = group_cleanup_error {
            return Err(validation_group_cleanup_error(
                pid,
                source,
                output.diagnostics(),
            ));
        }
        let exit = classify_exit(status);
        if !status.success() {
            return Err(probe.failed(exit, output.diagnostics()));
        }
        Ok(CompletedProbe { status, output })
    }

    pub fn spawn_pinned(
        &self,
        pinned: &PinnedSingBoxLaunch,
        spec: &SingBoxLaunchSpec,
    ) -> Result<SingBoxChild, SingBoxProcessError> {
        ensure_supported()?;
        validate_spec(spec)?;
        let prepared = pinned_command(pinned, spec, "run")?;
        self.run_spawn(prepared, spec)
    }

    fn run_spawn(
        &self,
        mut prepared: PreparedCommand,
        spec: &SingBoxLaunchSpec,
    ) -> Result<SingBoxChild, SingBoxProcessError> {
        let log = open_log_streams(&spec.log)?;
        prepared
            .command
            .current_dir(&spec.working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.stdout))
            .stderr(Stdio::from(log.stderr));
        configure_child(&mut prepared.command, false, prepared.inherited_fds)?;

        let child = prepared
            .command
            .spawn()
            .map_err(|source| SingBoxProcessError::Spawn {
                program: prepared.program,
                source,
            })?;
        let pid = child.id();
        let identity = match read_child_identity(pid) {
            Ok(identity) => identity,
            Err(source) => {
                kill_and_reap_bounded(child, CLEANUP_GRACE);
                return Err(SingBoxProcessError::ReadChildIdentity { pid, source });
            }
        };
        Ok(SingBoxChild {
            child: Some(child),
            identity,
            reaped_exit: None,
            log: log.diagnostic,
            log_path: spec.log.clone(),
        })
    }

    pub fn wait_ready(
        &self,
        child: &mut SingBoxChild,
        spec: &SingBoxLaunchSpec,
    ) -> Result<ReadinessEvidence, SingBoxProcessError> {
        ensure_supported()?;
        validate_spec(spec)?;
        let deadline = deadline_after(spec.startup_timeout, "startup_timeout")?;
        loop {
            if let Some(exit) = self.try_wait(child)? {
                return Err(SingBoxProcessError::ExitedBeforeReady {
                    exit,
                    diagnostics: log_diagnostics(&child.log),
                });
            }

            if let Some(evidence) = readiness_evidence(&spec.readiness, &child.identity)? {
                if let Some(exit) = self.try_wait(child)? {
                    return Err(SingBoxProcessError::ExitedBeforeReady {
                        exit,
                        diagnostics: log_diagnostics(&child.log),
                    });
                }
                return Ok(evidence);
            }
            if Instant::now() >= deadline {
                return Err(SingBoxProcessError::ReadinessTimedOut {
                    timeout: spec.startup_timeout,
                    diagnostics: log_diagnostics(&child.log),
                });
            }
            sleep_until_poll(deadline);
        }
    }

    pub fn try_wait(
        &self,
        child: &mut SingBoxChild,
    ) -> Result<Option<SingBoxExit>, SingBoxProcessError> {
        ensure_supported()?;
        if let Some(exit) = child.reaped_exit {
            return Ok(Some(exit));
        }
        let status = child
            .child
            .as_mut()
            .expect("unreaped Sing-Box child retains its process handle")
            .try_wait()
            .map_err(|source| SingBoxProcessError::Wait {
                pid: child.identity.pid,
                source,
            })?;
        let Some(status) = status else {
            return Ok(None);
        };
        let exit = classify_exit(status);
        child.reaped_exit = Some(exit);
        child.child = None;
        Ok(Some(exit))
    }

    pub fn terminate(
        &self,
        child: &mut SingBoxChild,
        timeout: Duration,
    ) -> Result<TerminationOutcome, SingBoxProcessError> {
        ensure_supported()?;
        let deadline = deadline_after(timeout, "termination timeout")?;
        if let Some(exit) = self.try_wait(child)? {
            return Ok(TerminationOutcome::AlreadyExited { exit });
        }

        match signal_child(child, ProcessSignal::Terminate) {
            Ok(()) => {}
            Err(error) if child_process::is_no_such_process(&error) => {}
            Err(source) => {
                return Err(SingBoxProcessError::Signal {
                    pid: child.identity.pid,
                    signal: ProcessSignal::Terminate.as_raw(),
                    source,
                });
            }
        }

        loop {
            if let Some(exit) = self.try_wait(child)? {
                return Ok(TerminationOutcome::Terminated { exit });
            }
            if Instant::now() >= deadline {
                break;
            }
            sleep_until_poll(deadline);
        }

        match signal_child(child, ProcessSignal::Kill) {
            Ok(()) => {}
            Err(error) if child_process::is_no_such_process(&error) => {}
            Err(source) => {
                return Err(SingBoxProcessError::Signal {
                    pid: child.identity.pid,
                    signal: ProcessSignal::Kill.as_raw(),
                    source,
                });
            }
        }
        let kill_deadline = deadline_after(timeout, "post-kill reap timeout")?;
        loop {
            if let Some(exit) = self.try_wait(child)? {
                return Ok(TerminationOutcome::Killed { exit });
            }
            if Instant::now() >= kill_deadline {
                return Err(SingBoxProcessError::PostSignalReapTimedOut {
                    identity: child.identity,
                    signal: ProcessSignal::Kill.as_raw(),
                    timeout,
                    diagnostics: log_diagnostics(&child.log),
                });
            }
            sleep_until_poll(kill_deadline);
        }
    }
}

fn validate_spec(spec: &SingBoxLaunchSpec) -> Result<(), SingBoxProcessError> {
    validate_absolute_path("binary", &spec.binary)?;
    validate_absolute_path("config", &spec.config)?;
    validate_absolute_path("working_directory", &spec.working_directory)?;
    validate_absolute_path("log", &spec.log)?;
    if let SingBoxLauncher::BusyBoxSetuidgid { busybox, identity } = &spec.launcher {
        validate_absolute_path("launcher.busybox", busybox)?;
        validate_setuidgid_identity(identity)?;
    }
    if let SingBoxReadiness::TunInterface { name } = &spec.readiness {
        if name.is_empty() {
            return Err(invalid_spec("readiness.name", "interface name is empty"));
        }
        if name.len() > INTERFACE_NAME_MAX_BYTES {
            return Err(invalid_spec(
                "readiness.name",
                "interface name exceeds the kernel IFNAMSIZ limit",
            ));
        }
        if name == "." || name == ".." || name.contains('/') || name.as_bytes().contains(&0) {
            return Err(invalid_spec(
                "readiness.name",
                "interface name is not a single safe path component",
            ));
        }
    }
    if spec.startup_timeout.is_zero() {
        return Err(invalid_spec(
            "startup_timeout",
            "duration must be greater than zero",
        ));
    }
    if spec.stop_timeout.is_zero() {
        return Err(invalid_spec(
            "stop_timeout",
            "duration must be greater than zero",
        ));
    }
    Ok(())
}

fn validate_absolute_path(field: &'static str, path: &Path) -> Result<(), SingBoxProcessError> {
    if path.as_os_str().is_empty() {
        Err(invalid_spec(field, "path must not be empty"))
    } else if !path.is_absolute() {
        Err(invalid_spec(field, "path must be absolute"))
    } else {
        Ok(())
    }
}

fn validate_setuidgid_identity(identity: &OsString) -> Result<(), SingBoxProcessError> {
    let Some(identity) = identity.to_str() else {
        return Err(invalid_spec(
            "launcher.identity",
            "identity must be valid UTF-8",
        ));
    };
    let components = identity.split(':').collect::<Vec<_>>();
    if !(components.len() == 1 || components.len() == 2)
        || components
            .iter()
            .any(|component| !valid_identity(component))
    {
        return Err(invalid_spec(
            "launcher.identity",
            "expected USER or USER:GROUP using decimal IDs or safe names",
        ));
    }
    Ok(())
}

fn valid_identity(identity: &str) -> bool {
    if identity.is_empty() || identity.len() > 255 {
        return false;
    }
    if identity.bytes().all(|byte| byte.is_ascii_digit()) {
        return identity.parse::<u32>().is_ok();
    }
    let mut bytes = identity.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn invalid_spec(field: &'static str, detail: impl Into<String>) -> SingBoxProcessError {
    SingBoxProcessError::InvalidSpec {
        field,
        detail: detail.into(),
    }
}

fn deadline_after(timeout: Duration, field: &'static str) -> Result<Instant, SingBoxProcessError> {
    if timeout.is_zero() {
        return Err(invalid_spec(field, "duration must be greater than zero"));
    }
    Instant::now().checked_add(timeout).ok_or_else(|| {
        invalid_spec(
            field,
            "duration cannot be represented by a monotonic deadline",
        )
    })
}

fn sleep_until_poll(deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    thread::sleep(POLL_INTERVAL.min(remaining));
}

#[derive(Clone, Copy)]
enum PinnedProbe {
    Check,
    Version,
}

impl PinnedProbe {
    fn failed(self, exit: SingBoxExit, diagnostics: ProcessDiagnostics) -> SingBoxProcessError {
        match self {
            Self::Check => SingBoxProcessError::CheckFailed { exit, diagnostics },
            Self::Version => SingBoxProcessError::VersionFailed { exit, diagnostics },
        }
    }

    fn timed_out(self, timeout: Duration, diagnostics: ProcessDiagnostics) -> SingBoxProcessError {
        match self {
            Self::Check => SingBoxProcessError::CheckTimedOut {
                timeout,
                diagnostics,
            },
            Self::Version => SingBoxProcessError::VersionTimedOut {
                timeout,
                diagnostics,
            },
        }
    }
}

struct CompletedProbe {
    status: ExitStatus,
    output: CapturedOutput,
}

struct PreparedCommand {
    command: Command,
    program: PathBuf,
    inherited_fds: Vec<i32>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn pinned_command(
    pinned: &PinnedSingBoxLaunch,
    spec: &SingBoxLaunchSpec,
    subcommand: &'static str,
) -> Result<PreparedCommand, SingBoxProcessError> {
    let mut prepared = pinned_base_command(pinned, spec)?;
    let config = descriptor_path(&pinned.config);
    prepared.inherited_fds.push(pinned.config.as_raw_fd());
    prepared.inherited_fds.sort_unstable();
    prepared.inherited_fds.dedup();
    prepared
        .command
        .arg(subcommand)
        .arg("-c")
        .arg(config)
        .arg("-D")
        .arg(&spec.working_directory);
    Ok(prepared)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn pinned_version_command(
    pinned: &PinnedSingBoxLaunch,
    spec: &SingBoxLaunchSpec,
) -> Result<PreparedCommand, SingBoxProcessError> {
    let mut prepared = pinned_base_command(pinned, spec)?;
    prepared.command.arg("version");
    Ok(prepared)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn pinned_base_command(
    pinned: &PinnedSingBoxLaunch,
    spec: &SingBoxLaunchSpec,
) -> Result<PreparedCommand, SingBoxProcessError> {
    let binary = descriptor_path(&pinned.binary);
    let binary_fd = pinned.binary.as_raw_fd();
    let (command, program, mut inherited_fds) = match &spec.launcher {
        SingBoxLauncher::Direct => {
            let inherited = if descriptor_is_script("binary", &pinned.binary)? {
                vec![binary_fd]
            } else {
                Vec::new()
            };
            (Command::new(&binary), binary.clone(), inherited)
        }
        SingBoxLauncher::BusyBoxSetuidgid { identity, .. } => {
            let busybox = pinned.busybox.as_ref().ok_or_else(|| {
                invalid_spec(
                    "launcher.busybox_file",
                    "pinned BusyBox descriptor is required for setuidgid",
                )
            })?;
            let busybox_path = descriptor_path(busybox);
            let mut command = Command::new(&busybox_path);
            command.arg("setuidgid").arg(identity).arg(&binary);
            let mut inherited = vec![binary_fd];
            if descriptor_is_script("busybox", busybox)? {
                inherited.push(busybox.as_raw_fd());
            }
            (command, busybox_path, inherited)
        }
    };
    inherited_fds.sort_unstable();
    inherited_fds.dedup();
    Ok(PreparedCommand {
        command,
        program,
        inherited_fds,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn pinned_command(
    _pinned: &PinnedSingBoxLaunch,
    _spec: &SingBoxLaunchSpec,
    _subcommand: &'static str,
) -> Result<PreparedCommand, SingBoxProcessError> {
    Err(SingBoxProcessError::UnsupportedPlatform {
        platform: std::env::consts::OS,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn pinned_version_command(
    _pinned: &PinnedSingBoxLaunch,
    _spec: &SingBoxLaunchSpec,
) -> Result<PreparedCommand, SingBoxProcessError> {
    Err(SingBoxProcessError::UnsupportedPlatform {
        platform: std::env::consts::OS,
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn descriptor_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn validate_pinned_descriptor(role: &'static str, file: &File) -> Result<(), SingBoxProcessError> {
    let metadata = file
        .metadata()
        .map_err(|source| SingBoxProcessError::PinnedDescriptor { role, source })?;
    if !metadata.file_type().is_file() {
        return Err(SingBoxProcessError::PinnedDescriptor {
            role,
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "descriptor is not a regular file",
            ),
        });
    }
    set_descriptor_close_on_exec(role, file)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_descriptor_close_on_exec(
    role: &'static str,
    file: &File,
) -> Result<(), SingBoxProcessError> {
    if file.as_raw_fd() < 3 {
        return Err(SingBoxProcessError::PinnedDescriptor {
            role,
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "descriptor overlaps standard input or output",
            ),
        });
    }
    child_process::set_close_on_exec(file.as_raw_fd())
        .map_err(|source| SingBoxProcessError::PinnedDescriptor { role, source })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_descriptor_close_on_exec(
    _role: &'static str,
    _file: &File,
) -> Result<(), SingBoxProcessError> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn descriptor_is_script(role: &'static str, file: &File) -> Result<bool, SingBoxProcessError> {
    let mut magic = [0_u8; 2];
    let read = file
        .read_at(&mut magic, 0)
        .map_err(|source| SingBoxProcessError::PinnedDescriptor { role, source })?;
    Ok(read == magic.len() && magic == *b"#!")
}

struct OpenedLog {
    diagnostic: File,
    stdout: File,
    stderr: File,
}

fn open_log_streams(path: &Path) -> Result<OpenedLog, SingBoxProcessError> {
    let diagnostic =
        open_append_only_regular_file(path).map_err(|source| SingBoxProcessError::OpenLog {
            path: path.to_path_buf(),
            source,
        })?;
    let stdout = diagnostic
        .try_clone()
        .map_err(|source| SingBoxProcessError::OpenLog {
            path: path.to_path_buf(),
            source,
        })?;
    let stderr = diagnostic
        .try_clone()
        .map_err(|source| SingBoxProcessError::OpenLog {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(OpenedLog {
        diagnostic,
        stdout,
        stderr,
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_append_only_regular_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Sing-Box log is not a regular file",
        ));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn open_append_only_regular_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .open(path)
}

fn capture_stream<R>(
    mut stream: R,
    stop: Arc<AtomicBool>,
    stream_name: &'static str,
) -> Result<thread::JoinHandle<Result<CapturedStream, io::Error>>, SingBoxProcessError>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(format!("flux-engine-probe-{stream_name}"))
        .spawn(move || {
            let mut tail = Vec::with_capacity(CAPTURE_STREAM_LIMIT);
            let mut total = 0_usize;
            let mut buffer = [0_u8; 4096];
            loop {
                let stopping = stop.load(Ordering::Acquire);
                match stream.read(&mut buffer) {
                    Ok(0) => return Ok(CapturedStream { tail, total }),
                    Ok(read) => {
                        total = total.saturating_add(read);
                        retain_tail(&mut tail, &buffer[..read], CAPTURE_STREAM_LIMIT);
                        if stopping {
                            return Ok(CapturedStream { tail, total });
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if stop.load(Ordering::Acquire) {
                            return Ok(CapturedStream { tail, total });
                        }
                        thread::sleep(POLL_INTERVAL);
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .map_err(|source| SingBoxProcessError::CaptureWorkerSpawn {
            stream: stream_name,
            source,
        })
}

struct CapturedStream {
    tail: Vec<u8>,
    total: usize,
}

struct CapturedOutput {
    stdout: CapturedStream,
    stderr: CapturedStream,
}

impl CapturedOutput {
    fn diagnostics(&self) -> ProcessDiagnostics {
        ProcessDiagnostics {
            stdout_tail: bounded_lossy_tail(&self.stdout.tail, CAPTURE_STREAM_LIMIT),
            stderr_tail: bounded_lossy_tail(&self.stderr.tail, CAPTURE_STREAM_LIMIT),
            log_tail: String::new(),
        }
    }
}

fn retain_tail(tail: &mut Vec<u8>, bytes: &[u8], limit: usize) {
    if bytes.len() >= limit {
        tail.clear();
        tail.extend_from_slice(&bytes[bytes.len() - limit..]);
        return;
    }
    let overflow = tail.len().saturating_add(bytes.len()).saturating_sub(limit);
    if overflow != 0 {
        tail.drain(..overflow);
    }
    tail.extend_from_slice(bytes);
}

fn collect_capture(
    stdout: thread::JoinHandle<Result<CapturedStream, io::Error>>,
    stderr: thread::JoinHandle<Result<CapturedStream, io::Error>>,
) -> Result<CapturedOutput, SingBoxProcessError> {
    let stdout = join_capture(stdout, "stdout");
    let stderr = join_capture(stderr, "stderr");
    Ok(CapturedOutput {
        stdout: stdout?,
        stderr: stderr?,
    })
}

fn exact_version_report(
    output: CapturedOutput,
) -> Result<SingBoxVersionReport, SingBoxProcessError> {
    Ok(SingBoxVersionReport {
        stdout: exact_version_stream(output.stdout, "stdout")?,
        stderr: exact_version_stream(output.stderr, "stderr")?,
    })
}

fn exact_version_stream(
    stream: CapturedStream,
    name: &'static str,
) -> Result<Box<[u8]>, SingBoxProcessError> {
    if stream.total > CAPTURE_STREAM_LIMIT {
        return Err(SingBoxProcessError::VersionOutputTooLarge {
            stream: name,
            maximum: CAPTURE_STREAM_LIMIT,
            actual: stream.total,
        });
    }
    debug_assert_eq!(stream.total, stream.tail.len());
    Ok(stream.tail.into_boxed_slice())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_pipe_nonblocking<T: AsRawFd>(stream: &T) -> io::Result<()> {
    child_process::set_nonblocking(stream.as_raw_fd())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_pipe_nonblocking<T>(_stream: &T) -> io::Result<()> {
    Ok(())
}

fn join_capture(
    reader: thread::JoinHandle<Result<CapturedStream, io::Error>>,
    stream: &'static str,
) -> Result<CapturedStream, SingBoxProcessError> {
    reader
        .join()
        .map_err(|_| SingBoxProcessError::CaptureThreadPanicked { stream })?
        .map_err(|source| SingBoxProcessError::Capture { stream, source })
}

fn bounded_lossy_tail(bytes: &[u8], limit: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= limit {
        return text.into_owned();
    }
    let mut start = text.len() - limit;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_owned()
}

fn log_diagnostics(file: &File) -> ProcessDiagnostics {
    ProcessDiagnostics {
        stdout_tail: String::new(),
        stderr_tail: String::new(),
        log_tail: read_file_tail(file, DIAGNOSTIC_LIMIT).unwrap_or_default(),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_file_tail(file: &File, limit: usize) -> io::Result<String> {
    let length = file.metadata()?.len();
    let limit_u64 = u64::try_from(limit).unwrap_or(u64::MAX);
    let start = length.saturating_sub(limit_u64);
    let requested = usize::try_from(length - start).unwrap_or(limit);
    let mut bytes = vec![0_u8; requested.min(limit)];
    let mut read = 0_usize;
    while read < bytes.len() {
        match file.read_at(
            &mut bytes[read..],
            start.saturating_add(u64::try_from(read).unwrap_or(u64::MAX)),
        ) {
            Ok(0) => break,
            Ok(received) => read = read.saturating_add(received),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    bytes.truncate(read);
    Ok(bounded_lossy_tail(&bytes, limit))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn read_file_tail(file: &File, limit: usize) -> io::Result<String> {
    use std::io::{Seek, SeekFrom};

    let mut file = file.try_clone()?;
    let length = file.metadata()?.len();
    let limit_u64 = u64::try_from(limit).unwrap_or(u64::MAX);
    if length > limit_u64 {
        file.seek(SeekFrom::Start(length - limit_u64))?;
    }
    let mut bytes = Vec::with_capacity(limit);
    file.take(limit_u64).read_to_end(&mut bytes)?;
    Ok(bounded_lossy_tail(&bytes, limit))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn ensure_supported() -> Result<(), SingBoxProcessError> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn ensure_supported() -> Result<(), SingBoxProcessError> {
    Err(SingBoxProcessError::UnsupportedPlatform {
        platform: std::env::consts::OS,
    })
}

fn configure_child(
    command: &mut Command,
    new_process_group: bool,
    inherited_fds: Vec<i32>,
) -> Result<(), SingBoxProcessError> {
    child_process::configure_child_process(
        command,
        ChildProcessConfig {
            raise_nofile_limit: true,
            new_process_group,
            // This contains direct launches. A later BusyBox setuidgid
            // credential transition can clear PDEATHSIG, so non-root launch
            // needs the deferred post-credential Rust launcher before it can
            // claim the same crash-time guarantee.
            kill_on_parent_death: true,
            close_unlisted_fds: false,
            inherited_fds,
        },
    )
    .map_err(|source| SingBoxProcessError::Spawn {
        program: PathBuf::from("<pre-exec child setup>"),
        source,
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_child_identity(pid: u32) -> io::Result<SingBoxChildIdentity> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let command_end = stat.rfind(')').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing command terminator in proc stat",
        )
    })?;
    let fields = stat
        .get(command_end + 1..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated proc stat"))?
        .split_whitespace()
        .collect::<Vec<_>>();
    let start_time_ticks = fields
        .get(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc start time"))?
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(SingBoxChildIdentity {
        pid,
        start_time_ticks,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn read_child_identity(_pid: u32) -> io::Result<SingBoxChildIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "proc child identity is unavailable",
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn classify_exit(status: ExitStatus) -> SingBoxExit {
    if let Some(code) = status.code() {
        SingBoxExit::Code(code)
    } else if let Some(signal) = status.signal() {
        SingBoxExit::Signal(signal)
    } else {
        SingBoxExit::Unknown
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn classify_exit(status: ExitStatus) -> SingBoxExit {
    status
        .code()
        .map_or(SingBoxExit::Unknown, SingBoxExit::Code)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn readiness_evidence(
    readiness: &SingBoxReadiness,
    identity: &SingBoxChildIdentity,
) -> Result<Option<ReadinessEvidence>, SingBoxProcessError> {
    match read_child_identity(identity.pid) {
        Ok(observed) if observed == *identity => {}
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(SingBoxProcessError::ReadinessProbe {
                path: PathBuf::from(format!("/proc/{}/stat", identity.pid)),
                source,
            });
        }
    }
    match readiness {
        SingBoxReadiness::Listener { port } => listener_evidence(*port, identity.pid),
        SingBoxReadiness::TunInterface { name } => {
            let path = Path::new("/sys/class/net").join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(_) if child_holds_tun_interface(identity.pid, name)? => {
                    Ok(Some(ReadinessEvidence::TunInterface {
                        name: name.clone(),
                        path,
                    }))
                }
                Ok(_) => Ok(None),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(source) => Err(SingBoxProcessError::ReadinessProbe { path, source }),
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn readiness_evidence(
    _readiness: &SingBoxReadiness,
    _identity: &SingBoxChildIdentity,
) -> Result<Option<ReadinessEvidence>, SingBoxProcessError> {
    Err(SingBoxProcessError::UnsupportedPlatform {
        platform: std::env::consts::OS,
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn listener_evidence(
    port: NonZeroU16,
    pid: u32,
) -> Result<Option<ReadinessEvidence>, SingBoxProcessError> {
    const TABLES: [(&str, bool); 4] = [
        ("tcp", true),
        ("tcp6", true),
        ("udp", false),
        ("udp6", false),
    ];
    let child_sockets = child_socket_inodes(pid)?;
    let network_root = PathBuf::from(format!("/proc/{pid}/net"));
    for (table, tcp) in TABLES {
        let path = network_root.join(table);
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(SingBoxProcessError::ReadinessProbe { path, source });
            }
        };
        if proc_net_socket_inodes(&contents, port, tcp).any(|inode| child_sockets.contains(&inode))
        {
            return Ok(Some(ReadinessEvidence::Listener { port, table: path }));
        }
    }
    Ok(None)
}

#[cfg(all(any(target_os = "linux", target_os = "android"), test))]
fn proc_net_contains_port(contents: &str, port: NonZeroU16, tcp: bool) -> bool {
    proc_net_socket_inodes(contents, port, tcp).next().is_some()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn proc_net_socket_inodes(
    contents: &str,
    port: NonZeroU16,
    tcp: bool,
) -> impl Iterator<Item = u64> + '_ {
    contents.lines().skip(1).filter_map(move |line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let local_address = *fields.get(1)?;
        let state = *fields.get(3)?;
        if tcp && state != "0A" {
            return None;
        }
        let (_, encoded_port) = local_address.rsplit_once(':')?;
        let candidate = u16::from_str_radix(encoded_port, 16).ok()?;
        if candidate != port.get() {
            return None;
        }
        fields.get(9)?.parse::<u64>().ok()
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn child_socket_inodes(pid: u32) -> Result<HashSet<u64>, SingBoxProcessError> {
    let directory = PathBuf::from(format!("/proc/{pid}/fd"));
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(source) => {
            return Err(SingBoxProcessError::ReadinessProbe {
                path: directory,
                source,
            });
        }
    };
    let mut inodes = HashSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| SingBoxProcessError::ReadinessProbe {
            path: directory.clone(),
            source,
        })?;
        let target = match std::fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(SingBoxProcessError::ReadinessProbe {
                    path: entry.path(),
                    source,
                });
            }
        };
        let target = target.as_os_str().to_string_lossy();
        if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<u64>().ok())
        {
            inodes.insert(inode);
        }
    }
    Ok(inodes)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn child_holds_tun_interface(pid: u32, name: &str) -> Result<bool, SingBoxProcessError> {
    let directory = PathBuf::from(format!("/proc/{pid}/fdinfo"));
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(SingBoxProcessError::ReadinessProbe {
                path: directory,
                source,
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| SingBoxProcessError::ReadinessProbe {
            path: directory.clone(),
            source,
        })?;
        let contents = match std::fs::read_to_string(entry.path()) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(SingBoxProcessError::ReadinessProbe {
                    path: entry.path(),
                    source,
                });
            }
        };
        if contents.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(field, value)| field == "iff" && value.trim() == name)
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn signal_child(child: &SingBoxChild, signal: ProcessSignal) -> io::Result<()> {
    signal_identity(child.identity, signal)
}

fn signal_identity(identity: SingBoxChildIdentity, signal: ProcessSignal) -> io::Result<()> {
    let observed = read_child_identity(identity.pid)?;
    if observed != identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refused to signal PID {} after start-time identity changed from {} to {}",
                identity.pid, identity.start_time_ticks, observed.start_time_ticks
            ),
        ));
    }
    child_process::signal_process(identity.pid, signal)
}

fn cleanup_validation_child(child: Child, process_group: u32) -> Option<SingBoxProcessError> {
    let group_signal_error = signal_validation_group(process_group).err();
    kill_and_reap_bounded(child, CLEANUP_GRACE);
    group_signal_error
        .or_else(|| wait_validation_group_exit(process_group, CLEANUP_GRACE).err())
        .map(|source| {
            validation_group_cleanup_error(process_group, source, ProcessDiagnostics::default())
        })
}

enum ValidationGroupCleanupError {
    Signal { signal: i32, source: io::Error },
    TimedOut { timeout: Duration },
}

fn signal_validation_group(process_group: u32) -> Result<(), ValidationGroupCleanupError> {
    match child_process::signal_process_group(process_group, ProcessSignal::Kill) {
        Ok(()) => Ok(()),
        Err(error) if child_process::is_no_such_process(&error) => Ok(()),
        Err(source) => Err(ValidationGroupCleanupError::Signal {
            signal: ProcessSignal::Kill.as_raw(),
            source,
        }),
    }
}

fn wait_validation_group_exit(
    process_group: u32,
    timeout: Duration,
) -> Result<(), ValidationGroupCleanupError> {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Err(ValidationGroupCleanupError::TimedOut { timeout });
    };
    loop {
        match child_process::process_group_exists(process_group) {
            Ok(false) => return Ok(()),
            Ok(true) if Instant::now() < deadline => sleep_until_poll(deadline),
            Ok(true) => return Err(ValidationGroupCleanupError::TimedOut { timeout }),
            Err(source) => {
                return Err(ValidationGroupCleanupError::Signal { signal: 0, source });
            }
        }
    }
}

fn validation_group_cleanup_error(
    process_group: u32,
    error: ValidationGroupCleanupError,
    diagnostics: ProcessDiagnostics,
) -> SingBoxProcessError {
    match error {
        ValidationGroupCleanupError::Signal { signal, source } => {
            SingBoxProcessError::ValidationGroupSignal {
                process_group,
                signal,
                source,
                diagnostics,
            }
        }
        ValidationGroupCleanupError::TimedOut { timeout } => {
            SingBoxProcessError::ValidationGroupCleanupTimedOut {
                process_group,
                timeout,
                diagnostics,
            }
        }
    }
}

fn kill_and_reap_bounded(mut child: Child, timeout: Duration) {
    let pid = child.id();
    let _ = child.kill();
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        defer_reap(child, pid);
        return;
    };
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => sleep_until_poll(deadline),
            Ok(None) | Err(_) => {
                defer_reap(child, pid);
                return;
            }
        }
    }
}

fn defer_reap(mut child: Child, pid: u32) {
    let reaper = thread::Builder::new()
        .name(format!("flux-reap-{pid}"))
        .spawn(move || {
            let _ = child.wait();
        });
    if let Ok(handle) = reaper {
        drop(handle);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use super::{
        ProcessHandleError, ReadinessEvidence, SingBoxChild, SingBoxProcessAdapter,
        SingBoxProcessError, listener_evidence, proc_net_contains_port, read_child_identity,
    };
    use super::{bounded_lossy_tail, retain_tail, valid_identity};
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::fs::File;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::num::NonZeroU16;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::process::Command;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::time::Duration;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn listener_probe_requires_a_socket_inode_owned_by_the_process() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind owned listener");
        let port = NonZeroU16::new(listener.local_addr().expect("read listener address").port())
            .expect("ephemeral port is nonzero");

        let evidence = listener_evidence(port, std::process::id())
            .expect("probe owned listener")
            .expect("owned listener is ready");

        let ReadinessEvidence::Listener {
            port: observed,
            table,
        } = evidence
        else {
            panic!("listener probe returned TUN evidence");
        };
        assert_eq!(observed, port);
        assert!(table.starts_with(format!("/proc/{}/net", std::process::id())));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn termination_refuses_a_changed_start_time_identity() {
        let directory = tempfile::tempdir().expect("create identity fixture");
        let process = Command::new("/bin/sh")
            .arg("-c")
            .arg("exec sleep 5")
            .spawn()
            .expect("spawn identity fixture");
        let mut identity = read_child_identity(process.id()).expect("read child identity");
        identity.start_time_ticks = identity.start_time_ticks.saturating_add(1);
        let log_path = directory.path().join("sing-box.log");
        let mut child = SingBoxChild {
            child: Some(process),
            identity,
            reaped_exit: None,
            log: File::create(&log_path).expect("create child log"),
            log_path,
        };

        let error = SingBoxProcessAdapter
            .terminate(&mut child, Duration::from_millis(50))
            .expect_err("changed identity must not be signalled");
        assert!(matches!(
            error,
            SingBoxProcessError::Signal { source, .. }
                if source.kind() == std::io::ErrorKind::PermissionDenied
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn process_handle_rejects_a_changed_recorded_child_identity() {
        let directory = tempfile::tempdir().expect("create process-handle identity fixture");
        let process = Command::new("/bin/sh")
            .arg("-c")
            .arg("exec sleep 5")
            .spawn()
            .expect("spawn process-handle identity fixture");
        let actual_identity = read_child_identity(process.id()).expect("read child identity");
        let mut changed_identity = actual_identity;
        changed_identity.start_time_ticks = if actual_identity.start_time_ticks == u64::MAX {
            actual_identity.start_time_ticks - 1
        } else {
            actual_identity.start_time_ticks + 1
        };
        let log_path = directory.path().join("sing-box.log");
        let mut child = SingBoxChild {
            child: Some(process),
            identity: changed_identity,
            reaped_exit: None,
            log: File::create(&log_path).expect("create child log"),
            log_path,
        };

        let error = child
            .open_process_handle()
            .expect_err("changed recorded identity must not become child authority");
        let ProcessHandleError::ProcessIdentityMismatch { expected, observed } = error else {
            panic!("unexpected process-handle error: {error:?}");
        };
        assert_eq!(expected.pid().get(), changed_identity.pid);
        assert_eq!(
            expected.start_time_ticks().get(),
            changed_identity.start_time_ticks
        );
        assert_eq!(observed.pid().get(), actual_identity.pid);
        assert_eq!(
            observed.start_time_ticks().get(),
            actual_identity.start_time_ticks
        );

        child.identity = actual_identity;
        assert!(matches!(
            SingBoxProcessAdapter
                .terminate(&mut child, Duration::from_millis(500))
                .expect("restore exact identity and reap child"),
            super::TerminationOutcome::Terminated { .. }
        ));
    }

    #[test]
    fn tail_buffer_discards_oldest_bytes() {
        let mut tail = Vec::new();
        retain_tail(&mut tail, b"abcdef", 4);
        retain_tail(&mut tail, b"gh", 4);
        assert_eq!(tail, b"efgh");
    }

    #[test]
    fn lossy_diagnostics_remain_byte_bounded() {
        let text = bounded_lossy_tail(&[0xff; 64], 16);
        assert!(text.len() <= 16);
    }

    #[test]
    fn setuidgid_identity_accepts_only_safe_numeric_or_named_components() {
        for valid in ["0", "1000", "root", "_service", "user_123", "4294967295"] {
            assert!(valid_identity(valid), "expected valid identity {valid:?}");
        }
        for invalid in [
            "",
            "-root",
            "+1",
            "user-name",
            "user.name",
            "4294967296",
            "é",
        ] {
            assert!(
                !valid_identity(invalid),
                "expected invalid identity {invalid:?}"
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn proc_net_parser_requires_tcp_listen_state() {
        let port = NonZeroU16::new(10_789).expect("nonzero port");
        let listening = "sl local_address rem_address st\n0: 0100007F:2A25 00000000:0000 0A 0:0 00:0 0 1000 0 4242\n";
        let connected = "sl local_address rem_address st\n0: 0100007F:2A25 0100007F:1234 01 0:0 00:0 0 1000 0 4242\n";
        assert!(proc_net_contains_port(listening, port, true));
        assert!(!proc_net_contains_port(connected, port, true));
    }
}
