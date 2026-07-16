use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::{XtablesRestoreArtifact, XtablesRestoreFamily};
use crate::child_process::{self, ChildProcessConfig, ProcessSignal};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsRawFd;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};

const MAX_WAIT_SECONDS: u16 = 60;
const MAX_PROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CAPTURE_BYTES: usize = 16 * 1024;
const MAX_TOOL_BYTES: u64 = 64 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const CLEANUP_GRACE: Duration = Duration::from_millis(250);
const TOOL_DIGEST_DOMAIN: &[u8] = b"Flux pinned xtables restore tool\0sha256-v1\0";

/// Exact executable paths selected for the native restore-process primitive.
///
/// Opening rejects a final-component symlink and descriptor-pins the tool on
/// Linux/Android. The original paths remain diagnostic labels only after the
/// descriptors are opened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesRestoreProcessPaths {
    ipv4: PathBuf,
    ipv6: Option<PathBuf>,
}

impl XtablesRestoreProcessPaths {
    #[must_use]
    pub fn new(ipv4: impl Into<PathBuf>, ipv6: Option<PathBuf>) -> Self {
        Self {
            ipv4: ipv4.into(),
            ipv6,
        }
    }

    #[must_use]
    pub fn ipv4(&self) -> &Path {
        &self.ipv4
    }

    #[must_use]
    pub fn ipv6(&self) -> Option<&Path> {
        self.ipv6.as_deref()
    }
}

/// Fixed bounded execution policy for every probe and restore child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct XtablesRestoreProcessConfig {
    wait_seconds: u16,
    timeout: Duration,
}

impl XtablesRestoreProcessConfig {
    pub fn new(wait_seconds: u16, timeout: Duration) -> Result<Self, XtablesRestoreProcessError> {
        if wait_seconds == 0 || wait_seconds > MAX_WAIT_SECONDS {
            return Err(XtablesRestoreProcessError::InvalidConfig {
                field: "wait_seconds",
                reason: format!("must be in 1..={MAX_WAIT_SECONDS}").into_boxed_str(),
            });
        }
        if timeout.is_zero() || timeout > MAX_PROCESS_TIMEOUT {
            return Err(XtablesRestoreProcessError::InvalidConfig {
                field: "timeout",
                reason: format!("must be nonzero and at most {MAX_PROCESS_TIMEOUT:?}")
                    .into_boxed_str(),
            });
        }
        Ok(Self {
            wait_seconds,
            timeout,
        })
    }

    #[must_use]
    pub const fn wait_seconds(self) -> u16 {
        self.wait_seconds
    }

    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum XtablesRestoreReportedFlavor {
    Legacy,
    NfTables,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct XtablesRestoreToolDigest([u8; 32]);

impl XtablesRestoreToolDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesRestoreToolIdentity {
    path: PathBuf,
    digest: XtablesRestoreToolDigest,
    reported_flavor: XtablesRestoreReportedFlavor,
    version: Box<str>,
}

impl XtablesRestoreToolIdentity {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn digest(&self) -> XtablesRestoreToolDigest {
        self.digest
    }

    #[must_use]
    pub const fn reported_flavor(&self) -> XtablesRestoreReportedFlavor {
        self.reported_flavor
    }

    #[must_use]
    pub const fn version(&self) -> &str {
        &self.version
    }
}

/// Successful direct-child restore execution.
///
/// This is process evidence only. It is not live xtables readback, cleanup
/// proof, a writer lease, or native transaction authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesRestoreProcessOutput {
    family: XtablesRestoreFamily,
    tool_identity: XtablesRestoreToolIdentity,
    stdout: Box<str>,
    stderr: Box<str>,
}

impl XtablesRestoreProcessOutput {
    #[must_use]
    pub const fn family(&self) -> XtablesRestoreFamily {
        self.family
    }

    #[must_use]
    pub const fn tool_identity(&self) -> &XtablesRestoreToolIdentity {
        &self.tool_identity
    }

    #[must_use]
    pub const fn stdout(&self) -> &str {
        &self.stdout
    }

    #[must_use]
    pub const fn stderr(&self) -> &str {
        &self.stderr
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XtablesRestoreProcessOperation {
    Probe,
    Restore,
}

impl fmt::Display for XtablesRestoreProcessOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Probe => "probe",
            Self::Restore => "restore",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XtablesRestoreProcessStream {
    Stdin,
    Stdout,
    Stderr,
}

impl fmt::Display for XtablesRestoreProcessStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stdin => "stdin",
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XtablesRestoreProcessErrorKind {
    Unsupported,
    InvalidConfig,
    InvalidPath,
    ToolOpen,
    ToolIdentity,
    ToolFlavor,
    MissingFamily,
    ChildSetup,
    Spawn,
    Stream,
    Wait,
    NonZeroExit,
    TimedOut,
    OutputLimit,
    Cleanup,
}

/// Conservative kernel-mutation disposition for one process failure.
///
/// Once a restore child has spawned, Flux must re-read live state before any
/// compensation even when the child reported failure or timed out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XtablesRestoreMutationDisposition {
    NotStarted,
    MayHaveMutated,
}

#[derive(Debug)]
pub(crate) enum XtablesRestoreProcessError {
    UnsupportedPlatform(&'static str),
    InvalidConfig {
        field: &'static str,
        reason: Box<str>,
    },
    InvalidPath {
        family: XtablesRestoreFamily,
        path: PathBuf,
        reason: Box<str>,
    },
    ToolOpen {
        family: XtablesRestoreFamily,
        path: PathBuf,
        source: io::Error,
    },
    ToolIdentity {
        family: XtablesRestoreFamily,
        path: PathBuf,
        source: io::Error,
    },
    ToolIdentityChanged {
        family: XtablesRestoreFamily,
        path: PathBuf,
        mutation: XtablesRestoreMutationDisposition,
    },
    PostExecutionToolIdentity {
        family: XtablesRestoreFamily,
        path: PathBuf,
        source: Box<XtablesRestoreProcessError>,
    },
    ToolFlavor {
        family: XtablesRestoreFamily,
        version: Box<str>,
    },
    ToolFlavorMismatch {
        ipv4: XtablesRestoreReportedFlavor,
        ipv6: XtablesRestoreReportedFlavor,
    },
    MissingFamily {
        family: XtablesRestoreFamily,
    },
    ChildSetup {
        operation: XtablesRestoreProcessOperation,
        family: XtablesRestoreFamily,
        source: io::Error,
    },
    Spawn {
        operation: XtablesRestoreProcessOperation,
        family: XtablesRestoreFamily,
        program: PathBuf,
        source: io::Error,
    },
    StreamWorkerSpawn {
        operation: XtablesRestoreProcessOperation,
        family: XtablesRestoreFamily,
        stream: XtablesRestoreProcessStream,
        source: io::Error,
    },
    StreamWorkerPanicked {
        operation: XtablesRestoreProcessOperation,
        family: XtablesRestoreFamily,
        stream: XtablesRestoreProcessStream,
    },
    Stream {
        operation: XtablesRestoreProcessOperation,
        family: XtablesRestoreFamily,
        stream: XtablesRestoreProcessStream,
        source: io::Error,
    },
    Wait {
        operation: XtablesRestoreProcessOperation,
        family: XtablesRestoreFamily,
        pid: u32,
        source: io::Error,
    },
    NonZeroExit {
        operation: XtablesRestoreProcessOperation,
        family: XtablesRestoreFamily,
        status: ExitStatus,
        stdout: Box<str>,
        stderr: Box<str>,
    },
    TimedOut {
        operation: XtablesRestoreProcessOperation,
        family: XtablesRestoreFamily,
        timeout: Duration,
        stdout: Box<str>,
        stderr: Box<str>,
    },
    OutputLimit {
        operation: XtablesRestoreProcessOperation,
        family: XtablesRestoreFamily,
        stream: XtablesRestoreProcessStream,
        maximum: usize,
        actual: usize,
        stdout: Box<str>,
        stderr: Box<str>,
    },
    Cleanup {
        operation: XtablesRestoreProcessOperation,
        family: XtablesRestoreFamily,
        process_group: u32,
        source: io::Error,
    },
}

impl XtablesRestoreProcessError {
    #[must_use]
    pub const fn kind(&self) -> XtablesRestoreProcessErrorKind {
        match self {
            Self::UnsupportedPlatform(_) => XtablesRestoreProcessErrorKind::Unsupported,
            Self::InvalidConfig { .. } => XtablesRestoreProcessErrorKind::InvalidConfig,
            Self::InvalidPath { .. } => XtablesRestoreProcessErrorKind::InvalidPath,
            Self::ToolOpen { .. } => XtablesRestoreProcessErrorKind::ToolOpen,
            Self::ToolIdentity { .. }
            | Self::ToolIdentityChanged { .. }
            | Self::PostExecutionToolIdentity { .. } => {
                XtablesRestoreProcessErrorKind::ToolIdentity
            }
            Self::ToolFlavor { .. } | Self::ToolFlavorMismatch { .. } => {
                XtablesRestoreProcessErrorKind::ToolFlavor
            }
            Self::MissingFamily { .. } => XtablesRestoreProcessErrorKind::MissingFamily,
            Self::ChildSetup { .. } => XtablesRestoreProcessErrorKind::ChildSetup,
            Self::Spawn { .. } => XtablesRestoreProcessErrorKind::Spawn,
            Self::StreamWorkerSpawn { .. }
            | Self::StreamWorkerPanicked { .. }
            | Self::Stream { .. } => XtablesRestoreProcessErrorKind::Stream,
            Self::Wait { .. } => XtablesRestoreProcessErrorKind::Wait,
            Self::NonZeroExit { .. } => XtablesRestoreProcessErrorKind::NonZeroExit,
            Self::TimedOut { .. } => XtablesRestoreProcessErrorKind::TimedOut,
            Self::OutputLimit { .. } => XtablesRestoreProcessErrorKind::OutputLimit,
            Self::Cleanup { .. } => XtablesRestoreProcessErrorKind::Cleanup,
        }
    }

    #[must_use]
    pub const fn mutation_disposition(&self) -> XtablesRestoreMutationDisposition {
        match self {
            Self::ToolIdentityChanged { mutation, .. } => *mutation,
            Self::PostExecutionToolIdentity { .. } => {
                XtablesRestoreMutationDisposition::MayHaveMutated
            }
            Self::StreamWorkerSpawn { operation, .. }
            | Self::StreamWorkerPanicked { operation, .. }
            | Self::Stream { operation, .. }
            | Self::Wait { operation, .. }
            | Self::NonZeroExit { operation, .. }
            | Self::TimedOut { operation, .. }
            | Self::OutputLimit { operation, .. }
            | Self::Cleanup { operation, .. }
                if matches!(operation, XtablesRestoreProcessOperation::Restore) =>
            {
                XtablesRestoreMutationDisposition::MayHaveMutated
            }
            Self::UnsupportedPlatform(_)
            | Self::InvalidConfig { .. }
            | Self::InvalidPath { .. }
            | Self::ToolOpen { .. }
            | Self::ToolIdentity { .. }
            | Self::ToolFlavor { .. }
            | Self::ToolFlavorMismatch { .. }
            | Self::MissingFamily { .. }
            | Self::ChildSetup { .. }
            | Self::Spawn { .. }
            | Self::StreamWorkerSpawn { .. }
            | Self::StreamWorkerPanicked { .. }
            | Self::Stream { .. }
            | Self::Wait { .. }
            | Self::NonZeroExit { .. }
            | Self::TimedOut { .. }
            | Self::OutputLimit { .. }
            | Self::Cleanup { .. } => XtablesRestoreMutationDisposition::NotStarted,
        }
    }
}

impl fmt::Display for XtablesRestoreProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform(platform) => {
                write!(
                    formatter,
                    "native xtables restore processes are unsupported on {platform}"
                )
            }
            Self::InvalidConfig { field, reason } => {
                write!(
                    formatter,
                    "invalid xtables restore process {field}: {reason}"
                )
            }
            Self::InvalidPath {
                family,
                path,
                reason,
            } => write!(
                formatter,
                "invalid {family:?} restore tool path {}: {reason}",
                path.display()
            ),
            Self::ToolOpen {
                family,
                path,
                source,
            } => write!(
                formatter,
                "cannot open pinned {family:?} restore tool {}: {source}",
                path.display()
            ),
            Self::ToolIdentity {
                family,
                path,
                source,
            } => write!(
                formatter,
                "cannot identify pinned {family:?} restore tool {}: {source}",
                path.display()
            ),
            Self::ToolIdentityChanged { family, path, .. } => write!(
                formatter,
                "pinned {family:?} restore tool changed after admission: {}",
                path.display()
            ),
            Self::PostExecutionToolIdentity {
                family,
                path,
                source,
            } => write!(
                formatter,
                "cannot revalidate pinned {family:?} restore tool after execution {}: {source}",
                path.display()
            ),
            Self::ToolFlavor { family, version } => write!(
                formatter,
                "cannot classify pinned {family:?} restore tool version: {version}"
            ),
            Self::ToolFlavorMismatch { ipv4, ipv6 } => write!(
                formatter,
                "IPv4 and IPv6 restore tools use different implementations: {ipv4:?} versus {ipv6:?}"
            ),
            Self::MissingFamily { family } => {
                write!(
                    formatter,
                    "no pinned restore tool is available for {family:?}"
                )
            }
            Self::ChildSetup {
                operation,
                family,
                source,
            } => write!(
                formatter,
                "cannot initialize {family:?} xtables {operation} child: {source}"
            ),
            Self::Spawn {
                operation,
                family,
                program,
                source,
            } => write!(
                formatter,
                "cannot spawn {family:?} xtables {operation} child {}: {source}",
                program.display()
            ),
            Self::StreamWorkerSpawn {
                operation,
                family,
                stream,
                source,
            } => write!(
                formatter,
                "cannot start {stream} worker for {family:?} xtables {operation}: {source}"
            ),
            Self::StreamWorkerPanicked {
                operation,
                family,
                stream,
            } => write!(
                formatter,
                "{stream} worker panicked for {family:?} xtables {operation}"
            ),
            Self::Stream {
                operation,
                family,
                stream,
                source,
            } => write!(
                formatter,
                "{stream} failed for {family:?} xtables {operation}: {source}"
            ),
            Self::Wait {
                operation,
                family,
                pid,
                source,
            } => write!(
                formatter,
                "cannot wait for {family:?} xtables {operation} child {pid}: {source}"
            ),
            Self::NonZeroExit {
                operation,
                family,
                status,
                stderr,
                ..
            } => write!(
                formatter,
                "{family:?} xtables {operation} child exited with {status}: {stderr}"
            ),
            Self::TimedOut {
                operation,
                family,
                timeout,
                ..
            } => write!(
                formatter,
                "{family:?} xtables {operation} child timed out after {timeout:?}"
            ),
            Self::OutputLimit {
                operation,
                family,
                stream,
                maximum,
                actual,
                ..
            } => write!(
                formatter,
                "{family:?} xtables {operation} {stream} exceeded {maximum} bytes with at least {actual} bytes"
            ),
            Self::Cleanup {
                operation,
                family,
                process_group,
                source,
            } => write!(
                formatter,
                "cannot clean process group {process_group} after {family:?} xtables {operation}: {source}"
            ),
        }
    }
}

impl Error for XtablesRestoreProcessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ToolOpen { source, .. }
            | Self::ToolIdentity { source, .. }
            | Self::ChildSetup { source, .. }
            | Self::Spawn { source, .. }
            | Self::StreamWorkerSpawn { source, .. }
            | Self::Stream { source, .. }
            | Self::Wait { source, .. }
            | Self::Cleanup { source, .. } => Some(source),
            Self::PostExecutionToolIdentity { source, .. } => Some(source),
            Self::UnsupportedPlatform(_)
            | Self::InvalidConfig { .. }
            | Self::InvalidPath { .. }
            | Self::ToolIdentityChanged { .. }
            | Self::ToolFlavor { .. }
            | Self::ToolFlavorMismatch { .. }
            | Self::MissingFamily { .. }
            | Self::StreamWorkerPanicked { .. }
            | Self::NonZeroExit { .. }
            | Self::TimedOut { .. }
            | Self::OutputLimit { .. } => None,
        }
    }
}

/// Descriptor-pinned direct restore primitive used by the future native
/// xtables owner.
///
/// The adapter deliberately has no stable-hook, rtnetlink, readback, journal,
/// transition-lease, or production-driver integration. A successful child
/// exit is not sufficient native transaction evidence.
pub(crate) struct XtablesRestoreProcessAdapter {
    ipv4: PinnedRestoreTool,
    ipv6: Option<PinnedRestoreTool>,
    reported_flavor: XtablesRestoreReportedFlavor,
    config: XtablesRestoreProcessConfig,
}

impl XtablesRestoreProcessAdapter {
    pub fn open(
        paths: XtablesRestoreProcessPaths,
        config: XtablesRestoreProcessConfig,
    ) -> Result<Self, XtablesRestoreProcessError> {
        ensure_supported()?;
        let ipv4 = PinnedRestoreTool::open(XtablesRestoreFamily::Ipv4, paths.ipv4, config.timeout)?;
        let ipv6 = paths
            .ipv6
            .map(|path| PinnedRestoreTool::open(XtablesRestoreFamily::Ipv6, path, config.timeout))
            .transpose()?;
        if let Some(ipv6) = &ipv6
            && ipv4.identity.reported_flavor != ipv6.identity.reported_flavor
        {
            return Err(XtablesRestoreProcessError::ToolFlavorMismatch {
                ipv4: ipv4.identity.reported_flavor,
                ipv6: ipv6.identity.reported_flavor,
            });
        }
        let reported_flavor = ipv4.identity.reported_flavor;
        Ok(Self {
            ipv4,
            ipv6,
            reported_flavor,
            config,
        })
    }

    #[must_use]
    pub const fn reported_flavor(&self) -> XtablesRestoreReportedFlavor {
        self.reported_flavor
    }

    #[must_use]
    pub fn tool_identity(
        &self,
        family: XtablesRestoreFamily,
    ) -> Option<&XtablesRestoreToolIdentity> {
        self.tool(family).map(|tool| &tool.identity)
    }

    pub fn execute(
        &mut self,
        artifact: &XtablesRestoreArtifact,
    ) -> Result<XtablesRestoreProcessOutput, XtablesRestoreProcessError> {
        let family = artifact.context().family();
        let config = self.config;
        let tool = self
            .tool(family)
            .ok_or(XtablesRestoreProcessError::MissingFamily { family })?;
        tool.verify_identity(XtablesRestoreMutationDisposition::NotStarted)?;
        let wait = config.wait_seconds.to_string();
        let input = artifact.render_canonical();
        let output = run_pinned_process(
            tool,
            XtablesRestoreProcessOperation::Restore,
            &["-w", &wait, "--noflush"],
            input,
            config.timeout,
        )?;
        // Descriptor pinning prevents path replacement, while the paired
        // byte digests detect in-place mutation both before and across exec.
        // A mismatch cannot be accepted as restore evidence even if the
        // child returned zero.
        tool.verify_identity(XtablesRestoreMutationDisposition::MayHaveMutated)?;
        Ok(XtablesRestoreProcessOutput {
            family,
            tool_identity: tool.identity.clone(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn tool(&self, family: XtablesRestoreFamily) -> Option<&PinnedRestoreTool> {
        match family {
            XtablesRestoreFamily::Ipv4 => Some(&self.ipv4),
            XtablesRestoreFamily::Ipv6 => self.ipv6.as_ref(),
        }
    }
}

struct PinnedRestoreTool {
    family: XtablesRestoreFamily,
    file: File,
    script: bool,
    identity: XtablesRestoreToolIdentity,
}

impl PinnedRestoreTool {
    fn open(
        family: XtablesRestoreFamily,
        path: PathBuf,
        timeout: Duration,
    ) -> Result<Self, XtablesRestoreProcessError> {
        validate_tool_path(family, &path)?;
        let file = open_tool_file(family, &path)?;
        validate_tool_file(family, &path, &file)?;
        let digest = digest_tool_file(family, &path, &file)?;
        let script = descriptor_is_script(family, &path, &file)?;
        let provisional = Self {
            family,
            file,
            script,
            identity: XtablesRestoreToolIdentity {
                path: path.clone(),
                digest,
                reported_flavor: XtablesRestoreReportedFlavor::Legacy,
                version: Box::from("unprobed"),
            },
        };
        let output = run_pinned_process(
            &provisional,
            XtablesRestoreProcessOperation::Probe,
            &["--version"],
            Box::new([]),
            timeout,
        )?;
        let version = joined_version_output(&output.stdout, &output.stderr);
        let reported_flavor = classify_reported_flavor(family, &version)?;
        let observed = digest_tool_file(family, &path, &provisional.file)?;
        if observed != digest {
            return Err(XtablesRestoreProcessError::ToolIdentityChanged {
                family,
                path,
                mutation: XtablesRestoreMutationDisposition::NotStarted,
            });
        }
        Ok(Self {
            identity: XtablesRestoreToolIdentity {
                path,
                digest,
                reported_flavor,
                version,
            },
            ..provisional
        })
    }

    fn verify_identity(
        &self,
        mutation: XtablesRestoreMutationDisposition,
    ) -> Result<(), XtablesRestoreProcessError> {
        let observed =
            digest_tool_file(self.family, &self.identity.path, &self.file).map_err(|source| {
                if mutation == XtablesRestoreMutationDisposition::MayHaveMutated {
                    XtablesRestoreProcessError::PostExecutionToolIdentity {
                        family: self.family,
                        path: self.identity.path.clone(),
                        source: Box::new(source),
                    }
                } else {
                    source
                }
            })?;
        if observed == self.identity.digest {
            Ok(())
        } else {
            Err(XtablesRestoreProcessError::ToolIdentityChanged {
                family: self.family,
                path: self.identity.path.clone(),
                mutation,
            })
        }
    }
}

struct ProcessOutput {
    stdout: Box<str>,
    stderr: Box<str>,
}

struct CapturedBytes {
    tail: Vec<u8>,
    total: usize,
}

enum ChildCompletion {
    Exited(ExitStatus),
    WaitFailed(io::Error),
    TimedOut,
    OutputLimit {
        stream: XtablesRestoreProcessStream,
        actual: usize,
    },
}

fn run_pinned_process(
    tool: &PinnedRestoreTool,
    operation: XtablesRestoreProcessOperation,
    arguments: &[&str],
    input: Box<[u8]>,
    timeout: Duration,
) -> Result<ProcessOutput, XtablesRestoreProcessError> {
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (tool, operation, arguments, input, timeout);
        return Err(XtablesRestoreProcessError::UnsupportedPlatform(
            std::env::consts::OS,
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            XtablesRestoreProcessError::InvalidConfig {
                field: "timeout",
                reason: Box::from("cannot be represented by a monotonic deadline"),
            }
        })?;
        let program = descriptor_path(&tool.file);
        let mut command = Command::new(&program);
        command
            .args(arguments)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        child_process::configure_child_process(
            &mut command,
            ChildProcessConfig {
                new_process_group: true,
                kill_on_parent_death: true,
                close_unlisted_fds: true,
                inherited_fds: if tool.script {
                    vec![tool.file.as_raw_fd()]
                } else {
                    Vec::new()
                },
                ..ChildProcessConfig::default()
            },
        )
        .map_err(|source| XtablesRestoreProcessError::ChildSetup {
            operation,
            family: tool.family,
            source,
        })?;

        let mut child = command
            .spawn()
            .map_err(|source| XtablesRestoreProcessError::Spawn {
                operation,
                family: tool.family,
                program,
                source,
            })?;
        let pid = child.id();
        let stdin = child.stdin.take().expect("piped stdin is present");
        let stdout = child.stdout.take().expect("piped stdout is present");
        let stderr = child.stderr.take().expect("piped stderr is present");
        if let Err(source) = child_process::set_nonblocking(stdin.as_raw_fd()) {
            let error = XtablesRestoreProcessError::Stream {
                operation,
                family: tool.family,
                stream: XtablesRestoreProcessStream::Stdin,
                source,
            };
            return Err(setup_failure_error(
                child,
                pid,
                operation,
                tool.family,
                error,
            ));
        }
        if let Err(source) = child_process::set_nonblocking(stdout.as_raw_fd()) {
            let error = XtablesRestoreProcessError::Stream {
                operation,
                family: tool.family,
                stream: XtablesRestoreProcessStream::Stdout,
                source,
            };
            return Err(setup_failure_error(
                child,
                pid,
                operation,
                tool.family,
                error,
            ));
        }
        if let Err(source) = child_process::set_nonblocking(stderr.as_raw_fd()) {
            let error = XtablesRestoreProcessError::Stream {
                operation,
                family: tool.family,
                stream: XtablesRestoreProcessStream::Stderr,
                source,
            };
            return Err(setup_failure_error(
                child,
                pid,
                operation,
                tool.family,
                error,
            ));
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stdout_total = Arc::new(AtomicUsize::new(0));
        let stderr_total = Arc::new(AtomicUsize::new(0));
        let stdin_worker =
            match spawn_stdin_worker(operation, tool.family, stdin, input, Arc::clone(&stop)) {
                Ok(worker) => worker,
                Err(error) => {
                    return Err(setup_failure_error(
                        child,
                        pid,
                        operation,
                        tool.family,
                        error,
                    ));
                }
            };
        let stdout_worker = match spawn_capture_worker(
            operation,
            tool.family,
            XtablesRestoreProcessStream::Stdout,
            stdout,
            Arc::clone(&stop),
            Arc::clone(&stdout_total),
        ) {
            Ok(worker) => worker,
            Err(error) => {
                stop.store(true, Ordering::Release);
                let cleanup = cleanup_process_group(&mut child, pid);
                let _ = join_stdin_worker(stdin_worker, operation, tool.family);
                if let Err(source) = cleanup {
                    defer_reap(child);
                    return Err(XtablesRestoreProcessError::Cleanup {
                        operation,
                        family: tool.family,
                        process_group: pid,
                        source,
                    });
                }
                return Err(error);
            }
        };
        let stderr_worker = match spawn_capture_worker(
            operation,
            tool.family,
            XtablesRestoreProcessStream::Stderr,
            stderr,
            Arc::clone(&stop),
            Arc::clone(&stderr_total),
        ) {
            Ok(worker) => worker,
            Err(error) => {
                stop.store(true, Ordering::Release);
                let cleanup = cleanup_process_group(&mut child, pid);
                let _ = join_stdin_worker(stdin_worker, operation, tool.family);
                let _ = join_capture_worker(
                    stdout_worker,
                    operation,
                    tool.family,
                    XtablesRestoreProcessStream::Stdout,
                );
                if let Err(source) = cleanup {
                    defer_reap(child);
                    return Err(XtablesRestoreProcessError::Cleanup {
                        operation,
                        family: tool.family,
                        process_group: pid,
                        source,
                    });
                }
                return Err(error);
            }
        };
        let completion = loop {
            let stdout_seen = stdout_total.load(Ordering::Acquire);
            if stdout_seen > MAX_CAPTURE_BYTES {
                break ChildCompletion::OutputLimit {
                    stream: XtablesRestoreProcessStream::Stdout,
                    actual: stdout_seen,
                };
            }
            let stderr_seen = stderr_total.load(Ordering::Acquire);
            if stderr_seen > MAX_CAPTURE_BYTES {
                break ChildCompletion::OutputLimit {
                    stream: XtablesRestoreProcessStream::Stderr,
                    actual: stderr_seen,
                };
            }
            match child.try_wait() {
                Ok(Some(status)) => break ChildCompletion::Exited(status),
                Ok(None) if Instant::now() < deadline => sleep_until_poll(deadline),
                Ok(None) => break ChildCompletion::TimedOut,
                Err(source) => break ChildCompletion::WaitFailed(source),
            }
        };

        let cleanup = cleanup_process_group(&mut child, pid);
        stop.store(true, Ordering::Release);
        let stdin_result = join_stdin_worker(stdin_worker, operation, tool.family);
        let stdout_result = join_capture_worker(
            stdout_worker,
            operation,
            tool.family,
            XtablesRestoreProcessStream::Stdout,
        );
        let stderr_result = join_capture_worker(
            stderr_worker,
            operation,
            tool.family,
            XtablesRestoreProcessStream::Stderr,
        );

        if let Err(source) = cleanup {
            defer_reap(child);
            return Err(XtablesRestoreProcessError::Cleanup {
                operation,
                family: tool.family,
                process_group: pid,
                source,
            });
        }
        let stdout = stdout_result?;
        let stderr = stderr_result?;
        let stdout_text = bounded_lossy_tail(&stdout.tail).into_boxed_str();
        let stderr_text = bounded_lossy_tail(&stderr.tail).into_boxed_str();
        let stdout_actual = stdout.total.max(stdout_total.load(Ordering::Acquire));
        let stderr_actual = stderr.total.max(stderr_total.load(Ordering::Acquire));

        if stdout_actual > MAX_CAPTURE_BYTES {
            return Err(XtablesRestoreProcessError::OutputLimit {
                operation,
                family: tool.family,
                stream: XtablesRestoreProcessStream::Stdout,
                maximum: MAX_CAPTURE_BYTES,
                actual: stdout_actual,
                stdout: stdout_text,
                stderr: stderr_text,
            });
        }
        if stderr_actual > MAX_CAPTURE_BYTES {
            return Err(XtablesRestoreProcessError::OutputLimit {
                operation,
                family: tool.family,
                stream: XtablesRestoreProcessStream::Stderr,
                maximum: MAX_CAPTURE_BYTES,
                actual: stderr_actual,
                stdout: stdout_text,
                stderr: stderr_text,
            });
        }

        match completion {
            ChildCompletion::WaitFailed(source) => Err(XtablesRestoreProcessError::Wait {
                operation,
                family: tool.family,
                pid,
                source,
            }),
            ChildCompletion::TimedOut => Err(XtablesRestoreProcessError::TimedOut {
                operation,
                family: tool.family,
                timeout,
                stdout: stdout_text,
                stderr: stderr_text,
            }),
            ChildCompletion::OutputLimit { stream, actual } => {
                Err(XtablesRestoreProcessError::OutputLimit {
                    operation,
                    family: tool.family,
                    stream,
                    maximum: MAX_CAPTURE_BYTES,
                    actual,
                    stdout: stdout_text,
                    stderr: stderr_text,
                })
            }
            ChildCompletion::Exited(status) if !status.success() => {
                Err(XtablesRestoreProcessError::NonZeroExit {
                    operation,
                    family: tool.family,
                    status,
                    stdout: stdout_text,
                    stderr: stderr_text,
                })
            }
            ChildCompletion::Exited(_) => {
                stdin_result?;
                Ok(ProcessOutput {
                    stdout: stdout_text,
                    stderr: stderr_text,
                })
            }
        }
    }
}

fn spawn_stdin_worker(
    operation: XtablesRestoreProcessOperation,
    family: XtablesRestoreFamily,
    mut stdin: std::process::ChildStdin,
    input: Box<[u8]>,
    stop: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<io::Result<()>>, XtablesRestoreProcessError> {
    thread::Builder::new()
        .name(format!("flux-xtables-{family:?}-stdin"))
        .spawn(move || {
            let mut offset = 0_usize;
            while offset < input.len() {
                match stdin.write(&input[offset..]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "restore stdin accepted zero bytes",
                        ));
                    }
                    Ok(written) => offset = offset.saturating_add(written),
                    Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                    Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                        if stop.load(Ordering::Acquire) {
                            return Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "restore stdin was cancelled before all bytes were written",
                            ));
                        }
                        thread::sleep(POLL_INTERVAL);
                    }
                    Err(source) => return Err(source),
                }
            }
            stdin.flush()
        })
        .map_err(|source| XtablesRestoreProcessError::StreamWorkerSpawn {
            operation,
            family,
            stream: XtablesRestoreProcessStream::Stdin,
            source,
        })
}

fn spawn_capture_worker<R>(
    operation: XtablesRestoreProcessOperation,
    family: XtablesRestoreFamily,
    stream: XtablesRestoreProcessStream,
    mut reader: R,
    stop: Arc<AtomicBool>,
    total: Arc<AtomicUsize>,
) -> Result<thread::JoinHandle<io::Result<CapturedBytes>>, XtablesRestoreProcessError>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(format!("flux-xtables-{family:?}-{stream}"))
        .spawn(move || {
            let mut tail = Vec::with_capacity(MAX_CAPTURE_BYTES);
            let mut observed = 0_usize;
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        return Ok(CapturedBytes {
                            tail,
                            total: observed,
                        });
                    }
                    Ok(read) => {
                        observed = observed.saturating_add(read);
                        total.store(observed, Ordering::Release);
                        retain_tail(&mut tail, &buffer[..read]);
                    }
                    Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                    Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                        if stop.load(Ordering::Acquire) {
                            return Ok(CapturedBytes {
                                tail,
                                total: observed,
                            });
                        }
                        thread::sleep(POLL_INTERVAL);
                    }
                    Err(source) => return Err(source),
                }
            }
        })
        .map_err(|source| XtablesRestoreProcessError::StreamWorkerSpawn {
            operation,
            family,
            stream,
            source,
        })
}

fn join_stdin_worker(
    worker: thread::JoinHandle<io::Result<()>>,
    operation: XtablesRestoreProcessOperation,
    family: XtablesRestoreFamily,
) -> Result<(), XtablesRestoreProcessError> {
    worker
        .join()
        .map_err(|_| XtablesRestoreProcessError::StreamWorkerPanicked {
            operation,
            family,
            stream: XtablesRestoreProcessStream::Stdin,
        })?
        .map_err(|source| XtablesRestoreProcessError::Stream {
            operation,
            family,
            stream: XtablesRestoreProcessStream::Stdin,
            source,
        })
}

fn join_capture_worker(
    worker: thread::JoinHandle<io::Result<CapturedBytes>>,
    operation: XtablesRestoreProcessOperation,
    family: XtablesRestoreFamily,
    stream: XtablesRestoreProcessStream,
) -> Result<CapturedBytes, XtablesRestoreProcessError> {
    worker
        .join()
        .map_err(|_| XtablesRestoreProcessError::StreamWorkerPanicked {
            operation,
            family,
            stream,
        })?
        .map_err(|source| XtablesRestoreProcessError::Stream {
            operation,
            family,
            stream,
            source,
        })
}

fn retain_tail(tail: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() >= MAX_CAPTURE_BYTES {
        tail.clear();
        tail.extend_from_slice(&bytes[bytes.len() - MAX_CAPTURE_BYTES..]);
        return;
    }
    let overflow = tail
        .len()
        .saturating_add(bytes.len())
        .saturating_sub(MAX_CAPTURE_BYTES);
    if overflow != 0 {
        tail.drain(..overflow);
    }
    tail.extend_from_slice(bytes);
}

fn bounded_lossy_tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= MAX_CAPTURE_BYTES {
        return text.into_owned();
    }
    let mut start = text.len() - MAX_CAPTURE_BYTES;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_owned()
}

fn joined_version_output(stdout: &str, stderr: &str) -> Box<str> {
    let stdout = stdout.trim();
    let stderr = stderr.trim();
    match (stdout.is_empty(), stderr.is_empty()) {
        (false, true) => stdout.into(),
        (true, false) => stderr.into(),
        (false, false) => format!("{stdout}\n{stderr}").into_boxed_str(),
        (true, true) => Box::from(""),
    }
}

fn classify_reported_flavor(
    family: XtablesRestoreFamily,
    version: &str,
) -> Result<XtablesRestoreReportedFlavor, XtablesRestoreProcessError> {
    let legacy = version.contains("(legacy)");
    let nft = version.contains("(nf_tables)");
    match (legacy, nft) {
        (true, false) => Ok(XtablesRestoreReportedFlavor::Legacy),
        (false, true) => Ok(XtablesRestoreReportedFlavor::NfTables),
        _ => Err(XtablesRestoreProcessError::ToolFlavor {
            family,
            version: version.into(),
        }),
    }
}

fn validate_tool_path(
    family: XtablesRestoreFamily,
    path: &Path,
) -> Result<(), XtablesRestoreProcessError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(XtablesRestoreProcessError::InvalidPath {
            family,
            path: path.to_path_buf(),
            reason: Box::from("path must be absolute"),
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_tool_file(
    family: XtablesRestoreFamily,
    path: &Path,
) -> Result<File, XtablesRestoreProcessError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| XtablesRestoreProcessError::ToolOpen {
            family,
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn open_tool_file(
    family: XtablesRestoreFamily,
    path: &Path,
) -> Result<File, XtablesRestoreProcessError> {
    let _ = (family, path);
    Err(XtablesRestoreProcessError::UnsupportedPlatform(
        std::env::consts::OS,
    ))
}

fn validate_tool_file(
    family: XtablesRestoreFamily,
    path: &Path,
    file: &File,
) -> Result<(), XtablesRestoreProcessError> {
    let metadata = file
        .metadata()
        .map_err(|source| XtablesRestoreProcessError::ToolIdentity {
            family,
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.file_type().is_file() {
        return Err(XtablesRestoreProcessError::InvalidPath {
            family,
            path: path.to_path_buf(),
            reason: Box::from("tool must be a regular file"),
        });
    }
    if metadata.len() == 0 || metadata.len() > MAX_TOOL_BYTES {
        return Err(XtablesRestoreProcessError::InvalidPath {
            family,
            path: path.to_path_buf(),
            reason: format!("tool size must be in 1..={MAX_TOOL_BYTES}").into_boxed_str(),
        });
    }
    validate_executable_mode(family, path, &metadata)?;
    validate_descriptor(family, path, file)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn validate_executable_mode(
    family: XtablesRestoreFamily,
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), XtablesRestoreProcessError> {
    if metadata.permissions().mode() & 0o111 != 0 {
        Ok(())
    } else {
        Err(XtablesRestoreProcessError::InvalidPath {
            family,
            path: path.to_path_buf(),
            reason: Box::from("tool is not executable"),
        })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn validate_executable_mode(
    _family: XtablesRestoreFamily,
    _path: &Path,
    _metadata: &std::fs::Metadata,
) -> Result<(), XtablesRestoreProcessError> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn validate_descriptor(
    family: XtablesRestoreFamily,
    path: &Path,
    file: &File,
) -> Result<(), XtablesRestoreProcessError> {
    if file.as_raw_fd() < 3 {
        return Err(XtablesRestoreProcessError::InvalidPath {
            family,
            path: path.to_path_buf(),
            reason: Box::from("tool descriptor overlaps standard input or output"),
        });
    }
    child_process::set_close_on_exec(file.as_raw_fd()).map_err(|source| {
        XtablesRestoreProcessError::ToolIdentity {
            family,
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn validate_descriptor(
    _family: XtablesRestoreFamily,
    _path: &Path,
    _file: &File,
) -> Result<(), XtablesRestoreProcessError> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn digest_tool_file(
    family: XtablesRestoreFamily,
    path: &Path,
    file: &File,
) -> Result<XtablesRestoreToolDigest, XtablesRestoreProcessError> {
    let metadata = file
        .metadata()
        .map_err(|source| XtablesRestoreProcessError::ToolIdentity {
            family,
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.len() == 0 || metadata.len() > MAX_TOOL_BYTES {
        return Err(XtablesRestoreProcessError::InvalidPath {
            family,
            path: path.to_path_buf(),
            reason: format!("tool size must be in 1..={MAX_TOOL_BYTES}").into_boxed_str(),
        });
    }
    let mut digest = Sha256::new();
    digest.update(TOOL_DIGEST_DOMAIN);
    digest.update(metadata.len().to_le_bytes());
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 8192];
    while offset < metadata.len() {
        let read = file.read_at(&mut buffer, offset).map_err(|source| {
            XtablesRestoreProcessError::ToolIdentity {
                family,
                path: path.to_path_buf(),
                source,
            }
        })?;
        if read == 0 {
            return Err(XtablesRestoreProcessError::ToolIdentity {
                family,
                path: path.to_path_buf(),
                source: io::Error::new(io::ErrorKind::UnexpectedEof, "tool changed while hashing"),
            });
        }
        digest.update(&buffer[..read]);
        offset = offset.saturating_add(read as u64);
    }
    Ok(XtablesRestoreToolDigest(digest.finalize().into()))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn digest_tool_file(
    _family: XtablesRestoreFamily,
    _path: &Path,
    _file: &File,
) -> Result<XtablesRestoreToolDigest, XtablesRestoreProcessError> {
    Err(XtablesRestoreProcessError::UnsupportedPlatform(
        std::env::consts::OS,
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn descriptor_is_script(
    family: XtablesRestoreFamily,
    path: &Path,
    file: &File,
) -> Result<bool, XtablesRestoreProcessError> {
    let mut magic = [0_u8; 2];
    let read =
        file.read_at(&mut magic, 0)
            .map_err(|source| XtablesRestoreProcessError::ToolIdentity {
                family,
                path: path.to_path_buf(),
                source,
            })?;
    Ok(read == magic.len() && magic == *b"#!")
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn descriptor_is_script(
    _family: XtablesRestoreFamily,
    _path: &Path,
    _file: &File,
) -> Result<bool, XtablesRestoreProcessError> {
    Ok(false)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn descriptor_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn setup_failure_error(
    mut child: Child,
    process_group: u32,
    operation: XtablesRestoreProcessOperation,
    family: XtablesRestoreFamily,
    fallback: XtablesRestoreProcessError,
) -> XtablesRestoreProcessError {
    match cleanup_process_group(&mut child, process_group) {
        Ok(()) => fallback,
        Err(source) => {
            defer_reap(child);
            XtablesRestoreProcessError::Cleanup {
                operation,
                family,
                process_group,
                source,
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn cleanup_process_group(child: &mut Child, process_group: u32) -> io::Result<()> {
    match child_process::signal_process_group(process_group, ProcessSignal::Kill) {
        Ok(()) => {}
        Err(source) if child_process::is_no_such_process(&source) => {}
        Err(source) => return Err(source),
    }
    let Some(deadline) = Instant::now().checked_add(CLEANUP_GRACE) else {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "cleanup deadline overflowed",
        ));
    };
    loop {
        let child_reaped = child.try_wait()?.is_some();
        let group_absent = !child_process::process_group_exists(process_group)?;
        if child_reaped && group_absent {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "restore process group did not exit within cleanup grace",
            ));
        }
        sleep_until_poll(deadline);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn cleanup_process_group(_child: &mut Child, _process_group: u32) -> io::Result<()> {
    Ok(())
}

fn defer_reap(mut child: Child) {
    let pid = child.id();
    let _ = child.kill();
    if let Ok(handle) = thread::Builder::new()
        .name(format!("flux-xtables-reap-{pid}"))
        .spawn(move || {
            let _ = child.wait();
        })
    {
        drop(handle);
    }
}

fn sleep_until_poll(deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    thread::sleep(POLL_INTERVAL.min(remaining));
}

fn ensure_supported() -> Result<(), XtablesRestoreProcessError> {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        Ok(())
    } else {
        Err(XtablesRestoreProcessError::UnsupportedPlatform(
            std::env::consts::OS,
        ))
    }
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
