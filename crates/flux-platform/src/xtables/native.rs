use std::error::Error;
use std::ffi::CString;
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

use super::{MAX_XTABLES_RESTORE_BYTES, XtablesRestoreArtifact, XtablesRestoreFamily};
use crate::child_process::{self, ChildProcessConfig, ProcessSignal};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::ffi::OsStrExt;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::process::CommandExt as _;

const MAX_WAIT_SECONDS: u16 = 60;
const MAX_PROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CAPTURE_BYTES: usize = 16 * 1024;
const MAX_ANDROID_CENSUS_SAVE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOOL_BYTES: u64 = 64 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const CLEANUP_GRACE: Duration = Duration::from_millis(250);
const TOOL_DIGEST_DOMAIN: &[u8] = b"Flux pinned xtables executable\0sha256-v2\0";
const TOOL_SET_DIGEST_DOMAIN: &[u8] = b"Flux coherent pinned xtables tool set\0sha256-v2\0";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum XtablesToolRole {
    Command,
    Restore,
    Save,
}

impl XtablesToolRole {
    #[must_use]
    pub(crate) const fn applet(self, family: XtablesRestoreFamily) -> &'static str {
        match (family, self) {
            (XtablesRestoreFamily::Ipv4, Self::Command) => "iptables",
            (XtablesRestoreFamily::Ipv4, Self::Restore) => "iptables-restore",
            (XtablesRestoreFamily::Ipv4, Self::Save) => "iptables-save",
            (XtablesRestoreFamily::Ipv6, Self::Command) => "ip6tables",
            (XtablesRestoreFamily::Ipv6, Self::Restore) => "ip6tables-restore",
            (XtablesRestoreFamily::Ipv6, Self::Save) => "ip6tables-save",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Command => 1,
            Self::Restore => 2,
            Self::Save => 3,
        }
    }
}

impl fmt::Display for XtablesToolRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Command => "command",
            Self::Restore => "restore",
            Self::Save => "save",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesToolFamilyPaths {
    command: PathBuf,
    restore: PathBuf,
    save: PathBuf,
}

impl XtablesToolFamilyPaths {
    #[must_use]
    pub(crate) fn new(
        command: impl Into<PathBuf>,
        restore: impl Into<PathBuf>,
        save: impl Into<PathBuf>,
    ) -> Self {
        Self {
            command: command.into(),
            restore: restore.into(),
            save: save.into(),
        }
    }

    fn standard(root: &Path, family: XtablesRestoreFamily) -> Self {
        Self::new(
            root.join(XtablesToolRole::Command.applet(family)),
            root.join(XtablesToolRole::Restore.applet(family)),
            root.join(XtablesToolRole::Save.applet(family)),
        )
    }

    #[must_use]
    pub(crate) fn path(&self, role: XtablesToolRole) -> &Path {
        match role {
            XtablesToolRole::Command => &self.command,
            XtablesToolRole::Restore => &self.restore,
            XtablesToolRole::Save => &self.save,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesToolSetPaths {
    ipv4: XtablesToolFamilyPaths,
    ipv6: Option<XtablesToolFamilyPaths>,
}

impl XtablesToolSetPaths {
    #[must_use]
    pub(crate) fn new(ipv4: XtablesToolFamilyPaths, ipv6: Option<XtablesToolFamilyPaths>) -> Self {
        Self { ipv4, ipv6 }
    }

    #[must_use]
    pub(crate) fn ipv4(&self) -> &XtablesToolFamilyPaths {
        &self.ipv4
    }

    #[must_use]
    pub(crate) fn ipv6(&self) -> Option<&XtablesToolFamilyPaths> {
        self.ipv6.as_ref()
    }
}

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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct XtablesToolFileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    owner_user: u32,
    owner_group: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

impl XtablesToolFileIdentity {
    #[must_use]
    pub(crate) const fn device(self) -> u64 {
        self.device
    }

    #[must_use]
    pub(crate) const fn inode(self) -> u64 {
        self.inode
    }

    #[must_use]
    pub(crate) const fn length(self) -> u64 {
        self.length
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesRestoreToolIdentity {
    path: PathBuf,
    family: XtablesRestoreFamily,
    role: XtablesToolRole,
    applet: Box<str>,
    file: XtablesToolFileIdentity,
    digest: XtablesRestoreToolDigest,
    reported_flavor: XtablesRestoreReportedFlavor,
    release: Box<str>,
    version: Box<str>,
}

impl XtablesRestoreToolIdentity {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub(crate) const fn family(&self) -> XtablesRestoreFamily {
        self.family
    }

    #[must_use]
    pub(crate) const fn role(&self) -> XtablesToolRole {
        self.role
    }

    #[must_use]
    pub const fn applet(&self) -> &str {
        &self.applet
    }

    #[must_use]
    pub(crate) const fn file_identity(&self) -> XtablesToolFileIdentity {
        self.file
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
    pub(crate) const fn release(&self) -> &str {
        &self.release
    }

    #[must_use]
    pub const fn version(&self) -> &str {
        &self.version
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct XtablesToolSetDigest([u8; 32]);

impl XtablesToolSetDigest {
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesToolFamilyIdentity {
    command: XtablesRestoreToolIdentity,
    restore: XtablesRestoreToolIdentity,
    save: XtablesRestoreToolIdentity,
}

impl XtablesToolFamilyIdentity {
    #[must_use]
    pub(crate) const fn tool(&self, role: XtablesToolRole) -> &XtablesRestoreToolIdentity {
        match role {
            XtablesToolRole::Command => &self.command,
            XtablesToolRole::Restore => &self.restore,
            XtablesToolRole::Save => &self.save,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesToolSetIdentity {
    digest: XtablesToolSetDigest,
    reported_flavor: XtablesRestoreReportedFlavor,
    release: Box<str>,
    ipv4: XtablesToolFamilyIdentity,
    ipv6: Option<XtablesToolFamilyIdentity>,
}

impl XtablesToolSetIdentity {
    #[must_use]
    pub(crate) const fn digest(&self) -> XtablesToolSetDigest {
        self.digest
    }

    #[must_use]
    pub(crate) const fn reported_flavor(&self) -> XtablesRestoreReportedFlavor {
        self.reported_flavor
    }

    #[must_use]
    pub(crate) const fn release(&self) -> &str {
        &self.release
    }

    #[must_use]
    pub(crate) const fn family(
        &self,
        family: XtablesRestoreFamily,
    ) -> Option<&XtablesToolFamilyIdentity> {
        match family {
            XtablesRestoreFamily::Ipv4 => Some(&self.ipv4),
            XtablesRestoreFamily::Ipv6 => self.ipv6.as_ref(),
        }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesSaveProcessOutput {
    family: XtablesRestoreFamily,
    tool_identity: XtablesRestoreToolIdentity,
    stdout: Box<[u8]>,
    stderr: Box<str>,
}

impl XtablesSaveProcessOutput {
    #[must_use]
    pub(crate) const fn family(&self) -> XtablesRestoreFamily {
        self.family
    }

    #[must_use]
    pub(crate) const fn tool_identity(&self) -> &XtablesRestoreToolIdentity {
        &self.tool_identity
    }

    #[must_use]
    pub(crate) const fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    #[must_use]
    pub(crate) const fn stderr(&self) -> &str {
        &self.stderr
    }
}

/// Complete dual-stack save bytes collected through the read-only Android census boundary.
///
/// Tool identities and diagnostics remain private to the process adapter. Callers receive only the
/// two bounded snapshots needed by the typed fwmark parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AndroidXtablesSaveSnapshots {
    ipv4: Box<[u8]>,
    ipv6: Box<[u8]>,
}

impl AndroidXtablesSaveSnapshots {
    #[must_use]
    pub(crate) const fn ipv4(&self) -> &[u8] {
        &self.ipv4
    }

    #[must_use]
    pub(crate) const fn ipv6(&self) -> &[u8] {
        &self.ipv6
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XtablesRestoreProcessOperation {
    Probe(XtablesToolRole),
    Restore,
    Save,
}

impl fmt::Display for XtablesRestoreProcessOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Probe(XtablesToolRole::Command) => "command probe",
            Self::Probe(XtablesToolRole::Restore) => "restore probe",
            Self::Probe(XtablesToolRole::Save) => "save probe",
            Self::Restore => "restore",
            Self::Save => "save",
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
    ToolCoherence,
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
    ToolSetCoherence {
        family: XtablesRestoreFamily,
        role: XtablesToolRole,
        reason: Box<str>,
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
            Self::ToolSetCoherence { .. } => XtablesRestoreProcessErrorKind::ToolCoherence,
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
            | Self::ToolSetCoherence { .. }
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
            Self::ToolSetCoherence {
                family,
                role,
                reason,
            } => write!(
                formatter,
                "incoherent {family:?} xtables {role} tool set: {reason}"
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
            | Self::ToolSetCoherence { .. }
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
    ipv4: PinnedXtablesTool,
    ipv6: Option<PinnedXtablesTool>,
    reported_flavor: XtablesRestoreReportedFlavor,
    config: XtablesRestoreProcessConfig,
}

impl XtablesRestoreProcessAdapter {
    pub fn open(
        paths: XtablesRestoreProcessPaths,
        config: XtablesRestoreProcessConfig,
    ) -> Result<Self, XtablesRestoreProcessError> {
        ensure_supported()?;
        let mut ipv4 = PinnedXtablesTool::open_exact_unprobed(
            XtablesRestoreFamily::Ipv4,
            XtablesToolRole::Restore,
            paths.ipv4,
        )?;
        let mut ipv6 = paths
            .ipv6
            .map(|path| {
                PinnedXtablesTool::open_exact_unprobed(
                    XtablesRestoreFamily::Ipv6,
                    XtablesToolRole::Restore,
                    path,
                )
            })
            .transpose()?;
        // Open, validate, and descriptor-pin the complete selected mapping
        // before any candidate executable is allowed to run its version probe.
        ipv4.probe(config.timeout)?;
        if let Some(ipv6) = &mut ipv6 {
            ipv6.probe(config.timeout)?;
        }
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
            &["-w", &wait, "--noflush", "--modprobe=/dev/null"],
            ProcessStdin::Bytes(input),
            CapturePolicy::Tail(MAX_CAPTURE_BYTES),
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
            stdout: bounded_lossy_tail(&output.stdout.bytes).into_boxed_str(),
            stderr: bounded_lossy_tail(&output.stderr.bytes).into_boxed_str(),
        })
    }

    fn tool(&self, family: XtablesRestoreFamily) -> Option<&PinnedXtablesTool> {
        match family {
            XtablesRestoreFamily::Ipv4 => Some(&self.ipv4),
            XtablesRestoreFamily::Ipv6 => self.ipv6.as_ref(),
        }
    }
}

#[derive(Debug)]
struct PinnedXtablesTool {
    family: XtablesRestoreFamily,
    role: XtablesToolRole,
    file: File,
    script: bool,
    identity: XtablesRestoreToolIdentity,
}

impl PinnedXtablesTool {
    fn open_exact_unprobed(
        family: XtablesRestoreFamily,
        role: XtablesToolRole,
        path: PathBuf,
    ) -> Result<Self, XtablesRestoreProcessError> {
        validate_tool_path(family, &path)?;
        let file = open_tool_file_exact(family, &path)?;
        Self::from_opened_unprobed(family, role, path, file)
    }

    fn from_opened_unprobed(
        family: XtablesRestoreFamily,
        role: XtablesToolRole,
        path: PathBuf,
        file: File,
    ) -> Result<Self, XtablesRestoreProcessError> {
        validate_tool_file(family, &path, &file)?;
        let digest = digest_tool_file(family, &path, &file)?;
        let file_identity = tool_file_identity(family, &path, &file)?;
        let script = descriptor_is_script(family, &path, &file)?;
        Ok(Self {
            family,
            role,
            file,
            script,
            identity: XtablesRestoreToolIdentity {
                path: path.clone(),
                family,
                role,
                applet: role.applet(family).into(),
                file: file_identity,
                digest,
                reported_flavor: XtablesRestoreReportedFlavor::Legacy,
                release: Box::from("unprobed"),
                version: Box::from("unprobed"),
            },
        })
    }

    fn probe(&mut self, timeout: Duration) -> Result<(), XtablesRestoreProcessError> {
        let output = run_pinned_process(
            self,
            XtablesRestoreProcessOperation::Probe(self.role),
            &["--version"],
            ProcessStdin::Null,
            CapturePolicy::Tail(MAX_CAPTURE_BYTES),
            timeout,
        )?;
        let stdout = bounded_lossy_tail(&output.stdout.bytes);
        let stderr = bounded_lossy_tail(&output.stderr.bytes);
        let version = joined_version_output(&stdout, &stderr);
        let (reported_flavor, release) = parse_tool_version(self.family, self.role, &version)?;
        let observed = digest_tool_file(self.family, &self.identity.path, &self.file)?;
        let observed_file = tool_file_identity(self.family, &self.identity.path, &self.file)?;
        if observed != self.identity.digest || observed_file != self.identity.file {
            return Err(XtablesRestoreProcessError::ToolIdentityChanged {
                family: self.family,
                path: self.identity.path.clone(),
                mutation: XtablesRestoreMutationDisposition::NotStarted,
            });
        }
        self.identity.reported_flavor = reported_flavor;
        self.identity.release = release;
        self.identity.version = version;
        Ok(())
    }

    fn verify_identity(
        &self,
        mutation: XtablesRestoreMutationDisposition,
    ) -> Result<(), XtablesRestoreProcessError> {
        let observe = || {
            Ok((
                digest_tool_file(self.family, &self.identity.path, &self.file)?,
                tool_file_identity(self.family, &self.identity.path, &self.file)?,
            ))
        };
        let (observed, observed_file) = observe().map_err(|source| {
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
        if observed == self.identity.digest && observed_file == self.identity.file {
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

/// Collects complete IPv4 and IPv6 save output without admitting command or restore applets.
///
/// Both fixed save applets are opened and descriptor-pinned before either is executed. The pair
/// must identify one coherent multicall executable and one normalized version/flavor. Only the
/// fixed `--version` probes and zero-argument save operations can be executed through this API.
pub(crate) fn collect_android_xtables_save_snapshots(
    root_path: &Path,
    bound: Duration,
) -> Result<AndroidXtablesSaveSnapshots, XtablesRestoreProcessError> {
    ensure_supported()?;
    if bound.is_zero() || bound > MAX_PROCESS_TIMEOUT {
        return Err(XtablesRestoreProcessError::InvalidConfig {
            field: "Android census xtables deadline",
            reason: format!("must be nonzero and at most {MAX_PROCESS_TIMEOUT:?}").into_boxed_str(),
        });
    }
    let deadline = Instant::now().checked_add(bound).ok_or_else(|| {
        XtablesRestoreProcessError::InvalidConfig {
            field: "Android census xtables deadline",
            reason: Box::from("cannot be represented by a monotonic deadline"),
        }
    })?;
    validate_discovery_root(root_path)?;
    let root = open_discovery_root(root_path)?;
    let mut ipv4 = open_discovered_tool(
        &root,
        root_path,
        XtablesRestoreFamily::Ipv4,
        XtablesToolRole::Save,
    )?;
    census_remaining(deadline, bound, XtablesRestoreFamily::Ipv4)?;
    let mut ipv6 = open_discovered_tool(
        &root,
        root_path,
        XtablesRestoreFamily::Ipv6,
        XtablesToolRole::Save,
    )?;
    census_remaining(deadline, bound, XtablesRestoreFamily::Ipv6)?;

    if ipv4.identity.digest != ipv6.identity.digest {
        return Err(tool_set_coherence_error(
            &ipv6.identity,
            "executable digest differs from the admitted dual-stack save profile".to_owned(),
        ));
    }

    ipv4.probe(census_remaining(
        deadline,
        bound,
        XtablesRestoreFamily::Ipv4,
    )?)?;
    ipv6.probe(census_remaining(
        deadline,
        bound,
        XtablesRestoreFamily::Ipv6,
    )?)?;
    if ipv4.identity.reported_flavor != ipv6.identity.reported_flavor {
        return Err(tool_set_coherence_error(
            &ipv6.identity,
            format!(
                "reported {:?}, expected {:?}",
                ipv6.identity.reported_flavor, ipv4.identity.reported_flavor
            ),
        ));
    }
    if ipv4.identity.release != ipv6.identity.release {
        return Err(tool_set_coherence_error(
            &ipv6.identity,
            format!(
                "reported release {}, expected {}",
                ipv6.identity.release, ipv4.identity.release
            ),
        ));
    }

    verify_android_census_save_tools(&ipv4, &ipv6)?;
    let ipv4_output = run_pinned_process(
        &ipv4,
        XtablesRestoreProcessOperation::Save,
        &[],
        ProcessStdin::Null,
        CapturePolicy::Complete(MAX_ANDROID_CENSUS_SAVE_BYTES),
        census_remaining(deadline, bound, XtablesRestoreFamily::Ipv4)?,
    )?;
    let ipv6_output = run_pinned_process(
        &ipv6,
        XtablesRestoreProcessOperation::Save,
        &[],
        ProcessStdin::Null,
        CapturePolicy::Complete(MAX_ANDROID_CENSUS_SAVE_BYTES),
        census_remaining(deadline, bound, XtablesRestoreFamily::Ipv6)?,
    )?;
    verify_android_census_save_tools(&ipv4, &ipv6)?;
    census_remaining(deadline, bound, XtablesRestoreFamily::Ipv6)?;

    Ok(AndroidXtablesSaveSnapshots {
        ipv4: ipv4_output.stdout.bytes.into_boxed_slice(),
        ipv6: ipv6_output.stdout.bytes.into_boxed_slice(),
    })
}

fn verify_android_census_save_tools(
    ipv4: &PinnedXtablesTool,
    ipv6: &PinnedXtablesTool,
) -> Result<(), XtablesRestoreProcessError> {
    ipv4.verify_identity(XtablesRestoreMutationDisposition::NotStarted)?;
    ipv6.verify_identity(XtablesRestoreMutationDisposition::NotStarted)
}

fn census_remaining(
    deadline: Instant,
    bound: Duration,
    family: XtablesRestoreFamily,
) -> Result<Duration, XtablesRestoreProcessError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(XtablesRestoreProcessError::TimedOut {
            operation: XtablesRestoreProcessOperation::Save,
            family,
            timeout: bound,
            stdout: Box::from(""),
            stderr: Box::from(""),
        })
    } else {
        Ok(remaining)
    }
}

#[derive(Debug)]
struct PinnedXtablesFamily {
    command: PinnedXtablesTool,
    restore: PinnedXtablesTool,
    save: PinnedXtablesTool,
}

impl PinnedXtablesFamily {
    fn open_exact_unprobed(
        family: XtablesRestoreFamily,
        paths: XtablesToolFamilyPaths,
    ) -> Result<Self, XtablesRestoreProcessError> {
        Ok(Self {
            command: PinnedXtablesTool::open_exact_unprobed(
                family,
                XtablesToolRole::Command,
                paths.command,
            )?,
            restore: PinnedXtablesTool::open_exact_unprobed(
                family,
                XtablesToolRole::Restore,
                paths.restore,
            )?,
            save: PinnedXtablesTool::open_exact_unprobed(
                family,
                XtablesToolRole::Save,
                paths.save,
            )?,
        })
    }

    fn discover_standard_unprobed(
        root: &File,
        root_path: &Path,
        family: XtablesRestoreFamily,
    ) -> Result<Self, XtablesRestoreProcessError> {
        Ok(Self {
            command: open_discovered_tool(root, root_path, family, XtablesToolRole::Command)?,
            restore: open_discovered_tool(root, root_path, family, XtablesToolRole::Restore)?,
            save: open_discovered_tool(root, root_path, family, XtablesToolRole::Save)?,
        })
    }

    fn probe_all(&mut self, timeout: Duration) -> Result<(), XtablesRestoreProcessError> {
        self.command.probe(timeout)?;
        self.restore.probe(timeout)?;
        self.save.probe(timeout)
    }

    const fn tool(&self, role: XtablesToolRole) -> &PinnedXtablesTool {
        match role {
            XtablesToolRole::Command => &self.command,
            XtablesToolRole::Restore => &self.restore,
            XtablesToolRole::Save => &self.save,
        }
    }

    fn identity(&self) -> XtablesToolFamilyIdentity {
        XtablesToolFamilyIdentity {
            command: self.command.identity.clone(),
            restore: self.restore.identity.clone(),
            save: self.save.identity.clone(),
        }
    }

    fn verify_all(
        &self,
        mutation: XtablesRestoreMutationDisposition,
    ) -> Result<(), XtablesRestoreProcessError> {
        self.command.verify_identity(mutation)?;
        self.restore.verify_identity(mutation)?;
        self.save.verify_identity(mutation)
    }
}

/// Coherent descriptor-pinned command/restore/save process Adapter.
///
/// The Adapter exposes only typed restore and save operations. It never accepts
/// caller-supplied argument vectors, and successful process execution remains
/// implementation evidence rather than native transaction authority.
#[derive(Debug)]
pub(crate) struct XtablesToolSetProcessAdapter {
    ipv4: PinnedXtablesFamily,
    ipv6: Option<PinnedXtablesFamily>,
    identity: XtablesToolSetIdentity,
    config: XtablesRestoreProcessConfig,
}

impl XtablesToolSetProcessAdapter {
    pub(crate) fn open_exact(
        paths: XtablesToolSetPaths,
        config: XtablesRestoreProcessConfig,
    ) -> Result<Self, XtablesRestoreProcessError> {
        Self::open_exact_with_coherence(paths, config, true)
    }

    fn open_exact_with_coherence(
        paths: XtablesToolSetPaths,
        config: XtablesRestoreProcessConfig,
        require_common_digest: bool,
    ) -> Result<Self, XtablesRestoreProcessError> {
        ensure_supported()?;
        let ipv4 =
            PinnedXtablesFamily::open_exact_unprobed(XtablesRestoreFamily::Ipv4, paths.ipv4)?;
        let ipv6 = paths
            .ipv6
            .map(|paths| {
                PinnedXtablesFamily::open_exact_unprobed(XtablesRestoreFamily::Ipv6, paths)
            })
            .transpose()?;
        Self::from_families(ipv4, ipv6, config, require_common_digest)
    }

    pub(crate) fn discover_standard(
        root: impl AsRef<Path>,
        include_ipv6: bool,
        config: XtablesRestoreProcessConfig,
    ) -> Result<Self, XtablesRestoreProcessError> {
        Self::discover_standard_with_coherence(root.as_ref(), include_ipv6, config, true)
    }

    fn discover_standard_with_coherence(
        root_path: &Path,
        include_ipv6: bool,
        config: XtablesRestoreProcessConfig,
        require_common_digest: bool,
    ) -> Result<Self, XtablesRestoreProcessError> {
        ensure_supported()?;
        validate_discovery_root(root_path)?;
        let root = open_discovery_root(root_path)?;
        let ipv4 = PinnedXtablesFamily::discover_standard_unprobed(
            &root,
            root_path,
            XtablesRestoreFamily::Ipv4,
        )?;
        let ipv6 = include_ipv6
            .then(|| {
                PinnedXtablesFamily::discover_standard_unprobed(
                    &root,
                    root_path,
                    XtablesRestoreFamily::Ipv6,
                )
            })
            .transpose()?;
        Self::from_families(ipv4, ipv6, config, require_common_digest)
    }

    #[cfg(test)]
    fn open_exact_for_tests(
        paths: XtablesToolSetPaths,
        config: XtablesRestoreProcessConfig,
    ) -> Result<Self, XtablesRestoreProcessError> {
        Self::open_exact_with_coherence(paths, config, false)
    }

    #[cfg(test)]
    fn discover_standard_for_tests(
        root: impl AsRef<Path>,
        include_ipv6: bool,
        config: XtablesRestoreProcessConfig,
    ) -> Result<Self, XtablesRestoreProcessError> {
        Self::discover_standard_with_coherence(root.as_ref(), include_ipv6, config, false)
    }

    fn from_families(
        mut ipv4: PinnedXtablesFamily,
        mut ipv6: Option<PinnedXtablesFamily>,
        config: XtablesRestoreProcessConfig,
        require_common_digest: bool,
    ) -> Result<Self, XtablesRestoreProcessError> {
        validate_tool_set_mapping_coherence(&ipv4, ipv6.as_ref(), require_common_digest)?;
        // Mapping and trust admission happens before the first `--version`
        // execution. A mismapped candidate therefore cannot execute merely to
        // tell Flux that the set is incoherent.
        ipv4.probe_all(config.timeout)?;
        if let Some(ipv6) = &mut ipv6 {
            ipv6.probe_all(config.timeout)?;
        }
        validate_tool_set_version_coherence(&ipv4, ipv6.as_ref())?;
        let ipv4_identity = ipv4.identity();
        let ipv6_identity = ipv6.as_ref().map(PinnedXtablesFamily::identity);
        let reported_flavor = ipv4.command.identity.reported_flavor;
        let release = ipv4.command.identity.release.clone();
        let digest = digest_tool_set(&ipv4_identity, ipv6_identity.as_ref());
        Ok(Self {
            ipv4,
            ipv6,
            identity: XtablesToolSetIdentity {
                digest,
                reported_flavor,
                release,
                ipv4: ipv4_identity,
                ipv6: ipv6_identity,
            },
            config,
        })
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> &XtablesToolSetIdentity {
        &self.identity
    }

    pub(crate) fn restore(
        &mut self,
        artifact: &XtablesRestoreArtifact,
    ) -> Result<XtablesRestoreProcessOutput, XtablesRestoreProcessError> {
        let family = artifact.context().family();
        let config = self.config;
        self.verify_all(XtablesRestoreMutationDisposition::NotStarted)?;
        let tool = self
            .family(family)
            .ok_or(XtablesRestoreProcessError::MissingFamily { family })?
            .tool(XtablesToolRole::Restore);
        let wait = config.wait_seconds.to_string();
        // This disables the userspace modprobe helper only. It is not evidence
        // that the kernel avoided request_module(), so the caller must not
        // treat process success as no-autoload or production mutation authority.
        let output = run_pinned_process(
            tool,
            XtablesRestoreProcessOperation::Restore,
            &["-w", &wait, "--noflush", "--modprobe=/dev/null"],
            ProcessStdin::Bytes(artifact.render_canonical()),
            CapturePolicy::Tail(MAX_CAPTURE_BYTES),
            config.timeout,
        )?;
        self.verify_all(XtablesRestoreMutationDisposition::MayHaveMutated)?;
        Ok(XtablesRestoreProcessOutput {
            family,
            tool_identity: tool.identity.clone(),
            stdout: bounded_lossy_tail(&output.stdout.bytes).into_boxed_str(),
            stderr: bounded_lossy_tail(&output.stderr.bytes).into_boxed_str(),
        })
    }

    pub(crate) fn save(
        &mut self,
        family: XtablesRestoreFamily,
    ) -> Result<XtablesSaveProcessOutput, XtablesRestoreProcessError> {
        let config = self.config;
        self.verify_all(XtablesRestoreMutationDisposition::NotStarted)?;
        let tool = self
            .family(family)
            .ok_or(XtablesRestoreProcessError::MissingFamily { family })?
            .tool(XtablesToolRole::Save);
        let output = run_pinned_process(
            tool,
            XtablesRestoreProcessOperation::Save,
            &[],
            ProcessStdin::Null,
            CapturePolicy::Complete(MAX_XTABLES_RESTORE_BYTES),
            config.timeout,
        )?;
        self.verify_all(XtablesRestoreMutationDisposition::NotStarted)?;
        Ok(XtablesSaveProcessOutput {
            family,
            tool_identity: tool.identity.clone(),
            stdout: output.stdout.bytes.into_boxed_slice(),
            stderr: bounded_lossy_tail(&output.stderr.bytes).into_boxed_str(),
        })
    }

    fn family(&self, family: XtablesRestoreFamily) -> Option<&PinnedXtablesFamily> {
        match family {
            XtablesRestoreFamily::Ipv4 => Some(&self.ipv4),
            XtablesRestoreFamily::Ipv6 => self.ipv6.as_ref(),
        }
    }

    fn verify_all(
        &self,
        mutation: XtablesRestoreMutationDisposition,
    ) -> Result<(), XtablesRestoreProcessError> {
        self.ipv4.verify_all(mutation)?;
        if let Some(ipv6) = &self.ipv6 {
            ipv6.verify_all(mutation)?;
        }
        Ok(())
    }
}

fn validate_tool_set_mapping_coherence(
    ipv4: &PinnedXtablesFamily,
    ipv6: Option<&PinnedXtablesFamily>,
    require_common_digest: bool,
) -> Result<(), XtablesRestoreProcessError> {
    if !require_common_digest {
        return Ok(());
    }
    let reference = &ipv4.command.identity;
    for family_tools in std::iter::once(ipv4).chain(ipv6) {
        for role in [
            XtablesToolRole::Command,
            XtablesToolRole::Restore,
            XtablesToolRole::Save,
        ] {
            let identity = &family_tools.tool(role).identity;
            if identity.digest != reference.digest {
                return Err(tool_set_coherence_error(
                    identity,
                    "executable digest differs from the admitted multicall profile".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_tool_set_version_coherence(
    ipv4: &PinnedXtablesFamily,
    ipv6: Option<&PinnedXtablesFamily>,
) -> Result<(), XtablesRestoreProcessError> {
    let reference = &ipv4.command.identity;
    for family_tools in std::iter::once(ipv4).chain(ipv6) {
        for role in [
            XtablesToolRole::Command,
            XtablesToolRole::Restore,
            XtablesToolRole::Save,
        ] {
            let identity = &family_tools.tool(role).identity;
            if identity.reported_flavor != reference.reported_flavor {
                return Err(tool_set_coherence_error(
                    identity,
                    format!(
                        "reported {:?}, expected {:?}",
                        identity.reported_flavor, reference.reported_flavor
                    ),
                ));
            }
            if identity.release != reference.release {
                return Err(tool_set_coherence_error(
                    identity,
                    format!(
                        "reported release {}, expected {}",
                        identity.release, reference.release
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn tool_set_coherence_error(
    identity: &XtablesRestoreToolIdentity,
    reason: String,
) -> XtablesRestoreProcessError {
    XtablesRestoreProcessError::ToolSetCoherence {
        family: identity.family,
        role: identity.role,
        reason: reason.into_boxed_str(),
    }
}

fn digest_tool_set(
    ipv4: &XtablesToolFamilyIdentity,
    ipv6: Option<&XtablesToolFamilyIdentity>,
) -> XtablesToolSetDigest {
    let mut digest = Sha256::new();
    digest.update(TOOL_SET_DIGEST_DOMAIN);
    hash_tool_family(&mut digest, XtablesRestoreFamily::Ipv4, ipv4);
    if let Some(ipv6) = ipv6 {
        digest.update([1]);
        hash_tool_family(&mut digest, XtablesRestoreFamily::Ipv6, ipv6);
    } else {
        digest.update([0]);
    }
    XtablesToolSetDigest(digest.finalize().into())
}

fn hash_tool_family(
    digest: &mut Sha256,
    family: XtablesRestoreFamily,
    identity: &XtablesToolFamilyIdentity,
) {
    digest.update([match family {
        XtablesRestoreFamily::Ipv4 => 4,
        XtablesRestoreFamily::Ipv6 => 6,
    }]);
    for role in [
        XtablesToolRole::Command,
        XtablesToolRole::Restore,
        XtablesToolRole::Save,
    ] {
        let tool = identity.tool(role);
        digest.update([role.tag()]);
        hash_sized_bytes(digest, tool.applet.as_bytes());
        hash_sized_bytes(digest, path_bytes(&tool.path).as_ref());
        digest.update(tool.file.device.to_le_bytes());
        digest.update(tool.file.inode.to_le_bytes());
        digest.update(tool.file.length.to_le_bytes());
        digest.update(tool.file.mode.to_le_bytes());
        digest.update(tool.file.owner_user.to_le_bytes());
        digest.update(tool.file.owner_group.to_le_bytes());
        digest.update(tool.file.modified_seconds.to_le_bytes());
        digest.update(tool.file.modified_nanoseconds.to_le_bytes());
        digest.update(tool.digest.as_bytes());
        digest.update([match tool.reported_flavor {
            XtablesRestoreReportedFlavor::Legacy => 1,
            XtablesRestoreReportedFlavor::NfTables => 2,
        }]);
        hash_sized_bytes(digest, tool.release.as_bytes());
        hash_sized_bytes(digest, tool.version.as_bytes());
    }
}

fn hash_sized_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn path_bytes(path: &Path) -> std::borrow::Cow<'_, [u8]> {
    std::borrow::Cow::Borrowed(path.as_os_str().as_bytes())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn path_bytes(path: &Path) -> std::borrow::Cow<'_, [u8]> {
    std::borrow::Cow::Owned(path.to_string_lossy().into_owned().into_bytes())
}

struct ProcessOutput {
    stdout: CapturedBytes,
    stderr: CapturedBytes,
}

struct CapturedBytes {
    bytes: Vec<u8>,
    total: usize,
}

enum ProcessStdin {
    Null,
    Bytes(Box<[u8]>),
}

#[derive(Clone, Copy)]
enum CapturePolicy {
    Tail(usize),
    Complete(usize),
}

impl CapturePolicy {
    const fn limit(self) -> usize {
        match self {
            Self::Tail(limit) | Self::Complete(limit) => limit,
        }
    }
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
    tool: &PinnedXtablesTool,
    operation: XtablesRestoreProcessOperation,
    arguments: &[&str],
    input: ProcessStdin,
    stdout_policy: CapturePolicy,
    timeout: Duration,
) -> Result<ProcessOutput, XtablesRestoreProcessError> {
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (tool, operation, arguments, input, stdout_policy, timeout);
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
        let piped_stdin = matches!(&input, ProcessStdin::Bytes(_));
        command
            .arg0(tool.identity.applet())
            .args(arguments)
            .env_clear()
            .current_dir("/")
            .stdin(if piped_stdin {
                Stdio::piped()
            } else {
                Stdio::null()
            })
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
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("piped stdout is present");
        let stderr = child.stderr.take().expect("piped stderr is present");
        if let Some(stdin) = &stdin
            && let Err(source) = child_process::set_nonblocking(stdin.as_raw_fd())
        {
            return Err(setup_failure_error(
                child,
                pid,
                operation,
                tool.family,
                XtablesRestoreProcessError::Stream {
                    operation,
                    family: tool.family,
                    stream: XtablesRestoreProcessStream::Stdin,
                    source,
                },
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
        let stdin_worker = match (stdin, input) {
            (Some(stdin), ProcessStdin::Bytes(bytes)) => {
                match spawn_stdin_worker(operation, tool.family, stdin, bytes, Arc::clone(&stop)) {
                    Ok(worker) => Some(worker),
                    Err(error) => {
                        return Err(setup_failure_error(
                            child,
                            pid,
                            operation,
                            tool.family,
                            error,
                        ));
                    }
                }
            }
            (None, ProcessStdin::Null) => None,
            (Some(_), ProcessStdin::Null) | (None, ProcessStdin::Bytes(_)) => {
                unreachable!("configured child stdin and typed input must agree")
            }
        };
        let stdout_worker = match spawn_capture_worker(
            operation,
            tool.family,
            XtablesRestoreProcessStream::Stdout,
            stdout,
            Arc::clone(&stop),
            Arc::clone(&stdout_total),
            stdout_policy,
        ) {
            Ok(worker) => worker,
            Err(error) => {
                stop.store(true, Ordering::Release);
                let cleanup = cleanup_process_group(&mut child, pid);
                if let Some(stdin_worker) = stdin_worker {
                    let _ = join_stdin_worker(stdin_worker, operation, tool.family);
                }
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
            CapturePolicy::Tail(MAX_CAPTURE_BYTES),
        ) {
            Ok(worker) => worker,
            Err(error) => {
                stop.store(true, Ordering::Release);
                let cleanup = cleanup_process_group(&mut child, pid);
                if let Some(stdin_worker) = stdin_worker {
                    let _ = join_stdin_worker(stdin_worker, operation, tool.family);
                }
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
        let stdout_limit = stdout_policy.limit();
        let completion = loop {
            let stdout_seen = stdout_total.load(Ordering::Acquire);
            if stdout_seen > stdout_limit {
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
        let stdin_result = stdin_worker
            .map(|worker| join_stdin_worker(worker, operation, tool.family))
            .transpose();
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
        let stdout_text = bounded_lossy_tail(&stdout.bytes).into_boxed_str();
        let stderr_text = bounded_lossy_tail(&stderr.bytes).into_boxed_str();
        let stdout_actual = stdout.total.max(stdout_total.load(Ordering::Acquire));
        let stderr_actual = stderr.total.max(stderr_total.load(Ordering::Acquire));

        if stdout_actual > stdout_limit {
            return Err(XtablesRestoreProcessError::OutputLimit {
                operation,
                family: tool.family,
                stream: XtablesRestoreProcessStream::Stdout,
                maximum: stdout_limit,
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
                let maximum = match stream {
                    XtablesRestoreProcessStream::Stdout => stdout_limit,
                    XtablesRestoreProcessStream::Stderr => MAX_CAPTURE_BYTES,
                    XtablesRestoreProcessStream::Stdin => {
                        unreachable!("stdin is never an output-limit stream")
                    }
                };
                Err(XtablesRestoreProcessError::OutputLimit {
                    operation,
                    family: tool.family,
                    stream,
                    maximum,
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
                Ok(ProcessOutput { stdout, stderr })
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
    policy: CapturePolicy,
) -> Result<thread::JoinHandle<io::Result<CapturedBytes>>, XtablesRestoreProcessError>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(format!("flux-xtables-{family:?}-{stream}"))
        .spawn(move || {
            let mut bytes = Vec::with_capacity(policy.limit().min(16 * 1024));
            let mut observed = 0_usize;
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        return Ok(CapturedBytes {
                            bytes,
                            total: observed,
                        });
                    }
                    Ok(read) => {
                        observed = observed.saturating_add(read);
                        total.store(observed, Ordering::Release);
                        match policy {
                            CapturePolicy::Tail(limit) => {
                                retain_tail(&mut bytes, &buffer[..read], limit);
                            }
                            CapturePolicy::Complete(limit) => {
                                let remaining = limit.saturating_sub(bytes.len());
                                bytes.extend_from_slice(&buffer[..read.min(remaining)]);
                            }
                        }
                    }
                    Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                    Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                        if stop.load(Ordering::Acquire) {
                            return Ok(CapturedBytes {
                                bytes,
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

fn parse_tool_version(
    family: XtablesRestoreFamily,
    role: XtablesToolRole,
    version: &str,
) -> Result<(XtablesRestoreReportedFlavor, Box<str>), XtablesRestoreProcessError> {
    let prefix = format!("{} v", role.applet(family));
    let Some(remainder) = version.strip_prefix(&prefix) else {
        return Err(XtablesRestoreProcessError::ToolFlavor {
            family,
            version: version.into(),
        });
    };
    let (release, reported_flavor) = if let Some(release) = remainder.strip_suffix(" (legacy)") {
        (release, XtablesRestoreReportedFlavor::Legacy)
    } else if let Some(release) = remainder.strip_suffix(" (nf_tables)") {
        (release, XtablesRestoreReportedFlavor::NfTables)
    } else {
        return Err(XtablesRestoreProcessError::ToolFlavor {
            family,
            version: version.into(),
        });
    };
    if release.is_empty()
        || release.len() > 128
        || !release
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(XtablesRestoreProcessError::ToolFlavor {
            family,
            version: version.into(),
        });
    }
    Ok((reported_flavor, release.into()))
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
fn open_tool_file_exact(
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
fn open_tool_file_exact(
    family: XtablesRestoreFamily,
    path: &Path,
) -> Result<File, XtablesRestoreProcessError> {
    let _ = (family, path);
    Err(XtablesRestoreProcessError::UnsupportedPlatform(
        std::env::consts::OS,
    ))
}

fn validate_discovery_root(root: &Path) -> Result<(), XtablesRestoreProcessError> {
    if root.is_absolute() {
        Ok(())
    } else {
        Err(XtablesRestoreProcessError::InvalidPath {
            family: XtablesRestoreFamily::Ipv4,
            path: root.to_path_buf(),
            reason: Box::from("system xtables discovery root must be absolute"),
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_discovery_root(root: &Path) -> Result<File, XtablesRestoreProcessError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)
        .map_err(|source| XtablesRestoreProcessError::ToolOpen {
            family: XtablesRestoreFamily::Ipv4,
            path: root.to_path_buf(),
            source,
        })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn open_discovery_root(root: &Path) -> Result<File, XtablesRestoreProcessError> {
    let _ = root;
    Err(XtablesRestoreProcessError::UnsupportedPlatform(
        std::env::consts::OS,
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_discovered_tool(
    root: &File,
    root_path: &Path,
    family: XtablesRestoreFamily,
    role: XtablesToolRole,
) -> Result<PinnedXtablesTool, XtablesRestoreProcessError> {
    let applet = role.applet(family);
    let name = CString::new(applet).expect("fixed xtables applet names contain no NUL");
    let logical_path = root_path.join(applet);
    // SAFETY: `root` owns a live directory descriptor, `name` is a fixed
    // NUL-terminated single component, and successful openat returns a new
    // descriptor whose ownership is transferred exactly once into `File`.
    let descriptor = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(XtablesRestoreProcessError::ToolOpen {
            family,
            path: logical_path,
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: `descriptor` was returned by openat and has not been transferred.
    let file = unsafe { File::from_raw_fd(descriptor) };
    PinnedXtablesTool::from_opened_unprobed(family, role, logical_path, file)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn open_discovered_tool(
    _root: &File,
    _root_path: &Path,
    _family: XtablesRestoreFamily,
    _role: XtablesToolRole,
) -> Result<PinnedXtablesTool, XtablesRestoreProcessError> {
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
    validate_trusted_tool_owner(family, path, &metadata)?;
    validate_descriptor(family, path, file)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn tool_file_identity(
    family: XtablesRestoreFamily,
    path: &Path,
    file: &File,
) -> Result<XtablesToolFileIdentity, XtablesRestoreProcessError> {
    let metadata = file
        .metadata()
        .map_err(|source| XtablesRestoreProcessError::ToolIdentity {
            family,
            path: path.to_path_buf(),
            source,
        })?;
    Ok(XtablesToolFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        mode: metadata.mode(),
        owner_user: metadata.uid(),
        owner_group: metadata.gid(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn tool_file_identity(
    family: XtablesRestoreFamily,
    path: &Path,
    file: &File,
) -> Result<XtablesToolFileIdentity, XtablesRestoreProcessError> {
    let metadata = file
        .metadata()
        .map_err(|source| XtablesRestoreProcessError::ToolIdentity {
            family,
            path: path.to_path_buf(),
            source,
        })?;
    Ok(XtablesToolFileIdentity {
        device: 0,
        inode: 0,
        length: metadata.len(),
        mode: 0,
        owner_user: 0,
        owner_group: 0,
        modified_seconds: 0,
        modified_nanoseconds: 0,
    })
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

#[cfg(any(target_os = "linux", target_os = "android"))]
fn validate_trusted_tool_owner(
    family: XtablesRestoreFamily,
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), XtablesRestoreProcessError> {
    let mode = metadata.mode();
    if mode & 0o022 != 0 {
        return Err(XtablesRestoreProcessError::InvalidPath {
            family,
            path: path.to_path_buf(),
            reason: Box::from("tool must not be writable by group or other users"),
        });
    }
    // A production root daemon admits only root-owned system tools. Non-root
    // development and hermetic tests may admit files owned by their own euid;
    // root-owned distribution tools remain usable for non-root host probes.
    // SAFETY: geteuid has no arguments, no failure mode, and reads only the
    // calling process credential.
    let effective_user = unsafe { libc::geteuid() };
    if metadata.uid() == 0 || metadata.uid() == effective_user {
        Ok(())
    } else {
        Err(XtablesRestoreProcessError::InvalidPath {
            family,
            path: path.to_path_buf(),
            reason: format!(
                "tool owner {} is neither root nor the effective user {effective_user}",
                metadata.uid()
            )
            .into_boxed_str(),
        })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn validate_trusted_tool_owner(
    _family: XtablesRestoreFamily,
    _path: &Path,
    _metadata: &std::fs::Metadata,
) -> Result<(), XtablesRestoreProcessError> {
    Ok(())
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
