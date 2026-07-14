//! Linux and Android platform adapters for Flux.

use std::error::Error;
use std::fmt;

// This hardened parser is intentionally internal until the inventory source
// owns the higher-level snapshot interface that consumes it.
#[allow(dead_code)]
mod address_sync;
mod capability;
mod child_process;
mod legacy_dispatcher;
mod netlink;
#[allow(dead_code)]
mod network_observer;
mod phase_dispatcher;
mod process;
mod reactor;
mod seqpacket;
mod shutdown;
mod sing_box;
pub mod socket_diagnostics;
mod xtables;

pub use capability::{CapabilityProfilePaths, SystemCapabilityProfileSource};
pub use legacy_dispatcher::{LegacyScriptPaths, ProcessLegacyDispatcher};
pub use network_observer::NetworkInventorySource;
pub use phase_dispatcher::{
    DispatcherPhaseCommand, PhaseDispatcherError, PhaseDispatcherErrorKind, PhaseDispatcherPaths,
    ProcessPhaseDispatcher,
};
pub use process::{
    PROCESS_CREDENTIAL_MAP_DIGEST_BYTES, ProcessCredentialMapDigest, ProcessCredentialMapKind,
    ProcessCredentials, ProcessDomainObservation, ProcessHandle, ProcessHandleError,
    ProcessHandleErrorKind, ProcessIdentity, ProcessNamespaceIdentity, ProcessObservation,
};
pub use reactor::{
    DaemonReactor, NetworkInventoryDegradation, ReactorError, ReactorStopHandle, StopDisposition,
};
pub use seqpacket::{PeerCredentials, SeqpacketConnection, SeqpacketListener, Uid};
pub use shutdown::ShutdownSignal;
pub use sing_box::{
    ReadinessEvidence, SingBoxExit, SingBoxLaunchSpec, SingBoxLauncher, SingBoxReadiness,
};
pub use xtables::{
    LegacyRulesPlan, LegacyRulesRenderError, LegacyRulesRenderRequest, MAX_XTABLES_RESTORE_BYTES,
    MAX_XTABLES_RESTORE_CHAIN_BYTES, MAX_XTABLES_RESTORE_COMMANDS, MAX_XTABLES_RESTORE_LINE_BYTES,
    MAX_XTABLES_RESTORE_LINES, MAX_XTABLES_RESTORE_TOKEN_BYTES,
    MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND, MAX_XTABLES_RESTORE_TRANSACTIONS,
    XTABLES_RESTORE_DIGEST_BYTES, XTABLES_RESTORE_SCHEMA_VERSION, XtablesChainDeclaration,
    XtablesRestoreAction, XtablesRestoreArtifact, XtablesRestoreCommand, XtablesRestoreCommandKind,
    XtablesRestoreContext, XtablesRestoreDigest, XtablesRestoreEntry, XtablesRestoreFamily,
    XtablesRestoreLimit, XtablesRestoreParseError, XtablesRestoreParseErrorKind,
    XtablesRestoreResourceUsage, XtablesRestoreTable, XtablesRestoreToken,
    XtablesRestoreTransaction, parse_xtables_restore, render_legacy_rules_restore,
};

#[doc(hidden)]
pub mod internal {
    pub use crate::sing_box::{
        PinnedSingBoxLaunch, ProcessDiagnostics, SingBoxChild, SingBoxChildIdentity,
        SingBoxProcessAdapter, SingBoxProcessError, TerminationOutcome, ValidationReport,
    };
}

pub trait KernelReleaseSource {
    fn kernel_release(&self) -> Result<String, PlatformError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemKernelReleaseSource;

impl KernelReleaseSource for SystemKernelReleaseSource {
    fn kernel_release(&self) -> Result<String, PlatformError> {
        system_kernel_release()
    }
}

#[derive(Debug)]
pub enum PlatformError {
    UnsupportedPlatform(&'static str),
    SystemCall {
        operation: &'static str,
        source: std::io::Error,
    },
    InvalidKernelReleaseEncoding,
    InvalidSocketPath(String),
    PacketTooLarge {
        actual: usize,
        limit: usize,
    },
    PeerClosed,
    PeerUidMismatch {
        expected_uid: Uid,
        pid: u32,
        uid: Uid,
        gid: u32,
    },
    ShortWrite {
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform(platform) => {
                write!(formatter, "unsupported host platform '{platform}'")
            }
            Self::SystemCall { operation, source } => {
                write!(formatter, "{operation} failed: {source}")
            }
            Self::InvalidKernelReleaseEncoding => {
                formatter.write_str("kernel release is not valid UTF-8")
            }
            Self::InvalidSocketPath(message) => {
                write!(formatter, "invalid Unix socket path: {message}")
            }
            Self::PacketTooLarge { actual, limit } => {
                write!(formatter, "packet of {actual} bytes exceeds {limit} bytes")
            }
            Self::PeerClosed => formatter.write_str("control peer closed the connection"),
            Self::PeerUidMismatch {
                expected_uid,
                pid,
                uid,
                gid,
            } => {
                write!(
                    formatter,
                    "control peer UID mismatch: expected uid={expected_uid}, pid={pid}, uid={uid}, gid={gid}"
                )
            }
            Self::ShortWrite { expected, actual } => {
                write!(
                    formatter,
                    "short packet write: expected {expected} bytes, wrote {actual}"
                )
            }
        }
    }
}

impl Error for PlatformError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SystemCall { source, .. } => Some(source),
            Self::UnsupportedPlatform(_)
            | Self::InvalidKernelReleaseEncoding
            | Self::InvalidSocketPath(_)
            | Self::PacketTooLarge { .. }
            | Self::PeerClosed
            | Self::PeerUidMismatch { .. }
            | Self::ShortWrite { .. } => None,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn system_kernel_release() -> Result<String, PlatformError> {
    use std::ffi::CStr;
    use std::mem::MaybeUninit;

    let mut name = MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: `name` points to writable storage for one `utsname`. A successful
    // `uname` call initializes the full structure before `assume_init`.
    if unsafe { libc::uname(name.as_mut_ptr()) } != 0 {
        return Err(PlatformError::SystemCall {
            operation: "uname",
            source: std::io::Error::last_os_error(),
        });
    }

    // SAFETY: the successful `uname` call above initialized `name`.
    let name = unsafe { name.assume_init() };
    // SAFETY: POSIX specifies `release` as a NUL-terminated character array
    // within the initialized `utsname` value.
    let release = unsafe { CStr::from_ptr(name.release.as_ptr()) };
    release
        .to_str()
        .map(str::to_owned)
        .map_err(|_| PlatformError::InvalidKernelReleaseEncoding)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn system_kernel_release() -> Result<String, PlatformError> {
    Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
}
