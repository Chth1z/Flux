//! Exact, child-origin process handles for Linux and Android.
//!
//! A [`ProcessHandle`] can be opened only from a live, unreaped
//! [`std::process::Child`]. Linux and Android implementations retain a pidfd,
//! require the process-wide `SIGCHLD` disposition to preserve waitable
//! children, verify that the pidfd still names a child of this process, and
//! correlate every observation through `/proc/self/fdinfo/<pidfd>` before and
//! after reading the process's procfs identity, credentials, namespaces, and
//! credential maps. The caller must not use an out-of-band `waitpid`/`waitid`
//! reaper for the child while opening the handle. The handle deliberately
//! exposes no signaling or reap API: pidfd readability proves exit, not
//! parent-side reaping.

use std::error::Error;
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::process::Child;

pub const PROCESS_CREDENTIAL_MAP_DIGEST_BYTES: usize = 32;

/// Stable PID plus Linux procfs start-time identity for one process instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessIdentity {
    pid: NonZeroU32,
    start_time_ticks: NonZeroU64,
}

impl ProcessIdentity {
    #[must_use]
    pub const fn new(pid: NonZeroU32, start_time_ticks: NonZeroU64) -> Self {
        Self {
            pid,
            start_time_ticks,
        }
    }

    #[must_use]
    pub const fn pid(self) -> NonZeroU32 {
        self.pid
    }

    #[must_use]
    pub const fn start_time_ticks(self) -> NonZeroU64 {
        self.start_time_ticks
    }
}

/// Complete Linux task credentials shared by every thread in one stable scan.
///
/// Construction succeeds only when two consecutive bounded
/// `/proc/<pid>/task/*/status` censuses have the same task set, every task's
/// credentials remain unchanged, and every thread matches the process leader.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessCredentials {
    uids: [u32; 4],
    gids: [u32; 4],
    supplementary_groups: Box<[u32]>,
    capability_inheritable: u64,
    capability_permitted: u64,
    capability_effective: u64,
    capability_bounding: u64,
    capability_ambient: u64,
    no_new_privileges: bool,
}

impl ProcessCredentials {
    /// Real, effective, saved-set, and filesystem UIDs, in procfs order.
    #[must_use]
    pub const fn uids(&self) -> &[u32; 4] {
        &self.uids
    }

    /// Real, effective, saved-set, and filesystem GIDs, in procfs order.
    #[must_use]
    pub const fn gids(&self) -> &[u32; 4] {
        &self.gids
    }

    #[must_use]
    pub fn supplementary_groups(&self) -> &[u32] {
        &self.supplementary_groups
    }

    #[must_use]
    pub const fn capability_inheritable(&self) -> u64 {
        self.capability_inheritable
    }

    #[must_use]
    pub const fn capability_permitted(&self) -> u64 {
        self.capability_permitted
    }

    #[must_use]
    pub const fn capability_effective(&self) -> u64 {
        self.capability_effective
    }

    #[must_use]
    pub const fn capability_bounding(&self) -> u64 {
        self.capability_bounding
    }

    #[must_use]
    pub const fn capability_ambient(&self) -> u64 {
        self.capability_ambient
    }

    #[must_use]
    pub const fn no_new_privileges(&self) -> bool {
        self.no_new_privileges
    }
}

/// Stable kernel object identity for one process namespace.
///
/// Linux and Android observations use the complete namespace descriptor
/// `st_dev`/`st_ino` pair rather than a textual procfs symlink rendering.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcessNamespaceIdentity {
    device: u64,
    inode: NonZeroU64,
}

impl ProcessNamespaceIdentity {
    #[must_use]
    pub const fn new(device: u64, inode: NonZeroU64) -> Self {
        Self { device, inode }
    }

    #[must_use]
    pub const fn device(self) -> u64 {
        self.device
    }

    #[must_use]
    pub const fn inode(self) -> NonZeroU64 {
        self.inode
    }
}

/// Versioned SHA-256 identity for one canonical Linux UID or GID map.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessCredentialMapDigest([u8; PROCESS_CREDENTIAL_MAP_DIGEST_BYTES]);

impl ProcessCredentialMapDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PROCESS_CREDENTIAL_MAP_DIGEST_BYTES] {
        &self.0
    }
}

/// Stable user-namespace and credential-map evidence for one process.
///
/// `Unsupported` is returned only when the observer and every observed task
/// coherently omit the user-namespace descriptor and both credential maps.
/// Permission failures and mixed presence remain observation errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessUserNamespaceObservation {
    Unsupported,
    Observed {
        namespace: ProcessNamespaceIdentity,
        uid_map_digest: ProcessCredentialMapDigest,
        gid_map_digest: ProcessCredentialMapDigest,
    },
}

/// Stable process-wide namespace and credential-map domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessDomainObservation {
    user_namespace: ProcessUserNamespaceObservation,
    mount_namespace: ProcessNamespaceIdentity,
    network_namespace: ProcessNamespaceIdentity,
}

impl ProcessDomainObservation {
    #[must_use]
    pub const fn user_namespace(self) -> ProcessUserNamespaceObservation {
        self.user_namespace
    }

    #[must_use]
    pub const fn mount_namespace(self) -> ProcessNamespaceIdentity {
        self.mount_namespace
    }

    #[must_use]
    pub const fn network_namespace(self) -> ProcessNamespaceIdentity {
        self.network_namespace
    }
}

/// One complete point-in-time observation through a retained process handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessObservation {
    identity: ProcessIdentity,
    credentials: ProcessCredentials,
    domain: ProcessDomainObservation,
}

impl ProcessObservation {
    #[must_use]
    pub const fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    #[must_use]
    pub const fn credentials(&self) -> &ProcessCredentials {
        &self.credentials
    }

    #[must_use]
    pub const fn domain(&self) -> ProcessDomainObservation {
        self.domain
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessCredentialMapKind {
    Uid,
    Gid,
}

impl ProcessCredentialMapKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Uid => "UID",
            Self::Gid => "GID",
        }
    }
}

/// Stable classification for process-handle failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessHandleErrorKind {
    Unsupported,
    Exited,
    IdentityChanged,
    Parse,
    SystemCall,
}

/// Stable stage reached while opening exact child-origin process authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessHandleOpenStage {
    Start,
    ChildDispositionBeforeOpen,
    ProcfsPidNamespace,
    ChildIdentity,
    ChildOwnershipBeforePidFd,
    PidFdOpen,
    PidFdChildOwnership,
    InitialObservation(ProcessHandleObservationStage),
    ChildDispositionAfterObservation,
    ChildOwnershipAfterObservation,
    RecordedChildIdentity,
}

impl ProcessHandleOpenStage {
    const BEFORE_INITIAL_OBSERVATION: [Self; 7] = [
        Self::Start,
        Self::ChildDispositionBeforeOpen,
        Self::ProcfsPidNamespace,
        Self::ChildIdentity,
        Self::ChildOwnershipBeforePidFd,
        Self::PidFdOpen,
        Self::PidFdChildOwnership,
    ];
    const AFTER_INITIAL_OBSERVATION: [Self; 3] = [
        Self::ChildDispositionAfterObservation,
        Self::ChildOwnershipAfterObservation,
        Self::RecordedChildIdentity,
    ];
    #[cfg(test)]
    pub(crate) const COUNT: usize = Self::BEFORE_INITIAL_OBSERVATION.len()
        + ProcessHandleObservationStage::ALL.len()
        + Self::AFTER_INITIAL_OBSERVATION.len();

    pub(crate) fn all() -> impl Iterator<Item = Self> {
        Self::BEFORE_INITIAL_OBSERVATION
            .into_iter()
            .chain(
                ProcessHandleObservationStage::ALL
                    .into_iter()
                    .map(Self::InitialObservation),
            )
            .chain(Self::AFTER_INITIAL_OBSERVATION)
    }

    #[must_use]
    pub fn as_str(self) -> String {
        match self {
            Self::Start => "start".to_owned(),
            Self::ChildDispositionBeforeOpen => "child-disposition-before-open".to_owned(),
            Self::ProcfsPidNamespace => "procfs-pid-namespace".to_owned(),
            Self::ChildIdentity => "child-identity".to_owned(),
            Self::ChildOwnershipBeforePidFd => "child-ownership-before-pidfd".to_owned(),
            Self::PidFdOpen => "pidfd-open".to_owned(),
            Self::PidFdChildOwnership => "pidfd-child-ownership".to_owned(),
            Self::InitialObservation(stage) => {
                format!("initial-observation-{}", stage.as_str())
            }
            Self::ChildDispositionAfterObservation => {
                "child-disposition-after-observation".to_owned()
            }
            Self::ChildOwnershipAfterObservation => "child-ownership-after-observation".to_owned(),
            Self::RecordedChildIdentity => "recorded-child-identity".to_owned(),
        }
    }
}

/// Stable stage reached while observing one exact pidfd-bound process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessHandleObservationStage {
    ChildDispositionBeforeObservation,
    ProcfsPidNamespace,
    PidFdLivenessBeforeObservation,
    PidFdChildOwnershipBeforeObservation,
    PidFdIdentityBeforeObservation,
    ProcessIdentity,
    UserNamespaceSupportBeforeObservation,
    FirstTaskIds,
    FirstTaskStatus,
    FirstTaskUserNamespace,
    FirstTaskMountNamespace,
    FirstTaskNetworkNamespace,
    FirstUidMap,
    FirstGidMap,
    SecondTaskIds,
    SecondTaskStatus,
    SecondTaskUserNamespace,
    SecondTaskMountNamespace,
    SecondTaskNetworkNamespace,
    SecondUidMap,
    SecondGidMap,
    FinalTaskIds,
    UserNamespaceSupportAfterObservation,
    CensusValidation,
    PidFdIdentityAfterObservation,
    PidFdChildOwnershipAfterObservation,
    PidFdLivenessAfterObservation,
    ChildDispositionAfterObservation,
}

impl ProcessHandleObservationStage {
    pub const ALL: [Self; 28] = [
        Self::ChildDispositionBeforeObservation,
        Self::ProcfsPidNamespace,
        Self::PidFdLivenessBeforeObservation,
        Self::PidFdChildOwnershipBeforeObservation,
        Self::PidFdIdentityBeforeObservation,
        Self::ProcessIdentity,
        Self::UserNamespaceSupportBeforeObservation,
        Self::FirstTaskIds,
        Self::FirstTaskStatus,
        Self::FirstTaskUserNamespace,
        Self::FirstTaskMountNamespace,
        Self::FirstTaskNetworkNamespace,
        Self::FirstUidMap,
        Self::FirstGidMap,
        Self::SecondTaskIds,
        Self::SecondTaskStatus,
        Self::SecondTaskUserNamespace,
        Self::SecondTaskMountNamespace,
        Self::SecondTaskNetworkNamespace,
        Self::SecondUidMap,
        Self::SecondGidMap,
        Self::FinalTaskIds,
        Self::UserNamespaceSupportAfterObservation,
        Self::CensusValidation,
        Self::PidFdIdentityAfterObservation,
        Self::PidFdChildOwnershipAfterObservation,
        Self::PidFdLivenessAfterObservation,
        Self::ChildDispositionAfterObservation,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChildDispositionBeforeObservation => "child-disposition-before-observation",
            Self::ProcfsPidNamespace => "procfs-pid-namespace",
            Self::PidFdLivenessBeforeObservation => "pidfd-liveness-before-observation",
            Self::PidFdChildOwnershipBeforeObservation => {
                "pidfd-child-ownership-before-observation"
            }
            Self::PidFdIdentityBeforeObservation => "pidfd-identity-before-observation",
            Self::ProcessIdentity => "process-identity",
            Self::UserNamespaceSupportBeforeObservation => {
                "user-namespace-support-before-observation"
            }
            Self::FirstTaskIds => "first-task-ids",
            Self::FirstTaskStatus => "first-task-status",
            Self::FirstTaskUserNamespace => "first-task-user-namespace",
            Self::FirstTaskMountNamespace => "first-task-mount-namespace",
            Self::FirstTaskNetworkNamespace => "first-task-network-namespace",
            Self::FirstUidMap => "first-uid-map",
            Self::FirstGidMap => "first-gid-map",
            Self::SecondTaskIds => "second-task-ids",
            Self::SecondTaskStatus => "second-task-status",
            Self::SecondTaskUserNamespace => "second-task-user-namespace",
            Self::SecondTaskMountNamespace => "second-task-mount-namespace",
            Self::SecondTaskNetworkNamespace => "second-task-network-namespace",
            Self::SecondUidMap => "second-uid-map",
            Self::SecondGidMap => "second-gid-map",
            Self::FinalTaskIds => "final-task-ids",
            Self::UserNamespaceSupportAfterObservation => {
                "user-namespace-support-after-observation"
            }
            Self::CensusValidation => "census-validation",
            Self::PidFdIdentityAfterObservation => "pidfd-identity-after-observation",
            Self::PidFdChildOwnershipAfterObservation => "pidfd-child-ownership-after-observation",
            Self::PidFdLivenessAfterObservation => "pidfd-liveness-after-observation",
            Self::ChildDispositionAfterObservation => "child-disposition-after-observation",
        }
    }
}

/// Failure to open or reobserve an exact child-origin process handle.
#[derive(Debug)]
pub enum ProcessHandleError {
    UnsupportedPlatform(&'static str),
    PidFdUnsupported {
        source: std::io::Error,
    },
    InvalidChildPid {
        pid: u32,
    },
    Exited {
        pid: NonZeroU32,
    },
    PidFdIdentityMismatch {
        expected: NonZeroU32,
        observed: NonZeroU32,
    },
    ProcessIdentityMismatch {
        expected: ProcessIdentity,
        observed: ProcessIdentity,
    },
    ProcessStatusPidMismatch {
        expected: NonZeroU32,
        observed: NonZeroU32,
    },
    ProcessStatusTgidMismatch {
        expected: NonZeroU32,
        observed: NonZeroU32,
    },
    MissingProcessLeaderTask {
        pid: NonZeroU32,
    },
    ProcessThreadSetChanged {
        pid: NonZeroU32,
    },
    ProcessThreadCredentialsChanged {
        pid: NonZeroU32,
        thread: NonZeroU32,
    },
    ProcessThreadCredentialMismatch {
        pid: NonZeroU32,
        thread: NonZeroU32,
    },
    ProcessThreadNamespacesChanged {
        pid: NonZeroU32,
        thread: NonZeroU32,
    },
    ProcessThreadNamespaceMismatch {
        pid: NonZeroU32,
        thread: NonZeroU32,
    },
    ProcessCredentialMapChanged {
        pid: NonZeroU32,
        map: ProcessCredentialMapKind,
    },
    ChildReapContractUnavailable,
    ChildOwnershipLost {
        pid: NonZeroU32,
    },
    ProcfsPidNamespaceMismatch {
        caller_pid: NonZeroU32,
        procfs_pid: NonZeroU32,
    },
    ProcessUserNamespaceSupportIncoherent,
    ProcessUserNamespaceSupportChanged {
        pid: NonZeroU32,
    },
    ProcessUserNamespaceObservationMismatch {
        pid: NonZeroU32,
    },
    MalformedProcStat {
        path: PathBuf,
    },
    MalformedProcStatus {
        path: PathBuf,
    },
    MalformedPidFdInfo {
        path: PathBuf,
    },
    MalformedProcessTaskEntry {
        path: PathBuf,
    },
    MalformedProcessNamespace {
        path: PathBuf,
    },
    MalformedProcessIdMap {
        path: PathBuf,
    },
    ProcFileLimitExceeded {
        path: PathBuf,
        limit: usize,
    },
    ProcessThreadLimitExceeded {
        pid: NonZeroU32,
        limit: usize,
    },
    ProcessIdMapEntryLimitExceeded {
        path: PathBuf,
        limit: usize,
    },
    SystemCall {
        operation: &'static str,
        path: Option<PathBuf>,
        source: std::io::Error,
    },
}

impl ProcessHandleError {
    #[must_use]
    pub const fn kind(&self) -> ProcessHandleErrorKind {
        match self {
            Self::UnsupportedPlatform(_) | Self::PidFdUnsupported { .. } => {
                ProcessHandleErrorKind::Unsupported
            }
            Self::Exited { .. } => ProcessHandleErrorKind::Exited,
            Self::InvalidChildPid { .. }
            | Self::PidFdIdentityMismatch { .. }
            | Self::ProcessIdentityMismatch { .. }
            | Self::ProcessStatusPidMismatch { .. }
            | Self::ProcessStatusTgidMismatch { .. }
            | Self::MissingProcessLeaderTask { .. }
            | Self::ProcessThreadSetChanged { .. }
            | Self::ProcessThreadCredentialsChanged { .. }
            | Self::ProcessThreadCredentialMismatch { .. }
            | Self::ProcessThreadNamespacesChanged { .. }
            | Self::ProcessThreadNamespaceMismatch { .. }
            | Self::ProcessCredentialMapChanged { .. }
            | Self::ChildReapContractUnavailable
            | Self::ChildOwnershipLost { .. }
            | Self::ProcfsPidNamespaceMismatch { .. }
            | Self::ProcessUserNamespaceSupportIncoherent
            | Self::ProcessUserNamespaceSupportChanged { .. }
            | Self::ProcessUserNamespaceObservationMismatch { .. } => {
                ProcessHandleErrorKind::IdentityChanged
            }
            Self::MalformedProcStat { .. }
            | Self::MalformedProcStatus { .. }
            | Self::MalformedPidFdInfo { .. }
            | Self::MalformedProcessTaskEntry { .. }
            | Self::MalformedProcessNamespace { .. }
            | Self::MalformedProcessIdMap { .. }
            | Self::ProcFileLimitExceeded { .. }
            | Self::ProcessThreadLimitExceeded { .. }
            | Self::ProcessIdMapEntryLimitExceeded { .. } => ProcessHandleErrorKind::Parse,
            Self::SystemCall { .. } => ProcessHandleErrorKind::SystemCall,
        }
    }
}

impl fmt::Display for ProcessHandleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform(platform) => {
                write!(formatter, "process handles are unsupported on {platform}")
            }
            Self::PidFdUnsupported { source } => {
                write!(formatter, "pidfd_open is unsupported: {source}")
            }
            Self::InvalidChildPid { pid } => write!(formatter, "child PID {pid} is invalid"),
            Self::Exited { pid } => write!(formatter, "process {pid} has exited"),
            Self::PidFdIdentityMismatch { expected, observed } => write!(
                formatter,
                "pidfd identity mismatch: expected PID {expected}, observed PID {observed}"
            ),
            Self::ProcessIdentityMismatch { expected, observed } => write!(
                formatter,
                "process identity changed: expected pid={} start_ticks={}, observed pid={} start_ticks={}",
                expected.pid(),
                expected.start_time_ticks(),
                observed.pid(),
                observed.start_time_ticks()
            ),
            Self::ProcessStatusPidMismatch { expected, observed } => write!(
                formatter,
                "process status PID mismatch: expected {expected}, observed {observed}"
            ),
            Self::ProcessStatusTgidMismatch { expected, observed } => write!(
                formatter,
                "process status thread-group mismatch: expected TGID {expected}, observed {observed}"
            ),
            Self::MissingProcessLeaderTask { pid } => {
                write!(formatter, "process {pid} task census omitted its leader")
            }
            Self::ProcessThreadSetChanged { pid } => {
                write!(
                    formatter,
                    "process {pid} thread set changed during observation"
                )
            }
            Self::ProcessThreadCredentialsChanged { pid, thread } => write!(
                formatter,
                "process {pid} thread {thread} credentials changed during observation"
            ),
            Self::ProcessThreadCredentialMismatch { pid, thread } => write!(
                formatter,
                "process {pid} thread {thread} credentials differ from the process leader"
            ),
            Self::ProcessThreadNamespacesChanged { pid, thread } => write!(
                formatter,
                "process {pid} thread {thread} namespaces changed during observation"
            ),
            Self::ProcessThreadNamespaceMismatch { pid, thread } => write!(
                formatter,
                "process {pid} thread {thread} namespaces differ from the process leader"
            ),
            Self::ProcessCredentialMapChanged { pid, map } => write!(
                formatter,
                "process {pid} {} map changed during observation",
                map.label()
            ),
            Self::ChildReapContractUnavailable => formatter.write_str(
                "process-wide SIGCHLD disposition does not preserve exact waitable children",
            ),
            Self::ChildOwnershipLost { pid } => write!(
                formatter,
                "pidfd for process {pid} is no longer waitable by this parent"
            ),
            Self::ProcfsPidNamespaceMismatch {
                caller_pid,
                procfs_pid,
            } => write!(
                formatter,
                "procfs PID namespace mismatch: caller sees PID {caller_pid}, /proc/self/stat reports {procfs_pid}"
            ),
            Self::ProcessUserNamespaceSupportIncoherent => {
                formatter.write_str("observer user-namespace procfs facilities have mixed presence")
            }
            Self::ProcessUserNamespaceSupportChanged { pid } => write!(
                formatter,
                "process {pid} user-namespace procfs support changed during observation"
            ),
            Self::ProcessUserNamespaceObservationMismatch { pid } => write!(
                formatter,
                "process {pid} user-namespace procfs facilities do not match observer support"
            ),
            Self::MalformedProcStat { path } => {
                write!(formatter, "malformed proc stat {}", path.display())
            }
            Self::MalformedProcStatus { path } => {
                write!(formatter, "malformed proc status {}", path.display())
            }
            Self::MalformedPidFdInfo { path } => {
                write!(formatter, "malformed pidfd info {}", path.display())
            }
            Self::MalformedProcessTaskEntry { path } => {
                write!(formatter, "malformed process task entry {}", path.display())
            }
            Self::MalformedProcessNamespace { path } => {
                write!(formatter, "malformed process namespace {}", path.display())
            }
            Self::MalformedProcessIdMap { path } => {
                write!(formatter, "malformed process ID map {}", path.display())
            }
            Self::ProcFileLimitExceeded { path, limit } => write!(
                formatter,
                "proc file {} exceeds the hard limit of {limit} bytes",
                path.display()
            ),
            Self::ProcessThreadLimitExceeded { pid, limit } => write!(
                formatter,
                "process {pid} exceeds the hard limit of {limit} observed threads"
            ),
            Self::ProcessIdMapEntryLimitExceeded { path, limit } => write!(
                formatter,
                "process ID map {} exceeds the hard limit of {limit} entries",
                path.display()
            ),
            Self::SystemCall {
                operation,
                path,
                source,
            } => {
                write!(formatter, "{operation}")?;
                if let Some(path) = path {
                    write!(formatter, " {}", path.display())?;
                }
                write!(formatter, ": {source}")
            }
        }
    }
}

impl Error for ProcessHandleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PidFdUnsupported { source } | Self::SystemCall { source, .. } => Some(source),
            Self::UnsupportedPlatform(_)
            | Self::InvalidChildPid { .. }
            | Self::Exited { .. }
            | Self::PidFdIdentityMismatch { .. }
            | Self::ProcessIdentityMismatch { .. }
            | Self::ProcessStatusPidMismatch { .. }
            | Self::ProcessStatusTgidMismatch { .. }
            | Self::MissingProcessLeaderTask { .. }
            | Self::ProcessThreadSetChanged { .. }
            | Self::ProcessThreadCredentialsChanged { .. }
            | Self::ProcessThreadCredentialMismatch { .. }
            | Self::ProcessThreadNamespacesChanged { .. }
            | Self::ProcessThreadNamespaceMismatch { .. }
            | Self::ProcessCredentialMapChanged { .. }
            | Self::ChildReapContractUnavailable
            | Self::ChildOwnershipLost { .. }
            | Self::ProcfsPidNamespaceMismatch { .. }
            | Self::ProcessUserNamespaceSupportIncoherent
            | Self::ProcessUserNamespaceSupportChanged { .. }
            | Self::ProcessUserNamespaceObservationMismatch { .. }
            | Self::MalformedProcStat { .. }
            | Self::MalformedProcStatus { .. }
            | Self::MalformedPidFdInfo { .. }
            | Self::MalformedProcessTaskEntry { .. }
            | Self::MalformedProcessNamespace { .. }
            | Self::MalformedProcessIdMap { .. }
            | Self::ProcFileLimitExceeded { .. }
            | Self::ProcessThreadLimitExceeded { .. }
            | Self::ProcessIdMapEntryLimitExceeded { .. } => None,
        }
    }
}

/// Failure to open exact child-origin process authority at a stable stage.
#[derive(Debug)]
pub struct ProcessHandleOpenError {
    stage: ProcessHandleOpenStage,
    source: ProcessHandleError,
}

impl ProcessHandleOpenError {
    #[must_use]
    pub const fn new(stage: ProcessHandleOpenStage, source: ProcessHandleError) -> Self {
        Self { stage, source }
    }

    #[must_use]
    pub const fn stage(&self) -> ProcessHandleOpenStage {
        self.stage
    }

    #[must_use]
    pub const fn kind(&self) -> ProcessHandleErrorKind {
        self.source.kind()
    }

    #[must_use]
    pub const fn source_error(&self) -> &ProcessHandleError {
        &self.source
    }

    #[must_use]
    pub fn into_source(self) -> ProcessHandleError {
        self.source
    }
}

impl fmt::Display for ProcessHandleOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cannot open exact child process handle during {}: {}",
            self.stage.as_str(),
            self.source
        )
    }
}

impl Error for ProcessHandleOpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Failure to observe exact pidfd-bound process authority at a stable stage.
#[derive(Debug)]
pub struct ProcessHandleObservationError {
    stage: ProcessHandleObservationStage,
    source: ProcessHandleError,
}

impl ProcessHandleObservationError {
    #[must_use]
    pub const fn new(stage: ProcessHandleObservationStage, source: ProcessHandleError) -> Self {
        Self { stage, source }
    }

    #[must_use]
    pub const fn stage(&self) -> ProcessHandleObservationStage {
        self.stage
    }

    #[must_use]
    pub const fn kind(&self) -> ProcessHandleErrorKind {
        self.source.kind()
    }

    #[must_use]
    pub const fn source_error(&self) -> &ProcessHandleError {
        &self.source
    }

    #[must_use]
    pub fn into_source(self) -> ProcessHandleError {
        self.source
    }
}

impl fmt::Display for ProcessHandleObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cannot observe exact child process handle during {}: {}",
            self.stage.as_str(),
            self.source
        )
    }
}

impl Error for ProcessHandleObservationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Non-cloneable handle for one exact child process instance.
pub struct ProcessHandle {
    identity: ProcessIdentity,
    credentials: ProcessCredentials,
    domain: ProcessDomainObservation,
    transport: ProcessHandleTransport,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct ProcessHandleTransport {
    pidfd: std::os::fd::OwnedFd,
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
struct ProcessHandleTransport {
    _never: std::convert::Infallible,
}

const _: fn() = || {
    fn assert_send_static<T: Send + 'static>() {}
    assert_send_static::<ProcessHandle>();
};

impl ProcessHandle {
    /// Open a pidfd for the exact process represented by `child` and capture its
    /// initial procfs identity, credentials, and process domain.
    ///
    /// The process-wide `SIGCHLD` disposition must be the default without
    /// `SA_NOCLDWAIT`, and no external reaper may wait on this child while the
    /// handle is opened. These preconditions ensure an unreaped child PID cannot
    /// be recycled between `spawn` and `pidfd_open`.
    pub fn open_child(child: &Child) -> Result<Self, ProcessHandleOpenError> {
        implementation::open_child(child)
    }

    #[must_use]
    pub const fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    #[must_use]
    pub const fn credentials(&self) -> &ProcessCredentials {
        &self.credentials
    }

    #[must_use]
    pub const fn domain(&self) -> ProcessDomainObservation {
        self.domain
    }

    /// Return the exact identity, credentials, and process domain captured
    /// while this child-origin handle was opened.
    ///
    /// The returned value is an owned observation so callers can retain it
    /// alongside a later [`Self::reobserve`] result without cloning or
    /// reconstructing process authority from a PID.
    #[must_use]
    pub fn initial_observation(&self) -> ProcessObservation {
        ProcessObservation {
            identity: self.identity,
            credentials: self.credentials.clone(),
            domain: self.domain,
        }
    }

    /// Reobserve the same live pidfd-bound process.
    ///
    /// Once pidfd readiness observes exit, it is reported as
    /// [`ProcessHandleErrorKind::Exited`]. Success proves only a live exact
    /// identity plus point-in-time credential and process-domain observations;
    /// it does not prove that a later exit was reaped by the parent. Callers
    /// must not use the complete procfs census as an exit-wait primitive.
    pub fn reobserve(&self) -> Result<ProcessObservation, ProcessHandleObservationError> {
        implementation::reobserve(self)
    }
}

impl fmt::Debug for ProcessHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessHandle")
            .field("identity", &self.identity)
            .field("credentials", &self.credentials)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::fs::{self, File};
    use std::io::{self, Read};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::process::Child;

    use sha2::{Digest, Sha256};

    use super::{
        ProcessCredentialMapDigest, ProcessCredentialMapKind, ProcessCredentials,
        ProcessDomainObservation, ProcessHandle, ProcessHandleError, ProcessHandleObservationError,
        ProcessHandleObservationStage, ProcessHandleOpenError, ProcessHandleOpenStage,
        ProcessHandleTransport, ProcessIdentity, ProcessNamespaceIdentity, ProcessObservation,
        ProcessUserNamespaceObservation,
    };
    use std::num::{NonZeroU32, NonZeroU64};

    const PROC_STAT_LIMIT: usize = 64 * 1024;
    // Linux permits up to 65,536 supplementary groups. Their worst-case
    // decimal `Groups:` representation fits below this bound with the rest of
    // one task status file.
    const PROC_STATUS_LIMIT: usize = 1024 * 1024;
    const PROC_ID_MAP_LIMIT: usize = 16 * 1024;
    const PIDFD_INFO_LIMIT: usize = 16 * 1024;
    const MAX_PROCESS_THREADS: usize = 1024;
    const MAX_PROCESS_ID_MAP_ENTRIES: usize = 340;
    const UID_MAP_DIGEST_DOMAIN: &[u8] = b"flux.process.uid-map.v1\0";
    const GID_MAP_DIGEST_DOMAIN: &[u8] = b"flux.process.gid-map.v1\0";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum ProcessTaskUserNamespaceObservation {
        Unsupported,
        Observed(ProcessNamespaceIdentity),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) struct ProcessTaskNamespaces {
        pub(super) user: ProcessTaskUserNamespaceObservation,
        pub(super) mount: ProcessNamespaceIdentity,
        pub(super) network: ProcessNamespaceIdentity,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(super) struct ProcessTaskObservation {
        pub(super) credentials: ProcessCredentials,
        pub(super) namespaces: ProcessTaskNamespaces,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum ProcessCredentialMapObservation {
        Unsupported,
        Observed {
            uid: ProcessCredentialMapDigest,
            gid: ProcessCredentialMapDigest,
        },
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum UserNamespaceSupport {
        Unsupported,
        Supported,
    }

    #[derive(Clone, Copy)]
    struct ProcessTaskObservationStages {
        status: ProcessHandleObservationStage,
        user_namespace: ProcessHandleObservationStage,
        mount_namespace: ProcessHandleObservationStage,
        network_namespace: ProcessHandleObservationStage,
    }

    const FIRST_TASK_OBSERVATION_STAGES: ProcessTaskObservationStages =
        ProcessTaskObservationStages {
            status: ProcessHandleObservationStage::FirstTaskStatus,
            user_namespace: ProcessHandleObservationStage::FirstTaskUserNamespace,
            mount_namespace: ProcessHandleObservationStage::FirstTaskMountNamespace,
            network_namespace: ProcessHandleObservationStage::FirstTaskNetworkNamespace,
        };
    const SECOND_TASK_OBSERVATION_STAGES: ProcessTaskObservationStages =
        ProcessTaskObservationStages {
            status: ProcessHandleObservationStage::SecondTaskStatus,
            user_namespace: ProcessHandleObservationStage::SecondTaskUserNamespace,
            mount_namespace: ProcessHandleObservationStage::SecondTaskMountNamespace,
            network_namespace: ProcessHandleObservationStage::SecondTaskNetworkNamespace,
        };

    #[derive(Clone, Copy)]
    struct ProcessCredentialMapObservationStages {
        uid: ProcessHandleObservationStage,
        gid: ProcessHandleObservationStage,
    }

    const FIRST_CREDENTIAL_MAP_STAGES: ProcessCredentialMapObservationStages =
        ProcessCredentialMapObservationStages {
            uid: ProcessHandleObservationStage::FirstUidMap,
            gid: ProcessHandleObservationStage::FirstGidMap,
        };
    const SECOND_CREDENTIAL_MAP_STAGES: ProcessCredentialMapObservationStages =
        ProcessCredentialMapObservationStages {
            uid: ProcessHandleObservationStage::SecondUidMap,
            gid: ProcessHandleObservationStage::SecondGidMap,
        };

    #[derive(Clone, Copy, Debug)]
    pub(super) struct ProcessObservationCensusPass<'a> {
        pub(super) task_ids: &'a [NonZeroU32],
        pub(super) task_observations: &'a [(NonZeroU32, ProcessTaskObservation)],
        pub(super) credential_maps: ProcessCredentialMapObservation,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ProcessIdMapEntry {
        inside: u32,
        outside: u32,
        length: u32,
    }

    pub(super) fn open_child(child: &Child) -> Result<ProcessHandle, ProcessHandleOpenError> {
        require_waitable_child_disposition().map_err(|source| {
            ProcessHandleOpenError::new(ProcessHandleOpenStage::ChildDispositionBeforeOpen, source)
        })?;
        require_procfs_pid_namespace().map_err(|source| {
            ProcessHandleOpenError::new(ProcessHandleOpenStage::ProcfsPidNamespace, source)
        })?;
        let raw_pid = child.id();
        let pid = NonZeroU32::new(raw_pid)
            .filter(|pid| i32::try_from(pid.get()).is_ok())
            .ok_or_else(|| {
                ProcessHandleOpenError::new(
                    ProcessHandleOpenStage::ChildIdentity,
                    ProcessHandleError::InvalidChildPid { pid: raw_pid },
                )
            })?;
        require_waitable_child_pid(pid).map_err(|source| {
            ProcessHandleOpenError::new(ProcessHandleOpenStage::ChildOwnershipBeforePidFd, source)
        })?;
        let pidfd = open_pidfd(pid).map_err(|source| {
            ProcessHandleOpenError::new(ProcessHandleOpenStage::PidFdOpen, source)
        })?;
        require_waitable_child(&pidfd, pid).map_err(|source| {
            ProcessHandleOpenError::new(ProcessHandleOpenStage::PidFdChildOwnership, source)
        })?;
        let observation = observe(&pidfd, pid, None).map_err(|error| {
            ProcessHandleOpenError::new(
                ProcessHandleOpenStage::InitialObservation(error.stage()),
                error.into_source(),
            )
        })?;
        require_waitable_child_disposition().map_err(|source| {
            ProcessHandleOpenError::new(
                ProcessHandleOpenStage::ChildDispositionAfterObservation,
                source,
            )
        })?;
        require_waitable_child(&pidfd, pid).map_err(|source| {
            ProcessHandleOpenError::new(
                ProcessHandleOpenStage::ChildOwnershipAfterObservation,
                source,
            )
        })?;
        Ok(ProcessHandle {
            identity: observation.identity,
            credentials: observation.credentials,
            domain: observation.domain,
            transport: ProcessHandleTransport { pidfd },
        })
    }

    pub(super) fn reobserve(
        handle: &ProcessHandle,
    ) -> Result<ProcessObservation, ProcessHandleObservationError> {
        observe(
            &handle.transport.pidfd,
            handle.identity.pid(),
            Some(handle.identity),
        )
    }

    fn open_pidfd(pid: NonZeroU32) -> Result<OwnedFd, ProcessHandleError> {
        let raw_pid = libc::pid_t::try_from(pid.get())
            .map_err(|_| ProcessHandleError::InvalidChildPid { pid: pid.get() })?;
        // SAFETY: `pidfd_open` receives a validated positive pid_t and the only
        // currently valid flags value, zero. Success returns a new owned file
        // descriptor; failure leaves ownership unchanged and reports errno.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, raw_pid, 0_u32) };
        if descriptor < 0 {
            let source = io::Error::last_os_error();
            return match source.raw_os_error() {
                Some(libc::ENOSYS) => Err(ProcessHandleError::PidFdUnsupported { source }),
                Some(libc::ESRCH) => Err(ProcessHandleError::Exited { pid }),
                _ => Err(ProcessHandleError::SystemCall {
                    operation: "open child pidfd",
                    path: None,
                    source,
                }),
            };
        }
        let descriptor = i32::try_from(descriptor).map_err(|_| ProcessHandleError::SystemCall {
            operation: "open child pidfd",
            path: None,
            source: io::Error::other("pidfd descriptor exceeds c_int"),
        })?;
        // SAFETY: successful pidfd_open returned one new descriptor, and this
        // is the unique transfer of its ownership into `OwnedFd`.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }

    fn observe(
        pidfd: &OwnedFd,
        expected_pid: NonZeroU32,
        expected_identity: Option<ProcessIdentity>,
    ) -> Result<ProcessObservation, ProcessHandleObservationError> {
        require_waitable_child_disposition().map_err(|source| {
            ProcessHandleObservationError::new(
                ProcessHandleObservationStage::ChildDispositionBeforeObservation,
                source,
            )
        })?;
        require_procfs_pid_namespace().map_err(|source| {
            ProcessHandleObservationError::new(
                ProcessHandleObservationStage::ProcfsPidNamespace,
                source,
            )
        })?;
        require_live(pidfd, expected_pid).map_err(|source| {
            ProcessHandleObservationError::new(
                ProcessHandleObservationStage::PidFdLivenessBeforeObservation,
                source,
            )
        })?;
        require_waitable_child(pidfd, expected_pid).map_err(|source| {
            ProcessHandleObservationError::new(
                ProcessHandleObservationStage::PidFdChildOwnershipBeforeObservation,
                source,
            )
        })?;
        require_pidfd_pid(pidfd, expected_pid).map_err(|source| {
            ProcessHandleObservationError::new(
                ProcessHandleObservationStage::PidFdIdentityBeforeObservation,
                source,
            )
        })?;

        let stat_path = proc_process_path(expected_pid, "stat");
        let stat = read_bounded(&stat_path, PROC_STAT_LIMIT, "read process stat")
            .map_err(|error| prefer_exit(pidfd, expected_pid, error))
            .map_err(|source| {
                ProcessHandleObservationError::new(
                    ProcessHandleObservationStage::ProcessIdentity,
                    source,
                )
            })?;
        let identity = parse_proc_stat(&stat)
            .ok_or_else(|| ProcessHandleError::MalformedProcStat {
                path: stat_path.clone(),
            })
            .map_err(|error| prefer_exit(pidfd, expected_pid, error))
            .map_err(|source| {
                ProcessHandleObservationError::new(
                    ProcessHandleObservationStage::ProcessIdentity,
                    source,
                )
            })?;
        if identity.pid() != expected_pid {
            return Err(ProcessHandleObservationError::new(
                ProcessHandleObservationStage::ProcessIdentity,
                prefer_exit(
                    pidfd,
                    expected_pid,
                    ProcessHandleError::PidFdIdentityMismatch {
                        expected: expected_pid,
                        observed: identity.pid(),
                    },
                ),
            ));
        }
        if let Some(expected) = expected_identity
            && identity != expected
        {
            return Err(ProcessHandleObservationError::new(
                ProcessHandleObservationStage::ProcessIdentity,
                prefer_exit(
                    pidfd,
                    expected_pid,
                    ProcessHandleError::ProcessIdentityMismatch {
                        expected,
                        observed: identity,
                    },
                ),
            ));
        }

        let (credentials, domain) = observe_process_state(pidfd, expected_pid)?;

        require_pidfd_pid(pidfd, expected_pid).map_err(|source| {
            ProcessHandleObservationError::new(
                ProcessHandleObservationStage::PidFdIdentityAfterObservation,
                source,
            )
        })?;
        require_waitable_child(pidfd, expected_pid).map_err(|source| {
            ProcessHandleObservationError::new(
                ProcessHandleObservationStage::PidFdChildOwnershipAfterObservation,
                source,
            )
        })?;
        require_live(pidfd, expected_pid).map_err(|source| {
            ProcessHandleObservationError::new(
                ProcessHandleObservationStage::PidFdLivenessAfterObservation,
                source,
            )
        })?;
        require_waitable_child_disposition().map_err(|source| {
            ProcessHandleObservationError::new(
                ProcessHandleObservationStage::ChildDispositionAfterObservation,
                source,
            )
        })?;
        Ok(ProcessObservation {
            identity,
            credentials,
            domain,
        })
    }

    fn prefer_exit(
        pidfd: &OwnedFd,
        pid: NonZeroU32,
        original: ProcessHandleError,
    ) -> ProcessHandleError {
        match require_live(pidfd, pid) {
            Err(error) if error.kind() == super::ProcessHandleErrorKind::Exited => error,
            Ok(()) | Err(_) => original,
        }
    }

    fn observe_process_state(
        pidfd: &OwnedFd,
        pid: NonZeroU32,
    ) -> Result<(ProcessCredentials, ProcessDomainObservation), ProcessHandleObservationError> {
        let user_namespace_support = observe_user_namespace_support().map_err(|source| {
            ProcessHandleObservationError::new(
                ProcessHandleObservationStage::UserNamespaceSupportBeforeObservation,
                source,
            )
        })?;
        let first_ids = scan_process_task_ids(pidfd, pid).map_err(|source| {
            ProcessHandleObservationError::new(ProcessHandleObservationStage::FirstTaskIds, source)
        })?;
        let first = read_process_task_observations(
            pidfd,
            pid,
            &first_ids,
            user_namespace_support,
            FIRST_TASK_OBSERVATION_STAGES,
        )?;
        let first_maps = read_process_credential_maps(
            pidfd,
            pid,
            user_namespace_support,
            FIRST_CREDENTIAL_MAP_STAGES,
        )?;
        let middle_ids = scan_process_task_ids(pidfd, pid).map_err(|source| {
            ProcessHandleObservationError::new(ProcessHandleObservationStage::SecondTaskIds, source)
        })?;
        let second = read_process_task_observations(
            pidfd,
            pid,
            &middle_ids,
            user_namespace_support,
            SECOND_TASK_OBSERVATION_STAGES,
        )?;
        let second_maps = read_process_credential_maps(
            pidfd,
            pid,
            user_namespace_support,
            SECOND_CREDENTIAL_MAP_STAGES,
        )?;
        let final_ids = scan_process_task_ids(pidfd, pid).map_err(|source| {
            ProcessHandleObservationError::new(ProcessHandleObservationStage::FinalTaskIds, source)
        })?;
        let final_user_namespace_support = observe_user_namespace_support().map_err(|source| {
            ProcessHandleObservationError::new(
                ProcessHandleObservationStage::UserNamespaceSupportAfterObservation,
                source,
            )
        })?;
        validate_process_observation_census(
            pid,
            ProcessObservationCensusPass {
                task_ids: &first_ids,
                task_observations: &first,
                credential_maps: first_maps,
            },
            ProcessObservationCensusPass {
                task_ids: &middle_ids,
                task_observations: &second,
                credential_maps: second_maps,
            },
            &final_ids,
            user_namespace_support,
            final_user_namespace_support,
        )
        .map_err(|source| {
            ProcessHandleObservationError::new(
                ProcessHandleObservationStage::CensusValidation,
                source,
            )
        })
    }

    pub(super) fn validate_process_observation_census(
        pid: NonZeroU32,
        first: ProcessObservationCensusPass<'_>,
        second: ProcessObservationCensusPass<'_>,
        final_ids: &[NonZeroU32],
        user_namespace_support: UserNamespaceSupport,
        final_user_namespace_support: UserNamespaceSupport,
    ) -> Result<(ProcessCredentials, ProcessDomainObservation), ProcessHandleError> {
        if user_namespace_support != final_user_namespace_support {
            return Err(ProcessHandleError::ProcessUserNamespaceSupportChanged { pid });
        }
        let first_aligned = first.task_observations.len() == first.task_ids.len()
            && first
                .task_observations
                .iter()
                .zip(first.task_ids)
                .all(|((observed, _), expected)| observed == expected);
        let second_aligned = second.task_observations.len() == second.task_ids.len()
            && second
                .task_observations
                .iter()
                .zip(second.task_ids)
                .all(|((observed, _), expected)| observed == expected);
        if first.task_ids != second.task_ids
            || second.task_ids != final_ids
            || !first_aligned
            || !second_aligned
        {
            return Err(ProcessHandleError::ProcessThreadSetChanged { pid });
        }
        for ((first_thread, first_observation), (second_thread, second_observation)) in
            first.task_observations.iter().zip(second.task_observations)
        {
            debug_assert_eq!(first_thread, second_thread);
            if first_observation.credentials != second_observation.credentials {
                return Err(ProcessHandleError::ProcessThreadCredentialsChanged {
                    pid,
                    thread: *first_thread,
                });
            }
            if first_observation.namespaces != second_observation.namespaces {
                return Err(ProcessHandleError::ProcessThreadNamespacesChanged {
                    pid,
                    thread: *first_thread,
                });
            }
        }
        let leader = second
            .task_observations
            .iter()
            .find_map(|(thread, observation)| (*thread == pid).then_some(observation))
            .ok_or(ProcessHandleError::MissingProcessLeaderTask { pid })?;
        for (thread, observation) in second.task_observations {
            if observation.credentials != leader.credentials {
                return Err(ProcessHandleError::ProcessThreadCredentialMismatch {
                    pid,
                    thread: *thread,
                });
            }
            if observation.namespaces != leader.namespaces {
                return Err(ProcessHandleError::ProcessThreadNamespaceMismatch {
                    pid,
                    thread: *thread,
                });
            }
        }
        let user_namespace = match (
            user_namespace_support,
            leader.namespaces.user,
            first.credential_maps,
            second.credential_maps,
        ) {
            (
                UserNamespaceSupport::Unsupported,
                ProcessTaskUserNamespaceObservation::Unsupported,
                ProcessCredentialMapObservation::Unsupported,
                ProcessCredentialMapObservation::Unsupported,
            ) if first.task_observations.iter().all(|(_, observation)| {
                observation.namespaces.user == ProcessTaskUserNamespaceObservation::Unsupported
            }) && second.task_observations.iter().all(|(_, observation)| {
                observation.namespaces.user == ProcessTaskUserNamespaceObservation::Unsupported
            }) =>
            {
                ProcessUserNamespaceObservation::Unsupported
            }
            (
                UserNamespaceSupport::Supported,
                ProcessTaskUserNamespaceObservation::Observed(namespace),
                ProcessCredentialMapObservation::Observed {
                    uid: first_uid,
                    gid: first_gid,
                },
                ProcessCredentialMapObservation::Observed {
                    uid: second_uid,
                    gid: second_gid,
                },
            ) if first.task_observations.iter().all(|(_, observation)| {
                matches!(
                    observation.namespaces.user,
                    ProcessTaskUserNamespaceObservation::Observed(_)
                )
            }) && second.task_observations.iter().all(|(_, observation)| {
                matches!(
                    observation.namespaces.user,
                    ProcessTaskUserNamespaceObservation::Observed(_)
                )
            }) =>
            {
                if first_uid != second_uid {
                    return Err(ProcessHandleError::ProcessCredentialMapChanged {
                        pid,
                        map: ProcessCredentialMapKind::Uid,
                    });
                }
                if first_gid != second_gid {
                    return Err(ProcessHandleError::ProcessCredentialMapChanged {
                        pid,
                        map: ProcessCredentialMapKind::Gid,
                    });
                }
                ProcessUserNamespaceObservation::Observed {
                    namespace,
                    uid_map_digest: second_uid,
                    gid_map_digest: second_gid,
                }
            }
            _ => {
                return Err(ProcessHandleError::ProcessUserNamespaceObservationMismatch { pid });
            }
        };
        Ok((
            leader.credentials.clone(),
            ProcessDomainObservation {
                user_namespace,
                mount_namespace: leader.namespaces.mount,
                network_namespace: leader.namespaces.network,
            },
        ))
    }

    fn scan_process_task_ids(
        pidfd: &OwnedFd,
        pid: NonZeroU32,
    ) -> Result<Vec<NonZeroU32>, ProcessHandleError> {
        let directory = PathBuf::from(format!("/proc/{pid}/task"));
        let entries = fs::read_dir(&directory)
            .map_err(|source| ProcessHandleError::SystemCall {
                operation: "read process task directory",
                path: Some(directory.clone()),
                source,
            })
            .map_err(|error| prefer_exit(pidfd, pid, error))?;
        let mut threads = Vec::new();
        for entry in entries {
            let entry = entry
                .map_err(|source| ProcessHandleError::SystemCall {
                    operation: "read process task entry",
                    path: Some(directory.clone()),
                    source,
                })
                .map_err(|error| prefer_exit(pidfd, pid, error))?;
            if threads.len() == MAX_PROCESS_THREADS {
                return Err(ProcessHandleError::ProcessThreadLimitExceeded {
                    pid,
                    limit: MAX_PROCESS_THREADS,
                });
            }
            let path = entry.path();
            let thread = NonZeroU32::new(
                parse_canonical_u32(entry.file_name().as_os_str().as_bytes()).ok_or_else(|| {
                    ProcessHandleError::MalformedProcessTaskEntry { path: path.clone() }
                })?,
            )
            .ok_or(ProcessHandleError::MalformedProcessTaskEntry { path })?;
            threads.push(thread);
        }
        threads.sort_unstable();
        if threads.is_empty() || threads.windows(2).any(|window| window[0] == window[1]) {
            return Err(ProcessHandleError::MalformedProcessTaskEntry { path: directory });
        }
        if !threads.contains(&pid) {
            return Err(ProcessHandleError::MissingProcessLeaderTask { pid });
        }
        Ok(threads)
    }

    fn read_process_task_observations(
        pidfd: &OwnedFd,
        pid: NonZeroU32,
        threads: &[NonZeroU32],
        user_namespace_support: UserNamespaceSupport,
        stages: ProcessTaskObservationStages,
    ) -> Result<Vec<(NonZeroU32, ProcessTaskObservation)>, ProcessHandleObservationError> {
        let mut observations = Vec::with_capacity(threads.len());
        for thread in threads {
            let path = PathBuf::from(format!("/proc/{pid}/task/{thread}/status"));
            let status = read_bounded(&path, PROC_STATUS_LIMIT, "read process task status")
                .map_err(|error| prefer_task_change_or_exit(pidfd, pid, threads, error))
                .map_err(|source| ProcessHandleObservationError::new(stages.status, source))?;
            let (status_tgid, status_pid, credentials) = parse_proc_status(&status)
                .ok_or_else(|| ProcessHandleError::MalformedProcStatus { path: path.clone() })
                .map_err(|error| prefer_task_change_or_exit(pidfd, pid, threads, error))
                .map_err(|source| ProcessHandleObservationError::new(stages.status, source))?;
            if status_tgid != pid {
                return Err(ProcessHandleObservationError::new(
                    stages.status,
                    ProcessHandleError::ProcessStatusTgidMismatch {
                        expected: pid,
                        observed: status_tgid,
                    },
                ));
            }
            if status_pid != *thread {
                return Err(ProcessHandleObservationError::new(
                    stages.status,
                    ProcessHandleError::ProcessStatusPidMismatch {
                        expected: *thread,
                        observed: status_pid,
                    },
                ));
            }
            let namespaces = ProcessTaskNamespaces {
                user: read_process_task_user_namespace(
                    pidfd,
                    pid,
                    threads,
                    *thread,
                    user_namespace_support,
                )
                .map_err(|source| {
                    ProcessHandleObservationError::new(stages.user_namespace, source)
                })?,
                mount: read_process_task_namespace(pidfd, pid, threads, *thread, "mnt").map_err(
                    |source| ProcessHandleObservationError::new(stages.mount_namespace, source),
                )?,
                network: read_process_task_namespace(pidfd, pid, threads, *thread, "net").map_err(
                    |source| ProcessHandleObservationError::new(stages.network_namespace, source),
                )?,
            };
            observations.push((
                *thread,
                ProcessTaskObservation {
                    credentials,
                    namespaces,
                },
            ));
        }
        Ok(observations)
    }

    fn read_process_task_user_namespace(
        pidfd: &OwnedFd,
        pid: NonZeroU32,
        threads: &[NonZeroU32],
        thread: NonZeroU32,
        support: UserNamespaceSupport,
    ) -> Result<ProcessTaskUserNamespaceObservation, ProcessHandleError> {
        let path = PathBuf::from(format!("/proc/{pid}/task/{thread}/ns/user"));
        let file = open_optional_process_domain_file(&path, "open process user namespace")
            .map_err(|error| prefer_task_change_or_exit(pidfd, pid, threads, error))?;
        match (support, file) {
            (UserNamespaceSupport::Unsupported, None) => {
                Ok(ProcessTaskUserNamespaceObservation::Unsupported)
            }
            (UserNamespaceSupport::Supported, Some(file)) => {
                read_process_namespace_identity(file, &path, "inspect process user namespace")
                    .map(ProcessTaskUserNamespaceObservation::Observed)
                    .map_err(|error| prefer_task_change_or_exit(pidfd, pid, threads, error))
            }
            (UserNamespaceSupport::Unsupported, Some(_))
            | (UserNamespaceSupport::Supported, None) => Err(prefer_task_change_or_exit(
                pidfd,
                pid,
                threads,
                ProcessHandleError::ProcessUserNamespaceObservationMismatch { pid },
            )),
        }
    }

    fn read_process_task_namespace(
        pidfd: &OwnedFd,
        pid: NonZeroU32,
        threads: &[NonZeroU32],
        thread: NonZeroU32,
        namespace: &str,
    ) -> Result<ProcessNamespaceIdentity, ProcessHandleError> {
        let path = PathBuf::from(format!("/proc/{pid}/task/{thread}/ns/{namespace}"));
        let file = File::open(&path)
            .map_err(|source| ProcessHandleError::SystemCall {
                operation: "open process namespace",
                path: Some(path.clone()),
                source,
            })
            .map_err(|error| prefer_task_change_or_exit(pidfd, pid, threads, error))?;
        read_process_namespace_identity(file, &path, "inspect process namespace")
            .map_err(|error| prefer_task_change_or_exit(pidfd, pid, threads, error))
    }

    fn read_process_namespace_identity(
        file: File,
        path: &Path,
        operation: &'static str,
    ) -> Result<ProcessNamespaceIdentity, ProcessHandleError> {
        let metadata = file
            .metadata()
            .map_err(|source| ProcessHandleError::SystemCall {
                operation,
                path: Some(path.to_path_buf()),
                source,
            })?;
        let inode = NonZeroU64::new(metadata.ino()).ok_or_else(|| {
            ProcessHandleError::MalformedProcessNamespace {
                path: path.to_path_buf(),
            }
        })?;
        Ok(ProcessNamespaceIdentity::new(metadata.dev(), inode))
    }

    fn read_process_credential_maps(
        pidfd: &OwnedFd,
        pid: NonZeroU32,
        support: UserNamespaceSupport,
        stages: ProcessCredentialMapObservationStages,
    ) -> Result<ProcessCredentialMapObservation, ProcessHandleObservationError> {
        let uid = read_process_credential_map(pidfd, pid, ProcessCredentialMapKind::Uid, support)
            .map_err(|source| ProcessHandleObservationError::new(stages.uid, source))?;
        let gid = read_process_credential_map(pidfd, pid, ProcessCredentialMapKind::Gid, support)
            .map_err(|source| ProcessHandleObservationError::new(stages.gid, source))?;
        match (uid, gid) {
            (None, None) => Ok(ProcessCredentialMapObservation::Unsupported),
            (Some(uid), Some(gid)) => Ok(ProcessCredentialMapObservation::Observed { uid, gid }),
            (None, Some(_)) | (Some(_), None) => Err(ProcessHandleObservationError::new(
                stages.gid,
                ProcessHandleError::ProcessUserNamespaceObservationMismatch { pid },
            )),
        }
    }

    fn read_process_credential_map(
        pidfd: &OwnedFd,
        pid: NonZeroU32,
        kind: ProcessCredentialMapKind,
        support: UserNamespaceSupport,
    ) -> Result<Option<ProcessCredentialMapDigest>, ProcessHandleError> {
        let leaf = match kind {
            ProcessCredentialMapKind::Uid => "uid_map",
            ProcessCredentialMapKind::Gid => "gid_map",
        };
        let path = proc_process_path(pid, leaf);
        let file = open_optional_process_domain_file(&path, "open process credential map")
            .map_err(|error| prefer_exit(pidfd, pid, error))?;
        match (support, file) {
            (UserNamespaceSupport::Unsupported, None) => Ok(None),
            (UserNamespaceSupport::Supported, Some(file)) => {
                let contents = read_file_bounded(
                    file,
                    &path,
                    PROC_ID_MAP_LIMIT,
                    "read process credential map",
                )
                .map_err(|error| prefer_exit(pidfd, pid, error))?;
                digest_process_id_map(&contents, &path, kind)
                    .map(Some)
                    .map_err(|error| prefer_exit(pidfd, pid, error))
            }
            (UserNamespaceSupport::Unsupported, Some(_))
            | (UserNamespaceSupport::Supported, None) => Err(prefer_exit(
                pidfd,
                pid,
                ProcessHandleError::ProcessUserNamespaceObservationMismatch { pid },
            )),
        }
    }

    fn open_optional_process_domain_file(
        path: &Path,
        operation: &'static str,
    ) -> Result<Option<File>, ProcessHandleError> {
        match File::open(path) {
            Ok(file) => Ok(Some(file)),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(ProcessHandleError::SystemCall {
                operation,
                path: Some(path.to_path_buf()),
                source,
            }),
        }
    }

    fn observe_user_namespace_support() -> Result<UserNamespaceSupport, ProcessHandleError> {
        let present = [
            (
                Path::new("/proc/self/ns/user"),
                "probe observer user namespace",
            ),
            (Path::new("/proc/self/uid_map"), "probe observer UID map"),
            (Path::new("/proc/self/gid_map"), "probe observer GID map"),
        ]
        .map(|(path, operation)| {
            open_optional_process_domain_file(path, operation).map(|file| file.is_some())
        });
        let [user_namespace, uid_map, gid_map] = present;
        let user_namespace = user_namespace?;
        let uid_map = uid_map?;
        let gid_map = gid_map?;
        match (user_namespace, uid_map, gid_map) {
            (true, true, true) => Ok(UserNamespaceSupport::Supported),
            (false, false, false) => Ok(UserNamespaceSupport::Unsupported),
            _ => Err(ProcessHandleError::ProcessUserNamespaceSupportIncoherent),
        }
    }

    pub(super) fn digest_process_id_map(
        contents: &[u8],
        path: &Path,
        kind: ProcessCredentialMapKind,
    ) -> Result<ProcessCredentialMapDigest, ProcessHandleError> {
        let entries = parse_process_id_map(contents, path)?;
        let mut hasher = Sha256::new();
        hasher.update(match kind {
            ProcessCredentialMapKind::Uid => UID_MAP_DIGEST_DOMAIN,
            ProcessCredentialMapKind::Gid => GID_MAP_DIGEST_DOMAIN,
        });
        hasher.update(
            u32::try_from(entries.len())
                .expect("the process ID-map entry limit fits u32")
                .to_le_bytes(),
        );
        for entry in entries {
            hasher.update(entry.inside.to_le_bytes());
            hasher.update(entry.outside.to_le_bytes());
            hasher.update(entry.length.to_le_bytes());
        }
        Ok(ProcessCredentialMapDigest(hasher.finalize().into()))
    }

    fn parse_process_id_map(
        contents: &[u8],
        path: &Path,
    ) -> Result<Vec<ProcessIdMapEntry>, ProcessHandleError> {
        let mut entries = Vec::new();
        for line in contents.split(|byte| *byte == b'\n') {
            let line = trim_ascii(line);
            if line.is_empty() {
                continue;
            }
            if entries.len() == MAX_PROCESS_ID_MAP_ENTRIES {
                return Err(ProcessHandleError::ProcessIdMapEntryLimitExceeded {
                    path: path.to_path_buf(),
                    limit: MAX_PROCESS_ID_MAP_ENTRIES,
                });
            }
            let fields = line
                .split(|byte| byte.is_ascii_whitespace())
                .filter(|field| !field.is_empty())
                .collect::<Vec<_>>();
            let [inside, outside, length] = fields.as_slice() else {
                return Err(ProcessHandleError::MalformedProcessIdMap {
                    path: path.to_path_buf(),
                });
            };
            let inside = parse_canonical_u32(inside).ok_or_else(|| {
                ProcessHandleError::MalformedProcessIdMap {
                    path: path.to_path_buf(),
                }
            })?;
            let outside = parse_canonical_u32(outside).ok_or_else(|| {
                ProcessHandleError::MalformedProcessIdMap {
                    path: path.to_path_buf(),
                }
            })?;
            let length = parse_canonical_u32(length)
                .filter(|length| *length != 0)
                .ok_or_else(|| ProcessHandleError::MalformedProcessIdMap {
                    path: path.to_path_buf(),
                })?;
            let maximum = u64::from(u32::MAX);
            if u64::from(inside) + u64::from(length) > maximum
                || u64::from(outside) + u64::from(length) > maximum
            {
                return Err(ProcessHandleError::MalformedProcessIdMap {
                    path: path.to_path_buf(),
                });
            }
            entries.push(ProcessIdMapEntry {
                inside,
                outside,
                length,
            });
        }
        if entries.is_empty() {
            return Err(ProcessHandleError::MalformedProcessIdMap {
                path: path.to_path_buf(),
            });
        }

        let mut inside_order = entries.clone();
        inside_order.sort_unstable_by_key(|entry| entry.inside);
        if inside_order.windows(2).any(|window| {
            ranges_overlap(
                window[0].inside,
                window[0].length,
                window[1].inside,
                window[1].length,
            )
        }) {
            return Err(ProcessHandleError::MalformedProcessIdMap {
                path: path.to_path_buf(),
            });
        }
        let mut outside_order = entries.clone();
        outside_order.sort_unstable_by_key(|entry| entry.outside);
        if outside_order.windows(2).any(|window| {
            ranges_overlap(
                window[0].outside,
                window[0].length,
                window[1].outside,
                window[1].length,
            )
        }) {
            return Err(ProcessHandleError::MalformedProcessIdMap {
                path: path.to_path_buf(),
            });
        }
        entries.sort_unstable_by_key(|entry| (entry.inside, entry.outside, entry.length));
        Ok(entries)
    }

    fn ranges_overlap(first: u32, first_length: u32, second: u32, second_length: u32) -> bool {
        u64::from(first) < u64::from(second) + u64::from(second_length)
            && u64::from(second) < u64::from(first) + u64::from(first_length)
    }

    fn prefer_task_change_or_exit(
        pidfd: &OwnedFd,
        pid: NonZeroU32,
        expected_threads: &[NonZeroU32],
        original: ProcessHandleError,
    ) -> ProcessHandleError {
        let error = prefer_exit(pidfd, pid, original);
        if error.kind() == super::ProcessHandleErrorKind::Exited {
            return error;
        }
        match scan_process_task_ids(pidfd, pid) {
            Ok(observed) if observed != expected_threads => {
                ProcessHandleError::ProcessThreadSetChanged { pid }
            }
            Ok(_) | Err(_) => error,
        }
    }

    fn require_pidfd_pid(
        pidfd: &OwnedFd,
        expected_pid: NonZeroU32,
    ) -> Result<(), ProcessHandleError> {
        let path = PathBuf::from(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()));
        let contents = read_bounded(&path, PIDFD_INFO_LIMIT, "read pidfd identity")?;
        let observed = parse_pidfd_info(&contents)
            .ok_or_else(|| ProcessHandleError::MalformedPidFdInfo { path: path.clone() })?;
        let Some(observed) = observed else {
            return Err(ProcessHandleError::Exited { pid: expected_pid });
        };
        if observed != expected_pid {
            return Err(ProcessHandleError::PidFdIdentityMismatch {
                expected: expected_pid,
                observed,
            });
        }
        Ok(())
    }

    pub(super) fn require_live(pidfd: &OwnedFd, pid: NonZeroU32) -> Result<(), ProcessHandleError> {
        let mut poll_fd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll_fd` points to one initialized pollfd, its descriptor is
        // borrowed from the live OwnedFd, and a zero timeout cannot block.
        let result = loop {
            // SAFETY: `poll_fd` points to one initialized pollfd, its descriptor
            // is borrowed from the live OwnedFd, and a zero timeout cannot block.
            let result = unsafe { libc::poll(&raw mut poll_fd, 1, 0) };
            if result >= 0 {
                break result;
            }
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::Interrupted {
                poll_fd.revents = 0;
                continue;
            }
            return Err(ProcessHandleError::SystemCall {
                operation: "poll child pidfd",
                path: None,
                source,
            });
        };
        if result == 0 {
            return Ok(());
        }
        if poll_fd.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            return Err(ProcessHandleError::Exited { pid });
        }
        let source = if poll_fd.revents & libc::POLLNVAL != 0 {
            io::Error::from_raw_os_error(libc::EBADF)
        } else {
            io::Error::other(format!(
                "unexpected pidfd poll events 0x{:x}",
                poll_fd.revents
            ))
        };
        Err(ProcessHandleError::SystemCall {
            operation: "poll child pidfd",
            path: None,
            source,
        })
    }

    fn require_waitable_child_disposition() -> Result<(), ProcessHandleError> {
        let mut action = MaybeUninit::<libc::sigaction>::zeroed();
        // SAFETY: a null new-action pointer requests a read-only query, while
        // `action` points to writable storage for the current disposition.
        if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) } != 0 {
            return Err(ProcessHandleError::SystemCall {
                operation: "read SIGCHLD disposition",
                path: None,
                source: io::Error::last_os_error(),
            });
        }
        // SAFETY: sigaction initialized the complete value on success.
        let action = unsafe { action.assume_init() };
        if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
            return Err(ProcessHandleError::ChildReapContractUnavailable);
        }
        Ok(())
    }

    pub(super) fn require_waitable_child(
        pidfd: &OwnedFd,
        pid: NonZeroU32,
    ) -> Result<(), ProcessHandleError> {
        let mut information = MaybeUninit::<libc::siginfo_t>::zeroed();
        loop {
            // SAFETY: `information` points to writable siginfo storage; P_PIDFD
            // interprets the validated owned descriptor as the selected child;
            // WNOWAIT guarantees this ownership check cannot reap it.
            let result = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    u32::try_from(pidfd.as_raw_fd()).expect("owned descriptors are nonnegative"),
                    information.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == 0 {
                return Ok(());
            }
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return if source.raw_os_error() == Some(libc::ECHILD) {
                match require_live(pidfd, pid) {
                    Err(error) if error.kind() == super::ProcessHandleErrorKind::Exited => {
                        Err(error)
                    }
                    Ok(()) | Err(_) => Err(ProcessHandleError::ChildOwnershipLost { pid }),
                }
            } else {
                Err(ProcessHandleError::SystemCall {
                    operation: "verify pidfd child ownership",
                    path: None,
                    source,
                })
            };
        }
    }

    fn require_waitable_child_pid(pid: NonZeroU32) -> Result<(), ProcessHandleError> {
        let mut information = MaybeUninit::<libc::siginfo_t>::zeroed();
        loop {
            // SAFETY: `information` points to writable siginfo storage; the
            // validated PID selects one child; WNOWAIT guarantees this
            // pre-pidfd ownership check cannot reap it.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid.get(),
                    information.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == 0 {
                return Ok(());
            }
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return if source.raw_os_error() == Some(libc::ECHILD) {
                Err(ProcessHandleError::Exited { pid })
            } else {
                Err(ProcessHandleError::SystemCall {
                    operation: "verify child ownership before pidfd_open",
                    path: None,
                    source,
                })
            };
        }
    }

    fn require_procfs_pid_namespace() -> Result<(), ProcessHandleError> {
        // SAFETY: getpid has no arguments or failure mode and only reads the
        // calling process identity.
        let raw_pid = unsafe { libc::getpid() };
        let caller_pid = u32::try_from(raw_pid)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or(ProcessHandleError::InvalidChildPid {
                pid: u32::try_from(raw_pid).unwrap_or(0),
            })?;
        let path = Path::new("/proc/self/stat");
        let contents = read_bounded(path, PROC_STAT_LIMIT, "read procfs namespace identity")?;
        let identity =
            parse_proc_stat(&contents).ok_or_else(|| ProcessHandleError::MalformedProcStat {
                path: path.to_path_buf(),
            })?;
        if identity.pid() != caller_pid {
            return Err(ProcessHandleError::ProcfsPidNamespaceMismatch {
                caller_pid,
                procfs_pid: identity.pid(),
            });
        }
        Ok(())
    }

    fn read_bounded(
        path: &Path,
        limit: usize,
        operation: &'static str,
    ) -> Result<Vec<u8>, ProcessHandleError> {
        let file = File::open(path).map_err(|source| ProcessHandleError::SystemCall {
            operation,
            path: Some(path.to_path_buf()),
            source,
        })?;
        read_file_bounded(file, path, limit, operation)
    }

    fn read_file_bounded(
        file: File,
        path: &Path,
        limit: usize,
        operation: &'static str,
    ) -> Result<Vec<u8>, ProcessHandleError> {
        let read_limit = u64::try_from(limit)
            .expect("proc observation limits fit u64")
            .saturating_add(1);
        let mut contents = Vec::new();
        file.take(read_limit)
            .read_to_end(&mut contents)
            .map_err(|source| ProcessHandleError::SystemCall {
                operation,
                path: Some(path.to_path_buf()),
                source,
            })?;
        if contents.len() > limit {
            return Err(ProcessHandleError::ProcFileLimitExceeded {
                path: path.to_path_buf(),
                limit,
            });
        }
        Ok(contents)
    }

    fn proc_process_path(pid: NonZeroU32, leaf: &str) -> PathBuf {
        PathBuf::from(format!("/proc/{pid}/{leaf}"))
    }

    pub(super) fn parse_proc_stat(contents: &[u8]) -> Option<ProcessIdentity> {
        let command_start = contents.windows(2).position(|window| window == b" (")?;
        let pid = NonZeroU32::new(parse_canonical_u32(&contents[..command_start])?)?;
        let command_end = contents.iter().rposition(|byte| *byte == b')')?;
        if command_end < command_start + 2 || contents.get(command_end + 1) != Some(&b' ') {
            return None;
        }
        let fields = contents[command_end + 2..]
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let state = *fields.first()?;
        if state.len() != 1 || !state[0].is_ascii_alphabetic() {
            return None;
        }
        let start_time_ticks = NonZeroU64::new(parse_canonical_u64(fields.get(19)?)?)?;
        Some(ProcessIdentity::new(pid, start_time_ticks))
    }

    pub(super) fn parse_proc_status(
        contents: &[u8],
    ) -> Option<(NonZeroU32, NonZeroU32, ProcessCredentials)> {
        let tgid = NonZeroU32::new(parse_single_decimal(field(contents, b"Tgid:")?)?)?;
        let pid = NonZeroU32::new(parse_single_decimal(field(contents, b"Pid:")?)?)?;
        let uids = parse_quad(field(contents, b"Uid:")?)?;
        let gids = parse_quad(field(contents, b"Gid:")?)?;
        let supplementary_groups = parse_decimal_list(field(contents, b"Groups:")?)?;
        let capability_inheritable = parse_single_hex(field(contents, b"CapInh:")?)?;
        let capability_permitted = parse_single_hex(field(contents, b"CapPrm:")?)?;
        let capability_effective = parse_single_hex(field(contents, b"CapEff:")?)?;
        let capability_bounding = parse_single_hex(field(contents, b"CapBnd:")?)?;
        let capability_ambient = parse_single_hex(field(contents, b"CapAmb:")?)?;
        let no_new_privileges = match parse_single_decimal(field(contents, b"NoNewPrivs:")?)? {
            0 => false,
            1 => true,
            _ => return None,
        };
        Some((
            tgid,
            pid,
            ProcessCredentials {
                uids,
                gids,
                supplementary_groups: supplementary_groups.into_boxed_slice(),
                capability_inheritable,
                capability_permitted,
                capability_effective,
                capability_bounding,
                capability_ambient,
                no_new_privileges,
            },
        ))
    }

    pub(super) fn parse_pidfd_info(contents: &[u8]) -> Option<Option<NonZeroU32>> {
        let value = field(contents, b"Pid:")?;
        if value == b"-1" {
            return Some(None);
        }
        Some(Some(NonZeroU32::new(parse_single_decimal(value)?)?))
    }

    fn field<'a>(contents: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
        let mut found = None;
        for line in contents.split(|byte| *byte == b'\n') {
            let Some(value) = line.strip_prefix(name) else {
                continue;
            };
            if found.is_some() {
                return None;
            }
            found = Some(trim_ascii(value));
        }
        found
    }

    fn trim_ascii(mut value: &[u8]) -> &[u8] {
        while value.first().is_some_and(u8::is_ascii_whitespace) {
            value = &value[1..];
        }
        while value.last().is_some_and(u8::is_ascii_whitespace) {
            value = &value[..value.len() - 1];
        }
        value
    }

    fn parse_quad(value: &[u8]) -> Option<[u32; 4]> {
        let values = parse_decimal_list(value)?;
        values.try_into().ok()
    }

    fn parse_decimal_list(value: &[u8]) -> Option<Vec<u32>> {
        value
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .map(parse_canonical_u32)
            .collect()
    }

    fn parse_single_decimal(value: &[u8]) -> Option<u32> {
        if value.iter().any(|byte| byte.is_ascii_whitespace()) {
            return None;
        }
        parse_canonical_u32(value)
    }

    fn parse_single_hex(value: &[u8]) -> Option<u64> {
        if value.is_empty()
            || value.len() > 16
            || value.iter().any(|byte| !byte.is_ascii_hexdigit())
        {
            return None;
        }
        let value = std::str::from_utf8(value).ok()?;
        u64::from_str_radix(value, 16).ok()
    }

    fn parse_canonical_u32(value: &[u8]) -> Option<u32> {
        let value = parse_canonical_u64(value)?;
        u32::try_from(value).ok()
    }

    fn parse_canonical_u64(value: &[u8]) -> Option<u64> {
        if value.is_empty()
            || !value.iter().all(u8::is_ascii_digit)
            || (value.len() > 1 && value[0] == b'0')
        {
            return None;
        }
        let mut parsed = 0_u64;
        for digit in value {
            parsed = parsed
                .checked_mul(10)?
                .checked_add(u64::from(*digit - b'0'))?;
        }
        Some(parsed)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod implementation {
    use std::process::Child;

    use super::{
        ProcessHandle, ProcessHandleError, ProcessHandleObservationError, ProcessHandleOpenError,
        ProcessHandleOpenStage, ProcessObservation,
    };

    pub(super) fn open_child(_child: &Child) -> Result<ProcessHandle, ProcessHandleOpenError> {
        Err(ProcessHandleOpenError::new(
            ProcessHandleOpenStage::Start,
            ProcessHandleError::UnsupportedPlatform(std::env::consts::OS),
        ))
    }

    pub(super) fn reobserve(
        handle: &ProcessHandle,
    ) -> Result<ProcessObservation, ProcessHandleObservationError> {
        match handle.transport._never {}
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
