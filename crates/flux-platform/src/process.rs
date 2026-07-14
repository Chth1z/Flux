//! Exact, child-origin process handles for Linux and Android.
//!
//! A [`ProcessHandle`] can be opened only from a live, unreaped
//! [`std::process::Child`]. Linux and Android implementations retain a pidfd,
//! require the process-wide `SIGCHLD` disposition to preserve waitable
//! children, verify that the pidfd still names a child of this process, and
//! correlate every observation through `/proc/self/fdinfo/<pidfd>` before and
//! after reading the process's procfs identity and credentials. The caller must
//! not use an out-of-band `waitpid`/`waitid` reaper for the child while opening
//! the handle. The handle deliberately exposes no signaling or reap API: pidfd
//! readability proves exit, not parent-side reaping.

use std::error::Error;
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::process::Child;

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
    pub const fn capability_ambient(&self) -> u64 {
        self.capability_ambient
    }

    #[must_use]
    pub const fn no_new_privileges(&self) -> bool {
        self.no_new_privileges
    }
}

/// One complete point-in-time observation through a retained process handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessObservation {
    identity: ProcessIdentity,
    credentials: ProcessCredentials,
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
    ChildReapContractUnavailable,
    ChildOwnershipLost {
        pid: NonZeroU32,
    },
    ProcfsPidNamespaceMismatch {
        caller_pid: NonZeroU32,
        procfs_pid: NonZeroU32,
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
    ProcFileLimitExceeded {
        path: PathBuf,
        limit: usize,
    },
    ProcessThreadLimitExceeded {
        pid: NonZeroU32,
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
            | Self::ChildReapContractUnavailable
            | Self::ChildOwnershipLost { .. }
            | Self::ProcfsPidNamespaceMismatch { .. } => ProcessHandleErrorKind::IdentityChanged,
            Self::MalformedProcStat { .. }
            | Self::MalformedProcStatus { .. }
            | Self::MalformedPidFdInfo { .. }
            | Self::MalformedProcessTaskEntry { .. }
            | Self::ProcFileLimitExceeded { .. }
            | Self::ProcessThreadLimitExceeded { .. } => ProcessHandleErrorKind::Parse,
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
            Self::ProcFileLimitExceeded { path, limit } => write!(
                formatter,
                "proc file {} exceeds the hard limit of {limit} bytes",
                path.display()
            ),
            Self::ProcessThreadLimitExceeded { pid, limit } => write!(
                formatter,
                "process {pid} exceeds the hard limit of {limit} observed threads"
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
            | Self::ChildReapContractUnavailable
            | Self::ChildOwnershipLost { .. }
            | Self::ProcfsPidNamespaceMismatch { .. }
            | Self::MalformedProcStat { .. }
            | Self::MalformedProcStatus { .. }
            | Self::MalformedPidFdInfo { .. }
            | Self::MalformedProcessTaskEntry { .. }
            | Self::ProcFileLimitExceeded { .. }
            | Self::ProcessThreadLimitExceeded { .. } => None,
        }
    }
}

/// Non-cloneable handle for one exact child process instance.
pub struct ProcessHandle {
    identity: ProcessIdentity,
    credentials: ProcessCredentials,
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
    /// initial procfs identity and credentials.
    ///
    /// The process-wide `SIGCHLD` disposition must be the default without
    /// `SA_NOCLDWAIT`, and no external reaper may wait on this child while the
    /// handle is opened. These preconditions ensure an unreaped child PID cannot
    /// be recycled between `spawn` and `pidfd_open`.
    pub fn open_child(child: &Child) -> Result<Self, ProcessHandleError> {
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

    /// Return the exact identity and credentials captured while this child-
    /// origin handle was opened.
    ///
    /// The returned value is an owned observation so callers can retain it
    /// alongside a later [`Self::reobserve`] result without cloning or
    /// reconstructing process authority from a PID.
    #[must_use]
    pub fn initial_observation(&self) -> ProcessObservation {
        ProcessObservation {
            identity: self.identity,
            credentials: self.credentials.clone(),
        }
    }

    /// Reobserve the same live pidfd-bound process.
    ///
    /// Exit is reported as [`ProcessHandleErrorKind::Exited`]. Success proves
    /// only a live exact identity plus a point-in-time credential observation;
    /// it does not prove that a later exit was reaped by the parent.
    pub fn reobserve(&self) -> Result<ProcessObservation, ProcessHandleError> {
        implementation::reobserve(self)
    }
}

impl fmt::Debug for ProcessHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessHandle")
            .field("identity", &self.identity)
            .field("credentials", &self.credentials)
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
    use std::path::{Path, PathBuf};
    use std::process::Child;

    use super::{
        ProcessCredentials, ProcessHandle, ProcessHandleError, ProcessHandleTransport,
        ProcessIdentity, ProcessObservation,
    };
    use std::num::{NonZeroU32, NonZeroU64};

    const PROC_STAT_LIMIT: usize = 64 * 1024;
    // Linux permits up to 65,536 supplementary groups. Their worst-case
    // decimal `Groups:` representation fits below this bound with the rest of
    // one task status file.
    const PROC_STATUS_LIMIT: usize = 1024 * 1024;
    const PIDFD_INFO_LIMIT: usize = 16 * 1024;
    const MAX_PROCESS_THREADS: usize = 1024;

    pub(super) fn open_child(child: &Child) -> Result<ProcessHandle, ProcessHandleError> {
        require_waitable_child_disposition()?;
        require_procfs_pid_namespace()?;
        let raw_pid = child.id();
        let pid = NonZeroU32::new(raw_pid)
            .filter(|pid| i32::try_from(pid.get()).is_ok())
            .ok_or(ProcessHandleError::InvalidChildPid { pid: raw_pid })?;
        require_waitable_child_pid(pid)?;
        let pidfd = open_pidfd(pid)?;
        require_waitable_child(&pidfd, pid)?;
        let observation = observe(&pidfd, pid, None)?;
        require_waitable_child_disposition()?;
        require_waitable_child(&pidfd, pid)?;
        Ok(ProcessHandle {
            identity: observation.identity,
            credentials: observation.credentials,
            transport: ProcessHandleTransport { pidfd },
        })
    }

    pub(super) fn reobserve(
        handle: &ProcessHandle,
    ) -> Result<ProcessObservation, ProcessHandleError> {
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
    ) -> Result<ProcessObservation, ProcessHandleError> {
        require_waitable_child_disposition()?;
        require_procfs_pid_namespace()?;
        require_live(pidfd, expected_pid)?;
        require_waitable_child(pidfd, expected_pid)?;
        require_pidfd_pid(pidfd, expected_pid)?;

        let stat_path = proc_process_path(expected_pid, "stat");
        let stat = read_bounded(&stat_path, PROC_STAT_LIMIT, "read process stat")
            .map_err(|error| prefer_exit(pidfd, expected_pid, error))?;
        let identity = parse_proc_stat(&stat)
            .ok_or_else(|| ProcessHandleError::MalformedProcStat {
                path: stat_path.clone(),
            })
            .map_err(|error| prefer_exit(pidfd, expected_pid, error))?;
        if identity.pid() != expected_pid {
            return Err(prefer_exit(
                pidfd,
                expected_pid,
                ProcessHandleError::PidFdIdentityMismatch {
                    expected: expected_pid,
                    observed: identity.pid(),
                },
            ));
        }
        if let Some(expected) = expected_identity
            && identity != expected
        {
            return Err(prefer_exit(
                pidfd,
                expected_pid,
                ProcessHandleError::ProcessIdentityMismatch {
                    expected,
                    observed: identity,
                },
            ));
        }

        let credentials = observe_process_credentials(pidfd, expected_pid)?;

        require_pidfd_pid(pidfd, expected_pid)?;
        require_waitable_child(pidfd, expected_pid)?;
        require_live(pidfd, expected_pid)?;
        require_waitable_child_disposition()?;
        Ok(ProcessObservation {
            identity,
            credentials,
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

    fn observe_process_credentials(
        pidfd: &OwnedFd,
        pid: NonZeroU32,
    ) -> Result<ProcessCredentials, ProcessHandleError> {
        let first_ids = scan_process_task_ids(pidfd, pid)?;
        let first = read_process_task_credentials(pidfd, pid, &first_ids)?;
        let middle_ids = scan_process_task_ids(pidfd, pid)?;
        let second = read_process_task_credentials(pidfd, pid, &middle_ids)?;
        let final_ids = scan_process_task_ids(pidfd, pid)?;
        validate_process_credential_census(
            pid,
            &first_ids,
            &first,
            &middle_ids,
            &second,
            &final_ids,
        )
    }

    pub(super) fn validate_process_credential_census(
        pid: NonZeroU32,
        first_ids: &[NonZeroU32],
        first: &[(NonZeroU32, ProcessCredentials)],
        second_ids: &[NonZeroU32],
        second: &[(NonZeroU32, ProcessCredentials)],
        final_ids: &[NonZeroU32],
    ) -> Result<ProcessCredentials, ProcessHandleError> {
        let first_aligned = first.len() == first_ids.len()
            && first
                .iter()
                .zip(first_ids)
                .all(|((observed, _), expected)| observed == expected);
        let second_aligned = second.len() == second_ids.len()
            && second
                .iter()
                .zip(second_ids)
                .all(|((observed, _), expected)| observed == expected);
        if first_ids != second_ids || second_ids != final_ids || !first_aligned || !second_aligned {
            return Err(ProcessHandleError::ProcessThreadSetChanged { pid });
        }
        for ((first_thread, first_credentials), (second_thread, second_credentials)) in
            first.iter().zip(second)
        {
            debug_assert_eq!(first_thread, second_thread);
            if first_credentials != second_credentials {
                return Err(ProcessHandleError::ProcessThreadCredentialsChanged {
                    pid,
                    thread: *first_thread,
                });
            }
        }
        let leader = second
            .iter()
            .find_map(|(thread, credentials)| (*thread == pid).then_some(credentials))
            .ok_or(ProcessHandleError::MissingProcessLeaderTask { pid })?;
        for (thread, credentials) in second {
            if credentials != leader {
                return Err(ProcessHandleError::ProcessThreadCredentialMismatch {
                    pid,
                    thread: *thread,
                });
            }
        }
        Ok(leader.clone())
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

    fn read_process_task_credentials(
        pidfd: &OwnedFd,
        pid: NonZeroU32,
        threads: &[NonZeroU32],
    ) -> Result<Vec<(NonZeroU32, ProcessCredentials)>, ProcessHandleError> {
        let mut observations = Vec::with_capacity(threads.len());
        for thread in threads {
            let path = PathBuf::from(format!("/proc/{pid}/task/{thread}/status"));
            let status = read_bounded(&path, PROC_STATUS_LIMIT, "read process task status")
                .map_err(|error| prefer_task_change_or_exit(pidfd, pid, threads, error))?;
            let (status_tgid, status_pid, credentials) = parse_proc_status(&status)
                .ok_or_else(|| ProcessHandleError::MalformedProcStatus { path: path.clone() })
                .map_err(|error| prefer_task_change_or_exit(pidfd, pid, threads, error))?;
            if status_tgid != pid {
                return Err(ProcessHandleError::ProcessStatusTgidMismatch {
                    expected: pid,
                    observed: status_tgid,
                });
            }
            if status_pid != *thread {
                return Err(ProcessHandleError::ProcessStatusPidMismatch {
                    expected: *thread,
                    observed: status_pid,
                });
            }
            observations.push((*thread, credentials));
        }
        Ok(observations)
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

    fn require_live(pidfd: &OwnedFd, pid: NonZeroU32) -> Result<(), ProcessHandleError> {
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

    use super::{ProcessHandle, ProcessHandleError, ProcessObservation};

    pub(super) fn open_child(_child: &Child) -> Result<ProcessHandle, ProcessHandleError> {
        Err(ProcessHandleError::UnsupportedPlatform(
            std::env::consts::OS,
        ))
    }

    pub(super) fn reobserve(
        handle: &ProcessHandle,
    ) -> Result<ProcessObservation, ProcessHandleError> {
        match handle.transport._never {}
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
