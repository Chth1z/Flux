//! Authoritative process-FD and INET_DIAG socket inventory.
//!
//! A successful snapshot is deliberately all-or-nothing: the expected procfs
//! process identity must match before and after the FD scan plus all four
//! IPv4/IPv6 TCP/connected-UDP dumps, and every netlink dump must reach an
//! unambiguous `NLMSG_DONE` terminator.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::time::Instant;

/// PID and procfs start-time identity of the process whose sockets are read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketDiagnosticsProcessIdentity {
    pid: NonZeroU32,
    start_time_ticks: NonZeroU64,
}

impl SocketDiagnosticsProcessIdentity {
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

/// Internet address family covered by one diagnostic dump.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InetSocketAddressFamily {
    Ipv4,
    Ipv6,
}

/// Transport protocol covered by the authoritative inventory.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InetSocketProtocol {
    Tcp,
    Udp,
}

/// Kernel-assigned INET_DIAG socket cookie.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InetDiagCookie {
    words: [u32; 2],
}

impl InetDiagCookie {
    #[must_use]
    pub const fn words(self) -> [u32; 2] {
        self.words
    }
}

/// One socket symlink observed in `/proc/<pid>/fd`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessSocketFd {
    fd: u32,
    inode: NonZeroU64,
}

impl ProcessSocketFd {
    #[must_use]
    pub const fn fd(self) -> u32 {
        self.fd
    }

    #[must_use]
    pub const fn inode(self) -> NonZeroU64 {
        self.inode
    }
}

/// One socket returned by a complete INET_DIAG dump.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InetSocketDiagnostic {
    dump_sequence: NonZeroU32,
    address_family: InetSocketAddressFamily,
    protocol: InetSocketProtocol,
    state: u8,
    local_address: SocketAddr,
    remote_address: SocketAddr,
    interface_index: u32,
    uid: u32,
    inode: u64,
    cookie: InetDiagCookie,
    mark: Option<u32>,
}

impl InetSocketDiagnostic {
    #[must_use]
    pub const fn dump_sequence(self) -> NonZeroU32 {
        self.dump_sequence
    }

    #[must_use]
    pub const fn address_family(self) -> InetSocketAddressFamily {
        self.address_family
    }

    #[must_use]
    pub const fn protocol(self) -> InetSocketProtocol {
        self.protocol
    }

    /// Raw Linux `sk_state`; connected UDP records are always state 1.
    #[must_use]
    pub const fn state(self) -> u8 {
        self.state
    }

    #[must_use]
    pub const fn local_address(self) -> SocketAddr {
        self.local_address
    }

    #[must_use]
    pub const fn remote_address(self) -> SocketAddr {
        self.remote_address
    }

    #[must_use]
    pub const fn interface_index(self) -> u32 {
        self.interface_index
    }

    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Socket inode reported by INET_DIAG. Some unowned TCP states use zero.
    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }

    #[must_use]
    pub const fn cookie(self) -> InetDiagCookie {
        self.cookie
    }

    /// Socket mark when the kernel disclosed `INET_DIAG_MARK` to this caller.
    #[must_use]
    pub const fn mark(self) -> Option<u32> {
        self.mark
    }
}

/// One completed diagnostic transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InetSocketDump {
    sequence: NonZeroU32,
    address_family: InetSocketAddressFamily,
    protocol: InetSocketProtocol,
    started_at: Instant,
    completed_at: Instant,
}

impl InetSocketDump {
    #[must_use]
    pub const fn sequence(self) -> NonZeroU32 {
        self.sequence
    }

    #[must_use]
    pub const fn address_family(self) -> InetSocketAddressFamily {
        self.address_family
    }

    #[must_use]
    pub const fn protocol(self) -> InetSocketProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn started_at(self) -> Instant {
        self.started_at
    }

    #[must_use]
    pub const fn completed_at(self) -> Instant {
        self.completed_at
    }
}

/// Complete, identity-bound procfs plus INET_DIAG inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessSocketDiagnostics {
    process: SocketDiagnosticsProcessIdentity,
    netlink_port_id: NonZeroU32,
    started_at: Instant,
    completed_at: Instant,
    socket_fds: Box<[ProcessSocketFd]>,
    dumps: Box<[InetSocketDump]>,
    sockets: Box<[InetSocketDiagnostic]>,
}

impl ProcessSocketDiagnostics {
    #[must_use]
    pub const fn process(&self) -> SocketDiagnosticsProcessIdentity {
        self.process
    }

    #[must_use]
    pub const fn netlink_port_id(&self) -> NonZeroU32 {
        self.netlink_port_id
    }

    #[must_use]
    pub const fn started_at(&self) -> Instant {
        self.started_at
    }

    #[must_use]
    pub const fn completed_at(&self) -> Instant {
        self.completed_at
    }

    #[must_use]
    pub fn socket_fds(&self) -> &[ProcessSocketFd] {
        &self.socket_fds
    }

    /// The four completed IPv4/IPv6 TCP/connected-UDP transactions.
    #[must_use]
    pub fn dumps(&self) -> &[InetSocketDump] {
        &self.dumps
    }

    #[must_use]
    pub fn sockets(&self) -> &[InetSocketDiagnostic] {
        &self.sockets
    }

    /// Success itself is the completeness proof; partial inventories are errors.
    #[must_use]
    pub const fn fd_scan_complete(&self) -> bool {
        true
    }

    /// Success itself is the completeness proof; all four dumps reached `NLMSG_DONE`.
    #[must_use]
    pub const fn diag_dumps_complete(&self) -> bool {
        true
    }

    /// Join one exact process FD to one exact INET_DIAG row.
    ///
    /// The join is authoritative only when the FD maps to one procfs socket
    /// inode and that inode, protocol, and directional tuple select exactly
    /// one row from the completed dumps.
    pub fn correlate(
        &self,
        fd: u32,
        protocol: InetSocketProtocol,
        local_address: SocketAddr,
        remote_address: SocketAddr,
    ) -> Result<CorrelatedProcessSocket, SocketCorrelationError> {
        let process_fd = self
            .socket_fds
            .iter()
            .copied()
            .find(|candidate| candidate.fd == fd)
            .ok_or(SocketCorrelationError::MissingProcessSocketFd { fd })?;
        let mut matches = self.sockets.iter().copied().filter(|diagnostic| {
            diagnostic.inode == process_fd.inode.get()
                && diagnostic.protocol == protocol
                && diagnostic.local_address == local_address
                && diagnostic.remote_address == remote_address
        });
        let diagnostic = matches
            .next()
            .ok_or(SocketCorrelationError::MissingDiagnostic { fd })?;
        if matches.next().is_some() {
            return Err(SocketCorrelationError::AmbiguousDiagnostic { fd });
        }
        Ok(CorrelatedProcessSocket {
            process_fd,
            diagnostic,
        })
    }
}

/// Exact procfs-FD to INET_DIAG join selected from one complete snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorrelatedProcessSocket {
    process_fd: ProcessSocketFd,
    diagnostic: InetSocketDiagnostic,
}

impl CorrelatedProcessSocket {
    #[must_use]
    pub const fn process_fd(self) -> ProcessSocketFd {
        self.process_fd
    }

    #[must_use]
    pub const fn diagnostic(self) -> InetSocketDiagnostic {
        self.diagnostic
    }
}

/// Failure to make an exact, unambiguous FD/inode/protocol/tuple join.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketCorrelationError {
    MissingProcessSocketFd { fd: u32 },
    MissingDiagnostic { fd: u32 },
    AmbiguousDiagnostic { fd: u32 },
}

impl fmt::Display for SocketCorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProcessSocketFd { fd } => {
                write!(
                    formatter,
                    "process FD {fd} is not a socket in this snapshot"
                )
            }
            Self::MissingDiagnostic { fd } => {
                write!(
                    formatter,
                    "process socket FD {fd} has no exact INET_DIAG match"
                )
            }
            Self::AmbiguousDiagnostic { fd } => write!(
                formatter,
                "process socket FD {fd} has multiple exact INET_DIAG matches"
            ),
        }
    }
}

impl Error for SocketCorrelationError {}

/// Stable high-level classification for collection failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketDiagnosticsErrorKind {
    UnsupportedPlatform,
    DeadlineExpired,
    Io,
    ProcessIdentityMismatch,
    ProcessSocketFdsChanged,
    MalformedProcStat,
    MalformedFdEntry,
    MalformedSocketSymlink,
    CollectionLimitExceeded,
    NetlinkProtocol,
}

/// Failure to produce a complete authoritative snapshot.
#[derive(Debug)]
pub enum SocketDiagnosticsError {
    UnsupportedPlatform(&'static str),
    DeadlineExpired,
    Io {
        operation: &'static str,
        path: Option<PathBuf>,
        source: std::io::Error,
    },
    ProcessIdentityMismatch {
        expected: SocketDiagnosticsProcessIdentity,
        observed: Option<SocketDiagnosticsProcessIdentity>,
    },
    ProcessSocketFdsChanged {
        process: SocketDiagnosticsProcessIdentity,
    },
    MalformedProcStat {
        path: PathBuf,
    },
    MalformedFdEntry {
        path: PathBuf,
    },
    MalformedSocketSymlink {
        path: PathBuf,
        target: OsString,
    },
    CollectionLimitExceeded {
        operation: &'static str,
        limit: usize,
    },
    NetlinkProtocol {
        operation: &'static str,
        detail: &'static str,
        offset: Option<usize>,
    },
}

impl SocketDiagnosticsError {
    #[must_use]
    pub const fn kind(&self) -> SocketDiagnosticsErrorKind {
        match self {
            Self::UnsupportedPlatform(_) => SocketDiagnosticsErrorKind::UnsupportedPlatform,
            Self::DeadlineExpired => SocketDiagnosticsErrorKind::DeadlineExpired,
            Self::Io { .. } => SocketDiagnosticsErrorKind::Io,
            Self::ProcessIdentityMismatch { .. } => {
                SocketDiagnosticsErrorKind::ProcessIdentityMismatch
            }
            Self::ProcessSocketFdsChanged { .. } => {
                SocketDiagnosticsErrorKind::ProcessSocketFdsChanged
            }
            Self::MalformedProcStat { .. } => SocketDiagnosticsErrorKind::MalformedProcStat,
            Self::MalformedFdEntry { .. } => SocketDiagnosticsErrorKind::MalformedFdEntry,
            Self::MalformedSocketSymlink { .. } => {
                SocketDiagnosticsErrorKind::MalformedSocketSymlink
            }
            Self::CollectionLimitExceeded { .. } => {
                SocketDiagnosticsErrorKind::CollectionLimitExceeded
            }
            Self::NetlinkProtocol { .. } => SocketDiagnosticsErrorKind::NetlinkProtocol,
        }
    }
}

impl fmt::Display for SocketDiagnosticsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform(platform) => {
                write!(
                    formatter,
                    "socket diagnostics are unsupported on {platform}"
                )
            }
            Self::DeadlineExpired => {
                formatter.write_str("socket-diagnostic collection deadline expired")
            }
            Self::Io {
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
            Self::ProcessIdentityMismatch { expected, observed } => {
                write!(
                    formatter,
                    "process identity changed while collecting socket diagnostics: expected pid={} start_ticks={}, observed={observed:?}",
                    expected.pid(),
                    expected.start_time_ticks()
                )
            }
            Self::ProcessSocketFdsChanged { process } => write!(
                formatter,
                "process socket FD mapping changed while collecting diagnostics: pid={} start_ticks={}",
                process.pid(),
                process.start_time_ticks()
            ),
            Self::MalformedProcStat { path } => {
                write!(formatter, "malformed proc stat {}", path.display())
            }
            Self::MalformedFdEntry { path } => {
                write!(formatter, "malformed proc FD entry {}", path.display())
            }
            Self::MalformedSocketSymlink { path, target } => write!(
                formatter,
                "malformed socket symlink {} -> {:?}",
                path.display(),
                target
            ),
            Self::CollectionLimitExceeded { operation, limit } => {
                write!(formatter, "{operation} exceeded the hard limit of {limit}")
            }
            Self::NetlinkProtocol {
                operation,
                detail,
                offset,
            } => {
                write!(formatter, "{operation}: {detail}")?;
                if let Some(offset) = offset {
                    write!(formatter, " at byte {offset}")?;
                }
                Ok(())
            }
        }
    }
}

impl Error for SocketDiagnosticsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Stateless system collector for process socket ownership evidence.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSocketDiagnosticsSource;

impl SystemSocketDiagnosticsSource {
    /// Collect a complete identity-bound snapshot before an exclusive deadline.
    pub fn collect_until(
        self,
        expected: SocketDiagnosticsProcessIdentity,
        deadline: Instant,
    ) -> Result<ProcessSocketDiagnostics, SocketDiagnosticsError> {
        collect_until(expected, deadline)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn collect_until(
    expected: SocketDiagnosticsProcessIdentity,
    deadline: Instant,
) -> Result<ProcessSocketDiagnostics, SocketDiagnosticsError> {
    implementation::collect_until(expected, deadline)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn collect_until(
    _expected: SocketDiagnosticsProcessIdentity,
    _deadline: Instant,
) -> Result<ProcessSocketDiagnostics, SocketDiagnosticsError> {
    Err(SocketDiagnosticsError::UnsupportedPlatform(
        std::env::consts::OS,
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation;

#[cfg(test)]
mod tests;
