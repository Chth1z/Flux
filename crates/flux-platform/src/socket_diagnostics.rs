//! Authoritative process-FD and INET_DIAG socket inventory.
//!
//! A successful snapshot is deliberately all-or-nothing: the expected procfs
//! process identity must match before and after the FD scan plus all four
//! IPv4/IPv6 TCP/connected-UDP dumps, and every netlink dump must reach an
//! unambiguous `NLMSG_DONE` terminator.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::time::Instant;

const TARGETED_LISTENER_DUMP_COUNT: usize = 2;
const TCP_CLOSE: u8 = 7;
const TCP_LISTEN: u8 = 10;

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
    transparent: Option<bool>,
    ipv6_only: Option<bool>,
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

    /// Whether the kernel reported `IP_TRANSPARENT` for this socket.
    ///
    /// The value is optional because older or restricted diagnostic providers
    /// may omit `INET_DIAG_SOCKOPT`; listener correlation rejects omission.
    #[must_use]
    pub const fn transparent(self) -> Option<bool> {
        self.transparent
    }

    /// IPv6-only state when the kernel reported `INET_DIAG_SKV6ONLY`.
    #[must_use]
    pub const fn ipv6_only(self) -> Option<bool> {
        self.ipv6_only
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
    listener_port: Option<NonZeroU16>,
    listener_dumps: Box<[InetSocketDump]>,
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

    /// Targeted listener transactions, when this snapshot was collected with
    /// an explicit listener port. There is one IPv4 and one IPv6 UDP dump.
    #[must_use]
    pub fn listener_dumps(&self) -> &[InetSocketDump] {
        &self.listener_dumps
    }

    /// Source port selected by the targeted listener transactions.
    #[must_use]
    pub const fn listener_port(&self) -> Option<NonZeroU16> {
        self.listener_port
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

    /// Whether this snapshot contains the exact completed broad transaction set.
    #[must_use]
    pub fn diag_dumps_complete(&self) -> bool {
        let [ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp] = self.dumps.as_ref() else {
            return false;
        };
        [
            (
                ipv4_tcp,
                InetSocketAddressFamily::Ipv4,
                InetSocketProtocol::Tcp,
            ),
            (
                ipv4_udp,
                InetSocketAddressFamily::Ipv4,
                InetSocketProtocol::Udp,
            ),
            (
                ipv6_tcp,
                InetSocketAddressFamily::Ipv6,
                InetSocketProtocol::Tcp,
            ),
            (
                ipv6_udp,
                InetSocketAddressFamily::Ipv6,
                InetSocketProtocol::Udp,
            ),
        ]
        .into_iter()
        .all(|(dump, family, protocol)| {
            dump.address_family == family
                && dump.protocol == protocol
                && dump.started_at >= self.started_at
                && dump.completed_at >= dump.started_at
                && dump.completed_at <= self.completed_at
        }) && dump_sequences_are_contiguous(&self.dumps)
    }

    /// Whether this snapshot contains the exact completed targeted-listener
    /// transaction set.
    ///
    /// Ordinary process snapshots return `false`: they never requested these
    /// dumps and cannot be promoted into listener evidence.
    #[must_use]
    pub fn listener_diag_dumps_complete(&self) -> bool {
        let [ipv4, ipv6] = self.listener_dumps.as_ref() else {
            return false;
        };
        self.diag_dumps_complete()
            && self.listener_port.is_some()
            && self.listener_dumps.len() == TARGETED_LISTENER_DUMP_COUNT
            && ipv4.address_family == InetSocketAddressFamily::Ipv4
            && ipv4.protocol == InetSocketProtocol::Udp
            && ipv6.address_family == InetSocketAddressFamily::Ipv6
            && ipv6.protocol == InetSocketProtocol::Udp
            && dump_sequences_are_contiguous(&self.dumps)
            && dump_sequences_are_contiguous(&self.listener_dumps)
            && dump_sequence_sets_are_disjoint(&self.dumps, &self.listener_dumps)
            && dump_sequence_sets_are_contiguous(&self.dumps, &self.listener_dumps)
            && [ipv4, ipv6].into_iter().all(|dump| {
                dump.started_at >= self.started_at
                    && dump.completed_at >= dump.started_at
                    && dump.completed_at <= self.completed_at
            })
    }

    /// Sequence carrying one listener role in the exact complete transaction.
    ///
    /// TCP listener rows come from the broad family dump; UDP listener rows
    /// come from the source-port-targeted dump. Incomplete or ambiguous dump
    /// provenance is never projected as a role sequence.
    #[must_use]
    pub fn listener_role_sequence(
        &self,
        address_family: InetSocketAddressFamily,
        protocol: InetSocketProtocol,
    ) -> Option<NonZeroU32> {
        if !self.listener_diag_dumps_complete() {
            return None;
        }
        let dumps = match protocol {
            InetSocketProtocol::Tcp => self.dumps.as_ref(),
            InetSocketProtocol::Udp => self.listener_dumps.as_ref(),
        };
        let mut matches = dumps
            .iter()
            .filter(|dump| dump.address_family == address_family && dump.protocol == protocol);
        let sequence = matches.next()?.sequence;
        matches.next().is_none().then_some(sequence)
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
                && self.diag_dumps_complete()
                && has_exact_dump(&self.dumps, *diagnostic)
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

    /// Join one exact transparent wildcard listener to one exact process FD.
    ///
    /// TCP listeners come from the all-state TCP dumps. UDP listeners come
    /// only from the targeted `TCP_CLOSE` listener dumps. The method is
    /// intentionally strict: the role tuple, state, transparency, IPv6-only
    /// contract, diagnostic row, and process FD/inode join must each be
    /// unique.
    pub fn correlate_transparent_listener(
        &self,
        address_family: InetSocketAddressFamily,
        protocol: InetSocketProtocol,
        port: NonZeroU16,
    ) -> Result<CorrelatedProcessSocket, ListenerSocketCorrelationError> {
        let wildcard = match address_family {
            InetSocketAddressFamily::Ipv4 => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port.get())
            }
            InetSocketAddressFamily::Ipv6 => {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port.get())
            }
        };
        let zero_remote = match address_family {
            InetSocketAddressFamily::Ipv4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            InetSocketAddressFamily::Ipv6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let expected_state = match protocol {
            InetSocketProtocol::Tcp => TCP_LISTEN,
            InetSocketProtocol::Udp => TCP_CLOSE,
        };
        let mut diagnostics = self.sockets.iter().copied().filter(|diagnostic| {
            diagnostic.address_family == address_family
                && diagnostic.protocol == protocol
                && diagnostic.state == expected_state
                && diagnostic.local_address == wildcard
                && diagnostic.remote_address == zero_remote
                && diagnostic.transparent == Some(true)
                && match address_family {
                    InetSocketAddressFamily::Ipv4 => diagnostic.ipv6_only.is_none(),
                    InetSocketAddressFamily::Ipv6 => diagnostic.ipv6_only == Some(true),
                }
                && diagnostic.inode != 0
                && diagnostic.cookie.words() != [u32::MAX; 2]
                && match protocol {
                    InetSocketProtocol::Tcp => {
                        self.diag_dumps_complete() && has_exact_dump(&self.dumps, *diagnostic)
                    }
                    InetSocketProtocol::Udp => {
                        self.listener_port == Some(port)
                            && self.listener_diag_dumps_complete()
                            && has_exact_dump(&self.listener_dumps, *diagnostic)
                    }
                }
        });
        let diagnostic =
            diagnostics
                .next()
                .ok_or(ListenerSocketCorrelationError::MissingDiagnostic {
                    address_family,
                    protocol,
                    port,
                })?;
        if diagnostics.next().is_some() {
            return Err(ListenerSocketCorrelationError::AmbiguousDiagnostic {
                address_family,
                protocol,
                port,
            });
        }

        let inode = NonZeroU64::new(diagnostic.inode).ok_or(
            ListenerSocketCorrelationError::MissingDiagnostic {
                address_family,
                protocol,
                port,
            },
        )?;
        let mut process_fds = self
            .socket_fds
            .iter()
            .copied()
            .filter(|process_fd| process_fd.inode == inode);
        let process_fd = process_fds
            .next()
            .ok_or(ListenerSocketCorrelationError::MissingProcessSocketFd { inode: inode.get() })?;
        if process_fds.next().is_some() {
            return Err(ListenerSocketCorrelationError::AmbiguousProcessSocketFd {
                inode: inode.get(),
            });
        }
        Ok(CorrelatedProcessSocket {
            process_fd,
            diagnostic,
        })
    }
}

fn dump_sequences_are_contiguous(dumps: &[InetSocketDump]) -> bool {
    !dumps.is_empty()
        && dumps
            .windows(2)
            .all(|pair| pair[0].sequence.get().checked_add(1) == Some(pair[1].sequence.get()))
}

fn dump_sequence_sets_are_disjoint(left: &[InetSocketDump], right: &[InetSocketDump]) -> bool {
    left.iter().all(|left_dump| {
        right
            .iter()
            .all(|right_dump| left_dump.sequence != right_dump.sequence)
    })
}

fn dump_sequence_sets_are_contiguous(left: &[InetSocketDump], right: &[InetSocketDump]) -> bool {
    left.last()
        .and_then(|dump| dump.sequence.get().checked_add(1))
        == right.first().map(|dump| dump.sequence.get())
}

fn has_exact_dump(dumps: &[InetSocketDump], diagnostic: InetSocketDiagnostic) -> bool {
    let mut matching = dumps.iter().filter(|dump| {
        dump.sequence == diagnostic.dump_sequence
            && dump.address_family == diagnostic.address_family
            && dump.protocol == diagnostic.protocol
    });
    matching.next().is_some() && matching.next().is_none()
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

/// Failure to select one exact transparent listener and one process-FD join.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerSocketCorrelationError {
    MissingDiagnostic {
        address_family: InetSocketAddressFamily,
        protocol: InetSocketProtocol,
        port: NonZeroU16,
    },
    AmbiguousDiagnostic {
        address_family: InetSocketAddressFamily,
        protocol: InetSocketProtocol,
        port: NonZeroU16,
    },
    MissingProcessSocketFd {
        inode: u64,
    },
    AmbiguousProcessSocketFd {
        inode: u64,
    },
}

impl fmt::Display for ListenerSocketCorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDiagnostic {
                address_family,
                protocol,
                port,
            } => write!(
                formatter,
                "no exact transparent {address_family:?}/{protocol:?} listener on port {port}"
            ),
            Self::AmbiguousDiagnostic {
                address_family,
                protocol,
                port,
            } => write!(
                formatter,
                "multiple transparent {address_family:?}/{protocol:?} listeners on port {port}"
            ),
            Self::MissingProcessSocketFd { inode } => {
                write!(
                    formatter,
                    "listener inode {inode} is absent from process FDs"
                )
            }
            Self::AmbiguousProcessSocketFd { inode } => write!(
                formatter,
                "listener inode {inode} is referenced by multiple process FDs"
            ),
        }
    }
}

impl Error for ListenerSocketCorrelationError {}

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
            Self::DeadlineExpired => formatter.write_str("socket-diagnostic deadline expired"),
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

/// System entry point for process socket ownership evidence.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSocketDiagnosticsSource;

impl SystemSocketDiagnosticsSource {
    /// Open and bind a reusable diagnostic session before an exclusive deadline.
    ///
    /// The returned session exposes its kernel-assigned netlink port ID before
    /// any process collection, allowing callers to bind that real observer
    /// authority into an immutable canary request.
    pub fn open_until(
        self,
        deadline: Instant,
    ) -> Result<SystemSocketDiagnosticsSession, SocketDiagnosticsError> {
        open_until(deadline)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct SystemSocketDiagnosticsSession {
    inner: implementation::SystemSocketDiagnosticsSession,
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub struct SystemSocketDiagnosticsSession {
    _unsupported: std::convert::Infallible,
}

impl SystemSocketDiagnosticsSession {
    /// Kernel-assigned port ID of the already-bound NETLINK_SOCK_DIAG socket.
    ///
    /// The number is network-namespace-scoped and may be reused after close;
    /// authority therefore requires retaining this exact live session.
    #[must_use]
    pub fn netlink_port_id(&self) -> NonZeroU32 {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            self.inner.netlink_port_id()
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            match self._unsupported {}
        }
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "android")))]
    fn set_deadline_for_test(&mut self, deadline: Instant) {
        self.inner.set_deadline_for_test(deadline);
    }

    /// Collect one complete process snapshot through this prebound session.
    ///
    /// Ownership serializes transactions and preserves monotonically
    /// increasing, nonzero netlink sequences. Success returns the same clean
    /// session for another collection; every error consumes and drops it, so
    /// unread late datagrams can never satisfy a later transaction. The
    /// supplied deadline may shorten but can never extend the exclusive
    /// deadline fixed when the session opened.
    pub fn collect_process_until(
        self,
        expected: SocketDiagnosticsProcessIdentity,
        deadline: Instant,
    ) -> Result<(Self, ProcessSocketDiagnostics), SocketDiagnosticsError> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let (inner, snapshot) = self.inner.collect_process_until(expected, deadline)?;
            Ok((Self { inner }, snapshot))
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = (expected, deadline);
            match self._unsupported {}
        }
    }

    /// Collect a complete process snapshot plus targeted UDP listener dumps,
    /// retaining this exact prebound session on success.
    pub fn collect_process_and_listeners_until(
        self,
        expected: SocketDiagnosticsProcessIdentity,
        listener_port: NonZeroU16,
        deadline: Instant,
    ) -> Result<(Self, ProcessSocketDiagnostics), SocketDiagnosticsError> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let (inner, snapshot) = self.inner.collect_process_and_listeners_until(
                expected,
                listener_port,
                deadline,
            )?;
            Ok((Self { inner }, snapshot))
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = (expected, listener_port, deadline);
            match self._unsupported {}
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_until(deadline: Instant) -> Result<SystemSocketDiagnosticsSession, SocketDiagnosticsError> {
    Ok(SystemSocketDiagnosticsSession {
        inner: implementation::SystemSocketDiagnosticsSession::open_until(deadline)?,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn open_until(
    _deadline: Instant,
) -> Result<SystemSocketDiagnosticsSession, SocketDiagnosticsError> {
    Err(SocketDiagnosticsError::UnsupportedPlatform(
        std::env::consts::OS,
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation;

#[cfg(test)]
mod tests;
