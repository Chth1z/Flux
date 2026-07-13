use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU32, NonZeroU64};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Instant;

use crate::netlink::{
    NETLINK_HEADER_LENGTH, NLM_F_DUMP_INTR, NLMSG_DONE, NLMSG_ERROR, NLMSG_OVERRUN,
    NetlinkAttributeIter, NetlinkMessageIter, validate_done_payload,
};

use super::{
    InetDiagCookie, InetSocketAddressFamily, InetSocketDiagnostic, InetSocketDump,
    InetSocketProtocol, ProcessSocketDiagnostics, ProcessSocketFd, SocketDiagnosticsError,
    SocketDiagnosticsProcessIdentity,
};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_MULTI: u16 = 0x02;
const NLM_F_DUMP: u16 = 0x300;
const INET_DIAG_MESSAGE_LENGTH: usize = 72;
const INET_DIAG_REQUEST_LENGTH: usize = NETLINK_HEADER_LENGTH + 56;
const INET_DIAG_PROTOCOL: u16 = 10;
const INET_DIAG_MARK: u16 = 15;
const TCP_ESTABLISHED: u8 = 1;
const SOCKET_DIAG_RECEIVE_BUFFER_BYTES: i32 = 4 * 1024 * 1024;
const MAX_SOCKET_DIAG_DATAGRAM_BYTES: usize = 1024 * 1024;
const MAX_SOCKET_DIAG_DUMP_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOCKET_DIAG_DUMP_MESSAGES: usize = 262_144;
const MAX_SOCKET_DIAG_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const MAX_SOCKET_DIAG_SNAPSHOT_ROWS: usize = 262_144;
const MAX_PROCESS_FD_ENTRIES: usize = 262_144;
const MAX_PROCESS_SOCKET_FDS: usize = 262_144;
const SOCKET_DIAG_DUMP_COUNT: usize = 4;
const SOCKADDR_NL_LENGTH: libc::socklen_t = 12;

const _: () = assert!(SOCKADDR_NL_LENGTH as usize == mem::size_of::<libc::sockaddr_nl>());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DumpSpec {
    pub(super) address_family: InetSocketAddressFamily,
    pub(super) protocol: InetSocketProtocol,
}

impl DumpSpec {
    const ALL: [Self; 4] = [
        Self {
            address_family: InetSocketAddressFamily::Ipv4,
            protocol: InetSocketProtocol::Tcp,
        },
        Self {
            address_family: InetSocketAddressFamily::Ipv4,
            protocol: InetSocketProtocol::Udp,
        },
        Self {
            address_family: InetSocketAddressFamily::Ipv6,
            protocol: InetSocketProtocol::Tcp,
        },
        Self {
            address_family: InetSocketAddressFamily::Ipv6,
            protocol: InetSocketProtocol::Udp,
        },
    ];

    const fn family_number(self) -> u8 {
        match self.address_family {
            InetSocketAddressFamily::Ipv4 => libc::AF_INET as u8,
            InetSocketAddressFamily::Ipv6 => libc::AF_INET6 as u8,
        }
    }

    const fn protocol_number(self) -> u8 {
        match self.protocol {
            InetSocketProtocol::Tcp => libc::IPPROTO_TCP as u8,
            InetSocketProtocol::Udp => libc::IPPROTO_UDP as u8,
        }
    }

    const fn states(self) -> u32 {
        match self.protocol {
            InetSocketProtocol::Tcp => u32::MAX,
            InetSocketProtocol::Udp => 1_u32 << TCP_ESTABLISHED,
        }
    }
}

const _: () = assert!(DumpSpec::ALL.len() == SOCKET_DIAG_DUMP_COUNT);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(super) struct RawNetlinkSocketAddress {
    pub(super) family: u16,
    pub(super) padding: u16,
    pub(super) port_id: u32,
    pub(super) groups: u32,
}

const _: () =
    assert!(mem::size_of::<RawNetlinkSocketAddress>() == mem::size_of::<libc::sockaddr_nl>());
const _: () =
    assert!(mem::align_of::<RawNetlinkSocketAddress>() == mem::align_of::<libc::sockaddr_nl>());

pub(super) struct SystemSocketDiagnosticsSession {
    socket: SocketDiagSocket,
    sequences: DumpSequenceState,
    deadline: Instant,
}

impl SystemSocketDiagnosticsSession {
    pub(super) fn open_until(deadline: Instant) -> Result<Self, SocketDiagnosticsError> {
        Ok(Self {
            socket: SocketDiagSocket::open(deadline)?,
            sequences: DumpSequenceState::new(),
            deadline,
        })
    }

    pub(super) const fn netlink_port_id(&self) -> NonZeroU32 {
        self.socket.port_id
    }

    #[cfg(test)]
    pub(super) fn set_deadline_for_test(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }

    pub(super) fn collect_process_until(
        mut self,
        expected: SocketDiagnosticsProcessIdentity,
        deadline: Instant,
    ) -> Result<(Self, ProcessSocketDiagnostics), SocketDiagnosticsError> {
        let deadline = bounded_session_deadline(self.deadline, deadline);
        let started_at = deadline_checkpoint(deadline)?;
        verify_process_identity(expected, deadline)?;
        let socket_fds = scan_socket_fds(expected.pid(), deadline)?;
        let sequences = self.sequences.reserve_snapshot()?;
        let mut sockets = Vec::new();
        let mut dumps = Vec::with_capacity(SOCKET_DIAG_DUMP_COUNT);
        let mut snapshot_bytes = 0_usize;

        for (spec, sequence) in DumpSpec::ALL.into_iter().zip(sequences) {
            let mut decoded = self.socket.dump(spec, sequence, deadline)?;
            snapshot_bytes = snapshot_bytes
                .checked_add(decoded.received_bytes)
                .filter(|bytes| *bytes <= MAX_SOCKET_DIAG_SNAPSHOT_BYTES)
                .ok_or_else(|| {
                    protocol_error(
                        "collect socket-diagnostic snapshot",
                        "snapshot byte bound exceeded",
                        None,
                    )
                })?;
            if sockets.len().saturating_add(decoded.sockets.len()) > MAX_SOCKET_DIAG_SNAPSHOT_ROWS {
                return Err(protocol_error(
                    "collect socket-diagnostic snapshot",
                    "snapshot socket-row bound exceeded",
                    None,
                ));
            }
            sockets.append(&mut decoded.sockets);
            dumps.push(InetSocketDump {
                sequence,
                address_family: spec.address_family,
                protocol: spec.protocol,
                started_at: decoded.started_at,
                completed_at: decoded.completed_at,
            });
        }

        verify_process_identity(expected, deadline)?;
        let final_socket_fds = scan_socket_fds(expected.pid(), deadline)?;
        verify_process_identity(expected, deadline)?;
        require_stable_socket_fds(expected, &socket_fds, &final_socket_fds)?;
        let completed_at = deadline_checkpoint(deadline)?;
        let snapshot = ProcessSocketDiagnostics {
            process: expected,
            netlink_port_id: self.socket.port_id,
            started_at,
            completed_at,
            socket_fds: socket_fds.into_boxed_slice(),
            dumps: dumps.into_boxed_slice(),
            sockets: sockets.into_boxed_slice(),
        };
        Ok((self, snapshot))
    }
}

pub(super) fn bounded_session_deadline(hard: Instant, requested: Instant) -> Instant {
    std::cmp::min(hard, requested)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DumpSequenceState {
    next: Option<NonZeroU32>,
}

impl DumpSequenceState {
    const fn new() -> Self {
        Self {
            next: NonZeroU32::new(1),
        }
    }

    #[cfg(test)]
    pub(super) const fn starting_at(next: NonZeroU32) -> Self {
        Self { next: Some(next) }
    }

    pub(super) fn reserve_snapshot(
        &mut self,
    ) -> Result<[NonZeroU32; SOCKET_DIAG_DUMP_COUNT], SocketDiagnosticsError> {
        let Some(first) = self.next else {
            return Err(sequence_limit_error());
        };
        let first = first.get();
        let Some(last) = first.checked_add(
            u32::try_from(SOCKET_DIAG_DUMP_COUNT - 1)
                .expect("socket diagnostic dump count fits u32"),
        ) else {
            self.next = None;
            return Err(sequence_limit_error());
        };
        self.next = last.checked_add(1).and_then(NonZeroU32::new);
        Ok(std::array::from_fn(|index| {
            let offset = u32::try_from(index).expect("dump sequence index fits u32");
            NonZeroU32::new(first + offset).expect("reserved sequence is nonzero")
        }))
    }
}

fn sequence_limit_error() -> SocketDiagnosticsError {
    SocketDiagnosticsError::CollectionLimitExceeded {
        operation: "reserve socket-diagnostic session sequences",
        limit: u32::MAX as usize,
    }
}

fn verify_process_identity(
    expected: SocketDiagnosticsProcessIdentity,
    deadline: Instant,
) -> Result<(), SocketDiagnosticsError> {
    deadline_checkpoint(deadline)?;
    let path = proc_stat_path(expected.pid());
    let contents = match fs::read(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(SocketDiagnosticsError::ProcessIdentityMismatch {
                expected,
                observed: None,
            });
        }
        Err(source) => {
            return Err(SocketDiagnosticsError::Io {
                operation: "read process identity",
                path: Some(path),
                source,
            });
        }
    };
    deadline_checkpoint(deadline)?;
    let observed = parse_proc_stat(&contents)
        .ok_or_else(|| SocketDiagnosticsError::MalformedProcStat { path: path.clone() })?;
    if observed != expected {
        return Err(SocketDiagnosticsError::ProcessIdentityMismatch {
            expected,
            observed: Some(observed),
        });
    }
    deadline_checkpoint(deadline)?;
    Ok(())
}

fn proc_stat_path(pid: NonZeroU32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/stat"))
}

pub(super) fn parse_proc_stat(contents: &[u8]) -> Option<SocketDiagnosticsProcessIdentity> {
    let command_start = contents.windows(2).position(|window| window == b" (")?;
    let pid = parse_canonical_u32(&contents[..command_start])?;
    let pid = NonZeroU32::new(pid)?;
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
    Some(SocketDiagnosticsProcessIdentity::new(pid, start_time_ticks))
}

fn scan_socket_fds(
    pid: NonZeroU32,
    deadline: Instant,
) -> Result<Vec<ProcessSocketFd>, SocketDiagnosticsError> {
    deadline_checkpoint(deadline)?;
    let directory = PathBuf::from(format!("/proc/{pid}/fd"));
    let entries = fs::read_dir(&directory).map_err(|source| SocketDiagnosticsError::Io {
        operation: "read process FD directory",
        path: Some(directory.clone()),
        source,
    })?;
    let mut seen_fds = BTreeSet::new();
    let mut sockets = Vec::new();
    let mut entry_count = 0_usize;
    for entry in entries {
        deadline_checkpoint(deadline)?;
        entry_count =
            entry_count
                .checked_add(1)
                .ok_or(SocketDiagnosticsError::CollectionLimitExceeded {
                    operation: "scan process FD entries",
                    limit: MAX_PROCESS_FD_ENTRIES,
                })?;
        if entry_count > MAX_PROCESS_FD_ENTRIES {
            return Err(SocketDiagnosticsError::CollectionLimitExceeded {
                operation: "scan process FD entries",
                limit: MAX_PROCESS_FD_ENTRIES,
            });
        }
        let entry = entry.map_err(|source| SocketDiagnosticsError::Io {
            operation: "read process FD entry",
            path: Some(directory.clone()),
            source,
        })?;
        let path = entry.path();
        let fd = parse_fd_name(&entry.file_name())
            .ok_or_else(|| SocketDiagnosticsError::MalformedFdEntry { path: path.clone() })?;
        if !seen_fds.insert(fd) {
            return Err(SocketDiagnosticsError::MalformedFdEntry { path });
        }
        let target = fs::read_link(&path).map_err(|source| SocketDiagnosticsError::Io {
            operation: "read process FD symlink",
            path: Some(path.clone()),
            source,
        })?;
        deadline_checkpoint(deadline)?;
        match parse_socket_symlink_target(target.as_os_str()) {
            Ok(Some(inode)) => {
                if sockets.len() >= MAX_PROCESS_SOCKET_FDS {
                    return Err(SocketDiagnosticsError::CollectionLimitExceeded {
                        operation: "retain process socket FDs",
                        limit: MAX_PROCESS_SOCKET_FDS,
                    });
                }
                sockets.push(ProcessSocketFd { fd, inode });
            }
            Ok(None) => {}
            Err(()) => {
                return Err(SocketDiagnosticsError::MalformedSocketSymlink {
                    path,
                    target: target.into_os_string(),
                });
            }
        }
    }
    sockets.sort_unstable_by_key(|socket| socket.fd);
    deadline_checkpoint(deadline)?;
    Ok(sockets)
}

pub(super) fn require_stable_socket_fds(
    process: SocketDiagnosticsProcessIdentity,
    initial: &[ProcessSocketFd],
    final_snapshot: &[ProcessSocketFd],
) -> Result<(), SocketDiagnosticsError> {
    if initial != final_snapshot {
        return Err(SocketDiagnosticsError::ProcessSocketFdsChanged { process });
    }
    Ok(())
}

pub(super) fn parse_fd_name(name: &OsStr) -> Option<u32> {
    parse_canonical_u32(name.as_bytes()).filter(|fd| *fd <= i32::MAX as u32)
}

pub(super) fn parse_socket_symlink_target(target: &OsStr) -> Result<Option<NonZeroU64>, ()> {
    let bytes = target.as_bytes();
    if !bytes.starts_with(b"socket:") {
        return Ok(None);
    }
    let inode = bytes
        .strip_prefix(b"socket:[")
        .and_then(|value| value.strip_suffix(b"]"))
        .and_then(parse_canonical_u64)
        .and_then(NonZeroU64::new)
        .ok_or(())?;
    Ok(Some(inode))
}

fn parse_canonical_u32(bytes: &[u8]) -> Option<u32> {
    let value = parse_canonical_u64(bytes)?;
    u32::try_from(value).ok()
}

fn parse_canonical_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') {
        return None;
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        let digit = byte.checked_sub(b'0').filter(|digit| *digit <= 9)?;
        value.checked_mul(10)?.checked_add(u64::from(digit))
    })
}

struct SocketDiagSocket {
    fd: OwnedFd,
    port_id: NonZeroU32,
}

impl SocketDiagSocket {
    fn open(deadline: Instant) -> Result<Self, SocketDiagnosticsError> {
        deadline_checkpoint(deadline)?;
        // SAFETY: `socket` has no pointer arguments. On success it returns a
        // new descriptor; CLOEXEC and nonblocking mode are set atomically.
        let descriptor = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_SOCK_DIAG,
            )
        };
        if descriptor < 0 {
            return Err(last_io_error("create socket-diagnostic netlink socket"));
        }
        // SAFETY: the successful socket call returned a newly owned FD.
        let fd = unsafe { OwnedFd::from_raw_fd(descriptor) };
        deadline_checkpoint(deadline)?;
        set_receive_buffer(fd.as_raw_fd())?;
        deadline_checkpoint(deadline)?;

        let local = RawNetlinkSocketAddress {
            family: libc::AF_NETLINK as u16,
            ..RawNetlinkSocketAddress::default()
        };
        // SAFETY: `local` has the sockaddr_nl ABI and remains readable for its
        // exact size while the descriptor owns a netlink socket.
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::from_ref(&local).cast::<libc::sockaddr>(),
                SOCKADDR_NL_LENGTH,
            )
        } != 0
        {
            return Err(last_io_error("bind socket-diagnostic netlink socket"));
        }
        deadline_checkpoint(deadline)?;

        let mut observed = RawNetlinkSocketAddress::default();
        let mut observed_length = SOCKADDR_NL_LENGTH;
        // SAFETY: both output pointers refer to initialized writable storage
        // and the descriptor owns a bound netlink socket.
        if unsafe {
            libc::getsockname(
                fd.as_raw_fd(),
                std::ptr::from_mut(&mut observed).cast::<libc::sockaddr>(),
                &raw mut observed_length,
            )
        } != 0
        {
            return Err(last_io_error(
                "read socket-diagnostic netlink local address",
            ));
        }
        deadline_checkpoint(deadline)?;
        if observed_length != SOCKADDR_NL_LENGTH
            || observed.family != libc::AF_NETLINK as u16
            || observed.padding != 0
            || observed.groups != 0
        {
            return Err(protocol_error(
                "verify socket-diagnostic netlink local address",
                "unexpected local netlink address",
                None,
            ));
        }
        let port_id = NonZeroU32::new(observed.port_id).ok_or_else(|| {
            protocol_error(
                "verify socket-diagnostic netlink local address",
                "kernel assigned a zero port ID",
                None,
            )
        })?;
        Ok(Self { fd, port_id })
    }

    fn dump(
        &self,
        spec: DumpSpec,
        sequence: NonZeroU32,
        deadline: Instant,
    ) -> Result<CompletedDump, SocketDiagnosticsError> {
        let started_at = deadline_checkpoint(deadline)?;
        let request = encode_dump_request(spec, sequence);
        self.send_request(&request, deadline)?;
        let mut decoder = DumpDecoder::new(spec, sequence, self.port_id);
        while !decoder.is_complete() {
            let datagram = receive_datagram(self.fd.as_raw_fd(), deadline)?;
            decoder.decode_datagram(&datagram)?;
        }
        let completed_at = deadline_checkpoint(deadline)?;
        decoder.finish(started_at, completed_at)
    }

    fn send_request(
        &self,
        request: &[u8],
        deadline: Instant,
    ) -> Result<(), SocketDiagnosticsError> {
        deadline_checkpoint(deadline)?;
        let kernel = RawNetlinkSocketAddress {
            family: libc::AF_NETLINK as u16,
            ..RawNetlinkSocketAddress::default()
        };
        let sent = loop {
            // SAFETY: request is readable for its complete length, `kernel`
            // has the sockaddr_nl ABI, and the owned descriptor stays valid.
            let result = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    request.as_ptr().cast::<libc::c_void>(),
                    request.len(),
                    libc::MSG_DONTWAIT,
                    std::ptr::from_ref(&kernel).cast::<libc::sockaddr>(),
                    SOCKADDR_NL_LENGTH,
                )
            };
            if result >= 0 {
                break result;
            }
            let source = io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::EINTR) {
                return Err(SocketDiagnosticsError::Io {
                    operation: "send socket-diagnostic dump request",
                    path: None,
                    source,
                });
            }
            deadline_checkpoint(deadline)?;
        };
        let actual = usize::try_from(sent).map_err(|_| {
            protocol_error(
                "send socket-diagnostic dump request",
                "negative or overflowing write length",
                None,
            )
        })?;
        if actual != request.len() {
            return Err(protocol_error(
                "send socket-diagnostic dump request",
                "short netlink datagram write",
                None,
            ));
        }
        deadline_checkpoint(deadline)?;
        Ok(())
    }
}

fn set_receive_buffer(fd: i32) -> Result<(), SocketDiagnosticsError> {
    let value = SOCKET_DIAG_RECEIVE_BUFFER_BYTES;
    // SAFETY: `value` is readable for one i32 and `fd` owns a socket.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::from_ref(&value).cast::<libc::c_void>(),
            mem::size_of_val(&value) as libc::socklen_t,
        )
    } != 0
    {
        return Err(last_io_error(
            "set socket-diagnostic netlink receive buffer",
        ));
    }
    Ok(())
}

fn receive_datagram(fd: i32, deadline: Instant) -> Result<Vec<u8>, SocketDiagnosticsError> {
    wait_readable(fd, deadline)?;
    let expected_length = peek_datagram_length(fd, deadline)?;
    if expected_length == 0 || expected_length > MAX_SOCKET_DIAG_DATAGRAM_BYTES {
        return Err(protocol_error(
            "receive socket-diagnostic dump datagram",
            "invalid or excessive netlink datagram length",
            None,
        ));
    }
    let mut bytes = vec![0_u8; expected_length];
    let mut sender = RawNetlinkSocketAddress::default();
    let mut iovec = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: bytes.len(),
    };
    let mut header = receive_header(&mut sender, &mut iovec);
    let received = retry_recvmsg(
        fd,
        &mut header,
        libc::MSG_TRUNC | libc::MSG_DONTWAIT,
        deadline,
    )?;
    validate_kernel_sender(sender, header.msg_namelen)?;
    if header.msg_flags != 0 || received != expected_length {
        return Err(protocol_error(
            "receive socket-diagnostic dump datagram",
            "truncated or length-mismatched netlink datagram",
            None,
        ));
    }
    Ok(bytes)
}

fn peek_datagram_length(fd: i32, deadline: Instant) -> Result<usize, SocketDiagnosticsError> {
    let mut byte = 0_u8;
    let mut sender = RawNetlinkSocketAddress::default();
    let mut iovec = libc::iovec {
        iov_base: std::ptr::from_mut(&mut byte).cast::<libc::c_void>(),
        iov_len: 1,
    };
    let mut header = receive_header(&mut sender, &mut iovec);
    let length = retry_recvmsg(
        fd,
        &mut header,
        libc::MSG_PEEK | libc::MSG_TRUNC | libc::MSG_DONTWAIT,
        deadline,
    )?;
    validate_kernel_sender(sender, header.msg_namelen)?;
    Ok(length)
}

fn receive_header<'a>(
    sender: &'a mut RawNetlinkSocketAddress,
    iovec: &'a mut libc::iovec,
) -> libc::msghdr {
    libc::msghdr {
        msg_name: std::ptr::from_mut(sender).cast::<libc::c_void>(),
        msg_namelen: SOCKADDR_NL_LENGTH,
        msg_iov: std::ptr::from_mut(iovec),
        msg_iovlen: 1,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    }
}

fn retry_recvmsg(
    fd: i32,
    header: &mut libc::msghdr,
    flags: i32,
    deadline: Instant,
) -> Result<usize, SocketDiagnosticsError> {
    loop {
        if Instant::now() >= deadline {
            return Err(dump_timeout_error());
        }
        // SAFETY: `header` and its single iovec point to writable storage for
        // the duration of this call, and `fd` owns a netlink socket.
        let result = unsafe { libc::recvmsg(fd, header, flags) };
        if result >= 0 {
            return usize::try_from(result).map_err(|_| {
                protocol_error(
                    "receive socket-diagnostic dump datagram",
                    "overflowing receive length",
                    None,
                )
            });
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::EINTR) {
            return Err(SocketDiagnosticsError::Io {
                operation: "receive socket-diagnostic dump datagram",
                path: None,
                source,
            });
        }
    }
}

fn wait_readable(fd: i32, deadline: Instant) -> Result<(), SocketDiagnosticsError> {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(dump_timeout_error)?;
        if remaining.is_zero() {
            return Err(dump_timeout_error());
        }
        let milliseconds = remaining
            .as_millis()
            .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0))
            .min(i32::MAX as u128) as i32;
        descriptor.revents = 0;
        // SAFETY: `descriptor` points to one writable pollfd for the duration
        // of this call, and `fd` remains owned by the diagnostic socket.
        let result = unsafe { libc::poll(&raw mut descriptor, 1, milliseconds) };
        if result > 0 {
            if descriptor.revents & libc::POLLIN != 0 {
                return Ok(());
            }
            return Err(protocol_error(
                "wait for socket-diagnostic dump datagram",
                "netlink descriptor became ready without readable data",
                None,
            ));
        }
        if result == 0 {
            return Err(dump_timeout_error());
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::EINTR) {
            return Err(SocketDiagnosticsError::Io {
                operation: "wait for socket-diagnostic dump datagram",
                path: None,
                source,
            });
        }
    }
}

fn dump_timeout_error() -> SocketDiagnosticsError {
    SocketDiagnosticsError::DeadlineExpired
}

fn deadline_checkpoint(deadline: Instant) -> Result<Instant, SocketDiagnosticsError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(dump_timeout_error());
    }
    Ok(now)
}

pub(super) fn validate_kernel_sender(
    sender: RawNetlinkSocketAddress,
    length: libc::socklen_t,
) -> Result<(), SocketDiagnosticsError> {
    if length != SOCKADDR_NL_LENGTH
        || sender.family != libc::AF_NETLINK as u16
        || sender.padding != 0
        || sender.port_id != 0
        || sender.groups != 0
    {
        return Err(protocol_error(
            "receive socket-diagnostic dump datagram",
            "unexpected netlink sender",
            None,
        ));
    }
    Ok(())
}

pub(super) fn encode_dump_request(spec: DumpSpec, sequence: NonZeroU32) -> [u8; 72] {
    let mut request = [0_u8; INET_DIAG_REQUEST_LENGTH];
    request[..4].copy_from_slice(&(INET_DIAG_REQUEST_LENGTH as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.get().to_ne_bytes());
    request[NETLINK_HEADER_LENGTH] = spec.family_number();
    request[NETLINK_HEADER_LENGTH + 1] = spec.protocol_number();
    request[NETLINK_HEADER_LENGTH + 4..NETLINK_HEADER_LENGTH + 8]
        .copy_from_slice(&spec.states().to_ne_bytes());
    request
}

pub(super) struct DumpDecoder {
    spec: DumpSpec,
    sequence: NonZeroU32,
    port_id: NonZeroU32,
    complete: bool,
    received_bytes: usize,
    message_count: usize,
    sockets: Vec<InetSocketDiagnostic>,
}

impl DumpDecoder {
    pub(super) const fn new(spec: DumpSpec, sequence: NonZeroU32, port_id: NonZeroU32) -> Self {
        Self {
            spec,
            sequence,
            port_id,
            complete: false,
            received_bytes: 0,
            message_count: 0,
            sockets: Vec::new(),
        }
    }

    const fn is_complete(&self) -> bool {
        self.complete
    }

    pub(super) fn decode_datagram(
        &mut self,
        datagram: &[u8],
    ) -> Result<(), SocketDiagnosticsError> {
        self.received_bytes = self
            .received_bytes
            .checked_add(datagram.len())
            .filter(|bytes| *bytes <= MAX_SOCKET_DIAG_DUMP_BYTES)
            .ok_or_else(|| {
                protocol_error(
                    "decode socket-diagnostic dump datagram",
                    "dump byte bound exceeded",
                    None,
                )
            })?;
        let mut saw_message = false;
        for message in NetlinkMessageIter::new(datagram) {
            saw_message = true;
            self.message_count = self
                .message_count
                .checked_add(1)
                .filter(|count| *count <= MAX_SOCKET_DIAG_DUMP_MESSAGES)
                .ok_or_else(|| {
                    protocol_error(
                        "decode socket-diagnostic dump datagram",
                        "dump message bound exceeded",
                        None,
                    )
                })?;
            let message = message.map_err(|error| {
                protocol_error(
                    "decode socket-diagnostic dump datagram",
                    "malformed netlink message framing",
                    Some(error.offset()),
                )
            })?;
            let header = message.header();
            if self.complete {
                return Err(protocol_error(
                    "decode socket-diagnostic dump datagram",
                    "message follows NLMSG_DONE",
                    Some(message.offset()),
                ));
            }
            if header.sequence() != self.sequence.get() {
                return Err(protocol_error(
                    "decode socket-diagnostic dump datagram",
                    "netlink sequence mismatch",
                    Some(message.offset()),
                ));
            }
            if header.port_id() != self.port_id.get() {
                return Err(protocol_error(
                    "decode socket-diagnostic dump datagram",
                    "netlink header sender mismatch",
                    Some(message.offset()),
                ));
            }
            if header.flags() & NLM_F_DUMP_INTR != 0 {
                return Err(protocol_error(
                    "decode socket-diagnostic dump datagram",
                    "kernel reported an interrupted dump",
                    Some(message.offset()),
                ));
            }
            match header.message_type() {
                SOCK_DIAG_BY_FAMILY => {
                    if header.flags() & NLM_F_MULTI == 0 {
                        return Err(protocol_error(
                            "decode socket-diagnostic dump datagram",
                            "diagnostic response is not multipart",
                            Some(message.offset()),
                        ));
                    }
                    if self.sockets.len() >= MAX_SOCKET_DIAG_SNAPSHOT_ROWS {
                        return Err(protocol_error(
                            "decode socket-diagnostic dump datagram",
                            "dump socket-row bound exceeded",
                            Some(message.offset()),
                        ));
                    }
                    self.sockets.push(decode_diagnostic(
                        self.spec,
                        self.sequence,
                        message.payload(),
                        message.offset() + NETLINK_HEADER_LENGTH,
                    )?);
                }
                NLMSG_DONE => {
                    if header.flags() & NLM_F_MULTI == 0 {
                        return Err(protocol_error(
                            "decode socket-diagnostic dump datagram",
                            "NLMSG_DONE is not multipart",
                            Some(message.offset()),
                        ));
                    }
                    validate_done_payload(
                        message.payload(),
                        header.flags(),
                        message.offset() + NETLINK_HEADER_LENGTH,
                    )
                    .map_err(|error| {
                        protocol_error(
                            "decode socket-diagnostic dump datagram",
                            "malformed or failed NLMSG_DONE",
                            Some(error.offset()),
                        )
                    })?;
                    self.complete = true;
                }
                NLMSG_ERROR => {
                    return Err(protocol_error(
                        "decode socket-diagnostic dump datagram",
                        "kernel returned NLMSG_ERROR",
                        Some(message.offset()),
                    ));
                }
                NLMSG_OVERRUN => {
                    return Err(protocol_error(
                        "decode socket-diagnostic dump datagram",
                        "kernel reported a netlink overrun",
                        Some(message.offset()),
                    ));
                }
                _ => {
                    return Err(protocol_error(
                        "decode socket-diagnostic dump datagram",
                        "unexpected netlink message type",
                        Some(message.offset()),
                    ));
                }
            }
        }
        if !saw_message {
            return Err(protocol_error(
                "decode socket-diagnostic dump datagram",
                "empty netlink datagram",
                None,
            ));
        }
        Ok(())
    }

    pub(super) fn finish(
        self,
        started_at: Instant,
        completed_at: Instant,
    ) -> Result<CompletedDump, SocketDiagnosticsError> {
        if !self.complete {
            return Err(protocol_error(
                "finish socket-diagnostic dump",
                "dump ended without NLMSG_DONE",
                None,
            ));
        }
        Ok(CompletedDump {
            sockets: self.sockets,
            received_bytes: self.received_bytes,
            started_at,
            completed_at,
        })
    }
}

pub(super) struct CompletedDump {
    pub(super) sockets: Vec<InetSocketDiagnostic>,
    received_bytes: usize,
    started_at: Instant,
    completed_at: Instant,
}

fn decode_diagnostic(
    spec: DumpSpec,
    sequence: NonZeroU32,
    payload: &[u8],
    payload_offset: usize,
) -> Result<InetSocketDiagnostic, SocketDiagnosticsError> {
    if payload.len() < INET_DIAG_MESSAGE_LENGTH {
        return Err(protocol_error(
            "decode INET_DIAG message",
            "truncated inet_diag_msg",
            Some(payload_offset),
        ));
    }
    if payload[0] != spec.family_number() {
        return Err(protocol_error(
            "decode INET_DIAG message",
            "address family mismatch",
            Some(payload_offset),
        ));
    }
    let state = payload[1];
    if spec.protocol == InetSocketProtocol::Udp && state != TCP_ESTABLISHED {
        return Err(protocol_error(
            "decode INET_DIAG message",
            "unconnected UDP record in connected-UDP dump",
            Some(payload_offset + 1),
        ));
    }

    let local_port = read_u16_be(&payload[4..]);
    let remote_port = read_u16_be(&payload[6..]);
    let local_ip = decode_ip(spec.address_family, &payload[8..24], payload_offset + 8)?;
    let remote_ip = decode_ip(spec.address_family, &payload[24..40], payload_offset + 24)?;
    let interface_index = read_u32_ne(&payload[40..]);
    let cookie_words = [read_u32_ne(&payload[44..]), read_u32_ne(&payload[48..])];
    if cookie_words == [u32::MAX; 2] {
        return Err(protocol_error(
            "decode INET_DIAG message",
            "kernel omitted the socket cookie",
            Some(payload_offset + 44),
        ));
    }
    let uid = read_u32_ne(&payload[64..]);
    let inode = u64::from(read_u32_ne(&payload[68..]));
    let mut mark = None;
    let mut protocol_attribute = None;
    for attribute in NetlinkAttributeIter::new(
        &payload[INET_DIAG_MESSAGE_LENGTH..],
        payload_offset + INET_DIAG_MESSAGE_LENGTH,
    ) {
        let attribute = attribute.map_err(|error| {
            protocol_error(
                "decode INET_DIAG attributes",
                "malformed netlink attribute",
                Some(error.offset()),
            )
        })?;
        match attribute.attribute_type() {
            INET_DIAG_MARK => {
                if attribute.flags() != 0 || attribute.value().len() != 4 || mark.is_some() {
                    return Err(protocol_error(
                        "decode INET_DIAG attributes",
                        "malformed or duplicate INET_DIAG_MARK",
                        Some(attribute.offset()),
                    ));
                }
                mark = Some(read_u32_ne(attribute.value()));
            }
            INET_DIAG_PROTOCOL => {
                if attribute.flags() != 0
                    || attribute.value().len() != 1
                    || protocol_attribute.is_some()
                    || attribute.value()[0] != spec.protocol_number()
                {
                    return Err(protocol_error(
                        "decode INET_DIAG attributes",
                        "malformed or mismatched INET_DIAG_PROTOCOL",
                        Some(attribute.offset()),
                    ));
                }
                protocol_attribute = Some(attribute.value()[0]);
            }
            _ => {}
        }
    }

    Ok(InetSocketDiagnostic {
        dump_sequence: sequence,
        address_family: spec.address_family,
        protocol: spec.protocol,
        state,
        local_address: SocketAddr::new(local_ip, local_port),
        remote_address: SocketAddr::new(remote_ip, remote_port),
        interface_index,
        uid,
        inode,
        cookie: InetDiagCookie {
            words: cookie_words,
        },
        mark,
    })
}

fn decode_ip(
    family: InetSocketAddressFamily,
    bytes: &[u8],
    offset: usize,
) -> Result<IpAddr, SocketDiagnosticsError> {
    let bytes: &[u8; 16] = bytes.try_into().expect("caller supplies a 16-byte address");
    match family {
        InetSocketAddressFamily::Ipv4 => {
            if bytes[4..].iter().any(|byte| *byte != 0) {
                return Err(protocol_error(
                    "decode INET_DIAG address",
                    "nonzero IPv4 address tail",
                    Some(offset + 4),
                ));
            }
            Ok(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        }
        InetSocketAddressFamily::Ipv6 => Ok(IpAddr::V6(Ipv6Addr::from(*bytes))),
    }
}

fn read_u16_be(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes[..2].try_into().expect("validated two-byte field"))
}

fn read_u32_ne(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes[..4].try_into().expect("validated four-byte field"))
}

fn protocol_error(
    operation: &'static str,
    detail: &'static str,
    offset: Option<usize>,
) -> SocketDiagnosticsError {
    SocketDiagnosticsError::NetlinkProtocol {
        operation,
        detail,
        offset,
    }
}

fn last_io_error(operation: &'static str) -> SocketDiagnosticsError {
    SocketDiagnosticsError::Io {
        operation,
        path: None,
        source: io::Error::last_os_error(),
    }
}
