use std::error::Error;
use std::fmt;
use std::time::Duration;

use crate::netlink::{
    NLM_F_DUMP_INTR, NLMSG_DONE, NLMSG_ERROR, NLMSG_OVERRUN, NetlinkMessageIter,
    validate_done_payload,
};

pub(super) const MAX_READ_ONLY_NETLINK_BOUND: Duration = Duration::from_secs(30);
pub(super) const MAX_READ_ONLY_NETLINK_DUMP_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_READ_ONLY_NETLINK_DUMP_MESSAGES: usize = 65_536;

const MIN_READ_ONLY_NETLINK_BOUND: Duration = Duration::from_millis(1);
const NETLINK_DATAGRAM_BYTES: usize = 1024 * 1024;
const NETLINK_RECEIVE_BUFFER_BYTES: i32 = 4 * 1024 * 1024;
const NETLINK_HEADER_BYTES: usize = 16;
const NETLINK_NOOP: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReadOnlyNetlinkMessage {
    message_type: u16,
    flags: u16,
    payload: Box<[u8]>,
}

impl ReadOnlyNetlinkMessage {
    #[cfg(test)]
    pub(super) fn fixture(message_type: u16, flags: u16, payload: Vec<u8>) -> Self {
        Self {
            message_type,
            flags,
            payload: payload.into_boxed_slice(),
        }
    }

    pub(super) const fn message_type(&self) -> u16 {
        self.message_type
    }

    pub(super) const fn flags(&self) -> u16 {
        self.flags
    }

    pub(super) const fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadOnlyNetlinkErrorKind {
    InvalidBound,
    SystemCall,
    Timeout,
    ShortWrite,
    TruncatedDatagram,
    UnexpectedSender,
    ConcurrentNotification,
    MalformedDatagram,
    DumpInterrupted,
    KernelRejected,
    LimitExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReadOnlyNetlinkError {
    kind: ReadOnlyNetlinkErrorKind,
    raw_os_error: Option<i32>,
}

impl ReadOnlyNetlinkError {
    const fn new(kind: ReadOnlyNetlinkErrorKind) -> Self {
        Self {
            kind,
            raw_os_error: None,
        }
    }

    const fn os(kind: ReadOnlyNetlinkErrorKind, raw_os_error: Option<i32>) -> Self {
        Self { kind, raw_os_error }
    }

    pub(super) const fn kind(self) -> ReadOnlyNetlinkErrorKind {
        self.kind
    }

    pub(super) const fn raw_os_error(self) -> Option<i32> {
        self.raw_os_error
    }
}

impl fmt::Display for ReadOnlyNetlinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "read-only netlink dump failed: {}",
            match self.kind {
                ReadOnlyNetlinkErrorKind::InvalidBound => "invalid caller deadline",
                ReadOnlyNetlinkErrorKind::SystemCall => "system call failure",
                ReadOnlyNetlinkErrorKind::Timeout => "caller deadline expired",
                ReadOnlyNetlinkErrorKind::ShortWrite => "short request write",
                ReadOnlyNetlinkErrorKind::TruncatedDatagram => "truncated response datagram",
                ReadOnlyNetlinkErrorKind::UnexpectedSender =>
                    "response did not come from the kernel",
                ReadOnlyNetlinkErrorKind::ConcurrentNotification => {
                    "subscribed state changed during the dump"
                }
                ReadOnlyNetlinkErrorKind::MalformedDatagram => "malformed response datagram",
                ReadOnlyNetlinkErrorKind::DumpInterrupted => "kernel interrupted the dump",
                ReadOnlyNetlinkErrorKind::KernelRejected => "kernel rejected the request",
                ReadOnlyNetlinkErrorKind::LimitExceeded =>
                    "response exceeded a fixed resource limit",
            }
        )?;
        if let Some(raw_os_error) = self.raw_os_error {
            write!(formatter, " (errno {raw_os_error})")?;
        }
        Ok(())
    }
}

impl Error for ReadOnlyNetlinkError {}

pub(super) fn validate_bound(bound: Duration) -> Result<(), ReadOnlyNetlinkError> {
    if !(MIN_READ_ONLY_NETLINK_BOUND..=MAX_READ_ONLY_NETLINK_BOUND).contains(&bound) {
        Err(ReadOnlyNetlinkError::new(
            ReadOnlyNetlinkErrorKind::InvalidBound,
        ))
    } else {
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn collect_read_only_netlink_dump(
    protocol: i32,
    groups: u32,
    request: &[u8],
    sequence: u32,
    bound: Duration,
) -> Result<Box<[ReadOnlyNetlinkMessage]>, ReadOnlyNetlinkError> {
    implementation::collect(protocol, groups, request, sequence, bound)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::io;
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Instant;

    use super::*;

    const SOCKADDR_NL_BYTES: libc::socklen_t = 12;

    #[derive(Clone, Copy, Debug, Default)]
    #[repr(C)]
    struct RawNetlinkAddress {
        family: u16,
        padding: u16,
        port_id: u32,
        groups: u32,
    }

    const _: () = assert!(mem::size_of::<RawNetlinkAddress>() == 12);

    pub(super) fn collect(
        protocol: i32,
        groups: u32,
        request: &[u8],
        sequence: u32,
        bound: Duration,
    ) -> Result<Box<[ReadOnlyNetlinkMessage]>, ReadOnlyNetlinkError> {
        validate_bound(bound)?;
        if sequence == 0
            || request.len() < NETLINK_HEADER_BYTES
            || u32::from_ne_bytes(request[8..12].try_into().expect("validated request header"))
                != sequence
        {
            return Err(ReadOnlyNetlinkError::new(
                ReadOnlyNetlinkErrorKind::MalformedDatagram,
            ));
        }

        let deadline = Instant::now()
            .checked_add(bound)
            .ok_or_else(|| ReadOnlyNetlinkError::new(ReadOnlyNetlinkErrorKind::InvalidBound))?;
        let fd = open_socket(protocol, groups)?;
        send_request(fd.as_raw_fd(), request, deadline)?;
        receive_dump(fd.as_raw_fd(), sequence, deadline)
    }

    fn open_socket(protocol: i32, groups: u32) -> Result<OwnedFd, ReadOnlyNetlinkError> {
        // SAFETY: socket has no pointer arguments and returns one new descriptor on success.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                protocol,
            )
        };
        if raw < 0 {
            return Err(last_os_error());
        }
        // SAFETY: the successful socket call returned a new owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        set_receive_buffer(fd.as_raw_fd())?;
        let address = RawNetlinkAddress {
            family: libc::AF_NETLINK as u16,
            groups,
            ..RawNetlinkAddress::default()
        };
        // SAFETY: address has the stable sockaddr_nl ABI and remains readable for the call.
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
                SOCKADDR_NL_BYTES,
            )
        };
        if result != 0 {
            return Err(last_os_error());
        }
        Ok(fd)
    }

    fn set_receive_buffer(fd: i32) -> Result<(), ReadOnlyNetlinkError> {
        // SAFETY: value points to one initialized i32 for the duration of setsockopt.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                std::ptr::from_ref(&NETLINK_RECEIVE_BUFFER_BYTES).cast::<libc::c_void>(),
                mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(last_os_error());
        }
        Ok(())
    }

    fn send_request(
        fd: i32,
        request: &[u8],
        deadline: Instant,
    ) -> Result<(), ReadOnlyNetlinkError> {
        let kernel = RawNetlinkAddress {
            family: libc::AF_NETLINK as u16,
            ..RawNetlinkAddress::default()
        };
        loop {
            // SAFETY: request and destination are readable for their declared lengths; the FD is
            // owned by the caller and the kernel does not retain either pointer.
            let sent = unsafe {
                libc::sendto(
                    fd,
                    request.as_ptr().cast::<libc::c_void>(),
                    request.len(),
                    libc::MSG_DONTWAIT,
                    std::ptr::from_ref(&kernel).cast::<libc::sockaddr>(),
                    SOCKADDR_NL_BYTES,
                )
            };
            if sent >= 0 {
                let sent = usize::try_from(sent)
                    .map_err(|_| ReadOnlyNetlinkError::new(ReadOnlyNetlinkErrorKind::ShortWrite))?;
                return if sent == request.len() {
                    Ok(())
                } else {
                    Err(ReadOnlyNetlinkError::new(
                        ReadOnlyNetlinkErrorKind::ShortWrite,
                    ))
                };
            }
            let source = io::Error::last_os_error();
            match source.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => poll_until(fd, libc::POLLOUT, deadline)?,
                _ => return Err(os_error(source)),
            }
        }
    }

    fn receive_dump(
        fd: i32,
        sequence: u32,
        deadline: Instant,
    ) -> Result<Box<[ReadOnlyNetlinkMessage]>, ReadOnlyNetlinkError> {
        let mut storage = vec![0_u8; NETLINK_DATAGRAM_BYTES];
        let mut messages = Vec::new();
        let mut retained_bytes = 0_usize;

        loop {
            poll_until(fd, libc::POLLIN, deadline)?;
            let mut sender = RawNetlinkAddress::default();
            let mut iovec = libc::iovec {
                iov_base: storage.as_mut_ptr().cast::<libc::c_void>(),
                iov_len: storage.len(),
            };
            // SAFETY: a zeroed msghdr is a valid base and all receive pointers and lengths are
            // assigned below before the syscall.
            let mut header: libc::msghdr = unsafe { mem::zeroed() };
            header.msg_name = std::ptr::from_mut(&mut sender).cast::<libc::c_void>();
            header.msg_namelen = SOCKADDR_NL_BYTES;
            header.msg_iov = std::ptr::from_mut(&mut iovec);
            header.msg_iovlen = 1;

            // SAFETY: header references distinct initialized writable storage that lives through
            // the call; the kernel does not retain it.
            let received =
                unsafe { libc::recvmsg(fd, &mut header, libc::MSG_DONTWAIT | libc::MSG_TRUNC) };
            if received < 0 {
                let source = io::Error::last_os_error();
                match source.raw_os_error() {
                    Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                    _ => return Err(os_error(source)),
                }
            }
            let received = usize::try_from(received).map_err(|_| {
                ReadOnlyNetlinkError::new(ReadOnlyNetlinkErrorKind::MalformedDatagram)
            })?;
            if received > storage.len() || header.msg_flags & libc::MSG_TRUNC != 0 {
                return Err(ReadOnlyNetlinkError::new(
                    ReadOnlyNetlinkErrorKind::TruncatedDatagram,
                ));
            }
            if header.msg_namelen != SOCKADDR_NL_BYTES
                || sender.family != libc::AF_NETLINK as u16
                || sender.port_id != 0
            {
                return Err(ReadOnlyNetlinkError::new(
                    ReadOnlyNetlinkErrorKind::UnexpectedSender,
                ));
            }
            if received == 0 {
                return Err(ReadOnlyNetlinkError::new(
                    ReadOnlyNetlinkErrorKind::MalformedDatagram,
                ));
            }

            if sender.groups != 0 {
                return Err(ReadOnlyNetlinkError::new(
                    ReadOnlyNetlinkErrorKind::ConcurrentNotification,
                ));
            }
            if append_response_datagram(
                &storage[..received],
                sequence,
                &mut messages,
                &mut retained_bytes,
            )? {
                return Ok(messages.into_boxed_slice());
            }
        }
    }

    pub(super) fn append_response_datagram(
        datagram: &[u8],
        sequence: u32,
        messages: &mut Vec<ReadOnlyNetlinkMessage>,
        retained_bytes: &mut usize,
    ) -> Result<bool, ReadOnlyNetlinkError> {
        let mut complete = false;
        for message in NetlinkMessageIter::new(datagram) {
            let message = message.map_err(|_| {
                ReadOnlyNetlinkError::new(ReadOnlyNetlinkErrorKind::MalformedDatagram)
            })?;
            if complete {
                return Err(ReadOnlyNetlinkError::new(
                    ReadOnlyNetlinkErrorKind::MalformedDatagram,
                ));
            }
            let netlink_header = message.header();
            if netlink_header.sequence() != sequence {
                return Err(ReadOnlyNetlinkError::new(
                    ReadOnlyNetlinkErrorKind::MalformedDatagram,
                ));
            }
            if netlink_header.flags() & NLM_F_DUMP_INTR != 0 {
                return Err(ReadOnlyNetlinkError::new(
                    ReadOnlyNetlinkErrorKind::DumpInterrupted,
                ));
            }

            match netlink_header.message_type() {
                NETLINK_NOOP => {}
                NLMSG_DONE => {
                    validate_done_payload(
                        message.payload(),
                        netlink_header.flags(),
                        message.offset() + NETLINK_HEADER_BYTES,
                    )
                    .map_err(|_| {
                        ReadOnlyNetlinkError::new(ReadOnlyNetlinkErrorKind::MalformedDatagram)
                    })?;
                    complete = true;
                }
                NLMSG_ERROR => {
                    let payload = message.payload();
                    if payload.len() < mem::size_of::<i32>() {
                        return Err(ReadOnlyNetlinkError::new(
                            ReadOnlyNetlinkErrorKind::MalformedDatagram,
                        ));
                    }
                    let status = i32::from_ne_bytes(
                        payload[..4].try_into().expect("validated error status"),
                    );
                    if status != 0 {
                        return Err(ReadOnlyNetlinkError::os(
                            ReadOnlyNetlinkErrorKind::KernelRejected,
                            status.checked_neg(),
                        ));
                    }
                }
                NLMSG_OVERRUN => {
                    return Err(ReadOnlyNetlinkError::new(
                        ReadOnlyNetlinkErrorKind::TruncatedDatagram,
                    ));
                }
                message_type => {
                    if messages.len() == MAX_READ_ONLY_NETLINK_DUMP_MESSAGES {
                        return Err(ReadOnlyNetlinkError::new(
                            ReadOnlyNetlinkErrorKind::LimitExceeded,
                        ));
                    }
                    *retained_bytes = retained_bytes
                        .checked_add(message.payload().len())
                        .ok_or_else(|| {
                            ReadOnlyNetlinkError::new(ReadOnlyNetlinkErrorKind::LimitExceeded)
                        })?;
                    if *retained_bytes > MAX_READ_ONLY_NETLINK_DUMP_BYTES {
                        return Err(ReadOnlyNetlinkError::new(
                            ReadOnlyNetlinkErrorKind::LimitExceeded,
                        ));
                    }
                    messages.push(ReadOnlyNetlinkMessage {
                        message_type,
                        flags: netlink_header.flags(),
                        payload: message.payload().into(),
                    });
                }
            }
        }
        Ok(complete)
    }

    fn poll_until(fd: i32, events: i16, deadline: Instant) -> Result<(), ReadOnlyNetlinkError> {
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| ReadOnlyNetlinkError::new(ReadOnlyNetlinkErrorKind::Timeout))?;
            let milliseconds = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            // SAFETY: descriptor points to one initialized pollfd and remains writable for the
            // duration of the call.
            let result = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
            if result > 0 {
                if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    return Err(ReadOnlyNetlinkError::new(
                        ReadOnlyNetlinkErrorKind::SystemCall,
                    ));
                }
                if descriptor.revents & events != 0 {
                    return Ok(());
                }
                continue;
            }
            if result == 0 {
                return Err(ReadOnlyNetlinkError::new(ReadOnlyNetlinkErrorKind::Timeout));
            }
            let source = io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::EINTR) {
                return Err(os_error(source));
            }
        }
    }

    fn last_os_error() -> ReadOnlyNetlinkError {
        os_error(io::Error::last_os_error())
    }

    fn os_error(source: io::Error) -> ReadOnlyNetlinkError {
        ReadOnlyNetlinkError::os(ReadOnlyNetlinkErrorKind::SystemCall, source.raw_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_reject_zero_and_values_above_the_public_maximum() {
        assert_eq!(
            validate_bound(Duration::ZERO).unwrap_err().kind(),
            ReadOnlyNetlinkErrorKind::InvalidBound
        );
        assert!(validate_bound(Duration::from_millis(1)).is_ok());
        assert!(validate_bound(MAX_READ_ONLY_NETLINK_BOUND).is_ok());
        assert_eq!(
            validate_bound(MAX_READ_ONLY_NETLINK_BOUND + Duration::from_millis(1))
                .unwrap_err()
                .kind(),
            ReadOnlyNetlinkErrorKind::InvalidBound
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn response_framing_rejects_messages_after_completion() {
        let mut datagram = netlink_message(NLMSG_DONE, 0, 7, &[]);
        datagram.extend(netlink_message(0x1234, 0, 7, &[]));
        let mut messages = Vec::new();
        let mut retained_bytes = 0;
        assert_eq!(
            implementation::append_response_datagram(
                &datagram,
                7,
                &mut messages,
                &mut retained_bytes,
            )
            .unwrap_err()
            .kind(),
            ReadOnlyNetlinkErrorKind::MalformedDatagram
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn netlink_message(message_type: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = NETLINK_HEADER_BYTES + payload.len();
        let aligned = (length + 3) & !3;
        let mut message = vec![0_u8; aligned];
        message[..4].copy_from_slice(&(length as u32).to_ne_bytes());
        message[4..6].copy_from_slice(&message_type.to_ne_bytes());
        message[6..8].copy_from_slice(&flags.to_ne_bytes());
        message[8..12].copy_from_slice(&sequence.to_ne_bytes());
        message[NETLINK_HEADER_BYTES..length].copy_from_slice(payload);
        message
    }
}
