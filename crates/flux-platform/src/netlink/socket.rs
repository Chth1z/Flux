use std::num::NonZeroU32;

const NETLINK_HEADER_LENGTH: usize = 16;
const INTERFACE_ADDRESS_MESSAGE_LENGTH: usize = 8;
const ADDRESS_DUMP_REQUEST_LENGTH: usize = NETLINK_HEADER_LENGTH + INTERFACE_ADDRESS_MESSAGE_LENGTH;
const RTM_GETADDR: u16 = 22;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_DUMP: u16 = 0x0300;

#[cfg(target_os = "linux")]
const RTNLGRP_LINK: u32 = libc::RTNLGRP_LINK;
#[cfg(not(target_os = "linux"))]
const RTNLGRP_LINK: u32 = 1;
#[cfg(target_os = "linux")]
const RTNLGRP_IPV4_IFADDR: u32 = libc::RTNLGRP_IPV4_IFADDR;
#[cfg(not(target_os = "linux"))]
const RTNLGRP_IPV4_IFADDR: u32 = 5;
#[cfg(target_os = "linux")]
const RTNLGRP_IPV4_ROUTE: u32 = libc::RTNLGRP_IPV4_ROUTE;
#[cfg(not(target_os = "linux"))]
const RTNLGRP_IPV4_ROUTE: u32 = 7;
#[cfg(target_os = "linux")]
const RTNLGRP_IPV4_RULE: u32 = libc::RTNLGRP_IPV4_RULE;
#[cfg(not(target_os = "linux"))]
const RTNLGRP_IPV4_RULE: u32 = 8;
#[cfg(target_os = "linux")]
const RTNLGRP_IPV6_IFADDR: u32 = libc::RTNLGRP_IPV6_IFADDR;
#[cfg(not(target_os = "linux"))]
const RTNLGRP_IPV6_IFADDR: u32 = 9;
#[cfg(target_os = "linux")]
const RTNLGRP_IPV6_ROUTE: u32 = libc::RTNLGRP_IPV6_ROUTE;
#[cfg(not(target_os = "linux"))]
const RTNLGRP_IPV6_ROUTE: u32 = 11;
#[cfg(target_os = "linux")]
const RTNLGRP_IPV6_RULE: u32 = libc::RTNLGRP_IPV6_RULE;
#[cfg(not(target_os = "linux"))]
const RTNLGRP_IPV6_RULE: u32 = 19;

const AF_NETLINK: u16 = 16;
const SOCKADDR_NL_LENGTH: u32 = 12;
const MSG_TRUNC: i32 = 0x20;
pub(crate) const RECEIVE_BATCH_SLOTS: usize = 8;
pub(crate) const ROUTE_DATAGRAM_CAPACITY: usize = 64 * 1024;
const ROUTE_SOCKET_RECEIVE_BUFFER_BYTES: i32 = 4 * 1024 * 1024;
const MAX_EFFECTIVE_ROUTE_SOCKET_RECEIVE_BUFFER_BYTES: i32 = ROUTE_SOCKET_RECEIVE_BUFFER_BYTES * 2;

const fn multicast_group_bit(group: u32) -> u32 {
    1_u32 << (group - 1)
}

pub(crate) const fn route_subscription_groups() -> u32 {
    multicast_group_bit(RTNLGRP_LINK)
        | multicast_group_bit(RTNLGRP_IPV4_IFADDR)
        | multicast_group_bit(RTNLGRP_IPV4_ROUTE)
        | multicast_group_bit(RTNLGRP_IPV4_RULE)
        | multicast_group_bit(RTNLGRP_IPV6_IFADDR)
        | multicast_group_bit(RTNLGRP_IPV6_ROUTE)
        | multicast_group_bit(RTNLGRP_IPV6_RULE)
}

#[derive(Debug)]
pub(crate) struct NetlinkSequenceAllocator {
    next: NonZeroU32,
}

impl NetlinkSequenceAllocator {
    pub(crate) const fn new(first: NonZeroU32) -> Self {
        Self { next: first }
    }

    pub(crate) fn allocate(&mut self) -> NonZeroU32 {
        let allocated = self.next;
        self.next = NonZeroU32::new(allocated.get().wrapping_add(1)).unwrap_or(NonZeroU32::MIN);
        allocated
    }
}

impl Default for NetlinkSequenceAllocator {
    fn default() -> Self {
        Self::new(NonZeroU32::MIN)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AddressDumpRequest {
    bytes: [u8; ADDRESS_DUMP_REQUEST_LENGTH],
    sequence: NonZeroU32,
}

impl AddressDumpRequest {
    pub(crate) fn all(sequence: NonZeroU32) -> Self {
        let mut bytes = [0; ADDRESS_DUMP_REQUEST_LENGTH];
        bytes[..4].copy_from_slice(&(ADDRESS_DUMP_REQUEST_LENGTH as u32).to_ne_bytes());
        bytes[4..6].copy_from_slice(&RTM_GETADDR.to_ne_bytes());
        bytes[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        bytes[8..12].copy_from_slice(&sequence.get().to_ne_bytes());
        Self { bytes, sequence }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; ADDRESS_DUMP_REQUEST_LENGTH] {
        &self.bytes
    }

    pub(crate) const fn sequence(&self) -> NonZeroU32 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SocketOptionEvidence {
    Enabled,
    Rejected { raw_os_error: Option<i32> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RouteNetlinkSocketEvidence {
    extended_ack: SocketOptionEvidence,
    strict_check: SocketOptionEvidence,
    effective_receive_buffer_bytes: i32,
    local_port_id: u32,
    subscribed_groups: u32,
}

impl RouteNetlinkSocketEvidence {
    pub(crate) const fn extended_ack(self) -> SocketOptionEvidence {
        self.extended_ack
    }

    pub(crate) const fn strict_check(self) -> SocketOptionEvidence {
        self.strict_check
    }

    pub(crate) const fn effective_receive_buffer_bytes(self) -> i32 {
        self.effective_receive_buffer_bytes
    }

    pub(crate) const fn local_port_id(self) -> u32 {
        self.local_port_id
    }

    pub(crate) const fn subscribed_groups(self) -> u32 {
        self.subscribed_groups
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetlinkSenderAddress {
    address_length: u32,
    family: u16,
    padding: u16,
    port_id: u32,
    groups: u32,
}

impl NetlinkSenderAddress {
    const EMPTY: Self = Self {
        address_length: 0,
        family: 0,
        padding: 0,
        port_id: 0,
        groups: 0,
    };

    const fn new(
        address_length: u32,
        family: u16,
        padding: u16,
        port_id: u32,
        groups: u32,
    ) -> Self {
        Self {
            address_length,
            family,
            padding,
            port_id,
            groups,
        }
    }

    pub(crate) const fn address_length(self) -> u32 {
        self.address_length
    }

    pub(crate) const fn family(self) -> u16 {
        self.family
    }

    pub(crate) const fn padding(self) -> u16 {
        self.padding
    }

    pub(crate) const fn port_id(self) -> u32 {
        self.port_id
    }

    pub(crate) const fn groups(self) -> u32 {
        self.groups
    }

    pub(crate) const fn is_kernel(self) -> bool {
        self.address_length == SOCKADDR_NL_LENGTH && self.family == AF_NETLINK && self.port_id == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetlinkDatagramMetadata {
    reported_length: usize,
    message_flags: i32,
    sender: NetlinkSenderAddress,
}

impl NetlinkDatagramMetadata {
    const EMPTY: Self = Self {
        reported_length: 0,
        message_flags: 0,
        sender: NetlinkSenderAddress::EMPTY,
    };

    const fn new(reported_length: usize, message_flags: i32, sender: NetlinkSenderAddress) -> Self {
        Self {
            reported_length,
            message_flags,
            sender,
        }
    }

    pub(crate) const fn reported_length(self) -> usize {
        self.reported_length
    }

    pub(crate) const fn message_flags(self) -> i32 {
        self.message_flags
    }

    pub(crate) const fn sender(self) -> NetlinkSenderAddress {
        self.sender
    }

    pub(crate) const fn is_truncated(self) -> bool {
        self.reported_length > ROUTE_DATAGRAM_CAPACITY || self.message_flags & MSG_TRUNC != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NetlinkBatchMetadata {
    entries: [NetlinkDatagramMetadata; RECEIVE_BATCH_SLOTS],
    count: usize,
}

impl NetlinkBatchMetadata {
    fn copy_from(entries: &[NetlinkDatagramMetadata]) -> Self {
        debug_assert!(entries.len() <= RECEIVE_BATCH_SLOTS);
        let mut copied = [NetlinkDatagramMetadata::EMPTY; RECEIVE_BATCH_SLOTS];
        copied[..entries.len()].copy_from_slice(entries);
        Self {
            entries: copied,
            count: entries.len(),
        }
    }

    pub(crate) fn entries(&self) -> &[NetlinkDatagramMetadata] {
        &self.entries[..self.count]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NetlinkReceiveLoss {
    Enobufs,
    Truncated(Box<NetlinkBatchMetadata>),
    UnexpectedSender(Box<NetlinkBatchMetadata>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetlinkSendOutcome {
    Sent,
    WouldBlock,
}

pub(crate) enum NetlinkReceiveOutcome<'a> {
    WouldBlock,
    Datagrams(NetlinkDatagramBatch<'a>),
    Loss(NetlinkReceiveLoss),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetlinkDatagram<'a> {
    bytes: &'a [u8],
    metadata: NetlinkDatagramMetadata,
}

impl<'a> NetlinkDatagram<'a> {
    const fn new(bytes: &'a [u8], metadata: NetlinkDatagramMetadata) -> Self {
        Self { bytes, metadata }
    }

    pub(crate) const fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    pub(crate) const fn metadata(self) -> NetlinkDatagramMetadata {
        self.metadata
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BatchIntegrity {
    Complete,
    Truncated,
    UnexpectedSender,
}

fn classify_batch(metadata: &[NetlinkDatagramMetadata]) -> BatchIntegrity {
    if metadata
        .iter()
        .copied()
        .any(NetlinkDatagramMetadata::is_truncated)
    {
        return BatchIntegrity::Truncated;
    }
    if metadata
        .iter()
        .any(|datagram| !datagram.sender().is_kernel())
    {
        return BatchIntegrity::UnexpectedSender;
    }
    BatchIntegrity::Complete
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::fmt;
    use std::mem;
    use std::num::NonZeroUsize;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

    use super::{
        AF_NETLINK, AddressDumpRequest, BatchIntegrity,
        MAX_EFFECTIVE_ROUTE_SOCKET_RECEIVE_BUFFER_BYTES, MSG_TRUNC, NetlinkBatchMetadata,
        NetlinkDatagram, NetlinkDatagramMetadata, NetlinkReceiveLoss, NetlinkReceiveOutcome,
        NetlinkSendOutcome, NetlinkSenderAddress, RECEIVE_BATCH_SLOTS, ROUTE_DATAGRAM_CAPACITY,
        ROUTE_SOCKET_RECEIVE_BUFFER_BYTES, RouteNetlinkSocketEvidence, SOCKADDR_NL_LENGTH,
        SocketOptionEvidence, classify_batch, route_subscription_groups,
    };
    use crate::PlatformError;

    const _: () = assert!(AF_NETLINK == libc::AF_NETLINK as u16);
    const _: () = assert!(MSG_TRUNC == libc::MSG_TRUNC);
    const _: () = assert!(SOCKADDR_NL_LENGTH as usize == mem::size_of::<libc::sockaddr_nl>());

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[repr(C)]
    struct RawNetlinkSocketAddress {
        family: u16,
        padding: u16,
        port_id: u32,
        groups: u32,
    }

    const _: () =
        assert!(mem::size_of::<RawNetlinkSocketAddress>() == mem::size_of::<libc::sockaddr_nl>());
    const _: () =
        assert!(mem::align_of::<RawNetlinkSocketAddress>() == mem::align_of::<libc::sockaddr_nl>());

    /// Fixed receive storage for one bounded `recvmmsg` syscall.
    ///
    /// The slab and the three descriptor arrays are boxed once. Raw pointers
    /// installed in `headers` therefore remain valid when this owner moves.
    /// No method replaces or resizes those allocations.
    pub(crate) struct NetlinkReceiveRing {
        slab: Box<[u8]>,
        iovecs: Box<[libc::iovec]>,
        senders: Box<[RawNetlinkSocketAddress]>,
        headers: Box<[libc::mmsghdr]>,
        metadata: [NetlinkDatagramMetadata; RECEIVE_BATCH_SLOTS],
    }

    impl NetlinkReceiveRing {
        pub(crate) fn new() -> Self {
            let slab = vec![0; RECEIVE_BATCH_SLOTS * ROUTE_DATAGRAM_CAPACITY].into_boxed_slice();
            let iovecs = (0..RECEIVE_BATCH_SLOTS)
                .map(|_| libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let senders =
                vec![RawNetlinkSocketAddress::default(); RECEIVE_BATCH_SLOTS].into_boxed_slice();
            let headers = (0..RECEIVE_BATCH_SLOTS)
                .map(|_| empty_mmsghdr())
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let mut ring = Self {
                slab,
                iovecs,
                senders,
                headers,
                metadata: [NetlinkDatagramMetadata::EMPTY; RECEIVE_BATCH_SLOTS],
            };
            ring.prepare();
            ring
        }

        fn prepare(&mut self) {
            self.metadata = [NetlinkDatagramMetadata::EMPTY; RECEIVE_BATCH_SLOTS];
            let slab = self.slab.as_mut_ptr();
            for index in 0..RECEIVE_BATCH_SLOTS {
                self.senders[index] = RawNetlinkSocketAddress::default();

                let start = index * ROUTE_DATAGRAM_CAPACITY;
                // SAFETY: every slot start is within the fixed slab, and each
                // slot spans exactly ROUTE_DATAGRAM_CAPACITY bytes.
                let buffer = unsafe { slab.add(start) };
                self.iovecs[index] = libc::iovec {
                    iov_base: buffer.cast::<libc::c_void>(),
                    iov_len: ROUTE_DATAGRAM_CAPACITY,
                };

                // SAFETY: an all-zero msghdr/mmsghdr is a valid empty receive
                // descriptor; every required pointer and length is assigned
                // immediately below before it reaches the kernel.
                let mut header = empty_mmsghdr();
                header.msg_hdr.msg_name =
                    std::ptr::from_mut(&mut self.senders[index]).cast::<libc::c_void>();
                header.msg_hdr.msg_namelen = SOCKADDR_NL_LENGTH;
                header.msg_hdr.msg_iov = std::ptr::from_mut(&mut self.iovecs[index]);
                header.msg_hdr.msg_iovlen = 1;
                self.headers[index] = header;
            }
        }

        fn update_metadata(&mut self, count: usize) {
            for index in 0..count {
                let header = &self.headers[index];
                let sender = self.senders[index];
                self.metadata[index] = NetlinkDatagramMetadata::new(
                    header.msg_len as usize,
                    header.msg_hdr.msg_flags,
                    NetlinkSenderAddress::new(
                        header.msg_hdr.msg_namelen,
                        sender.family,
                        sender.padding,
                        sender.port_id,
                        sender.groups,
                    ),
                );
            }
        }
    }

    impl Default for NetlinkReceiveRing {
        fn default() -> Self {
            Self::new()
        }
    }

    pub(crate) struct NetlinkDatagramBatch<'a> {
        ring: &'a NetlinkReceiveRing,
        count: usize,
    }

    impl NetlinkDatagramBatch<'_> {
        pub(crate) const fn len(&self) -> usize {
            self.count
        }

        pub(crate) const fn is_empty(&self) -> bool {
            self.count == 0
        }

        pub(crate) fn metadata(&self) -> &[NetlinkDatagramMetadata] {
            &self.ring.metadata[..self.count]
        }

        pub(crate) fn datagram(&self, index: usize) -> Option<NetlinkDatagram<'_>> {
            let metadata = *self.metadata().get(index)?;
            debug_assert!(!metadata.is_truncated());
            let start = index * ROUTE_DATAGRAM_CAPACITY;
            let end = start + metadata.reported_length();
            Some(NetlinkDatagram::new(&self.ring.slab[start..end], metadata))
        }
    }

    impl fmt::Debug for NetlinkDatagramBatch<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("NetlinkDatagramBatch")
                .field("metadata", &self.metadata())
                .finish_non_exhaustive()
        }
    }

    #[derive(Debug)]
    pub(crate) struct RouteNetlinkSocket {
        fd: OwnedFd,
        evidence: RouteNetlinkSocketEvidence,
    }

    impl RouteNetlinkSocket {
        pub(crate) fn open() -> Result<Self, PlatformError> {
            // SAFETY: socket has no pointer arguments. On success it returns a
            // new descriptor owned by the caller. Both state flags are applied
            // atomically, before the descriptor can be observed elsewhere.
            let descriptor = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    libc::NETLINK_ROUTE,
                )
            };
            if descriptor < 0 {
                return Err(last_error("create route-netlink socket"));
            }
            // SAFETY: the successful socket call returned a new owned FD.
            let fd = unsafe { OwnedFd::from_raw_fd(descriptor) };

            set_socket_option_i32(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                ROUTE_SOCKET_RECEIVE_BUFFER_BYTES,
                "set route-netlink receive buffer",
            )?;
            let extended_ack = enable_best_effort(fd.as_raw_fd(), libc::NETLINK_EXT_ACK);
            let strict_check = enable_best_effort(fd.as_raw_fd(), libc::NETLINK_GET_STRICT_CHK);

            // NETLINK_NO_ENOBUFS is deliberately not set. Its Linux default is
            // disabled, which keeps queue overflow observable as ENOBUFS.
            bind_subscriptions(fd.as_raw_fd())?;
            let local_address = local_address(fd.as_raw_fd())?;
            if local_address.family != AF_NETLINK
                || local_address.groups != route_subscription_groups()
            {
                return Err(protocol_error("verify route-netlink subscriptions"));
            }
            let effective_receive_buffer_bytes = socket_option_i32(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                "read route-netlink receive buffer",
            )?;
            if !(1..=MAX_EFFECTIVE_ROUTE_SOCKET_RECEIVE_BUFFER_BYTES)
                .contains(&effective_receive_buffer_bytes)
            {
                return Err(protocol_error("verify route-netlink receive buffer"));
            }

            Ok(Self {
                fd,
                evidence: RouteNetlinkSocketEvidence {
                    extended_ack,
                    strict_check,
                    effective_receive_buffer_bytes,
                    local_port_id: local_address.port_id,
                    subscribed_groups: local_address.groups,
                },
            })
        }

        pub(crate) fn readiness_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }

        pub(crate) const fn evidence(&self) -> RouteNetlinkSocketEvidence {
            self.evidence
        }

        pub(crate) fn send_address_dump(
            &self,
            request: &AddressDumpRequest,
        ) -> Result<NetlinkSendOutcome, PlatformError> {
            let destination = RawNetlinkSocketAddress {
                family: AF_NETLINK,
                ..RawNetlinkSocketAddress::default()
            };
            let sent = loop {
                // SAFETY: request bytes are readable for their full fixed
                // length, destination has the sockaddr_nl ABI, and the owned
                // FD remains valid for this nonblocking call.
                let sent = unsafe {
                    libc::sendto(
                        self.fd.as_raw_fd(),
                        request.as_bytes().as_ptr().cast::<libc::c_void>(),
                        request.as_bytes().len(),
                        libc::MSG_DONTWAIT,
                        std::ptr::from_ref(&destination).cast::<libc::sockaddr>(),
                        SOCKADDR_NL_LENGTH,
                    )
                };
                if sent >= 0 {
                    break sent;
                }
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EINTR) {
                    if source.kind() == std::io::ErrorKind::WouldBlock {
                        return Ok(NetlinkSendOutcome::WouldBlock);
                    }
                    return Err(system_call_error("send route-netlink address dump", source));
                }
            };
            let actual = usize::try_from(sent).map_err(|_| PlatformError::ShortWrite {
                expected: request.as_bytes().len(),
                actual: 0,
            })?;
            if actual != request.as_bytes().len() {
                return Err(PlatformError::ShortWrite {
                    expected: request.as_bytes().len(),
                    actual,
                });
            }
            Ok(NetlinkSendOutcome::Sent)
        }

        pub(crate) fn receive_batch<'a>(
            &self,
            ring: &'a mut NetlinkReceiveRing,
            max_datagrams: NonZeroUsize,
        ) -> Result<NetlinkReceiveOutcome<'a>, PlatformError> {
            let max_datagrams = max_datagrams.get().min(RECEIVE_BATCH_SLOTS);
            let received = loop {
                ring.prepare();
                // SAFETY: every mmsghdr points to one distinct fixed slab slot
                // and one distinct writable sender address. The arrays remain
                // allocated and exclusively borrowed throughout this syscall.
                let received = unsafe {
                    libc::recvmmsg(
                        self.fd.as_raw_fd(),
                        ring.headers.as_mut_ptr(),
                        max_datagrams as libc::c_uint,
                        (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as _,
                        std::ptr::null_mut(),
                    )
                };
                if received >= 0 {
                    break received;
                }
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EINTR) {
                    if source.kind() == std::io::ErrorKind::WouldBlock {
                        return Ok(NetlinkReceiveOutcome::WouldBlock);
                    }
                    if source.raw_os_error() == Some(libc::ENOBUFS) {
                        return Ok(NetlinkReceiveOutcome::Loss(NetlinkReceiveLoss::Enobufs));
                    }
                    return Err(system_call_error("receive route-netlink batch", source));
                }
            };
            if received == 0 {
                return Ok(NetlinkReceiveOutcome::WouldBlock);
            }
            let count = usize::try_from(received)
                .map_err(|_| protocol_error("receive route-netlink batch"))?;
            if count > RECEIVE_BATCH_SLOTS {
                return Err(protocol_error("receive route-netlink batch"));
            }
            ring.update_metadata(count);

            let metadata = &ring.metadata[..count];
            match classify_batch(metadata) {
                BatchIntegrity::Complete => {
                    Ok(NetlinkReceiveOutcome::Datagrams(NetlinkDatagramBatch {
                        ring,
                        count,
                    }))
                }
                BatchIntegrity::Truncated => {
                    Ok(NetlinkReceiveOutcome::Loss(NetlinkReceiveLoss::Truncated(
                        Box::new(NetlinkBatchMetadata::copy_from(metadata)),
                    )))
                }
                BatchIntegrity::UnexpectedSender => Ok(NetlinkReceiveOutcome::Loss(
                    NetlinkReceiveLoss::UnexpectedSender(Box::new(
                        NetlinkBatchMetadata::copy_from(metadata),
                    )),
                )),
            }
        }
    }

    fn empty_mmsghdr() -> libc::mmsghdr {
        // SAFETY: an all-zero mmsghdr contains null pointers and zero lengths,
        // which is its valid empty descriptor state. Callers fill the receive
        // pointers before passing it to the kernel.
        unsafe { mem::zeroed() }
    }

    fn bind_subscriptions(fd: i32) -> Result<(), PlatformError> {
        let address = RawNetlinkSocketAddress {
            family: AF_NETLINK,
            groups: route_subscription_groups(),
            ..RawNetlinkSocketAddress::default()
        };
        // SAFETY: address has the sockaddr_nl ABI and remains readable for the
        // supplied exact length while fd owns a route-netlink socket.
        if unsafe {
            libc::bind(
                fd,
                std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
                SOCKADDR_NL_LENGTH,
            )
        } != 0
        {
            return Err(last_error("bind route-netlink subscriptions"));
        }
        Ok(())
    }

    fn local_address(fd: i32) -> Result<RawNetlinkSocketAddress, PlatformError> {
        let mut address = RawNetlinkSocketAddress::default();
        let mut length = SOCKADDR_NL_LENGTH;
        // SAFETY: address and length point to writable storage of the declared
        // size, and fd owns a bound route-netlink socket.
        if unsafe {
            libc::getsockname(
                fd,
                std::ptr::from_mut(&mut address).cast::<libc::sockaddr>(),
                &raw mut length,
            )
        } != 0
        {
            return Err(last_error("read route-netlink local address"));
        }
        if length != SOCKADDR_NL_LENGTH {
            return Err(protocol_error("read route-netlink local address"));
        }
        Ok(address)
    }

    fn enable_best_effort(fd: i32, option: i32) -> SocketOptionEvidence {
        let value = 1_i32;
        // SAFETY: value is readable for one i32 and fd owns a netlink socket.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_NETLINK,
                option,
                std::ptr::from_ref(&value).cast::<libc::c_void>(),
                mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if result == 0 {
            SocketOptionEvidence::Enabled
        } else {
            SocketOptionEvidence::Rejected {
                raw_os_error: std::io::Error::last_os_error().raw_os_error(),
            }
        }
    }

    fn set_socket_option_i32(
        fd: i32,
        level: i32,
        option: i32,
        value: i32,
        operation: &'static str,
    ) -> Result<(), PlatformError> {
        // SAFETY: value is readable for one i32 and fd owns a socket.
        if unsafe {
            libc::setsockopt(
                fd,
                level,
                option,
                std::ptr::from_ref(&value).cast::<libc::c_void>(),
                mem::size_of_val(&value) as libc::socklen_t,
            )
        } != 0
        {
            return Err(last_error(operation));
        }
        Ok(())
    }

    fn socket_option_i32(
        fd: i32,
        level: i32,
        option: i32,
        operation: &'static str,
    ) -> Result<i32, PlatformError> {
        let mut value = 0_i32;
        let mut length = mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: value and length point to writable storage for one i32 and
        // fd owns a socket.
        if unsafe {
            libc::getsockopt(
                fd,
                level,
                option,
                std::ptr::from_mut(&mut value).cast::<libc::c_void>(),
                &raw mut length,
            )
        } != 0
        {
            return Err(last_error(operation));
        }
        if length as usize != mem::size_of_val(&value) {
            return Err(protocol_error(operation));
        }
        Ok(value)
    }

    fn protocol_error(operation: &'static str) -> PlatformError {
        system_call_error(operation, std::io::Error::from_raw_os_error(libc::EPROTO))
    }

    fn last_error(operation: &'static str) -> PlatformError {
        system_call_error(operation, std::io::Error::last_os_error())
    }

    fn system_call_error(operation: &'static str, source: std::io::Error) -> PlatformError {
        PlatformError::SystemCall { operation, source }
    }

    #[cfg(test)]
    mod tests {
        use std::num::NonZeroU32;
        use std::time::{Duration, Instant};

        use super::*;
        use crate::netlink::{NLMSG_DONE, NLMSG_ERROR, NetlinkMessageIter};

        #[test]
        fn receive_ring_slots_are_fixed_non_overlapping_and_pointer_stable() {
            let mut ring = NetlinkReceiveRing::new();
            let slab_start = ring.slab.as_ptr() as usize;

            for index in 0..RECEIVE_BATCH_SLOTS {
                let expected = slab_start + index * ROUTE_DATAGRAM_CAPACITY;
                assert_eq!(ring.iovecs[index].iov_base as usize, expected);
                assert_eq!(ring.iovecs[index].iov_len, ROUTE_DATAGRAM_CAPACITY);
                assert_eq!(
                    ring.headers[index].msg_hdr.msg_iov,
                    std::ptr::from_mut(&mut ring.iovecs[index])
                );
                assert_eq!(
                    ring.headers[index].msg_hdr.msg_name,
                    std::ptr::from_mut(&mut ring.senders[index]).cast::<libc::c_void>()
                );
                assert_eq!(ring.headers[index].msg_hdr.msg_namelen, SOCKADDR_NL_LENGTH);
            }

            ring.headers[0].msg_hdr.msg_flags = MSG_TRUNC;
            ring.headers[0].msg_len = 99;
            ring.senders[0].port_id = 44;
            ring.prepare();
            assert_eq!(ring.headers[0].msg_hdr.msg_flags, 0);
            assert_eq!(ring.headers[0].msg_len, 0);
            assert_eq!(ring.senders[0], RawNetlinkSocketAddress::default());
        }

        #[test]
        fn opened_socket_is_nonblocking_cloexec_and_subscribed_before_dump() {
            let socket = match RouteNetlinkSocket::open() {
                Ok(socket) => socket,
                Err(PlatformError::SystemCall { source, .. })
                    if source.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    return;
                }
                Err(error) => panic!("open route-netlink socket: {error}"),
            };
            // SAFETY: readiness_fd exposes the live owned descriptor and fcntl
            // with F_GETFL/F_GETFD has no pointer argument.
            let status_flags =
                unsafe { libc::fcntl(socket.readiness_fd().as_raw_fd(), libc::F_GETFL) };
            // SAFETY: same live descriptor; F_GETFD has no pointer argument.
            let descriptor_flags =
                unsafe { libc::fcntl(socket.readiness_fd().as_raw_fd(), libc::F_GETFD) };

            assert_ne!(status_flags & libc::O_NONBLOCK, 0);
            assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
            assert_eq!(
                socket.evidence().subscribed_groups(),
                route_subscription_groups()
            );
            assert!(socket.evidence().effective_receive_buffer_bytes() > 0);
            assert!(
                socket.evidence().effective_receive_buffer_bytes()
                    <= MAX_EFFECTIVE_ROUTE_SOCKET_RECEIVE_BUFFER_BYTES
            );
        }

        #[test]
        fn address_dump_round_trip_retains_kernel_sender_until_matching_done() {
            let socket = match RouteNetlinkSocket::open() {
                Ok(socket) => socket,
                Err(PlatformError::SystemCall { source, .. })
                    if source.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    return;
                }
                Err(error) => panic!("open route-netlink socket: {error}"),
            };
            let sequence = NonZeroU32::new(0x1020_3040).unwrap();
            let request = AddressDumpRequest::all(sequence);
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match socket
                    .send_address_dump(&request)
                    .expect("send address dump")
                {
                    NetlinkSendOutcome::Sent => break,
                    NetlinkSendOutcome::WouldBlock => {
                        wait_for(&socket, libc::POLLOUT, deadline);
                    }
                }
            }

            let mut ring = NetlinkReceiveRing::new();
            loop {
                match socket
                    .receive_batch(&mut ring, NonZeroUsize::new(RECEIVE_BATCH_SLOTS).unwrap())
                    .expect("receive address dump")
                {
                    NetlinkReceiveOutcome::WouldBlock => {
                        wait_for(&socket, libc::POLLIN, deadline);
                    }
                    NetlinkReceiveOutcome::Loss(loss) => {
                        panic!("unexpected route-netlink loss during address dump: {loss:?}");
                    }
                    NetlinkReceiveOutcome::Datagrams(batch) => {
                        assert!(!batch.is_empty());
                        for index in 0..batch.len() {
                            let datagram = batch.datagram(index).expect("received datagram");
                            assert!(datagram.metadata().sender().is_kernel());
                            assert_eq!(
                                datagram.bytes().len(),
                                datagram.metadata().reported_length()
                            );
                            for message in NetlinkMessageIter::new(datagram.bytes()) {
                                let message = message.expect("kernel emitted framed netlink data");
                                if message.header().sequence() != sequence.get() {
                                    continue;
                                }
                                assert_ne!(
                                    message.header().message_type(),
                                    NLMSG_ERROR,
                                    "kernel rejected exact RTM_GETADDR request"
                                );
                                if message.header().message_type() == NLMSG_DONE {
                                    return;
                                }
                            }
                        }
                    }
                }
                assert!(Instant::now() < deadline, "address dump did not complete");
            }
        }

        fn wait_for(socket: &RouteNetlinkSocket, events: i16, deadline: Instant) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "route-netlink readiness timed out");
            let timeout = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
            let mut descriptor = libc::pollfd {
                fd: socket.readiness_fd().as_raw_fd(),
                events,
                revents: 0,
            };
            loop {
                // SAFETY: descriptor points to one initialized pollfd and is
                // writable for the duration of this bounded wait.
                let result = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
                if result > 0 {
                    assert_eq!(descriptor.revents & libc::POLLNVAL, 0);
                    return;
                }
                if result == 0 {
                    panic!("route-netlink readiness timed out");
                }
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EINTR) {
                    panic!("poll route-netlink socket: {source}");
                }
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod implementation {
    use std::marker::PhantomData;
    use std::num::NonZeroUsize;

    use super::{
        AddressDumpRequest, NetlinkDatagram, NetlinkDatagramMetadata, NetlinkReceiveOutcome,
        NetlinkSendOutcome, RouteNetlinkSocketEvidence,
    };
    use crate::PlatformError;

    #[derive(Debug, Default)]
    pub(crate) struct NetlinkReceiveRing;

    impl NetlinkReceiveRing {
        pub(crate) const fn new() -> Self {
            Self
        }
    }

    #[derive(Debug)]
    pub(crate) struct NetlinkDatagramBatch<'a> {
        _lifetime: PhantomData<&'a NetlinkReceiveRing>,
    }

    impl NetlinkDatagramBatch<'_> {
        pub(crate) const fn len(&self) -> usize {
            0
        }

        pub(crate) const fn is_empty(&self) -> bool {
            true
        }

        pub(crate) const fn metadata(&self) -> &[NetlinkDatagramMetadata] {
            &[]
        }

        pub(crate) const fn datagram(&self, _index: usize) -> Option<NetlinkDatagram<'_>> {
            None
        }
    }

    #[derive(Debug)]
    pub(crate) struct RouteNetlinkSocket;

    impl RouteNetlinkSocket {
        pub(crate) fn open() -> Result<Self, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub(crate) fn evidence(&self) -> RouteNetlinkSocketEvidence {
            unreachable!("an unsupported platform cannot construct a route-netlink socket")
        }

        pub(crate) fn send_address_dump(
            &self,
            _request: &AddressDumpRequest,
        ) -> Result<NetlinkSendOutcome, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub(crate) fn receive_batch<'a>(
            &self,
            _ring: &'a mut NetlinkReceiveRing,
            _max_datagrams: NonZeroUsize,
        ) -> Result<NetlinkReceiveOutcome<'a>, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }
    }
}

pub(crate) type NetlinkDatagramBatch<'a> = implementation::NetlinkDatagramBatch<'a>;
pub(crate) type NetlinkReceiveRing = implementation::NetlinkReceiveRing;
pub(crate) type RouteNetlinkSocket = implementation::RouteNetlinkSocket;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_mask_contains_link_address_route_and_rule_groups_for_both_families() {
        let expected = multicast_group_bit(RTNLGRP_LINK)
            | multicast_group_bit(RTNLGRP_IPV4_IFADDR)
            | multicast_group_bit(RTNLGRP_IPV4_ROUTE)
            | multicast_group_bit(RTNLGRP_IPV4_RULE)
            | multicast_group_bit(RTNLGRP_IPV6_IFADDR)
            | multicast_group_bit(RTNLGRP_IPV6_ROUTE)
            | multicast_group_bit(RTNLGRP_IPV6_RULE);

        assert_eq!(route_subscription_groups(), expected);
        assert_eq!(route_subscription_groups(), 0x0004_05d1);
    }

    #[test]
    fn sequence_allocator_wraps_to_one_without_emitting_zero() {
        let mut sequences = NetlinkSequenceAllocator::new(NonZeroU32::new(u32::MAX).unwrap());

        assert_eq!(sequences.allocate().get(), u32::MAX);
        assert_eq!(sequences.allocate().get(), 1);
        assert_eq!(sequences.allocate().get(), 2);
    }

    #[test]
    fn address_dump_builder_emits_exact_af_unspec_rtm_getaddr_request() {
        let sequence = NonZeroU32::new(0x0102_0304).unwrap();
        let all = AddressDumpRequest::all(sequence);

        #[cfg(target_endian = "little")]
        let expected_all = [
            0x18, 0x00, 0x00, 0x00, // nlmsg_len
            0x16, 0x00, // RTM_GETADDR
            0x01, 0x03, // NLM_F_REQUEST | NLM_F_DUMP
            0x04, 0x03, 0x02, 0x01, // sequence
            0x00, 0x00, 0x00, 0x00, // kernel-selected port id
            0x00, 0x00, 0x00, 0x00, // AF_UNSPEC + zeroed ifaddrmsg
            0x00, 0x00, 0x00, 0x00,
        ];
        #[cfg(target_endian = "big")]
        let expected_all = [
            0x00, 0x00, 0x00, 0x18, // nlmsg_len
            0x00, 0x16, // RTM_GETADDR
            0x03, 0x01, // NLM_F_REQUEST | NLM_F_DUMP
            0x01, 0x02, 0x03, 0x04, // sequence
            0x00, 0x00, 0x00, 0x00, // kernel-selected port id
            0x00, 0x00, 0x00, 0x00, // AF_UNSPEC + zeroed ifaddrmsg
            0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(all.as_bytes(), &expected_all);
        assert_eq!(all.sequence(), sequence);
    }

    #[test]
    fn batch_classification_preserves_flags_and_sender_before_accepting_bytes() {
        let sender = NetlinkSenderAddress::new(SOCKADDR_NL_LENGTH, AF_NETLINK, 7, 0, 0x40);
        let metadata = [
            NetlinkDatagramMetadata::new(128, 0x4000, sender),
            NetlinkDatagramMetadata::new(256, 0x8000, sender),
        ];

        assert_eq!(classify_batch(&metadata), BatchIntegrity::Complete);
        let copied = NetlinkBatchMetadata::copy_from(&metadata);
        assert_eq!(copied.entries(), metadata);
        assert_eq!(copied.entries()[0].message_flags(), 0x4000);
        assert_eq!(copied.entries()[1].reported_length(), 256);
        assert_eq!(
            copied.entries()[0].sender().address_length(),
            SOCKADDR_NL_LENGTH
        );
        assert_eq!(copied.entries()[0].sender().family(), AF_NETLINK);
        assert_eq!(copied.entries()[0].sender().padding(), 7);
        assert_eq!(copied.entries()[0].sender().port_id(), 0);
        assert_eq!(copied.entries()[0].sender().groups(), 0x40);
    }

    #[test]
    fn truncated_or_non_kernel_sender_quarantines_the_entire_batch() {
        let kernel = NetlinkSenderAddress::new(SOCKADDR_NL_LENGTH, AF_NETLINK, 0, 0, 0);
        let userspace = NetlinkSenderAddress::new(SOCKADDR_NL_LENGTH, AF_NETLINK, 0, 44, 0);
        let truncated = [
            NetlinkDatagramMetadata::new(64, 0, kernel),
            NetlinkDatagramMetadata::new(ROUTE_DATAGRAM_CAPACITY + 1, MSG_TRUNC, kernel),
        ];
        let foreign = [
            NetlinkDatagramMetadata::new(64, 0, kernel),
            NetlinkDatagramMetadata::new(64, 0, userspace),
        ];

        assert_eq!(classify_batch(&truncated), BatchIntegrity::Truncated);
        assert_eq!(classify_batch(&foreign), BatchIntegrity::UnexpectedSender);
    }
}
