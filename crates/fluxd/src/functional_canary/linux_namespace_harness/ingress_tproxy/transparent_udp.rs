use std::io;
use std::mem::{size_of, size_of_val, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::AsRawFd;
use std::ptr;
use std::slice;
use std::time::Duration;

use super::transparent_tcp::{
    bind_fd, connect_fd, get_i32_option, get_u32_option, set_i32_option, set_u32_option,
    socket_owned,
};

const CONTROL_WORDS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpFamily {
    Ipv4,
    Ipv6,
}

impl UdpFamily {
    const fn from_ip(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }

    const fn domain(self) -> i32 {
        match self {
            Self::Ipv4 => libc::AF_INET,
            Self::Ipv6 => libc::AF_INET6,
        }
    }

    const fn wildcard(self, port: u16) -> SocketAddr {
        match self {
            Self::Ipv4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            Self::Ipv6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
        }
    }

    const fn transparent_option(self) -> (i32, i32) {
        match self {
            Self::Ipv4 => (libc::SOL_IP, libc::IP_TRANSPARENT),
            Self::Ipv6 => (libc::SOL_IPV6, libc::IPV6_TRANSPARENT),
        }
    }

    const fn original_destination_option(self) -> (i32, i32) {
        match self {
            Self::Ipv4 => (libc::SOL_IP, libc::IP_RECVORIGDSTADDR),
            Self::Ipv6 => (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR),
        }
    }
}

#[repr(C)]
struct ControlBuffer([usize; CONTROL_WORDS]);

pub(super) struct TransparentUdpListener {
    socket: UdpSocket,
    family: UdpFamily,
    transparent: i32,
    receive_original_destination: i32,
    ipv6_only: Option<i32>,
}

#[derive(Debug)]
pub(super) struct ReceivedUdpDatagram {
    pub(super) payload: Vec<u8>,
    pub(super) remote: SocketAddr,
    pub(super) original_destination: SocketAddr,
}

impl TransparentUdpListener {
    pub(super) fn bind(
        family_address: IpAddr,
        port: u16,
        timeout: Duration,
    ) -> Result<Self, String> {
        let family = UdpFamily::from_ip(family_address);
        let domain = family.domain();
        let address = family.wildcard(port);
        let (transparent_level, transparent_name) = family.transparent_option();
        let (original_destination_level, original_destination_name) =
            family.original_destination_option();
        let fd = socket_owned(
            domain,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )?;
        set_i32_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        if family == UdpFamily::Ipv6 {
            set_i32_option(fd.as_raw_fd(), libc::SOL_IPV6, libc::IPV6_V6ONLY, 1)?;
        }
        set_i32_option(fd.as_raw_fd(), transparent_level, transparent_name, 1)?;
        set_i32_option(
            fd.as_raw_fd(),
            original_destination_level,
            original_destination_name,
            1,
        )?;
        bind_fd(fd.as_raw_fd(), address)?;

        let transparent = get_i32_option(fd.as_raw_fd(), transparent_level, transparent_name)?;
        if transparent != 1 {
            return Err(format!(
                "transparent UDP listener {address} read back option {transparent_name}={transparent}"
            ));
        }
        let receive_original_destination = get_i32_option(
            fd.as_raw_fd(),
            original_destination_level,
            original_destination_name,
        )?;
        if receive_original_destination != 1 {
            return Err(format!(
                "transparent UDP listener {address} read back option {original_destination_name}={receive_original_destination}"
            ));
        }
        let ipv6_only = if family == UdpFamily::Ipv6 {
            let value = get_i32_option(fd.as_raw_fd(), libc::SOL_IPV6, libc::IPV6_V6ONLY)?;
            if value != 1 {
                return Err(format!(
                    "transparent IPv6 UDP listener {address} read back IPV6_V6ONLY={value}"
                ));
            }
            Some(value)
        } else {
            None
        };
        let socket = UdpSocket::from(fd);
        socket
            .set_read_timeout(Some(timeout))
            .and_then(|()| socket.set_write_timeout(Some(timeout)))
            .map_err(|error| format!("configure transparent UDP listener {address}: {error}"))?;
        Ok(Self {
            socket,
            family,
            transparent,
            receive_original_destination,
            ipv6_only,
        })
    }

    pub(super) fn local_addr(&self) -> Result<SocketAddr, String> {
        self.socket
            .local_addr()
            .map_err(|error| format!("read transparent UDP listener address: {error}"))
    }

    pub(super) const fn transparent_readback(&self) -> i32 {
        self.transparent
    }

    pub(super) const fn receive_original_destination_readback(&self) -> i32 {
        self.receive_original_destination
    }

    pub(super) const fn ipv6_only_readback(&self) -> Option<i32> {
        self.ipv6_only
    }

    pub(super) fn receive(&self, buffer: &mut [u8]) -> Result<ReceivedUdpDatagram, String> {
        if buffer.is_empty() {
            return Err("transparent UDP receive buffer must not be empty".to_owned());
        }
        // SAFETY: every field is initialized below before the storage is read by `recvmsg`.
        let mut remote = unsafe { zeroed::<libc::sockaddr_storage>() };
        let mut control = ControlBuffer([0; CONTROL_WORDS]);
        let mut io_vector = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        // SAFETY: every pointer and length field is initialized below before the header is passed
        // to `recvmsg`.
        let mut message = unsafe { zeroed::<libc::msghdr>() };
        message.msg_name = (&mut remote as *mut libc::sockaddr_storage).cast();
        message.msg_namelen = libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>())
            .map_err(|_| "sockaddr_storage length does not fit socklen_t".to_owned())?;
        message.msg_iov = &mut io_vector;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen = size_of_val(&control.0);
        // SAFETY: `message` points to live writable name, iovec, and control buffers for the
        // duration of the call. The socket descriptor remains owned by `self`.
        let received = unsafe { libc::recvmsg(self.socket.as_raw_fd(), &mut message, 0) };
        if received < 0 {
            return Err(format!(
                "receive transparent UDP datagram: {}",
                io::Error::last_os_error()
            ));
        }
        let received = usize::try_from(received)
            .map_err(|_| "recvmsg returned a negative UDP payload length".to_owned())?;
        validate_recvmsg_lengths(
            received,
            buffer.len(),
            message.msg_flags,
            message.msg_controllen,
            size_of_val(&control.0),
        )?;
        let remote = decode_socket_address(&remote, message.msg_namelen, self.family, "remote")?;
        // SAFETY: `message.msg_controllen` was checked against the initialized control buffer,
        // whose `usize` backing also provides the alignment required by `cmsghdr`.
        let control_bytes = unsafe {
            slice::from_raw_parts(control.0.as_ptr().cast::<u8>(), message.msg_controllen)
        };
        let original_destination = parse_original_destination(control_bytes, self.family)?;
        Ok(ReceivedUdpDatagram {
            payload: buffer[..received].to_vec(),
            remote,
            original_destination,
        })
    }
}

pub(super) fn connect_marked(
    source: SocketAddr,
    destination: SocketAddr,
    mark: u32,
    timeout: Duration,
) -> Result<(UdpSocket, u32), String> {
    let (socket, observed_mark, transparent) =
        connect_configured(source, destination, mark, timeout, false)?;
    if transparent.is_some() {
        return Err(
            "non-transparent marked UDP socket unexpectedly reported transparency".to_owned(),
        );
    }
    Ok((socket, observed_mark))
}

pub(super) fn connect_transparent_marked(
    source: SocketAddr,
    destination: SocketAddr,
    mark: u32,
    timeout: Duration,
) -> Result<(UdpSocket, u32, i32), String> {
    let (socket, observed_mark, transparent) =
        connect_configured(source, destination, mark, timeout, true)?;
    Ok((
        socket,
        observed_mark,
        transparent.ok_or_else(|| "transparent UDP socket omitted readback".to_owned())?,
    ))
}

pub(super) fn socket_mark(socket: &UdpSocket) -> Result<u32, String> {
    get_u32_option(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK)
}

fn connect_configured(
    source: SocketAddr,
    destination: SocketAddr,
    mark: u32,
    timeout: Duration,
    transparent: bool,
) -> Result<(UdpSocket, u32, Option<i32>), String> {
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(format!(
            "configured UDP source {source} and destination {destination} use different families"
        ));
    }
    let family = UdpFamily::from_ip(source.ip());
    let fd = socket_owned(
        family.domain(),
        libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        libc::IPPROTO_UDP,
    )?;
    if family == UdpFamily::Ipv6 {
        set_i32_option(fd.as_raw_fd(), libc::SOL_IPV6, libc::IPV6_V6ONLY, 1)?;
    }
    let transparent_readback = if transparent {
        let (level, name) = family.transparent_option();
        set_i32_option(fd.as_raw_fd(), level, name, 1)?;
        let observed = get_i32_option(fd.as_raw_fd(), level, name)?;
        if observed != 1 {
            return Err(format!(
                "transparent UDP socket {source} -> {destination} read back option {name}={observed}"
            ));
        }
        Some(observed)
    } else {
        None
    };
    set_u32_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, mark)?;
    let observed_mark = get_u32_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK)?;
    if observed_mark != mark {
        return Err(format!(
            "configured UDP socket read back SO_MARK={observed_mark:#x}, expected {mark:#x}"
        ));
    }
    bind_fd(fd.as_raw_fd(), source)?;
    connect_fd(fd.as_raw_fd(), destination, timeout)?;
    let socket = UdpSocket::from(fd);
    socket
        .set_nonblocking(false)
        .and_then(|()| socket.set_read_timeout(Some(timeout)))
        .and_then(|()| socket.set_write_timeout(Some(timeout)))
        .map_err(|error| format!("configure UDP socket {source} -> {destination}: {error}"))?;
    Ok((socket, observed_mark, transparent_readback))
}

fn parse_original_destination(
    control: &[u8],
    expected_family: UdpFamily,
) -> Result<SocketAddr, String> {
    // SAFETY: a zero data length is valid and the macro-equivalent calculation dereferences no
    // pointers.
    let raw_header_length = unsafe { libc::CMSG_LEN(0) };
    let header_length = usize::try_from(raw_header_length)
        .map_err(|_| "CMSG_LEN(0) does not fit usize".to_owned())?;
    let mut offset = 0;
    let mut original_destination = None;
    while control.len().saturating_sub(offset) >= header_length {
        // SAFETY: the remaining slice contains at least a complete `cmsghdr`; unaligned reads are
        // used because the kernel-provided stream is parsed as bytes.
        let header =
            unsafe { ptr::read_unaligned(control.as_ptr().add(offset).cast::<libc::cmsghdr>()) };
        let control_length = header.cmsg_len;
        let remaining = control.len() - offset;
        if control_length < header_length || control_length > remaining {
            return Err(format!(
                "transparent UDP cmsg has invalid length {control_length}, header={header_length}, remaining={remaining}"
            ));
        }
        let ipv4_original =
            header.cmsg_level == libc::SOL_IP && header.cmsg_type == libc::IP_ORIGDSTADDR;
        let ipv6_original =
            header.cmsg_level == libc::SOL_IPV6 && header.cmsg_type == libc::IPV6_ORIGDSTADDR;
        if ipv4_original || ipv6_original {
            let observed_family = if ipv4_original {
                UdpFamily::Ipv4
            } else {
                UdpFamily::Ipv6
            };
            if observed_family != expected_family {
                return Err(format!(
                    "transparent UDP listener for {expected_family:?} received wrong-family {observed_family:?} original-destination cmsg"
                ));
            }
            if original_destination.is_some() {
                return Err(
                    "transparent UDP datagram contained duplicate original-destination cmsgs"
                        .to_owned(),
                );
            }
            let expected_payload_length = match expected_family {
                UdpFamily::Ipv4 => size_of::<libc::sockaddr_in>(),
                UdpFamily::Ipv6 => size_of::<libc::sockaddr_in6>(),
            };
            let observed_payload_length = control_length - header_length;
            if observed_payload_length != expected_payload_length {
                return Err(format!(
                    "transparent UDP original-destination cmsg for {expected_family:?} has payload length {observed_payload_length}, expected {expected_payload_length}"
                ));
            }
            let payload_offset = offset + header_length;
            let destination = match expected_family {
                UdpFamily::Ipv4 => {
                    // SAFETY: the exact payload length was checked above; an unaligned read avoids
                    // imposing alignment requirements on the byte slice.
                    let address = unsafe {
                        ptr::read_unaligned(
                            control
                                .as_ptr()
                                .add(payload_offset)
                                .cast::<libc::sockaddr_in>(),
                        )
                    };
                    decode_ipv4(address, "original destination")?
                }
                UdpFamily::Ipv6 => {
                    // SAFETY: the exact payload length was checked above; an unaligned read avoids
                    // imposing alignment requirements on the byte slice.
                    let address = unsafe {
                        ptr::read_unaligned(
                            control
                                .as_ptr()
                                .add(payload_offset)
                                .cast::<libc::sockaddr_in6>(),
                        )
                    };
                    decode_ipv6(address, "original destination")?
                }
            };
            original_destination = Some(destination);
        } else {
            return Err(format!(
                "transparent UDP datagram contained unexpected cmsg level={} type={}",
                header.cmsg_level, header.cmsg_type
            ));
        }

        let aligned_length = cmsg_align(control_length);
        if aligned_length > remaining {
            if control_length != remaining {
                return Err(format!(
                    "transparent UDP cmsg alignment {aligned_length} exceeds remaining control bytes {remaining}"
                ));
            }
            offset = control.len();
        } else {
            offset += aligned_length;
        }
    }
    if offset != control.len() && !control.is_empty() {
        return Err(format!(
            "transparent UDP control data has {} trailing bytes without a complete cmsg header",
            control.len() - offset
        ));
    }
    original_destination
        .ok_or_else(|| "transparent UDP datagram omitted original-destination cmsg".to_owned())
}

fn validate_recvmsg_lengths(
    received: usize,
    payload_capacity: usize,
    flags: i32,
    control_length: usize,
    control_capacity: usize,
) -> Result<(), String> {
    if flags & libc::MSG_TRUNC != 0 || received > payload_capacity {
        return Err(format!(
            "transparent UDP datagram was truncated: flags={flags:#x} received={received} capacity={payload_capacity}"
        ));
    }
    if flags & libc::MSG_CTRUNC != 0 {
        return Err(format!(
            "transparent UDP control data was truncated: flags={flags:#x}"
        ));
    }
    if control_length > control_capacity {
        return Err(format!(
            "recvmsg returned control length {control_length} beyond capacity {control_capacity}"
        ));
    }
    Ok(())
}

const fn cmsg_align(length: usize) -> usize {
    (length + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}

fn decode_socket_address(
    storage: &libc::sockaddr_storage,
    length: libc::socklen_t,
    expected_family: UdpFamily,
    label: &str,
) -> Result<SocketAddr, String> {
    let observed_family = i32::from(storage.ss_family);
    match expected_family {
        UdpFamily::Ipv4 => {
            let expected_length = libc::socklen_t::try_from(size_of::<libc::sockaddr_in>())
                .map_err(|_| "sockaddr_in length does not fit socklen_t".to_owned())?;
            if observed_family != libc::AF_INET || length != expected_length {
                return Err(format!(
                    "transparent UDP {label} has family={observed_family} length={length}, expected AF_INET/{expected_length}"
                ));
            }
            // SAFETY: the family and exact returned address length were checked above; storage is
            // large enough for `sockaddr_in` and an unaligned read is used conservatively.
            let address = unsafe {
                ptr::read_unaligned(
                    (storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
                )
            };
            decode_ipv4(address, label)
        }
        UdpFamily::Ipv6 => {
            let expected_length = libc::socklen_t::try_from(size_of::<libc::sockaddr_in6>())
                .map_err(|_| "sockaddr_in6 length does not fit socklen_t".to_owned())?;
            if observed_family != libc::AF_INET6 || length != expected_length {
                return Err(format!(
                    "transparent UDP {label} has family={observed_family} length={length}, expected AF_INET6/{expected_length}"
                ));
            }
            // SAFETY: the family and exact returned address length were checked above; storage is
            // large enough for `sockaddr_in6` and an unaligned read is used conservatively.
            let address = unsafe {
                ptr::read_unaligned(
                    (storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
                )
            };
            decode_ipv6(address, label)
        }
    }
}

fn decode_ipv4(address: libc::sockaddr_in, label: &str) -> Result<SocketAddr, String> {
    if i32::from(address.sin_family) != libc::AF_INET {
        return Err(format!(
            "transparent UDP {label} sockaddr_in has family {}",
            address.sin_family
        ));
    }
    Ok(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(address.sin_port),
    )))
}

fn decode_ipv6(address: libc::sockaddr_in6, label: &str) -> Result<SocketAddr, String> {
    if i32::from(address.sin6_family) != libc::AF_INET6 {
        return Err(format!(
            "transparent UDP {label} sockaddr_in6 has family {}",
            address.sin6_family
        ));
    }
    Ok(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(address.sin6_addr.s6_addr),
        u16::from_be(address.sin6_port),
        // Match `std::net`'s Linux/Android sockaddr conversion and the encoder used by the TCP
        // side of this harness: `sin6_flowinfo` is carried through verbatim.
        address.sin6_flowinfo,
        address.sin6_scope_id,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_of<T>(value: &T) -> &[u8] {
        // SAFETY: the returned slice borrows `value`, covers exactly its initialized storage, and
        // is used only as an immutable byte representation during the call that consumes it.
        unsafe { slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }
    }

    fn encode_cmsg(
        level: i32,
        kind: i32,
        payload: &[u8],
        advertised_payload_length: usize,
    ) -> Vec<u8> {
        let advertised_payload_length = u32::try_from(advertised_payload_length)
            .expect("test ancillary payload length fits u32");
        // SAFETY: the payload length is a bounded test value and the calculation dereferences no
        // pointers.
        let raw_length = unsafe { libc::CMSG_LEN(advertised_payload_length) };
        let control_length = usize::try_from(raw_length).expect("test cmsg length fits usize");
        let total_length = cmsg_align(control_length);
        // SAFETY: every field is assigned below before the header is copied as bytes.
        let mut header = unsafe { zeroed::<libc::cmsghdr>() };
        header.cmsg_len = control_length;
        header.cmsg_level = level;
        header.cmsg_type = kind;
        let mut control = vec![0_u8; total_length];
        // SAFETY: `control` contains at least `CMSG_LEN(0)` bytes and an unaligned write is used.
        unsafe { ptr::write_unaligned(control.as_mut_ptr().cast::<libc::cmsghdr>(), header) };
        let header_length = usize::try_from({
            // SAFETY: a zero payload length is valid and the calculation dereferences no pointers.
            unsafe { libc::CMSG_LEN(0) }
        })
        .expect("test header length fits usize");
        let copied = payload.len().min(control.len() - header_length);
        control[header_length..header_length + copied].copy_from_slice(&payload[..copied]);
        control
    }

    fn ipv4_destination(family: i32) -> libc::sockaddr_in {
        // SAFETY: every semantically relevant field is initialized below and zero is valid for
        // padding.
        let mut address = unsafe { zeroed::<libc::sockaddr_in>() };
        address.sin_family = family as libc::sa_family_t;
        address.sin_port = 41_002_u16.to_be();
        address.sin_addr.s_addr = u32::from_ne_bytes([192, 0, 2, 42]);
        address
    }

    fn ipv6_destination(family: i32) -> libc::sockaddr_in6 {
        // SAFETY: every semantically relevant field is initialized below and zero is valid for
        // padding.
        let mut address = unsafe { zeroed::<libc::sockaddr_in6>() };
        address.sin6_family = family as libc::sa_family_t;
        address.sin6_port = 41_002_u16.to_be();
        address.sin6_addr.s6_addr = Ipv6Addr::LOCALHOST.octets();
        address
    }

    #[test]
    fn cmsg_parser_accepts_exact_ipv4_and_ipv6_original_destinations() {
        let ipv4 = ipv4_destination(libc::AF_INET);
        let ipv4_control = encode_cmsg(
            libc::SOL_IP,
            libc::IP_ORIGDSTADDR,
            bytes_of(&ipv4),
            size_of::<libc::sockaddr_in>(),
        );
        assert_eq!(
            parse_original_destination(&ipv4_control, UdpFamily::Ipv4)
                .expect("exact IPv4 original destination"),
            "192.0.2.42:41002".parse().expect("test IPv4 tuple")
        );

        let mut ipv6 = ipv6_destination(libc::AF_INET6);
        ipv6.sin6_flowinfo = 0x0102_0304;
        ipv6.sin6_scope_id = 7;
        let ipv6_control = encode_cmsg(
            libc::SOL_IPV6,
            libc::IPV6_ORIGDSTADDR,
            bytes_of(&ipv6),
            size_of::<libc::sockaddr_in6>(),
        );
        assert_eq!(
            parse_original_destination(&ipv6_control, UdpFamily::Ipv6)
                .expect("exact IPv6 original destination"),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                41_002,
                0x0102_0304,
                7,
            ))
        );
    }

    #[test]
    fn cmsg_parser_rejects_missing_original_destination() {
        let error = parse_original_destination(&[], UdpFamily::Ipv4)
            .expect_err("missing original destination must fail");
        assert!(error.contains("omitted original-destination"));
    }

    #[test]
    fn cmsg_parser_rejects_duplicate_wrong_family_and_wrong_length() {
        let ipv4 = ipv4_destination(libc::AF_INET);
        let exact = encode_cmsg(
            libc::SOL_IP,
            libc::IP_ORIGDSTADDR,
            bytes_of(&ipv4),
            size_of::<libc::sockaddr_in>(),
        );
        let mut duplicate = exact.clone();
        duplicate.extend_from_slice(&exact);
        assert!(
            parse_original_destination(&duplicate, UdpFamily::Ipv4)
                .expect_err("duplicate cmsg must fail")
                .contains("duplicate")
        );
        assert!(
            parse_original_destination(&exact, UdpFamily::Ipv6)
                .expect_err("wrong-family cmsg must fail")
                .contains("wrong-family")
        );

        let wrong_length = encode_cmsg(
            libc::SOL_IP,
            libc::IP_ORIGDSTADDR,
            bytes_of(&ipv4),
            size_of::<libc::sockaddr_in>() - 1,
        );
        assert!(
            parse_original_destination(&wrong_length, UdpFamily::Ipv4)
                .expect_err("wrong-length cmsg must fail")
                .contains("payload length")
        );
    }

    #[test]
    fn cmsg_parser_rejects_wrong_embedded_family_and_unexpected_control_data() {
        let wrong_family = ipv4_destination(libc::AF_INET6);
        let wrong_family = encode_cmsg(
            libc::SOL_IP,
            libc::IP_ORIGDSTADDR,
            bytes_of(&wrong_family),
            size_of::<libc::sockaddr_in>(),
        );
        assert!(
            parse_original_destination(&wrong_family, UdpFamily::Ipv4)
                .expect_err("wrong embedded family must fail")
                .contains("sockaddr_in has family")
        );

        let unexpected = encode_cmsg(libc::SOL_SOCKET, libc::SCM_RIGHTS, &[0_u8; 4], 4);
        assert!(
            parse_original_destination(&unexpected, UdpFamily::Ipv4)
                .expect_err("unexpected cmsg must fail")
                .contains("unexpected cmsg")
        );
    }

    #[test]
    fn cmsg_parser_rejects_trailing_malformed_control_bytes() {
        let ipv4 = ipv4_destination(libc::AF_INET);
        let mut control = encode_cmsg(
            libc::SOL_IP,
            libc::IP_ORIGDSTADDR,
            bytes_of(&ipv4),
            size_of::<libc::sockaddr_in>(),
        );
        control.push(0);
        assert!(
            parse_original_destination(&control, UdpFamily::Ipv4)
                .expect_err("trailing malformed control data must fail")
                .contains("trailing bytes")
        );
    }

    #[test]
    fn recvmsg_length_validation_rejects_payload_and_control_truncation() {
        assert!(
            validate_recvmsg_lengths(1, 1, libc::MSG_TRUNC, 0, 128)
                .expect_err("MSG_TRUNC must fail")
                .contains("datagram was truncated")
        );
        assert!(
            validate_recvmsg_lengths(1, 1, libc::MSG_CTRUNC, 1, 128)
                .expect_err("MSG_CTRUNC must fail")
                .contains("control data was truncated")
        );
    }
}
