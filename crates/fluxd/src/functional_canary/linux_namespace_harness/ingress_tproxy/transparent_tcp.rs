use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

pub(super) struct TransparentTcpListener {
    listener: TcpListener,
    transparent: i32,
    ipv6_only: Option<i32>,
}

impl TransparentTcpListener {
    pub(super) fn bind(family: IpAddr, port: u16) -> Result<Self, String> {
        let (domain, transparent_level, transparent_name, address) = match family {
            IpAddr::V4(_) => (
                libc::AF_INET,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            ),
            IpAddr::V6(_) => (
                libc::AF_INET6,
                libc::SOL_IPV6,
                libc::IPV6_TRANSPARENT,
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
            ),
        };
        let fd = socket_owned(
            domain,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::IPPROTO_TCP,
        )?;
        set_i32_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        set_i32_option(fd.as_raw_fd(), transparent_level, transparent_name, 1)?;
        if domain == libc::AF_INET6 {
            set_i32_option(fd.as_raw_fd(), libc::SOL_IPV6, libc::IPV6_V6ONLY, 1)?;
        }
        bind_fd(fd.as_raw_fd(), address)?;
        // SAFETY: `fd` is a valid stream socket and `listen` does not retain the pointer-free
        // integer arguments.
        let listen_result = unsafe { libc::listen(fd.as_raw_fd(), 8) };
        if listen_result != 0 {
            return Err(format!(
                "listen on transparent TCP socket {address}: {}",
                io::Error::last_os_error()
            ));
        }
        let transparent = get_i32_option(fd.as_raw_fd(), transparent_level, transparent_name)?;
        if transparent != 1 {
            return Err(format!(
                "transparent TCP listener {address} read back {transparent_name}={transparent}"
            ));
        }
        let ipv6_only = if domain == libc::AF_INET6 {
            let value = get_i32_option(fd.as_raw_fd(), libc::SOL_IPV6, libc::IPV6_V6ONLY)?;
            if value != 1 {
                return Err(format!(
                    "transparent IPv6 TCP listener {address} read back IPV6_V6ONLY={value}"
                ));
            }
            Some(value)
        } else {
            None
        };
        let listener = TcpListener::from(fd);
        Ok(Self {
            listener,
            transparent,
            ipv6_only,
        })
    }

    pub(super) fn listener(&self) -> &TcpListener {
        &self.listener
    }

    pub(super) fn local_addr(&self) -> Result<SocketAddr, String> {
        self.listener
            .local_addr()
            .map_err(|error| format!("read transparent TCP listener address: {error}"))
    }

    pub(super) const fn transparent_readback(&self) -> i32 {
        self.transparent
    }

    pub(super) const fn ipv6_only_readback(&self) -> Option<i32> {
        self.ipv6_only
    }

    pub(super) fn set_mark(&self, mark: u32) -> Result<u32, String> {
        set_u32_option(
            self.listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            mark,
        )?;
        let observed = get_u32_option(self.listener.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK)?;
        if observed != mark {
            return Err(format!(
                "transparent TCP listener read back SO_MARK={observed:#x}, expected {mark:#x}"
            ));
        }
        Ok(observed)
    }
}

pub(super) fn connect_marked(
    source: SocketAddr,
    destination: SocketAddr,
    mark: u32,
    timeout: Duration,
) -> Result<(TcpStream, u32), String> {
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(format!(
            "marked TCP source {source} and destination {destination} use different families"
        ));
    }
    let domain = if source.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = socket_owned(
        domain,
        libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        libc::IPPROTO_TCP,
    )?;
    if domain == libc::AF_INET6 {
        set_i32_option(fd.as_raw_fd(), libc::SOL_IPV6, libc::IPV6_V6ONLY, 1)?;
    }
    set_u32_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, mark)?;
    let observed_mark = get_u32_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK)?;
    if observed_mark != mark {
        return Err(format!(
            "marked TCP socket read back SO_MARK={observed_mark:#x}, expected {mark:#x}"
        ));
    }
    bind_fd(fd.as_raw_fd(), source)?;
    connect_fd(fd.as_raw_fd(), destination, timeout)?;
    let stream = TcpStream::from(fd);
    stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(timeout)))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| {
            format!("configure marked TCP stream {source} -> {destination}: {error}")
        })?;
    Ok((stream, observed_mark))
}

pub(super) fn socket_mark(stream: &TcpStream) -> Result<u32, String> {
    get_u32_option(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK)
}

pub(super) fn set_socket_mark(stream: &TcpStream, mark: u32) -> Result<u32, String> {
    set_u32_option(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, mark)?;
    let observed = socket_mark(stream)?;
    if observed != mark {
        return Err(format!(
            "TCP socket read back SO_MARK={observed:#x}, expected {mark:#x}"
        ));
    }
    Ok(observed)
}

pub(super) fn socket_owned(
    domain: i32,
    socket_type: i32,
    protocol: i32,
) -> Result<OwnedFd, String> {
    // SAFETY: `socket` receives only integer constants and returns a new descriptor on success.
    let raw_fd = unsafe { libc::socket(domain, socket_type, protocol) };
    if raw_fd < 0 {
        return Err(format!(
            "create socket domain={domain} type={socket_type:#x}: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: `raw_fd` is a newly returned owned descriptor and is converted exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

pub(super) fn set_i32_option(fd: RawFd, level: i32, name: i32, value: i32) -> Result<(), String> {
    let length = libc::socklen_t::try_from(size_of::<i32>())
        .map_err(|_| "i32 socket-option length does not fit socklen_t".to_owned())?;
    // SAFETY: `value` is initialized, `length` matches it, and `setsockopt` does not retain the
    // pointer.
    let result =
        unsafe { libc::setsockopt(fd, level, name, (&value as *const i32).cast(), length) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "setsockopt fd={fd} level={level} name={name}: {}",
            io::Error::last_os_error()
        ))
    }
}

pub(super) fn set_u32_option(fd: RawFd, level: i32, name: i32, value: u32) -> Result<(), String> {
    let length = libc::socklen_t::try_from(size_of::<u32>())
        .map_err(|_| "u32 socket-option length does not fit socklen_t".to_owned())?;
    // SAFETY: `value` is initialized, `length` matches it, and `setsockopt` does not retain the
    // pointer.
    let result =
        unsafe { libc::setsockopt(fd, level, name, (&value as *const u32).cast(), length) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "setsockopt fd={fd} level={level} name={name}: {}",
            io::Error::last_os_error()
        ))
    }
}

pub(super) fn get_i32_option(fd: RawFd, level: i32, name: i32) -> Result<i32, String> {
    let mut value = 0_i32;
    let mut length = libc::socklen_t::try_from(size_of::<i32>())
        .map_err(|_| "i32 socket-option length does not fit socklen_t".to_owned())?;
    // SAFETY: `value` and `length` are writable and describe the full output buffer.
    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&mut value as *mut i32).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(format!(
            "getsockopt fd={fd} level={level} name={name}: {}",
            io::Error::last_os_error()
        ));
    }
    let expected = libc::socklen_t::try_from(size_of::<i32>())
        .map_err(|_| "i32 socket-option length does not fit socklen_t".to_owned())?;
    if length != expected {
        return Err(format!(
            "getsockopt fd={fd} level={level} name={name} returned length {length}, expected {expected}"
        ));
    }
    Ok(value)
}

pub(super) fn get_u32_option(fd: RawFd, level: i32, name: i32) -> Result<u32, String> {
    let mut value = 0_u32;
    let mut length = libc::socklen_t::try_from(size_of::<u32>())
        .map_err(|_| "u32 socket-option length does not fit socklen_t".to_owned())?;
    // SAFETY: `value` and `length` are writable and describe the full output buffer.
    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&mut value as *mut u32).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(format!(
            "getsockopt fd={fd} level={level} name={name}: {}",
            io::Error::last_os_error()
        ));
    }
    let expected = libc::socklen_t::try_from(size_of::<u32>())
        .map_err(|_| "u32 socket-option length does not fit socklen_t".to_owned())?;
    if length != expected {
        return Err(format!(
            "getsockopt fd={fd} level={level} name={name} returned length {length}, expected {expected}"
        ));
    }
    Ok(value)
}

pub(super) fn bind_fd(fd: RawFd, address: SocketAddr) -> Result<(), String> {
    let result = match address {
        SocketAddr::V4(address) => {
            let raw = sockaddr_in(address.ip(), address.port());
            let length = libc::socklen_t::try_from(size_of::<libc::sockaddr_in>())
                .map_err(|_| "IPv4 socket address length does not fit socklen_t".to_owned())?;
            // SAFETY: `raw` is initialized, `length` matches it, and `bind` does not retain the
            // pointer.
            unsafe { libc::bind(fd, (&raw as *const libc::sockaddr_in).cast(), length) }
        }
        SocketAddr::V6(address) => {
            let raw = sockaddr_in6(
                address.ip(),
                address.port(),
                address.flowinfo(),
                address.scope_id(),
            );
            let length = libc::socklen_t::try_from(size_of::<libc::sockaddr_in6>())
                .map_err(|_| "IPv6 socket address length does not fit socklen_t".to_owned())?;
            // SAFETY: `raw` is initialized, `length` matches it, and `bind` does not retain the
            // pointer.
            unsafe { libc::bind(fd, (&raw as *const libc::sockaddr_in6).cast(), length) }
        }
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "bind socket fd={fd} to {address}: {}",
            io::Error::last_os_error()
        ))
    }
}

pub(super) fn connect_fd(fd: RawFd, address: SocketAddr, timeout: Duration) -> Result<(), String> {
    let result = match address {
        SocketAddr::V4(address) => {
            let raw = sockaddr_in(address.ip(), address.port());
            let length = libc::socklen_t::try_from(size_of::<libc::sockaddr_in>())
                .map_err(|_| "IPv4 socket address length does not fit socklen_t".to_owned())?;
            // SAFETY: `raw` is initialized, `length` matches it, and `connect` does not retain the
            // pointer.
            unsafe { libc::connect(fd, (&raw as *const libc::sockaddr_in).cast(), length) }
        }
        SocketAddr::V6(address) => {
            let raw = sockaddr_in6(
                address.ip(),
                address.port(),
                address.flowinfo(),
                address.scope_id(),
            );
            let length = libc::socklen_t::try_from(size_of::<libc::sockaddr_in6>())
                .map_err(|_| "IPv6 socket address length does not fit socklen_t".to_owned())?;
            // SAFETY: `raw` is initialized, `length` matches it, and `connect` does not retain the
            // pointer.
            unsafe { libc::connect(fd, (&raw as *const libc::sockaddr_in6).cast(), length) }
        }
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EINPROGRESS) {
        return Err(format!("connect socket fd={fd} to {address}: {error}"));
    }

    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!("connect socket fd={fd} to {address} timed out"));
        }
        let milliseconds = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: `poll_fd` is a valid one-element array for the duration of the call.
        let poll_result = unsafe { libc::poll(&mut poll_fd, 1, milliseconds) };
        if poll_result > 0 {
            if poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
                || poll_fd.revents & libc::POLLOUT != 0
            {
                break;
            }
        } else if poll_result == 0 {
            return Err(format!("connect socket fd={fd} to {address} timed out"));
        } else if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(format!(
                "poll connect socket fd={fd} to {address}: {}",
                io::Error::last_os_error()
            ));
        }
    }

    let socket_error = get_i32_option(fd, libc::SOL_SOCKET, libc::SO_ERROR)?;
    if socket_error == 0 {
        Ok(())
    } else {
        Err(format!(
            "connect socket fd={fd} to {address}: {}",
            io::Error::from_raw_os_error(socket_error)
        ))
    }
}

fn sockaddr_in(address: &Ipv4Addr, port: u16) -> libc::sockaddr_in {
    // SAFETY: all fields are initialized immediately below; zero is valid for padding fields.
    let mut raw = unsafe { zeroed::<libc::sockaddr_in>() };
    raw.sin_family = libc::AF_INET as libc::sa_family_t;
    raw.sin_port = port.to_be();
    raw.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(address.octets()),
    };
    raw
}

fn sockaddr_in6(address: &Ipv6Addr, port: u16, flowinfo: u32, scope_id: u32) -> libc::sockaddr_in6 {
    // SAFETY: all fields are initialized immediately below; zero is valid for padding fields.
    let mut raw = unsafe { zeroed::<libc::sockaddr_in6>() };
    raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    raw.sin6_port = port.to_be();
    raw.sin6_flowinfo = flowinfo;
    raw.sin6_addr = libc::in6_addr {
        s6_addr: address.octets(),
    };
    raw.sin6_scope_id = scope_id;
    raw
}
