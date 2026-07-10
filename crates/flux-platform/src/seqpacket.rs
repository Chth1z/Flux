#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pid: u32,
    uid: u32,
    gid: u32,
}

impl PeerCredentials {
    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }

    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }

    #[must_use]
    pub const fn is_root(self) -> bool {
        self.uid == 0
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::fs;
    use std::mem::{MaybeUninit, offset_of};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use super::PeerCredentials;
    use crate::PlatformError;

    #[derive(Debug)]
    pub struct SeqpacketListener {
        fd: OwnedFd,
        path: PathBuf,
        socket_inode: u64,
    }

    impl SeqpacketListener {
        pub fn bind(path: impl AsRef<Path>) -> Result<Self, PlatformError> {
            let path = path.as_ref();
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|source| PlatformError::SystemCall {
                    operation: "create Unix socket directory",
                    source,
                })?;
            }

            let fd = create_socket()?;
            let (address, length) = socket_address(path)?;
            // SAFETY: `address` is initialized for `length` bytes and points to
            // a pathname Unix-domain address for the lifetime of this call.
            if bind_socket(fd.as_raw_fd(), &address, length) != 0 {
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EADDRINUSE) {
                    return Err(system_call_error("bind Unix seqpacket socket", source));
                }
                recover_stale_socket(path)?;
                if bind_socket(fd.as_raw_fd(), &address, length) != 0 {
                    return Err(last_error("bind Unix seqpacket socket"));
                }
            }

            // SAFETY: `fd` is a valid Unix seqpacket socket owned by this value.
            if unsafe { libc::listen(fd.as_raw_fd(), 16) } != 0 {
                let error = last_error("listen on Unix seqpacket socket");
                let _ = fs::remove_file(path);
                return Err(error);
            }

            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
                let _ = fs::remove_file(path);
                PlatformError::SystemCall {
                    operation: "set Unix socket permissions",
                    source,
                }
            })?;
            let socket_inode = fs::metadata(path)
                .map_err(|source| PlatformError::SystemCall {
                    operation: "read Unix socket metadata",
                    source,
                })?
                .ino();

            Ok(Self {
                fd,
                path: path.to_owned(),
                socket_inode,
            })
        }

        pub fn accept(&self) -> Result<SeqpacketConnection, PlatformError> {
            accept_connection(self.fd.as_raw_fd())
        }

        pub fn accept_timeout(
            &self,
            timeout: Duration,
        ) -> Result<Option<SeqpacketConnection>, PlatformError> {
            let started = Instant::now();
            loop {
                let elapsed = started.elapsed();
                let remaining = timeout.saturating_sub(elapsed);
                let poll_timeout = duration_to_poll_timeout(remaining);
                let mut descriptor = libc::pollfd {
                    fd: self.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: `descriptor` points to one initialized pollfd and
                // remains writable for the duration of the call.
                let result = unsafe { libc::poll(&raw mut descriptor, 1, poll_timeout) };
                if result > 0 {
                    if descriptor.revents & libc::POLLNVAL != 0 {
                        return Err(system_call_error(
                            "poll Unix seqpacket listener",
                            std::io::Error::from_raw_os_error(libc::EBADF),
                        ));
                    }
                    return self.accept().map(Some);
                }
                if result == 0 {
                    if started.elapsed() >= timeout || timeout.is_zero() {
                        return Ok(None);
                    }
                    continue;
                }
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EINTR) {
                    return Err(system_call_error("poll Unix seqpacket listener", source));
                }
            }
        }
    }

    impl Drop for SeqpacketListener {
        fn drop(&mut self) {
            let Ok(metadata) = fs::symlink_metadata(&self.path) else {
                return;
            };
            if metadata.file_type().is_socket() && metadata.ino() == self.socket_inode {
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    #[derive(Debug)]
    pub struct SeqpacketConnection {
        fd: OwnedFd,
    }

    impl SeqpacketConnection {
        pub fn connect(path: impl AsRef<Path>) -> Result<Self, PlatformError> {
            let fd = create_socket()?;
            let (address, length) = socket_address(path.as_ref())?;
            // SAFETY: `address` is initialized for `length` bytes and the FD is
            // a valid Unix seqpacket socket.
            if unsafe {
                libc::connect(
                    fd.as_raw_fd(),
                    (&raw const address).cast::<libc::sockaddr>(),
                    length,
                )
            } != 0
            {
                return Err(last_error("connect Unix seqpacket socket"));
            }
            Ok(Self { fd })
        }

        pub fn recv_packet(&self, limit: usize) -> Result<Vec<u8>, PlatformError> {
            let capacity = limit.checked_add(1).ok_or_else(|| {
                PlatformError::InvalidSocketPath("packet limit is too large".to_owned())
            })?;
            let mut packet = vec![0_u8; capacity];
            let received = loop {
                // SAFETY: `packet` provides writable storage for `capacity`
                // bytes, and the connection FD remains valid for this call.
                let received = unsafe {
                    libc::recv(
                        self.fd.as_raw_fd(),
                        packet.as_mut_ptr().cast::<libc::c_void>(),
                        capacity,
                        libc::MSG_TRUNC,
                    )
                };
                if received >= 0 {
                    break received;
                }
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EINTR) {
                    return Err(system_call_error("receive Unix seqpacket message", source));
                }
            };
            if received == 0 {
                return Err(PlatformError::PeerClosed);
            }
            let actual = usize::try_from(received)
                .map_err(|_| PlatformError::InvalidSocketPath("negative packet size".to_owned()))?;
            if actual > limit {
                return Err(PlatformError::PacketTooLarge { actual, limit });
            }
            packet.truncate(actual);
            Ok(packet)
        }

        pub fn peer_credentials(&self) -> Result<PeerCredentials, PlatformError> {
            let mut credentials = MaybeUninit::<libc::ucred>::zeroed();
            let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
                .expect("ucred size fits socklen_t");
            loop {
                // SAFETY: `credentials` points to writable storage for one
                // `ucred`, `length` describes that storage, and the connection
                // FD remains valid for this call.
                let result = unsafe {
                    libc::getsockopt(
                        self.fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_PEERCRED,
                        credentials.as_mut_ptr().cast::<libc::c_void>(),
                        &raw mut length,
                    )
                };
                if result == 0 {
                    break;
                }
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EINTR) {
                    return Err(system_call_error(
                        "read Unix seqpacket peer credentials",
                        source,
                    ));
                }
            }
            if usize::try_from(length).ok() != Some(std::mem::size_of::<libc::ucred>()) {
                return Err(system_call_error(
                    "read Unix seqpacket peer credentials",
                    std::io::Error::from_raw_os_error(libc::EPROTO),
                ));
            }
            // SAFETY: a successful `getsockopt(SO_PEERCRED)` initialized the
            // complete `ucred` value and returned its exact size.
            let credentials = unsafe { credentials.assume_init() };
            let pid = u32::try_from(credentials.pid).map_err(|_| {
                system_call_error(
                    "read Unix seqpacket peer credentials",
                    std::io::Error::from_raw_os_error(libc::EPROTO),
                )
            })?;
            Ok(PeerCredentials {
                pid,
                uid: credentials.uid,
                gid: credentials.gid,
            })
        }

        pub fn require_root_peer(&self) -> Result<PeerCredentials, PlatformError> {
            self.require_peer_uid(0)
        }

        pub fn require_same_effective_user(&self) -> Result<PeerCredentials, PlatformError> {
            // SAFETY: `geteuid` has no pointer arguments or preconditions.
            self.require_peer_uid(unsafe { libc::geteuid() })
        }

        pub fn require_peer_uid(
            &self,
            expected_uid: u32,
        ) -> Result<PeerCredentials, PlatformError> {
            let credentials = self.peer_credentials()?;
            if credentials.uid() == expected_uid {
                return Ok(credentials);
            }
            Err(PlatformError::PeerUidMismatch {
                expected_uid,
                pid: credentials.pid(),
                uid: credentials.uid(),
                gid: credentials.gid(),
            })
        }

        pub fn send_packet(&self, packet: &[u8]) -> Result<(), PlatformError> {
            let sent = loop {
                // SAFETY: `packet` is readable for its length and the connection
                // FD remains valid. MSG_NOSIGNAL prevents a peer close from
                // signalling the daemon process.
                let sent = unsafe {
                    libc::send(
                        self.fd.as_raw_fd(),
                        packet.as_ptr().cast::<libc::c_void>(),
                        packet.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                if sent >= 0 {
                    break sent;
                }
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EINTR) {
                    return Err(system_call_error("send Unix seqpacket message", source));
                }
            };
            let actual = usize::try_from(sent).map_err(|_| PlatformError::ShortWrite {
                expected: packet.len(),
                actual: 0,
            })?;
            if actual != packet.len() {
                return Err(PlatformError::ShortWrite {
                    expected: packet.len(),
                    actual,
                });
            }
            Ok(())
        }
    }

    fn create_socket() -> Result<OwnedFd, PlatformError> {
        create_socket_with_flags(0)
    }

    fn create_socket_with_flags(additional_flags: i32) -> Result<OwnedFd, PlatformError> {
        // SAFETY: `socket` has no pointer arguments. On success it returns one
        // new descriptor owned by the caller.
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | additional_flags,
                0,
            )
        };
        if fd < 0 {
            return Err(last_error("create Unix seqpacket socket"));
        }
        // SAFETY: the successful socket call returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn accept_connection(fd: i32) -> Result<SeqpacketConnection, PlatformError> {
        loop {
            // SAFETY: the listener FD is valid. Null address pointers request
            // no peer pathname, and SOCK_CLOEXEC applies to the returned FD.
            let accepted = unsafe {
                libc::accept4(
                    fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if accepted >= 0 {
                // SAFETY: a successful `accept4` returns a new owned descriptor.
                return Ok(SeqpacketConnection {
                    fd: unsafe { OwnedFd::from_raw_fd(accepted) },
                });
            }
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::EINTR) {
                return Err(system_call_error(
                    "accept Unix seqpacket connection",
                    source,
                ));
            }
        }
    }

    fn duration_to_poll_timeout(duration: Duration) -> i32 {
        if duration.is_zero() {
            return 0;
        }
        let millis = duration.as_millis().saturating_add(u128::from(
            !duration.subsec_nanos().is_multiple_of(1_000_000),
        ));
        i32::try_from(millis).unwrap_or(i32::MAX)
    }

    fn bind_socket(fd: i32, address: &libc::sockaddr_un, length: libc::socklen_t) -> i32 {
        // SAFETY: `address` is initialized for `length` bytes and points to a
        // pathname Unix-domain address for the lifetime of this call.
        unsafe {
            libc::bind(
                fd,
                (address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
                length,
            )
        }
    }

    fn recover_stale_socket(path: &Path) -> Result<(), PlatformError> {
        let before = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(system_call_error(
                    "inspect existing Unix socket path",
                    source,
                ));
            }
        };
        if !before.file_type().is_socket() {
            return Err(system_call_error(
                "bind Unix seqpacket socket",
                std::io::Error::from_raw_os_error(libc::EADDRINUSE),
            ));
        }

        let probe = create_socket_with_flags(libc::SOCK_NONBLOCK)?;
        let (address, length) = socket_address(path)?;
        loop {
            // SAFETY: `address` is initialized for `length` bytes and `probe`
            // owns a valid Unix seqpacket socket.
            let result = unsafe {
                libc::connect(
                    probe.as_raw_fd(),
                    (&raw const address).cast::<libc::sockaddr>(),
                    length,
                )
            };
            if result == 0 {
                return Err(system_call_error(
                    "bind Unix seqpacket socket",
                    std::io::Error::from_raw_os_error(libc::EADDRINUSE),
                ));
            }

            let source = std::io::Error::last_os_error();
            match source.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ENOENT) => return Ok(()),
                Some(libc::ECONNREFUSED) => break,
                Some(libc::EAGAIN)
                | Some(libc::EINPROGRESS)
                | Some(libc::EALREADY)
                | Some(libc::EISCONN) => {
                    return Err(system_call_error(
                        "bind Unix seqpacket socket",
                        std::io::Error::from_raw_os_error(libc::EADDRINUSE),
                    ));
                }
                _ => {
                    return Err(system_call_error(
                        "probe existing Unix seqpacket socket",
                        source,
                    ));
                }
            }
        }

        let after = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(system_call_error(
                    "recheck existing Unix socket path",
                    source,
                ));
            }
        };
        if !after.file_type().is_socket()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
        {
            return Err(system_call_error(
                "bind Unix seqpacket socket",
                std::io::Error::from_raw_os_error(libc::EADDRINUSE),
            ));
        }

        fs::remove_file(path)
            .map_err(|source| system_call_error("remove stale Unix socket", source))
    }

    fn socket_address(path: &Path) -> Result<(libc::sockaddr_un, libc::socklen_t), PlatformError> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() {
            return Err(PlatformError::InvalidSocketPath(
                "path must not be empty".to_owned(),
            ));
        }
        if bytes.contains(&0) {
            return Err(PlatformError::InvalidSocketPath(
                "path contains a NUL byte".to_owned(),
            ));
        }

        let mut address = MaybeUninit::<libc::sockaddr_un>::zeroed();
        let address_ptr = address.as_mut_ptr();
        // SAFETY: `address_ptr` points to writable zeroed storage. We write the
        // family and then inspect the fixed sun_path capacity.
        unsafe {
            (*address_ptr).sun_family = libc::AF_UNIX as libc::sa_family_t;
        }
        // SAFETY: the field access is within the allocated sockaddr_un value.
        let path_capacity = unsafe { (*address_ptr).sun_path.len() };
        if bytes.len().saturating_add(1) > path_capacity {
            return Err(PlatformError::InvalidSocketPath(format!(
                "{} is {} bytes; maximum is {}",
                path.display(),
                bytes.len(),
                path_capacity.saturating_sub(1)
            )));
        }
        // SAFETY: the capacity check above proves that the byte string and its
        // existing zero terminator fit in sun_path without overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (*address_ptr).sun_path.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
        }
        let length = offset_of!(libc::sockaddr_un, sun_path)
            .saturating_add(bytes.len())
            .saturating_add(1);
        let length = libc::socklen_t::try_from(length)
            .map_err(|_| PlatformError::InvalidSocketPath("sockaddr length overflow".to_owned()))?;
        // SAFETY: all fields needed by the kernel have been initialized above;
        // the remainder stays zeroed.
        Ok((unsafe { address.assume_init() }, length))
    }

    fn last_error(operation: &'static str) -> PlatformError {
        system_call_error(operation, std::io::Error::last_os_error())
    }

    fn system_call_error(operation: &'static str, source: std::io::Error) -> PlatformError {
        PlatformError::SystemCall { operation, source }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod implementation {
    use std::path::Path;
    use std::time::Duration;

    use super::PeerCredentials;
    use crate::PlatformError;

    #[derive(Debug)]
    pub struct SeqpacketListener;

    impl SeqpacketListener {
        pub fn bind(_path: impl AsRef<Path>) -> Result<Self, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn accept(&self) -> Result<SeqpacketConnection, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn accept_timeout(
            &self,
            _timeout: Duration,
        ) -> Result<Option<SeqpacketConnection>, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }
    }

    #[derive(Debug)]
    pub struct SeqpacketConnection;

    impl SeqpacketConnection {
        pub fn connect(_path: impl AsRef<Path>) -> Result<Self, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn recv_packet(&self, _limit: usize) -> Result<Vec<u8>, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn peer_credentials(&self) -> Result<PeerCredentials, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn require_root_peer(&self) -> Result<PeerCredentials, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn require_same_effective_user(&self) -> Result<PeerCredentials, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn require_peer_uid(
            &self,
            _expected_uid: u32,
        ) -> Result<PeerCredentials, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn send_packet(&self, _packet: &[u8]) -> Result<(), PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }
    }
}

pub use implementation::{SeqpacketConnection, SeqpacketListener};
