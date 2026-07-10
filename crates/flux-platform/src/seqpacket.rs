#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::fs;
    use std::mem::{MaybeUninit, offset_of};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

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
            if unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&raw const address).cast::<libc::sockaddr>(),
                    length,
                )
            } != 0
            {
                return Err(last_error("bind Unix seqpacket socket"));
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
            // SAFETY: the listener FD is valid. Null address pointers request
            // no peer pathname, and SOCK_CLOEXEC applies to the returned FD.
            let fd = unsafe {
                libc::accept4(
                    self.fd.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(last_error("accept Unix seqpacket connection"));
            }
            // SAFETY: a successful `accept4` returns a new owned file descriptor.
            Ok(SeqpacketConnection {
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
            })
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
            // SAFETY: `packet` provides writable storage for `capacity` bytes,
            // and the connection FD remains valid for this call.
            let received = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    packet.as_mut_ptr().cast::<libc::c_void>(),
                    capacity,
                    libc::MSG_TRUNC,
                )
            };
            if received < 0 {
                return Err(last_error("receive Unix seqpacket message"));
            }
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

        pub fn send_packet(&self, packet: &[u8]) -> Result<(), PlatformError> {
            // SAFETY: `packet` is readable for its length and the connection FD
            // remains valid. MSG_NOSIGNAL prevents a peer close from signalling
            // the daemon process.
            let sent = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    packet.as_ptr().cast::<libc::c_void>(),
                    packet.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if sent < 0 {
                return Err(last_error("send Unix seqpacket message"));
            }
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
        // SAFETY: `socket` has no pointer arguments. On success it returns one
        // new descriptor owned by the caller.
        let fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(last_error("create Unix seqpacket socket"));
        }
        // SAFETY: the successful socket call returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
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
        PlatformError::SystemCall {
            operation,
            source: std::io::Error::last_os_error(),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod implementation {
    use std::path::Path;

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

        pub fn send_packet(&self, _packet: &[u8]) -> Result<(), PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }
    }
}

pub use implementation::{SeqpacketConnection, SeqpacketListener};
