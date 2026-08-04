use std::fmt;

/// A validated Linux/Android user identity.
///
/// The all-ones `uid_t` value is reserved as the kernel's "no identity"
/// sentinel and is therefore excluded from this type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Uid(u32);

impl Uid {
    pub const ROOT: Self = Self(0);

    #[must_use]
    pub const fn from_raw(raw: u32) -> Option<Self> {
        if raw == u32::MAX {
            None
        } else {
            Some(Self(raw))
        }
    }

    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn is_root(self) -> bool {
        self.0 == Self::ROOT.0
    }
}

impl fmt::Display for Uid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pid: u32,
    uid: Uid,
    gid: u32,
}

/// One record-oriented receive outcome from a Unix seqpacket connection.
#[derive(Debug, Eq, PartialEq)]
pub enum SeqpacketReceive {
    /// One complete or prefix-truncated record.
    Record {
        bytes: Vec<u8>,
        truncated: bool,
        credentials: PeerCredentials,
    },
    /// Every peer descriptor has been closed and all queued records are drained.
    Eof,
}

/// One resource-bearing receive outcome from a Unix seqpacket control connection.
#[derive(Debug)]
pub enum SeqpacketConnectionHandoffReceive {
    /// One complete record carrying exactly one validated Unix seqpacket connection.
    Record {
        bytes: Vec<u8>,
        credentials: PeerCredentials,
        connection: SeqpacketConnection,
    },
    /// Every peer descriptor has been closed and all queued records are drained.
    Eof,
}

impl PeerCredentials {
    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }

    #[must_use]
    pub const fn uid(self) -> Uid {
        self.uid
    }

    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }

    #[must_use]
    pub const fn is_root(self) -> bool {
        self.uid.is_root()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::fs;
    use std::mem::{MaybeUninit, offset_of};
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use super::{PeerCredentials, SeqpacketConnectionHandoffReceive, SeqpacketReceive, Uid};
    use crate::PlatformError;

    const RECEIVE_CONTROL_WORDS: usize = 16;

    #[derive(Debug)]
    pub struct SeqpacketListener {
        fd: OwnedFd,
        path: PathBuf,
        socket_inode: u64,
    }

    impl SeqpacketListener {
        pub fn bind(path: impl AsRef<Path>) -> Result<Self, PlatformError> {
            Self::bind_with_socket_flags(path.as_ref(), 0)
        }

        pub(crate) fn bind_nonblocking(path: impl AsRef<Path>) -> Result<Self, PlatformError> {
            Self::bind_with_socket_flags(path.as_ref(), libc::SOCK_NONBLOCK)
        }

        fn bind_with_socket_flags(
            path: &Path,
            additional_flags: i32,
        ) -> Result<Self, PlatformError> {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|source| PlatformError::SystemCall {
                    operation: "create Unix socket directory",
                    source,
                })?;
            }

            let fd = create_socket_with_flags(additional_flags)?;
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

        pub(crate) fn try_accept(&self) -> Result<Option<SeqpacketConnection>, PlatformError> {
            match accept_connection(self.fd.as_raw_fd()) {
                Ok(connection) => Ok(Some(connection)),
                Err(PlatformError::SystemCall { source, .. })
                    if source.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        }

        pub(crate) fn readiness_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
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

    #[derive(Debug)]
    enum RawSeqpacketReceive {
        Record {
            bytes: Vec<u8>,
            actual: usize,
            truncated: bool,
            control: ReceivedRecordControl,
        },
        Eof,
    }

    #[derive(Debug, Default)]
    struct ReceivedRecordControl {
        credentials: Option<PeerCredentials>,
        credential_messages: usize,
        invalid_credentials: bool,
        rights_messages: usize,
        descriptors: Vec<OwnedFd>,
        invalid_descriptors: bool,
        unexpected_messages: usize,
        truncated: bool,
    }

    /// The exact ancillary byte range returned by one successful `recvmsg` call.
    ///
    /// This token is deliberately non-cloneable: parsing it transfers ownership of every distinct
    /// descriptor installed by `SCM_RIGHTS` into one `ReceivedRecordControl`.
    struct InstalledControl<'a> {
        bytes: &'a [u8],
    }

    impl<'a> InstalledControl<'a> {
        /// # Safety
        ///
        /// Every distinct nonnegative descriptor encoded in an `SCM_RIGHTS` message must have been
        /// installed for this process by the represented `recvmsg` call and must not already have a
        /// Rust owner. The caller must create at most one token for that receive result.
        unsafe fn from_recvmsg(bytes: &'a [u8]) -> Self {
            Self { bytes }
        }
    }

    struct ControlMessage<'a> {
        level: libc::c_int,
        kind: libc::c_int,
        payload: &'a [u8],
        complete: bool,
    }

    struct ControlMessageCursor<'a> {
        control: &'a [u8],
        header_length: usize,
        header_offset: usize,
        finished: bool,
    }

    impl<'a> ControlMessageCursor<'a> {
        fn new(control: &'a [u8]) -> Result<Self, PlatformError> {
            Ok(Self {
                control,
                header_length: control_message_header_length()?,
                header_offset: 0,
                finished: false,
            })
        }
    }

    impl<'a> Iterator for ControlMessageCursor<'a> {
        type Item = Result<ControlMessage<'a>, PlatformError>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.finished
                || self.control.len().saturating_sub(self.header_offset) < self.header_length
            {
                self.finished = true;
                return None;
            }

            let result = self.next_message();
            if result.is_err() {
                self.finished = true;
            }
            Some(result)
        }
    }

    impl<'a> ControlMessageCursor<'a> {
        fn next_message(&mut self) -> Result<ControlMessage<'a>, PlatformError> {
            let cmsg_len = read_control_usize(
                self.control,
                checked_field_offset(self.header_offset, offset_of!(libc::cmsghdr, cmsg_len))?,
            )
            .ok_or_else(|| protocol_error("truncated Unix seqpacket control header"))?;
            let level = read_control_c_int(
                self.control,
                checked_field_offset(self.header_offset, offset_of!(libc::cmsghdr, cmsg_level))?,
            )
            .ok_or_else(|| protocol_error("truncated Unix seqpacket control header"))?;
            let kind = read_control_c_int(
                self.control,
                checked_field_offset(self.header_offset, offset_of!(libc::cmsghdr, cmsg_type))?,
            )
            .ok_or_else(|| protocol_error("truncated Unix seqpacket control header"))?;
            if cmsg_len < self.header_length {
                return Err(protocol_error(
                    "invalid Unix seqpacket control header length",
                ));
            }

            let reported_end = self
                .header_offset
                .checked_add(cmsg_len)
                .ok_or_else(|| protocol_error("Unix seqpacket control length overflow"))?;
            let available_end = reported_end.min(self.control.len());
            let payload_offset = self
                .header_offset
                .checked_add(self.header_length)
                .ok_or_else(|| protocol_error("Unix seqpacket control offset overflow"))?;
            let complete = reported_end <= self.control.len();
            let message = ControlMessage {
                level,
                kind,
                payload: &self.control[payload_offset..available_end],
                complete,
            };
            if !complete {
                self.finished = true;
                return Ok(message);
            }

            let aligned_length = checked_control_message_align(cmsg_len)
                .ok_or_else(|| protocol_error("Unix seqpacket control alignment overflow"))?;
            let next_offset = self
                .header_offset
                .checked_add(aligned_length)
                .ok_or_else(|| protocol_error("Unix seqpacket control offset overflow"))?;
            if self.control.len().saturating_sub(next_offset) < self.header_length {
                self.finished = true;
            } else {
                self.header_offset = next_offset;
            }
            Ok(message)
        }
    }

    impl ReceivedRecordControl {
        fn canonical_credentials(&self) -> Result<PeerCredentials, PlatformError> {
            if self.truncated {
                return Err(protocol_error("truncated Unix seqpacket control data"));
            }
            if self.invalid_credentials {
                return Err(protocol_error(
                    "invalid Unix seqpacket SCM_CREDENTIALS payload",
                ));
            }
            if self.unexpected_messages != 0 {
                return Err(protocol_error("unexpected Unix seqpacket ancillary data"));
            }
            if self.credential_messages != 1 {
                return Err(protocol_error(if self.credential_messages == 0 {
                    "missing Unix seqpacket SCM_CREDENTIALS"
                } else {
                    "duplicate Unix seqpacket SCM_CREDENTIALS"
                }));
            }
            self.credentials
                .ok_or_else(|| protocol_error("invalid Unix seqpacket SCM_CREDENTIALS payload"))
        }

        fn require_canonical_credentials(self) -> Result<PeerCredentials, PlatformError> {
            let credentials = self.canonical_credentials()?;
            if self.rights_messages != 0 {
                return Err(protocol_error("unexpected Unix seqpacket ancillary data"));
            }
            Ok(credentials)
        }

        fn require_canonical_connection_handoff(
            mut self,
        ) -> Result<(PeerCredentials, OwnedFd), PlatformError> {
            let credentials = self.canonical_credentials()?;
            if self.rights_messages != 1 {
                return Err(protocol_error(if self.rights_messages == 0 {
                    "missing Unix seqpacket SCM_RIGHTS"
                } else {
                    "duplicate Unix seqpacket SCM_RIGHTS"
                }));
            }
            if self.invalid_descriptors {
                return Err(protocol_error("invalid Unix seqpacket SCM_RIGHTS payload"));
            }
            if self.descriptors.len() != 1 {
                return Err(protocol_error(
                    "Unix seqpacket SCM_RIGHTS must contain exactly one descriptor",
                ));
            }
            let descriptor = self
                .descriptors
                .pop()
                .expect("one validated descriptor remains owned");
            Ok((credentials, descriptor))
        }
    }

    impl SeqpacketConnection {
        pub fn pair() -> Result<(Self, Self), PlatformError> {
            let mut descriptors = [-1; 2];
            loop {
                // SAFETY: `descriptors` points to writable storage for two FDs.
                // On success, socketpair initializes both with new descriptors
                // owned by the caller.
                let result = unsafe {
                    libc::socketpair(
                        libc::AF_UNIX,
                        libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                        0,
                        descriptors.as_mut_ptr(),
                    )
                };
                if result == 0 {
                    break;
                }
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EINTR) {
                    return Err(system_call_error(
                        "create anonymous Unix seqpacket pair",
                        source,
                    ));
                }
                descriptors = [-1; 2];
            }

            // SAFETY: the successful socketpair call initialized both entries
            // with distinct new descriptors, each owned by the corresponding
            // connection below.
            let first = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
            // SAFETY: see the ownership argument above for the second entry.
            let second = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
            enable_record_credentials(first.as_raw_fd())?;
            enable_record_credentials(second.as_raw_fd())?;
            Ok((Self { fd: first }, Self { fd: second }))
        }

        pub(crate) fn inherited_descriptor(&self) -> libc::c_int {
            self.fd.as_raw_fd()
        }

        /// Claims one descriptor that crossed an exact child `exec` with close-on-exec cleared.
        ///
        /// # Safety
        ///
        /// `descriptor` must name the caller's sole unowned copy of the inherited endpoint. No
        /// other Rust value may own it, and no concurrent code may close or replace it while this
        /// function validates and claims it.
        pub(crate) unsafe fn claim_inherited(
            descriptor: libc::c_int,
        ) -> Result<Self, PlatformError> {
            if descriptor < 3 {
                return Err(handoff_error(
                    "inherited Unix seqpacket descriptor overlaps standard streams",
                ));
            }
            // SAFETY: the caller guarantees this is the sole unowned inherited descriptor. Taking
            // ownership before validation makes every subsequent rejection close it fail-closed.
            let fd = unsafe { OwnedFd::from_raw_fd(descriptor) };
            let flags = descriptor_flags(fd.as_raw_fd())?;
            if flags & libc::FD_CLOEXEC != 0 {
                return Err(handoff_error(
                    "inherited Unix seqpacket descriptor did not cross exec",
                ));
            }
            validate_connection_object(fd.as_raw_fd())?;
            set_descriptor_close_on_exec(fd.as_raw_fd(), flags)?;
            enable_record_credentials(fd.as_raw_fd())?;
            Ok(Self { fd })
        }

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
            let received = loop {
                match self.recv_record(limit, 0) {
                    Ok(received) => break received,
                    Err(PlatformError::SystemCall { source, .. })
                        if source.raw_os_error() == Some(libc::EINTR) => {}
                    Err(error) => return Err(error),
                }
            };
            match received {
                RawSeqpacketReceive::Record {
                    bytes,
                    actual,
                    truncated,
                    control,
                } => {
                    control.require_canonical_credentials()?;
                    if truncated {
                        return Err(PlatformError::PacketTooLarge { actual, limit });
                    }
                    Ok(bytes)
                }
                RawSeqpacketReceive::Eof => Err(PlatformError::PeerClosed),
            }
        }

        pub fn recv_record_until(
            &self,
            limit: usize,
            exclusive_deadline: Instant,
        ) -> Result<Option<SeqpacketReceive>, PlatformError> {
            match self.recv_record_until_raw(limit, exclusive_deadline)? {
                Some(RawSeqpacketReceive::Record {
                    bytes,
                    truncated,
                    control,
                    ..
                }) => {
                    let credentials = control.require_canonical_credentials()?;
                    Ok(Some(SeqpacketReceive::Record {
                        bytes,
                        truncated,
                        credentials,
                    }))
                }
                Some(RawSeqpacketReceive::Eof) => Ok(Some(SeqpacketReceive::Eof)),
                None => Ok(None),
            }
        }

        pub fn recv_connection_until(
            &self,
            limit: usize,
            exclusive_deadline: Instant,
        ) -> Result<Option<SeqpacketConnectionHandoffReceive>, PlatformError> {
            match self.recv_record_until_raw(limit, exclusive_deadline)? {
                Some(RawSeqpacketReceive::Record {
                    bytes,
                    actual,
                    truncated,
                    control,
                }) => {
                    let (credentials, descriptor) =
                        control.require_canonical_connection_handoff()?;
                    if truncated {
                        return Err(PlatformError::PacketTooLarge { actual, limit });
                    }
                    let connection = validate_transferred_connection(descriptor)?;
                    Ok(Some(SeqpacketConnectionHandoffReceive::Record {
                        bytes,
                        credentials,
                        connection,
                    }))
                }
                Some(RawSeqpacketReceive::Eof) => Ok(Some(SeqpacketConnectionHandoffReceive::Eof)),
                None => Ok(None),
            }
        }

        fn recv_record_until_raw(
            &self,
            limit: usize,
            exclusive_deadline: Instant,
        ) -> Result<Option<RawSeqpacketReceive>, PlatformError> {
            checked_packet_capacity(limit)?;
            loop {
                let now = Instant::now();
                if now >= exclusive_deadline {
                    return Ok(None);
                }
                let remaining = exclusive_deadline.saturating_duration_since(now);
                let mut descriptor = libc::pollfd {
                    fd: self.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: `descriptor` points to one initialized pollfd and
                // remains writable for the duration of the call.
                let result = unsafe {
                    libc::poll(&raw mut descriptor, 1, duration_to_poll_timeout(remaining))
                };
                if result == 0 {
                    continue;
                }
                if result < 0 {
                    let source = std::io::Error::last_os_error();
                    if source.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(system_call_error("poll Unix seqpacket connection", source));
                }
                if Instant::now() >= exclusive_deadline {
                    return Ok(None);
                }
                if descriptor.revents & libc::POLLNVAL != 0 {
                    return Err(system_call_error(
                        "poll Unix seqpacket connection",
                        std::io::Error::from_raw_os_error(libc::EBADF),
                    ));
                }

                match self.recv_record(limit, libc::MSG_DONTWAIT) {
                    Ok(received) => return Ok(Some(received)),
                    Err(PlatformError::SystemCall { source, .. })
                        if source.kind() == std::io::ErrorKind::WouldBlock
                            || source.raw_os_error() == Some(libc::EINTR) => {}
                    Err(error) => return Err(error),
                }
            }
        }

        fn recv_record(
            &self,
            limit: usize,
            additional_flags: libc::c_int,
        ) -> Result<RawSeqpacketReceive, PlatformError> {
            let mut bytes = packet_buffer(limit)?;
            let mut control = [0_usize; RECEIVE_CONTROL_WORDS];
            let mut iovec = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast::<libc::c_void>(),
                iov_len: bytes.len(),
            };
            // SAFETY: zero initializes all optional address and control-buffer
            // fields to null/zero before the one payload iovec is attached.
            let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
            message.msg_iov = &raw mut iovec;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
            message.msg_controllen = std::mem::size_of_val(&control);

            // SAFETY: `message` references one writable iovec backed by
            // `bytes`, and the connection FD remains valid for this call.
            let received = unsafe {
                libc::recvmsg(
                    self.fd.as_raw_fd(),
                    &raw mut message,
                    libc::MSG_CMSG_CLOEXEC | libc::MSG_TRUNC | additional_flags,
                )
            };
            if received < 0 {
                return Err(last_error("receive Unix seqpacket message"));
            }
            let control_truncated = message.msg_flags & libc::MSG_CTRUNC != 0;
            let control_bytes = control_buffer_bytes(&control);
            let Some(received_control) = control_bytes.get(..message.msg_controllen) else {
                // The kernel must never report more control data than the supplied buffer. Close
                // every descriptor that can be parsed from the complete buffer before rejecting
                // an impossible length so even this defensive path cannot leak installed rights.
                // SAFETY: this is the sole ownership token created for the completed recvmsg. The
                // full zero-initialized buffer contains every descriptor the kernel could install.
                let installed = unsafe { InstalledControl::from_recvmsg(control_bytes) };
                inspect_received_record_control(installed, true)?;
                return Err(protocol_error("invalid Unix seqpacket control length"));
            };
            let actual = usize::try_from(received).map_err(|_| {
                system_call_error(
                    "receive Unix seqpacket message",
                    std::io::Error::from_raw_os_error(libc::EOVERFLOW),
                )
            })?;
            // Linux does not set MSG_EOR on an empty AF_UNIX seqpacket record.
            // SO_PASSCRED supplies a control message for every real record,
            // including an empty one, while drained EOF has no control data.
            if actual == 0 && message.msg_controllen == 0 && !control_truncated {
                return Ok(RawSeqpacketReceive::Eof);
            }
            // SAFETY: this is the sole ownership token created for the successful recvmsg result.
            // SCM_RIGHTS entries in its returned control range are newly installed descriptors.
            let installed = unsafe { InstalledControl::from_recvmsg(received_control) };
            let control = inspect_received_record_control(installed, control_truncated)?;

            let stored = actual.min(limit);
            bytes.truncate(stored);
            Ok(RawSeqpacketReceive::Record {
                bytes,
                actual,
                truncated: actual > limit || message.msg_flags & libc::MSG_TRUNC != 0,
                control,
            })
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
            let uid = Uid::from_raw(credentials.uid).ok_or_else(|| {
                system_call_error(
                    "read Unix seqpacket peer credentials",
                    std::io::Error::from_raw_os_error(libc::EPROTO),
                )
            })?;
            Ok(PeerCredentials {
                pid,
                uid,
                gid: credentials.gid,
            })
        }

        pub fn require_root_peer(&self) -> Result<PeerCredentials, PlatformError> {
            self.require_peer_uid(Uid::ROOT)
        }

        pub fn require_same_effective_user(&self) -> Result<PeerCredentials, PlatformError> {
            // SAFETY: `geteuid` has no pointer arguments or preconditions.
            let effective_uid = Uid::from_raw(unsafe { libc::geteuid() }).ok_or_else(|| {
                system_call_error(
                    "read daemon effective UID",
                    std::io::Error::from_raw_os_error(libc::EPROTO),
                )
            })?;
            self.require_peer_uid(effective_uid)
        }

        pub fn require_peer_uid(
            &self,
            expected_uid: Uid,
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
            self.send_record(packet, None)
        }

        pub fn send_connection(
            &self,
            payload: &[u8],
            connection: &SeqpacketConnection,
        ) -> Result<(), PlatformError> {
            self.send_record(payload, Some(connection))
        }

        /// Transfers a borrowed endpoint only if the complete record can be queued before the
        /// exclusive deadline.
        ///
        /// A `false` result sends no record and leaves `connection` owned by the caller.
        pub fn send_connection_until(
            &self,
            payload: &[u8],
            connection: &SeqpacketConnection,
            exclusive_deadline: Instant,
        ) -> Result<bool, PlatformError> {
            self.send_record_until(payload, Some(connection), exclusive_deadline)
        }

        fn send_record(
            &self,
            packet: &[u8],
            connection: Option<&SeqpacketConnection>,
        ) -> Result<(), PlatformError> {
            loop {
                match self.send_record_once(packet, connection, 0) {
                    Ok(()) => return Ok(()),
                    Err(PlatformError::SystemCall { source, .. })
                        if source.raw_os_error() == Some(libc::EINTR) => {}
                    Err(error) => return Err(error),
                }
            }
        }

        fn send_record_until(
            &self,
            packet: &[u8],
            connection: Option<&SeqpacketConnection>,
            exclusive_deadline: Instant,
        ) -> Result<bool, PlatformError> {
            loop {
                let now = Instant::now();
                if now >= exclusive_deadline {
                    return Ok(false);
                }
                let remaining = exclusive_deadline.saturating_duration_since(now);
                let mut descriptor = libc::pollfd {
                    fd: self.fd.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: `descriptor` points to one initialized pollfd and remains writable for
                // the duration of the call.
                let result = unsafe {
                    libc::poll(&raw mut descriptor, 1, duration_to_poll_timeout(remaining))
                };
                if result == 0 {
                    continue;
                }
                if result < 0 {
                    let source = std::io::Error::last_os_error();
                    if source.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(system_call_error("poll Unix seqpacket connection", source));
                }
                if Instant::now() >= exclusive_deadline {
                    return Ok(false);
                }
                if descriptor.revents & libc::POLLNVAL != 0 {
                    return Err(system_call_error(
                        "poll Unix seqpacket connection",
                        std::io::Error::from_raw_os_error(libc::EBADF),
                    ));
                }

                match self.send_record_once(packet, connection, libc::MSG_DONTWAIT) {
                    Ok(()) => return Ok(true),
                    Err(PlatformError::SystemCall { source, .. })
                        if source.kind() == std::io::ErrorKind::WouldBlock
                            || source.raw_os_error() == Some(libc::EINTR) => {}
                    Err(error) => return Err(error),
                }
            }
        }

        fn send_record_once(
            &self,
            packet: &[u8],
            connection: Option<&SeqpacketConnection>,
            additional_flags: libc::c_int,
        ) -> Result<(), PlatformError> {
            let mut iovec = libc::iovec {
                iov_base: packet.as_ptr().cast_mut().cast::<libc::c_void>(),
                iov_len: packet.len(),
            };
            // SAFETY: zero initializes every optional msghdr field before the payload and
            // optional aligned control buffer are attached below.
            let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
            message.msg_iov = &raw mut iovec;
            message.msg_iovlen = 1;

            let mut control = connection
                .map(|connection| single_descriptor_control(connection.fd.as_raw_fd()))
                .transpose()?;
            if let Some(control) = control.as_mut() {
                message.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
                message.msg_controllen = std::mem::size_of_val(control.as_slice());
            }

            // SAFETY: `message` references the immutable payload through one iovec and, when
            // present, one initialized SCM_RIGHTS record. All borrowed connection descriptors
            // remain live for the call. MSG_NOSIGNAL suppresses process-directed SIGPIPE.
            let sent = unsafe {
                libc::sendmsg(
                    self.fd.as_raw_fd(),
                    &raw const message,
                    libc::MSG_NOSIGNAL | additional_flags,
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

    fn single_descriptor_control(descriptor: libc::c_int) -> Result<Vec<usize>, PlatformError> {
        let payload_length = std::mem::size_of::<libc::c_int>();
        let control_space = control_message_space(payload_length)
            .ok_or_else(|| protocol_error("Unix seqpacket control space overflow"))?;
        let control_length = control_message_length(payload_length)
            .ok_or_else(|| protocol_error("Unix seqpacket control length overflow"))?;
        if !control_space.is_multiple_of(std::mem::size_of::<usize>()) {
            return Err(protocol_error("unaligned Unix seqpacket control space"));
        }
        let mut control = vec![0_usize; control_space / std::mem::size_of::<usize>()];
        let header = control.as_mut_ptr().cast::<libc::cmsghdr>();
        let payload_offset = control_message_header_length()?;
        // SAFETY: the word-backed vector is aligned for cmsghdr and contains CMSG_SPACE(c_int)
        // zeroed bytes. The payload offset is CMSG_LEN(0), so both writes stay within that buffer.
        unsafe {
            (*header).cmsg_len = control_length;
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            control
                .as_mut_ptr()
                .cast::<u8>()
                .add(payload_offset)
                .cast::<libc::c_int>()
                .write(descriptor);
        }
        Ok(control)
    }

    fn checked_packet_capacity(limit: usize) -> Result<usize, PlatformError> {
        limit
            .checked_add(1)
            .ok_or_else(|| PlatformError::InvalidSocketPath("packet limit is too large".to_owned()))
    }

    fn packet_buffer(limit: usize) -> Result<Vec<u8>, PlatformError> {
        let capacity = checked_packet_capacity(limit)?;
        let mut bytes = vec![0_u8; capacity];
        bytes.truncate(limit);
        Ok(bytes)
    }

    fn control_buffer_bytes(control: &[usize]) -> &[u8] {
        // SAFETY: a byte slice may inspect every initialized byte of the word-aligned control
        // buffer. The returned slice retains the source lifetime and does not outlive it.
        unsafe {
            std::slice::from_raw_parts(
                control.as_ptr().cast::<u8>(),
                std::mem::size_of_val(control),
            )
        }
    }

    fn inspect_received_record_control(
        control: InstalledControl<'_>,
        control_truncated: bool,
    ) -> Result<ReceivedRecordControl, PlatformError> {
        let mut inspection = ReceivedRecordControl {
            truncated: control_truncated,
            ..ReceivedRecordControl::default()
        };
        let messages = ControlMessageCursor::new(control.bytes)?;

        for message in messages {
            let ControlMessage {
                level,
                kind,
                payload,
                complete,
            } = message?;
            match (level, kind) {
                (libc::SOL_SOCKET, libc::SCM_RIGHTS) => {
                    inspection.rights_messages = inspection
                        .rights_messages
                        .checked_add(1)
                        .ok_or_else(|| protocol_error("Unix seqpacket control count overflow"))?;
                    // SAFETY: `InstalledControl` proves every distinct nonnegative descriptor in
                    // this SCM_RIGHTS payload is newly installed and currently unowned.
                    if !unsafe { own_descriptor_payload(payload, &mut inspection.descriptors) } {
                        inspection.invalid_descriptors = true;
                    }
                }
                (libc::SOL_SOCKET, libc::SCM_CREDENTIALS) => {
                    inspection.credential_messages = inspection
                        .credential_messages
                        .checked_add(1)
                        .ok_or_else(|| protocol_error("Unix seqpacket control count overflow"))?;
                    if !complete {
                        inspection.invalid_credentials = true;
                    } else {
                        match parse_record_credentials(payload) {
                            Some(credentials) => {
                                inspection.credentials.get_or_insert(credentials);
                            }
                            None => inspection.invalid_credentials = true,
                        }
                    }
                }
                _ => {
                    inspection.unexpected_messages = inspection
                        .unexpected_messages
                        .checked_add(1)
                        .ok_or_else(|| protocol_error("Unix seqpacket control count overflow"))?;
                }
            }

            if !complete {
                return if control_truncated {
                    Ok(inspection)
                } else {
                    Err(protocol_error("truncated Unix seqpacket control message"))
                };
            }
        }
        Ok(inspection)
    }

    fn parse_record_credentials(payload: &[u8]) -> Option<PeerCredentials> {
        if payload.len() != std::mem::size_of::<libc::ucred>() {
            return None;
        }
        let raw_pid = read_control_c_int(payload, offset_of!(libc::ucred, pid))?;
        let pid = u32::try_from(raw_pid).ok().filter(|pid| *pid != 0)?;
        let uid = read_control_u32(payload, offset_of!(libc::ucred, uid))?;
        let uid = Uid::from_raw(uid)?;
        let gid = read_control_u32(payload, offset_of!(libc::ucred, gid))?;
        if gid == u32::MAX {
            return None;
        }
        Some(PeerCredentials { pid, uid, gid })
    }

    /// # Safety
    ///
    /// Every distinct nonnegative descriptor encoded by `payload` must be newly installed in this
    /// process and must not have another Rust owner. Duplicate raw numbers are permitted and are
    /// deliberately claimed only once.
    unsafe fn own_descriptor_payload(payload: &[u8], owned: &mut Vec<OwnedFd>) -> bool {
        let mut valid = true;
        let mut descriptors = payload.chunks_exact(std::mem::size_of::<libc::c_int>());
        for descriptor in &mut descriptors {
            let descriptor = libc::c_int::from_ne_bytes(
                descriptor
                    .try_into()
                    .expect("chunks_exact yields one native c_int"),
            );
            if descriptor < 0
                || owned
                    .iter()
                    .any(|owned_descriptor| owned_descriptor.as_raw_fd() == descriptor)
            {
                valid = false;
                continue;
            }
            // SAFETY: SCM_RIGHTS installed a new descriptor in this process. No earlier payload
            // entry claimed this raw number, so this creates its single Rust owner.
            owned.push(unsafe { OwnedFd::from_raw_fd(descriptor) });
        }
        valid && descriptors.remainder().is_empty()
    }

    fn read_control_usize(control: &[u8], offset: usize) -> Option<usize> {
        let end = offset.checked_add(std::mem::size_of::<usize>())?;
        Some(usize::from_ne_bytes(
            control.get(offset..end)?.try_into().ok()?,
        ))
    }

    fn read_control_c_int(control: &[u8], offset: usize) -> Option<libc::c_int> {
        let end = offset.checked_add(std::mem::size_of::<libc::c_int>())?;
        Some(libc::c_int::from_ne_bytes(
            control.get(offset..end)?.try_into().ok()?,
        ))
    }

    fn read_control_u32(control: &[u8], offset: usize) -> Option<u32> {
        let end = offset.checked_add(std::mem::size_of::<u32>())?;
        Some(u32::from_ne_bytes(
            control.get(offset..end)?.try_into().ok()?,
        ))
    }

    fn checked_field_offset(
        header_offset: usize,
        field_offset: usize,
    ) -> Result<usize, PlatformError> {
        header_offset
            .checked_add(field_offset)
            .ok_or_else(|| protocol_error("Unix seqpacket control field offset overflow"))
    }

    fn checked_control_message_align(length: usize) -> Option<usize> {
        let mask = std::mem::size_of::<usize>() - 1;
        length.checked_add(mask).map(|length| length & !mask)
    }

    fn control_message_header_length() -> Result<usize, PlatformError> {
        checked_control_message_align(std::mem::size_of::<libc::cmsghdr>())
            .ok_or_else(|| protocol_error("Unix seqpacket control header alignment overflow"))
    }

    fn control_message_space(payload_length: usize) -> Option<usize> {
        control_message_header_length()
            .ok()?
            .checked_add(checked_control_message_align(payload_length)?)
    }

    fn control_message_length(payload_length: usize) -> Option<usize> {
        control_message_header_length()
            .ok()?
            .checked_add(payload_length)
    }

    fn protocol_error(message: &'static str) -> PlatformError {
        system_call_error(
            "parse Unix seqpacket control data",
            std::io::Error::new(std::io::ErrorKind::InvalidData, message),
        )
    }

    fn handoff_error(message: &'static str) -> PlatformError {
        system_call_error(
            "validate Unix seqpacket connection handoff",
            std::io::Error::new(std::io::ErrorKind::InvalidData, message),
        )
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
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        enable_record_credentials(fd.as_raw_fd())?;
        Ok(fd)
    }

    fn validate_transferred_connection(fd: OwnedFd) -> Result<SeqpacketConnection, PlatformError> {
        let descriptor_flags = descriptor_flags(fd.as_raw_fd())?;
        if descriptor_flags & libc::FD_CLOEXEC == 0 {
            return Err(handoff_error(
                "transferred Unix seqpacket descriptor is not close-on-exec",
            ));
        }
        validate_connection_object(fd.as_raw_fd())?;
        enable_record_credentials(fd.as_raw_fd())?;
        Ok(SeqpacketConnection { fd })
    }

    fn validate_connection_object(fd: libc::c_int) -> Result<(), PlatformError> {
        let domain = socket_integer_option(fd, libc::SO_DOMAIN, "read transferred socket domain")?;
        if domain != libc::AF_UNIX {
            return Err(handoff_error(
                "transferred connection is not an AF_UNIX socket",
            ));
        }
        let socket_type = socket_integer_option(fd, libc::SO_TYPE, "read transferred socket type")?;
        if socket_type != libc::SOCK_SEQPACKET {
            return Err(handoff_error(
                "transferred connection is not a SOCK_SEQPACKET socket",
            ));
        }
        let accepting = socket_integer_option(
            fd,
            libc::SO_ACCEPTCONN,
            "read transferred socket listener state",
        )?;
        if accepting != 0 {
            return Err(handoff_error(
                "transferred Unix seqpacket socket is a listener",
            ));
        }
        require_connected_peer(fd)
    }

    fn require_connected_peer(fd: libc::c_int) -> Result<(), PlatformError> {
        // SAFETY: all-zero is a valid initialized sockaddr_storage value. getpeername may overwrite
        // at most the exact storage length supplied below.
        let mut peer = unsafe { std::mem::zeroed::<libc::sockaddr_storage>() };
        let mut length = libc::socklen_t::try_from(std::mem::size_of_val(&peer))
            .expect("sockaddr_storage length fits socklen_t");
        loop {
            // SAFETY: peer is writable sockaddr storage, length names its capacity, and fd remains
            // owned and live for the duration of the call.
            let result = unsafe {
                libc::getpeername(
                    fd,
                    (&raw mut peer).cast::<libc::sockaddr>(),
                    &raw mut length,
                )
            };
            if result == 0 {
                let length = usize::try_from(length).map_err(|_| {
                    handoff_error("transferred Unix seqpacket peer address length is invalid")
                })?;
                if length < std::mem::size_of::<libc::sa_family_t>()
                    || length > std::mem::size_of_val(&peer)
                {
                    return Err(handoff_error(
                        "transferred Unix seqpacket peer address length is invalid",
                    ));
                }
                return Ok(());
            }
            let source = std::io::Error::last_os_error();
            match source.raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::ENOTCONN) => {
                    return Err(handoff_error(
                        "transferred Unix seqpacket socket is not connected",
                    ));
                }
                _ => return Err(system_call_error("read transferred socket peer", source)),
            }
        }
    }

    fn descriptor_flags(fd: libc::c_int) -> Result<libc::c_int, PlatformError> {
        loop {
            // SAFETY: fd names an owned live descriptor and F_GETFD has no pointer argument.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags >= 0 {
                return Ok(flags);
            }
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::EINTR) {
                return Err(system_call_error(
                    "read transferred descriptor flags",
                    source,
                ));
            }
        }
    }

    fn set_descriptor_close_on_exec(
        fd: libc::c_int,
        flags: libc::c_int,
    ) -> Result<(), PlatformError> {
        loop {
            // SAFETY: fd names the inherited live descriptor and F_SETFD consumes one scalar flag
            // value. The caller immediately establishes its sole Rust owner after success.
            let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
            if result == 0 {
                return Ok(());
            }
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::EINTR) {
                return Err(system_call_error(
                    "restore close-on-exec on inherited Unix seqpacket descriptor",
                    source,
                ));
            }
        }
    }

    fn socket_integer_option(
        fd: libc::c_int,
        option: libc::c_int,
        operation: &'static str,
    ) -> Result<libc::c_int, PlatformError> {
        let mut value = 0 as libc::c_int;
        let mut length = libc::socklen_t::try_from(std::mem::size_of_val(&value))
            .expect("integer socket option length fits socklen_t");
        loop {
            // SAFETY: value is writable storage for one integer, length describes that storage,
            // and fd remains owned for the duration of the getsockopt call.
            let result = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    (&raw mut value).cast::<libc::c_void>(),
                    &raw mut length,
                )
            };
            if result == 0 {
                break;
            }
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::EINTR) {
                return Err(system_call_error(operation, source));
            }
        }
        if usize::try_from(length).ok() != Some(std::mem::size_of_val(&value)) {
            return Err(system_call_error(
                operation,
                std::io::Error::from_raw_os_error(libc::EPROTO),
            ));
        }
        Ok(value)
    }

    fn enable_record_credentials(fd: libc::c_int) -> Result<(), PlatformError> {
        let enabled: libc::c_int = 1;
        loop {
            // SAFETY: `enabled` is a fully initialized integer socket-option
            // value and `fd` names a live AF_UNIX socket owned by the caller.
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&raw const enabled).cast::<libc::c_void>(),
                    libc::socklen_t::try_from(std::mem::size_of_val(&enabled))
                        .expect("socket option length fits socklen_t"),
                )
            };
            if result == 0 {
                return Ok(());
            }
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::EINTR) {
                return Err(system_call_error(
                    "enable Unix seqpacket record credentials",
                    source,
                ));
            }
        }
    }

    fn accept_connection(fd: i32) -> Result<SeqpacketConnection, PlatformError> {
        loop {
            // SAFETY: the listener FD is valid. Null address pointers request
            // no peer pathname, and SOCK_CLOEXEC applies to the returned FD.
            // SOCK_NONBLOCK is deliberately omitted so a reactor-ready listener
            // still hands blocking connections to its worker threads.
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
                let accepted_fd = unsafe { OwnedFd::from_raw_fd(accepted) };
                enable_record_credentials(accepted_fd.as_raw_fd())?;
                return Ok(SeqpacketConnection { fd: accepted_fd });
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

    #[cfg(test)]
    mod record_control_tests {
        use std::net::TcpListener;
        use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
        use std::thread;
        use std::time::{Duration, Instant};

        use super::{
            ControlMessageCursor, InstalledControl, RECEIVE_CONTROL_WORDS, RawSeqpacketReceive,
            ReceivedRecordControl, SeqpacketConnection, SeqpacketListener, control_buffer_bytes,
            control_message_header_length, control_message_length, control_message_space,
            create_socket, inspect_received_record_control, validate_transferred_connection,
        };
        use crate::PlatformError;
        use crate::seqpacket::{PeerCredentials, SeqpacketConnectionHandoffReceive, Uid};

        #[test]
        fn record_control_requires_one_canonical_kernel_credential() {
            let credentials = current_credentials();
            let canonical = credential_control(credentials);
            assert_eq!(
                inspect_synthetic_record_control(control_buffer_bytes(&canonical), false)
                    .expect("inspect canonical credentials")
                    .require_canonical_credentials()
                    .expect("canonical credentials are required"),
                credentials
            );

            let missing = inspect_synthetic_record_control(&[], false)
                .expect("inspect absent credentials")
                .require_canonical_credentials()
                .expect_err("credentials are mandatory");
            assert!(
                missing
                    .to_string()
                    .contains("missing Unix seqpacket SCM_CREDENTIALS")
            );

            let mut duplicate = canonical.clone();
            duplicate.extend_from_slice(&canonical);
            let duplicate =
                inspect_synthetic_record_control(control_buffer_bytes(&duplicate), false)
                    .expect("inspect duplicate credentials")
                    .require_canonical_credentials()
                    .expect_err("duplicate credentials are not canonical");
            assert!(
                duplicate
                    .to_string()
                    .contains("duplicate Unix seqpacket SCM_CREDENTIALS")
            );

            let truncated =
                inspect_synthetic_record_control(control_buffer_bytes(&canonical), true)
                    .expect("inspect truncated credentials")
                    .require_canonical_credentials()
                    .expect_err("truncated control is not evidence");
            assert!(
                truncated
                    .to_string()
                    .contains("truncated Unix seqpacket control data")
            );
        }

        #[test]
        fn record_control_rejects_malformed_or_unknown_ancillary_data() {
            let credentials = current_credentials();
            let mut malformed = credential_control(credentials);
            write_control_usize(
                control_buffer_bytes_mut(&mut malformed),
                std::mem::offset_of!(libc::cmsghdr, cmsg_len),
                control_message_length(std::mem::size_of::<libc::ucred>() - 1)
                    .expect("malformed credential length"),
            );
            let malformed =
                inspect_synthetic_record_control(control_buffer_bytes(&malformed), false)
                    .expect("inspect malformed credentials")
                    .require_canonical_credentials()
                    .expect_err("malformed credentials are not evidence");
            assert!(
                malformed
                    .to_string()
                    .contains("invalid Unix seqpacket SCM_CREDENTIALS payload")
            );

            let mut unknown = credential_control(credentials);
            write_control_c_int(
                control_buffer_bytes_mut(&mut unknown),
                std::mem::offset_of!(libc::cmsghdr, cmsg_type),
                libc::SCM_CREDENTIALS + 1,
            );
            let unknown = inspect_synthetic_record_control(control_buffer_bytes(&unknown), false)
                .expect("inspect unknown ancillary data")
                .require_canonical_credentials()
                .expect_err("unknown ancillary data is not evidence");
            assert!(
                unknown
                    .to_string()
                    .contains("unexpected Unix seqpacket ancillary data")
            );
        }

        #[test]
        fn closes_received_file_descriptors_after_record_classification() {
            let (producer, collector) = SeqpacketConnection::pair().expect("create pair");
            let (read_end, write_end) = nonblocking_pipe();

            send_file_descriptors(&producer, read_end.as_raw_fd(), 1);
            drop(read_end);
            let error = collector
                .recv_record_until(1, Instant::now() + Duration::from_secs(1))
                .expect_err("SCM_RIGHTS is not valid record evidence");
            assert!(
                error
                    .to_string()
                    .contains("unexpected Unix seqpacket ancillary data")
            );

            assert_writer_has_no_readers(&write_end);
        }

        #[test]
        fn credential_and_ancillary_rejection_closes_every_handoff_descriptor() {
            let credentials = current_credentials();
            let (malformed_read_end, malformed_write_end) = nonblocking_pipe();
            let mut malformed = credential_control(credentials);
            write_control_usize(
                control_buffer_bytes_mut(&mut malformed),
                std::mem::offset_of!(libc::cmsghdr, cmsg_len),
                control_message_length(std::mem::size_of::<libc::ucred>() - 1)
                    .expect("malformed credential length"),
            );
            malformed.extend(rights_control(&[malformed_read_end.into_raw_fd()]));

            let malformed_error =
                inspect_synthetic_record_control(control_buffer_bytes(&malformed), false)
                    .expect("inspect malformed credentials with rights")
                    .require_canonical_connection_handoff()
                    .expect_err("malformed credentials reject the handoff");
            assert!(
                malformed_error
                    .to_string()
                    .contains("invalid Unix seqpacket SCM_CREDENTIALS payload")
            );
            assert_writer_has_no_readers(&malformed_write_end);

            let (unexpected_read_end, unexpected_write_end) = nonblocking_pipe();
            let mut unexpected = credential_control(credentials);
            let mut unknown = credential_control(credentials);
            write_control_c_int(
                control_buffer_bytes_mut(&mut unknown),
                std::mem::offset_of!(libc::cmsghdr, cmsg_type),
                libc::SCM_CREDENTIALS + 1,
            );
            unexpected.extend(unknown);
            unexpected.extend(rights_control(&[unexpected_read_end.into_raw_fd()]));

            let unexpected_error =
                inspect_synthetic_record_control(control_buffer_bytes(&unexpected), false)
                    .expect("inspect unrelated ancillary data with rights")
                    .require_canonical_connection_handoff()
                    .expect_err("unrelated ancillary data rejects the handoff");
            assert!(
                unexpected_error
                    .to_string()
                    .contains("unexpected Unix seqpacket ancillary data")
            );
            assert_writer_has_no_readers(&unexpected_write_end);
        }

        #[test]
        fn connection_handoff_rejects_a_non_socket_and_closes_it() {
            let (producer, collector) = SeqpacketConnection::pair().expect("create pair");
            let (read_end, write_end) = nonblocking_pipe();

            send_file_descriptors(&producer, read_end.as_raw_fd(), 1);
            drop(read_end);
            let error = collector
                .recv_connection_until(1, Instant::now() + Duration::from_secs(1))
                .expect_err("a pipe is not a typed seqpacket connection");
            assert!(error.to_string().contains("read transferred socket domain"));
            assert_writer_has_no_readers(&write_end);
        }

        #[test]
        fn connection_handoff_rejects_multiple_descriptors_and_closes_all_of_them() {
            let (producer, collector) = SeqpacketConnection::pair().expect("create pair");
            let (read_end, write_end) = nonblocking_pipe();

            send_file_descriptors(&producer, read_end.as_raw_fd(), 2);
            drop(read_end);
            let error = collector
                .recv_connection_until(1, Instant::now() + Duration::from_secs(1))
                .expect_err("a handoff record must contain one descriptor");
            assert!(
                error
                    .to_string()
                    .contains("SCM_RIGHTS must contain exactly one descriptor")
            );
            assert_writer_has_no_readers(&write_end);
        }

        #[test]
        fn connection_handoff_requires_one_rights_message() {
            let (producer, collector) = SeqpacketConnection::pair().expect("create pair");
            producer
                .send_packet(b"x")
                .expect("send descriptor-free record");

            let error = collector
                .recv_connection_until(1, Instant::now() + Duration::from_secs(1))
                .expect_err("a handoff record requires SCM_RIGHTS");
            assert!(
                error
                    .to_string()
                    .contains("missing Unix seqpacket SCM_RIGHTS")
            );
        }

        #[test]
        fn connection_handoff_rejects_duplicate_rights_messages_and_closes_every_descriptor() {
            let credentials = current_credentials();
            let (first_read_end, first_write_end) = nonblocking_pipe();
            let (second_read_end, second_write_end) = nonblocking_pipe();
            let mut control = credential_control(credentials);
            control.extend(rights_control(&[first_read_end.into_raw_fd()]));
            control.extend(rights_control(&[second_read_end.into_raw_fd()]));

            let error = inspect_synthetic_record_control(control_buffer_bytes(&control), false)
                .expect("inspect duplicate rights messages")
                .require_canonical_connection_handoff()
                .expect_err("duplicate rights messages are not canonical");
            assert!(
                error
                    .to_string()
                    .contains("duplicate Unix seqpacket SCM_RIGHTS")
            );
            assert_writer_has_no_readers(&first_write_end);
            assert_writer_has_no_readers(&second_write_end);
        }

        #[test]
        fn duplicate_descriptor_numbers_are_owned_and_closed_exactly_once() {
            let credentials = current_credentials();
            let (read_end, write_end) = nonblocking_pipe();
            let raw_read_end = read_end.into_raw_fd();
            let mut control = credential_control(credentials);
            control.extend(rights_control(&[raw_read_end, raw_read_end]));

            let error = inspect_synthetic_record_control(control_buffer_bytes(&control), false)
                .expect("inspect duplicate descriptor numbers")
                .require_canonical_connection_handoff()
                .expect_err("duplicate raw descriptor ownership is invalid");
            assert!(
                error
                    .to_string()
                    .contains("invalid Unix seqpacket SCM_RIGHTS payload")
            );
            assert_writer_has_no_readers(&write_end);
        }

        #[test]
        fn transferred_connection_requires_close_on_exec() {
            let (candidate, peer) = SeqpacketConnection::pair().expect("create pair");
            // SAFETY: candidate owns a live descriptor and these fcntl commands have no pointer
            // arguments. Clearing FD_CLOEXEC deliberately constructs the rejected boundary case.
            let flags = unsafe { libc::fcntl(candidate.fd.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0, "read descriptor flags");
            // SAFETY: see the descriptor-ownership argument above.
            let clear_result = unsafe {
                libc::fcntl(
                    candidate.fd.as_raw_fd(),
                    libc::F_SETFD,
                    flags & !libc::FD_CLOEXEC,
                )
            };
            assert_eq!(
                clear_result,
                0,
                "clear close-on-exec: {}",
                std::io::Error::last_os_error()
            );
            let SeqpacketConnection { fd } = candidate;

            let error = validate_transferred_connection(fd)
                .expect_err("a transferred endpoint must be close-on-exec");
            assert!(error.to_string().contains("is not close-on-exec"));
            assert_eq!(
                peer.recv_record_until(1, Instant::now() + Duration::from_secs(1))
                    .expect("observe rejected endpoint close"),
                Some(crate::seqpacket::SeqpacketReceive::Eof)
            );
        }

        #[test]
        fn transferred_connection_requires_unix_seqpacket_socket_identity() {
            let inet_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .expect("bind Internet listener");
            let inet_address = inet_listener.local_addr().expect("listener address");
            // SAFETY: into_raw_fd relinquishes the listener's exact descriptor to this OwnedFd.
            let inet_socket = unsafe { OwnedFd::from_raw_fd(inet_listener.into_raw_fd()) };
            let domain_error = validate_transferred_connection(inet_socket)
                .expect_err("a transferred endpoint must be AF_UNIX");
            assert!(
                domain_error
                    .to_string()
                    .contains("is not an AF_UNIX socket")
            );
            let rebound_listener =
                TcpListener::bind(inet_address).expect("rebind released Internet listener address");
            drop(rebound_listener);

            let (stream_socket, stream_peer) = unix_socket_pair(libc::SOCK_STREAM);
            let type_error = validate_transferred_connection(stream_socket)
                .expect_err("a transferred endpoint must be SOCK_SEQPACKET");
            assert!(
                type_error
                    .to_string()
                    .contains("is not a SOCK_SEQPACKET socket")
            );
            let mut byte = 0_u8;
            // SAFETY: byte is writable for one byte and stream_peer owns a live connected socket.
            let received = unsafe {
                libc::recv(
                    stream_peer.as_raw_fd(),
                    (&raw mut byte).cast::<libc::c_void>(),
                    1,
                    0,
                )
            };
            assert_eq!(received, 0, "rejected stream endpoint must be closed");
        }

        #[test]
        fn transferred_connection_requires_a_connected_non_listener_socket() {
            let unconnected = create_socket().expect("create unconnected Unix seqpacket socket");
            let unconnected_error = validate_transferred_connection(unconnected)
                .expect_err("an unconnected socket is not a connection");
            assert!(unconnected_error.to_string().contains("is not connected"));

            let directory = tempfile::tempdir().expect("temporary directory");
            let listener = SeqpacketListener::bind(directory.path().join("listener.sock"))
                .expect("bind Unix seqpacket listener");
            let listener_copy = duplicate_owned_fd(listener.fd.as_raw_fd());
            let listener_error = validate_transferred_connection(listener_copy)
                .expect_err("a listener is not a connection");
            assert!(listener_error.to_string().contains("is a listener"));
        }

        #[test]
        fn deterministic_arbitrary_control_layouts_never_panic() {
            let maximum_length = std::mem::size_of::<[usize; RECEIVE_CONTROL_WORDS]>() * 2;
            for seed in 0_u64..64 {
                let mut state = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
                for length in 0..=maximum_length {
                    let mut control = vec![0_u8; length];
                    for byte in &mut control {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        *byte = state as u8;
                    }
                    let messages =
                        ControlMessageCursor::new(&control).expect("control header layout");
                    for message in messages {
                        if message.is_err() {
                            break;
                        }
                    }
                }
            }

            let header_length = control_message_header_length().expect("control header length");
            for cmsg_len in [0, header_length - 1, header_length, usize::MAX] {
                let mut control = vec![0_u8; header_length * 3];
                write_control_usize(
                    &mut control,
                    std::mem::offset_of!(libc::cmsghdr, cmsg_len),
                    cmsg_len,
                );
                let messages = ControlMessageCursor::new(&control).expect("control header layout");
                for message in messages {
                    if message.is_err() {
                        break;
                    }
                }
            }
        }

        #[test]
        fn connection_handoff_reenables_record_credentials() {
            let (control_sender, control_receiver) =
                SeqpacketConnection::pair().expect("create control pair");
            let (candidate, peer) = SeqpacketConnection::pair().expect("create endpoint pair");
            set_record_credentials(candidate.fd.as_raw_fd(), false);

            control_sender
                .send_connection(b"x", &candidate)
                .expect("transfer endpoint");
            drop(candidate);
            let received = control_receiver
                .recv_connection_until(1, Instant::now() + Duration::from_secs(1))
                .expect("receive endpoint")
                .expect("handoff must arrive");
            let SeqpacketConnectionHandoffReceive::Record { connection, .. } = received else {
                panic!("queued handoff cannot be EOF");
            };

            peer.send_packet(b"proof")
                .expect("send credentialled record");
            assert_eq!(
                connection
                    .recv_packet(5)
                    .expect("promoted endpoint receives kernel credentials"),
                b"proof"
            );
        }

        #[test]
        fn exact_control_buffer_fill_closes_every_received_descriptor() {
            let (producer, collector) = SeqpacketConnection::pair().expect("create pair");
            let (read_end, write_end) = nonblocking_pipe();
            let descriptor_count = exact_fill_descriptor_count();

            send_file_descriptors(&producer, read_end.as_raw_fd(), descriptor_count);
            drop(read_end);
            let received = collector
                .recv_record(1, 0)
                .expect("receive exact-fill record");
            let RawSeqpacketReceive::Record {
                bytes,
                truncated,
                control,
                ..
            } = received
            else {
                panic!("descriptor record cannot be EOF");
            };
            assert_eq!(bytes, b"x");
            assert!(!truncated);
            assert!(
                !control.truncated,
                "credentials plus rights must exactly fill the receive control buffer"
            );
            assert_eq!(control.credential_messages, 1);
            assert_eq!(control.rights_messages, 1);
            assert_eq!(control.descriptors.len(), descriptor_count);
            control
                .require_canonical_credentials()
                .expect_err("ordinary records reject rights");
            assert_writer_has_no_readers(&write_end);
        }

        #[test]
        fn truncated_multi_descriptor_control_closes_every_installed_descriptor() {
            let (producer, collector) = SeqpacketConnection::pair().expect("create pair");
            let (read_end, write_end) = nonblocking_pipe();
            let exact_fill_count = exact_fill_descriptor_count();
            let descriptor_count = exact_fill_count + 32;
            let sent_control_space =
                control_message_space(descriptor_count * std::mem::size_of::<libc::c_int>())
                    .expect("sent control size");
            let credential_space = control_message_space(std::mem::size_of::<libc::ucred>())
                .expect("credential control size");
            assert!(
                sent_control_space + credential_space
                    > std::mem::size_of::<[usize; RECEIVE_CONTROL_WORDS]>()
            );

            send_file_descriptors(&producer, read_end.as_raw_fd(), descriptor_count);
            drop(read_end);
            let received = collector
                .recv_record(1, 0)
                .expect("receive truncated control");
            let RawSeqpacketReceive::Record {
                bytes,
                truncated,
                control,
                ..
            } = received
            else {
                panic!("descriptor record cannot be EOF");
            };
            assert_eq!(bytes, b"x");
            assert!(!truncated);
            assert!(control.truncated, "receive must exercise MSG_CTRUNC");
            control
                .require_canonical_credentials()
                .expect_err("truncated control is rejected");
            assert_writer_has_no_readers(&write_end);
        }

        #[test]
        fn writer_reader_absence_waits_for_a_transient_inherited_reader() {
            let (read_end, write_end) = nonblocking_pipe();
            let transient_reader = duplicate_owned_fd(read_end.as_raw_fd());
            let release = thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                drop(transient_reader);
            });
            drop(read_end);

            assert_writer_has_no_readers(&write_end);
            release.join().expect("join transient pipe reader");
        }

        fn exact_fill_descriptor_count() -> usize {
            let receive_control_bytes = std::mem::size_of::<[usize; RECEIVE_CONTROL_WORDS]>();
            let credential_space = control_message_space(std::mem::size_of::<libc::ucred>())
                .expect("credential control size");
            let rights_space = receive_control_bytes
                .checked_sub(credential_space)
                .expect("receive buffer holds credentials");
            let header_length = control_message_header_length().expect("control header length");
            let rights_payload = rights_space
                .checked_sub(header_length)
                .expect("receive buffer holds a rights header");
            assert_eq!(control_message_space(rights_payload), Some(rights_space));
            assert_eq!(rights_payload % std::mem::size_of::<libc::c_int>(), 0);
            rights_payload / std::mem::size_of::<libc::c_int>()
        }

        fn inspect_synthetic_record_control(
            control: &[u8],
            control_truncated: bool,
        ) -> Result<ReceivedRecordControl, PlatformError> {
            // SAFETY: test callers surrender every distinct descriptor encoded in SCM_RIGHTS with
            // into_raw_fd before this call. Descriptor-free controls satisfy the same contract
            // vacuously, and this helper creates exactly one ownership token per test buffer.
            let installed = unsafe { InstalledControl::from_recvmsg(control) };
            inspect_received_record_control(installed, control_truncated)
        }

        fn duplicate_owned_fd(fd: libc::c_int) -> OwnedFd {
            loop {
                // SAFETY: fd names a live descriptor and F_DUPFD_CLOEXEC returns a distinct owned
                // descriptor at or above the scalar lower bound.
                let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
                if duplicate >= 0 {
                    // SAFETY: successful F_DUPFD_CLOEXEC returned one new owned descriptor.
                    return unsafe { OwnedFd::from_raw_fd(duplicate) };
                }
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EINTR) {
                    panic!("duplicate descriptor: {source}");
                }
            }
        }

        fn current_credentials() -> PeerCredentials {
            // SAFETY: these process identity getters have no pointer arguments or preconditions.
            let raw_pid = unsafe { libc::getpid() };
            // SAFETY: see the process-ID call above.
            let raw_uid = unsafe { libc::geteuid() };
            // SAFETY: see the process-ID call above.
            let raw_gid = unsafe { libc::getegid() };
            PeerCredentials {
                pid: u32::try_from(raw_pid).expect("positive process ID"),
                uid: Uid::from_raw(raw_uid).expect("valid effective UID"),
                gid: raw_gid,
            }
        }

        fn credential_control(credentials: PeerCredentials) -> Vec<usize> {
            let payload_length = std::mem::size_of::<libc::ucred>();
            let control_space = control_message_space(payload_length).expect("credential space");
            let control_length = control_message_length(payload_length).expect("credential length");
            let mut control = vec![0_usize; control_space / std::mem::size_of::<usize>()];
            let control_bytes = control_buffer_bytes_mut(&mut control);
            write_control_usize(
                control_bytes,
                std::mem::offset_of!(libc::cmsghdr, cmsg_len),
                control_length,
            );
            write_control_c_int(
                control_bytes,
                std::mem::offset_of!(libc::cmsghdr, cmsg_level),
                libc::SOL_SOCKET,
            );
            write_control_c_int(
                control_bytes,
                std::mem::offset_of!(libc::cmsghdr, cmsg_type),
                libc::SCM_CREDENTIALS,
            );
            let payload_offset = control_message_header_length().expect("control header length");
            write_control_c_int(
                control_bytes,
                payload_offset + std::mem::offset_of!(libc::ucred, pid),
                libc::pid_t::try_from(credentials.pid()).expect("credential PID fits pid_t"),
            );
            write_control_u32(
                control_bytes,
                payload_offset + std::mem::offset_of!(libc::ucred, uid),
                credentials.uid().as_raw(),
            );
            write_control_u32(
                control_bytes,
                payload_offset + std::mem::offset_of!(libc::ucred, gid),
                credentials.gid(),
            );
            control
        }

        fn rights_control(descriptors: &[libc::c_int]) -> Vec<usize> {
            let payload_length = descriptors
                .len()
                .checked_mul(std::mem::size_of::<libc::c_int>())
                .expect("rights payload length");
            let control_space = control_message_space(payload_length).expect("rights space");
            let control_length = control_message_length(payload_length).expect("rights length");
            let mut control = vec![0_usize; control_space / std::mem::size_of::<usize>()];
            let control_bytes = control_buffer_bytes_mut(&mut control);
            write_control_usize(
                control_bytes,
                std::mem::offset_of!(libc::cmsghdr, cmsg_len),
                control_length,
            );
            write_control_c_int(
                control_bytes,
                std::mem::offset_of!(libc::cmsghdr, cmsg_level),
                libc::SOL_SOCKET,
            );
            write_control_c_int(
                control_bytes,
                std::mem::offset_of!(libc::cmsghdr, cmsg_type),
                libc::SCM_RIGHTS,
            );
            let payload_offset = control_message_header_length().expect("control header length");
            for (index, descriptor) in descriptors.iter().copied().enumerate() {
                write_control_c_int(
                    control_bytes,
                    payload_offset + index * std::mem::size_of::<libc::c_int>(),
                    descriptor,
                );
            }
            control
        }

        fn nonblocking_pipe() -> (OwnedFd, OwnedFd) {
            let mut pipe_descriptors = [-1; 2];
            // SAFETY: `pipe_descriptors` is writable storage for two new FDs.
            let pipe_result = unsafe {
                libc::pipe2(
                    pipe_descriptors.as_mut_ptr(),
                    libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            assert_eq!(
                pipe_result,
                0,
                "create pipe: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: the successful pipe2 call initialized two distinct owned descriptors.
            let read_end = unsafe { OwnedFd::from_raw_fd(pipe_descriptors[0]) };
            // SAFETY: see the ownership argument above for the second entry.
            let write_end = unsafe { OwnedFd::from_raw_fd(pipe_descriptors[1]) };
            (read_end, write_end)
        }

        fn unix_socket_pair(socket_type: libc::c_int) -> (OwnedFd, OwnedFd) {
            let mut descriptors = [-1; 2];
            // SAFETY: descriptors is writable storage for two new descriptors and the remaining
            // socketpair arguments are scalar constants.
            let result = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    socket_type | libc::SOCK_CLOEXEC,
                    0,
                    descriptors.as_mut_ptr(),
                )
            };
            assert_eq!(
                result,
                0,
                "create Unix socket pair: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: the successful socketpair call initialized two distinct owned descriptors.
            let first = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
            // SAFETY: see the ownership argument above for the second descriptor.
            let second = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
            (first, second)
        }

        fn set_record_credentials(fd: libc::c_int, enabled: bool) {
            let enabled = libc::c_int::from(enabled);
            // SAFETY: enabled is an initialized integer option value, its length is exact, and fd
            // names a live Unix-domain socket owned by the test.
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&raw const enabled).cast::<libc::c_void>(),
                    libc::socklen_t::try_from(std::mem::size_of_val(&enabled))
                        .expect("option length fits socklen_t"),
                )
            };
            assert_eq!(
                result,
                0,
                "set record credentials: {}",
                std::io::Error::last_os_error()
            );
        }

        fn assert_writer_has_no_readers(write_end: &OwnedFd) {
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut descriptor = libc::pollfd {
                fd: write_end.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            loop {
                descriptor.revents = 0;
                // SAFETY: `descriptor` points to one initialized writable pollfd.
                assert_eq!(unsafe { libc::poll(&raw mut descriptor, 1, 0) }, 1);
                if descriptor.revents & libc::POLLERR != 0 {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "received pipe readers remained open after the bounded close wait"
                );
                thread::sleep(Duration::from_millis(1));
            }
        }

        fn send_file_descriptors(
            connection: &SeqpacketConnection,
            fd: libc::c_int,
            descriptor_count: usize,
        ) {
            let mut payload = [b'x'];
            let mut iovec = libc::iovec {
                iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
                iov_len: payload.len(),
            };
            let descriptor_bytes = descriptor_count
                .checked_mul(std::mem::size_of::<libc::c_int>())
                .expect("descriptor control payload size");
            let control_space = control_message_space(descriptor_bytes).expect("control space");
            let control_length = control_message_length(descriptor_bytes).expect("control length");
            assert_eq!(control_space % std::mem::size_of::<usize>(), 0);
            let mut control = vec![0_usize; control_space / std::mem::size_of::<usize>()];
            let control_bytes = control_buffer_bytes_mut(&mut control);
            write_control_usize(
                control_bytes,
                std::mem::offset_of!(libc::cmsghdr, cmsg_len),
                control_length,
            );
            write_control_c_int(
                control_bytes,
                std::mem::offset_of!(libc::cmsghdr, cmsg_level),
                libc::SOL_SOCKET,
            );
            write_control_c_int(
                control_bytes,
                std::mem::offset_of!(libc::cmsghdr, cmsg_type),
                libc::SCM_RIGHTS,
            );
            let payload_offset = control_message_header_length().expect("control header length");
            for index in 0..descriptor_count {
                write_control_c_int(
                    control_bytes,
                    payload_offset + index * std::mem::size_of::<libc::c_int>(),
                    fd,
                );
            }

            // SAFETY: zero initializes every optional msghdr field before the
            // payload and aligned control buffer are attached below.
            let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
            message.msg_iov = &raw mut iovec;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
            message.msg_controllen = control_space;

            // SAFETY: `message` references initialized payload and control
            // buffers, and the connection owns its live socket descriptor.
            let sent = unsafe {
                libc::sendmsg(
                    connection.fd.as_raw_fd(),
                    &raw const message,
                    libc::MSG_NOSIGNAL,
                )
            };
            assert_eq!(
                sent,
                1,
                "send descriptor record: {}",
                std::io::Error::last_os_error()
            );
        }

        fn control_buffer_bytes_mut(control: &mut [usize]) -> &mut [u8] {
            // SAFETY: a mutable byte slice may initialize every byte of this exclusively borrowed,
            // word-aligned control buffer and retains exactly the source slice lifetime.
            unsafe {
                std::slice::from_raw_parts_mut(
                    control.as_mut_ptr().cast::<u8>(),
                    std::mem::size_of_val(control),
                )
            }
        }

        fn write_control_usize(control: &mut [u8], offset: usize, value: usize) {
            write_control_bytes(control, offset, &value.to_ne_bytes());
        }

        fn write_control_c_int(control: &mut [u8], offset: usize, value: libc::c_int) {
            write_control_bytes(control, offset, &value.to_ne_bytes());
        }

        fn write_control_u32(control: &mut [u8], offset: usize, value: u32) {
            write_control_bytes(control, offset, &value.to_ne_bytes());
        }

        fn write_control_bytes(control: &mut [u8], offset: usize, value: &[u8]) {
            let end = offset
                .checked_add(value.len())
                .expect("control write offset");
            let destination = control
                .get_mut(offset..end)
                .expect("control write is within the allocated message");
            destination.copy_from_slice(value);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod implementation {
    use std::path::Path;
    use std::time::{Duration, Instant};

    use super::{PeerCredentials, SeqpacketConnectionHandoffReceive, SeqpacketReceive, Uid};
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
        pub fn pair() -> Result<(Self, Self), PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub(crate) const fn inherited_descriptor(&self) -> i32 {
            -1
        }

        /// # Safety
        ///
        /// The descriptor must be the caller's sole unowned inherited endpoint.
        pub(crate) unsafe fn claim_inherited(_descriptor: i32) -> Result<Self, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn connect(_path: impl AsRef<Path>) -> Result<Self, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn recv_packet(&self, _limit: usize) -> Result<Vec<u8>, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn recv_record_until(
            &self,
            _limit: usize,
            _exclusive_deadline: Instant,
        ) -> Result<Option<SeqpacketReceive>, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn recv_connection_until(
            &self,
            _limit: usize,
            _exclusive_deadline: Instant,
        ) -> Result<Option<SeqpacketConnectionHandoffReceive>, PlatformError> {
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
            _expected_uid: Uid,
        ) -> Result<PeerCredentials, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn send_packet(&self, _packet: &[u8]) -> Result<(), PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn send_connection(
            &self,
            _payload: &[u8],
            _connection: &SeqpacketConnection,
        ) -> Result<(), PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        /// Transfers a borrowed endpoint only if the complete record can be queued before the
        /// exclusive deadline.
        ///
        /// A `false` result sends no record and leaves `connection` owned by the caller.
        pub fn send_connection_until(
            &self,
            _payload: &[u8],
            _connection: &SeqpacketConnection,
            _exclusive_deadline: Instant,
        ) -> Result<bool, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }
    }
}

pub use implementation::{SeqpacketConnection, SeqpacketListener};

#[cfg(test)]
mod tests {
    use super::Uid;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    mod nonblocking_listener {
        use std::os::fd::AsRawFd;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        use super::super::{SeqpacketConnection, SeqpacketListener};
        use tempfile::tempdir;

        #[test]
        fn reports_an_empty_backlog() {
            let directory = tempdir().expect("temporary directory");
            let socket_path = directory.path().join("fluxd.sock");
            let listener = SeqpacketListener::bind_nonblocking(&socket_path)
                .expect("bind nonblocking listener");

            assert!(
                listener
                    .try_accept()
                    .expect("try accepting client")
                    .is_none()
            );
        }

        #[test]
        fn exposes_a_borrowed_readiness_descriptor() {
            let directory = tempdir().expect("temporary directory");
            let socket_path = directory.path().join("fluxd.sock");
            let listener = SeqpacketListener::bind_nonblocking(&socket_path)
                .expect("bind nonblocking listener");

            // SAFETY: the borrowed descriptor remains owned by `listener` for
            // this call and F_GETFL does not modify memory through a pointer.
            let status = unsafe { libc::fcntl(listener.readiness_fd().as_raw_fd(), libc::F_GETFL) };

            assert!(
                status >= 0,
                "read listener status: {}",
                std::io::Error::last_os_error()
            );
            assert_ne!(status & libc::O_NONBLOCK, 0);
        }

        #[test]
        fn accepts_a_queued_peer() {
            let directory = tempdir().expect("temporary directory");
            let socket_path = directory.path().join("fluxd.sock");
            let listener = SeqpacketListener::bind_nonblocking(&socket_path)
                .expect("bind nonblocking listener");
            let _client = SeqpacketConnection::connect(&socket_path).expect("queue client");

            assert!(
                listener
                    .try_accept()
                    .expect("try accepting client")
                    .is_some()
            );
        }

        #[test]
        fn returns_a_blocking_usable_connection() {
            let directory = tempdir().expect("temporary directory");
            let socket_path = directory.path().join("fluxd.sock");
            let listener = SeqpacketListener::bind_nonblocking(&socket_path)
                .expect("bind nonblocking listener");
            let client = SeqpacketConnection::connect(&socket_path).expect("queue client");
            let connection = listener
                .try_accept()
                .expect("try accepting client")
                .expect("queued client must be accepted");
            let (started_tx, started_rx) = mpsc::sync_channel(1);
            let (result_tx, result_rx) = mpsc::sync_channel(1);
            let receiver = thread::spawn(move || {
                started_tx.send(()).expect("publish receive start");
                result_tx
                    .send(connection.recv_packet(64))
                    .expect("publish receive result");
            });

            started_rx.recv().expect("receive must start");
            assert!(matches!(
                result_rx.recv_timeout(Duration::from_millis(30)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));

            client.send_packet(b"request").expect("send request");
            assert_eq!(
                result_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("blocking receive must complete")
                    .expect("receive request"),
                b"request"
            );
            receiver.join().expect("receiver thread");
        }
    }

    #[test]
    fn uid_round_trips_valid_kernel_value() {
        let uid = Uid::from_raw(10_123).expect("valid UID");

        assert_eq!(uid.as_raw(), 10_123);
        assert!(!uid.is_root());
    }

    #[test]
    fn uid_rejects_kernel_no_identity_sentinel() {
        assert_eq!(Uid::from_raw(u32::MAX), None);
    }
}
