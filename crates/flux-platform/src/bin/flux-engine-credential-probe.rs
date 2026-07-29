#[cfg(target_os = "android")]
mod android {
    use std::env;
    use std::fs::OpenOptions;
    use std::io::{BufWriter, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    use flux_platform::internal::{
        EngineCredentialProbeCapabilities, EngineCredentialProbeCommand,
        EngineCredentialProbeConfig, EngineCredentialProbePrivilege, EngineCredentialProbeReport,
    };

    const REQUIRED_ENV: &str = "FLUX_ENGINE_CREDENTIAL_PROBE_REQUIRED";
    const PROCESS_NAME: &[u8] = b"flux-cred-probe\0";
    const MAX_CAPABILITY_NUMBER: u32 = 63;
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const IP_TRANSPARENT_OPTION: libc::c_int = 19;
    const IPV6_TRANSPARENT_OPTION: libc::c_int = 75;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapabilityHeader {
        version: u32,
        pid: libc::c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    struct ProbeSockets {
        ipv4_tcp: OwnedFd,
        ipv6_tcp: OwnedFd,
        _ipv4_udp: OwnedFd,
        _ipv6_udp: OwnedFd,
    }

    impl ProbeSockets {
        fn create(config: &EngineCredentialProbeConfig) -> Result<Self, String> {
            let ipv4_tcp = create_socket(
                libc::AF_INET,
                libc::SOCK_STREAM,
                config.listener_port().get(),
                config.socket_mark().get(),
            )?;
            let ipv6_tcp = create_socket(
                libc::AF_INET6,
                libc::SOCK_STREAM,
                0,
                config.socket_mark().get(),
            )?;
            let ipv4_udp = create_socket(
                libc::AF_INET,
                libc::SOCK_DGRAM,
                0,
                config.socket_mark().get(),
            )?;
            let ipv6_udp = create_socket(
                libc::AF_INET6,
                libc::SOCK_DGRAM,
                0,
                config.socket_mark().get(),
            )?;
            Ok(Self {
                ipv4_tcp,
                ipv6_tcp,
                _ipv4_udp: ipv4_udp,
                _ipv6_udp: ipv6_udp,
            })
        }

        fn listen(&self) -> Result<(), String> {
            for socket in [&self.ipv4_tcp, &self.ipv6_tcp] {
                // SAFETY: each descriptor owns a bound stream socket and the
                // backlog is a positive scalar value.
                if unsafe { libc::listen(socket.as_raw_fd(), 1) } != 0 {
                    return Err(format!(
                        "listen on transparent socket: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            Ok(())
        }
    }

    pub(super) fn main() -> Result<(), String> {
        require_authority()?;
        set_process_name()?;
        let arguments = env::args_os().collect::<Vec<_>>();
        match EngineCredentialProbeCommand::parse(&arguments)? {
            EngineCredentialProbeCommand::Version => {
                println!("sing-box version 1.12.0");
                println!("Environment: flux-engine-credential-probe");
                Ok(())
            }
            EngineCredentialProbeCommand::Check {
                config,
                working_directory,
            } => execute(config.as_path(), working_directory.as_path(), false),
            EngineCredentialProbeCommand::Run {
                config,
                working_directory,
            } => execute(config.as_path(), working_directory.as_path(), true),
        }
    }

    fn execute(config_path: &Path, working_directory: &Path, run: bool) -> Result<(), String> {
        validate_working_directory(working_directory)?;
        let config = EngineCredentialProbeConfig::parse(
            &std::fs::read(config_path).map_err(|error| format!("read probe config: {error}"))?,
        )?;
        let report = EngineCredentialProbeReport::new(observe_privilege()?);
        report.validate_for(config.credentials())?;
        let sockets = ProbeSockets::create(&config)?;
        if !run {
            return sockets.listen();
        }
        write_report(&config, report)?;
        sockets.listen()?;
        loop {
            // SAFETY: pause has no arguments and only blocks until a signal is delivered.
            unsafe { libc::pause() };
        }
    }

    fn validate_working_directory(expected: &Path) -> Result<(), String> {
        let current = env::current_dir()
            .map_err(|error| format!("read credential-probe working directory: {error}"))?;
        if current == expected {
            Ok(())
        } else {
            Err("credential-probe -D path differs from its current directory".to_owned())
        }
    }

    fn require_authority() -> Result<(), String> {
        if env::var(REQUIRED_ENV).as_deref() == Ok("1") {
            Ok(())
        } else {
            Err("explicit Android credential-probe authority is required".to_owned())
        }
    }

    fn set_process_name() -> Result<(), String> {
        // SAFETY: PROCESS_NAME is a live NUL-terminated string whose payload is
        // at most Linux's 15-byte task-name limit.
        if unsafe { libc::prctl(libc::PR_SET_NAME, PROCESS_NAME.as_ptr(), 0, 0, 0) } == 0 {
            Ok(())
        } else {
            Err(format!(
                "set credential-probe process name: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    fn observe_privilege() -> Result<EngineCredentialProbePrivilege, String> {
        let mut uids = [u32::MAX; 3];
        // SAFETY: each pointer names distinct writable u32 storage.
        if unsafe {
            libc::syscall(
                libc::SYS_getresuid,
                &raw mut uids[0],
                &raw mut uids[1],
                &raw mut uids[2],
            )
        } != 0
        {
            return Err(format!("getresuid: {}", std::io::Error::last_os_error()));
        }
        let mut gids = [u32::MAX; 3];
        // SAFETY: each pointer names distinct writable u32 storage.
        if unsafe {
            libc::syscall(
                libc::SYS_getresgid,
                &raw mut gids[0],
                &raw mut gids[1],
                &raw mut gids[2],
            )
        } != 0
        {
            return Err(format!("getresgid: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: zero count means the null group pointer is not dereferenced.
        let group_count = unsafe {
            libc::syscall(
                libc::SYS_getgroups,
                0_usize,
                std::ptr::null_mut::<libc::gid_t>(),
            )
        };
        if group_count != 0 {
            return Err("supplementary group set is not exactly empty".to_owned());
        }
        let capabilities = read_capabilities()?;
        let capability_inheritable = join_capability_words(capabilities, |word| word.inheritable);
        let capability_permitted = join_capability_words(capabilities, |word| word.permitted);
        let capability_effective = join_capability_words(capabilities, |word| word.effective);
        // SAFETY: PR_GET_SECUREBITS accepts scalar zero arguments and returns
        // process-local state without dereferencing user memory.
        let securebits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) };
        if securebits < 0 {
            return Err(format!(
                "read securebits: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: PR_GET_NO_NEW_PRIVS accepts scalar zero arguments.
        let no_new_privileges = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        if no_new_privileges < 0 {
            return Err(format!(
                "read no-new-privileges: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut parent_death_signal = 0;
        // SAFETY: PR_GET_PDEATHSIG writes one c_int to the supplied live pointer.
        if unsafe {
            libc::prctl(
                libc::PR_GET_PDEATHSIG,
                &raw mut parent_death_signal,
                0,
                0,
                0,
            )
        } != 0
        {
            return Err(format!(
                "read parent-death signal: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(EngineCredentialProbePrivilege {
            uids,
            gids,
            capabilities: EngineCredentialProbeCapabilities {
                inheritable: capability_inheritable,
                permitted: capability_permitted,
                effective: capability_effective,
                bounding: read_capability_set(libc::PR_CAPBSET_READ)?,
                ambient: read_ambient_capabilities()?,
            },
            securebits: securebits as u64,
            no_new_privileges: no_new_privileges == 1,
            parent_death_signal,
        })
    }

    fn read_capabilities() -> Result<[CapabilityData; 2], String> {
        let mut header = CapabilityHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        // SAFETY: the version-3 header names self and data provides two writable words.
        if unsafe {
            libc::syscall(
                libc::SYS_capget,
                &raw mut header,
                (&raw mut data).cast::<CapabilityData>(),
            )
        } == 0
        {
            Ok(data)
        } else {
            Err(format!("capget: {}", std::io::Error::last_os_error()))
        }
    }

    fn join_capability_words(
        words: [CapabilityData; 2],
        field: impl Fn(CapabilityData) -> u32,
    ) -> u64 {
        u64::from(field(words[0])) | (u64::from(field(words[1])) << u32::BITS)
    }

    fn read_capability_set(operation: libc::c_int) -> Result<u64, String> {
        let mut result = 0_u64;
        for capability in 0..=MAX_CAPABILITY_NUMBER {
            // SAFETY: operation accepts one bounded capability number and scalar zeros.
            match unsafe { libc::prctl(operation, capability, 0, 0, 0) } {
                0 => {}
                1 => result |= 1_u64 << capability,
                _ => {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EINVAL) {
                        return Err(format!("read capability set: {error}"));
                    }
                }
            }
        }
        Ok(result)
    }

    fn read_ambient_capabilities() -> Result<u64, String> {
        let mut result = 0_u64;
        for capability in 0..=MAX_CAPABILITY_NUMBER {
            // SAFETY: PR_CAP_AMBIENT_IS_SET accepts a bounded capability and scalar zeros.
            match unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_IS_SET,
                    capability,
                    0,
                    0,
                )
            } {
                0 => {}
                1 => result |= 1_u64 << capability,
                _ => {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EINVAL) {
                        return Err(format!("read ambient capabilities: {error}"));
                    }
                }
            }
        }
        Ok(result)
    }

    fn create_socket(
        domain: libc::c_int,
        socket_type: libc::c_int,
        port: u16,
        mark: u32,
    ) -> Result<OwnedFd, String> {
        // SAFETY: domain/type are fixed supported socket constants and protocol zero selects
        // the canonical transport implementation.
        let descriptor = unsafe { libc::socket(domain, socket_type | libc::SOCK_CLOEXEC, 0) };
        if descriptor < 0 {
            return Err(format!(
                "create probe socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: descriptor was returned uniquely by socket and is now owned exactly once.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        if socket_type == libc::SOCK_STREAM {
            set_socket_option(&descriptor, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        }
        if domain == libc::AF_INET6 {
            set_socket_option(&descriptor, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;
            set_socket_option(&descriptor, libc::IPPROTO_IPV6, IPV6_TRANSPARENT_OPTION, 1)?;
        } else {
            set_socket_option(&descriptor, libc::IPPROTO_IP, IP_TRANSPARENT_OPTION, 1)?;
        }
        set_socket_option(
            &descriptor,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            mark as libc::c_int,
        )?;
        bind_loopback(&descriptor, domain, port)?;
        let transparent = if domain == libc::AF_INET6 {
            get_socket_option(&descriptor, libc::IPPROTO_IPV6, IPV6_TRANSPARENT_OPTION)?
        } else {
            get_socket_option(&descriptor, libc::IPPROTO_IP, IP_TRANSPARENT_OPTION)?
        };
        if transparent != 1
            || get_socket_option(&descriptor, libc::SOL_SOCKET, libc::SO_MARK)? as u32 != mark
        {
            return Err("transparent socket option readback mismatch".to_owned());
        }
        Ok(descriptor)
    }

    fn set_socket_option(
        descriptor: &OwnedFd,
        level: libc::c_int,
        option: libc::c_int,
        value: libc::c_int,
    ) -> Result<(), String> {
        // SAFETY: descriptor is live and the pointer/length describe one initialized c_int.
        if unsafe {
            libc::setsockopt(
                descriptor.as_raw_fd(),
                level,
                option,
                (&raw const value).cast(),
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(format!(
                "set probe socket option: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    fn get_socket_option(
        descriptor: &OwnedFd,
        level: libc::c_int,
        option: libc::c_int,
    ) -> Result<libc::c_int, String> {
        let mut value = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: descriptor is live and value/length provide writable storage for one c_int.
        if unsafe {
            libc::getsockopt(
                descriptor.as_raw_fd(),
                level,
                option,
                (&raw mut value).cast(),
                &raw mut length,
            )
        } != 0
            || length as usize != std::mem::size_of_val(&value)
        {
            return Err(format!(
                "read probe socket option: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(value)
    }

    fn bind_loopback(descriptor: &OwnedFd, domain: libc::c_int, port: u16) -> Result<(), String> {
        let result = if domain == libc::AF_INET6 {
            let address = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: port.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                },
                sin6_scope_id: 0,
            };
            // SAFETY: address is an initialized sockaddr_in6 with its exact length.
            unsafe {
                libc::bind(
                    descriptor.as_raw_fd(),
                    (&raw const address).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            }
        } else {
            let address = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: address is an initialized sockaddr_in with its exact length.
            unsafe {
                libc::bind(
                    descriptor.as_raw_fd(),
                    (&raw const address).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            }
        };
        if result == 0 {
            Ok(())
        } else {
            Err(format!(
                "bind transparent loopback socket: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    fn write_report(
        config: &EngineCredentialProbeConfig,
        report: EngineCredentialProbeReport,
    ) -> Result<(), String> {
        let rendered = report.render();
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(config.report_name())
            .map_err(|error| format!("create credential report: {error}"))?;
        let mut output = BufWriter::new(file);
        output
            .write_all(rendered.as_bytes())
            .map_err(report_error)?;
        output.flush().map_err(report_error)?;
        output.get_ref().sync_all().map_err(report_error)
    }

    fn report_error(error: std::io::Error) -> String {
        format!("write credential report: {error}")
    }
}

#[cfg(target_os = "android")]
fn main() {
    if let Err(error) = android::main() {
        eprintln!("Flux engine credential probe: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "android"))]
fn main() {
    eprintln!("flux-engine-credential-probe is available only on Android");
    std::process::exit(2);
}
