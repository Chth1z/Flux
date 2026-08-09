use std::num::NonZeroU32;

use flux_core::EngineCredentials;

pub const TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK: u64 = (1_u64 << 12) | (1_u64 << 13);
pub(crate) const TRANSPARENT_PROXY_ENGINE_SECUREBITS: u64 =
    (1_u64 << 0) | (1_u64 << 1) | (1_u64 << 2) | (1_u64 << 3) | (1_u64 << 6) | (1_u64 << 7);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessSignal {
    Terminate,
    Kill,
}

impl ProcessSignal {
    #[must_use]
    pub(crate) const fn as_raw(self) -> i32 {
        implementation::signal_number(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum ChildProcessPrivilege {
    #[default]
    Inherit,
    TransparentProxy(EngineCredentials),
    Restricted(RestrictedChildCredentials),
}

/// Exact credentials for a child that must retain no Linux capabilities.
///
/// This is an internal cross-crate boundary for the packaged functional canary.
/// It deliberately does not carry process, namespace, or lifecycle authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestrictedChildCredentials {
    uid: NonZeroU32,
    gid: NonZeroU32,
}

impl RestrictedChildCredentials {
    #[must_use]
    pub const fn new(uid: NonZeroU32, gid: NonZeroU32) -> Self {
        Self { uid, gid }
    }

    #[must_use]
    pub const fn uid(self) -> NonZeroU32 {
        self.uid
    }

    #[must_use]
    pub const fn gid(self) -> NonZeroU32 {
        self.gid
    }
}

#[derive(Debug, Default)]
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
pub(crate) struct ChildProcessConfig {
    pub(crate) raise_nofile_limit: bool,
    pub(crate) new_process_group: bool,
    pub(crate) kill_on_parent_death: bool,
    pub(crate) close_unlisted_fds: bool,
    pub(crate) inherited_fds: Vec<i32>,
    pub(crate) network_namespace: Option<std::fs::File>,
    pub(crate) privilege: ChildProcessPrivilege,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    use super::{
        ChildProcessConfig, ChildProcessPrivilege, ProcessSignal, RestrictedChildCredentials,
        TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK, TRANSPARENT_PROXY_ENGINE_SECUREBITS,
    };

    const DESIRED_NOFILE_LIMIT: libc::rlim_t = 1_048_576;
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const CAP_SETPCAP: u32 = 8;
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_NET_RAW: u32 = 13;
    const MAX_CAPABILITY_NUMBER: u32 = 63;
    const SECBIT_NOROOT: libc::c_ulong = 1 << 0;
    const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;
    const SECBIT_NO_SETUID_FIXUP: libc::c_ulong = 1 << 2;
    const SECBIT_NO_SETUID_FIXUP_LOCKED: libc::c_ulong = 1 << 3;
    const BASE_SECUREBITS: libc::c_ulong = SECBIT_NOROOT
        | SECBIT_NOROOT_LOCKED
        | SECBIT_NO_SETUID_FIXUP
        | SECBIT_NO_SETUID_FIXUP_LOCKED;
    const FINAL_SECUREBITS: libc::c_ulong = TRANSPARENT_PROXY_ENGINE_SECUREBITS as libc::c_ulong;

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

    pub(crate) fn configure_child_process(
        command: &mut Command,
        config: ChildProcessConfig,
    ) -> Result<(), io::Error> {
        let mut empty_mask = MaybeUninit::<libc::sigset_t>::zeroed();
        // SAFETY: `empty_mask` points to writable storage for one signal set.
        if unsafe { libc::sigemptyset(empty_mask.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: sigemptyset initialized the complete signal set.
        let empty_mask = unsafe { empty_mask.assume_init() };
        let nofile_limit = preferred_nofile_limit(config.raise_nofile_limit);
        let new_process_group = config.new_process_group;
        let close_unlisted_fds = config.close_unlisted_fds;
        let privilege = config.privilege;
        let network_namespace = config.network_namespace;
        // Capture the creating process before fork. `PR_SET_PDEATHSIG` is not
        // retroactive, so the child compares this identity after arming the
        // signal to close the parent-exit-before-prctl race.
        let expected_parent = config.kill_on_parent_death.then(|| {
            // SAFETY: getpid has no arguments or failure mode and only reads
            // the calling process identity.
            unsafe { libc::getpid() }
        });
        let inherited_fds = config.inherited_fds;

        // SAFETY: the closure runs after fork and before exec. `sigprocmask`,
        // `setpgid`, `close_range`, `fcntl`, `prctl`, the raw credential and
        // capability syscalls, `getpid`, `getppid`, `kill`, Linux/Bionic's
        // errno accessor, and Linux/Bionic's `setrlimit` wrapper are
        // allocation-free syscall/TLS operations. The closure touches only
        // copied or preallocated values and constructs an `io::Error` from a
        // captured errno integer or constant.
        unsafe {
            command.pre_exec(move || {
                if libc::sigprocmask(
                    libc::SIG_SETMASK,
                    &raw const empty_mask,
                    std::ptr::null_mut(),
                ) != 0
                {
                    return Err(last_fork_error());
                }
                if new_process_group && libc::setpgid(0, 0) != 0 {
                    return Err(last_fork_error());
                }
                if close_unlisted_fds {
                    mark_unlisted_descriptors_close_on_exec()?;
                }
                for descriptor in &inherited_fds {
                    let flags = libc::fcntl(*descriptor, libc::F_GETFD);
                    if flags < 0 {
                        return Err(last_fork_error());
                    }
                    if libc::fcntl(*descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(last_fork_error());
                    }
                }
                if let Some(limit) = nofile_limit {
                    // Raising the descriptor limit is best effort. Failure is
                    // intentionally ignored so a sandbox cannot prevent exec.
                    let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit);
                }
                if let Some(network_namespace) = &network_namespace
                    && libc::syscall(
                        libc::SYS_setns,
                        network_namespace.as_raw_fd(),
                        libc::CLONE_NEWNET,
                    ) != 0
                {
                    return Err(last_fork_error());
                }
                apply_privilege(privilege)?;
                if let Some(expected_parent) = expected_parent {
                    arm_parent_death_signal(expected_parent)?;
                }
                Ok(())
            });
        }
        Ok(())
    }

    fn apply_privilege(privilege: ChildProcessPrivilege) -> Result<(), io::Error> {
        match privilege {
            ChildProcessPrivilege::Inherit => Ok(()),
            ChildProcessPrivilege::TransparentProxy(credentials) => {
                apply_transparent_proxy_privilege(credentials)
            }
            ChildProcessPrivilege::Restricted(credentials) => {
                apply_restricted_privilege(credentials)
            }
        }
    }

    fn apply_transparent_proxy_privilege(
        credentials: flux_core::EngineCredentials,
    ) -> Result<(), io::Error> {
        // Clear any inherited ambient authority before locking the root and
        // set-ID capability fixups into their least-privilege behavior.
        // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL accepts only scalar arguments and
        // applies to the calling child without dereferencing user memory.
        if unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
        {
            return Err(last_fork_error());
        }
        set_securebits(BASE_SECUREBITS)?;
        drop_unrequired_bounding_capabilities(TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK)?;

        // SAFETY: the raw Linux setgroups syscall receives a zero element count,
        // so the null group-array pointer is not dereferenced.
        if unsafe {
            libc::syscall(
                libc::SYS_setgroups,
                0_usize,
                std::ptr::null::<libc::gid_t>(),
            )
        } != 0
        {
            return Err(last_fork_error());
        }
        let gid = credentials.gid().get();
        // SAFETY: the raw Linux setresgid syscall receives three scalar IDs
        // accepted by Flux's credential value type and mutates only this child.
        if unsafe { libc::syscall(libc::SYS_setresgid, gid, gid, gid) } != 0 {
            return Err(last_fork_error());
        }
        let uid = credentials.uid().get();
        // SAFETY: the raw Linux setresuid syscall receives three scalar IDs
        // accepted by Flux's credential value type and mutates only this child.
        if unsafe { libc::syscall(libc::SYS_setresuid, uid, uid, uid) } != 0 {
            return Err(last_fork_error());
        }

        let setup_capabilities = TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK | (1_u64 << CAP_SETPCAP);
        set_capabilities(
            setup_capabilities,
            setup_capabilities,
            TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK,
        )?;
        for capability in [CAP_NET_ADMIN, CAP_NET_RAW] {
            // SAFETY: PR_CAP_AMBIENT_RAISE accepts a validated capability
            // number and scalar zero arguments; it accesses no user pointer.
            if unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_RAISE,
                    capability,
                    0,
                    0,
                )
            } != 0
            {
                return Err(last_fork_error());
            }
        }
        set_securebits(FINAL_SECUREBITS)?;
        set_capabilities(
            TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK,
            TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK,
            TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK,
        )?;
        // SAFETY: PR_SET_NO_NEW_PRIVS accepts scalar arguments and irreversibly
        // constrains only the calling child.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(last_fork_error());
        }
        verify_privilege(credentials.uid().get(), credentials.gid().get())
    }

    fn apply_restricted_privilege(
        credentials: RestrictedChildCredentials,
    ) -> Result<(), io::Error> {
        // Optional namespace entry has already completed. From this point the
        // child cannot regain namespace or networking authority across exec.
        // SAFETY: the ambient-clear prctl accepts scalar constants only and
        // affects only the calling pre-exec child.
        if unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
        {
            return Err(last_fork_error());
        }
        set_securebits(BASE_SECUREBITS)?;
        drop_unrequired_bounding_capabilities(0)?;
        clear_supplementary_groups()?;

        let gid = credentials.gid().get();
        // SAFETY: setresgid receives three validated scalar IDs and mutates
        // only the calling pre-exec child.
        if unsafe { libc::syscall(libc::SYS_setresgid, gid, gid, gid) } != 0 {
            return Err(last_fork_error());
        }
        let uid = credentials.uid().get();
        // SAFETY: setresuid receives three validated scalar IDs and mutates
        // only the calling pre-exec child.
        if unsafe { libc::syscall(libc::SYS_setresuid, uid, uid, uid) } != 0 {
            return Err(last_fork_error());
        }
        set_capabilities(0, 0, 0)?;
        // SAFETY: PR_SET_NO_NEW_PRIVS accepts scalar arguments only and
        // irreversibly constrains the calling pre-exec child.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(last_fork_error());
        }
        verify_restricted_privilege(uid, gid)
    }

    fn clear_supplementary_groups() -> Result<(), io::Error> {
        // SAFETY: a zero element count means the null group pointer is not
        // dereferenced; the syscall affects only the calling child.
        if unsafe {
            libc::syscall(
                libc::SYS_setgroups,
                0_usize,
                std::ptr::null::<libc::gid_t>(),
            )
        } == 0
        {
            return Ok(());
        }
        let error = last_fork_error();
        if error.raw_os_error() == Some(libc::EPERM)
            // SAFETY: the zero-count query does not dereference its null output
            // pointer and reads only the calling child's group count.
            && unsafe {
                libc::syscall(
                    libc::SYS_getgroups,
                    0_usize,
                    std::ptr::null_mut::<libc::gid_t>(),
                )
            } == 0
        {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn set_securebits(bits: libc::c_ulong) -> Result<(), io::Error> {
        // SAFETY: PR_SET_SECUREBITS accepts one scalar bit mask and accesses no
        // user pointer; the caller supplies only the masks defined above.
        if unsafe { libc::prctl(libc::PR_SET_SECUREBITS, bits, 0, 0, 0) } == 0 {
            Ok(())
        } else {
            Err(last_fork_error())
        }
    }

    fn drop_unrequired_bounding_capabilities(retained: u64) -> Result<(), io::Error> {
        for capability in 0..=MAX_CAPABILITY_NUMBER {
            if retained & (1_u64 << capability) != 0 {
                continue;
            }
            // SAFETY: PR_CAPBSET_DROP accepts one capability number from the
            // bounded 0..=63 scan and scalar zero arguments.
            if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } == 0 {
                continue;
            }
            let error = last_fork_error();
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn set_capabilities(effective: u64, permitted: u64, inheritable: u64) -> Result<(), io::Error> {
        let mut header = CapabilityHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = capability_data(effective, permitted, inheritable);
        // SAFETY: the version-3 header names the calling process and `data`
        // contains the required two initialized capability words for capset.
        if unsafe {
            libc::syscall(
                libc::SYS_capset,
                &raw mut header,
                (&raw const data).cast::<CapabilityData>(),
            )
        } == 0
        {
            Ok(())
        } else {
            Err(last_fork_error())
        }
    }

    fn read_capabilities() -> Result<[CapabilityData; 2], io::Error> {
        let mut header = CapabilityHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        // SAFETY: the version-3 header names the calling process and `data`
        // provides writable storage for both capability words filled by capget.
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
            Err(last_fork_error())
        }
    }

    const fn capability_data(
        effective: u64,
        permitted: u64,
        inheritable: u64,
    ) -> [CapabilityData; 2] {
        [
            CapabilityData {
                effective: effective as u32,
                permitted: permitted as u32,
                inheritable: inheritable as u32,
            },
            CapabilityData {
                effective: (effective >> u32::BITS) as u32,
                permitted: (permitted >> u32::BITS) as u32,
                inheritable: (inheritable >> u32::BITS) as u32,
            },
        ]
    }

    fn verify_privilege(uid: u32, gid: u32) -> Result<(), io::Error> {
        verify_ids_and_groups(uid, gid)?;
        let capabilities = read_capabilities()?;
        let expected = capability_data(
            TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK,
            TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK,
            TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK,
        );
        // SAFETY: both getter operations accept only scalar zero arguments and
        // return state for the calling child without dereferencing user memory.
        let securebits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) };
        // SAFETY: PR_GET_NO_NEW_PRIVS likewise accepts scalar zero arguments
        // and reads only state associated with the calling child.
        let no_new_privileges = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        if capabilities
            .iter()
            .zip(expected)
            .any(|(observed, expected)| {
                observed.effective != expected.effective
                    || observed.permitted != expected.permitted
                    || observed.inheritable != expected.inheritable
            })
            || securebits != FINAL_SECUREBITS as libc::c_int
            || no_new_privileges != 1
            || read_capability_bounding()? != TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK
        {
            return Err(fork_contract_error());
        }
        for capability in [CAP_NET_ADMIN, CAP_NET_RAW] {
            // SAFETY: PR_CAP_AMBIENT_IS_SET accepts a validated capability
            // number and scalar zero arguments, with no user pointer.
            if unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_IS_SET,
                    capability,
                    0,
                    0,
                )
            } != 1
            {
                return Err(fork_contract_error());
            }
        }
        Ok(())
    }

    fn verify_restricted_privilege(uid: u32, gid: u32) -> Result<(), io::Error> {
        verify_ids_and_groups(uid, gid)?;
        let capabilities = read_capabilities()?;
        // SAFETY: both getter operations accept scalar zero arguments and read
        // only state associated with the calling child.
        let securebits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) };
        // SAFETY: PR_GET_NO_NEW_PRIVS likewise accepts scalar zero arguments.
        let no_new_privileges = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        if capabilities.iter().any(|observed| {
            observed.effective != 0 || observed.permitted != 0 || observed.inheritable != 0
        }) || securebits != BASE_SECUREBITS as libc::c_int
            || no_new_privileges != 1
            || read_capability_bounding()? != 0
        {
            return Err(fork_contract_error());
        }
        for capability in 0..=MAX_CAPABILITY_NUMBER {
            // SAFETY: the bounded capability number and remaining arguments
            // are scalar values; no user pointer is dereferenced.
            if unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_IS_SET,
                    capability,
                    0,
                    0,
                )
            } > 0
            {
                return Err(fork_contract_error());
            }
        }
        Ok(())
    }

    fn verify_ids_and_groups(uid: u32, gid: u32) -> Result<(), io::Error> {
        let mut real_uid = u32::MAX;
        let mut effective_uid = u32::MAX;
        let mut saved_uid = u32::MAX;
        // SAFETY: getresuid receives pointers to three distinct writable u32
        // values owned by this stack frame.
        if unsafe {
            libc::syscall(
                libc::SYS_getresuid,
                &raw mut real_uid,
                &raw mut effective_uid,
                &raw mut saved_uid,
            )
        } != 0
            || [real_uid, effective_uid, saved_uid] != [uid; 3]
        {
            return Err(fork_contract_error());
        }
        let mut real_gid = u32::MAX;
        let mut effective_gid = u32::MAX;
        let mut saved_gid = u32::MAX;
        // SAFETY: getresgid receives pointers to three distinct writable u32
        // values owned by this stack frame.
        if unsafe {
            libc::syscall(
                libc::SYS_getresgid,
                &raw mut real_gid,
                &raw mut effective_gid,
                &raw mut saved_gid,
            )
        } != 0
            || [real_gid, effective_gid, saved_gid] != [gid; 3]
        {
            return Err(fork_contract_error());
        }
        // SAFETY: the zero-count query does not dereference its null output
        // pointer and reads only the calling child's group count.
        if unsafe {
            libc::syscall(
                libc::SYS_getgroups,
                0_usize,
                std::ptr::null_mut::<libc::gid_t>(),
            )
        } != 0
        {
            return Err(fork_contract_error());
        }
        Ok(())
    }

    fn read_capability_bounding() -> Result<u64, io::Error> {
        let mut bounding = 0_u64;
        for capability in 0..=MAX_CAPABILITY_NUMBER {
            // SAFETY: PR_CAPBSET_READ accepts one capability number from the
            // bounded 0..=63 scan and scalar zero arguments.
            match unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0) } {
                0 => {}
                1 => bounding |= 1_u64 << capability,
                _ => {
                    let error = last_fork_error();
                    if error.raw_os_error() != Some(libc::EINVAL) {
                        return Err(error);
                    }
                }
            }
        }
        Ok(bounding)
    }

    fn arm_parent_death_signal(expected_parent: libc::pid_t) -> Result<(), io::Error> {
        // SAFETY: PR_SET_PDEATHSIG accepts a valid signal number and scalar
        // zero arguments, changing only the calling child's process state.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
            return Err(last_fork_error());
        }
        // SAFETY: getppid has no arguments, pointers, or failure mode.
        if unsafe { libc::getppid() } == expected_parent {
            return Ok(());
        }
        // SAFETY: getpid returns the calling child's valid PID; kill targets
        // exactly that PID with the valid SIGKILL constant.
        if unsafe { libc::kill(libc::getpid(), libc::SIGKILL) } != 0 {
            return Err(last_fork_error());
        }
        Err(io::Error::from_raw_os_error(libc::ECHILD))
    }

    fn fork_contract_error() -> io::Error {
        io::Error::from_raw_os_error(libc::EPERM)
    }

    pub(crate) fn set_nonblocking(descriptor: i32) -> Result<(), io::Error> {
        // SAFETY: `descriptor` is supplied from a live owned descriptor; F_GETFL
        // has no pointer argument and does not mutate descriptor ownership.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_SETFL receives the existing flags plus O_NONBLOCK and no
        // pointer argument. Descriptor ownership remains with the caller.
        if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(crate) fn set_close_on_exec(descriptor: i32) -> Result<(), io::Error> {
        // SAFETY: the descriptor is live and both fcntl operations use integer
        // arguments only; ownership remains with the caller.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_SETFD updates only descriptor flags.
        if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(crate) fn signal_process(pid: u32, signal: ProcessSignal) -> Result<(), io::Error> {
        signal_target(process_target(pid)?, signal)
    }

    pub(crate) fn signal_process_group(
        process_group: u32,
        signal: ProcessSignal,
    ) -> Result<(), io::Error> {
        signal_target(process_group_target(process_group)?, signal)
    }

    pub(crate) fn process_group_exists(process_group: u32) -> Result<bool, io::Error> {
        let target = process_group_target(process_group)?;
        // SAFETY: signal zero performs an existence/permission probe only; the
        // validated negative target addresses one process group and mutates no
        // process state.
        if unsafe { libc::kill(target, 0) } == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            Some(libc::EPERM) => Ok(true),
            _ => Err(error),
        }
    }

    pub(crate) fn is_no_such_process(error: &io::Error) -> bool {
        error.raw_os_error() == Some(libc::ESRCH)
    }

    pub(crate) const fn signal_number(signal: ProcessSignal) -> i32 {
        match signal {
            ProcessSignal::Terminate => libc::SIGTERM,
            ProcessSignal::Kill => libc::SIGKILL,
        }
    }

    fn signal_target(target: libc::pid_t, signal: ProcessSignal) -> Result<(), io::Error> {
        // SAFETY: `target` is either a validated positive PID or negative
        // process-group ID, and `signal_number` returns a libc signal constant.
        if unsafe { libc::kill(target, signal_number(signal)) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn process_target(pid: u32) -> Result<libc::pid_t, io::Error> {
        let pid = libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "PID exceeds pid_t"))?;
        if pid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PID must be nonzero",
            ));
        }
        Ok(pid)
    }

    fn process_group_target(process_group: u32) -> Result<libc::pid_t, io::Error> {
        let process_group = libc::pid_t::try_from(process_group).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "process group exceeds pid_t")
        })?;
        if process_group == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "process group must be nonzero",
            ));
        }
        process_group
            .checked_neg()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid process group"))
    }

    fn preferred_nofile_limit(enabled: bool) -> Option<libc::rlimit> {
        if !enabled {
            return None;
        }
        let mut limit = MaybeUninit::<libc::rlimit>::zeroed();
        // SAFETY: `limit` is writable storage for one rlimit value.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: getrlimit initialized the value on success.
        let mut limit = unsafe { limit.assume_init() };
        let desired = DESIRED_NOFILE_LIMIT.min(limit.rlim_max);
        if desired <= limit.rlim_cur {
            return None;
        }
        limit.rlim_cur = desired;
        Some(limit)
    }

    fn last_fork_error() -> io::Error {
        io::Error::from_raw_os_error(fork_errno())
    }

    fn mark_unlisted_descriptors_close_on_exec() -> Result<(), io::Error> {
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
        // SAFETY: close_range receives an inclusive integer descriptor range
        // and the CLOEXEC-only flag. Descriptors are not closed in the child;
        // the explicitly admitted inheritance list is cleared afterward.
        let result =
            unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
        if result == 0 {
            Ok(())
        } else {
            Err(last_fork_error())
        }
    }

    #[cfg(target_os = "linux")]
    fn fork_errno() -> i32 {
        // SAFETY: immediately after the failed libc call, glibc/musl exposes
        // the calling thread's errno through this allocation-free TLS pointer.
        unsafe { *libc::__errno_location() }
    }

    #[cfg(target_os = "android")]
    fn fork_errno() -> i32 {
        // SAFETY: immediately after the failed libc call, Bionic exposes the
        // calling thread's errno through this allocation-free TLS pointer.
        unsafe { *libc::__errno() }
    }

    #[cfg(test)]
    mod tests {
        use std::io;

        use super::{process_group_target, process_target};

        #[test]
        fn signal_targets_reject_zero_before_the_kill_syscall() {
            assert_eq!(
                process_target(0).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                process_group_target(0).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }

        #[test]
        fn signal_targets_preserve_process_and_group_addressing() {
            assert_eq!(process_target(42).unwrap(), 42);
            assert_eq!(process_group_target(42).unwrap(), -42);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod implementation {
    use std::io;
    use std::process::Command;

    use super::{ChildProcessConfig, ProcessSignal};

    pub(crate) fn configure_child_process(
        _command: &mut Command,
        config: ChildProcessConfig,
    ) -> Result<(), io::Error> {
        let ChildProcessConfig {
            raise_nofile_limit: _,
            new_process_group: _,
            kill_on_parent_death: _,
            close_unlisted_fds: _,
            inherited_fds: _,
            network_namespace: _,
            privilege: _,
        } = config;
        Ok(())
    }

    pub(crate) fn signal_process(_pid: u32, _signal: ProcessSignal) -> Result<(), io::Error> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process signals are unavailable",
        ))
    }

    pub(crate) fn signal_process_group(
        _process_group: u32,
        _signal: ProcessSignal,
    ) -> Result<(), io::Error> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process-group signals are unavailable",
        ))
    }

    pub(crate) fn process_group_exists(_process_group: u32) -> Result<bool, io::Error> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process-group probes are unavailable",
        ))
    }

    pub(crate) fn is_no_such_process(_error: &io::Error) -> bool {
        false
    }

    pub(crate) const fn signal_number(signal: ProcessSignal) -> i32 {
        match signal {
            ProcessSignal::Terminate => 15,
            ProcessSignal::Kill => 9,
        }
    }
}

pub(crate) fn configure_child_process(
    command: &mut std::process::Command,
    config: ChildProcessConfig,
) -> Result<(), std::io::Error> {
    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    record_native_composition_test_exec(command)?;
    implementation::configure_child_process(command, config)
}

/// Configure one packaged canary child to enter its final namespace and exact
/// zero-capability credentials before exec.
pub fn configure_restricted_child_process(
    command: &mut std::process::Command,
    credentials: RestrictedChildCredentials,
    network_namespace: Option<std::fs::File>,
    inherited_fds: Vec<i32>,
) -> Result<(), std::io::Error> {
    configure_child_process(
        command,
        ChildProcessConfig {
            raise_nofile_limit: false,
            new_process_group: false,
            kill_on_parent_death: true,
            close_unlisted_fds: true,
            inherited_fds,
            network_namespace,
            privilege: ChildProcessPrivilege::Restricted(credentials),
        },
    )
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
fn record_native_composition_test_exec(
    command: &std::process::Command,
) -> Result<(), std::io::Error> {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::{Mutex, OnceLock};

    const AUDIT_ENV: &str = "FLUX_NATIVE_COMPOSITION_EXEC_AUDIT";
    static AUDIT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    let Some(path) = std::env::var_os(AUDIT_ENV) else {
        return Ok(());
    };
    let path = std::path::PathBuf::from(path);
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{AUDIT_ENV} must be an absolute path"),
        ));
    }

    let _guard = AUDIT_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| std::io::Error::other("native composition exec audit lock is poisoned"))?;
    let mut record = String::from("v1\t");
    push_hex(&mut record, command.get_program().as_bytes());
    for argument in command.get_args() {
        record.push('\t');
        push_hex(&mut record, argument.as_bytes());
    }
    record.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(record.as_bytes())
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
fn push_hex(output: &mut String, bytes: &[u8]) {
    use std::fmt::Write;

    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing into a String cannot fail");
    }
}

pub(crate) use implementation::{
    is_no_such_process, process_group_exists, signal_process, signal_process_group,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use implementation::{set_close_on_exec, set_nonblocking};
