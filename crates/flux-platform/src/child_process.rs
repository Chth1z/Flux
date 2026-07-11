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

#[derive(Debug, Default)]
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
pub(crate) struct ChildProcessConfig {
    pub(crate) raise_nofile_limit: bool,
    pub(crate) new_process_group: bool,
    pub(crate) inherited_fds: Vec<i32>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    use super::{ChildProcessConfig, ProcessSignal};

    const DESIRED_NOFILE_LIMIT: libc::rlim_t = 1_048_576;

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
        let inherited_fds = config.inherited_fds;

        // SAFETY: the closure runs after fork and before exec. `sigprocmask`,
        // `setpgid`, `fcntl`, Linux/Bionic's errno accessor, and Linux/Bionic's
        // `setrlimit` wrapper are allocation-free syscall/TLS operations. The
        // closure touches only copied or preallocated values and constructs an
        // `io::Error` from the captured errno integer.
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
                Ok(())
            });
        }
        Ok(())
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
        let pid = libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "PID exceeds pid_t"))?;
        signal_target(pid, signal)
    }

    pub(crate) fn signal_process_group(
        process_group: u32,
        signal: ProcessSignal,
    ) -> Result<(), io::Error> {
        let process_group = libc::pid_t::try_from(process_group).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "process group exceeds pid_t")
        })?;
        let target = process_group
            .checked_neg()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid process group"))?;
        signal_target(target, signal)
    }

    pub(crate) fn process_group_exists(process_group: u32) -> Result<bool, io::Error> {
        let process_group = libc::pid_t::try_from(process_group).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "process group exceeds pid_t")
        })?;
        if process_group == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "process group must be nonzero",
            ));
        }
        let target = process_group
            .checked_neg()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid process group"))?;
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
            inherited_fds: _,
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

pub(crate) use implementation::{
    configure_child_process, is_no_such_process, process_group_exists, signal_process,
    signal_process_group,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use implementation::{set_close_on_exec, set_nonblocking};
