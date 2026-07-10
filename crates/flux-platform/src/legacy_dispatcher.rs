use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::mem::MaybeUninit;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::process::CommandExt;

use flux_core::{ControlError, LegacyDispatcher, LegacyIntent};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyScriptPaths {
    pub shell: PathBuf,
    pub shell_args: Vec<OsString>,
    pub dispatcher: PathBuf,
    pub addrsync: PathBuf,
}

#[derive(Debug)]
pub struct ProcessLegacyDispatcher {
    paths: LegacyScriptPaths,
}

impl ProcessLegacyDispatcher {
    #[must_use]
    pub const fn new(paths: LegacyScriptPaths) -> Self {
        Self { paths }
    }

    fn command_for(&self, intent: &LegacyIntent) -> (&PathBuf, Vec<&'static str>) {
        match intent {
            LegacyIntent::Running { .. } => (&self.paths.dispatcher, vec!["start"]),
            LegacyIntent::Stopped { .. } => (&self.paths.dispatcher, vec!["stop"]),
            LegacyIntent::Reload { reason } => {
                (&self.paths.dispatcher, vec!["restart", reason.as_token()])
            }
            LegacyIntent::ResyncAddresses { .. } => (&self.paths.addrsync, vec!["resync"]),
        }
    }
}

impl LegacyDispatcher for ProcessLegacyDispatcher {
    fn execute(&mut self, intent: &LegacyIntent) -> Result<(), ControlError> {
        let (script, arguments) = self.command_for(intent);
        let mut command = Command::new(&self.paths.shell);
        command
            .args(&self.paths.shell_args)
            .arg(script)
            .args(&arguments)
            .env("FLUXD_BRIDGE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        restore_clean_child_signal_mask(&mut command)?;
        let status = command.status().map_err(|error| {
            ControlError::dispatcher(format!(
                "cannot execute {} through {}: {error}",
                script.display(),
                self.paths.shell.display()
            ))
        })?;

        if status.success() {
            Ok(())
        } else {
            Err(ControlError::dispatcher(format!(
                "{} {} exited with {status}",
                script.display(),
                arguments.join(" ")
            )))
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn restore_clean_child_signal_mask(command: &mut Command) -> Result<(), ControlError> {
    let mut empty_mask = MaybeUninit::<libc::sigset_t>::zeroed();
    // SAFETY: `empty_mask` points to writable storage for one signal set.
    if unsafe { libc::sigemptyset(empty_mask.as_mut_ptr()) } != 0 {
        return Err(ControlError::dispatcher(format!(
            "cannot initialize legacy child signal mask: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: sigemptyset initialized the complete signal set.
    let empty_mask = unsafe { empty_mask.assume_init() };

    // SAFETY: after fork and before exec the closure calls only sigprocmask,
    // which POSIX defines as async-signal-safe. Error construction stores a
    // fixed OS error code inline and performs no allocation or I/O.
    unsafe {
        command.pre_exec(move || {
            if libc::sigprocmask(
                libc::SIG_SETMASK,
                &raw const empty_mask,
                std::ptr::null_mut(),
            ) == 0
            {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
        });
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn restore_clean_child_signal_mask(_command: &mut Command) -> Result<(), ControlError> {
    Ok(())
}
