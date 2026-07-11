use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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

fn restore_clean_child_signal_mask(command: &mut Command) -> Result<(), ControlError> {
    crate::child_process::configure_child_process(
        command,
        crate::child_process::ChildProcessConfig::default(),
    )
    .map_err(|error| {
        ControlError::dispatcher(format!(
            "cannot initialize legacy child signal mask: {error}"
        ))
    })
}
