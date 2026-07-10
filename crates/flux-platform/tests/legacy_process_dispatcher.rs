use std::fs;
use std::path::{Path, PathBuf};

use flux_core::{LegacyDispatcher, LegacyIntent, Reason};
use flux_platform::{LegacyScriptPaths, ProcessLegacyDispatcher};
use tempfile::tempdir;

#[test]
fn process_adapter_maps_intents_to_the_only_allowed_legacy_commands() {
    let directory = tempdir().expect("temporary directory");
    let dispatcher_record = directory.path().join("dispatcher.record");
    let addrsync_record = directory.path().join("addrsync.record");
    let (shell, dispatcher_script) =
        recording_script(directory.path(), "dispatcher", &dispatcher_record);
    let (_, addrsync_script) = recording_script(directory.path(), "addrsync", &addrsync_record);

    let mut adapter = ProcessLegacyDispatcher::new(LegacyScriptPaths {
        shell,
        shell_args: shell_arguments(),
        dispatcher: dispatcher_script,
        addrsync: addrsync_script,
    });

    let cases = [
        (
            LegacyIntent::Running {
                reason: Reason::Boot,
            },
            "bridge=1 args=start",
        ),
        (
            LegacyIntent::Stopped {
                reason: Reason::DisableCreated,
            },
            "bridge=1 args=stop",
        ),
        (
            LegacyIntent::Reload {
                reason: Reason::ConfigChanged,
            },
            "bridge=1 args=restart config_changed",
        ),
    ];

    for (intent, expected) in cases {
        adapter.execute(&intent).expect("dispatcher succeeds");
        assert_eq!(read_record(&dispatcher_record), expected);
    }

    adapter
        .execute(&LegacyIntent::ResyncAddresses {
            reason: Reason::Fluxctl,
        })
        .expect("addrsync succeeds");
    assert_eq!(read_record(&addrsync_record), "bridge=1 args=resync");
}

fn read_record(path: &Path) -> String {
    fs::read_to_string(path)
        .expect("recorded invocation")
        .trim()
        .to_owned()
}

#[cfg(windows)]
fn recording_script(directory: &Path, name: &str, record: &Path) -> (PathBuf, PathBuf) {
    let script = directory.join(format!("{name}.cmd"));
    fs::write(
        &script,
        format!(
            "@echo off\r\n>\"{}\" echo bridge=%FLUXD_BRIDGE% args=%*\r\n",
            record.display()
        ),
    )
    .expect("write command script");
    (PathBuf::from("cmd.exe"), script)
}

#[cfg(windows)]
fn shell_arguments() -> Vec<std::ffi::OsString> {
    vec![std::ffi::OsString::from("/C")]
}

#[cfg(unix)]
fn recording_script(directory: &Path, name: &str, record: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let script = directory.join(name);
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf 'bridge=%s args=%s\\n' \"$FLUXD_BRIDGE\" \"$*\" > '{}'\n",
            record.display()
        ),
    )
    .expect("write shell script");
    let mut permissions = fs::metadata(&script)
        .expect("script metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).expect("script permissions");
    (PathBuf::from("/bin/sh"), script)
}

#[cfg(unix)]
fn shell_arguments() -> Vec<std::ffi::OsString> {
    Vec::new()
}
