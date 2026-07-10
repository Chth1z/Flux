use std::fs;
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::sync::mpsc;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::thread;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::time::{Duration, Instant};

use flux_core::{LegacyDispatcher, LegacyIntent, Reason};
#[cfg(any(target_os = "linux", target_os = "android"))]
use flux_platform::ShutdownSignal;
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

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn legacy_child_can_receive_sigterm_when_dispatcher_worker_inherits_blocked_signals() {
    let directory = tempdir().expect("temporary directory");
    let child_pid_path = directory.path().join("legacy-child.pid");
    let dispatcher_script = termination_script(directory.path(), &child_pid_path);
    let addrsync_script = directory.path().join("unused-addrsync");
    let shutdown = ShutdownSignal::install().expect("block daemon shutdown signals");
    let (result_tx, result_rx) = mpsc::sync_channel(1);

    let worker = thread::spawn(move || {
        let mut adapter = ProcessLegacyDispatcher::new(LegacyScriptPaths {
            shell: PathBuf::from("/bin/sh"),
            shell_args: Vec::new(),
            dispatcher: dispatcher_script,
            addrsync: addrsync_script,
        });
        result_tx
            .send(adapter.execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            }))
            .expect("publish dispatcher result");
    });

    let child_pid = wait_for_child_pid(&child_pid_path);
    // SAFETY: the script published its live process ID after installing its
    // termination trap.
    assert_eq!(unsafe { libc::kill(child_pid, libc::SIGTERM) }, 0);

    let result = match result_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // SAFETY: the script process is still live because the synchronous
            // dispatcher has not returned. SIGKILL guarantees test cleanup.
            let _ = unsafe { libc::kill(child_pid, libc::SIGKILL) };
            let _ = result_rx.recv_timeout(Duration::from_secs(1));
            panic!("legacy child did not receive SIGTERM");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("dispatcher worker exited without publishing a result");
        }
    };

    worker.join().expect("dispatcher worker");
    result.expect("SIGTERM trap exits the legacy child successfully");
    drop(shutdown);
}

fn read_record(path: &Path) -> String {
    fs::read_to_string(path)
        .expect("recorded invocation")
        .trim()
        .to_owned()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn termination_script(directory: &Path, child_pid_path: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let script = directory.join("termination-dispatcher");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\ntrap 'exit 0' INT TERM\nprintf '%s\\n' \"$$\" > '{}'\nwhile :; do :; done\n",
            child_pid_path.display()
        ),
    )
    .expect("write termination script");
    let mut permissions = fs::metadata(&script)
        .expect("termination script metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).expect("termination script permissions");
    script
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn wait_for_child_pid(path: &Path) -> libc::pid_t {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match fs::read_to_string(path) {
            Ok(pid) => {
                return pid
                    .trim()
                    .parse::<libc::pid_t>()
                    .expect("valid legacy child process ID");
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("read legacy child process ID: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "legacy child did not publish its process ID"
        );
        thread::sleep(Duration::from_millis(10));
    }
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
