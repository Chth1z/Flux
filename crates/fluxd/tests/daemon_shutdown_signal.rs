#![cfg(any(target_os = "linux", target_os = "android"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;

const SIGTERM: std::ffi::c_int = 15;

unsafe extern "C" {
    fn kill(process: std::ffi::c_int, signal: std::ffi::c_int) -> std::ffi::c_int;
}

#[test]
fn process_directed_sigterm_stops_daemon_cleanly_with_live_legacy_worker() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let socket_path = root.join("run/fluxd.sock");
    let dispatcher_record = root.join("run/dispatcher.record");
    let boot_id_path = directory.path().join("boot-id");
    let disable_path = directory.path().join("disable");

    fs::create_dir_all(root.join("scripts")).expect("create scripts directory");
    fs::create_dir_all(root.join("state")).expect("create state directory");
    fs::create_dir_all(root.join("run")).expect("create run directory");
    fs::write(&boot_id_path, "signal-test-boot\n").expect("write boot ID");
    write_script(
        &root.join("scripts/dispatcher"),
        &format!(
            "printf '%s\\n' \"$*\" > '{}'\n",
            dispatcher_record.display()
        ),
    );
    write_script(&root.join("scripts/addrsync"), "exit 0\n");

    let mut child = Command::new(fluxd_binary())
        .arg("daemon")
        .env("FLUX_ROOT", &root)
        .env("FLUXD_SOCKET", &socket_path)
        .env("FLUX_BOOT_ID_PATH", &boot_id_path)
        .env("FLUX_DISABLE_PATH", &disable_path)
        .env("FLUX_SHELL", "/bin/sh")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start fluxd daemon");

    wait_for_daemon_ready(&mut child, &socket_path, &dispatcher_record);
    // SAFETY: `child.id()` names the live daemon process observed ready above.
    assert_eq!(unsafe { kill(child.id() as std::ffi::c_int, SIGTERM) }, 0);

    let status = wait_for_exit(&mut child, Duration::from_secs(3)).unwrap_or_else(|| {
        let _ = child.kill();
        let _ = child.wait();
        panic!("daemon did not stop after SIGTERM");
    });
    assert!(
        status.success(),
        "daemon must consume SIGTERM through signalfd, not terminate from signal {:?}: {status}",
        status.signal()
    );
}

fn fluxd_binary() -> std::path::PathBuf {
    std::env::current_exe()
        .expect("current test executable")
        .parent()
        .and_then(Path::parent)
        .expect("Cargo target debug directory")
        .join("fluxd")
}

fn write_script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}")).expect("write script");
    let mut permissions = fs::metadata(path).expect("script metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("script permissions");
}

fn wait_for_daemon_ready(child: &mut Child, socket_path: &Path, dispatcher_record: &Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if socket_path.exists() && dispatcher_record.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("inspect daemon status") {
            panic!("daemon exited before becoming ready: {status}");
        }
        assert!(Instant::now() < deadline, "daemon did not become ready");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("inspect daemon status") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}
