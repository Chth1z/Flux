#![cfg(any(target_os = "linux", target_os = "android"))]

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use flux_core::ControlError;
use flux_testkit::StaticKernelReleaseSource;
use fluxd::{DaemonError, DaemonOptions, run_daemon};
use tempfile::tempdir;

#[test]
fn failed_startup_reconciliation_never_admits_a_control_socket() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let boot_id_path = directory.path().join("boot-id");
    let disable_path = directory.path().join("disable");
    let intent_path = root.join("state/administrative-intent.json");
    let options = daemon_options(
        &root,
        &boot_id_path,
        &disable_path,
        intent_path,
        "exit 73\n",
    );
    let socket_path = options.socket_path.clone();
    let kernel = StaticKernelReleaseSource::new("5.10.0");

    let error = run_daemon(&kernel, options).expect_err("startup reconciliation must fail");

    assert!(
        matches!(error, DaemonError::Control(ControlError::Dispatcher(_))),
        "unexpected startup error: {error:?}"
    );
    assert!(
        !socket_path.exists(),
        "the control socket must not exist after failed startup reconciliation"
    );
}

#[test]
fn startup_persistence_error_preserves_its_source_chain_before_socket_admission() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let boot_id_path = directory.path().join("boot-id");
    let disable_path = directory.path().join("disable");
    let blocked_parent = root.join("state/not-a-directory");

    fs::create_dir_all(root.join("state")).expect("create state directory");
    fs::write(&blocked_parent, "blocks intent directory traversal\n")
        .expect("create non-directory intent parent");
    fs::write(&disable_path, "").expect("request stopped startup state");

    let options = daemon_options(
        &root,
        &boot_id_path,
        &disable_path,
        blocked_parent.join("administrative-intent.json"),
        "exit 73\n",
    );
    let socket_path = options.socket_path.clone();
    let kernel = StaticKernelReleaseSource::new("5.10.0");

    let error = run_daemon(&kernel, options).expect_err("startup persistence must fail");
    let DaemonError::Control(control_error @ ControlError::Persistence { .. }) = &error else {
        panic!("unexpected startup error: {error:?}");
    };
    let intent_error = control_error
        .source()
        .expect("persistence error retains the intent-store source");
    let io_error = intent_error
        .source()
        .expect("intent-store error retains the operating-system source");

    assert!(
        io_error.downcast_ref::<std::io::Error>().is_some(),
        "source chain must end in an I/O error, got {io_error:?}"
    );
    assert!(
        !socket_path.exists(),
        "the control socket must not exist after startup persistence failure"
    );
}

fn daemon_options(
    root: &Path,
    boot_id_path: &Path,
    disable_path: &Path,
    intent_path: PathBuf,
    dispatcher_body: &str,
) -> DaemonOptions {
    let scripts = root.join("scripts");
    let run = root.join("run");
    let dispatcher_script = scripts.join("dispatcher");
    let addrsync_script = scripts.join("addrsync");

    fs::create_dir_all(&scripts).expect("create scripts directory");
    fs::create_dir_all(root.join("state")).expect("create state directory");
    fs::create_dir_all(&run).expect("create run directory");
    fs::write(boot_id_path, "startup-admission-test-boot\n").expect("write boot identity");
    write_script(&dispatcher_script, dispatcher_body);
    write_script(&addrsync_script, "exit 0\n");

    DaemonOptions {
        socket_path: run.join("fluxd.sock"),
        shell: PathBuf::from("/bin/sh"),
        dispatcher_script,
        addrsync_script,
        intent_path,
        boot_id_path: boot_id_path.to_owned(),
        disable_path: disable_path.to_owned(),
        queue_capacity: 1,
    }
}

fn write_script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}")).expect("write script");
    let mut permissions = fs::metadata(path).expect("script metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("script permissions");
}
