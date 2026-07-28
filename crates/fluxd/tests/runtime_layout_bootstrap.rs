#![cfg(any(target_os = "linux", target_os = "android"))]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use flux_core::MutationGate;
use fluxd::{MAX_RUNTIME_LOG_FILE_BYTES, SocketControlClient};
use tempfile::tempdir;

#[test]
fn real_daemon_bootstraps_and_owns_a_fresh_script_free_runtime_layout() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let configuration = root.join("conf");
    let boot_id = configuration.join("boot-id");
    let selinux_enforce = configuration.join("selinux-enforce");
    fs::create_dir(&root).expect("create fresh runtime root");
    fs::create_dir(&configuration).expect("create configuration directory");
    fs::write(&boot_id, "deliberately-unverified\n").expect("write boot identity fixture");
    fs::write(&selinux_enforce, "1\n").expect("write SELinux fixture");

    let run = root.join("run");
    let state = root.join("state");
    let socket = run.join("fluxd.sock");
    assert!(!run.exists());
    assert!(!state.exists());
    assert!(!root.join("scripts").exists());

    let mut daemon = KillOnDrop::spawn(
        Command::new(env!("CARGO_BIN_EXE_fluxd"))
            .arg("daemon")
            .env_clear()
            .env("FLUX_ROOT", &root)
            .env("FLUX_BOOT_ID_PATH", &boot_id)
            .env("FLUX_SELINUX_ENFORCE_PATH", &selinux_enforce)
            .env("FLUX_SHELL", "/bin/sh")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit()),
    );

    wait_for_socket(daemon.child_mut(), &socket);
    let snapshot = SocketControlClient::new(&socket)
        .status()
        .expect("query initialized daemon");
    assert!(matches!(
        snapshot.capability_profile.mutation_gate(),
        MutationGate::ReadOnly { .. }
    ));

    assert_private_directory(&run);
    assert_private_directory(&state);
    assert_private_file(&run.join("fluxd.lease"));
    assert_private_file(&run.join("fluxd.log"));
    assert_private_file(&run.join("flux.log"));
    assert!(!run.join("fluxd.log.1").exists());
    assert!(!run.join("flux.log.1").exists());
    assert!(!root.join("scripts").exists());

    let daemon_pid = libc::pid_t::try_from(daemon.child_mut().id()).expect("daemon PID fits pid_t");
    // SAFETY: the positive child PID was observed through its live control socket and remains owned
    // by the guard until `wait_for_exit` reaps it; SIGTERM has no pointer arguments.
    let signal_result = unsafe { libc::kill(daemon_pid, libc::SIGTERM) };
    assert_eq!(signal_result, 0);
    let status = daemon.wait_for_exit(Duration::from_secs(3));
    assert!(status.success(), "daemon shutdown failed: {status}");

    let daemon_log = fs::read_to_string(run.join("fluxd.log")).expect("read daemon log");
    assert!(daemon_log.contains("severity=info component=daemon generation=-"));
    assert!(daemon_log.contains("runtime layout admitted"));
    assert!(daemon_log.contains("daemon shutdown completed"));
    assert!(daemon_log.len() as u64 <= MAX_RUNTIME_LOG_FILE_BYTES);
    assert!(fs::metadata(run.join("flux.log")).unwrap().len() <= MAX_RUNTIME_LOG_FILE_BYTES);
}

fn assert_private_directory(path: &Path) {
    let metadata = fs::metadata(path)
        .unwrap_or_else(|error| panic!("inspect private directory {}: {error}", path.display()));
    assert!(metadata.is_dir(), "{} is not a directory", path.display());
    assert_eq!(metadata.mode() & 0o777, 0o700);
    // SAFETY: `geteuid` has no preconditions and retains no state.
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
}

fn assert_private_file(path: &Path) {
    let metadata = fs::metadata(path)
        .unwrap_or_else(|error| panic!("inspect private file {}: {error}", path.display()));
    assert!(metadata.is_file(), "{} is not a file", path.display());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    // SAFETY: `geteuid` has no preconditions and retains no state.
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
}

fn wait_for_socket(child: &mut Child, socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if socket.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("inspect daemon process") {
            panic!(
                "daemon exited before binding {}: {status}",
                socket.display()
            );
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not bind control socket"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

struct KillOnDrop {
    child: Child,
    reaped: bool,
}

impl KillOnDrop {
    fn spawn(command: &mut Command) -> Self {
        Self {
            child: command.spawn().expect("start real fluxd daemon"),
            reaped: false,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("inspect daemon exit") {
                self.reaped = true;
                return status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let status = self.child.wait().expect("reap timed-out daemon");
                self.reaped = true;
                panic!("daemon did not exit within {timeout:?}: {status}");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
