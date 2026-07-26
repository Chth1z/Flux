use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

#[test]
fn binary_dispatches_cleanup_before_the_socket_client_and_requires_exact_syntax() {
    let fixture = Fixture::new();

    let output = fixture.run(["cleanup", "--offline"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"cleanup complete\n");
    assert!(output.stderr.is_empty());
    assert_eq!(
        fs::read_to_string(&fixture.marker).expect("read recovery marker"),
        "1:startup-recover\n"
    );
    assert!(fixture.lease.is_file());

    fs::remove_file(&fixture.marker).expect("remove recovery marker");
    fs::remove_file(&fixture.lease).expect("remove unlocked lease file");
    let output = fixture.run(["cleanup"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"fluxd: cleanup requires exactly --offline\n"
    );
    assert!(!fixture.marker.exists());
    assert!(!fixture.lease.exists());
}

#[test]
fn binary_reports_cross_process_daemon_lease_contention_as_temporary_failure() {
    let fixture = Fixture::new();
    let lease = create_and_lock(&fixture.lease);

    let output = fixture.run(["cleanup", "--offline"]);

    assert_eq!(output.status.code(), Some(75));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .expect("UTF-8 error")
            .contains("cleanup busy")
    );
    assert!(!fixture.marker.exists());
    drop(lease);
}

struct Fixture {
    _root: TempDir,
    root_path: PathBuf,
    marker: PathBuf,
    lease: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().expect("temporary root");
        let root_path = root.path().to_owned();
        let run = root_path.join("run");
        let scripts = root_path.join("scripts");
        fs::create_dir(&run).expect("create run directory");
        fs::create_dir(&scripts).expect("create scripts directory");
        fs::write(
            scripts.join("dispatcher"),
            concat!(
                "#!/bin/sh\n",
                "printf '%s:%s\\n' \"${FLUXD_BRIDGE:-}\" \"${1:-}\" >\"${CLEANUP_MARKER}\"\n"
            ),
        )
        .expect("write dispatcher");
        Self {
            marker: root_path.join("recovered"),
            lease: run.join("fluxd.lease"),
            root_path,
            _root: root,
        }
    }

    fn run<const N: usize>(&self, arguments: [&str; N]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_fluxd"))
            .args(arguments)
            .env("FLUX_ROOT", &self.root_path)
            .env("FLUX_SHELL", "/bin/sh")
            .env("CLEANUP_MARKER", &self.marker)
            .env(
                "FLUXD_SOCKET",
                self.root_path.join("missing/socket/fluxd.sock"),
            )
            .output()
            .expect("execute fluxd")
    }
}

fn create_and_lock(path: &Path) -> File {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .expect("create daemon lease fixture");
    // SAFETY: `file` owns a valid descriptor for the duration of this call.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(result, 0, "lock daemon lease fixture");
    file
}
