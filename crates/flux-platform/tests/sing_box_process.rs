#![cfg(any(target_os = "linux", target_os = "android"))]

use std::ffi::OsString;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use flux_platform::internal::{
    PinnedSingBoxLaunch, SingBoxChild, SingBoxProcessAdapter, SingBoxProcessError,
    TerminationOutcome,
};
use flux_platform::{
    ProcessHandleErrorKind, ShutdownSignal, SingBoxExit, SingBoxLaunchSpec, SingBoxLauncher,
    SingBoxReadiness,
};
use tempfile::{TempDir, tempdir};

const PARENT_DEATH_HELPER_ROOT: &str = "FLUX_TEST_SING_BOX_PARENT_DEATH_ROOT";

#[test]
fn validation_uses_exact_arguments_and_reports_check_failure() {
    let fixture = Fixture::new("success");
    let adapter = SingBoxProcessAdapter;
    let pinned = pin_launch(&fixture.spec);

    let report = adapter
        .validate_pinned(&pinned, &fixture.spec)
        .expect("configuration check succeeds");
    assert_eq!(report.exit, SingBoxExit::Code(0));
    assert!(report.diagnostics.stdout_tail().contains("check stdout"));
    assert!(report.diagnostics.stderr_tail().contains("check stderr"));
    assert_exact_invocation(&fixture, &pinned, "check");

    fs::write(&fixture.spec.config, "fail").expect("write failing config mode");
    let error = adapter
        .validate_pinned(&pinned, &fixture.spec)
        .expect_err("configuration check must fail");
    let SingBoxProcessError::CheckFailed { exit, diagnostics } = error else {
        panic!("unexpected check error: {error:?}");
    };
    assert_eq!(exit, SingBoxExit::Code(42));
    assert!(diagnostics.stdout_tail().contains("invalid config stdout"));
    assert!(diagnostics.stderr_tail().contains("invalid config stderr"));
    assert!(diagnostics.stdout_tail().len() <= 8 * 1024);
    assert!(diagnostics.stderr_tail().len() <= 8 * 1024);
}

#[test]
fn version_query_uses_only_the_pinned_binary_and_returns_exact_bounded_output() {
    let fixture = Fixture::new("success");
    let pinned = pin_launch(&fixture.spec);

    let report = SingBoxProcessAdapter
        .query_version_pinned(&pinned, &fixture.spec)
        .expect("version query succeeds");

    assert_eq!(
        report.stdout(),
        b"sing-box version 1.13.14\n\nEnvironment: go1.24.5 linux/amd64\n"
    );
    assert!(report.stderr().is_empty());
}

#[test]
fn version_query_rejects_output_larger_than_the_exact_capture_budget() {
    let fixture = Fixture::new("success");
    let oversized = "x".repeat(8 * 1024 + 1);
    write_executable(
        &fixture.spec.binary,
        &format!("#!/bin/sh\nprintf '%s' '{oversized}'\n"),
    );
    let pinned = pin_launch(&fixture.spec);

    let error = SingBoxProcessAdapter
        .query_version_pinned(&pinned, &fixture.spec)
        .expect_err("oversized version output must fail closed");

    assert!(matches!(
        error,
        SingBoxProcessError::VersionOutputTooLarge {
            stream: "stdout",
            maximum: 8192,
            actual: 8193,
        }
    ));
}

#[test]
fn version_query_rejects_a_detached_descendant_that_retains_output_pipes() {
    let fixture = Fixture::new("success");
    fs::write(
        fixture.spec.working_directory.join("retain-version-output"),
        [],
    )
    .expect("enable retained version output fixture");
    let pinned = pin_launch(&fixture.spec);
    let started = Instant::now();

    let error = SingBoxProcessAdapter
        .query_version_pinned(&pinned, &fixture.spec)
        .expect_err("detached output owner must fail closed");

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "probe output draining must remain bounded"
    );
    let SingBoxProcessError::ProbeOutputDrainTimedOut {
        timeout,
        diagnostics,
    } = error
    else {
        panic!("unexpected retained-output error: {error:?}");
    };
    assert_eq!(timeout, Duration::from_millis(250));
    assert!(
        diagnostics
            .stdout_tail()
            .contains("sing-box version 1.13.14")
    );

    let descendant_pid =
        read_recorded_pid(&fixture.spec.working_directory.join("version-writer.pid"));
    // SAFETY: this PID was published by the isolated detached fixture below.
    let result = unsafe { libc::kill(descendant_pid.cast_signed(), libc::SIGKILL) };
    assert_eq!(result, 0, "kill detached version-output fixture");
    wait_for_proc_exit(descendant_pid);
}

#[test]
fn validation_timeout_is_bounded_and_forcibly_reaps_the_check() {
    let mut fixture = Fixture::new("timeout");
    fixture.spec.startup_timeout = Duration::from_millis(500);
    let pinned = pin_launch(&fixture.spec);
    let started = Instant::now();

    let error = SingBoxProcessAdapter
        .validate_pinned(&pinned, &fixture.spec)
        .expect_err("busy check must time out");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "timeout cleanup must remain bounded"
    );
    let SingBoxProcessError::CheckTimedOut {
        timeout,
        diagnostics,
    } = error
    else {
        panic!("unexpected timeout error: {error:?}");
    };
    assert_eq!(timeout, Duration::from_millis(500));
    // The deadline may win before either the fixture or capture thread is scheduled.
    assert!(diagnostics.stderr_tail().len() <= 8 * 1024);
    let writer_pid = read_recorded_pid(&fixture.spec.working_directory.join("writer.pid"));
    wait_for_proc_exit(writer_pid);
}

#[test]
fn validation_success_kills_a_continuously_writing_descendant_group() {
    let fixture = Fixture::new("success_writer");
    let pinned = pin_launch(&fixture.spec);
    let started = Instant::now();

    let report = SingBoxProcessAdapter
        .validate_pinned(&pinned, &fixture.spec)
        .expect("direct check succeeds despite inherited writer pipe");
    assert_eq!(report.exit, SingBoxExit::Code(0));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(report.diagnostics.stderr_tail().len() <= 8 * 1024);
    let writer_pid = read_recorded_pid(&fixture.spec.working_directory.join("writer.pid"));
    wait_for_proc_exit(writer_pid);
}

#[test]
fn direct_spawn_retains_child_identity_and_observes_exit() {
    let fixture = Fixture::new("exit");
    let adapter = SingBoxProcessAdapter;
    let pinned = pin_launch(&fixture.spec);
    let mut child = adapter
        .spawn_pinned(&pinned, &fixture.spec)
        .expect("spawn fake Sing-Box");

    assert_ne!(child.identity().pid(), 0);
    assert_ne!(child.identity().start_time_ticks(), 0);
    let exit = wait_for_exit(&adapter, &mut child);
    assert_eq!(exit, SingBoxExit::Code(23));
    assert_exact_invocation(&fixture, &pinned, "run");

    assert_eq!(
        adapter
            .terminate(&mut child, fixture.spec.stop_timeout)
            .expect("terminate already reaped child"),
        TerminationOutcome::AlreadyExited {
            exit: SingBoxExit::Code(23)
        }
    );
    assert!(
        fs::read_to_string(&fixture.spec.log)
            .expect("read child log")
            .contains("run exiting")
    );
}

#[test]
fn retained_sing_box_child_opens_exact_process_handle_without_transferring_reap() {
    let fixture = Fixture::new("term");
    let adapter = SingBoxProcessAdapter;
    let pinned = pin_launch(&fixture.spec);
    let mut child = adapter
        .spawn_pinned(&pinned, &fixture.spec)
        .expect("spawn long-lived fake Sing-Box");
    wait_for_log(&fixture.spec.log, "term ready");

    let handle = child
        .open_process_handle()
        .expect("open exact retained child handle");
    assert_eq!(handle.identity().pid().get(), child.identity().pid());
    assert_eq!(
        handle.identity().start_time_ticks().get(),
        child.identity().start_time_ticks()
    );
    let observation = handle
        .reobserve()
        .expect("reobserve the same live Sing-Box child");
    assert_eq!(observation.identity(), handle.identity());
    assert_eq!(observation.credentials(), handle.credentials());

    assert_eq!(
        adapter
            .terminate(&mut child, fixture.spec.stop_timeout)
            .expect("the adapter retains termination and reap authority"),
        TerminationOutcome::Terminated {
            exit: SingBoxExit::Code(0)
        }
    );
    let error = child
        .open_process_handle()
        .expect_err("a reaped Sing-Box child cannot issue a fresh process handle");
    assert_eq!(error.kind(), ProcessHandleErrorKind::Exited);
    let error = handle
        .reobserve()
        .expect_err("a reaped Sing-Box child cannot remain live through its pidfd");
    assert_eq!(error.kind(), ProcessHandleErrorKind::Exited);
}

#[test]
fn sing_box_child_is_killed_when_its_supervisor_process_dies() {
    if let Some(root) = std::env::var_os(PARENT_DEATH_HELPER_ROOT) {
        run_parent_death_helper(Path::new(&root));
        return;
    }

    let directory = tempdir().expect("temporary parent-death directory");
    let child_pid_path = directory.path().join("sing-box.pid");
    let mut supervisor = NestedSupervisor::spawn(
        "sing_box_child_is_killed_when_its_supervisor_process_dies",
        PARENT_DEATH_HELPER_ROOT,
        directory.path(),
        child_pid_path.clone(),
    );
    let child_pid = wait_for_recorded_pid(&child_pid_path);

    let status = supervisor.kill_and_wait();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    wait_for_proc_exit(child_pid);
}

#[test]
fn unowned_tun_is_not_ready_and_sigterm_survives_a_blocked_parent_mask() {
    let mut fixture = Fixture::new("term");
    fixture.spec.startup_timeout = Duration::from_millis(75);
    let adapter = SingBoxProcessAdapter;
    let shutdown = ShutdownSignal::install().expect("block parent shutdown signals");
    let pinned = pin_launch(&fixture.spec);
    let mut child = adapter
        .spawn_pinned(&pinned, &fixture.spec)
        .expect("spawn fake Sing-Box");
    wait_for_log(&fixture.spec.log, "term ready");

    let error = adapter
        .wait_ready(&mut child, &fixture.spec)
        .expect_err("pre-existing loopback is not owned TUN evidence");
    assert!(matches!(
        error,
        SingBoxProcessError::ReadinessTimedOut { .. }
    ));
    let outcome = adapter
        .terminate(&mut child, Duration::from_millis(500))
        .expect("terminate fake Sing-Box");
    assert_eq!(
        outcome,
        TerminationOutcome::Terminated {
            exit: SingBoxExit::Code(0)
        }
    );
    drop(shutdown);
}

#[test]
fn termination_escalates_to_sigkill_and_reaps_an_uncooperative_child() {
    let fixture = Fixture::new("ignore");
    let adapter = SingBoxProcessAdapter;
    let pinned = pin_launch(&fixture.spec);
    let mut child = adapter
        .spawn_pinned(&pinned, &fixture.spec)
        .expect("spawn fake Sing-Box");
    wait_for_log(&fixture.spec.log, "ignore ready");

    let outcome = adapter
        .terminate(&mut child, Duration::from_millis(50))
        .expect("escalate termination");
    assert_eq!(
        outcome,
        TerminationOutcome::Killed {
            exit: SingBoxExit::Signal(libc::SIGKILL)
        }
    );
}

#[test]
fn dropping_a_running_child_defers_reaping_without_blocking_the_caller() {
    let fixture = Fixture::new("ignore");
    let pinned = pin_launch(&fixture.spec);
    let child = SingBoxProcessAdapter
        .spawn_pinned(&pinned, &fixture.spec)
        .expect("spawn fake Sing-Box");
    wait_for_log(&fixture.spec.log, "ignore ready");
    let pid = child.identity().pid();

    let started = Instant::now();
    drop(child);
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "Drop must transfer reaping instead of waiting"
    );
    wait_for_proc_exit(pid);
}

#[test]
fn pinned_busybox_check_uses_fd_paths_and_is_reusable_for_run() {
    let mut fixture = Fixture::new("success");
    let busybox_record = fixture.root.path().join("pinned-busybox-argv");
    let busybox_path = fake_busybox(fixture.root.path(), &busybox_record);
    fixture.spec.launcher = SingBoxLauncher::BusyBoxSetuidgid {
        busybox: busybox_path.clone(),
        identity: OsString::from("1000:3003"),
    };
    let pinned = PinnedSingBoxLaunch::new(
        File::open(&fixture.spec.binary).expect("open pinned binary"),
        File::open(&fixture.spec.config).expect("open pinned config"),
        Some(File::open(busybox_path).expect("open pinned BusyBox")),
    )
    .expect("validate pinned descriptors");
    let adapter = SingBoxProcessAdapter;

    adapter
        .query_version_pinned(&pinned, &fixture.spec)
        .expect("query version through pinned BusyBox");
    let version_arguments = read_arguments(&busybox_record);
    assert_eq!(version_arguments[0], "setuidgid");
    assert_eq!(version_arguments[1], "1000:3003");
    assert_eq!(
        version_arguments[2],
        format!("/proc/self/fd/{}", pinned.binary().as_raw_fd())
    );
    assert_eq!(version_arguments[3..], ["version"]);

    adapter
        .validate_pinned(&pinned, &fixture.spec)
        .expect("validate through pinned BusyBox");
    let check_arguments = read_arguments(&busybox_record);
    assert_eq!(check_arguments[0], "setuidgid");
    assert_eq!(check_arguments[1], "1000:3003");
    assert_eq!(
        check_arguments[2],
        format!("/proc/self/fd/{}", pinned.binary().as_raw_fd())
    );
    assert_eq!(check_arguments[3], "check");
    assert_eq!(check_arguments[4], "-c");
    assert_eq!(
        check_arguments[5],
        format!("/proc/self/fd/{}", pinned.config().as_raw_fd())
    );
    assert_eq!(check_arguments[6], "-D");
    assert_eq!(
        check_arguments[7],
        fixture.spec.working_directory.display().to_string()
    );

    let mut child = adapter
        .spawn_pinned(&pinned, &fixture.spec)
        .expect("reuse pinned descriptors for run");
    assert_eq!(wait_for_exit(&adapter, &mut child), SingBoxExit::Code(23));
    let run_arguments = read_arguments(&busybox_record);
    assert_eq!(run_arguments[3], "run");
}

#[test]
fn spawn_rejects_symlink_and_nonregular_log_targets() {
    use std::os::unix::fs::symlink;

    let mut fixture = Fixture::new("exit");
    let protected = fixture.root.path().join("protected");
    fs::write(&protected, "unchanged").expect("write protected fixture");
    symlink(&protected, &fixture.spec.log).expect("create log symlink");
    let pinned = pin_launch(&fixture.spec);

    let error = SingBoxProcessAdapter
        .spawn_pinned(&pinned, &fixture.spec)
        .expect_err("log symlink must be rejected");
    assert!(matches!(error, SingBoxProcessError::OpenLog { .. }));
    assert_eq!(
        fs::read_to_string(&protected).expect("read protected fixture"),
        "unchanged"
    );

    fixture.spec.log = PathBuf::from("/dev/null");
    let error = SingBoxProcessAdapter
        .spawn_pinned(&pinned, &fixture.spec)
        .expect_err("character-device log must be rejected");
    assert!(matches!(error, SingBoxProcessError::OpenLog { .. }));
}

#[test]
fn spawn_restricts_an_existing_regular_log_to_owner_access() {
    let fixture = Fixture::new("exit");
    fs::write(&fixture.spec.log, "existing\n").expect("create existing log");
    fs::set_permissions(&fixture.spec.log, fs::Permissions::from_mode(0o666))
        .expect("make log permissive");

    let adapter = SingBoxProcessAdapter;
    let pinned = pin_launch(&fixture.spec);
    let mut child = adapter
        .spawn_pinned(&pinned, &fixture.spec)
        .expect("spawn fake Sing-Box");
    assert_eq!(wait_for_exit(&adapter, &mut child), SingBoxExit::Code(23));

    let mode = fs::metadata(&fixture.spec.log)
        .expect("read log metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn diagnostics_stay_bound_to_the_opened_log_descriptor() {
    let fixture = Fixture::new("exit");
    let adapter = SingBoxProcessAdapter;
    let pinned = pin_launch(&fixture.spec);
    let mut child = adapter
        .spawn_pinned(&pinned, &fixture.spec)
        .expect("spawn fake Sing-Box");
    wait_for_log(&fixture.spec.log, "run exiting");

    let original_log = fixture.root.path().join("original-log");
    fs::rename(&fixture.spec.log, &original_log).expect("rename opened log");
    fs::write(&fixture.spec.log, "replacement path contents\n").expect("replace log path");

    let error = adapter
        .wait_ready(&mut child, &fixture.spec)
        .expect_err("exited child is not ready");
    let SingBoxProcessError::ExitedBeforeReady { diagnostics, .. } = error else {
        panic!("unexpected readiness error: {error:?}");
    };
    assert!(diagnostics.log_tail().contains("run exiting"));
    assert!(!diagnostics.log_tail().contains("replacement path contents"));
}

#[test]
fn every_launch_path_must_be_absolute() {
    let fixture = Fixture::new("success");
    let adapter = SingBoxProcessAdapter;
    let pinned = pin_launch(&fixture.spec);
    let cases = [
        ("binary", relative_spec(&fixture.spec, "binary")),
        ("config", relative_spec(&fixture.spec, "config")),
        (
            "working_directory",
            relative_spec(&fixture.spec, "working_directory"),
        ),
        ("log", relative_spec(&fixture.spec, "log")),
        (
            "launcher.busybox",
            SingBoxLaunchSpec {
                launcher: SingBoxLauncher::BusyBoxSetuidgid {
                    busybox: PathBuf::from("busybox"),
                    identity: OsString::from("1000:3003"),
                },
                ..fixture.spec.clone()
            },
        ),
    ];

    for (expected_field, spec) in cases {
        let error = adapter
            .validate_pinned(&pinned, &spec)
            .expect_err("relative launch path must be rejected");
        assert!(matches!(
            error,
            SingBoxProcessError::InvalidSpec { field, .. } if field == expected_field
        ));
    }
}

#[test]
fn busybox_identity_rejects_option_like_and_malformed_values() {
    let fixture = Fixture::new("success");
    let pinned = pin_launch(&fixture.spec);
    for identity in [
        "-root",
        "+1000",
        "root-wheel",
        "root::wheel",
        "root:",
        ":wheel",
        "root:wheel:extra",
        "4294967296",
    ] {
        let spec = SingBoxLaunchSpec {
            launcher: SingBoxLauncher::BusyBoxSetuidgid {
                busybox: fixture.root.path().join("busybox"),
                identity: OsString::from(identity),
            },
            ..fixture.spec.clone()
        };
        let error = SingBoxProcessAdapter
            .validate_pinned(&pinned, &spec)
            .expect_err("unsafe setuidgid identity must be rejected");
        assert!(matches!(
            error,
            SingBoxProcessError::InvalidSpec {
                field: "launcher.identity",
                ..
            }
        ));
    }
}

#[test]
fn zero_startup_and_termination_deadlines_are_rejected() {
    let mut fixture = Fixture::new("term");
    fixture.spec.startup_timeout = Duration::ZERO;
    let pinned = pin_launch(&fixture.spec);
    let error = SingBoxProcessAdapter
        .validate_pinned(&pinned, &fixture.spec)
        .expect_err("zero startup deadline must be rejected");
    assert!(matches!(
        error,
        SingBoxProcessError::InvalidSpec {
            field: "startup_timeout",
            ..
        }
    ));

    fixture.spec.startup_timeout = Duration::from_secs(1);
    let mut child = SingBoxProcessAdapter
        .spawn_pinned(&pinned, &fixture.spec)
        .expect("spawn fake Sing-Box");
    let error = SingBoxProcessAdapter
        .terminate(&mut child, Duration::ZERO)
        .expect_err("zero termination deadline must be rejected");
    assert!(matches!(
        error,
        SingBoxProcessError::InvalidSpec {
            field: "termination timeout",
            ..
        }
    ));
    wait_for_log(&fixture.spec.log, "term ready");
    assert!(matches!(
        SingBoxProcessAdapter
            .terminate(&mut child, fixture.spec.stop_timeout)
            .expect("child remains owned after rejected deadline"),
        TerminationOutcome::Terminated { .. }
    ));
}

struct Fixture {
    root: TempDir,
    invocation: PathBuf,
    spec: SingBoxLaunchSpec,
}

struct NestedSupervisor {
    child: Child,
    descendant_pid_path: PathBuf,
}

impl NestedSupervisor {
    fn spawn(test: &str, environment: &str, root: &Path, descendant_pid_path: PathBuf) -> Self {
        let child = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg(test)
            .arg("--nocapture")
            .env(environment, root)
            .spawn()
            .expect("spawn isolated Sing-Box supervisor");
        Self {
            child,
            descendant_pid_path,
        }
    }

    fn kill_and_wait(&mut self) -> ExitStatus {
        self.child.kill().expect("kill isolated supervisor");
        self.child.wait().expect("reap isolated supervisor")
    }
}

impl Drop for NestedSupervisor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if thread::panicking()
            && let Ok(pid) = fs::read_to_string(&self.descendant_pid_path)
            && let Ok(pid) = pid.trim().parse::<libc::pid_t>()
        {
            // SAFETY: during unwind this PID came from the isolated helper;
            // SIGKILL prevents a failed containment assertion leaking it.
            let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

impl Fixture {
    fn new(mode: &str) -> Self {
        let root = tempdir().expect("temporary test directory");
        let binary = fake_sing_box(root.path());
        let working_directory = root.path().join("work dir; no shell");
        fs::create_dir(&working_directory).expect("create working directory");
        let config = root.path().join("config; literal.toml");
        fs::write(&config, mode).expect("write fake config mode");
        let invocation = working_directory.join("invocation");
        let spec = SingBoxLaunchSpec {
            binary,
            config,
            working_directory,
            log: root.path().join("sing-box.log"),
            launcher: SingBoxLauncher::Direct,
            readiness: SingBoxReadiness::TunInterface {
                name: "lo".to_owned(),
            },
            startup_timeout: Duration::from_secs(1),
            stop_timeout: Duration::from_millis(500),
        };
        Self {
            root,
            invocation,
            spec,
        }
    }
}

fn fake_sing_box(directory: &Path) -> PathBuf {
    let script = directory.join("sing-box fake; literal");
    write_executable(
        &script,
        r#"#!/bin/sh
mode=$1
if [ "$mode" = version ]; then
    [ "$#" -eq 1 ] || exit 66
    if [ -f "$PWD/retain-version-output" ]; then
        /usr/bin/setsid /bin/sh -c 'printf "%s\n" "$$" > "$1"; sleep 4' sh "$PWD/version-writer.pid" &
        while [ ! -s "$PWD/version-writer.pid" ]; do :; done
    fi
    printf '%s\n\n%s\n' 'sing-box version 1.13.14' 'Environment: go1.24.5 linux/amd64'
    exit 0
fi
printf '%s\n' "$@" > "$5/invocation"
case "$mode" in
  check)
    case "$(cat "$3")" in
      success)
        printf '%s\n' 'check stdout'
        printf '%s\n' 'check stderr' >&2
        exit 0
        ;;
      success_writer)
        (while :; do printf '%s\n' 'descendant keeps writing' >&2; done) &
        printf '%s\n' "$!" > "$5/writer.pid"
        exit 0
        ;;
      fail)
        printf '%s\n' 'invalid config stdout'
        printf '%s\n' 'invalid config stderr' >&2
        exit 42
        ;;
      timeout)
        printf '%s\n' 'check waiting' >&2
        (while :; do printf '%s\n' 'timeout descendant keeps writing' >&2; done) &
        printf '%s\n' "$!" > "$5/writer.pid"
        while :; do :; done
        ;;
    esac
    ;;
  run)
    case "$(cat "$3")" in
      success|exit)
        printf '%s\n' 'run exiting'
        exit 23
        ;;
      term)
        trap 'exit 0' TERM
        printf '%s\n' 'term ready'
        while :; do :; done
        ;;
      ignore)
        trap '' TERM
        printf '%s\n' 'ignore ready'
        while :; do :; done
        ;;
    esac
    ;;
esac
exit 64
"#,
    );
    script
}

fn fake_busybox(directory: &Path, record: &Path) -> PathBuf {
    let script = directory.join("busybox");
    write_executable(
        &script,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n[ \"$1\" = setuidgid ] || exit 65\nshift 2\nexec \"$@\"\n",
            record.display()
        ),
    );
    script
}

fn relative_spec(spec: &SingBoxLaunchSpec, field: &str) -> SingBoxLaunchSpec {
    let mut spec = spec.clone();
    match field {
        "binary" => spec.binary = PathBuf::from("sing-box"),
        "config" => spec.config = PathBuf::from("config.json"),
        "working_directory" => spec.working_directory = PathBuf::from("work"),
        "log" => spec.log = PathBuf::from("sing-box.log"),
        _ => panic!("unknown launch path field"),
    }
    spec
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write executable fixture");
    let mut permissions = fs::metadata(path).expect("fixture metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("fixture permissions");
}

fn pin_launch(spec: &SingBoxLaunchSpec) -> PinnedSingBoxLaunch {
    let busybox = match &spec.launcher {
        SingBoxLauncher::Direct => None,
        SingBoxLauncher::BusyBoxSetuidgid { busybox, .. } => {
            Some(File::open(busybox).expect("open pinned BusyBox"))
        }
    };
    PinnedSingBoxLaunch::new(
        File::open(&spec.binary).expect("open pinned binary"),
        File::open(&spec.config).expect("open pinned config"),
        busybox,
    )
    .expect("validate pinned launch descriptors")
}

fn run_parent_death_helper(root: &Path) {
    let binary = fake_sing_box(root);
    let working_directory = root.join("supervised work");
    fs::create_dir(&working_directory).expect("create supervised working directory");
    let config = root.join("supervised-config");
    fs::write(&config, "ignore").expect("write supervised config");
    let spec = SingBoxLaunchSpec {
        binary,
        config,
        working_directory,
        log: root.join("supervised.log"),
        launcher: SingBoxLauncher::Direct,
        readiness: SingBoxReadiness::TunInterface {
            name: "lo".to_owned(),
        },
        startup_timeout: Duration::from_secs(1),
        stop_timeout: Duration::from_millis(500),
    };
    let pinned = pin_launch(&spec);
    let child = SingBoxProcessAdapter
        .spawn_pinned(&pinned, &spec)
        .expect("spawn supervised fake Sing-Box");
    fs::write(
        root.join("sing-box.pid"),
        child.identity().pid().to_string(),
    )
    .expect("publish supervised Sing-Box PID");

    loop {
        thread::park();
    }
}

fn assert_exact_invocation(fixture: &Fixture, pinned: &PinnedSingBoxLaunch, mode: &str) {
    let arguments = fs::read_to_string(&fixture.invocation).expect("read invocation record");
    let expected = [
        mode.to_owned(),
        "-c".to_owned(),
        format!("/proc/self/fd/{}", pinned.config().as_raw_fd()),
        "-D".to_owned(),
        fixture.spec.working_directory.display().to_string(),
    ]
    .join("\n");
    assert_eq!(arguments.trim_end(), expected);
}

fn read_arguments(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .expect("read argument record")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn read_recorded_pid(path: &Path) -> u32 {
    fs::read_to_string(path)
        .expect("read recorded process ID")
        .trim()
        .parse::<u32>()
        .expect("valid recorded process ID")
}

fn wait_for_recorded_pid(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match fs::read_to_string(path) {
            Ok(pid) => {
                return pid
                    .trim()
                    .parse::<u32>()
                    .expect("valid supervised process ID");
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("read supervised process ID: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "supervised process did not publish its process ID"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_exit(adapter: &SingBoxProcessAdapter, child: &mut SingBoxChild) -> SingBoxExit {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(exit) = adapter.try_wait(child).expect("poll child") {
            return exit;
        }
        assert!(Instant::now() < deadline, "child did not exit");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_log(path: &Path, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match fs::read_to_string(path) {
            Ok(contents) if contents.contains(expected) => return,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("read fake Sing-Box log: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "log never contained {expected:?}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_proc_exit(pid: u32) {
    let path = PathBuf::from(format!("/proc/{pid}"));
    let deadline = Instant::now() + Duration::from_secs(2);
    while path.exists() {
        assert!(
            Instant::now() < deadline,
            "background reaper did not reap {pid}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
