use std::error::Error;
use std::fs;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::sync::mpsc;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::thread;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{
    os::unix::process::ExitStatusExt,
    process::{Child, Command, ExitStatus},
};

#[cfg(any(target_os = "linux", target_os = "android"))]
use flux_platform::ShutdownSignal;
use flux_platform::{
    DispatcherPhaseCommand, PhaseDispatcherError, PhaseDispatcherErrorKind, PhaseDispatcherPaths,
    ProcessPhaseDispatcher,
};
use tempfile::tempdir;

#[cfg(any(target_os = "linux", target_os = "android"))]
const PARENT_DEATH_HELPER_ROOT: &str = "FLUX_TEST_PHASE_PARENT_DEATH_ROOT";

#[test]
fn phase_adapter_maps_all_commands_to_exact_bridge_argv() {
    let directory = tempdir().expect("temporary directory");
    let record = directory.path().join("phase.record");
    let (shell, shell_args) = recording_shell(directory.path(), &record);
    let dispatcher = directory.path().join("dispatcher with spaces");
    let mut adapter = ProcessPhaseDispatcher::new(PhaseDispatcherPaths {
        shell,
        shell_args,
        dispatcher: dispatcher.clone(),
    });

    let cases = [
        (DispatcherPhaseCommand::StartupRecover, "startup-recover"),
        (DispatcherPhaseCommand::Prepare, "prepare"),
        (DispatcherPhaseCommand::CaptureStart, "capture-start"),
        (DispatcherPhaseCommand::CaptureStop, "capture-stop"),
        (DispatcherPhaseCommand::CaptureVerify, "capture-verify"),
        (DispatcherPhaseCommand::AddressResync, "address-resync"),
        (DispatcherPhaseCommand::StateRunning, "state-running"),
        (DispatcherPhaseCommand::StateStopped, "state-stopped"),
        (DispatcherPhaseCommand::StateFailed, "state-failed"),
    ];

    for (command, verb) in cases {
        adapter.execute(command).expect("phase dispatcher succeeds");
        assert_eq!(
            read_record(&record),
            format!(
                "bridge=1\narg1=--shell-marker\narg2={}\narg3={verb}\narg4=",
                dispatcher.display()
            )
        );
    }
}

#[test]
fn generation_phase_appends_the_exact_generation_argument() {
    let directory = tempdir().expect("temporary directory");
    let record = directory.path().join("phase.record");
    let (shell, shell_args) = recording_shell(directory.path(), &record);
    let dispatcher = directory.path().join("dispatcher with spaces");
    let mut adapter = ProcessPhaseDispatcher::new(PhaseDispatcherPaths {
        shell,
        shell_args,
        dispatcher: dispatcher.clone(),
    });

    adapter
        .execute_for_generation(
            DispatcherPhaseCommand::CaptureStart,
            NonZeroU32::new(42).expect("nonzero generation"),
        )
        .expect("generation phase succeeds");

    assert_eq!(
        read_record(&record),
        format!(
            "bridge=1\narg1=--shell-marker\narg2={}\narg3=capture-start\narg4=42",
            dispatcher.display()
        )
    );
}

#[test]
fn spawn_failures_expose_the_underlying_io_error() {
    let directory = tempdir().expect("temporary directory");
    let mut adapter = ProcessPhaseDispatcher::new(PhaseDispatcherPaths {
        shell: directory.path().join("missing-shell"),
        shell_args: Vec::new(),
        dispatcher: directory.path().join("missing-dispatcher"),
    });

    let error = adapter
        .execute(DispatcherPhaseCommand::Prepare)
        .expect_err("missing shell must fail");

    assert_eq!(error.kind(), PhaseDispatcherErrorKind::Spawn);
    assert!(
        error
            .source()
            .is_some_and(|source| source.is::<std::io::Error>())
    );
}

#[test]
fn nonzero_dispatcher_exit_is_typed() {
    let directory = tempdir().expect("temporary directory");
    let (shell, shell_args, dispatcher) = failing_dispatcher(directory.path());
    let mut adapter = ProcessPhaseDispatcher::new(PhaseDispatcherPaths {
        shell,
        shell_args,
        dispatcher,
    });

    let error = adapter
        .execute(DispatcherPhaseCommand::CaptureVerify)
        .expect_err("nonzero dispatcher must fail");

    assert!(matches!(
        error,
        PhaseDispatcherError::NonZeroExit {
            command: DispatcherPhaseCommand::CaptureVerify,
            status,
        } if status.code() == Some(23)
    ));
}

#[test]
fn phase_execution_timeout_is_typed_and_bounded() {
    let directory = tempdir().expect("temporary directory");
    let (shell, shell_args, dispatcher) = hanging_dispatcher(directory.path());
    let mut adapter = ProcessPhaseDispatcher::new(PhaseDispatcherPaths {
        shell,
        shell_args,
        dispatcher,
    });
    let timeout = Duration::from_millis(50);
    let started = Instant::now();

    let error = adapter
        .execute_with_timeout(DispatcherPhaseCommand::CaptureStart, timeout)
        .expect_err("hanging dispatcher must time out");

    assert_eq!(error.kind(), PhaseDispatcherErrorKind::TimedOut);
    assert!(matches!(
        error,
        PhaseDispatcherError::TimedOut {
            command: DispatcherPhaseCommand::CaptureStart,
            timeout: observed,
            ..
        } if observed == timeout
    ));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "bounded phase execution took {:?}",
        started.elapsed()
    );
}

#[test]
fn phase_execution_timeout_must_be_within_the_supported_bound() {
    let directory = tempdir().expect("temporary directory");
    let mut adapter = ProcessPhaseDispatcher::new(PhaseDispatcherPaths {
        shell: directory.path().join("unused-shell"),
        shell_args: Vec::new(),
        dispatcher: directory.path().join("unused-dispatcher"),
    });

    for timeout in [Duration::ZERO, Duration::from_secs(61)] {
        let error = adapter
            .execute_with_timeout(DispatcherPhaseCommand::Prepare, timeout)
            .expect_err("invalid timeout must be rejected before spawn");

        assert_eq!(error.kind(), PhaseDispatcherErrorKind::InvalidTimeout);
        assert!(matches!(
            error,
            PhaseDispatcherError::InvalidTimeout {
                command: DispatcherPhaseCommand::Prepare,
                timeout: observed,
                maximum,
            } if observed == timeout && maximum == Duration::from_secs(60)
        ));
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn phase_child_can_receive_sigterm_when_caller_inherits_blocked_signals() {
    let directory = tempdir().expect("temporary directory");
    let child_pid_path = directory.path().join("phase-child.pid");
    let dispatcher = termination_dispatcher(directory.path(), &child_pid_path);
    let shutdown = ShutdownSignal::install().expect("block daemon shutdown signals");
    let (result_tx, result_rx) = mpsc::sync_channel(1);

    let worker = thread::spawn(move || {
        let mut adapter = ProcessPhaseDispatcher::new(PhaseDispatcherPaths {
            shell: PathBuf::from("/bin/sh"),
            shell_args: Vec::new(),
            dispatcher,
        });
        result_tx
            .send(adapter.execute(DispatcherPhaseCommand::Prepare))
            .expect("publish dispatcher result");
    });

    let child_pid = wait_for_child_pid(&child_pid_path);
    // SAFETY: the script published its live process ID after installing its
    // termination trap.
    assert_eq!(unsafe { libc::kill(child_pid, libc::SIGTERM) }, 0);

    let result = match result_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // SAFETY: the synchronous adapter has not returned, so the script
            // remains live. SIGKILL guarantees test cleanup.
            let _ = unsafe { libc::kill(child_pid, libc::SIGKILL) };
            let _ = result_rx.recv_timeout(Duration::from_secs(1));
            panic!("phase child did not receive SIGTERM");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("dispatcher worker exited without publishing a result");
        }
    };

    worker.join().expect("dispatcher worker");
    result.expect("SIGTERM trap exits the phase child successfully");
    drop(shutdown);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn phase_child_is_killed_when_its_supervisor_process_dies() {
    if let Some(root) = std::env::var_os(PARENT_DEATH_HELPER_ROOT) {
        let root = PathBuf::from(root);
        let dispatcher = parent_death_dispatcher(&root, &root.join("phase-child.pid"));
        let mut adapter = ProcessPhaseDispatcher::new(PhaseDispatcherPaths {
            shell: PathBuf::from("/bin/sh"),
            shell_args: Vec::new(),
            dispatcher,
        });
        let result = adapter.execute(DispatcherPhaseCommand::Prepare);
        panic!("parent-death phase unexpectedly completed: {result:?}");
    }

    let directory = tempdir().expect("temporary parent-death directory");
    let child_pid_path = directory.path().join("phase-child.pid");
    let mut supervisor = NestedSupervisor::spawn(
        "phase_child_is_killed_when_its_supervisor_process_dies",
        PARENT_DEATH_HELPER_ROOT,
        directory.path(),
        child_pid_path.clone(),
    );
    let child_pid = wait_for_child_pid(&child_pid_path);

    let status = supervisor.kill_and_wait();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    wait_for_process_absence(child_pid);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn timeout_escalates_and_removes_the_dispatcher_process_group() {
    let directory = tempdir().expect("temporary directory");
    let pid_path = directory.path().join("phase-tree.pid");
    let term_path = directory.path().join("phase-tree.term");
    let dispatcher = uncooperative_tree_dispatcher(directory.path(), &pid_path, &term_path);
    let mut adapter = ProcessPhaseDispatcher::new(PhaseDispatcherPaths {
        shell: PathBuf::from("/bin/sh"),
        shell_args: Vec::new(),
        dispatcher,
    });

    let error = adapter
        .execute_with_timeout(
            DispatcherPhaseCommand::CaptureStop,
            Duration::from_millis(200),
        )
        .expect_err("uncooperative process tree must time out");

    assert_eq!(error.kind(), PhaseDispatcherErrorKind::TimedOut);
    assert!(term_path.is_file(), "process group did not observe SIGTERM");
    let (process_group, descendant) = read_process_tree(&pid_path);
    assert_process_group_absent(process_group);
    assert_process_absent(descendant);
}

fn read_record(path: &Path) -> String {
    fs::read_to_string(path)
        .expect("recorded invocation")
        .replace("\r\n", "\n")
        .trim_end()
        .to_owned()
}

#[cfg(windows)]
fn failing_dispatcher(directory: &Path) -> (PathBuf, Vec<std::ffi::OsString>, PathBuf) {
    let dispatcher = directory.join("failing-dispatcher.cmd");
    fs::write(&dispatcher, "@exit /B 23\r\n").expect("write failing dispatcher");
    (
        PathBuf::from("cmd.exe"),
        vec!["/D".into(), "/C".into()],
        dispatcher,
    )
}

#[cfg(windows)]
fn hanging_dispatcher(directory: &Path) -> (PathBuf, Vec<std::ffi::OsString>, PathBuf) {
    let dispatcher = directory.join("hanging-dispatcher.cmd");
    fs::write(&dispatcher, "@echo off\r\n:loop\r\ngoto loop\r\n")
        .expect("write hanging dispatcher");
    (
        PathBuf::from("cmd.exe"),
        vec!["/D".into(), "/C".into()],
        dispatcher,
    )
}

#[cfg(unix)]
fn hanging_dispatcher(directory: &Path) -> (PathBuf, Vec<std::ffi::OsString>, PathBuf) {
    let dispatcher = directory.join("hanging-dispatcher");
    fs::write(&dispatcher, "#!/bin/sh\nwhile :; do :; done\n").expect("write hanging dispatcher");
    (PathBuf::from("/bin/sh"), Vec::new(), dispatcher)
}

#[cfg(unix)]
fn failing_dispatcher(directory: &Path) -> (PathBuf, Vec<std::ffi::OsString>, PathBuf) {
    let dispatcher = directory.join("failing-dispatcher");
    fs::write(&dispatcher, "#!/bin/sh\nexit 23\n").expect("write failing dispatcher");
    (PathBuf::from("/bin/sh"), Vec::new(), dispatcher)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn termination_dispatcher(directory: &Path, child_pid_path: &Path) -> PathBuf {
    let dispatcher = directory.join("termination-dispatcher");
    fs::write(
        &dispatcher,
        format!(
            "#!/bin/sh\ntrap 'exit 0' INT TERM\nprintf '%s\\n' \"$$\" > '{}'\nwhile :; do :; done\n",
            child_pid_path.display()
        ),
    )
    .expect("write termination dispatcher");
    dispatcher
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parent_death_dispatcher(directory: &Path, child_pid_path: &Path) -> PathBuf {
    let dispatcher = directory.join("parent-death-dispatcher");
    fs::write(
        &dispatcher,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$$\" > '{}'\nwhile :; do :; done\n",
            child_pid_path.display()
        ),
    )
    .expect("write parent-death dispatcher");
    dispatcher
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct NestedSupervisor {
    child: Child,
    descendant_pid_path: PathBuf,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl NestedSupervisor {
    fn spawn(test: &str, environment: &str, root: &Path, descendant_pid_path: PathBuf) -> Self {
        let child = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg(test)
            .arg("--nocapture")
            .env(environment, root)
            .spawn()
            .expect("spawn isolated phase supervisor");
        Self {
            child,
            descendant_pid_path,
        }
    }

    fn kill_and_wait(&mut self) -> ExitStatus {
        self.child.kill().expect("kill isolated phase supervisor");
        self.child.wait().expect("reap isolated phase supervisor")
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Drop for NestedSupervisor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if thread::panicking()
            && let Ok(pid) = fs::read_to_string(&self.descendant_pid_path)
            && let Ok(pid) = pid.trim().parse::<libc::pid_t>()
        {
            // SAFETY: during unwind this process group came from the isolated
            // helper; SIGKILL prevents a failed assertion leaking the tree.
            let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn uncooperative_tree_dispatcher(directory: &Path, pid_path: &Path, term_path: &Path) -> PathBuf {
    let dispatcher = directory.join("uncooperative-tree-dispatcher");
    fs::write(
        &dispatcher,
        format!(
            "#!/bin/sh\ntrap 'printf term > \"{}\"' TERM\n( trap '' TERM; while :; do :; done ) &\ndescendant=$!\nprintf '%s %s\\n' \"$$\" \"$descendant\" > \"{}\"\nwait \"$descendant\"\n",
            term_path.display(),
            pid_path.display()
        ),
    )
    .expect("write uncooperative process-tree dispatcher");
    dispatcher
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_process_tree(path: &Path) -> (libc::pid_t, libc::pid_t) {
    let values = fs::read_to_string(path).expect("dispatcher process tree record");
    let mut values = values.split_whitespace().map(|value| {
        value
            .parse::<libc::pid_t>()
            .expect("valid dispatcher process ID")
    });
    let process_group = values.next().expect("process-group leader");
    let descendant = values.next().expect("dispatcher descendant");
    assert!(values.next().is_none(), "unexpected process tree record");
    (process_group, descendant)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn assert_process_group_absent(process_group: libc::pid_t) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: the negative PID targets only the process group recorded by
        // the isolated dispatcher child. Signal zero probes existence only.
        let result = unsafe { libc::kill(-process_group, 0) };
        if result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "dispatcher process group {process_group} remained live"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn assert_process_absent(pid: libc::pid_t) {
    // SAFETY: the recorded positive PID belongs to the dispatcher descendant;
    // signal zero probes existence without changing process state.
    let result = unsafe { libc::kill(pid, 0) };
    assert!(
        result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
        "dispatcher descendant {pid} remained live"
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn wait_for_process_absence(pid: libc::pid_t) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: the recorded PID belongs to the isolated phase child and
        // signal zero only probes whether it remains present.
        let result = unsafe { libc::kill(pid, 0) };
        if result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "phase child {pid} remained live after its supervisor died"
        );
        thread::sleep(Duration::from_millis(10));
    }
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
                    .expect("valid phase child process ID");
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("read phase child process ID: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "phase child did not publish its process ID"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(windows)]
fn recording_shell(directory: &Path, record: &Path) -> (PathBuf, Vec<std::ffi::OsString>) {
    let script = directory.join("record-shell.cmd");
    fs::write(
        &script,
        format!(
            "@echo off\r\n>\"{}\" (\r\n  echo bridge=%FLUXD_BRIDGE%\r\n  echo arg1=%~1\r\n  echo arg2=%~2\r\n  echo arg3=%~3\r\n  echo arg4=%~4\r\n)\r\n",
            record.display()
        ),
    )
    .expect("write recording shell");
    (
        PathBuf::from("cmd.exe"),
        vec![
            "/D".into(),
            "/C".into(),
            script.into_os_string(),
            "--shell-marker".into(),
        ],
    )
}

#[cfg(unix)]
fn recording_shell(directory: &Path, record: &Path) -> (PathBuf, Vec<std::ffi::OsString>) {
    let script = directory.join("record-shell");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf 'bridge=%s\\narg1=%s\\narg2=%s\\narg3=%s\\narg4=%s\\n' \"$FLUXD_BRIDGE\" \"$1\" \"$2\" \"$3\" \"$4\" > '{}'\n",
            record.display()
        ),
    )
    .expect("write recording shell");
    (
        PathBuf::from("/bin/sh"),
        vec![script.into_os_string(), "--shell-marker".into()],
    )
}
