use std::io::{BufRead, BufReader, Write};
use std::num::{NonZeroU32, NonZeroU64};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use super::implementation::{
    parse_pidfd_info, parse_proc_stat, parse_proc_status, require_waitable_child,
    validate_process_credential_census,
};
use super::{ProcessHandle, ProcessHandleError, ProcessHandleErrorKind, ProcessIdentity};

const THREAD_HELPER_MODE: &str = "FLUX_PROCESS_HANDLE_THREAD_HELPER";
const THREAD_HELPER_TEST: &str = "process::tests::process_handle_thread_helper";
const THREAD_HELPER_READY: &str = "PROCESS_HANDLE_READY";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ThreadHelperReadiness {
    Homogeneous,
    Heterogeneous,
    HeterogeneityUnavailable,
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn sleeping() -> Self {
        let child = Command::new("/bin/sh")
            .args(["-c", "exec /bin/sleep 60"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleeping child");
        Self { child }
    }

    fn thread_helper(mode: &str) -> (Self, ThreadHelperReadiness) {
        let executable = std::env::current_exe().expect("resolve platform test executable");
        let mut child = Command::new(executable)
            .args([
                "--ignored",
                "--exact",
                THREAD_HELPER_TEST,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(THREAD_HELPER_MODE, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn multithreaded process helper");
        let stdout = child.stdout.take().expect("capture helper readiness");
        let mut reader = BufReader::new(stdout);
        let mut output = String::new();
        let readiness = loop {
            let mut line = String::new();
            let read = reader.read_line(&mut line).expect("read helper readiness");
            assert_ne!(
                read, 0,
                "thread helper exited before readiness; output: {output:?}"
            );
            output.push_str(&line);
            if line.contains(&format!("{THREAD_HELPER_READY}:homogeneous")) {
                break ThreadHelperReadiness::Homogeneous;
            }
            if line.contains(&format!("{THREAD_HELPER_READY}:heterogeneous")) {
                break ThreadHelperReadiness::Heterogeneous;
            }
            if line.contains(&format!("{THREAD_HELPER_READY}:unavailable")) {
                break ThreadHelperReadiness::HeterogeneityUnavailable;
            }
        };
        (Self { child }, readiness)
    }

    fn terminate(&mut self) {
        self.child.kill().expect("terminate child");
    }

    fn wait(&mut self) {
        self.child.wait().expect("wait for child exit");
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn proc_stat_parser_ignores_spaces_slashes_and_closing_parentheses_in_comm() {
    let mut fields = vec!["0"; 20];
    fields[0] = "S";
    fields[19] = "98765";
    let stat = format!(
        "4242 (name with spaces/) and ) parens) {}\n",
        fields.join(" ")
    );
    assert_eq!(
        parse_proc_stat(stat.as_bytes()),
        Some(ProcessIdentity::new(
            NonZeroU32::new(4242).unwrap(),
            NonZeroU64::new(98765).unwrap(),
        ))
    );

    assert!(
        parse_proc_stat(stat.replacen("4242", "04242", 1).as_bytes()).is_none(),
        "PID syntax must remain canonical"
    );
    assert!(
        parse_proc_stat(stat.replacen("98765", "098765", 1).as_bytes()).is_none(),
        "start ticks must remain canonical"
    );
    assert!(parse_proc_stat(b"4242 (unterminated S 0 0").is_none());
}

#[test]
fn proc_status_parser_captures_the_complete_credential_surface() {
    let status = b"Name:\tworker ) name\n\
Pid:\t4242\n\
Tgid:\t4242\n\
Uid:\t1000\t1001\t1002\t1003\n\
Gid:\t2000\t2001\t2002\t2003\n\
Groups:\t10 20 30\n\
CapInh:\t0000000000000001\n\
CapPrm:\t0000000000000002\n\
CapEff:\t0000000000000004\n\
CapAmb:\t0000000000000008\n\
NoNewPrivs:\t1\n";
    let (tgid, pid, credentials) = parse_proc_status(status).expect("parse exact proc status");
    assert_eq!(tgid, NonZeroU32::new(4242).unwrap());
    assert_eq!(pid, NonZeroU32::new(4242).unwrap());
    assert_eq!(credentials.uids(), &[1000, 1001, 1002, 1003]);
    assert_eq!(credentials.gids(), &[2000, 2001, 2002, 2003]);
    assert_eq!(credentials.supplementary_groups(), &[10, 20, 30]);
    assert_eq!(credentials.capability_inheritable(), 1);
    assert_eq!(credentials.capability_permitted(), 2);
    assert_eq!(credentials.capability_effective(), 4);
    assert_eq!(credentials.capability_ambient(), 8);
    assert!(credentials.no_new_privileges());

    assert!(
        parse_proc_status(
            &status.replace(b"Uid:\t1000\t1001\t1002\t1003", b"Uid:\t1000\t1001\t1002")
        )
        .is_none()
    );
    assert!(parse_proc_status(&status.replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t2")).is_none());
    let (_, _, empty_groups) =
        parse_proc_status(&status.replace(b"Groups:\t10 20 30", b"Groups:\t"))
            .expect("empty supplementary group set is valid");
    assert!(empty_groups.supplementary_groups().is_empty());
    assert!(parse_proc_status(&status.replace(b"CapAmb:", b"MissingCapAmb:")).is_none());
    let mut duplicate_pid = status.to_vec();
    duplicate_pid.extend_from_slice(b"Pid:\t4242\n");
    assert!(parse_proc_status(&duplicate_pid).is_none());
    assert!(
        parse_proc_status(
            &status.replace(b"CapEff:\t0000000000000004", b"CapEff:\t10000000000000004")
        )
        .is_none()
    );
    assert!(
        parse_proc_status(&status.replace(
            b"Uid:\t1000\t1001\t1002\t1003",
            b"Uid:\t4294967296\t1001\t1002\t1003"
        ))
        .is_none()
    );
}

#[test]
fn credential_census_validation_rejects_changed_or_heterogeneous_tasks() {
    let leader_id = NonZeroU32::new(4242).unwrap();
    let worker_id = NonZeroU32::new(4243).unwrap();
    let (_, _, leader) = parse_proc_status(
        b"Tgid:\t4242\nPid:\t4242\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\nNoNewPrivs:\t0\n",
    )
    .expect("parse leader credentials");
    let (_, _, restricted_worker) = parse_proc_status(
        b"Tgid:\t4242\nPid:\t4243\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\n",
    )
    .expect("parse worker credentials");
    let task_ids = [leader_id, worker_id];
    let homogeneous = [(leader_id, leader.clone()), (worker_id, leader.clone())];
    let heterogeneous = [(leader_id, leader), (worker_id, restricted_worker)];

    let error = validate_process_credential_census(
        leader_id,
        &task_ids,
        &heterogeneous,
        &task_ids,
        &heterogeneous,
        &task_ids,
    )
    .expect_err("a stable worker/leader credential mismatch must be rejected");
    assert!(matches!(
        error,
        ProcessHandleError::ProcessThreadCredentialMismatch {
            pid,
            thread
        } if pid == leader_id && thread == worker_id
    ));

    let error = validate_process_credential_census(
        leader_id,
        &task_ids,
        &homogeneous,
        &task_ids,
        &heterogeneous,
        &task_ids,
    )
    .expect_err("credentials changing between scans must be rejected");
    assert!(matches!(
        error,
        ProcessHandleError::ProcessThreadCredentialsChanged {
            pid,
            thread
        } if pid == leader_id && thread == worker_id
    ));
}

#[test]
fn pidfd_info_parser_distinguishes_live_and_exited_processes() {
    assert_eq!(
        parse_pidfd_info(b"pos:\t0\nflags:\t02000002\nPid:\t4242\nNSpid:\t4242\n"),
        Some(Some(NonZeroU32::new(4242).unwrap()))
    );
    assert_eq!(
        parse_pidfd_info(b"pos:\t0\nPid:\t-1\nNSpid:\t-1\n"),
        Some(None)
    );
    assert_eq!(parse_pidfd_info(b"Pid:\t04242\n"), None);
    assert_eq!(parse_pidfd_info(b"Pid:\t1\nPid:\t2\n"), None);
}

#[test]
fn child_origin_handle_reobserves_the_same_live_identity_and_credentials() {
    let child = ChildGuard::sleeping();
    let handle = ProcessHandle::open_child(&child.child).expect("open exact child handle");
    assert_eq!(handle.identity().pid().get(), child.child.id());

    let observation = handle.reobserve().expect("reobserve live child");
    assert_eq!(observation.identity(), handle.identity());
    assert_eq!(observation.credentials(), handle.credentials());
}

#[test]
fn process_credentials_require_a_stable_homogeneous_thread_census() {
    let (homogeneous, readiness) = ChildGuard::thread_helper("homogeneous");
    assert_eq!(readiness, ThreadHelperReadiness::Homogeneous);
    ProcessHandle::open_child(&homogeneous.child)
        .expect("matching credentials across live threads are authoritative");

    let (heterogeneous, readiness) = ChildGuard::thread_helper("heterogeneous");
    if readiness == ThreadHelperReadiness::HeterogeneityUnavailable {
        eprintln!(
            "skipping heterogeneous task assertion: no per-thread credential transition is available"
        );
        return;
    }
    assert_eq!(readiness, ThreadHelperReadiness::Heterogeneous);
    let error = ProcessHandle::open_child(&heterogeneous.child)
        .expect_err("one thread with different credentials must reject the process observation");
    assert_eq!(error.kind(), ProcessHandleErrorKind::IdentityChanged);
}

#[test]
fn pidfd_handle_reports_exit_without_claiming_reap_authority() {
    let mut child = ChildGuard::sleeping();
    let handle = ProcessHandle::open_child(&child.child).expect("open exact child handle");
    child.terminate();

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match handle.reobserve() {
            Err(error) if error.kind() == ProcessHandleErrorKind::Exited => break,
            Ok(_) if Instant::now() < deadline => std::thread::yield_now(),
            Ok(_) => panic!("pidfd did not report child exit before the test deadline"),
            Err(error) => panic!("unexpected pre-reap observation failure: {error}"),
        }
    }

    child.wait();

    let error = require_waitable_child(&handle.transport.pidfd, handle.identity().pid())
        .expect_err("a reaped pidfd cannot remain waitable by its former parent");
    assert_eq!(error.kind(), ProcessHandleErrorKind::Exited);

    let error = handle
        .reobserve()
        .expect_err("a reaped pidfd cannot produce a live observation");
    assert_eq!(error.kind(), ProcessHandleErrorKind::Exited);

    let error = ProcessHandle::open_child(&child.child)
        .expect_err("a reaped Child cannot produce a fresh process handle");
    assert_eq!(error.kind(), ProcessHandleErrorKind::Exited);
}

trait ByteSliceReplace {
    fn replace(&self, from: &[u8], to: &[u8]) -> Vec<u8>;
}

impl ByteSliceReplace for [u8] {
    fn replace(&self, from: &[u8], to: &[u8]) -> Vec<u8> {
        let Some(offset) = self.windows(from.len()).position(|window| window == from) else {
            return self.to_vec();
        };
        let mut replaced = Vec::with_capacity(self.len() - from.len() + to.len());
        replaced.extend_from_slice(&self[..offset]);
        replaced.extend_from_slice(to);
        replaced.extend_from_slice(&self[offset + from.len()..]);
        replaced
    }
}

#[test]
#[ignore = "reentered by the process-handle thread-census test"]
fn process_handle_thread_helper() {
    let mode = std::env::var(THREAD_HELPER_MODE).expect("thread helper mode");
    let barrier = Arc::new(Barrier::new(2));
    let (status_sender, status_receiver) = std::sync::mpsc::sync_channel(1);
    let worker_barrier = Arc::clone(&barrier);
    std::thread::spawn(move || {
        let readiness = if mode == "heterogeneous" {
            if make_worker_credentials_heterogeneous() {
                ThreadHelperReadiness::Heterogeneous
            } else {
                ThreadHelperReadiness::HeterogeneityUnavailable
            }
        } else {
            assert_eq!(mode, "homogeneous");
            ThreadHelperReadiness::Homogeneous
        };
        status_sender
            .send(readiness)
            .expect("send worker readiness");
        worker_barrier.wait();
        loop {
            std::thread::park();
        }
    });
    barrier.wait();
    let readiness = status_receiver.recv().expect("receive worker readiness");
    let readiness = match readiness {
        ThreadHelperReadiness::Homogeneous => "homogeneous",
        ThreadHelperReadiness::Heterogeneous => "heterogeneous",
        ThreadHelperReadiness::HeterogeneityUnavailable => "unavailable",
    };
    println!("{THREAD_HELPER_READY}:{readiness}");
    std::io::stdout().flush().expect("flush helper readiness");
    loop {
        std::thread::park();
    }
}

fn make_worker_credentials_heterogeneous() -> bool {
    // NoNewPrivs is irreversible and task-local. Prefer it when the helper did
    // not inherit NoNewPrivs from its test environment.
    // SAFETY: both prctl operations use integer-only arguments documented for
    // PR_GET_NO_NEW_PRIVS and PR_SET_NO_NEW_PRIVS.
    let no_new_privileges = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privileges == 0 {
        // SAFETY: PR_SET_NO_NEW_PRIVS with argument one changes only the
        // calling worker thread and uses no pointer arguments.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0 {
            return true;
        }
    }

    let Some(current_fs_gid) = query_fs_gid() else {
        return false;
    };
    let mut real_gid = 0;
    let mut effective_gid = 0;
    let mut saved_gid = 0;
    // SAFETY: all three pointers name initialized writable gid_t values.
    if unsafe {
        libc::getresgid(
            &raw mut real_gid,
            &raw mut effective_gid,
            &raw mut saved_gid,
        )
    } != 0
    {
        return false;
    }
    // An unprivileged task may select any real/effective/saved GID as its
    // filesystem GID. A privileged helper can additionally select `nobody`.
    [real_gid, effective_gid, saved_gid, 65_534]
        .into_iter()
        .any(|candidate| {
            candidate != current_fs_gid
                && set_fs_gid(candidate)
                && query_fs_gid() == Some(candidate)
        })
}

fn query_fs_gid() -> Option<libc::gid_t> {
    // SAFETY: the setfsgid syscall takes one scalar gid. An all-ones gid is the
    // documented query operation and does not change credentials.
    let result = unsafe { libc::syscall(libc::SYS_setfsgid, libc::gid_t::MAX) };
    libc::gid_t::try_from(result).ok()
}

fn set_fs_gid(gid: libc::gid_t) -> bool {
    // SAFETY: the setfsgid syscall takes one scalar gid and changes only the
    // calling task's filesystem GID when the requested transition is allowed.
    let result = unsafe { libc::syscall(libc::SYS_setfsgid, gid) };
    result >= 0
}
