#![cfg(any(target_os = "linux", target_os = "android"))]

use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::*;
use crate::xtables::{XtablesRestoreAction, XtablesRestoreContext, parse_xtables_restore};
use tempfile::TempDir;

#[cfg(target_os = "linux")]
const SHELL: &str = "/bin/sh";
#[cfg(target_os = "android")]
const SHELL: &str = "/system/bin/sh";

#[cfg(target_os = "linux")]
const CAT: &str = "/bin/cat";
#[cfg(target_os = "android")]
const CAT: &str = "/system/bin/cat";

#[cfg(target_os = "linux")]
const PRINTF: &str = "/usr/bin/printf";
#[cfg(target_os = "android")]
const PRINTF: &str = "/system/bin/printf";

#[cfg(target_os = "linux")]
const SLEEP: &str = "/bin/sleep";
#[cfg(target_os = "android")]
const SLEEP: &str = "/system/bin/sleep";

const LEGACY_VERSION: &str = "iptables-restore v1.8.7 (legacy)";
const NFT_VERSION: &str = "iptables-restore v1.8.7 (nf_tables)";

#[test]
fn process_limits_and_lossy_diagnostics_remain_strictly_bounded() {
    for (wait, timeout) in [
        (0, Duration::from_secs(1)),
        (61, Duration::from_secs(1)),
        (1, Duration::ZERO),
        (1, Duration::from_secs(61)),
    ] {
        let error = XtablesRestoreProcessConfig::new(wait, timeout)
            .expect_err("invalid process bound must fail");
        assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::InvalidConfig);
        assert_eq!(
            error.mutation_disposition(),
            XtablesRestoreMutationDisposition::NotStarted
        );
    }

    let diagnostic = bounded_lossy_tail(&vec![0xff; MAX_CAPTURE_BYTES]);
    assert!(diagnostic.len() <= MAX_CAPTURE_BYTES);
    assert!(diagnostic.is_char_boundary(0));
}

#[test]
fn direct_restore_uses_exact_arguments_and_canonical_stdin_for_both_families() {
    let fixture = Fixture::new();
    let ipv4_args = fixture.path("ipv4.args");
    let ipv4_stdin = fixture.path("ipv4.stdin");
    let ipv6_args = fixture.path("ipv6.args");
    let ipv6_stdin = fixture.path("ipv6.stdin");
    let ipv4 = fixture.script(
        "iptables-restore",
        LEGACY_VERSION,
        &record_restore_body(&ipv4_args, &ipv4_stdin, "ipv4-ok"),
    );
    let ipv6 = fixture.script(
        "ip6tables-restore",
        LEGACY_VERSION,
        &record_restore_body(&ipv6_args, &ipv6_stdin, "ipv6-ok"),
    );
    let mut adapter = open_adapter(ipv4.clone(), Some(ipv6.clone()), 7, Duration::from_secs(2))
        .expect("open restore tools with matching reported flavors");

    let (ipv4_bytes, ipv4_artifact) = artifact(XtablesRestoreFamily::Ipv4);
    let (ipv6_bytes, ipv6_artifact) = artifact(XtablesRestoreFamily::Ipv6);
    let ipv4_output = adapter
        .execute(&ipv4_artifact)
        .expect("execute IPv4 restore");
    let ipv6_output = adapter
        .execute(&ipv6_artifact)
        .expect("execute IPv6 restore");

    assert_eq!(fs::read_to_string(ipv4_args).unwrap(), "-w\n7\n--noflush\n");
    assert_eq!(fs::read_to_string(ipv6_args).unwrap(), "-w\n7\n--noflush\n");
    assert_eq!(fs::read(ipv4_stdin).unwrap(), ipv4_bytes);
    assert_eq!(fs::read(ipv6_stdin).unwrap(), ipv6_bytes);
    assert_eq!(ipv4_output.family(), XtablesRestoreFamily::Ipv4);
    assert_eq!(ipv6_output.family(), XtablesRestoreFamily::Ipv6);
    assert_eq!(ipv4_output.stdout(), "ipv4-ok\n");
    assert_eq!(ipv6_output.stdout(), "ipv6-ok\n");
    assert_eq!(ipv4_output.stderr(), "");
    assert_eq!(ipv6_output.stderr(), "");
    assert_eq!(ipv4_output.tool_identity().path(), ipv4);
    assert_eq!(ipv6_output.tool_identity().path(), ipv6);
}

#[test]
fn restore_child_does_not_inherit_unlisted_parent_descriptors() {
    let source = fs::File::open("/dev/null").expect("open descriptor source");
    // SAFETY: F_DUPFD duplicates one live descriptor into the caller-owned
    // table and returns a new descriptor on success.
    let descriptor = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD, 200) };
    assert!(descriptor >= 200, "duplicate a high descriptor");
    // SAFETY: `descriptor` was freshly returned by F_DUPFD and ownership is
    // transferred exactly once into this File.
    let leaked = unsafe { fs::File::from_raw_fd(descriptor) };
    // SAFETY: F_SETFD mutates flags on the live owned descriptor only.
    assert_eq!(unsafe { libc::fcntl(descriptor, libc::F_SETFD, 0) }, 0);

    let fixture = Fixture::new();
    let script = fixture.script(
        "iptables-restore",
        LEGACY_VERSION,
        &format!("if [ -e /proc/self/fd/{descriptor} ]; then exit 44; fi\n{CAT} >/dev/null"),
    );
    let mut adapter =
        open_adapter(script, None, 1, Duration::from_secs(1)).expect("open restore adapter");
    let (_, artifact) = artifact(XtablesRestoreFamily::Ipv4);

    adapter
        .execute(&artifact)
        .expect("unlisted parent descriptor must be close-on-exec");
    drop(leaked);
}

#[test]
fn probe_accepts_matching_legacy_and_nf_tables_flavors_and_rejects_mismatch() {
    let legacy = Fixture::new();
    let legacy_v4 = legacy.script("iptables-restore", LEGACY_VERSION, "exit 0");
    let legacy_v6 = legacy.script("ip6tables-restore", LEGACY_VERSION, "exit 0");
    let legacy_adapter = open_adapter(legacy_v4, Some(legacy_v6), 1, Duration::from_secs(1))
        .expect("open matching legacy pair");
    assert_eq!(
        legacy_adapter.reported_flavor(),
        XtablesRestoreReportedFlavor::Legacy
    );

    let nft = Fixture::new();
    let nft_v4 = nft.script("iptables-restore", NFT_VERSION, "exit 0");
    let nft_v6 = nft.script("ip6tables-restore", NFT_VERSION, "exit 0");
    let nft_adapter = open_adapter(nft_v4, Some(nft_v6), 1, Duration::from_secs(1))
        .expect("open matching nf_tables pair");
    assert_eq!(
        nft_adapter.reported_flavor(),
        XtablesRestoreReportedFlavor::NfTables
    );

    let mixed = Fixture::new();
    let mixed_v4 = mixed.script("iptables-restore", LEGACY_VERSION, "exit 0");
    let mixed_v6 = mixed.script("ip6tables-restore", NFT_VERSION, "exit 0");
    let error = expect_open_error(
        open_adapter(mixed_v4, Some(mixed_v6), 1, Duration::from_secs(1)),
        "mismatched reported restore flavors must be rejected",
    );
    assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::ToolFlavor);
    assert!(matches!(
        error,
        XtablesRestoreProcessError::ToolFlavorMismatch {
            ipv4: XtablesRestoreReportedFlavor::Legacy,
            ipv6: XtablesRestoreReportedFlavor::NfTables,
        }
    ));
}

#[test]
fn probe_timeout_is_bounded_and_kills_the_process_group() {
    let fixture = Fixture::new();
    let script = fixture.custom_script("iptables-restore", &format!("{SLEEP} 30"), "exit 0");
    let timeout = Duration::from_millis(100);

    let started = Instant::now();
    let error = expect_open_error(
        open_adapter(script, None, 1, timeout),
        "hung version probe must time out",
    );
    assert_eq!(
        error.mutation_disposition(),
        XtablesRestoreMutationDisposition::NotStarted
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(matches!(
        error,
        XtablesRestoreProcessError::TimedOut {
            operation: XtablesRestoreProcessOperation::Probe,
            family: XtablesRestoreFamily::Ipv4,
            timeout: observed,
            ..
        } if observed == timeout
    ));
}

#[test]
fn probe_nonzero_exit_preserves_stderr() {
    let fixture = Fixture::new();
    let script = fixture.custom_script(
        "iptables-restore",
        &format!("{PRINTF} '%s\\n' 'probe rejected by fixture' >&2\nexit 31"),
        "exit 0",
    );

    let error = expect_open_error(
        open_adapter(script, None, 1, Duration::from_secs(1)),
        "nonzero version probe must fail",
    );
    assert_eq!(
        error.mutation_disposition(),
        XtablesRestoreMutationDisposition::NotStarted
    );
    match error {
        XtablesRestoreProcessError::NonZeroExit {
            operation,
            family,
            status,
            stderr,
            ..
        } => {
            assert_eq!(operation, XtablesRestoreProcessOperation::Probe);
            assert_eq!(family, XtablesRestoreFamily::Ipv4);
            assert_eq!(status.code(), Some(31));
            assert_eq!(&*stderr, "probe rejected by fixture\n");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn probe_oversized_output_is_rejected_before_flavor_selection() {
    let fixture = Fixture::new();
    let script = fixture.custom_script(
        "iptables-restore",
        &format!("{}\nexit 0", oversized_output_body(false)),
        "exit 0",
    );

    let error = expect_open_error(
        open_adapter(script, None, 1, Duration::from_secs(2)),
        "oversized probe output must fail",
    );
    assert!(matches!(
        error,
        XtablesRestoreProcessError::OutputLimit {
            operation: XtablesRestoreProcessOperation::Probe,
            family: XtablesRestoreFamily::Ipv4,
            stream: XtablesRestoreProcessStream::Stdout,
            maximum: 16_384,
            actual,
            ..
        } if actual > 16_384
    ));
}

#[test]
fn probe_accepts_stderr_only_version_and_rejects_unknown_or_ambiguous_flavors() {
    let stderr_only = Fixture::new();
    let stderr_tool = stderr_only.custom_script(
        "iptables-restore",
        &format!(
            "{PRINTF} '%s\\n' {} >&2\nexit 0",
            shell_quote_text(LEGACY_VERSION)
        ),
        "exit 0",
    );
    let adapter = open_adapter(stderr_tool, None, 1, Duration::from_secs(1))
        .expect("stderr-only legacy flavor must be recognized");
    assert_eq!(
        adapter.reported_flavor(),
        XtablesRestoreReportedFlavor::Legacy
    );
    assert_eq!(
        adapter
            .tool_identity(XtablesRestoreFamily::Ipv4)
            .expect("IPv4 identity")
            .version(),
        LEGACY_VERSION
    );

    for (label, version) in [
        ("unknown", "iptables-restore v1.8.7"),
        (
            "ambiguous",
            "iptables-restore v1.8.7 (legacy) compatibility (nf_tables)",
        ),
    ] {
        let fixture = Fixture::new();
        let script = fixture.script("iptables-restore", version, "exit 0");
        let error = expect_open_error(
            open_adapter(script, None, 1, Duration::from_secs(1)),
            "unclassified reported_flavor must fail",
        );
        assert!(
            matches!(error, XtablesRestoreProcessError::ToolFlavor { .. }),
            "{label} reported_flavor produced {error:?}"
        );
    }
}

#[test]
fn tool_that_modifies_its_inode_during_probe_is_rejected_before_admission() {
    let fixture = Fixture::new();
    let tool = fixture.path("iptables-restore");
    let probe = format!(
        "{PRINTF} '%s\\n' {}\n{PRINTF} '%s\\n' '# changed during probe' >> {}\nexit 0",
        shell_quote_text(LEGACY_VERSION),
        shell_quote(&tool),
    );
    write_custom_script(&tool, &probe, "exit 0", 0o700);

    let error = expect_open_error(
        open_adapter(tool, None, 1, Duration::from_secs(2)),
        "probe-time digest mutation must prevent admission",
    );
    assert!(matches!(
        error,
        XtablesRestoreProcessError::ToolIdentityChanged {
            family: XtablesRestoreFamily::Ipv4,
            ..
        }
    ));
}

#[test]
fn relative_non_executable_and_missing_tool_paths_fail_closed() {
    let relative = expect_open_error(
        open_adapter(
            PathBuf::from("relative/iptables-restore"),
            None,
            1,
            Duration::from_secs(1),
        ),
        "relative path must fail",
    );
    assert_eq!(relative.kind(), XtablesRestoreProcessErrorKind::InvalidPath);

    let fixture = Fixture::new();
    let non_executable = fixture.path("not-executable");
    write_script(&non_executable, LEGACY_VERSION, "exit 0", 0o600);
    let non_executable_error = expect_open_error(
        open_adapter(non_executable, None, 1, Duration::from_secs(1)),
        "non-executable path must fail",
    );
    assert_eq!(
        non_executable_error.kind(),
        XtablesRestoreProcessErrorKind::InvalidPath
    );

    let missing = expect_open_error(
        open_adapter(
            fixture.path("missing-iptables-restore"),
            None,
            1,
            Duration::from_secs(1),
        ),
        "missing path must fail",
    );
    assert_eq!(missing.kind(), XtablesRestoreProcessErrorKind::ToolOpen);
}

#[test]
fn symlink_directory_and_fifo_paths_are_rejected_without_blocking() {
    let fixture = Fixture::new();
    let target = fixture.script("target-iptables-restore", LEGACY_VERSION, "exit 0");
    let link = fixture.path("symlink-iptables-restore");
    symlink(&target, &link).expect("create restore-tool symlink");
    let symlink_error = expect_open_error(
        open_adapter(link, None, 1, Duration::from_secs(1)),
        "symlink path must fail",
    );
    assert_eq!(
        symlink_error.kind(),
        XtablesRestoreProcessErrorKind::ToolOpen
    );

    let directory = fixture.path("restore-tool-directory");
    fs::create_dir(&directory).expect("create restore-tool directory");
    let directory_error = expect_open_error(
        open_adapter(directory, None, 1, Duration::from_secs(1)),
        "directory path must fail",
    );
    assert_eq!(
        directory_error.kind(),
        XtablesRestoreProcessErrorKind::InvalidPath
    );

    let fifo = fixture.path("restore-tool-fifo");
    let fifo_path = CString::new(fifo.as_os_str().as_bytes()).expect("FIFO path has no NUL");
    // SAFETY: `fifo_path` is a live, NUL-terminated path and the mode is a valid permission mask.
    let result = unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o700) };
    assert_eq!(result, 0, "create restore-tool FIFO");
    let started = Instant::now();
    let fifo_error = expect_open_error(
        open_adapter(fifo, None, 1, Duration::from_secs(1)),
        "FIFO path must fail",
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "FIFO admission blocked for {:?}",
        started.elapsed()
    );
    assert_eq!(
        fifo_error.kind(),
        XtablesRestoreProcessErrorKind::InvalidPath
    );
}

#[test]
fn executing_ipv6_without_a_selected_ipv6_tool_is_rejected_before_spawn() {
    let fixture = Fixture::new();
    let ipv4 = fixture.script("iptables-restore", LEGACY_VERSION, "exit 0");
    let mut adapter =
        open_adapter(ipv4, None, 1, Duration::from_secs(1)).expect("open IPv4-only adapter");
    let (_, ipv6_artifact) = artifact(XtablesRestoreFamily::Ipv6);

    let error = adapter
        .execute(&ipv6_artifact)
        .expect_err("missing IPv6 tool must fail");
    assert_eq!(
        error.mutation_disposition(),
        XtablesRestoreMutationDisposition::NotStarted
    );
    assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::MissingFamily);
    assert!(matches!(
        error,
        XtablesRestoreProcessError::MissingFamily {
            family: XtablesRestoreFamily::Ipv6
        }
    ));
}

#[test]
fn nonzero_restore_exit_preserves_bounded_stderr() {
    let fixture = Fixture::new();
    let script = fixture.script(
        "iptables-restore",
        LEGACY_VERSION,
        &format!("{PRINTF} '%s\\n' 'restore rejected by fixture' >&2\nexit 23"),
    );
    let mut adapter =
        open_adapter(script, None, 1, Duration::from_secs(1)).expect("open restore adapter");
    let (_, artifact) = artifact(XtablesRestoreFamily::Ipv4);

    let error = adapter
        .execute(&artifact)
        .expect_err("nonzero restore exit must fail");
    assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::NonZeroExit);
    assert_eq!(
        error.mutation_disposition(),
        XtablesRestoreMutationDisposition::MayHaveMutated
    );
    match error {
        XtablesRestoreProcessError::NonZeroExit {
            operation,
            family,
            status,
            stderr,
            ..
        } => {
            assert_eq!(operation, XtablesRestoreProcessOperation::Restore);
            assert_eq!(family, XtablesRestoreFamily::Ipv4);
            assert_eq!(status.code(), Some(23));
            assert_eq!(&*stderr, "restore rejected by fixture\n");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn restore_timeout_is_bounded_and_kills_the_process_group() {
    let fixture = Fixture::new();
    let script = fixture.script("iptables-restore", LEGACY_VERSION, &format!("{SLEEP} 30"));
    let timeout = Duration::from_millis(100);
    let mut adapter = open_adapter(script, None, 1, timeout).expect("open restore adapter");
    let (_, artifact) = artifact(XtablesRestoreFamily::Ipv4);

    let started = Instant::now();
    let error = adapter
        .execute(&artifact)
        .expect_err("hung restore must time out");
    assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::TimedOut);
    assert_eq!(
        error.mutation_disposition(),
        XtablesRestoreMutationDisposition::MayHaveMutated
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(matches!(
        error,
        XtablesRestoreProcessError::TimedOut {
            operation: XtablesRestoreProcessOperation::Restore,
            family: XtablesRestoreFamily::Ipv4,
            timeout: observed,
            ..
        } if observed == timeout
    ));
}

#[test]
fn timeout_unblocks_and_joins_a_writer_stuck_on_large_canonical_stdin() {
    let fixture = Fixture::new();
    let script = fixture.script("iptables-restore", LEGACY_VERSION, &format!("{SLEEP} 30"));
    let timeout = Duration::from_millis(100);
    let mut adapter = open_adapter(script, None, 1, timeout).expect("open restore adapter");
    let artifact = large_artifact();

    let started = Instant::now();
    let error = adapter
        .execute(&artifact)
        .expect_err("blocked stdin writer must be released by timeout cleanup");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(matches!(
        error,
        XtablesRestoreProcessError::TimedOut {
            operation: XtablesRestoreProcessOperation::Restore,
            family: XtablesRestoreFamily::Ipv4,
            timeout: observed,
            ..
        } if observed == timeout
    ));
}

#[test]
fn oversized_stderr_is_rejected_with_the_stream_identity() {
    let fixture = Fixture::new();
    let body = oversized_output_body(true);
    let script = fixture.script("iptables-restore", LEGACY_VERSION, &body);
    let mut adapter =
        open_adapter(script, None, 1, Duration::from_secs(3)).expect("open restore adapter");
    let (_, artifact) = artifact(XtablesRestoreFamily::Ipv4);

    let error = adapter
        .execute(&artifact)
        .expect_err("oversized stderr must fail");
    assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::OutputLimit);
    assert!(matches!(
        error,
        XtablesRestoreProcessError::OutputLimit {
            operation: XtablesRestoreProcessOperation::Restore,
            family: XtablesRestoreFamily::Ipv4,
            stream: XtablesRestoreProcessStream::Stderr,
            maximum: 16_384,
            actual,
            ..
        } if actual > 16_384
    ));
}

#[test]
fn oversized_stdout_is_rejected_with_the_stream_identity() {
    let fixture = Fixture::new();
    let script = fixture.script(
        "iptables-restore",
        LEGACY_VERSION,
        &oversized_output_body(false),
    );
    let mut adapter =
        open_adapter(script, None, 1, Duration::from_secs(2)).expect("open restore adapter");
    let (_, artifact) = artifact(XtablesRestoreFamily::Ipv4);

    let error = adapter
        .execute(&artifact)
        .expect_err("oversized stdout must fail");
    assert!(matches!(
        error,
        XtablesRestoreProcessError::OutputLimit {
            operation: XtablesRestoreProcessOperation::Restore,
            family: XtablesRestoreFamily::Ipv4,
            stream: XtablesRestoreProcessStream::Stdout,
            maximum: 16_384,
            actual,
            ..
        } if actual > 16_384
    ));
}

#[test]
fn a_successful_parent_cannot_leave_a_descendant_holding_capture_pipes() {
    let fixture = Fixture::new();
    let descendant_pid = fixture.path("descendant.pid");
    let body = format!(
        "{SLEEP} 30 &\nchild=$!\n{PRINTF} '%s\\n' \"$child\" > {}\nexit 0",
        shell_quote(&descendant_pid)
    );
    let script = fixture.script("iptables-restore", LEGACY_VERSION, &body);
    let mut adapter =
        open_adapter(script, None, 1, Duration::from_secs(2)).expect("open restore adapter");
    let (_, artifact) = artifact(XtablesRestoreFamily::Ipv4);

    let started = Instant::now();
    adapter
        .execute(&artifact)
        .expect("parent success must clean the entire process group");
    assert!(started.elapsed() < Duration::from_secs(2));
    let pid: u32 = fs::read_to_string(descendant_pid)
        .expect("descendant pid record")
        .trim()
        .parse()
        .expect("numeric descendant pid");
    assert!(
        !Path::new("/proc").join(pid.to_string()).exists(),
        "descendant {pid} remained after restore completion"
    );
}

#[test]
fn descriptor_pinning_executes_the_admitted_inode_after_path_replacement() {
    let fixture = Fixture::new();
    let admitted_args = fixture.path("admitted.args");
    let admitted_stdin = fixture.path("admitted.stdin");
    let replacement_args = fixture.path("replacement.args");
    let replacement_stdin = fixture.path("replacement.stdin");
    let tool = fixture.script(
        "iptables-restore",
        LEGACY_VERSION,
        &record_restore_body(&admitted_args, &admitted_stdin, "admitted"),
    );
    let mut adapter = open_adapter(tool.clone(), None, 5, Duration::from_secs(2))
        .expect("open pinned restore adapter");

    fs::rename(&tool, fixture.path("admitted-inode"))
        .expect("move admitted inode away from diagnostic path");
    write_script(
        &tool,
        LEGACY_VERSION,
        &record_restore_body(&replacement_args, &replacement_stdin, "replacement"),
        0o700,
    );
    let (bytes, artifact) = artifact(XtablesRestoreFamily::Ipv4);
    let output = adapter
        .execute(&artifact)
        .expect("execute the descriptor-pinned admitted tool");

    assert_eq!(output.stdout(), "admitted\n");
    assert_eq!(
        fs::read_to_string(admitted_args).unwrap(),
        "-w\n5\n--noflush\n"
    );
    assert_eq!(fs::read(admitted_stdin).unwrap(), bytes);
    assert!(!replacement_args.exists());
    assert!(!replacement_stdin.exists());
}

#[test]
fn in_place_tool_digest_change_is_refused_before_restore_execution() {
    let fixture = Fixture::new();
    let execution_record = fixture.path("executed");
    let tool = fixture.script("iptables-restore", LEGACY_VERSION, "exit 0");
    let mut adapter = open_adapter(tool.clone(), None, 1, Duration::from_secs(1))
        .expect("open pinned restore adapter");
    let changed_body = format!(
        "{PRINTF} '%s\\n' 'unexpected execution' > {}\nexit 0",
        shell_quote(&execution_record)
    );
    write_script(&tool, LEGACY_VERSION, &changed_body, 0o700);
    let (_, artifact) = artifact(XtablesRestoreFamily::Ipv4);

    let error = adapter
        .execute(&artifact)
        .expect_err("changed admitted inode must fail identity verification");
    assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::ToolIdentity);
    assert!(matches!(
        error,
        XtablesRestoreProcessError::ToolIdentityChanged {
            family: XtablesRestoreFamily::Ipv4,
            ..
        }
    ));
    assert!(!execution_record.exists());
}

#[test]
fn tool_that_modifies_its_inode_during_restore_is_rejected_after_execution() {
    let fixture = Fixture::new();
    let execution_record = fixture.path("executed-during-change");
    let tool = fixture.path("iptables-restore");
    let body = format!(
        "{CAT} >/dev/null\n{PRINTF} '%s\\n' 'restore executed' > {}\n{PRINTF} '%s\\n' '# changed during restore' >> {}\nexit 0",
        shell_quote(&execution_record),
        shell_quote(&tool),
    );
    write_script(&tool, LEGACY_VERSION, &body, 0o700);
    let mut adapter =
        open_adapter(tool, None, 1, Duration::from_secs(2)).expect("open pinned restore adapter");
    let (_, artifact) = artifact(XtablesRestoreFamily::Ipv4);

    let error = adapter
        .execute(&artifact)
        .expect_err("post-exec digest mismatch must reject restore evidence");
    assert_eq!(
        error.mutation_disposition(),
        XtablesRestoreMutationDisposition::MayHaveMutated
    );
    assert!(matches!(
        error,
        XtablesRestoreProcessError::ToolIdentityChanged {
            family: XtablesRestoreFamily::Ipv4,
            ..
        }
    ));
    assert_eq!(
        fs::read_to_string(execution_record).unwrap(),
        "restore executed\n"
    );
}

fn open_adapter(
    ipv4: PathBuf,
    ipv6: Option<PathBuf>,
    wait_seconds: u16,
    timeout: Duration,
) -> Result<XtablesRestoreProcessAdapter, XtablesRestoreProcessError> {
    let config = XtablesRestoreProcessConfig::new(wait_seconds, timeout)?;
    XtablesRestoreProcessAdapter::open(XtablesRestoreProcessPaths::new(ipv4, ipv6), config)
}

fn expect_open_error(
    result: Result<XtablesRestoreProcessAdapter, XtablesRestoreProcessError>,
    context: &str,
) -> XtablesRestoreProcessError {
    match result {
        Ok(_) => panic!("{context}"),
        Err(error) => error,
    }
}

fn artifact(family: XtablesRestoreFamily) -> (Vec<u8>, XtablesRestoreArtifact) {
    let bytes = match family {
        XtablesRestoreFamily::Ipv4 => {
            b"*mangle\n:FLX4O0000000001 - [0:0]\n-A FLX4O0000000001 -p tcp -j RETURN\nCOMMIT\n"
                .to_vec()
        }
        XtablesRestoreFamily::Ipv6 => {
            b"*mangle\n:FLX6O0000000001 - [0:0]\n-A FLX6O0000000001 -p udp -j RETURN\nCOMMIT\n"
                .to_vec()
        }
    };
    let artifact = parse_xtables_restore(
        &bytes,
        XtablesRestoreContext::new(XtablesRestoreAction::Apply, family),
    )
    .expect("valid canonical restore fixture");
    (bytes, artifact)
}

fn large_artifact() -> XtablesRestoreArtifact {
    let mut bytes = Vec::with_capacity(512 * 1024);
    bytes.extend_from_slice(b"*mangle\n:FLX4O0000000002 - [0:0]\n");
    for _ in 0..12_000 {
        bytes.extend_from_slice(b"-A FLX4O0000000002 -p tcp -j RETURN\n");
    }
    bytes.extend_from_slice(b"COMMIT\n");
    assert!(
        bytes.len() > 256 * 1024,
        "fixture must exceed pipe capacity"
    );
    parse_xtables_restore(
        &bytes,
        XtablesRestoreContext::new(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4),
    )
    .expect("large valid canonical restore fixture")
}

fn oversized_output_body(stderr: bool) -> String {
    let payload = "0123456789abcdef".repeat(1_250);
    format!(
        "{PRINTF} '%s' {}{}",
        shell_quote_text(&payload),
        if stderr { " >&2" } else { "" },
    )
}

fn record_restore_body(args: &Path, stdin: &Path, stdout: &str) -> String {
    format!(
        "{PRINTF} '%s\\n' \"$@\" > {}\n{CAT} > {}\n{PRINTF} '%s\\n' {}",
        shell_quote(args),
        shell_quote(stdin),
        shell_quote_text(stdout),
    )
}

fn write_script(path: &Path, version: &str, body: &str, mode: u32) {
    let probe = format!("{PRINTF} '%s\\n' {}\nexit 0", shell_quote_text(version));
    write_custom_script(path, &probe, body, mode);
}

fn write_custom_script(path: &Path, probe: &str, body: &str, mode: u32) {
    let source =
        format!("#!{SHELL}\nif [ \"${{1:-}}\" = \"--version\" ]; then\n{probe}\nfi\n{body}\n",);
    fs::write(path, source).expect("write executable fixture");
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).expect("set fixture mode");
}

fn shell_quote(path: &Path) -> String {
    shell_quote_text(&path.to_string_lossy())
}

fn shell_quote_text(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

struct Fixture {
    directory: TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            directory: tempfile::tempdir().expect("create fixture directory"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn script(&self, name: &str, version: &str, body: &str) -> PathBuf {
        let path = self.path(name);
        write_script(&path, version, body, 0o700);
        path
    }

    fn custom_script(&self, name: &str, probe: &str, body: &str) -> PathBuf {
        let path = self.path(name);
        write_custom_script(&path, probe, body, 0o700);
        path
    }
}
