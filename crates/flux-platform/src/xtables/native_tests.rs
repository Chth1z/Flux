#![cfg(any(target_os = "linux", target_os = "android"))]

use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;
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
const LEGACY_V6_VERSION: &str = "ip6tables-restore v1.8.7 (legacy)";
const NFT_VERSION: &str = "iptables-restore v1.8.7 (nf_tables)";
const NFT_V6_VERSION: &str = "ip6tables-restore v1.8.7 (nf_tables)";

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
        LEGACY_V6_VERSION,
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

    assert_eq!(
        fs::read_to_string(ipv4_args).unwrap(),
        "-w\n7\n--noflush\n--modprobe=/dev/null\n"
    );
    assert_eq!(
        fs::read_to_string(ipv6_args).unwrap(),
        "-w\n7\n--noflush\n--modprobe=/dev/null\n"
    );
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
    assert_eq!(ipv4_output.tool_identity().applet(), "iptables-restore");
    assert_eq!(ipv6_output.tool_identity().applet(), "ip6tables-restore");
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
    let legacy_v6 = legacy.script("ip6tables-restore", LEGACY_V6_VERSION, "exit 0");
    let legacy_adapter = open_adapter(legacy_v4, Some(legacy_v6), 1, Duration::from_secs(1))
        .expect("open matching legacy pair");
    assert_eq!(
        legacy_adapter.reported_flavor(),
        XtablesRestoreReportedFlavor::Legacy
    );

    let nft = Fixture::new();
    let nft_v4 = nft.script("iptables-restore", NFT_VERSION, "exit 0");
    let nft_v6 = nft.script("ip6tables-restore", NFT_V6_VERSION, "exit 0");
    let nft_adapter = open_adapter(nft_v4, Some(nft_v6), 1, Duration::from_secs(1))
        .expect("open matching nf_tables pair");
    assert_eq!(
        nft_adapter.reported_flavor(),
        XtablesRestoreReportedFlavor::NfTables
    );

    let mixed = Fixture::new();
    let mixed_v4 = mixed.script("iptables-restore", LEGACY_VERSION, "exit 0");
    let mixed_v6 = mixed.script("ip6tables-restore", NFT_V6_VERSION, "exit 0");
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
            operation: XtablesRestoreProcessOperation::Probe(XtablesToolRole::Restore),
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
            assert_eq!(
                operation,
                XtablesRestoreProcessOperation::Probe(XtablesToolRole::Restore)
            );
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
            operation: XtablesRestoreProcessOperation::Probe(XtablesToolRole::Restore),
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

    let writable = fixture.path("writable-iptables-restore");
    write_script(&writable, LEGACY_VERSION, "exit 0", 0o722);
    let writable_error = expect_open_error(
        open_adapter(writable, None, 1, Duration::from_secs(1)),
        "group/world-writable privileged tools must fail before probing",
    );
    assert_eq!(
        writable_error.kind(),
        XtablesRestoreProcessErrorKind::InvalidPath
    );
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
        "{CAT} >/dev/null\n{SLEEP} 30 &\nchild=$!\n{PRINTF} '%s\\n' \"$child\" > {}\nexit 0",
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
        "-w\n5\n--noflush\n--modprobe=/dev/null\n"
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

#[test]
fn coherent_tool_set_binds_exact_roles_versions_and_mapping_identity() {
    let fixture = Fixture::new();
    let paths = fixture.tool_set_paths(false, "1.8.11", "legacy", "exit 0", "exit 0");
    let adapter = XtablesToolSetProcessAdapter::open_exact_for_tests(
        paths,
        process_config(Duration::from_secs(2)),
    )
    .expect("open split executable fixtures with production coherence checks except common digest");
    let identity = adapter.identity();

    assert_eq!(
        identity.reported_flavor(),
        XtablesRestoreReportedFlavor::Legacy
    );
    assert_eq!(identity.release(), "1.8.11");
    let ipv4 = identity
        .family(XtablesRestoreFamily::Ipv4)
        .expect("IPv4 identity");
    for (role, applet) in [
        (XtablesToolRole::Command, "iptables"),
        (XtablesToolRole::Restore, "iptables-restore"),
        (XtablesToolRole::Save, "iptables-save"),
    ] {
        let tool = ipv4.tool(role);
        assert_eq!(tool.family(), XtablesRestoreFamily::Ipv4);
        assert_eq!(tool.role(), role);
        assert_eq!(tool.applet(), applet);
        assert_eq!(tool.release(), "1.8.11");
        assert_eq!(
            tool.file_identity().length(),
            fs::metadata(tool.path()).unwrap().len()
        );
    }
    assert_ne!(identity.digest().as_bytes(), &[0; 32]);
}

#[test]
fn strict_tool_set_rejects_split_executable_digests() {
    let fixture = Fixture::new();
    let paths = fixture.tool_set_paths(false, "1.8.11", "legacy", "exit 0", "exit 0");
    let probe_record = fixture.path("unexpected-version-probe");
    let command = paths.ipv4().path(XtablesToolRole::Command);
    write_custom_script(
        command,
        &format!(
            "{PRINTF} '%s\\n' probed > {}\n{PRINTF} '%s\\n' {}\nexit 0",
            shell_quote(&probe_record),
            shell_quote_text("iptables v1.8.11 (legacy)")
        ),
        "exit 0",
        0o700,
    );
    let error =
        XtablesToolSetProcessAdapter::open_exact(paths, process_config(Duration::from_secs(2)))
            .expect_err(
                "the first admitted profile requires one common multicall executable digest",
            );

    assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::ToolCoherence);
    assert!(matches!(
        error,
        XtablesRestoreProcessError::ToolSetCoherence { .. }
    ));
    assert!(
        !probe_record.exists(),
        "no candidate may execute before complete mapping coherence"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn strict_multicall_discovery_proves_argv0_restore_and_save_dispatch() {
    let fixture = Fixture::new();
    let applet_root = fixture.path("strict-multicall-bin");
    fs::create_dir(&applet_root).unwrap();
    let multicall = compile_multicall_fixture(&fixture);
    for family in [XtablesRestoreFamily::Ipv4, XtablesRestoreFamily::Ipv6] {
        for role in [
            XtablesToolRole::Command,
            XtablesToolRole::Restore,
            XtablesToolRole::Save,
        ] {
            symlink(&multicall, applet_root.join(role.applet(family))).unwrap();
        }
    }

    let mut adapter = XtablesToolSetProcessAdapter::discover_standard(
        &applet_root,
        true,
        process_config(Duration::from_secs(3)),
    )
    .expect("strict production discovery admits one descriptor-pinned multicall binary");
    let reference = adapter
        .identity()
        .family(XtablesRestoreFamily::Ipv4)
        .unwrap()
        .tool(XtablesToolRole::Command)
        .digest();
    for family in [XtablesRestoreFamily::Ipv4, XtablesRestoreFamily::Ipv6] {
        for role in [
            XtablesToolRole::Command,
            XtablesToolRole::Restore,
            XtablesToolRole::Save,
        ] {
            assert_eq!(
                adapter
                    .identity()
                    .family(family)
                    .unwrap()
                    .tool(role)
                    .digest(),
                reference
            );
        }
    }

    let (_, ipv4) = artifact(XtablesRestoreFamily::Ipv4);
    adapter
        .restore(&ipv4)
        .expect("logical restore argv0 dispatches through the pinned descriptor");
    let saved = adapter
        .save(XtablesRestoreFamily::Ipv6)
        .expect("logical save argv0 dispatches through the pinned descriptor");
    assert_eq!(saved.stdout(), b"*mangle\nCOMMIT\n");
}

#[cfg(target_os = "linux")]
#[test]
fn android_census_collector_opens_only_dual_stack_save_applets() {
    let fixture = Fixture::new();
    let applet_root = fixture.path("census-save-bin");
    fs::create_dir(&applet_root).unwrap();
    let multicall = compile_multicall_fixture(&fixture);
    for family in [XtablesRestoreFamily::Ipv4, XtablesRestoreFamily::Ipv6] {
        symlink(
            &multicall,
            applet_root.join(XtablesToolRole::Save.applet(family)),
        )
        .unwrap();
    }

    let snapshots = collect_android_xtables_save_snapshots(&applet_root, Duration::from_secs(3))
        .expect("save-only census collector must not require command or restore applets");

    assert_eq!(snapshots.ipv4(), b"*mangle\nCOMMIT\n");
    assert_eq!(snapshots.ipv6(), b"*mangle\nCOMMIT\n");
    assert!(!applet_root.join("iptables").exists());
    assert!(!applet_root.join("iptables-restore").exists());
    assert!(!applet_root.join("ip6tables").exists());
    assert!(!applet_root.join("ip6tables-restore").exists());
}

#[test]
fn android_census_collector_rejects_split_binaries_before_any_probe() {
    let fixture = Fixture::new();
    let applet_root = fixture.path("split-census-save-bin");
    fs::create_dir(&applet_root).unwrap();
    let probe_record = fixture.path("unexpected-census-probe");
    for (family, suffix) in [
        (XtablesRestoreFamily::Ipv4, "v4"),
        (XtablesRestoreFamily::Ipv6, "v6"),
    ] {
        let path = applet_root.join(XtablesToolRole::Save.applet(family));
        write_custom_script(
            &path,
            &format!(
                "{PRINTF} '%s\\n' {suffix} >> {}\n{PRINTF} '%s\\n' {}\nexit 0",
                shell_quote(&probe_record),
                shell_quote_text(&tool_version(
                    family,
                    XtablesToolRole::Save,
                    "1.8.11",
                    "legacy"
                )),
            ),
            "exit 0",
            0o700,
        );
    }

    let error = collect_android_xtables_save_snapshots(&applet_root, Duration::from_secs(2))
        .expect_err("split save executables must fail the multicall profile");

    assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::ToolCoherence);
    assert!(!probe_record.exists());
}

#[test]
fn android_census_collector_rejects_an_invalid_aggregate_bound() {
    let fixture = Fixture::new();
    let error = collect_android_xtables_save_snapshots(fixture.directory.path(), Duration::ZERO)
        .expect_err("zero aggregate bound must fail before opening applets");
    assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::InvalidConfig);
}

#[test]
fn tool_set_rejects_wrong_role_and_mixed_release_reports() {
    let wrong_role = Fixture::new();
    let paths = wrong_role.tool_set_paths(false, "1.8.11", "legacy", "exit 0", "exit 0");
    write_script(
        paths.ipv4().path(XtablesToolRole::Command),
        LEGACY_VERSION,
        "exit 0",
        0o700,
    );
    let error = XtablesToolSetProcessAdapter::open_exact_for_tests(
        paths,
        process_config(Duration::from_secs(2)),
    )
    .expect_err("a command role cannot report the restore applet grammar");
    assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::ToolFlavor);

    let mixed_release = Fixture::new();
    let paths = mixed_release.tool_set_paths(false, "1.8.11", "legacy", "exit 0", "exit 0");
    write_script(
        paths.ipv4().path(XtablesToolRole::Save),
        "iptables-save v1.8.10 (legacy)",
        "exit 0",
        0o700,
    );
    let error = XtablesToolSetProcessAdapter::open_exact_for_tests(
        paths,
        process_config(Duration::from_secs(2)),
    )
    .expect_err("all roles must report one exact normalized release");
    assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::ToolCoherence);
}

#[test]
fn save_uses_no_arguments_null_stdin_and_complete_bounded_stdout() {
    let fixture = Fixture::new();
    let args = fixture.path("save.args");
    let output_path = fixture.path("save.output");
    let output = b"*mangle\n# exact save payload\nCOMMIT\n"
        .repeat(1_024)
        .into_boxed_slice();
    assert!(output.len() > MAX_CAPTURE_BYTES);
    fs::write(&output_path, &output).unwrap();
    let save_body = format!(
        ": > {}\nfor argument in \"$@\"; do {PRINTF} '%s\\n' \"$argument\" >> {}; done\nif IFS= read -r unexpected; then exit 42; fi\n{CAT} {}",
        shell_quote(&args),
        shell_quote(&args),
        shell_quote(&output_path),
    );
    let paths = fixture.tool_set_paths(false, "1.8.11", "legacy", "exit 0", &save_body);
    let mut adapter = XtablesToolSetProcessAdapter::open_exact_for_tests(
        paths,
        process_config(Duration::from_secs(2)),
    )
    .unwrap();

    let observed = adapter.save(XtablesRestoreFamily::Ipv4).unwrap();
    assert_eq!(observed.family(), XtablesRestoreFamily::Ipv4);
    assert_eq!(observed.tool_identity().role(), XtablesToolRole::Save);
    assert_eq!(observed.tool_identity().applet(), "iptables-save");
    assert_eq!(observed.stdout(), &*output);
    assert_eq!(observed.stderr(), "");
    assert_eq!(fs::read(args).unwrap(), b"");
}

#[test]
fn save_stdout_above_the_restore_byte_budget_is_rejected_without_mutation() {
    let fixture = Fixture::new();
    let output_path = fixture.path("oversized-save.output");
    fs::write(&output_path, vec![b'x'; MAX_XTABLES_RESTORE_BYTES + 1]).unwrap();
    let save_body = format!("{CAT} {}", shell_quote(&output_path));
    let paths = fixture.tool_set_paths(false, "1.8.11", "legacy", "exit 0", &save_body);
    let mut adapter = XtablesToolSetProcessAdapter::open_exact_for_tests(
        paths,
        process_config(Duration::from_secs(2)),
    )
    .unwrap();

    let error = adapter
        .save(XtablesRestoreFamily::Ipv4)
        .expect_err("save output above the exact projection budget must fail");
    assert_eq!(
        error.mutation_disposition(),
        XtablesRestoreMutationDisposition::NotStarted
    );
    assert!(matches!(
        error,
        XtablesRestoreProcessError::OutputLimit {
            operation: XtablesRestoreProcessOperation::Save,
            stream: XtablesRestoreProcessStream::Stdout,
            maximum: MAX_XTABLES_RESTORE_BYTES,
            actual,
            ..
        } if actual > MAX_XTABLES_RESTORE_BYTES
    ));
}

#[test]
fn discovery_follows_only_final_standard_applet_links() {
    let fixture = Fixture::new();
    let target_root = fixture.path("targets");
    let applet_root = fixture.path("system-bin");
    fs::create_dir(&target_root).unwrap();
    fs::create_dir(&applet_root).unwrap();
    for role in [
        XtablesToolRole::Command,
        XtablesToolRole::Restore,
        XtablesToolRole::Save,
    ] {
        let applet = role.applet(XtablesRestoreFamily::Ipv4);
        let target = target_root.join(applet);
        write_script(
            &target,
            &tool_version(XtablesRestoreFamily::Ipv4, role, "1.8.11", "legacy"),
            "exit 0",
            0o700,
        );
        symlink(&target, applet_root.join(applet)).unwrap();
    }

    let exact_paths = XtablesToolSetPaths::new(
        XtablesToolFamilyPaths::standard(&applet_root, XtablesRestoreFamily::Ipv4),
        None,
    );
    let exact_error = XtablesToolSetProcessAdapter::open_exact_for_tests(
        exact_paths,
        process_config(Duration::from_secs(2)),
    )
    .expect_err("explicit exact paths retain final-component no-follow semantics");
    assert_eq!(exact_error.kind(), XtablesRestoreProcessErrorKind::ToolOpen);

    let discovered = XtablesToolSetProcessAdapter::discover_standard_for_tests(
        &applet_root,
        false,
        process_config(Duration::from_secs(2)),
    )
    .expect("fixed-root discovery follows and pins final standard applet links");
    assert_eq!(
        discovered
            .identity()
            .family(XtablesRestoreFamily::Ipv4)
            .unwrap()
            .tool(XtablesToolRole::Restore)
            .path(),
        applet_root.join("iptables-restore")
    );

    let root_link = fixture.path("system-bin-link");
    symlink(&applet_root, &root_link).unwrap();
    let root_error = XtablesToolSetProcessAdapter::discover_standard_for_tests(
        root_link,
        false,
        process_config(Duration::from_secs(2)),
    )
    .expect_err("the discovery root itself must not be a symlink");
    assert_eq!(root_error.kind(), XtablesRestoreProcessErrorKind::ToolOpen);
}

#[test]
fn tool_set_identity_changes_when_one_role_mapping_changes() {
    let fixture = Fixture::new();
    let first_paths = fixture.tool_set_paths(false, "1.8.11", "legacy", "exit 0", "exit 0");
    let first = XtablesToolSetProcessAdapter::open_exact_for_tests(
        first_paths.clone(),
        process_config(Duration::from_secs(2)),
    )
    .unwrap();
    let first_digest = first.identity().digest();
    drop(first);

    write_script(
        first_paths.ipv4().path(XtablesToolRole::Save),
        "iptables-save v1.8.11 (legacy)",
        "# mapping revision\nexit 0",
        0o700,
    );
    let second = XtablesToolSetProcessAdapter::open_exact_for_tests(
        first_paths,
        process_config(Duration::from_secs(2)),
    )
    .unwrap();
    assert_ne!(first_digest, second.identity().digest());
}

#[test]
fn save_tool_mutation_during_execution_invalidates_readback_evidence() {
    let fixture = Fixture::new();
    let paths = fixture.tool_set_paths(false, "1.8.11", "legacy", "exit 0", "exit 0");
    let save_path = paths.ipv4().path(XtablesToolRole::Save).to_path_buf();
    let body = format!(
        "{PRINTF} '%s\\n' '*mangle' 'COMMIT'\n{PRINTF} '%s\\n' '# changed' >> {}",
        shell_quote(&save_path)
    );
    write_script(&save_path, "iptables-save v1.8.11 (legacy)", &body, 0o700);
    let mut adapter = XtablesToolSetProcessAdapter::open_exact_for_tests(
        paths,
        process_config(Duration::from_secs(2)),
    )
    .unwrap();

    let error = adapter
        .save(XtablesRestoreFamily::Ipv4)
        .expect_err("a changed save executable cannot authorize observed bytes");
    assert_eq!(error.kind(), XtablesRestoreProcessErrorKind::ToolIdentity);
    assert_eq!(
        error.mutation_disposition(),
        XtablesRestoreMutationDisposition::NotStarted
    );
}

#[test]
#[ignore = "host capability probe: requires a coherent /usr/sbin xtables multicall installation"]
fn host_multicall_discovery_proves_role_specific_argv0_dispatch() {
    let adapter = XtablesToolSetProcessAdapter::discover_standard(
        "/usr/sbin",
        true,
        process_config(Duration::from_secs(2)),
    )
    .expect("discover the host xtables multicall tool set");
    assert!(matches!(
        adapter.identity().reported_flavor(),
        XtablesRestoreReportedFlavor::Legacy | XtablesRestoreReportedFlavor::NfTables
    ));
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

fn process_config(timeout: Duration) -> XtablesRestoreProcessConfig {
    XtablesRestoreProcessConfig::new(1, timeout).expect("valid process config")
}

fn tool_version(
    family: XtablesRestoreFamily,
    role: XtablesToolRole,
    release: &str,
    flavor: &str,
) -> String {
    format!("{} v{release} ({flavor})", role.applet(family))
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

#[cfg(target_os = "linux")]
fn compile_multicall_fixture(fixture: &Fixture) -> PathBuf {
    let source = fixture.path("xtables-multicall.rs");
    let binary = fixture.path("xtables-multicall");
    fs::write(
        &source,
        r#"
use std::env;
use std::io::{self, Read};
use std::path::Path;

fn main() {
    let arg0 = env::args_os().next().expect("argv0");
    let applet = Path::new(&arg0)
        .file_name()
        .and_then(|name| name.to_str())
        .expect("utf8 applet");
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments == ["--version"] {
        println!("{applet} v1.8.11 (legacy)");
        return;
    }
    match applet {
        "iptables-restore" | "ip6tables-restore" => {
            if arguments != ["-w", "1", "--noflush", "--modprobe=/dev/null"] {
                std::process::exit(41);
            }
            let mut input = Vec::new();
            io::stdin().read_to_end(&mut input).expect("restore stdin");
            if !input.starts_with(b"*mangle\n") || !input.ends_with(b"COMMIT\n") {
                std::process::exit(42);
            }
        }
        "iptables-save" | "ip6tables-save" => {
            if !arguments.is_empty() {
                std::process::exit(43);
            }
            print!("*mangle\nCOMMIT\n");
        }
        _ => std::process::exit(44),
    }
}
"#,
    )
    .expect("write multicall fixture source");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .arg("--edition=2021")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("run rustc for multicall fixture");
    assert!(
        output.status.success(),
        "compile multicall fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
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

    fn tool_set_paths(
        &self,
        include_ipv6: bool,
        release: &str,
        flavor: &str,
        restore_body: &str,
        save_body: &str,
    ) -> XtablesToolSetPaths {
        let family_paths = |family| {
            let mut paths = Vec::new();
            for (role, body) in [
                (XtablesToolRole::Command, "exit 0"),
                (XtablesToolRole::Restore, restore_body),
                (XtablesToolRole::Save, save_body),
            ] {
                let applet = role.applet(family);
                paths.push(self.script(applet, &tool_version(family, role, release, flavor), body));
            }
            XtablesToolFamilyPaths::new(paths.remove(0), paths.remove(0), paths.remove(0))
        };
        XtablesToolSetPaths::new(
            family_paths(XtablesRestoreFamily::Ipv4),
            include_ipv6.then(|| family_paths(XtablesRestoreFamily::Ipv6)),
        )
    }
}
