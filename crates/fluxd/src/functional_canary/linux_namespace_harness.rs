//! Privileged disposable-namespace checkpoints for the functional capture canary.
//!
//! The topology and ingress checkpoints remain Linux-only. The local-OUTPUT TPROXY checkpoint also
//! runs through a development-only rooted Android lane. The topology checkpoint deliberately does
//! not install a TPROXY selector, exercise the RPDB negative control, correlate sockets to the
//! supervised engine, collect capture/bypass/recapture counters, or construct/validate
//! `UnqualifiedCanaryGateEvidence`. None of these checkpoints can authorize `RUNNING` or qualify a
//! production Android profile.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const TEST_NAME: &str = "functional_canary::linux_namespace_harness::privileged_dual_stack_canary_exercises_real_topology_and_cleanup";
const REQUIRED_ENV: &str = "FLUX_LINUX_CANARY_REQUIRED";
const MODE_ENV: &str = "FLUX_LINUX_CANARY_HARNESS_MODE";
const CONFIG_ENV: &str = "FLUX_LINUX_CANARY_HARNESS_CONFIG";
const REENTRY_TOKEN_ENV: &str = "FLUX_LINUX_CANARY_REENTRY_TOKEN";
const OUTER_NETNS_ENV: &str = "FLUX_LINUX_CANARY_OUTER_NETNS";
const OUTER_USERNS_ENV: &str = "FLUX_LINUX_CANARY_OUTER_USERNS";
const OUTER_MOUNTNS_ENV: &str = "FLUX_LINUX_CANARY_OUTER_MOUNTNS";
#[cfg(target_os = "android")]
const OUTER_PID_ENV: &str = "FLUX_LINUX_CANARY_OUTER_PID";
const REENTRY_AUTHORITY_ENV: &str = "FLUX_LINUX_CANARY_REENTRY_AUTHORITY";
const ANDROID_REAL_ROOT_AUTHORITY: &str = "android-real-root";
const MODE_ISOLATED: &str = "isolated";
const MODE_HOLDER: &str = "holder";
const MODE_PEER: &str = "peer";
const MODE_CLIENT: &str = "client";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(4);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024;
const MAX_HELPER_FILE_BYTES: u64 = 64 * 1024;
const MAX_JSON_BYTES: usize = 48 * 1024;
const MAX_JOURNAL_BYTES: u64 = 192 * 1024;
const MAX_JOURNAL_RECORDS: usize = 96;
static JSON_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "android")]
mod android_engine_credential;
#[cfg(target_os = "linux")]
mod distinct_uid;
#[cfg(target_os = "linux")]
mod ingress_tproxy;
mod local_output_tproxy;
#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
mod native_composition;
#[path = "linux_namespace_harness/ingress_tproxy/transparent_tcp.rs"]
mod transparent_tcp;
#[path = "linux_namespace_harness/ingress_tproxy/transparent_udp.rs"]
mod transparent_udp;

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires Linux user/mount/network namespace authority"]
fn privileged_dual_stack_canary_exercises_real_topology_and_cleanup() {
    let result = match env::var(MODE_ENV).as_deref() {
        Err(env::VarError::NotPresent) => run_outer(),
        Ok(MODE_ISOLATED) => run_isolated(),
        Ok(MODE_HOLDER) => run_holder(),
        Ok(MODE_PEER) => run_peer(),
        Ok(MODE_CLIENT) => run_client(),
        Ok(other) => Err(format!("unsupported {MODE_ENV} value {other:?}")),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{MODE_ENV} must contain valid UTF-8")),
    };
    if let Err(error) = result {
        panic!("Linux functional-canary topology checkpoint failed: {error}");
    }
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires Linux user/mount/network namespace and TPROXY authority"]
fn privileged_ingress_tproxy_checkpoint_exercises_real_capture_counters_and_cleanup() {
    ingress_tproxy::run();
}

#[test]
#[ignore = "requires isolated mount/network namespace and local-OUTPUT TPROXY authority"]
fn privileged_local_output_tproxy_checkpoint_exercises_loopback_reinjection_and_cleanup() {
    local_output_tproxy::run();
}

#[test]
#[cfg(target_os = "android")]
#[ignore = "requires rooted Android local-OUTPUT and engine credential authority"]
fn privileged_android_output_tproxy_and_engine_credentials_exercise_exact_cleanup() {
    local_output_tproxy::run();
    android_engine_credential::run();
}

#[test]
#[cfg(target_os = "android")]
#[ignore = "helper invoked by the Android engine parent-death checkpoint"]
fn privileged_android_engine_credential_parent_death_helper() {
    android_engine_credential::run_parent_death_helper();
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires Linux user-namespace authority for distinct subordinate credentials"]
fn privileged_local_output_distinct_uid_capability_preflight() {
    distinct_uid::run();
}

#[test]
#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
#[ignore = "requires Linux user/mount/network namespace and native xtables authority"]
fn privileged_native_composition_exercises_lifecycle_recovery_and_exact_cleanup() {
    native_composition::run();
}

#[test]
fn published_process_identity_requires_exact_nonzero_framing() {
    assert_eq!(
        parse_published_process_identity("123:456\n"),
        Ok(ProcessIdentity {
            pid: 123,
            start_ticks: 456,
        })
    );
    for rejected in ["123:456", "0123:456\n", "123:0\n", "123:456:789\n"] {
        assert!(parse_published_process_identity(rejected).is_err());
    }
}

#[test]
fn checkpoint_and_cleanup_failures_remain_independent() {
    assert_eq!(
        combine_checkpoint_and_cleanup::<()>(Err("checkpoint".to_owned()), Ok(())),
        Err("checkpoint".to_owned())
    );
    assert_eq!(
        combine_checkpoint_and_cleanup(Ok(()), Err("cleanup".to_owned())),
        Err("cleanup failed: cleanup".to_owned())
    );
    assert_eq!(
        combine_checkpoint_and_cleanup::<()>(
            Err("checkpoint".to_owned()),
            Err("cleanup".to_owned()),
        ),
        Err("checkpoint; cleanup also failed: cleanup".to_owned())
    );
}

fn run_outer() -> Result<(), String> {
    let required = required_mode()?;
    for (program, arguments) in [
        ("unshare", &["--version"][..]),
        ("nsenter", &["--version"][..]),
        ("ip", &["-Version"][..]),
    ] {
        let mut command = Command::new(program);
        command.args(arguments);
        if let Err(reason) = checked_command(command, COMMAND_TIMEOUT) {
            return skip_or_fail(
                required,
                format!("required helper `{program}` is unavailable: {reason}"),
            );
        }
    }

    let mut probe = Command::new("unshare");
    probe.args([
        "--user",
        "--map-root-user",
        "--mount",
        "--net",
        "--",
        "true",
    ]);
    if let Err(reason) = checked_command(probe, COMMAND_TIMEOUT) {
        return skip_or_fail(
            required,
            format!("isolated user/mount/network namespaces are unavailable: {reason}"),
        );
    }

    let executable =
        env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    let reentry_token = random_nonce()?;
    let outer_netns = network_namespace_identity()?;
    let outer_userns = user_namespace_identity()?;
    let mut command = Command::new("unshare");
    command
        .args(["--user", "--map-root-user", "--mount", "--net", "--"])
        .arg(executable)
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, MODE_ISOLATED)
        .env(REENTRY_TOKEN_ENV, reentry_token)
        .env(OUTER_NETNS_ENV, outer_netns)
        .env(OUTER_USERNS_ENV, outer_userns);
    checked_command(command, PROCESS_TIMEOUT).map(|_| ())
}

fn required_mode() -> Result<bool, String> {
    match env::var(REQUIRED_ENV) {
        Ok(value) if value == "0" => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        Ok(_) => Err(format!("{REQUIRED_ENV} must be 0 or 1")),
        Err(env::VarError::NotPresent) => Ok(false),
        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("{REQUIRED_ENV} must contain valid UTF-8"))
        }
    }
}

fn skip_or_fail(required: bool, reason: String) -> Result<(), String> {
    if required {
        Err(reason)
    } else {
        eprintln!("SKIP: {reason}");
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HarnessConfig {
    nonce: String,
    daemon_network_namespace: String,
    daemon_interface: String,
    peer_interface: String,
    daemon_ipv4: Ipv4Addr,
    peer_ipv4: Ipv4Addr,
    daemon_ipv6: Ipv6Addr,
    peer_ipv6: Ipv6Addr,
    tcp_port: u16,
    udp_port: u16,
    dns_port: u16,
    journal_path: PathBuf,
    holder_ready_path: PathBuf,
    ready_path: PathBuf,
    peer_report_path: PathBuf,
    client_report_path: PathBuf,
    stop_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct HolderReadyReport {
    role: String,
    nonce: String,
    network_namespace: String,
    process_identity: ProcessIdentity,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReadyReport {
    role: String,
    nonce: String,
    network_namespace: String,
    interface: String,
    ifindex: u32,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProcessReport {
    role: String,
    nonce: String,
    network_namespace: String,
    flows: Vec<FlowReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FlowReport {
    id: String,
    family: String,
    transport: String,
    semantic: String,
    nonce: String,
    local: SocketAddr,
    remote: SocketAddr,
    request_hex: String,
    response_hex: String,
    dns: Option<DnsReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DnsReport {
    transaction_id: u16,
    question_name: String,
    question_type: u16,
    question_digest: String,
    answer: IpAddr,
}

#[derive(Debug, Serialize)]
struct JournalRecord<'a> {
    recorded_at_unix_nanos: u128,
    process_id: u32,
    owner_nonce: &'a str,
    stage: &'a str,
    action: &'a [String],
    inverse: &'a [String],
    target_process: Option<ProcessIdentity>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    start_ticks: u64,
}

fn parse_published_process_identity(record: &str) -> Result<ProcessIdentity, String> {
    let record = record
        .strip_suffix('\n')
        .ok_or_else(|| "published process identity lacks canonical LF framing".to_owned())?;
    let (pid, start_ticks) = record
        .split_once(':')
        .ok_or_else(|| "published process identity lacks delimiter".to_owned())?;
    if pid.is_empty()
        || start_ticks.is_empty()
        || (pid.len() > 1 && pid.starts_with('0'))
        || (start_ticks.len() > 1 && start_ticks.starts_with('0'))
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || !start_ticks.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("published process identity is not canonical decimal".to_owned());
    }
    let pid = pid
        .parse::<u32>()
        .map_err(|_| "published process PID exceeds u32".to_owned())?;
    let start_ticks = start_ticks
        .parse::<u64>()
        .map_err(|_| "published process start ticks exceed u64".to_owned())?;
    if pid == 0 || start_ticks == 0 {
        return Err("published process identity values must be nonzero".to_owned());
    }
    Ok(ProcessIdentity { pid, start_ticks })
}

fn combine_checkpoint_and_cleanup<T>(
    checkpoint: Result<T, String>,
    cleanup: Result<(), String>,
) -> Result<T, String> {
    match (checkpoint, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(format!("cleanup failed: {cleanup_error}")),
        (Err(error), Err(cleanup_error)) => {
            Err(format!("{error}; cleanup also failed: {cleanup_error}"))
        }
    }
}

struct Journal {
    path: PathBuf,
    owner_nonce: String,
    record_count: Cell<usize>,
}

impl Journal {
    fn create(path: PathBuf, owner_nonce: String) -> Result<Self, String> {
        File::create(&path)
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("create journal {}: {error}", path.display()))?;
        let parent = path
            .parent()
            .ok_or_else(|| format!("journal path {} has no parent", path.display()))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync journal directory {}: {error}", parent.display()))?;
        Ok(Self {
            path,
            owner_nonce,
            record_count: Cell::new(0),
        })
    }

    fn record(&self, stage: &str, action: &[String], inverse: &[String]) -> Result<(), String> {
        self.record_internal(stage, action, inverse, None)
    }

    fn record_for_process(
        &self,
        stage: &str,
        action: &[String],
        inverse: &[String],
        target_process: ProcessIdentity,
    ) -> Result<(), String> {
        self.record_internal(stage, action, inverse, Some(target_process))
    }

    fn record_internal(
        &self,
        stage: &str,
        action: &[String],
        inverse: &[String],
        target_process: Option<ProcessIdentity>,
    ) -> Result<(), String> {
        let recorded_at_unix_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("read wall clock for journal: {error}"))?
            .as_nanos();
        let record = JournalRecord {
            recorded_at_unix_nanos,
            process_id: std::process::id(),
            owner_nonce: &self.owner_nonce,
            stage,
            action,
            inverse,
            target_process,
        };
        let mut encoded = serde_json::to_vec(&record)
            .map_err(|error| format!("encode journal record: {error}"))?;
        encoded.push(b'\n');
        let record_count = self.record_count.get();
        if record_count >= MAX_JOURNAL_RECORDS {
            return Err(format!(
                "journal {} exceeds {MAX_JOURNAL_RECORDS} records",
                self.path.display()
            ));
        }
        let current_size = fs::metadata(&self.path)
            .map_err(|error| format!("stat journal {}: {error}", self.path.display()))?
            .len();
        let encoded_size = u64::try_from(encoded.len())
            .map_err(|_| "journal record length does not fit u64".to_owned())?;
        if current_size.saturating_add(encoded_size) > MAX_JOURNAL_BYTES {
            return Err(format!(
                "journal {} would exceed {MAX_JOURNAL_BYTES} bytes",
                self.path.display()
            ));
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|error| format!("append journal {}: {error}", self.path.display()))?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("sync journal {}: {error}", self.path.display()))?;
        self.record_count.set(record_count + 1);
        Ok(())
    }
}

struct IsolatedResources {
    journal: Journal,
    config: HarnessConfig,
    keeper: Option<Child>,
    keeper_identity: Option<ProcessIdentity>,
    peer_server: Option<Child>,
    peer_server_identity: Option<ProcessIdentity>,
    link_created: bool,
    keeper_log_path: PathBuf,
    peer_server_log_path: PathBuf,
}

fn run_isolated() -> Result<(), String> {
    ensure_isolated_authority()?;
    let directory =
        tempfile::tempdir().map_err(|error| format!("create harness directory: {error}"))?;
    let nonce = random_nonce()?;
    let suffix = &nonce[..8];
    let config = HarnessConfig {
        nonce: nonce.clone(),
        daemon_network_namespace: network_namespace_identity()?,
        daemon_interface: format!("fx{suffix}d"),
        peer_interface: format!("fx{suffix}p"),
        daemon_ipv4: Ipv4Addr::new(11, 23, 42, 1),
        peer_ipv4: Ipv4Addr::new(11, 23, 42, 2),
        daemon_ipv6: "2606:4700:fffe:ffff::1"
            .parse()
            .map_err(|error| format!("parse daemon IPv6 address: {error}"))?,
        peer_ipv6: "2606:4700:fffe:ffff::2"
            .parse()
            .map_err(|error| format!("parse peer IPv6 address: {error}"))?,
        tcp_port: 41_001,
        udp_port: 41_002,
        dns_port: 41_053,
        journal_path: directory.path().join("mutations.jsonl"),
        holder_ready_path: directory.path().join("holder-ready.json"),
        ready_path: directory.path().join("peer-ready.json"),
        peer_report_path: directory.path().join("peer-report.json"),
        client_report_path: directory.path().join("client-report.json"),
        stop_path: directory.path().join("peer-stop"),
    };
    write_json_synced(&directory.path().join("config.json"), &config)?;
    let journal = Journal::create(config.journal_path.clone(), nonce)?;
    let keeper_log_path = directory.path().join("keeper.log");
    let peer_server_log_path = directory.path().join("peer-server.log");
    let mut resources = IsolatedResources {
        journal,
        config,
        keeper: None,
        keeper_identity: None,
        peer_server: None,
        peer_server_identity: None,
        link_created: false,
        keeper_log_path,
        peer_server_log_path,
    };

    let execution = panic::catch_unwind(AssertUnwindSafe(|| {
        execute_isolated(&mut resources, &directory.path().join("config.json"))
    }))
    .unwrap_or_else(|payload| {
        Err(format!(
            "isolated execution panicked: {}",
            panic_message(payload)
        ))
    });
    let cleanup = cleanup_isolated(&mut resources);
    match (execution, cleanup) {
        (Ok(()), Ok(())) => validate_complete_journal(&resources),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(format!("cleanup failed: {cleanup_error}")),
        (Err(error), Err(cleanup_error)) => {
            Err(format!("{error}; cleanup also failed: {cleanup_error}"))
        }
    }
}

fn execute_isolated(resources: &mut IsolatedResources, config_path: &Path) -> Result<(), String> {
    let executable =
        env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    let spawn_action = command_words(
        "unshare",
        [
            OsString::from("--net"),
            OsString::from("--"),
            executable.as_os_str().to_owned(),
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from(TEST_NAME),
            OsString::from("--nocapture"),
            OsString::from("--test-threads=1"),
        ],
    );
    resources.journal.record(
        "before-keeper-spawn",
        &spawn_action,
        &["terminate-and-reap-keeper-child-by-owned-process-group".to_owned()],
    )?;
    let keeper_log = File::create(&resources.keeper_log_path).map_err(|error| {
        format!(
            "create keeper log {}: {error}",
            resources.keeper_log_path.display()
        )
    })?;
    let keeper_stderr = keeper_log
        .try_clone()
        .map_err(|error| format!("clone keeper log handle: {error}"))?;
    let mut keeper_command = Command::new("unshare");
    keeper_command
        .args(["--net", "--"])
        .arg(&executable)
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, MODE_HOLDER)
        .env(CONFIG_ENV, config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(keeper_log))
        .stderr(Stdio::from(keeper_stderr))
        .process_group(0);
    arm_parent_death_signal(&mut keeper_command)?;
    let mut keeper = keeper_command
        .spawn()
        .map_err(|error| format!("spawn peer namespace holder: {error}"))?;
    let keeper_identity = capture_spawned_identity(&mut keeper, "keeper")?;
    resources.keeper_identity = Some(keeper_identity);
    resources.keeper = Some(keeper);

    wait_for_path_and_child(
        &resources.config.holder_ready_path,
        resources
            .keeper
            .as_mut()
            .ok_or_else(|| "keeper child was not stored".to_owned())?,
        IO_TIMEOUT,
        &resources.keeper_log_path,
    )?;
    let holder_ready: HolderReadyReport = read_json(&resources.config.holder_ready_path)?;
    validate_holder_ready(&resources.config, keeper_identity, &holder_ready)?;

    let add_link = vec![
        "link".to_owned(),
        "add".to_owned(),
        resources.config.daemon_interface.clone(),
        "type".to_owned(),
        "veth".to_owned(),
        "peer".to_owned(),
        "name".to_owned(),
        resources.config.peer_interface.clone(),
    ];
    let delete_link = vec![
        "link".to_owned(),
        "delete".to_owned(),
        "dev".to_owned(),
        resources.config.daemon_interface.clone(),
    ];
    resources.journal.record(
        "before-veth-create",
        &prefixed_words("ip", &add_link),
        &prefixed_words("ip", &delete_link),
    )?;
    // The command may mutate the kernel before a timeout or observation error is returned, so
    // cleanup ownership begins immediately after the durable pre-mutation record.
    resources.link_created = true;
    let mut add_link_command = Command::new("ip");
    add_link_command.args(&add_link);
    checked_command(add_link_command, COMMAND_TIMEOUT)?;

    let move_peer = vec![
        "link".to_owned(),
        "set".to_owned(),
        resources.config.peer_interface.clone(),
        "netns".to_owned(),
        keeper_identity.pid.to_string(),
    ];
    let move_back = vec![
        "nsenter".to_owned(),
        "-t".to_owned(),
        keeper_identity.pid.to_string(),
        "-n".to_owned(),
        "ip".to_owned(),
        "link".to_owned(),
        "set".to_owned(),
        resources.config.peer_interface.clone(),
        "netns".to_owned(),
        std::process::id().to_string(),
    ];
    verify_process_identity(keeper_identity)?;
    resources.journal.record_for_process(
        "before-veth-move",
        &prefixed_words("ip", &move_peer),
        &move_back,
        keeper_identity,
    )?;
    verify_process_identity(keeper_identity)?;
    let mut move_command = Command::new("ip");
    move_command.args(&move_peer);
    checked_command(move_command, COMMAND_TIMEOUT)?;

    configure_daemon_link(&resources.journal, &resources.config)?;
    configure_peer_link_nsenter(&resources.journal, &resources.config, keeper_identity)?;

    verify_process_identity(keeper_identity)?;
    let server_action = command_words(
        "nsenter",
        [
            OsString::from("-t"),
            OsString::from(keeper_identity.pid.to_string()),
            OsString::from("-n"),
            OsString::from("--"),
            executable.as_os_str().to_owned(),
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from(TEST_NAME),
            OsString::from("--nocapture"),
            OsString::from("--test-threads=1"),
        ],
    );
    resources.journal.record_for_process(
        "before-peer-server-spawn",
        &server_action,
        &["terminate-and-reap-peer-server-by-owned-process-group".to_owned()],
        keeper_identity,
    )?;
    verify_process_identity(keeper_identity)?;
    let server_log = File::create(&resources.peer_server_log_path).map_err(|error| {
        format!(
            "create peer server log {}: {error}",
            resources.peer_server_log_path.display()
        )
    })?;
    let server_stderr = server_log
        .try_clone()
        .map_err(|error| format!("clone peer server log handle: {error}"))?;
    let mut server_command = Command::new("nsenter");
    server_command
        .args(["-t", &keeper_identity.pid.to_string(), "-n", "--"])
        .arg(&executable)
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, MODE_PEER)
        .env(CONFIG_ENV, config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(server_log))
        .stderr(Stdio::from(server_stderr))
        .process_group(0);
    arm_parent_death_signal(&mut server_command)?;
    verify_process_identity(keeper_identity)?;
    let mut server = server_command
        .spawn()
        .map_err(|error| format!("spawn peer server in isolated namespace: {error}"))?;
    let server_identity = capture_spawned_identity(&mut server, "peer server")?;
    resources.peer_server_identity = Some(server_identity);
    resources.peer_server = Some(server);

    wait_for_path_and_child(
        &resources.config.ready_path,
        resources
            .peer_server
            .as_mut()
            .ok_or_else(|| "peer server child was not stored".to_owned())?,
        IO_TIMEOUT,
        &resources.peer_server_log_path,
    )?;
    let ready: ReadyReport = read_json(&resources.config.ready_path)?;
    validate_ready_report(&resources.config, &ready, &holder_ready.network_namespace)?;

    run_client_reexec(&resources.journal, config_path)?;
    wait_for_path_and_child(
        &resources.config.peer_report_path,
        resources
            .peer_server
            .as_mut()
            .ok_or_else(|| "peer server child was not stored".to_owned())?,
        IO_TIMEOUT,
        &resources.peer_server_log_path,
    )?;
    resources.journal.record_for_process(
        "before-peer-server-reap",
        &[
            "wait-and-reap-peer-server".to_owned(),
            server_identity.pid.to_string(),
        ],
        &["no-inverse-process-completed".to_owned()],
        server_identity,
    )?;
    let status = wait_child(
        resources
            .peer_server
            .as_mut()
            .ok_or_else(|| "peer server child was not stored".to_owned())?,
        IO_TIMEOUT,
    )?;
    if !status.success() {
        return Err(format!(
            "peer server exited with {status}: {}",
            read_diagnostic(&resources.peer_server_log_path)
        ));
    }
    resources.peer_server = None;
    let client: ProcessReport = read_json(&resources.config.client_report_path)?;
    let peer: ProcessReport = read_json(&resources.config.peer_report_path)?;
    validate_reports(
        &resources.config,
        &client,
        &peer,
        &holder_ready.network_namespace,
    )?;
    Ok(())
}

fn configure_daemon_link(journal: &Journal, config: &HarnessConfig) -> Result<(), String> {
    let ipv4 = vec![
        "address".to_owned(),
        "add".to_owned(),
        format!("{}/30", config.daemon_ipv4),
        "dev".to_owned(),
        config.daemon_interface.clone(),
    ];
    let ipv4_inverse = vec![
        "address".to_owned(),
        "delete".to_owned(),
        format!("{}/30", config.daemon_ipv4),
        "dev".to_owned(),
        config.daemon_interface.clone(),
    ];
    journaled_ip(journal, "before-daemon-ipv4", &ipv4, &ipv4_inverse)?;

    let ipv6 = vec![
        "-6".to_owned(),
        "address".to_owned(),
        "add".to_owned(),
        format!("{}/126", config.daemon_ipv6),
        "dev".to_owned(),
        config.daemon_interface.clone(),
        "nodad".to_owned(),
    ];
    let ipv6_inverse = vec![
        "-6".to_owned(),
        "address".to_owned(),
        "delete".to_owned(),
        format!("{}/126", config.daemon_ipv6),
        "dev".to_owned(),
        config.daemon_interface.clone(),
    ];
    journaled_ip(journal, "before-daemon-ipv6", &ipv6, &ipv6_inverse)?;

    let up = vec![
        "link".to_owned(),
        "set".to_owned(),
        "dev".to_owned(),
        config.daemon_interface.clone(),
        "up".to_owned(),
    ];
    let down = vec![
        "link".to_owned(),
        "set".to_owned(),
        "dev".to_owned(),
        config.daemon_interface.clone(),
        "down".to_owned(),
    ];
    journaled_ip(journal, "before-daemon-link-up", &up, &down).map(|_| ())
}

fn run_client_reexec(journal: &Journal, config_path: &Path) -> Result<(), String> {
    let executable =
        env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    let action = command_words(
        executable.as_os_str(),
        [
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from(TEST_NAME),
            OsString::from("--nocapture"),
            OsString::from("--test-threads=1"),
        ],
    );
    journal.record(
        "before-client-spawn",
        &action,
        &["terminate-and-reap-client-child-by-owned-process-group".to_owned()],
    )?;
    let mut command = Command::new(executable);
    command
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, MODE_CLIENT)
        .env(CONFIG_ENV, config_path);
    checked_command(command, PROCESS_TIMEOUT).map(|_| ())
}

fn cleanup_isolated(resources: &mut IsolatedResources) -> Result<(), String> {
    let mut failures = Vec::new();

    if let Some(mut server) = resources.peer_server.take() {
        if let Some(identity) = resources.peer_server_identity {
            let action = vec![
                "terminate-and-reap-peer-server".to_owned(),
                identity.pid.to_string(),
            ];
            if let Err(error) = resources.journal.record_for_process(
                "before-peer-server-cleanup",
                &action,
                &["no-inverse-owned-process-cleanup".to_owned()],
                identity,
            ) {
                failures.push(error);
            }
            if let Err(error) = terminate_and_reap_owned(&mut server, identity, IO_TIMEOUT) {
                failures.push(format!("clean up peer server: {error}"));
            }
        } else {
            failures
                .push("peer-server child existed without a captured process identity".to_owned());
            if let Err(error) = kill_live_child_group(&mut server) {
                failures.push(format!("kill unidentified peer-server child: {error}"));
            }
            if let Err(error) = wait_child(&mut server, IO_TIMEOUT) {
                failures.push(format!("reap unidentified peer-server child: {error}"));
            }
        }
    }

    if resources.link_created {
        let action = vec![
            "ip".to_owned(),
            "link".to_owned(),
            "delete".to_owned(),
            "dev".to_owned(),
            resources.config.daemon_interface.clone(),
        ];
        if let Err(error) = resources.journal.record(
            "before-veth-cleanup",
            &action,
            &["no-inverse-cleanup-is-terminal".to_owned()],
        ) {
            failures.push(error);
        }
        if let Err(error) = delete_interface_if_present(&resources.config.daemon_interface) {
            failures.push(format!("delete daemon veth: {error}"));
        }
        resources.link_created = false;
    }

    if let Err(error) = assert_interface_absent(None, &resources.config.daemon_interface) {
        failures.push(error);
    }
    if let Some(keeper) = resources.keeper_identity
        && let Err(error) = assert_interface_absent(Some(keeper), &resources.config.peer_interface)
    {
        failures.push(error);
    }

    if let Some(mut keeper_child) = resources.keeper.take() {
        if let Some(keeper) = resources.keeper_identity {
            let stop_action = vec![
                "create-stop-token".to_owned(),
                resources.config.stop_path.display().to_string(),
            ];
            if let Err(error) = resources.journal.record_for_process(
                "before-keeper-stop",
                &stop_action,
                &["remove-stop-token".to_owned()],
                keeper,
            ) {
                failures.push(error);
            }
            if let Err(error) = write_synced(&resources.config.stop_path, b"stop\n") {
                failures.push(error);
            }
            let reap_action = vec!["wait-and-reap-keeper".to_owned(), keeper.pid.to_string()];
            if let Err(error) = resources.journal.record_for_process(
                "before-keeper-reap",
                &reap_action,
                &["no-inverse-process-completed".to_owned()],
                keeper,
            ) {
                failures.push(error);
            }
            match wait_child(&mut keeper_child, IO_TIMEOUT) {
                Ok(status) if status.success() => {}
                Ok(status) => failures.push(format!(
                    "peer namespace keeper exited with {status}: {}",
                    read_diagnostic(&resources.keeper_log_path)
                )),
                Err(error) => {
                    let kill_action =
                        vec!["kill-owned-keeper-group".to_owned(), keeper.pid.to_string()];
                    if let Err(journal_error) = resources.journal.record_for_process(
                        "before-keeper-kill",
                        &kill_action,
                        &["reap-owned-keeper".to_owned()],
                        keeper,
                    ) {
                        failures.push(journal_error);
                    }
                    let kill_error = kill_owned_process_group(keeper).err();
                    let fallback_kill_error = if kill_error.is_some() {
                        kill_live_child_group(&mut keeper_child).err()
                    } else {
                        None
                    };
                    let reap_error = wait_child(&mut keeper_child, IO_TIMEOUT).err();
                    failures.push(format!(
                        "{error}; kill_error={kill_error:?}; fallback_kill_error={fallback_kill_error:?}; reap_error={reap_error:?}"
                    ));
                }
            }
        } else {
            failures.push("keeper child existed without a captured process identity".to_owned());
            if let Err(error) = kill_live_child_group(&mut keeper_child) {
                failures.push(format!("kill unidentified keeper child: {error}"));
            }
            if let Err(error) = wait_child(&mut keeper_child, IO_TIMEOUT) {
                failures.push(format!("reap unidentified keeper child: {error}"));
            }
        }
    }

    if let Some(keeper) = resources.keeper_identity {
        match owned_process_remains(keeper) {
            Ok(true) => failures.push(format!(
                "keeper process {} with start_ticks={} remains after reap",
                keeper.pid, keeper.start_ticks
            )),
            Ok(false) => {}
            Err(error) => failures.push(error),
        }
    }
    if let Err(error) =
        validate_journal_integrity(&resources.config.journal_path, &resources.config.nonce)
    {
        failures.push(error);
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn run_holder() -> Result<(), String> {
    let config = config_from_environment()?;
    let ready = HolderReadyReport {
        role: "holder".to_owned(),
        nonce: config.nonce.clone(),
        network_namespace: network_namespace_identity()?,
        process_identity: capture_process_identity(std::process::id())?,
    };
    if ready.network_namespace == config.daemon_network_namespace {
        return Err("namespace holder did not enter a distinct network namespace".to_owned());
    }
    write_json_synced(&config.holder_ready_path, &ready)?;
    wait_for_stop(&config.stop_path, PROCESS_TIMEOUT)
}

fn run_peer() -> Result<(), String> {
    let config = config_from_environment()?;
    let mut servers = bind_peer_servers(&config)?;
    let ready = ReadyReport {
        role: "peer".to_owned(),
        nonce: config.nonce.clone(),
        network_namespace: network_namespace_identity()?,
        interface: config.peer_interface.clone(),
        ifindex: interface_index(&config.peer_interface)?,
        ipv4: config.peer_ipv4,
        ipv6: config.peer_ipv6,
    };
    write_json_synced(&config.ready_path, &ready)?;

    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let mut flows = Vec::with_capacity(servers.len());
    for server in &mut servers {
        flows.push(server.serve(&config, deadline)?);
    }
    let report = ProcessReport {
        role: "peer".to_owned(),
        nonce: config.nonce.clone(),
        network_namespace: network_namespace_identity()?,
        flows,
    };
    write_json_synced(&config.peer_report_path, &report)
}

fn run_client() -> Result<(), String> {
    let config = config_from_environment()?;
    let mut flows = Vec::new();
    for spec in flow_specs(&config) {
        flows.push(run_client_flow(&config, &spec)?);
    }
    let report = ProcessReport {
        role: "client".to_owned(),
        nonce: config.nonce.clone(),
        network_namespace: network_namespace_identity()?,
        flows,
    };
    write_json_synced(&config.client_report_path, &report)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    const fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowTransport {
    Tcp,
    Udp,
}

impl FlowTransport {
    const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowSemantic {
    Echo,
    Dns,
}

impl FlowSemantic {
    const fn label(self) -> &'static str {
        match self {
            Self::Echo => "echo",
            Self::Dns => "dns",
        }
    }
}

#[derive(Debug, Clone)]
struct FlowSpec {
    id: String,
    family: AddressFamily,
    transport: FlowTransport,
    semantic: FlowSemantic,
    peer: SocketAddr,
}

impl FlowSpec {
    fn request(&self, config: &HarnessConfig) -> Result<Vec<u8>, String> {
        match self.semantic {
            FlowSemantic::Echo => {
                Ok(format!("flux-canary-v1|{}|{}", config.nonce, self.id).into_bytes())
            }
            FlowSemantic::Dns => build_dns_query(&dns_expectation(config, self)),
        }
    }

    fn response(&self, config: &HarnessConfig, request: &[u8]) -> Result<Vec<u8>, String> {
        match self.semantic {
            FlowSemantic::Echo => {
                Ok(format!("flux-canary-ack-v1|{}|{}", config.nonce, self.id).into_bytes())
            }
            FlowSemantic::Dns => build_dns_response(request, &dns_expectation(config, self)),
        }
    }

    fn dns(&self, config: &HarnessConfig) -> Option<DnsReport> {
        (self.semantic == FlowSemantic::Dns).then(|| dns_expectation(config, self))
    }
}

fn flow_specs(config: &HarnessConfig) -> Vec<FlowSpec> {
    let mut flows = Vec::with_capacity(8);
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        let peer_ip = match family {
            AddressFamily::Ipv4 => IpAddr::V4(config.peer_ipv4),
            AddressFamily::Ipv6 => IpAddr::V6(config.peer_ipv6),
        };
        for (transport, semantic, port, suffix) in [
            (
                FlowTransport::Tcp,
                FlowSemantic::Echo,
                config.tcp_port,
                "tcp",
            ),
            (
                FlowTransport::Udp,
                FlowSemantic::Echo,
                config.udp_port,
                "udp",
            ),
            (
                FlowTransport::Udp,
                FlowSemantic::Dns,
                config.dns_port,
                "dns-udp",
            ),
            (
                FlowTransport::Tcp,
                FlowSemantic::Dns,
                config.dns_port,
                "dns-tcp",
            ),
        ] {
            flows.push(FlowSpec {
                id: format!("{}-{suffix}", family.label()),
                family,
                transport,
                semantic,
                peer: SocketAddr::new(peer_ip, port),
            });
        }
    }
    flows
}

enum BoundPeerServer {
    Tcp {
        spec: FlowSpec,
        listener: TcpListener,
    },
    Udp {
        spec: FlowSpec,
        socket: UdpSocket,
    },
}

impl BoundPeerServer {
    fn serve(&mut self, config: &HarnessConfig, deadline: Instant) -> Result<FlowReport, String> {
        match self {
            Self::Tcp { spec, listener } => serve_peer_tcp(config, spec, listener, deadline),
            Self::Udp { spec, socket } => serve_peer_udp(config, spec, socket, deadline),
        }
    }
}

fn bind_peer_servers(config: &HarnessConfig) -> Result<Vec<BoundPeerServer>, String> {
    flow_specs(config)
        .into_iter()
        .map(|spec| match spec.transport {
            FlowTransport::Tcp => {
                let listener = TcpListener::bind(spec.peer).map_err(|error| {
                    format!("bind peer TCP flow {} at {}: {error}", spec.id, spec.peer)
                })?;
                listener.set_nonblocking(true).map_err(|error| {
                    format!("make peer TCP flow {} nonblocking: {error}", spec.id)
                })?;
                Ok(BoundPeerServer::Tcp { spec, listener })
            }
            FlowTransport::Udp => {
                let socket = UdpSocket::bind(spec.peer).map_err(|error| {
                    format!("bind peer UDP flow {} at {}: {error}", spec.id, spec.peer)
                })?;
                socket
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(|error| format!("set peer UDP timeout for {}: {error}", spec.id))?;
                Ok(BoundPeerServer::Udp { spec, socket })
            }
        })
        .collect()
}

fn serve_peer_tcp(
    config: &HarnessConfig,
    spec: &FlowSpec,
    listener: &TcpListener,
    deadline: Instant,
) -> Result<FlowReport, String> {
    let (mut stream, remote) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "peer TCP flow {} timed out waiting for a connection",
                        spec.id
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(format!("accept peer TCP flow {}: {error}", spec.id)),
        }
    };
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|error| format!("set peer TCP timeouts for {}: {error}", spec.id))?;
    let request = if spec.semantic == FlowSemantic::Dns {
        read_u16_frame(&mut stream)?
    } else {
        read_u32_frame(&mut stream)?
    };
    let expected = spec.request(config)?;
    if request != expected {
        return Err(format!(
            "peer TCP flow {} received unexpected request: expected={} actual={}",
            spec.id,
            hex_encode(&expected),
            hex_encode(&request)
        ));
    }
    let response = spec.response(config, &request)?;
    if spec.semantic == FlowSemantic::Dns {
        write_u16_frame(&mut stream, &response)?;
    } else {
        write_u32_frame(&mut stream, &response)?;
    }
    let local = stream
        .local_addr()
        .map_err(|error| format!("read peer TCP local tuple for {}: {error}", spec.id))?;
    flow_report(spec, config, local, remote, request, response)
}

fn serve_peer_udp(
    config: &HarnessConfig,
    spec: &FlowSpec,
    socket: &UdpSocket,
    _deadline: Instant,
) -> Result<FlowReport, String> {
    let mut buffer = [0_u8; 4096];
    let (length, remote) = socket
        .recv_from(&mut buffer)
        .map_err(|error| format!("receive peer UDP flow {}: {error}", spec.id))?;
    let request = buffer[..length].to_vec();
    let expected = spec.request(config)?;
    if request != expected {
        return Err(format!(
            "peer UDP flow {} received unexpected request: expected={} actual={}",
            spec.id,
            hex_encode(&expected),
            hex_encode(&request)
        ));
    }
    let response = spec.response(config, &request)?;
    let sent = socket
        .send_to(&response, remote)
        .map_err(|error| format!("send peer UDP flow {} response: {error}", spec.id))?;
    if sent != response.len() {
        return Err(format!(
            "peer UDP flow {} sent {sent} of {} response bytes",
            spec.id,
            response.len()
        ));
    }
    let local = socket
        .local_addr()
        .map_err(|error| format!("read peer UDP local tuple for {}: {error}", spec.id))?;
    flow_report(spec, config, local, remote, request, response)
}

fn run_client_flow(config: &HarnessConfig, spec: &FlowSpec) -> Result<FlowReport, String> {
    match spec.transport {
        FlowTransport::Tcp => run_client_tcp(config, spec),
        FlowTransport::Udp => run_client_udp(config, spec),
    }
}

fn run_client_tcp(config: &HarnessConfig, spec: &FlowSpec) -> Result<FlowReport, String> {
    let mut stream = TcpStream::connect_timeout(&spec.peer, IO_TIMEOUT).map_err(|error| {
        format!(
            "connect client TCP flow {} to {}: {error}",
            spec.id, spec.peer
        )
    })?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|error| format!("set client TCP timeouts for {}: {error}", spec.id))?;
    let request = spec.request(config)?;
    if spec.semantic == FlowSemantic::Dns {
        write_u16_frame(&mut stream, &request)?;
    } else {
        write_u32_frame(&mut stream, &request)?;
    }
    let response = if spec.semantic == FlowSemantic::Dns {
        read_u16_frame(&mut stream)?
    } else {
        read_u32_frame(&mut stream)?
    };
    validate_response(spec, config, &request, &response)?;
    let local = stream
        .local_addr()
        .map_err(|error| format!("read client TCP local tuple for {}: {error}", spec.id))?;
    let remote = stream
        .peer_addr()
        .map_err(|error| format!("read client TCP peer tuple for {}: {error}", spec.id))?;
    flow_report(spec, config, local, remote, request, response)
}

fn run_client_udp(config: &HarnessConfig, spec: &FlowSpec) -> Result<FlowReport, String> {
    let daemon_ip = match spec.family {
        AddressFamily::Ipv4 => IpAddr::V4(config.daemon_ipv4),
        AddressFamily::Ipv6 => IpAddr::V6(config.daemon_ipv6),
    };
    let socket = UdpSocket::bind(SocketAddr::new(daemon_ip, 0))
        .map_err(|error| format!("bind client UDP flow {}: {error}", spec.id))?;
    socket.connect(spec.peer).map_err(|error| {
        format!(
            "connect client UDP flow {} to {}: {error}",
            spec.id, spec.peer
        )
    })?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| socket.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|error| format!("set client UDP timeouts for {}: {error}", spec.id))?;
    let request = spec.request(config)?;
    let sent = socket
        .send(&request)
        .map_err(|error| format!("send client UDP flow {}: {error}", spec.id))?;
    if sent != request.len() {
        return Err(format!(
            "client UDP flow {} sent {sent} of {} request bytes",
            spec.id,
            request.len()
        ));
    }
    let mut buffer = [0_u8; 4096];
    let length = socket
        .recv(&mut buffer)
        .map_err(|error| format!("receive client UDP flow {}: {error}", spec.id))?;
    let response = buffer[..length].to_vec();
    validate_response(spec, config, &request, &response)?;
    let local = socket
        .local_addr()
        .map_err(|error| format!("read client UDP local tuple for {}: {error}", spec.id))?;
    let remote = socket
        .peer_addr()
        .map_err(|error| format!("read client UDP peer tuple for {}: {error}", spec.id))?;
    flow_report(spec, config, local, remote, request, response)
}

fn validate_response(
    spec: &FlowSpec,
    config: &HarnessConfig,
    request: &[u8],
    response: &[u8],
) -> Result<(), String> {
    let expected = spec.response(config, request)?;
    if response != expected {
        return Err(format!(
            "client flow {} received unexpected response: expected={} actual={}",
            spec.id,
            hex_encode(&expected),
            hex_encode(response)
        ));
    }
    if spec.semantic == FlowSemantic::Dns {
        let observed = parse_dns_response(response)?;
        let expected_dns = dns_expectation(config, spec);
        if observed != expected_dns {
            return Err(format!(
                "client DNS flow {} response mismatch: expected={expected_dns:?} observed={observed:?}",
                spec.id
            ));
        }
    }
    Ok(())
}

fn flow_report(
    spec: &FlowSpec,
    config: &HarnessConfig,
    local: SocketAddr,
    remote: SocketAddr,
    request: Vec<u8>,
    response: Vec<u8>,
) -> Result<FlowReport, String> {
    let dns = if spec.semantic == FlowSemantic::Dns {
        let observed = parse_dns_response(&response)?;
        let question = parse_dns_question(&request)?;
        if observed.transaction_id != question.transaction_id
            || observed.question_name != question.question_name
            || observed.question_type != question.question_type
            || observed.question_digest != question.question_digest
        {
            return Err(format!(
                "DNS flow {} request and response questions differ",
                spec.id
            ));
        }
        Some(observed)
    } else {
        None
    };
    Ok(FlowReport {
        id: spec.id.clone(),
        family: spec.family.label().to_owned(),
        transport: spec.transport.label().to_owned(),
        semantic: spec.semantic.label().to_owned(),
        nonce: config.nonce.clone(),
        local,
        remote,
        request_hex: hex_encode(&request),
        response_hex: hex_encode(&response),
        dns,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedDnsQuestion {
    transaction_id: u16,
    question_name: String,
    question_type: u16,
    question_digest: String,
    question_end: usize,
}

fn dns_expectation(config: &HarnessConfig, spec: &FlowSpec) -> DnsReport {
    let seed = Sha256::digest(format!("{}|{}", config.nonce, spec.id).as_bytes());
    let transaction_id = u16::from_be_bytes([seed[0], seed[1]]);
    let question_name = format!("n{}.{}.flux-canary.invalid", &config.nonce[..16], spec.id);
    let question_type = match spec.family {
        AddressFamily::Ipv4 => 1,
        AddressFamily::Ipv6 => 28,
    };
    let question = encode_dns_question(&question_name, question_type)
        .expect("generated DNS question must be encodable");
    let question_digest = sha256_hex(&question);
    let answer = match spec.family {
        AddressFamily::Ipv4 => IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1 + (seed[2] % 254))),
        AddressFamily::Ipv6 => IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0x0db8,
            u16::from_be_bytes([seed[2], seed[3]]),
            u16::from_be_bytes([seed[4], seed[5]]),
            u16::from_be_bytes([seed[6], seed[7]]),
            u16::from_be_bytes([seed[8], seed[9]]),
            u16::from_be_bytes([seed[10], seed[11]]),
            u16::from_be_bytes([seed[12], seed[13]]),
        )),
    };
    DnsReport {
        transaction_id,
        question_name,
        question_type,
        question_digest,
        answer,
    }
}

fn build_dns_query(expected: &DnsReport) -> Result<Vec<u8>, String> {
    let question = encode_dns_question(&expected.question_name, expected.question_type)?;
    let mut packet = Vec::with_capacity(12 + question.len());
    packet.extend_from_slice(&expected.transaction_id.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&question);
    Ok(packet)
}

fn build_dns_response(request: &[u8], expected: &DnsReport) -> Result<Vec<u8>, String> {
    let observed = parse_dns_question(request)?;
    if observed.transaction_id != expected.transaction_id
        || observed.question_name != expected.question_name
        || observed.question_type != expected.question_type
        || observed.question_digest != expected.question_digest
        || observed.question_end != request.len()
    {
        return Err(format!(
            "DNS query does not match expected transaction/question: expected={expected:?} observed={observed:?}"
        ));
    }
    let mut packet = Vec::with_capacity(request.len() + 32);
    packet.extend_from_slice(&expected.transaction_id.to_be_bytes());
    // Authoritative answer, echoing the client's RD bit without advertising recursion support.
    packet.extend_from_slice(&0x8500_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&request[12..observed.question_end]);
    packet.extend_from_slice(&0xc00c_u16.to_be_bytes());
    packet.extend_from_slice(&expected.question_type.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&5_u32.to_be_bytes());
    match expected.answer {
        IpAddr::V4(address) => {
            packet.extend_from_slice(&4_u16.to_be_bytes());
            packet.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            packet.extend_from_slice(&16_u16.to_be_bytes());
            packet.extend_from_slice(&address.octets());
        }
    }
    Ok(packet)
}

fn parse_dns_question(packet: &[u8]) -> Result<ParsedDnsQuestion, String> {
    if packet.len() < 12 {
        return Err(format!("DNS packet is only {} bytes", packet.len()));
    }
    let transaction_id = read_be_u16(packet, 0)?;
    let question_count = read_be_u16(packet, 4)?;
    if question_count != 1 {
        return Err(format!(
            "DNS packet contains {question_count} questions instead of one"
        ));
    }
    let mut offset = 12;
    let question_name = decode_dns_name(packet, &mut offset)?;
    let question_type = read_be_u16(packet, offset)?;
    offset += 2;
    let question_class = read_be_u16(packet, offset)?;
    offset += 2;
    if question_class != 1 {
        return Err(format!(
            "DNS question class is {question_class} instead of IN"
        ));
    }
    Ok(ParsedDnsQuestion {
        transaction_id,
        question_name,
        question_type,
        question_digest: sha256_hex(&packet[12..offset]),
        question_end: offset,
    })
}

fn parse_dns_response(packet: &[u8]) -> Result<DnsReport, String> {
    if packet.len() < 12 {
        return Err(format!("DNS response is only {} bytes", packet.len()));
    }
    let flags = read_be_u16(packet, 2)?;
    let answer_count = read_be_u16(packet, 6)?;
    if flags != 0x8500 || answer_count != 1 {
        return Err(format!(
            "DNS response flags/count are invalid: flags=0x{flags:04x} answers={answer_count}"
        ));
    }
    let question = parse_dns_question(packet)?;
    let mut offset = question.question_end;
    let answer_name = read_be_u16(packet, offset)?;
    offset += 2;
    if answer_name != 0xc00c {
        return Err(format!(
            "DNS answer name is 0x{answer_name:04x} instead of pointer 0xc00c"
        ));
    }
    let answer_type = read_be_u16(packet, offset)?;
    offset += 2;
    let answer_class = read_be_u16(packet, offset)?;
    offset += 2;
    let _ttl = read_be_u32(packet, offset)?;
    offset += 4;
    let answer_length = usize::from(read_be_u16(packet, offset)?);
    offset += 2;
    let answer_end = offset
        .checked_add(answer_length)
        .ok_or_else(|| "DNS answer length overflow".to_owned())?;
    let answer_bytes = packet
        .get(offset..answer_end)
        .ok_or_else(|| "DNS answer extends beyond the packet".to_owned())?;
    if answer_end != packet.len() || answer_type != question.question_type || answer_class != 1 {
        return Err(format!(
            "DNS answer metadata/trailing bytes are invalid: type={answer_type} class={answer_class} end={answer_end} len={}",
            packet.len()
        ));
    }
    let answer = match (answer_type, answer_bytes) {
        (1, [a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        (28, bytes) if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes
                .try_into()
                .map_err(|_| "copy IPv6 DNS answer bytes".to_owned())?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => {
            return Err(format!(
                "DNS answer type {answer_type} has unsupported length {answer_length}"
            ));
        }
    };
    Ok(DnsReport {
        transaction_id: question.transaction_id,
        question_name: question.question_name,
        question_type: question.question_type,
        question_digest: question.question_digest,
        answer,
    })
}

fn encode_dns_question(name: &str, question_type: u16) -> Result<Vec<u8>, String> {
    let mut encoded = Vec::with_capacity(name.len() + 6);
    for label in name.split('.') {
        let length = u8::try_from(label.len())
            .map_err(|_| format!("DNS label {label:?} exceeds 255 bytes"))?;
        if length == 0
            || length > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!("DNS label {label:?} is invalid"));
        }
        encoded.push(length);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded.extend_from_slice(&question_type.to_be_bytes());
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    Ok(encoded)
}

fn decode_dns_name(packet: &[u8], offset: &mut usize) -> Result<String, String> {
    let mut labels = Vec::new();
    loop {
        let length = usize::from(
            *packet
                .get(*offset)
                .ok_or_else(|| "DNS name extends beyond the packet".to_owned())?,
        );
        *offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            return Err(format!(
                "DNS label length {length} is invalid or compressed"
            ));
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| "DNS label length overflow".to_owned())?;
        let label = packet
            .get(*offset..end)
            .ok_or_else(|| "DNS label extends beyond the packet".to_owned())?;
        if !label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err("DNS label contains invalid bytes".to_owned());
        }
        labels.push(
            std::str::from_utf8(label)
                .map_err(|error| format!("decode DNS label: {error}"))?
                .to_owned(),
        );
        *offset = end;
    }
    Ok(labels.join("."))
}

fn read_be_u16(packet: &[u8], offset: usize) -> Result<u16, String> {
    let bytes: [u8; 2] = packet
        .get(offset..offset + 2)
        .ok_or_else(|| format!("read u16 beyond DNS packet at offset {offset}"))?
        .try_into()
        .map_err(|_| "copy DNS u16 bytes".to_owned())?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_be_u32(packet: &[u8], offset: usize) -> Result<u32, String> {
    let bytes: [u8; 4] = packet
        .get(offset..offset + 4)
        .ok_or_else(|| format!("read u32 beyond DNS packet at offset {offset}"))?
        .try_into()
        .map_err(|_| "copy DNS u32 bytes".to_owned())?;
    Ok(u32::from_be_bytes(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn write_u16_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    let length = u16::try_from(payload.len())
        .map_err(|_| format!("TCP DNS frame is too large: {} bytes", payload.len()))?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(payload))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("write TCP DNS frame: {error}"))
}

fn read_u16_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut length = [0_u8; 2];
    stream
        .read_exact(&mut length)
        .map_err(|error| format!("read TCP DNS frame length: {error}"))?;
    read_frame_payload(stream, usize::from(u16::from_be_bytes(length)), "TCP DNS")
}

fn write_u32_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    let length = u32::try_from(payload.len())
        .map_err(|_| format!("TCP echo frame is too large: {} bytes", payload.len()))?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(payload))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("write TCP echo frame: {error}"))
}

fn read_u32_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|error| format!("read TCP echo frame length: {error}"))?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| "TCP echo frame length does not fit usize".to_owned())?;
    read_frame_payload(stream, length, "TCP echo")
}

fn read_frame_payload(
    stream: &mut TcpStream,
    length: usize,
    description: &str,
) -> Result<Vec<u8>, String> {
    if length > 4096 {
        return Err(format!(
            "{description} frame length {length} exceeds 4096 bytes"
        ));
    }
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(|error| format!("read {description} frame payload: {error}"))?;
    Ok(payload)
}

fn configure_peer_link_nsenter(
    journal: &Journal,
    config: &HarnessConfig,
    keeper: ProcessIdentity,
) -> Result<(), String> {
    let lo_up = vec![
        "link".to_owned(),
        "set".to_owned(),
        "dev".to_owned(),
        "lo".to_owned(),
        "up".to_owned(),
    ];
    let lo_down = vec![
        "link".to_owned(),
        "set".to_owned(),
        "dev".to_owned(),
        "lo".to_owned(),
        "down".to_owned(),
    ];
    journaled_nsenter_ip(journal, "before-peer-loopback-up", &lo_up, &lo_down, keeper)?;

    let ipv4 = vec![
        "address".to_owned(),
        "add".to_owned(),
        format!("{}/30", config.peer_ipv4),
        "dev".to_owned(),
        config.peer_interface.clone(),
    ];
    let ipv4_inverse = vec![
        "address".to_owned(),
        "delete".to_owned(),
        format!("{}/30", config.peer_ipv4),
        "dev".to_owned(),
        config.peer_interface.clone(),
    ];
    journaled_nsenter_ip(journal, "before-peer-ipv4", &ipv4, &ipv4_inverse, keeper)?;

    let ipv6 = vec![
        "-6".to_owned(),
        "address".to_owned(),
        "add".to_owned(),
        format!("{}/126", config.peer_ipv6),
        "dev".to_owned(),
        config.peer_interface.clone(),
        "nodad".to_owned(),
    ];
    let ipv6_inverse = vec![
        "-6".to_owned(),
        "address".to_owned(),
        "delete".to_owned(),
        format!("{}/126", config.peer_ipv6),
        "dev".to_owned(),
        config.peer_interface.clone(),
    ];
    journaled_nsenter_ip(journal, "before-peer-ipv6", &ipv6, &ipv6_inverse, keeper)?;

    let up = vec![
        "link".to_owned(),
        "set".to_owned(),
        "dev".to_owned(),
        config.peer_interface.clone(),
        "up".to_owned(),
    ];
    let down = vec![
        "link".to_owned(),
        "set".to_owned(),
        "dev".to_owned(),
        config.peer_interface.clone(),
        "down".to_owned(),
    ];
    journaled_nsenter_ip(journal, "before-peer-link-up", &up, &down, keeper).map(|_| ())
}

fn wait_for_stop(path: &Path, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() >= deadline {
            return Err(format!(
                "peer stop token {} was not created within {timeout:?}",
                path.display()
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn validate_holder_ready(
    config: &HarnessConfig,
    expected_identity: ProcessIdentity,
    ready: &HolderReadyReport,
) -> Result<(), String> {
    if ready.role != "holder"
        || ready.nonce != config.nonce
        || ready.network_namespace == config.daemon_network_namespace
        || ready.process_identity != expected_identity
    {
        return Err(format!(
            "namespace-holder readiness does not match the owned child/facility: {ready:?}"
        ));
    }
    verify_process_identity(expected_identity)
}

fn validate_ready_report(
    config: &HarnessConfig,
    ready: &ReadyReport,
    expected_peer_namespace: &str,
) -> Result<(), String> {
    if ready.role != "peer"
        || ready.nonce != config.nonce
        || ready.interface != config.peer_interface
        || ready.ifindex == 0
        || ready.ipv4 != config.peer_ipv4
        || ready.ipv6 != config.peer_ipv6
        || ready.network_namespace != expected_peer_namespace
    {
        return Err(format!(
            "peer readiness report does not match facility: {ready:?}"
        ));
    }
    let daemon_namespace = network_namespace_identity()?;
    if ready.network_namespace == daemon_namespace {
        return Err("peer and daemon unexpectedly share one network namespace".to_owned());
    }
    Ok(())
}

fn validate_reports(
    config: &HarnessConfig,
    client: &ProcessReport,
    peer: &ProcessReport,
    expected_peer_namespace: &str,
) -> Result<(), String> {
    let daemon_namespace = network_namespace_identity()?;
    if client.role != "client"
        || peer.role != "peer"
        || client.nonce != config.nonce
        || peer.nonce != config.nonce
        || client.network_namespace != daemon_namespace
        || peer.network_namespace != expected_peer_namespace
    {
        return Err(format!(
            "process report identities do not match the isolated facility: client={client:?} peer={peer:?}"
        ));
    }

    let client_flows = indexed_flows("client", &client.flows)?;
    let peer_flows = indexed_flows("peer", &peer.flows)?;
    let specs = flow_specs(config);
    if client_flows.len() != specs.len() || peer_flows.len() != specs.len() {
        return Err(format!(
            "expected {} unique flow reports, found client={} peer={}",
            specs.len(),
            client_flows.len(),
            peer_flows.len()
        ));
    }

    for spec in specs {
        let client_flow = client_flows
            .get(&spec.id)
            .ok_or_else(|| format!("client omitted flow {}", spec.id))?;
        let peer_flow = peer_flows
            .get(&spec.id)
            .ok_or_else(|| format!("peer omitted flow {}", spec.id))?;
        for (role, flow) in [("client", client_flow), ("peer", peer_flow)] {
            if flow.family != spec.family.label()
                || flow.transport != spec.transport.label()
                || flow.semantic != spec.semantic.label()
                || flow.nonce != config.nonce
            {
                return Err(format!(
                    "{role} flow {} metadata mismatch: {flow:?}",
                    spec.id
                ));
            }
        }
        if client_flow.remote != spec.peer
            || peer_flow.local != spec.peer
            || client_flow.local != peer_flow.remote
            || client_flow.remote != peer_flow.local
        {
            return Err(format!(
                "flow {} tuple cross-check failed: client {} -> {}, peer {} <- {}",
                spec.id, client_flow.local, client_flow.remote, peer_flow.local, peer_flow.remote
            ));
        }
        let expected_daemon_ip = match spec.family {
            AddressFamily::Ipv4 => IpAddr::V4(config.daemon_ipv4),
            AddressFamily::Ipv6 => IpAddr::V6(config.daemon_ipv6),
        };
        if client_flow.local.ip() != expected_daemon_ip {
            return Err(format!(
                "flow {} used client source {} instead of {expected_daemon_ip}",
                spec.id,
                client_flow.local.ip()
            ));
        }
        if client_flow.request_hex != peer_flow.request_hex
            || client_flow.response_hex != peer_flow.response_hex
        {
            return Err(format!(
                "flow {} raw request/response cross-check failed",
                spec.id
            ));
        }
        let request = spec.request(config)?;
        let response = spec.response(config, &request)?;
        if client_flow.request_hex != hex_encode(&request)
            || client_flow.response_hex != hex_encode(&response)
        {
            return Err(format!("flow {} nonce-bearing payload mismatch", spec.id));
        }
        let expected_dns = spec.dns(config);
        if client_flow.dns != expected_dns || peer_flow.dns != expected_dns {
            return Err(format!(
                "flow {} DNS transaction/question/answer cross-check failed: client={:?} peer={:?} expected={expected_dns:?}",
                spec.id, client_flow.dns, peer_flow.dns
            ));
        }
    }
    Ok(())
}

fn indexed_flows<'a>(
    role: &str,
    flows: &'a [FlowReport],
) -> Result<BTreeMap<String, &'a FlowReport>, String> {
    let mut indexed = BTreeMap::new();
    for flow in flows {
        if indexed.insert(flow.id.clone(), flow).is_some() {
            return Err(format!("{role} reported flow {} more than once", flow.id));
        }
    }
    Ok(indexed)
}

#[derive(Debug, Deserialize)]
struct OwnedJournalRecord {
    recorded_at_unix_nanos: u128,
    process_id: u32,
    owner_nonce: String,
    stage: String,
    action: Vec<String>,
    inverse: Vec<String>,
    target_process: Option<ProcessIdentity>,
}

fn validate_journal(path: &Path, nonce: &str, required_stages: &[&str]) -> Result<(), String> {
    let records = read_journal(path)?;
    let mut observed_stages = BTreeSet::new();
    for (index, record) in records.into_iter().enumerate() {
        if record.process_id == 0
            || record.owner_nonce != nonce
            || record.action.is_empty()
            || record.inverse.is_empty()
        {
            return Err(format!(
                "journal {} contains an incomplete record at line {}: {record:?}",
                path.display(),
                index + 1
            ));
        }
        observed_stages.insert(record.stage);
    }
    for stage in required_stages {
        if !observed_stages.contains(*stage) {
            return Err(format!(
                "journal {} omitted required stage {stage}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_journal_integrity(path: &Path, nonce: &str) -> Result<(), String> {
    validate_journal(path, nonce, &[])
}

fn read_journal(path: &Path) -> Result<Vec<OwnedJournalRecord>, String> {
    let encoded = read_bounded(
        path,
        usize::try_from(MAX_JOURNAL_BYTES)
            .map_err(|_| "journal byte limit does not fit usize".to_owned())?,
    )?;
    let contents = std::str::from_utf8(&encoded)
        .map_err(|error| format!("journal {} is not UTF-8: {error}", path.display()))?;
    let records = contents
        .lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|error| {
                format!(
                    "decode journal {} line {}: {error}",
                    path.display(),
                    index + 1
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if records.len() > MAX_JOURNAL_RECORDS {
        return Err(format!(
            "journal {} contains {} records, above the {MAX_JOURNAL_RECORDS}-record limit",
            path.display(),
            records.len()
        ));
    }
    Ok(records)
}

#[derive(Debug)]
struct ExpectedJournalRecord {
    stage: &'static str,
    action: Vec<String>,
    inverse: Vec<String>,
    target_process: Option<ProcessIdentity>,
}

fn validate_complete_journal(resources: &IsolatedResources) -> Result<(), String> {
    let keeper = resources
        .keeper_identity
        .ok_or_else(|| "completed harness lacks keeper process identity".to_owned())?;
    let server = resources
        .peer_server_identity
        .ok_or_else(|| "completed harness lacks peer-server process identity".to_owned())?;
    let executable =
        env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    let ip = |arguments: Vec<String>| prefixed_words("ip", &arguments);
    let nsenter_ip = |arguments: Vec<String>| {
        [
            "nsenter".to_owned(),
            "-t".to_owned(),
            keeper.pid.to_string(),
            "-n".to_owned(),
            "--".to_owned(),
            "ip".to_owned(),
        ]
        .into_iter()
        .chain(arguments)
        .collect::<Vec<_>>()
    };
    let config = &resources.config;
    let daemon_ipv4 = format!("{}/30", config.daemon_ipv4);
    let peer_ipv4 = format!("{}/30", config.peer_ipv4);
    let daemon_ipv6 = format!("{}/126", config.daemon_ipv6);
    let peer_ipv6 = format!("{}/126", config.peer_ipv6);
    let holder_spawn = command_words(
        "unshare",
        [
            OsString::from("--net"),
            OsString::from("--"),
            executable.as_os_str().to_owned(),
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from(TEST_NAME),
            OsString::from("--nocapture"),
            OsString::from("--test-threads=1"),
        ],
    );
    let server_spawn = command_words(
        "nsenter",
        [
            OsString::from("-t"),
            OsString::from(keeper.pid.to_string()),
            OsString::from("-n"),
            OsString::from("--"),
            executable.as_os_str().to_owned(),
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from(TEST_NAME),
            OsString::from("--nocapture"),
            OsString::from("--test-threads=1"),
        ],
    );
    let client_spawn = command_words(
        executable.as_os_str(),
        [
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from(TEST_NAME),
            OsString::from("--nocapture"),
            OsString::from("--test-threads=1"),
        ],
    );
    let expected = vec![
        ExpectedJournalRecord {
            stage: "before-keeper-spawn",
            action: holder_spawn,
            inverse: vec!["terminate-and-reap-keeper-child-by-owned-process-group".to_owned()],
            target_process: None,
        },
        ExpectedJournalRecord {
            stage: "before-veth-create",
            action: ip(vec![
                "link".to_owned(),
                "add".to_owned(),
                config.daemon_interface.clone(),
                "type".to_owned(),
                "veth".to_owned(),
                "peer".to_owned(),
                "name".to_owned(),
                config.peer_interface.clone(),
            ]),
            inverse: ip(vec![
                "link".to_owned(),
                "delete".to_owned(),
                "dev".to_owned(),
                config.daemon_interface.clone(),
            ]),
            target_process: None,
        },
        ExpectedJournalRecord {
            stage: "before-veth-move",
            action: ip(vec![
                "link".to_owned(),
                "set".to_owned(),
                config.peer_interface.clone(),
                "netns".to_owned(),
                keeper.pid.to_string(),
            ]),
            inverse: vec![
                "nsenter".to_owned(),
                "-t".to_owned(),
                keeper.pid.to_string(),
                "-n".to_owned(),
                "ip".to_owned(),
                "link".to_owned(),
                "set".to_owned(),
                config.peer_interface.clone(),
                "netns".to_owned(),
                std::process::id().to_string(),
            ],
            target_process: Some(keeper),
        },
        ExpectedJournalRecord {
            stage: "before-daemon-ipv4",
            action: ip(vec![
                "address".to_owned(),
                "add".to_owned(),
                daemon_ipv4.clone(),
                "dev".to_owned(),
                config.daemon_interface.clone(),
            ]),
            inverse: ip(vec![
                "address".to_owned(),
                "delete".to_owned(),
                daemon_ipv4,
                "dev".to_owned(),
                config.daemon_interface.clone(),
            ]),
            target_process: None,
        },
        ExpectedJournalRecord {
            stage: "before-daemon-ipv6",
            action: ip(vec![
                "-6".to_owned(),
                "address".to_owned(),
                "add".to_owned(),
                daemon_ipv6.clone(),
                "dev".to_owned(),
                config.daemon_interface.clone(),
                "nodad".to_owned(),
            ]),
            inverse: ip(vec![
                "-6".to_owned(),
                "address".to_owned(),
                "delete".to_owned(),
                daemon_ipv6,
                "dev".to_owned(),
                config.daemon_interface.clone(),
            ]),
            target_process: None,
        },
        ExpectedJournalRecord {
            stage: "before-daemon-link-up",
            action: ip(vec![
                "link".to_owned(),
                "set".to_owned(),
                "dev".to_owned(),
                config.daemon_interface.clone(),
                "up".to_owned(),
            ]),
            inverse: ip(vec![
                "link".to_owned(),
                "set".to_owned(),
                "dev".to_owned(),
                config.daemon_interface.clone(),
                "down".to_owned(),
            ]),
            target_process: None,
        },
        ExpectedJournalRecord {
            stage: "before-peer-loopback-up",
            action: nsenter_ip(vec![
                "link".to_owned(),
                "set".to_owned(),
                "dev".to_owned(),
                "lo".to_owned(),
                "up".to_owned(),
            ]),
            inverse: nsenter_ip(vec![
                "link".to_owned(),
                "set".to_owned(),
                "dev".to_owned(),
                "lo".to_owned(),
                "down".to_owned(),
            ]),
            target_process: Some(keeper),
        },
        ExpectedJournalRecord {
            stage: "before-peer-ipv4",
            action: nsenter_ip(vec![
                "address".to_owned(),
                "add".to_owned(),
                peer_ipv4.clone(),
                "dev".to_owned(),
                config.peer_interface.clone(),
            ]),
            inverse: nsenter_ip(vec![
                "address".to_owned(),
                "delete".to_owned(),
                peer_ipv4,
                "dev".to_owned(),
                config.peer_interface.clone(),
            ]),
            target_process: Some(keeper),
        },
        ExpectedJournalRecord {
            stage: "before-peer-ipv6",
            action: nsenter_ip(vec![
                "-6".to_owned(),
                "address".to_owned(),
                "add".to_owned(),
                peer_ipv6.clone(),
                "dev".to_owned(),
                config.peer_interface.clone(),
                "nodad".to_owned(),
            ]),
            inverse: nsenter_ip(vec![
                "-6".to_owned(),
                "address".to_owned(),
                "delete".to_owned(),
                peer_ipv6,
                "dev".to_owned(),
                config.peer_interface.clone(),
            ]),
            target_process: Some(keeper),
        },
        ExpectedJournalRecord {
            stage: "before-peer-link-up",
            action: nsenter_ip(vec![
                "link".to_owned(),
                "set".to_owned(),
                "dev".to_owned(),
                config.peer_interface.clone(),
                "up".to_owned(),
            ]),
            inverse: nsenter_ip(vec![
                "link".to_owned(),
                "set".to_owned(),
                "dev".to_owned(),
                config.peer_interface.clone(),
                "down".to_owned(),
            ]),
            target_process: Some(keeper),
        },
        ExpectedJournalRecord {
            stage: "before-peer-server-spawn",
            action: server_spawn,
            inverse: vec!["terminate-and-reap-peer-server-by-owned-process-group".to_owned()],
            target_process: Some(keeper),
        },
        ExpectedJournalRecord {
            stage: "before-client-spawn",
            action: client_spawn,
            inverse: vec!["terminate-and-reap-client-child-by-owned-process-group".to_owned()],
            target_process: None,
        },
        ExpectedJournalRecord {
            stage: "before-peer-server-reap",
            action: vec![
                "wait-and-reap-peer-server".to_owned(),
                server.pid.to_string(),
            ],
            inverse: vec!["no-inverse-process-completed".to_owned()],
            target_process: Some(server),
        },
        ExpectedJournalRecord {
            stage: "before-veth-cleanup",
            action: vec![
                "ip".to_owned(),
                "link".to_owned(),
                "delete".to_owned(),
                "dev".to_owned(),
                config.daemon_interface.clone(),
            ],
            inverse: vec!["no-inverse-cleanup-is-terminal".to_owned()],
            target_process: None,
        },
        ExpectedJournalRecord {
            stage: "before-keeper-stop",
            action: vec![
                "create-stop-token".to_owned(),
                config.stop_path.display().to_string(),
            ],
            inverse: vec!["remove-stop-token".to_owned()],
            target_process: Some(keeper),
        },
        ExpectedJournalRecord {
            stage: "before-keeper-reap",
            action: vec!["wait-and-reap-keeper".to_owned(), keeper.pid.to_string()],
            inverse: vec!["no-inverse-process-completed".to_owned()],
            target_process: Some(keeper),
        },
    ];
    let observed = read_journal(&config.journal_path)?;
    if observed.len() != expected.len() {
        return Err(format!(
            "journal {} contains {} records instead of the exact expected {}: {observed:?}",
            config.journal_path.display(),
            observed.len(),
            expected.len()
        ));
    }
    for (index, (observed, expected)) in observed.iter().zip(&expected).enumerate() {
        if observed.recorded_at_unix_nanos == 0
            || observed.process_id != std::process::id()
            || observed.owner_nonce != config.nonce
            || observed.stage != expected.stage
            || observed.action != expected.action
            || observed.inverse != expected.inverse
            || observed.target_process != expected.target_process
        {
            return Err(format!(
                "journal {} record {} mismatch: expected={expected:?} observed={observed:?}",
                config.journal_path.display(),
                index + 1
            ));
        }
    }
    Ok(())
}

fn journaled_ip(
    journal: &Journal,
    stage: &str,
    arguments: &[String],
    inverse_arguments: &[String],
) -> Result<CommandOutput, String> {
    let action = prefixed_words("ip", arguments);
    let inverse = prefixed_words("ip", inverse_arguments);
    journal.record(stage, &action, &inverse)?;
    let mut command = Command::new("ip");
    command.args(arguments);
    checked_command(command, COMMAND_TIMEOUT)
}

fn journaled_nsenter_ip(
    journal: &Journal,
    stage: &str,
    arguments: &[String],
    inverse_arguments: &[String],
    keeper: ProcessIdentity,
) -> Result<CommandOutput, String> {
    verify_process_identity(keeper)?;
    let prefix = [
        "nsenter".to_owned(),
        "-t".to_owned(),
        keeper.pid.to_string(),
        "-n".to_owned(),
        "--".to_owned(),
        "ip".to_owned(),
    ];
    let action = prefix
        .iter()
        .cloned()
        .chain(arguments.iter().cloned())
        .collect::<Vec<_>>();
    let inverse = prefix
        .iter()
        .cloned()
        .chain(inverse_arguments.iter().cloned())
        .collect::<Vec<_>>();
    journal.record_for_process(stage, &action, &inverse, keeper)?;
    verify_process_identity(keeper)?;
    let mut command = Command::new("nsenter");
    command
        .args(["-t", &keeper.pid.to_string(), "-n", "--", "ip"])
        .args(arguments)
        .env("LC_ALL", "C");
    checked_command(command, COMMAND_TIMEOUT)
}

fn assert_interface_absent(keeper: Option<ProcessIdentity>, interface: &str) -> Result<(), String> {
    let mut command = if let Some(keeper) = keeper {
        verify_process_identity(keeper)?;
        let mut command = Command::new("nsenter");
        command.args([
            "-t",
            &keeper.pid.to_string(),
            "-n",
            "--",
            "ip",
            "link",
            "show",
            "dev",
            interface,
        ]);
        command
    } else {
        let mut command = Command::new("ip");
        command.args(["link", "show", "dev", interface]);
        command
    };
    command.env("LC_ALL", "C");
    let description = format_command(&command);
    let output = run_command(&mut command, COMMAND_TIMEOUT)?;
    if output.status.success() {
        Err(format!("interface {interface} remains after cleanup"))
    } else if reports_missing_interface(&output.stderr, interface) {
        Ok(())
    } else {
        Err(format!(
            "{description} did not authoritatively report ENODEV/not-found: status={} stdout={} stderr={}",
            output.status,
            bounded_diagnostic(&output.stdout),
            bounded_diagnostic(&output.stderr)
        ))
    }
}

fn delete_interface_if_present(interface: &str) -> Result<(), String> {
    let mut command = Command::new("ip");
    command
        .args(["link", "delete", "dev", interface])
        .env("LC_ALL", "C");
    let description = format_command(&command);
    let output = run_command(&mut command, COMMAND_TIMEOUT)?;
    if output.status.success() || reports_missing_interface(&output.stderr, interface) {
        Ok(())
    } else {
        Err(format!(
            "{description} failed: status={} stdout={} stderr={}",
            output.status,
            bounded_diagnostic(&output.stdout),
            bounded_diagnostic(&output.stderr)
        ))
    }
}

fn reports_missing_interface(stderr: &[u8], interface: &str) -> bool {
    let show_missing = format!("Device \"{interface}\" does not exist.");
    let delete_missing = format!("Cannot find device \"{interface}\"");
    String::from_utf8_lossy(stderr)
        .lines()
        .map(str::trim)
        .any(|line| line == show_missing || line == delete_missing)
}

fn ensure_isolated_authority() -> Result<(), String> {
    ensure_isolated_authority_with_boundary(
        "topology-only; distinct engine/probe UID authority, TPROXY, loop escape, counters, and model validation remain pending",
    )
}

#[cfg(target_os = "linux")]
fn ensure_local_output_isolated_authority_with_boundary(boundary: &str) -> Result<(), String> {
    ensure_isolated_authority_with_boundary(boundary)
}

#[cfg(target_os = "android")]
fn ensure_local_output_isolated_authority_with_boundary(boundary: &str) -> Result<(), String> {
    ensure_android_real_root_authority_with_boundary(boundary)
}

fn ensure_isolated_authority_with_boundary(boundary: &str) -> Result<(), String> {
    require_parent_reentry_token()?;
    let outer_netns = env::var(OUTER_NETNS_ENV)
        .map_err(|_| format!("{MODE_ISOLATED} mode requires {OUTER_NETNS_ENV}"))?;
    let outer_userns = env::var(OUTER_USERNS_ENV)
        .map_err(|_| format!("{MODE_ISOLATED} mode requires {OUTER_USERNS_ENV}"))?;
    let current_netns = network_namespace_identity()?;
    let current_userns = user_namespace_identity()?;
    if current_netns == outer_netns || current_userns == outer_userns {
        return Err(format!(
            "isolated reentry did not change both namespaces: outer_net={outer_netns} current_net={current_netns} outer_user={outer_userns} current_user={current_userns}"
        ));
    }

    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("read /proc/self/status: {error}"))?;
    let effective_uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| "parse effective UID from /proc/self/status".to_owned())?;
    if effective_uid != "0" {
        return Err(format!(
            "isolated helper did not receive mapped root (effective UID {effective_uid})"
        ));
    }
    let uid_map = fs::read_to_string("/proc/self/uid_map")
        .map_err(|error| format!("read /proc/self/uid_map: {error}"))?;
    let mappings = uid_map
        .lines()
        .map(|line| {
            line.split_whitespace()
                .map(str::parse::<u64>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("parse /proc/self/uid_map line {line:?}: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if mappings.len() != 1
        || mappings[0].len() != 3
        || mappings[0].as_slice().first() != Some(&0)
        || mappings[0].as_slice().get(2) != Some(&1)
    {
        return Err(format!(
            "isolated mode rejects the initial/full UID map and requires one mapped root identity: {}",
            uid_map.trim().replace('\n', "; ")
        ));
    }
    eprintln!(
        "QUALIFICATION BOUNDARY: {boundary}; user namespace UID map {}",
        uid_map.trim().replace('\n', "; "),
    );
    Ok(())
}

fn require_parent_reentry_token() -> Result<(), String> {
    let reentry_token = env::var(REENTRY_TOKEN_ENV).map_err(|_| {
        format!("{MODE_ISOLATED} mode requires a parent-issued {REENTRY_TOKEN_ENV}")
    })?;
    if reentry_token.len() != 32 || !reentry_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{REENTRY_TOKEN_ENV} is not a 128-bit hexadecimal token"
        ));
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn ensure_android_real_root_authority_with_boundary(boundary: &str) -> Result<(), String> {
    require_parent_reentry_token()?;
    let authority = env::var(REENTRY_AUTHORITY_ENV)
        .map_err(|_| format!("isolated Android mode requires {REENTRY_AUTHORITY_ENV}"))?;
    let outer_pid = env::var(OUTER_PID_ENV)
        .map_err(|_| format!("isolated Android mode requires {OUTER_PID_ENV}"))?
        .parse::<u32>()
        .map_err(|error| format!("parse {OUTER_PID_ENV}: {error}"))?;
    let parent_pid = process_parent_pid()?;
    let issued_outer_netns = env::var(OUTER_NETNS_ENV)
        .map_err(|_| format!("isolated Android mode requires {OUTER_NETNS_ENV}"))?;
    let issued_outer_mountns = env::var(OUTER_MOUNTNS_ENV)
        .map_err(|_| format!("isolated Android mode requires {OUTER_MOUNTNS_ENV}"))?;
    let live_outer_netns = process_namespace_identity(outer_pid, "net")?;
    let live_outer_mountns = process_namespace_identity(outer_pid, "mnt")?;
    let current_netns = network_namespace_identity()?;
    let current_mountns = mount_namespace_identity()?;
    let outer_uid = effective_uid_for_process(outer_pid)?;
    let current_uid = effective_uid_for_process(std::process::id())?;
    validate_android_real_root_boundary(AndroidRealRootBoundary {
        authority: &authority,
        outer_pid,
        parent_pid,
        outer_uid,
        current_uid,
        issued_outer_netns: &issued_outer_netns,
        live_outer_netns: &live_outer_netns,
        current_netns: &current_netns,
        issued_outer_mountns: &issued_outer_mountns,
        live_outer_mountns: &live_outer_mountns,
        current_mountns: &current_mountns,
    })?;
    eprintln!(
        "QUALIFICATION BOUNDARY: {boundary}; Android real-root parent pid {outer_pid}; outer net={live_outer_netns} current net={current_netns}; outer mount={live_outer_mountns} current mount={current_mountns}"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct AndroidRealRootBoundary<'a> {
    authority: &'a str,
    outer_pid: u32,
    parent_pid: u32,
    outer_uid: u32,
    current_uid: u32,
    issued_outer_netns: &'a str,
    live_outer_netns: &'a str,
    current_netns: &'a str,
    issued_outer_mountns: &'a str,
    live_outer_mountns: &'a str,
    current_mountns: &'a str,
}

fn validate_android_real_root_boundary(
    boundary: AndroidRealRootBoundary<'_>,
) -> Result<(), String> {
    if boundary.authority != ANDROID_REAL_ROOT_AUTHORITY {
        return Err(format!(
            "{REENTRY_AUTHORITY_ENV} must be {ANDROID_REAL_ROOT_AUTHORITY:?}, found {:?}",
            boundary.authority
        ));
    }
    if boundary.outer_pid <= 1 || boundary.parent_pid != boundary.outer_pid {
        return Err(format!(
            "isolated Android helper is not the direct child of its issued live parent: issued={} observed_ppid={}",
            boundary.outer_pid, boundary.parent_pid
        ));
    }
    if boundary.outer_uid != 0 || boundary.current_uid != 0 {
        return Err(format!(
            "Android initial-root checkpoint requires outer and inner effective UID 0: outer={} inner={}",
            boundary.outer_uid, boundary.current_uid
        ));
    }
    if boundary.issued_outer_netns != boundary.live_outer_netns
        || boundary.issued_outer_mountns != boundary.live_outer_mountns
    {
        return Err(format!(
            "issued Android parent namespace identities do not match the live parent: issued_net={} live_net={} issued_mount={} live_mount={}",
            boundary.issued_outer_netns,
            boundary.live_outer_netns,
            boundary.issued_outer_mountns,
            boundary.live_outer_mountns
        ));
    }
    if boundary.current_netns == boundary.live_outer_netns
        || boundary.current_mountns == boundary.live_outer_mountns
    {
        return Err(format!(
            "isolated Android reentry did not change both namespaces: outer_net={} current_net={} outer_mount={} current_mount={}",
            boundary.live_outer_netns,
            boundary.current_netns,
            boundary.live_outer_mountns,
            boundary.current_mountns
        ));
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn require_effective_root(label: &str) -> Result<(), String> {
    let effective_uid = effective_uid_for_process(std::process::id())?;
    if effective_uid == 0 {
        Ok(())
    } else {
        Err(format!(
            "{label} requires effective UID 0, found {effective_uid}"
        ))
    }
}

#[cfg(target_os = "android")]
fn effective_uid_for_process(pid: u32) -> Result<u32, String> {
    let path = format!("/proc/{pid}/status");
    let status = fs::read_to_string(&path).map_err(|error| format!("read {path}: {error}"))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| format!("parse effective UID from {path}"))?
        .parse::<u32>()
        .map_err(|error| format!("parse effective UID from {path}: {error}"))
}

#[cfg(target_os = "android")]
fn process_parent_pid() -> Result<u32, String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("read /proc/self/status: {error}"))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| "parse parent PID from /proc/self/status".to_owned())?
        .parse::<u32>()
        .map_err(|error| format!("parse parent PID from /proc/self/status: {error}"))
}

fn config_from_environment() -> Result<HarnessConfig, String> {
    let path = env::var_os(CONFIG_ENV).ok_or_else(|| format!("{CONFIG_ENV} is required"))?;
    read_json(Path::new(&path))
}

fn random_nonce() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("read canary nonce from /dev/urandom: {error}"))?;
    Ok(hex_encode(&bytes))
}

fn network_namespace_identity() -> Result<String, String> {
    fs::read_link("/proc/self/ns/net")
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| format!("read network namespace identity: {error}"))
}

fn mount_namespace_identity() -> Result<String, String> {
    fs::read_link("/proc/self/ns/mnt")
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| format!("read mount namespace identity: {error}"))
}

#[cfg(target_os = "android")]
fn process_namespace_identity(pid: u32, namespace: &str) -> Result<String, String> {
    let path = format!("/proc/{pid}/ns/{namespace}");
    fs::read_link(&path)
        .map(|identity| identity.to_string_lossy().into_owned())
        .map_err(|error| format!("read namespace identity {path}: {error}"))
}

fn user_namespace_identity() -> Result<String, String> {
    fs::read_link("/proc/self/ns/user")
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| format!("read user namespace identity: {error}"))
}

fn interface_index(interface: &str) -> Result<u32, String> {
    let interface = CString::new(interface)
        .map_err(|_| "interface name contains an interior NUL".to_owned())?;
    // SAFETY: `interface` is a live NUL-terminated C string for the duration of the call.
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    if index == 0 {
        Err(format!(
            "resolve interface index: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(index)
    }
}

fn capture_process_identity(pid: u32) -> Result<ProcessIdentity, String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| format!("read process {pid} identity: {error}"))?;
    parse_process_identity(pid, &stat)
}

fn capture_spawned_identity(
    child: &mut Child,
    description: &str,
) -> Result<ProcessIdentity, String> {
    match capture_process_identity(child.id()) {
        Ok(identity) => Ok(identity),
        Err(identity_error) => {
            let kill_error = kill_live_child_group(child).err();
            let reap_error = wait_child(child, COMMAND_TIMEOUT).err();
            Err(format!(
                "capture {description} identity after spawn: {identity_error}; kill_error={kill_error:?}; reap_error={reap_error:?}"
            ))
        }
    }
}

fn parse_process_identity(pid: u32, stat: &str) -> Result<ProcessIdentity, String> {
    let command_end = stat
        .rfind(')')
        .ok_or_else(|| format!("process {pid} stat lacks a command terminator"))?;
    let start_ticks = stat[command_end + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| format!("process {pid} stat lacks start ticks"))?
        .parse()
        .map_err(|error| format!("parse process {pid} start ticks: {error}"))?;
    Ok(ProcessIdentity { pid, start_ticks })
}

fn owned_process_remains(expected: ProcessIdentity) -> Result<bool, String> {
    let path = format!("/proc/{}/stat", expected.pid);
    let stat = match fs::read_to_string(&path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("read post-reap identity {path}: {error}")),
    };
    Ok(parse_process_identity(expected.pid, &stat)? == expected)
}

fn verify_process_identity(expected: ProcessIdentity) -> Result<(), String> {
    let observed = capture_process_identity(expected.pid)?;
    if observed == expected {
        Ok(())
    } else {
        Err(format!(
            "process identity changed for PID {}: expected start_ticks={} observed={}",
            expected.pid, expected.start_ticks, observed.start_ticks
        ))
    }
}

fn kill_owned_process(identity: ProcessIdentity) -> Result<(), String> {
    let pid = i32::try_from(identity.pid)
        .map_err(|_| format!("PID {} does not fit Linux pid_t", identity.pid))?;
    // SAFETY: pid is a positive scalar PID and flags zero is the only supported
    // `pidfd_open` mode. A successful descriptor is uniquely owned below.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH) && !owned_process_remains(identity)? {
            Ok(())
        } else {
            Err(format!(
                "open owned process pidfd {}: {error}",
                identity.pid
            ))
        };
    }
    let descriptor = i32::try_from(descriptor)
        .map_err(|_| "pidfd_open returned a descriptor outside i32".to_owned())?;
    // SAFETY: the successful pidfd_open result is transferred into one OwnedFd.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    if let Err(error) = verify_process_identity(identity) {
        return if !owned_process_remains(identity)? {
            Ok(())
        } else {
            Err(error)
        };
    }
    // SAFETY: the pidfd was opened before the exact start-tick revalidation, so
    // PID reuse cannot redirect this signal; null siginfo and flags zero are valid.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            descriptor.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0_u32,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(format!(
                "signal owned process through pidfd {}: {error}",
                identity.pid
            ));
        }
    }
    Ok(())
}

fn terminate_and_reap_owned(
    child: &mut Child,
    identity: ProcessIdentity,
    timeout: Duration,
) -> Result<(), String> {
    if child
        .try_wait()
        .map_err(|error| format!("poll owned child {}: {error}", identity.pid))?
        .is_some()
    {
        return Ok(());
    }
    let mut failures = Vec::new();
    if let Err(error) = kill_owned_process_group(identity) {
        failures.push(error);
        if let Err(fallback_error) = kill_live_child_group(child) {
            failures.push(format!("fallback group kill failed: {fallback_error}"));
        }
    }
    if let Err(error) = wait_child(child, timeout) {
        failures.push(format!("bounded reap failed: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn kill_owned_process_group(identity: ProcessIdentity) -> Result<(), String> {
    verify_process_identity(identity)?;
    let process_group = i32::try_from(identity.pid)
        .map_err(|_| format!("PID {} does not fit a process-group ID", identity.pid))?;
    // SAFETY: the process group was created by this harness with PGID equal to the captured PID;
    // the immediately preceding start-tick check prevents targeting a reused PID.
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "kill owned process group {}: {}",
            identity.pid,
            std::io::Error::last_os_error()
        ))
    }
}

fn kill_live_child_group(child: &mut Child) -> Result<(), String> {
    if child
        .try_wait()
        .map_err(|error| format!("poll live child {} before group kill: {error}", child.id()))?
        .is_some()
    {
        return Ok(());
    }
    let process_group = i32::try_from(child.id())
        .map_err(|_| format!("PID {} does not fit a process-group ID", child.id()))?;
    // SAFETY: `try_wait` proved the directly owned group leader is still live, so its PID cannot
    // have been reused; the harness created its process group with PGID equal to that PID.
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "kill live child process group {}: {}",
            child.id(),
            std::io::Error::last_os_error()
        ))
    }
}

fn write_json_synced(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("encode JSON {}: {error}", path.display()))?;
    if encoded.len() > MAX_JSON_BYTES {
        return Err(format!(
            "JSON {} is {} bytes, above the {MAX_JSON_BYTES}-byte limit",
            path.display(),
            encoded.len()
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("JSON path {} has no parent", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("JSON path {} has no file name", path.display()))?
        .to_string_lossy();
    let sequence = JSON_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("create atomic JSON {}: {error}", temporary.display()))?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|error| {
                format!(
                    "write and sync atomic JSON {}: {error}",
                    temporary.display()
                )
            })?;
        fs::rename(&temporary, path).map_err(|error| {
            format!(
                "publish atomic JSON {} as {}: {error}",
                temporary.display(),
                path.display()
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync JSON directory {}: {error}", parent.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_synced(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file =
        File::create(path).map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write and sync {}: {error}", path.display()))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let encoded = read_bounded(path, MAX_JSON_BYTES)?;
    serde_json::from_slice(&encoded).map_err(|error| format!("decode {}: {error}", path.display()))
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let read_limit = u64::try_from(limit)
        .map_err(|_| "bounded read limit does not fit u64".to_owned())?
        .saturating_add(1);
    let mut encoded = Vec::new();
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut encoded)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if encoded.len() > limit {
        return Err(format!(
            "{} exceeds the {limit}-byte read limit",
            path.display()
        ));
    }
    Ok(encoded)
}

struct CommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn checked_command(mut command: Command, timeout: Duration) -> Result<CommandOutput, String> {
    let description = format_command(&command);
    let output = run_command(&mut command, timeout)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "{description} exited with {}: stdout={} stderr={}",
            output.status,
            bounded_diagnostic(&output.stdout),
            bounded_diagnostic(&output.stderr)
        ))
    }
}

fn run_command(command: &mut Command, timeout: Duration) -> Result<CommandOutput, String> {
    let description = format_command(command);
    command.process_group(0);
    arm_parent_death_signal(command)?;
    let mut stdout_file = tempfile::tempfile()
        .map_err(|error| format!("create stdout capture for {description}: {error}"))?;
    let mut stderr_file = tempfile::tempfile()
        .map_err(|error| format!("create stderr capture for {description}: {error}"))?;
    let stdout_sink = stdout_file
        .try_clone()
        .map_err(|error| format!("clone stdout capture for {description}: {error}"))?;
    let stderr_sink = stderr_file
        .try_clone()
        .map_err(|error| format!("clone stderr capture for {description}: {error}"))?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_sink))
        .stderr(Stdio::from(stderr_sink))
        .spawn()
        .map_err(|error| format!("spawn {description}: {error}"))?;
    let identity = match capture_process_identity(child.id()) {
        Ok(identity) => identity,
        Err(identity_error) => {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("poll {description} after identity race: {error}"))?
            {
                let stdout = read_command_capture(&mut stdout_file, &description, "stdout")?;
                let stderr = read_command_capture(&mut stderr_file, &description, "stderr")?;
                return Ok(CommandOutput {
                    status,
                    stdout,
                    stderr,
                });
            }
            let kill_error = kill_live_child_group(&mut child).err();
            let reap_error = wait_child(&mut child, COMMAND_TIMEOUT).err();
            return Err(format!(
                "capture child identity for {description} after spawn: {identity_error}; kill_error={kill_error:?}; reap_error={reap_error:?}"
            ));
        }
    };
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child
            .try_wait()
            .map_err(|error| format!("poll {description}: {error}"))?
        {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let kill_error = kill_owned_process_group(identity).err();
                let fallback_kill_error = if kill_error.is_some() {
                    kill_live_child_group(&mut child).err()
                } else {
                    None
                };
                let reap_error = wait_child(&mut child, COMMAND_TIMEOUT).err();
                let stdout = read_command_capture(&mut stdout_file, &description, "stdout")?;
                let stderr = read_command_capture(&mut stderr_file, &description, "stderr")?;
                return Err(format!(
                    "{description} exceeded {timeout:?}; kill_error={kill_error:?}; fallback_kill_error={fallback_kill_error:?}; reap_error={reap_error:?}; stdout={} stderr={}",
                    bounded_diagnostic(&stdout),
                    bounded_diagnostic(&stderr)
                ));
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    let stdout = read_command_capture(&mut stdout_file, &description, "stdout")?;
    let stderr = read_command_capture(&mut stderr_file, &description, "stderr")?;
    Ok(CommandOutput {
        status,
        stdout,
        stderr,
    })
}

fn read_command_capture(
    file: &mut File,
    description: &str,
    stream: &str,
) -> Result<Vec<u8>, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek {stream} capture for {description}: {error}"))?;
    let mut captured = Vec::new();
    Read::by_ref(file)
        .take(u64::try_from(MAX_DIAGNOSTIC_BYTES).expect("diagnostic limit fits u64"))
        .read_to_end(&mut captured)
        .map_err(|error| format!("read {stream} capture for {description}: {error}"))?;
    Ok(captured)
}

fn arm_parent_death_signal(command: &mut Command) -> Result<(), String> {
    let expected_parent = i32::try_from(std::process::id())
        .map_err(|_| "parent PID does not fit Linux pid_t".to_owned())?;
    // SAFETY: the pre-exec closure performs only async-signal-safe Linux syscalls, does not touch
    // shared memory, and returns fixed OS errors. It arms SIGKILL before the child executes any
    // harness code and verifies against the parent PID captured before `fork`, so adoption by a
    // subreaper before this closure runs cannot silently arm the child against the wrong process.
    unsafe {
        command.pre_exec(move || {
            let mut file_limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_FSIZE, &mut file_limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            file_limit.rlim_max = file_limit.rlim_max.min(MAX_HELPER_FILE_BYTES);
            file_limit.rlim_cur = file_limit.rlim_cur.min(file_limit.rlim_max);
            if libc::setrlimit(libc::RLIMIT_FSIZE, &file_limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != expected_parent {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    Ok(())
}

fn wait_child(child: &mut Child, timeout: Duration) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match child
            .try_wait()
            .map_err(|error| format!("poll child {}: {error}", child.id()))?
        {
            Some(status) => return Ok(status),
            None if Instant::now() >= deadline => {
                return Err(format!("child {} exceeded {timeout:?}", child.id()));
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn wait_for_path_and_child(
    path: &Path,
    child: &mut Child,
    timeout: Duration,
    log_path: &Path,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("poll peer {}: {error}", child.id()))?
        {
            return Err(format!(
                "peer exited with {status} before creating {}: {}",
                path.display(),
                read_diagnostic(log_path)
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "peer did not create {} within {timeout:?}: {}",
                path.display(),
                read_diagnostic(log_path)
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn read_diagnostic(path: &Path) -> String {
    read_bounded(
        path,
        usize::try_from(MAX_HELPER_FILE_BYTES).unwrap_or(MAX_DIAGNOSTIC_BYTES),
    )
    .map(|contents| bounded_diagnostic(&contents))
    .unwrap_or_else(|error| format!("cannot read {}: {error}", path.display()))
}

fn bounded_diagnostic(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_DIAGNOSTIC_BYTES);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn format_command(command: &Command) -> String {
    command_words(
        command.get_program(),
        command.get_args().map(OsStr::to_owned),
    )
    .join(" ")
}

fn command_words(
    program: impl AsRef<OsStr>,
    arguments: impl IntoIterator<Item = OsString>,
) -> Vec<String> {
    std::iter::once(program.as_ref().to_string_lossy().into_owned())
        .chain(
            arguments
                .into_iter()
                .map(|argument| argument.to_string_lossy().into_owned()),
        )
        .collect()
}

fn prefixed_words(program: &str, arguments: &[String]) -> Vec<String> {
    std::iter::once(program.to_owned())
        .chain(arguments.iter().cloned())
        .collect()
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod android_real_root_boundary_tests {
    use super::*;

    fn valid_boundary() -> AndroidRealRootBoundary<'static> {
        AndroidRealRootBoundary {
            authority: ANDROID_REAL_ROOT_AUTHORITY,
            outer_pid: 42,
            parent_pid: 42,
            outer_uid: 0,
            current_uid: 0,
            issued_outer_netns: "net:[1]",
            live_outer_netns: "net:[1]",
            current_netns: "net:[2]",
            issued_outer_mountns: "mnt:[3]",
            live_outer_mountns: "mnt:[3]",
            current_mountns: "mnt:[4]",
        }
    }

    #[test]
    fn android_real_root_boundary_accepts_exact_parent_and_changed_namespaces() {
        validate_android_real_root_boundary(valid_boundary()).expect("valid Android boundary");
    }

    #[test]
    fn android_real_root_boundary_rejects_forged_or_weak_evidence() {
        let cases = [
            AndroidRealRootBoundary {
                authority: "mapped-user-root",
                ..valid_boundary()
            },
            AndroidRealRootBoundary {
                parent_pid: 41,
                ..valid_boundary()
            },
            AndroidRealRootBoundary {
                outer_uid: 1000,
                ..valid_boundary()
            },
            AndroidRealRootBoundary {
                current_uid: 1000,
                ..valid_boundary()
            },
            AndroidRealRootBoundary {
                live_outer_netns: "net:[9]",
                ..valid_boundary()
            },
            AndroidRealRootBoundary {
                live_outer_mountns: "mnt:[9]",
                ..valid_boundary()
            },
            AndroidRealRootBoundary {
                current_netns: "net:[1]",
                ..valid_boundary()
            },
            AndroidRealRootBoundary {
                current_mountns: "mnt:[3]",
                ..valid_boundary()
            },
        ];
        for boundary in cases {
            assert!(validate_android_real_root_boundary(boundary).is_err());
        }
    }
}
