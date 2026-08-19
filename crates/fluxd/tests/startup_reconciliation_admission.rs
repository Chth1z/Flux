#![cfg(any(target_os = "linux", target_os = "android"))]

use std::env;
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use flux_core::{
    BootIdentityMutationStatus, ControlClient, ControlSnapshot, FailurePolicy, FluxConfig,
    KernelMutationStatus, MutationGate, Reason, RuntimeIntent,
};
use flux_testkit::{CapabilityProfileFixture, StaticCapabilityProfileSource};
use fluxd::{
    DaemonError, DaemonOptions, NativeAdmissionRejection, NativeAdmissionState,
    SocketControlClient, run_daemon,
};
use tempfile::tempdir;

const PACKAGED_CONFIG: &str = include_str!("../../../conf/flux.toml");
const UNSUPPORTED_HELPER_ROOT: &str = "FLUXD_TEST_UNSUPPORTED_HELPER_ROOT";
const SAFETY_REJECTION_HELPER_ROOT: &str = "FLUXD_TEST_SAFETY_REJECTION_HELPER_ROOT";
const INVALID_CONFIG_RECOVERY_HELPER_ROOT: &str = "FLUXD_TEST_INVALID_CONFIG_RECOVERY_HELPER_ROOT";
const MISSING_IDENTITY_RECOVERY_HELPER_ROOT: &str =
    "FLUXD_TEST_MISSING_IDENTITY_RECOVERY_HELPER_ROOT";

#[test]
fn packaged_default_config_matches_the_strict_product_schema() {
    let config = FluxConfig::parse(PACKAGED_CONFIG).expect("packaged flux.toml must be valid");

    assert_eq!(config.schema(), 4);
    assert_eq!(config.daemon().fail_policy(), FailurePolicy::Open);
    assert_eq!(
        config.daemon().reconcile_debounce().get(),
        Duration::from_millis(250)
    );
    assert_eq!(config.daemon().event_queue_capacity().get(), 256);
    assert_eq!(config.daemon().generation_history().get(), 2);
}

#[test]
fn unsupported_kernel_queries_ignore_missing_and_invalid_mutation_inputs() {
    for invalid_config in [false, true] {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("flux");
        let run = root.join("run");
        let conf = root.join("conf");
        let socket_path = run.join("fluxd.sock");
        let hostile_intent = root.join("state/administrative-intent.json");

        fs::create_dir_all(&run).expect("create run directory");
        fs::create_dir_all(&conf).expect("create config directory");
        fs::create_dir_all(root.join("state")).expect("create state directory");
        fs::create_dir(&hostile_intent).expect("create hostile intent path");
        fs::create_dir(root.join("disable")).expect("create hostile disable path");
        fs::write(
            root.join("boot-id"),
            "22222222-2222-4222-8222-222222222222\n",
        )
        .expect("write boot identity");
        if invalid_config {
            fs::write(conf.join("flux.toml"), "this is not valid TOML = [\n")
                .expect("write invalid configuration");
        }

        let mut child = KillOnDrop(
            daemon_helper_command(
                "unsupported_kernel_daemon_helper",
                UNSUPPORTED_HELPER_ROOT,
                &root,
            )
            .spawn()
            .expect("start unsupported-kernel helper"),
        );

        wait_for_socket(child.child_mut(), &socket_path);
        let snapshot = SocketControlClient::new(&socket_path)
            .status()
            .expect("unsupported daemon remains queryable");

        match snapshot.capability_profile.mutation_gate() {
            MutationGate::ReadOnly {
                kernel: KernelMutationStatus::Unsupported { found, minimum },
                boot_identity: BootIdentityMutationStatus::Verified,
            } => {
                assert_eq!(found.to_string(), "5.4.280");
                assert_eq!(minimum.to_string(), "5.10.0");
            }
            gate => panic!("unexpected mutation gate: {gate:?}"),
        }
        assert_eq!(snapshot.control, ControlSnapshot::default());
        assert!(
            hostile_intent.is_dir(),
            "hostile administrative intent must remain untouched"
        );
        assert_successful_sigterm(child.child_mut(), &socket_path);
    }
}

#[test]
fn configured_safety_rejection_remains_online_and_read_only_until_sigterm() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let socket_path = root.join("run/fluxd.sock");
    let facility_journal = root.join("run/canary-facility.owner");
    fs::create_dir_all(root.join("run")).expect("create run directory");
    fs::create_dir_all(root.join("conf")).expect("create config directory");
    fs::write(root.join("conf/flux.toml"), PACKAGED_CONFIG).expect("write packaged configuration");
    fs::write(&facility_journal, exact_absent_facility_journal())
        .expect("write prior facility journal");

    let mut child = KillOnDrop(
        daemon_helper_command(
            "configured_safety_rejection_daemon_helper",
            SAFETY_REJECTION_HELPER_ROOT,
            &root,
        )
        .spawn()
        .expect("start safety-rejection helper"),
    );

    wait_for_socket(child.child_mut(), &socket_path);
    let client = SocketControlClient::new(&socket_path);
    let snapshot = client.status().expect("rejected daemon remains queryable");
    assert!(
        !facility_journal.exists(),
        "read-only admission follows exact prior-state recovery"
    );
    assert_eq!(
        snapshot.native_admission,
        NativeAdmissionState::Rejected(NativeAdmissionRejection::AndroidVpnPolicyUnavailable)
    );
    assert_eq!(snapshot.control, ControlSnapshot::default());

    let error = client
        .submit_and_wait(RuntimeIntent::Running {
            reason: Reason::UserControl,
        })
        .expect_err("safety rejection must deny mutation");
    assert_eq!(
        error.rejection_code(),
        Some("android_vpn_policy_unavailable")
    );
    assert_eq!(
        client
            .status()
            .expect("status after rejected mutation")
            .control,
        ControlSnapshot::default()
    );

    assert_successful_sigterm(child.child_mut(), &socket_path);
}

#[test]
fn malformed_configuration_cannot_skip_prior_facility_recovery() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let run = root.join("run");
    let conf = root.join("conf");
    let journal = run.join("canary-facility.owner");
    fs::create_dir_all(&run).expect("create run directory");
    fs::create_dir_all(&conf).expect("create config directory");
    fs::write(conf.join("flux.toml"), "this is not valid TOML = [\n")
        .expect("write malformed configuration");
    fs::write(&journal, exact_absent_facility_journal()).expect("write prior facility journal");

    let status = daemon_helper_command(
        "malformed_configuration_recovery_daemon_helper",
        INVALID_CONFIG_RECOVERY_HELPER_ROOT,
        &root,
    )
    .status()
    .expect("run malformed-config recovery helper");

    assert!(status.success(), "recovery helper failed: {status}");
    assert!(
        !journal.exists(),
        "pre-admission recovery must retire proven-absent prior state"
    );
}

#[test]
fn unverifiable_owner_identity_cannot_hide_durable_recovery_residue() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let run = root.join("run");
    let journal = run.join("canary-facility.owner");
    fs::create_dir_all(&run).expect("create run directory");
    fs::write(&journal, exact_absent_facility_journal()).expect("write prior facility journal");

    let status = daemon_helper_command(
        "missing_identity_recovery_daemon_helper",
        MISSING_IDENTITY_RECOVERY_HELPER_ROOT,
        &root,
    )
    .status()
    .expect("run missing-identity recovery helper");

    assert!(status.success(), "recovery helper failed: {status}");
    assert!(
        journal.exists(),
        "unverified identity must retain durable recovery authority"
    );
}

#[test]
fn unsupported_kernel_daemon_helper() {
    let Some(root) = env::var_os(UNSUPPORTED_HELPER_ROOT).map(PathBuf::from) else {
        return;
    };
    let profile_source =
        StaticCapabilityProfileSource::new(CapabilityProfileFixture::unsupported_kernel());
    run_daemon(&profile_source, daemon_options(&root))
        .expect("unsupported daemon runs until the parent terminates it");
}

#[test]
fn configured_safety_rejection_daemon_helper() {
    let Some(root) = env::var_os(SAFETY_REJECTION_HELPER_ROOT).map(PathBuf::from) else {
        return;
    };
    let profile_source =
        StaticCapabilityProfileSource::new(CapabilityProfileFixture::device_qualified());
    run_daemon(&profile_source, daemon_options(&root))
        .expect("safety-rejected daemon runs until SIGTERM");
}

#[test]
fn malformed_configuration_recovery_daemon_helper() {
    let Some(root) = env::var_os(INVALID_CONFIG_RECOVERY_HELPER_ROOT).map(PathBuf::from) else {
        return;
    };
    let journal = root.join("run/canary-facility.owner");
    let profile_source =
        StaticCapabilityProfileSource::new(CapabilityProfileFixture::device_qualified());

    let error = run_daemon(&profile_source, daemon_options(&root))
        .expect_err("malformed configuration rejects startup after recovery");

    assert!(matches!(error, DaemonError::FluxConfig(_)));
    assert!(
        !journal.exists(),
        "facility recovery precedes config parsing"
    );
}

#[test]
fn missing_identity_recovery_daemon_helper() {
    let Some(root) = env::var_os(MISSING_IDENTITY_RECOVERY_HELPER_ROOT).map(PathBuf::from) else {
        return;
    };
    let profile_source =
        StaticCapabilityProfileSource::new(CapabilityProfileFixture::unsupported_kernel());

    let error = run_daemon(&profile_source, daemon_options(&root))
        .expect_err("durable residue without an owner identity fails startup");

    assert!(matches!(
        error,
        DaemonError::NativeStartup {
            operation: "recover durable native state without verified identity",
            ..
        }
    ));
}

fn exact_absent_facility_journal() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "boot_identity": "01234567-89ab-cdef-0123-456789abcdef",
        "daemon_network_namespace_device": 10,
        "daemon_network_namespace_inode": 20,
        "reviewed_policy_digest": vec![0x41_u8; 32],
        "reviewed_policy_revision": 1,
        "daemon_veth_name": b"fxjcan0".to_vec(),
        "peer_veth_name": b"fxjcanp".to_vec(),
        "daemon_ipv4": [9, 254, 254, 252],
        "peer_ipv4": [9, 254, 254, 253],
        "daemon_ipv6": null,
        "peer_ipv6": null,
        "tcp_echo_port": 61_001,
        "udp_echo_port": 61_002,
        "dns_port": 61_003,
        "engine_uid": 20_002,
        "proxy_rule_priority": 4_000_000_000_u32,
        "peer_rule_priority": 4_000_000_001_u32,
        "proxy_capture_table": 4_000_000_002_u32,
        "peer_table": 4_000_000_003_u32,
        "peer_return_table": 254,
        "rule_protocol": 186,
        "route_protocol": 186,
        "route_metric": 1_031,
        "proxy_mark_value": 0x0200_0000,
        "proxy_mark_mask": 0x0300_0000,
    }))
    .expect("serialize facility journal fixture")
}

fn daemon_options(root: &Path) -> DaemonOptions {
    let run = root.join("run");
    DaemonOptions {
        runtime_root: root.to_owned(),
        socket_path: run.join("fluxd.sock"),
        daemon_lease_path: run.join("fluxd.lease"),
        config_path: root.join("conf/flux.toml"),
        subscription_store_path: root.join("state/subscription"),
        intent_path: root.join("state/administrative-intent.json"),
        boot_id_path: root.join("boot-id"),
        selinux_enforce_path: root.join("selinux-enforce"),
        disable_path: root.join("disable"),
    }
}

fn daemon_helper_command(test_name: &str, root_variable: &str, root: &Path) -> Command {
    let mut command = Command::new(env::current_exe().expect("current test executable"));
    command
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env(root_variable, root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    // SAFETY: the callback invokes only signal-set syscalls and runs after
    // fork, before exec. The new process and every libtest/daemon thread then
    // inherit the blocked mask, matching the production launch contract.
    unsafe {
        command.pre_exec(block_shutdown_signals_before_exec);
    }
    command
}

fn block_shutdown_signals_before_exec() -> io::Result<()> {
    let mut mask = MaybeUninit::<libc::sigset_t>::zeroed();
    // SAFETY: `mask` points to writable storage for one signal set.
    if unsafe { libc::sigemptyset(mask.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `sigemptyset` initialized the set and SIGINT is a valid signal number.
    if unsafe { libc::sigaddset(mask.as_mut_ptr(), libc::SIGINT) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `sigemptyset` initialized the set and SIGTERM is a valid signal number.
    if unsafe { libc::sigaddset(mask.as_mut_ptr(), libc::SIGTERM) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `mask` is initialized; `SIG_BLOCK` accepts a null output pointer.
    if unsafe { libc::sigprocmask(libc::SIG_BLOCK, mask.as_ptr(), std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn wait_for_socket(child: &mut Child, socket_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if socket_path.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("inspect helper status") {
            panic!("daemon helper exited before binding: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "helper did not bind control socket"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_successful_sigterm(child: &mut Child, socket_path: &Path) {
    let process_id = i32::try_from(child.id()).expect("child PID fits pid_t");
    // SAFETY: `process_id` names the live helper child and SIGTERM is a valid signal.
    assert_eq!(unsafe { libc::kill(process_id, libc::SIGTERM) }, 0);
    let status = child.wait().expect("wait for SIGTERM shutdown");
    assert!(status.success(), "daemon SIGTERM exit failed: {status}");
    assert!(
        !socket_path.exists(),
        "control socket must be removed before daemon exit"
    );
}

struct KillOnDrop(Child);

impl KillOnDrop {
    fn child_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
