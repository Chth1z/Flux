#![cfg(any(target_os = "linux", target_os = "android"))]

use std::env;
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use flux_core::{
    BootIdentityMutationStatus, ConfigErrorKind, ControlError, ControlSnapshot, FailurePolicy,
    FluxConfig, KernelMutationStatus, LegacyMutationGate,
};
use flux_testkit::{CapabilityProfileFixture, StaticCapabilityProfileSource};
use fluxd::{DaemonError, DaemonOptions, SocketControlClient, run_daemon};
use tempfile::tempdir;

const PACKAGED_CONFIG: &str = include_str!("../../../conf/flux.toml");
const UNSUPPORTED_HELPER_ROOT: &str = "FLUXD_TEST_UNSUPPORTED_HELPER_ROOT";
const SUPPORTED_PROFILE_BOOT_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";

#[test]
fn packaged_default_config_matches_the_strict_phase_one_schema() {
    let config = FluxConfig::parse(PACKAGED_CONFIG).expect("packaged flux.toml must be valid");

    assert_eq!(config.schema(), 1);
    assert_eq!(config.daemon().fail_policy(), FailurePolicy::Open);
    assert_eq!(
        config.daemon().reconcile_debounce().get(),
        Duration::from_millis(250)
    );
    assert_eq!(config.daemon().event_queue_capacity().get(), 256);
    assert_eq!(config.daemon().generation_history().get(), 2);
}

#[test]
fn failed_startup_reconciliation_never_admits_a_control_socket() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let disable_path = directory.path().join("disable");
    let intent_path = root.join("state/administrative-intent.json");
    let options = daemon_options(&root, &disable_path, intent_path.clone(), "exit 73\n");
    let socket_path = options.socket_path.clone();
    let profile_source = supported_profile_source();

    let error = run_daemon(&profile_source, options).expect_err("startup reconciliation must fail");

    assert!(
        matches!(error, DaemonError::Control(ControlError::Runtime { .. })),
        "unexpected startup error: {error:?}"
    );
    assert!(
        !socket_path.exists(),
        "the control socket must not exist after failed startup reconciliation"
    );
    assert_eq!(
        fs::read_to_string(intent_path).expect("persisted startup intent"),
        format!(
            "{{\"schema_version\":1,\"boot_id\":\"{SUPPORTED_PROFILE_BOOT_ID}\",\"administrative_state\":\"running\"}}\n"
        ),
        "startup persistence must use the Capability Profile boot identity"
    );
}

#[test]
fn startup_persistence_error_preserves_its_source_chain_before_socket_admission() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let disable_path = directory.path().join("disable");
    let blocked_parent = root.join("state/not-a-directory");

    fs::create_dir_all(root.join("state")).expect("create state directory");
    fs::write(&blocked_parent, "blocks intent directory traversal\n")
        .expect("create non-directory intent parent");
    fs::write(&disable_path, "").expect("request stopped startup state");

    let options = daemon_options(
        &root,
        &disable_path,
        blocked_parent.join("administrative-intent.json"),
        "exit 73\n",
    );
    let socket_path = options.socket_path.clone();
    let profile_source = supported_profile_source();

    let error = run_daemon(&profile_source, options).expect_err("startup persistence must fail");
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

#[test]
fn cold_desired_stopped_runs_startup_recovery_before_the_initial_intent() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let disable_path = directory.path().join("disable");
    let intent_path = root.join("state/administrative-intent.json");
    let phase_record = root.join("run/startup-phases");
    fs::write(&disable_path, "").expect("request stopped startup state");
    let options = daemon_options(&root, &disable_path, intent_path.clone(), "exit 99\n");
    write_script(
        &options.dispatcher_script,
        &format!(
            "printf '%s\\n' \"${{1:-}}\" >> '{}'\n\
             case \"${{1:-}}\" in\n\
                 startup-recover) exit 0 ;;\n\
                 state-stopped) exit 73 ;;\n\
                 *) exit 99 ;;\n\
             esac\n",
            phase_record.display()
        ),
    );
    let socket_path = options.socket_path.clone();
    let profile_source = supported_profile_source();

    let error = run_daemon(&profile_source, options)
        .expect_err("initial stopped publication is deliberately failed");

    assert!(
        matches!(error, DaemonError::Control(ControlError::Runtime { .. })),
        "unexpected startup error: {error:?}"
    );
    let phases = fs::read_to_string(&phase_record).expect("startup phase record");
    let mut phases = phases.lines();
    assert_eq!(
        phases.next(),
        Some("startup-recover"),
        "recovery must be the first mutation phase"
    );
    assert!(
        phases.clone().next().is_some(),
        "the cold stopped intent must execute after recovery"
    );
    assert!(
        phases.all(|phase| phase == "state-stopped"),
        "only bounded stopped-publication retries may follow recovery"
    );
    assert_eq!(
        fs::read_to_string(intent_path).expect("persisted stopped intent"),
        format!(
            "{{\"schema_version\":1,\"boot_id\":\"{SUPPORTED_PROFILE_BOOT_ID}\",\"administrative_state\":\"stopped\"}}\n"
        )
    );
    assert!(!socket_path.exists(), "control socket must not be admitted");
}

#[test]
fn failed_startup_recovery_never_persists_or_executes_the_initial_intent() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let disable_path = directory.path().join("disable");
    let intent_path = root.join("state/administrative-intent.json");
    let phase_record = root.join("run/startup-phases");
    let options = daemon_options(&root, &disable_path, intent_path.clone(), "exit 99\n");
    write_script(
        &options.dispatcher_script,
        &format!(
            "printf '%s\\n' \"${{1:-}}\" >> '{}'\nexit 74\n",
            phase_record.display()
        ),
    );
    let socket_path = options.socket_path.clone();
    let profile_source = supported_profile_source();

    let error = run_daemon(&profile_source, options).expect_err("startup recovery must fail");

    assert!(
        matches!(error, DaemonError::Control(ControlError::Runtime { .. })),
        "unexpected startup error: {error:?}"
    );
    assert_eq!(
        fs::read_to_string(&phase_record).expect("startup phase record"),
        "startup-recover\n"
    );
    assert!(
        !intent_path.exists(),
        "initial intent must not be persisted"
    );
    assert!(!socket_path.exists(), "control socket must not be admitted");
}

#[test]
fn supported_kernel_recovers_before_rejecting_missing_config() {
    assert_supported_config_failure(ConfigFailureCase::Missing);
}

#[test]
fn supported_kernel_recovers_before_rejecting_invalid_config() {
    assert_supported_config_failure(ConfigFailureCase::Invalid);
}

enum ConfigFailureCase {
    Missing,
    Invalid,
}

fn assert_supported_config_failure(case: ConfigFailureCase) {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let disable_path = directory.path().join("disable");
    let intent_path = root.join("state/administrative-intent.json");
    let dispatcher_record = root.join("run/dispatcher.record");
    let stale_capture = root.join("run/stale-capture");
    let options = daemon_options(&root, &disable_path, intent_path.clone(), "exit 99\n");
    fs::write(&stale_capture, "same-boot Rust capture evidence\n")
        .expect("create stale capture fixture");
    write_script(
        &options.dispatcher_script,
        &format!(
            "printf '%s\\n' \"${{1:-}}\" >> '{}'\n\
             if [ \"${{1:-}}\" = startup-recover ]; then\n\
                 rm -f '{}'\n\
                 exit 0\n\
             fi\n\
             exit 99\n",
            dispatcher_record.display(),
            stale_capture.display()
        ),
    );
    let expected_kind = match case {
        ConfigFailureCase::Missing => {
            fs::remove_file(&options.config_path).expect("remove configuration");
            ConfigErrorKind::Io
        }
        ConfigFailureCase::Invalid => {
            fs::write(
                &options.config_path,
                format!("{PACKAGED_CONFIG}\nunknown = true\n"),
            )
            .expect("write invalid configuration");
            ConfigErrorKind::InvalidToml
        }
    };
    fs::create_dir(&disable_path).expect("create hostile disable path");
    let socket_path = options.socket_path.clone();
    let profile_source = supported_profile_source();

    let error =
        run_daemon(&profile_source, options).expect_err("configuration failure must be fatal");
    let DaemonError::FluxConfig(config_error) = &error else {
        panic!("unexpected startup error: {error:?}");
    };

    assert_eq!(config_error.kind(), expected_kind);
    assert_eq!(profile_source.calls(), 1, "profile must be collected once");
    assert_eq!(
        fs::read_to_string(dispatcher_record).expect("startup recovery record"),
        "startup-recover\n",
        "only startup recovery may execute before invalid configuration is rejected"
    );
    assert!(
        !stale_capture.exists(),
        "invalid current configuration must not block stale runtime cleanup"
    );
    assert!(!intent_path.exists(), "intent must not be persisted");
    assert!(!socket_path.exists(), "control socket must not be admitted");
}

#[test]
fn unsupported_kernel_queries_ignore_missing_and_invalid_mutation_inputs() {
    for invalid_config in [false, true] {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("flux");
        let run = root.join("run");
        let conf = root.join("conf");
        let scripts = root.join("scripts");
        let socket_path = run.join("fluxd.sock");
        let dispatcher_record = run.join("dispatcher.record");
        let hostile_intent = root.join("state/administrative-intent.json");

        fs::create_dir_all(&run).expect("create run directory");
        fs::create_dir_all(&conf).expect("create config directory");
        fs::create_dir_all(&scripts).expect("create scripts directory");
        fs::create_dir_all(root.join("state")).expect("create state directory");
        fs::create_dir(&hostile_intent).expect("create hostile intent path");
        fs::create_dir(root.join("disable")).expect("create hostile disable path");
        write_script(
            &scripts.join("dispatcher"),
            &format!("printf invoked > '{}'\n", dispatcher_record.display()),
        );
        write_script(&scripts.join("addrsync"), "exit 0\n");
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
            Command::new(env::current_exe().expect("current test executable"))
                .arg("--exact")
                .arg("unsupported_kernel_daemon_helper")
                .arg("--nocapture")
                .env(UNSUPPORTED_HELPER_ROOT, &root)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("start unsupported-kernel helper"),
        );

        wait_for_socket(child.child_mut(), &socket_path);
        let snapshot = SocketControlClient::new(&socket_path)
            .status()
            .expect("unsupported daemon remains queryable");

        match snapshot.capability_profile.legacy_mutation_gate() {
            LegacyMutationGate::ReadOnly {
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
            !dispatcher_record.exists(),
            "legacy writer must not execute"
        );
        assert!(
            hostile_intent.is_dir(),
            "hostile administrative intent must remain untouched"
        );
    }
}

#[test]
fn unsupported_kernel_daemon_helper() {
    let Some(root) = env::var_os(UNSUPPORTED_HELPER_ROOT).map(PathBuf::from) else {
        return;
    };
    let run = root.join("run");
    let options = DaemonOptions {
        socket_path: run.join("fluxd.sock"),
        config_path: root.join("conf/flux.toml"),
        shell: if cfg!(target_os = "android") {
            PathBuf::from("/system/bin/sh")
        } else {
            PathBuf::from("/bin/sh")
        },
        dispatcher_script: root.join("scripts/dispatcher"),
        addrsync_script: root.join("scripts/addrsync"),
        engine_manifest_path: run.join("engine.manifest"),
        intent_path: root.join("state/administrative-intent.json"),
        boot_id_path: root.join("boot-id"),
        selinux_enforce_path: root.join("selinux-enforce"),
        disable_path: root.join("disable"),
    };

    let profile_source =
        StaticCapabilityProfileSource::new(CapabilityProfileFixture::unsupported_kernel());
    run_daemon(&profile_source, options)
        .expect("unsupported daemon runs until the parent terminates it");
}

fn daemon_options(
    root: &Path,
    disable_path: &Path,
    intent_path: PathBuf,
    dispatcher_body: &str,
) -> DaemonOptions {
    let scripts = root.join("scripts");
    let run = root.join("run");
    let dispatcher_script = scripts.join("dispatcher");
    let addrsync_script = scripts.join("addrsync");

    fs::create_dir_all(&scripts).expect("create scripts directory");
    fs::create_dir_all(root.join("conf")).expect("create config directory");
    fs::create_dir_all(root.join("state")).expect("create state directory");
    fs::create_dir_all(&run).expect("create run directory");
    fs::write(root.join("conf/flux.toml"), PACKAGED_CONFIG).expect("write configuration");
    write_script(
        &dispatcher_script,
        &format!("if [ \"${{1:-}}\" = startup-recover ]; then exit 0; fi\n{dispatcher_body}"),
    );
    write_script(&addrsync_script, "exit 0\n");

    DaemonOptions {
        socket_path: run.join("fluxd.sock"),
        config_path: root.join("conf/flux.toml"),
        shell: PathBuf::from("/bin/sh"),
        dispatcher_script,
        addrsync_script,
        engine_manifest_path: run.join("engine.manifest"),
        intent_path,
        boot_id_path: root.join("must-not-be-read-boot-id"),
        selinux_enforce_path: root.join("selinux-enforce"),
        disable_path: disable_path.to_owned(),
    }
}

fn supported_profile_source() -> StaticCapabilityProfileSource {
    StaticCapabilityProfileSource::new(CapabilityProfileFixture::supported())
}

fn wait_for_socket(child: &mut Child, socket_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if socket_path.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("inspect helper status") {
            panic!("unsupported-kernel helper exited before binding: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "helper did not bind control socket"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

struct KillOnDrop(Child);

impl KillOnDrop {
    fn child_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}")).expect("write script");
    let mut permissions = fs::metadata(path).expect("script metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("script permissions");
}
