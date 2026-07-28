#![cfg(any(target_os = "linux", target_os = "android"))]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use flux_core::{
    BootIdentityMutationStatus, ControlSnapshot, FailurePolicy, FluxConfig, KernelMutationStatus,
    MutationGate,
};
use flux_testkit::{CapabilityProfileFixture, StaticCapabilityProfileSource};
use fluxd::{DaemonOptions, SocketControlClient, run_daemon};
use tempfile::tempdir;

const PACKAGED_CONFIG: &str = include_str!("../../../conf/flux.toml");
const UNSUPPORTED_HELPER_ROOT: &str = "FLUXD_TEST_UNSUPPORTED_HELPER_ROOT";

#[test]
fn packaged_default_config_matches_the_strict_product_schema() {
    let config = FluxConfig::parse(PACKAGED_CONFIG).expect("packaged flux.toml must be valid");

    assert_eq!(config.schema(), 3);
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
    }
}

#[test]
fn unsupported_kernel_daemon_helper() {
    let Some(root) = env::var_os(UNSUPPORTED_HELPER_ROOT).map(PathBuf::from) else {
        return;
    };
    let run = root.join("run");
    let options = DaemonOptions {
        runtime_root: root.clone(),
        socket_path: run.join("fluxd.sock"),
        daemon_lease_path: run.join("fluxd.lease"),
        config_path: root.join("conf/flux.toml"),
        subscription_store_path: root.join("state/subscription"),
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
