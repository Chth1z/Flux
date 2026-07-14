use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use fluxd::{LegacyRulesEnvironment, run_legacy_package_snapshot_cli, run_legacy_rules_cli};

#[derive(Default)]
struct TestEnvironment(BTreeMap<&'static str, OsString>);

impl TestEnvironment {
    fn maximal() -> Self {
        let mut values = BTreeMap::new();
        for (name, value) in [
            ("PROXY_MODE", "tproxy"),
            ("RULE_BACKEND", "iptables_restore"),
            ("BYPASS_SET_BACKEND", "zone"),
            ("PROXY_PORT", "1536"),
            ("MARK_MASK", "0xff"),
            ("IPV4_MARK", "0x14"),
            ("IPV6_MARK", "0x19"),
            ("BYPASS_MARK", "0x11"),
            ("ROUTING_MARK", ""),
            ("CORE_USER", "1000"),
            ("CORE_GROUP", "1000"),
            ("APP_PROXY_MODE", "2"),
            ("APP_LIST", "com.example.alpha com.example.beta"),
            ("APP_USER_SCOPE", "list"),
            ("APP_USER_LIST", "10 2 10"),
            ("EXCLUDE_INTERFACES", "wlan+ rmnet+ wlan+"),
            ("MOBILE_INTERFACE", "rmnet_data+"),
            ("PROXY_MOBILE", "1"),
            ("WIFI_INTERFACE", "wlan0"),
            ("PROXY_WIFI", "0"),
            ("HOTSPOT_INTERFACE", "wlan2"),
            ("PROXY_HOTSPOT", "1"),
            ("USB_INTERFACE", "rndis+"),
            ("PROXY_USB", "0"),
            ("PERFORMANCE_MODE", "1"),
            ("MSS_CLAMP_ENABLE", "1"),
            ("PROXY_IPV6", "1"),
            ("FAKEIP_V4_RANGE", "198.18.0.0/15"),
            ("FAKEIP_V6_RANGE", "fc00::/18"),
            ("KFEAT_OWNER", "1"),
            ("KFEAT_MARK", "1"),
            ("KFEAT_CONNTRACK", "1"),
            ("KFEAT_SOCKET_TCP", "1"),
            ("KFEAT_SOCKET_UDP", "0"),
            ("KFEAT_IPV6_NAT", "1"),
            ("KFEAT_TPROXY", "1"),
        ] {
            values.insert(name, value.into());
        }
        Self(values)
    }

    fn set(&mut self, name: &'static str, value: &str) {
        self.0.insert(name, value.into());
    }

    fn apply_to(&self, command: &mut Command) {
        command.env_clear();
        for (name, value) in &self.0 {
            command.env(name, value);
        }
    }
}

impl LegacyRulesEnvironment for TestEnvironment {
    fn value(&self, name: &'static str) -> Option<OsString> {
        self.0.get(name).cloned()
    }
}

#[test]
fn maximal_environment_renders_the_pinned_ipv4_apply_bytes() {
    let environment = TestEnvironment::maximal();
    let packages = oracle_packages();
    let (exit, stdout, stderr) = run(&environment, &packages, "4", "apply");

    assert_eq!(exit, 0, "{}", String::from_utf8_lossy(&stderr));
    assert!(stderr.is_empty());
    assert_eq!(
        stdout,
        include_bytes!("../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-apply.restore")
    );
}

#[test]
fn real_binary_dispatches_before_daemon_socket_use_and_emits_exact_bytes() {
    let environment = TestEnvironment::maximal();
    let mut command = Command::new(env!("CARGO_BIN_EXE_fluxd"));
    environment.apply_to(&mut command);
    command
        .env("FLUXD_SOCKET", "/definitely/unusable/fluxd.sock")
        .args([
            "render-legacy-rules",
            "--packages-list",
            oracle_packages().to_str().unwrap(),
            "--family",
            "4",
            "--action",
            "apply",
        ]);
    let output = command.output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        include_bytes!("../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-apply.restore")
    );
}

#[test]
fn package_snapshot_library_and_real_binary_emit_exact_source_bytes() {
    let source = oracle_packages();
    let expected = fs::read(&source).unwrap();
    let args = [
        "fluxd",
        "snapshot-legacy-packages",
        "--source",
        source.to_str().unwrap(),
    ];
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_legacy_package_snapshot_cli(args, &mut stdout, &mut stderr);
    assert_eq!(exit, 0, "{}", String::from_utf8_lossy(&stderr));
    assert!(stderr.is_empty());
    assert_eq!(stdout, expected);

    let output = Command::new(env!("CARGO_BIN_EXE_fluxd"))
        .env_clear()
        .env("FLUXD_SOCKET", "/definitely/unusable/fluxd.sock")
        .args([
            "snapshot-legacy-packages",
            "--source",
            source.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, expected);
}

#[test]
fn package_snapshot_rejects_nonregular_oversized_and_non_utf8_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let oversized = directory.path().join("oversized.list");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(4 * 1024 * 1024 + 1)
        .unwrap();
    let non_utf8 = directory.path().join("non-utf8.list");
    fs::write(&non_utf8, [0xff]).unwrap();

    for (path, expected) in [
        (directory.path(), "regular non-symlink"),
        (oversized.as_path(), "exceeds 4194304 bytes"),
        (non_utf8.as_path(), "is not valid UTF-8"),
    ] {
        let path = path.to_string_lossy().into_owned();
        let args = [
            "fluxd",
            "snapshot-legacy-packages",
            "--source",
            path.as_str(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_legacy_package_snapshot_cli(args, &mut stdout, &mut stderr);
        assert_eq!(exit, 1, "{path}");
        assert!(stdout.is_empty(), "{path}");
        assert!(
            String::from_utf8(stderr).unwrap().contains(expected),
            "{path}"
        );
    }
}

#[cfg(unix)]
#[test]
fn package_snapshot_rejects_a_symbolic_source() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let link = directory.path().join("packages.list");
    symlink(oracle_packages(), &link).unwrap();
    let path = link.to_string_lossy().into_owned();
    let args = [
        "fluxd",
        "snapshot-legacy-packages",
        "--source",
        path.as_str(),
    ];
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_legacy_package_snapshot_cli(args, &mut stdout, &mut stderr);

    assert_eq!(exit, 1);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("regular non-symlink")
    );
}

#[test]
fn maximal_environment_renders_the_pinned_ipv6_cleanup_without_reading_packages() {
    let environment = TestEnvironment::maximal();
    let missing = PathBuf::from("/definitely/missing/flux-packages.list");
    let (exit, stdout, stderr) = run(&environment, &missing, "6", "cleanup");

    assert_eq!(exit, 0, "{}", String::from_utf8_lossy(&stderr));
    assert!(stderr.is_empty());
    assert_eq!(
        stdout,
        include_bytes!(
            "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv6-cleanup.restore"
        )
    );
}

#[test]
fn disabled_application_filter_does_not_read_the_packages_path() {
    let mut environment = TestEnvironment::maximal();
    environment.set("APP_PROXY_MODE", "0");
    environment.set("APP_LIST", "");
    let missing = PathBuf::from("/definitely/missing/flux-packages.list");
    let (exit, stdout, stderr) = run(&environment, &missing, "4", "apply");

    assert_eq!(exit, 0, "{}", String::from_utf8_lossy(&stderr));
    let text = String::from_utf8(stdout).unwrap();
    assert!(text.contains("-A APP_CHAIN -j RETURN\n"));
    assert!(!text.contains("--uid-owner 210124"));
}

#[test]
fn unsupported_bridge_and_kernel_profiles_fail_before_output() {
    for (name, value, expected) in [
        ("PROXY_MODE", "tun", "PROXY_MODE=tun"),
        ("RULE_BACKEND", "nft", "RULE_BACKEND=nft"),
        ("BYPASS_SET_BACKEND", "ipset", "BYPASS_SET_BACKEND=ipset"),
        ("MARK_MASK", "0x1d", "MARK_MASK=0x1d"),
        ("KFEAT_OWNER", "0", "KFEAT_OWNER=0"),
        ("KFEAT_TPROXY", "0", "KFEAT_TPROXY=0"),
    ] {
        let mut environment = TestEnvironment::maximal();
        environment.set(name, value);
        let (exit, stdout, stderr) = run(&environment, &oracle_packages(), "4", "apply");
        assert_eq!(exit, 3, "{name}");
        assert!(stdout.is_empty(), "{name}");
        assert!(
            String::from_utf8(stderr).unwrap().contains(expected),
            "{name}"
        );
    }
}

#[test]
fn resolved_application_uid_expansion_fails_at_the_shared_bound() {
    let directory = tempfile::tempdir().unwrap();
    let packages = directory.path().join("packages.list");
    let mut contents = String::new();
    for uid in 10_000..10_201 {
        contents.push_str(&format!("com.example.alpha {uid}\n"));
    }
    fs::write(&packages, contents).unwrap();
    let mut environment = TestEnvironment::maximal();
    environment.set("APP_LIST", "com.example.alpha");
    environment.set("APP_USER_SCOPE", "all");
    let (exit, stdout, stderr) = run(&environment, &packages, "4", "apply");

    assert_eq!(exit, 1);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("resolved application UID count exceeds 20000")
    );
}

#[test]
fn renderer_uses_environment_marks_and_rejects_unsafe_combinations() {
    let mut custom = TestEnvironment::maximal();
    custom.set("IPV4_MARK", "0x24");
    custom.set("IPV6_MARK", "0x29");
    custom.set("BYPASS_MARK", "0x21");
    let (exit, stdout, stderr) = run(&custom, &oracle_packages(), "4", "apply");
    assert_eq!(exit, 0, "{}", String::from_utf8_lossy(&stderr));
    let text = String::from_utf8(stdout).unwrap();
    assert!(text.contains("--set-xmark 0x21/0xff"));
    assert!(text.contains("--tproxy-mark 0x24/0xff"));
    assert!(!text.contains("--tproxy-mark 0x14/0xff"));

    for (name, value) in [("BYPASS_MARK", "0x14"), ("IPV4_MARK", "0x114")] {
        let mut unsafe_environment = TestEnvironment::maximal();
        unsafe_environment.set(name, value);
        let (exit, stdout, stderr) = run(&unsafe_environment, &oracle_packages(), "4", "apply");
        assert_eq!(exit, 1, "{name}");
        assert!(stdout.is_empty(), "{name}");
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains("mark mask must contain and distinguish"),
            "{name}"
        );
    }
}

#[test]
fn malformed_environment_is_rejected_without_partial_restore_output() {
    for (name, value) in [
        ("PROXY_PORT", "0"),
        ("MARK_MASK", "0"),
        ("PROXY_WIFI", "true"),
        ("APP_USER_LIST", "1000"),
        ("CORE_USER", "-1"),
        ("MOBILE_INTERFACE", "rmnet++"),
    ] {
        let mut environment = TestEnvironment::maximal();
        environment.set(name, value);
        let (exit, stdout, stderr) = run(&environment, &oracle_packages(), "4", "apply");
        assert_eq!(exit, 1, "{name}");
        assert!(stdout.is_empty(), "{name}");
        assert!(!stderr.is_empty(), "{name}");
    }
}

#[cfg(unix)]
#[test]
fn selected_application_filter_rejects_a_symbolic_package_list() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let link = directory.path().join("packages.list");
    symlink(oracle_packages(), &link).unwrap();
    let environment = TestEnvironment::maximal();
    let (exit, stdout, stderr) = run(&environment, &link, "4", "apply");

    assert_eq!(exit, 1);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("regular non-symlink")
    );
}

#[test]
fn argument_contract_rejects_duplicates_and_unknown_values() {
    let environment = TestEnvironment::maximal();
    for args in [
        vec!["fluxd", "render-legacy-rules", "--family", "4"],
        vec![
            "fluxd",
            "render-legacy-rules",
            "--packages-list",
            "/tmp/packages.list",
            "--family",
            "5",
            "--action",
            "apply",
        ],
        vec![
            "fluxd",
            "render-legacy-rules",
            "--packages-list",
            "/tmp/packages.list",
            "--family",
            "4",
            "--family",
            "6",
            "--action",
            "apply",
        ],
    ] {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_legacy_rules_cli(args, &environment, &mut stdout, &mut stderr);
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert!(String::from_utf8(stderr).unwrap().contains("Usage:"));
    }
}

fn run(
    environment: &TestEnvironment,
    packages: &Path,
    family: &str,
    action: &str,
) -> (i32, Vec<u8>, Vec<u8>) {
    let packages = packages.to_string_lossy().into_owned();
    let args = [
        "fluxd",
        "render-legacy-rules",
        "--packages-list",
        packages.as_str(),
        "--family",
        family,
        "--action",
        action,
    ];
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_legacy_rules_cli(args, environment, &mut stdout, &mut stderr);
    (exit, stdout, stderr)
}

fn oracle_packages() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/oracle/xtables/packages.list")
}
