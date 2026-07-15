use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use flux_platform::MAX_XTABLES_RESTORE_BYTES;
use fluxd::{
    LegacyRulesEnvironment, LegacyRulesFamilyShape, LegacyRulesSetManifest,
    run_legacy_package_snapshot_cli, run_legacy_rules_attestation_cli, run_legacy_rules_cli,
};

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
fn attestation_library_emits_one_exact_dual_stack_generation_manifest() {
    let environment = TestEnvironment::maximal();
    let artifacts = AttestationArtifacts::exact();
    let (exit, stdout, stderr) = run_attestation(&environment, &artifacts.arguments("7", true));

    assert_eq!(exit, 0, "{}", String::from_utf8_lossy(&stderr));
    assert!(stderr.is_empty());
    let manifest = LegacyRulesSetManifest::parse(&stdout).unwrap();
    assert_eq!(manifest.generation().get(), 7);
    assert_eq!(manifest.families(), LegacyRulesFamilyShape::Ipv4AndIpv6);
    assert_eq!(
        manifest.ipv4().apply().resource_totals().input_bytes(),
        include_bytes!("../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-apply.restore")
            .len()
    );
    assert_eq!(
        manifest
            .ipv6()
            .unwrap()
            .cleanup()
            .resource_totals()
            .input_bytes(),
        include_bytes!(
            "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv6-cleanup.restore"
        )
        .len()
    );
    assert_eq!(manifest.render_canonical().as_ref(), stdout);

    let text = String::from_utf8(stdout.clone()).unwrap();
    assert_eq!(text.lines().count(), 53);
    assert!(
        text.starts_with("FLUX_LEGACY_RULES_SET_MANIFEST_V1\ngeneration=7\nfamilies=ipv4,ipv6\n")
    );
    for expected in [
        "plan_digest=f5cc1f52f7f1938fa6a2ec94b5a46b35796b917e5903ecd8bfa62b591a5f2981",
        "set_digest=93e6f53c5f0c147893caab4c6d851102c38ab117cc435e19df4afa07da2406f3",
        "ipv4_pair_digest=272b226c3845d7289a87142d5950a2b05beb4f043751e37ff1f29e251e1e62de",
        "ipv4_apply_digest=1dc78d3a2a4121c1ef7aeecea1022af537e7268fde7ba94b8d891faac669e258",
        "ipv4_cleanup_digest=5f534cee13c17ac7c0974c9617aa4b0b8b82f8e183ed1994e8b84585f130a9a2",
        "ipv6_pair_digest=1d910292c0f4e11ec8435a8532d9d521c81a3af4a0b65aacbbe988c0b39366c4",
        "ipv6_apply_digest=5357fe418a5ab6baac75364bde87856d5f066c06eb373fbb12deb8e6cbb0b14d",
        "ipv6_cleanup_digest=a4ba1f5a955ee208932aec901dac94de56a6ee51966888dc1b53bc128fcd6fcc",
    ] {
        assert!(text.lines().any(|line| line == expected), "{expected}");
    }

    let (repeat_exit, repeat_stdout, repeat_stderr) =
        run_attestation(&environment, &artifacts.arguments("7", true));
    assert_eq!(repeat_exit, 0);
    assert!(repeat_stderr.is_empty());
    assert_eq!(repeat_stdout, stdout);
}

#[test]
fn attestation_real_binary_dispatches_before_socket_and_matches_library_output() {
    let environment = TestEnvironment::maximal();
    let artifacts = AttestationArtifacts::exact();
    let arguments = artifacts.arguments("11", true);
    let (library_exit, expected, library_stderr) = run_attestation(&environment, &arguments);
    assert_eq!(library_exit, 0);
    assert!(library_stderr.is_empty());

    let mut command = Command::new(env!("CARGO_BIN_EXE_fluxd"));
    environment.apply_to(&mut command);
    command
        .env("FLUXD_SOCKET", "/definitely/unusable/fluxd.sock")
        .args(&arguments);
    let output = command.output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, expected);
    assert_eq!(
        LegacyRulesSetManifest::parse(&output.stdout)
            .unwrap()
            .generation()
            .get(),
        11
    );
}

#[test]
fn attestation_rejects_byte_mismatch_without_library_or_binary_stdout() {
    let environment = TestEnvironment::maximal();
    let artifacts = AttestationArtifacts::exact();
    fs::write(&artifacts.ipv4_apply, b"*mangle\nCOMMIT\n").unwrap();
    let arguments = artifacts.arguments("9", true);

    let (exit, stdout, stderr) = run_attestation(&environment, &arguments);
    assert_eq!(exit, 1);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("does not exactly match canonical Rust output")
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_fluxd"));
    environment.apply_to(&mut command);
    command
        .env("FLUXD_SOCKET", "/definitely/unusable/fluxd.sock")
        .args(&arguments);
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("does not exactly match canonical Rust output")
    );
}

#[test]
fn attestation_requires_an_exact_ipv6_argument_pair_matching_the_environment() {
    let enabled = TestEnvironment::maximal();
    let artifacts = AttestationArtifacts::exact();

    let (exit, stdout, stderr) = run_attestation(&enabled, &artifacts.arguments("1", false));
    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("requires both --ipv6-apply and --ipv6-cleanup")
    );

    let mut mixed = artifacts.arguments("1", false);
    mixed.extend([
        "--ipv6-apply".to_owned(),
        artifacts.ipv6_apply.to_string_lossy().into_owned(),
    ]);
    let (exit, stdout, stderr) = run_attestation(&enabled, &mixed);
    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("requires both --ipv6-apply and --ipv6-cleanup")
    );

    let mut disabled = TestEnvironment::maximal();
    disabled.set("PROXY_IPV6", "0");
    let (exit, stdout, stderr) = run_attestation(&disabled, &artifacts.arguments("1", true));
    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("forbids --ipv6-apply and --ipv6-cleanup")
    );
}

#[test]
fn attestation_accepts_an_exact_ipv4_only_set_when_ipv6_is_disabled() {
    let mut environment = TestEnvironment::maximal();
    environment.set("PROXY_IPV6", "0");
    let artifacts = AttestationArtifacts::exact();

    let (exit, stdout, stderr) = run_attestation(&environment, &artifacts.arguments("8", false));
    assert_eq!(exit, 0, "{}", String::from_utf8_lossy(&stderr));
    assert!(stderr.is_empty());
    let manifest = LegacyRulesSetManifest::parse(&stdout).unwrap();
    assert_eq!(manifest.generation().get(), 8);
    assert_eq!(manifest.families(), LegacyRulesFamilyShape::Ipv4);
    assert!(manifest.ipv6().is_none());
    assert_eq!(String::from_utf8(stdout).unwrap().lines().count(), 32);
}

#[test]
fn attestation_rejects_duplicate_and_unknown_options_without_output() {
    let environment = TestEnvironment::maximal();
    let artifacts = AttestationArtifacts::exact();

    let mut duplicate = artifacts.arguments("3", true);
    duplicate.extend(["--generation".to_owned(), "4".to_owned()]);
    let mut unknown = artifacts.arguments("3", true);
    unknown.extend(["--unexpected".to_owned(), "value".to_owned()]);

    for (arguments, expected) in [
        (duplicate, "--generation was specified more than once"),
        (unknown, "unknown attest-legacy-rules-set option"),
    ] {
        let (exit, stdout, stderr) = run_attestation(&environment, &arguments);
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert!(String::from_utf8(stderr).unwrap().contains(expected));
    }
}

#[test]
fn attestation_rejects_nonregular_and_oversized_restore_artifacts() {
    let environment = TestEnvironment::maximal();
    let artifacts = AttestationArtifacts::exact();
    let oversized = artifacts.directory.path().join("oversized.restore");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(1024 * 1024 + 1)
        .unwrap();

    for (path, expected) in [
        (artifacts.directory.path(), "regular non-symlink"),
        (oversized.as_path(), "exceeds 1048576 bytes"),
    ] {
        let mut arguments = artifacts.arguments("12", true);
        replace_option(&mut arguments, "--ipv4-apply", path);
        let (exit, stdout, stderr) = run_attestation(&environment, &arguments);
        assert_eq!(exit, 1, "{}", path.display());
        assert!(stdout.is_empty(), "{}", path.display());
        assert!(
            String::from_utf8(stderr).unwrap().contains(expected),
            "{}",
            path.display()
        );
    }
}

#[cfg(unix)]
#[test]
fn attestation_rejects_a_symbolic_restore_artifact() {
    use std::os::unix::fs::symlink;

    let environment = TestEnvironment::maximal();
    let artifacts = AttestationArtifacts::exact();
    let link = artifacts.directory.path().join("apply-link.restore");
    symlink(&artifacts.ipv4_apply, &link).unwrap();
    let mut arguments = artifacts.arguments("13", true);
    replace_option(&mut arguments, "--ipv4-apply", &link);

    let (exit, stdout, stderr) = run_attestation(&environment, &arguments);
    assert_eq!(exit, 1);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("regular non-symlink")
    );
}

#[test]
fn attestation_rejects_noncanonical_or_out_of_range_generation_ids() {
    let environment = TestEnvironment::maximal();
    let artifacts = AttestationArtifacts::exact();
    for generation in ["0", "01", "2147483648", "-1", ""] {
        let (exit, stdout, stderr) =
            run_attestation(&environment, &artifacts.arguments(generation, true));
        assert_eq!(exit, 2, "{generation}");
        assert!(stdout.is_empty(), "{generation}");
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains("--generation must be a canonical integer"),
            "{generation}"
        );
    }
}

#[test]
fn strict_manifest_parser_rejects_noncanonical_and_inconsistent_totals() {
    let environment = TestEnvironment::maximal();
    let artifacts = AttestationArtifacts::exact();
    let (exit, manifest, stderr) = run_attestation(&environment, &artifacts.arguments("17", true));
    assert_eq!(exit, 0, "{}", String::from_utf8_lossy(&stderr));

    let inconsistent_pair = increment_manifest_field(&manifest, "ipv4_pair_input_bytes");
    let error = LegacyRulesSetManifest::parse(&inconsistent_pair).unwrap_err();
    assert!(error.to_string().contains("pair resource totals"));

    let inconsistent_set = increment_manifest_field(&manifest, "set_input_bytes");
    let error = LegacyRulesSetManifest::parse(&inconsistent_set).unwrap_err();
    assert!(error.to_string().contains("set resource totals"));

    let overflow =
        replace_manifest_field(&manifest, "ipv4_apply_input_bytes", &usize::MAX.to_string());
    let error = LegacyRulesSetManifest::parse(&overflow).unwrap_err();
    assert!(error.to_string().contains("artifact resource input_bytes"));
    assert!(error.to_string().contains("exceeds"));

    let mut missing_newline = manifest;
    assert_eq!(missing_newline.pop(), Some(b'\n'));
    assert!(
        LegacyRulesSetManifest::parse(&missing_newline)
            .unwrap_err()
            .to_string()
            .contains("must end with exactly one LF")
    );
}

#[test]
fn strict_manifest_parser_rejects_consistent_totals_above_artifact_limits() {
    let environment = TestEnvironment::maximal();
    let artifacts = AttestationArtifacts::exact();
    let (exit, manifest, stderr) = run_attestation(&environment, &artifacts.arguments("18", true));
    assert_eq!(exit, 0, "{}", String::from_utf8_lossy(&stderr));

    let oversized_apply = MAX_XTABLES_RESTORE_BYTES + 1;
    let cleanup = manifest_field(&manifest, "ipv4_cleanup_input_bytes");
    let ipv6_pair = manifest_field(&manifest, "ipv6_pair_input_bytes");
    let ipv4_pair = oversized_apply + cleanup;
    let set = ipv4_pair + ipv6_pair;
    let manifest = replace_manifest_fields(
        &manifest,
        &[
            ("ipv4_apply_input_bytes", oversized_apply),
            ("ipv4_pair_input_bytes", ipv4_pair),
            ("set_input_bytes", set),
        ],
    );

    let error = LegacyRulesSetManifest::parse(&manifest).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("artifact resource input_bytes=1048577 exceeds 1048576"),
        "{error}",
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

struct AttestationArtifacts {
    directory: tempfile::TempDir,
    ipv4_apply: PathBuf,
    ipv4_cleanup: PathBuf,
    ipv6_apply: PathBuf,
    ipv6_cleanup: PathBuf,
}

impl AttestationArtifacts {
    fn exact() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let ipv4_apply = directory.path().join("ipv4-apply.restore");
        let ipv4_cleanup = directory.path().join("ipv4-cleanup.restore");
        let ipv6_apply = directory.path().join("ipv6-apply.restore");
        let ipv6_cleanup = directory.path().join("ipv6-cleanup.restore");
        for (path, bytes) in [
            (
                &ipv4_apply,
                include_bytes!(
                    "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-apply.restore"
                )
                .as_slice(),
            ),
            (
                &ipv4_cleanup,
                include_bytes!(
                    "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-cleanup.restore"
                )
                .as_slice(),
            ),
            (
                &ipv6_apply,
                include_bytes!(
                    "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv6-apply.restore"
                )
                .as_slice(),
            ),
            (
                &ipv6_cleanup,
                include_bytes!(
                    "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv6-cleanup.restore"
                )
                .as_slice(),
            ),
        ] {
            fs::write(path, bytes).unwrap();
        }
        Self {
            directory,
            ipv4_apply,
            ipv4_cleanup,
            ipv6_apply,
            ipv6_cleanup,
        }
    }

    fn arguments(&self, generation: &str, include_ipv6: bool) -> Vec<String> {
        let mut arguments = vec![
            "attest-legacy-rules-set".to_owned(),
            "--generation".to_owned(),
            generation.to_owned(),
            "--packages-list".to_owned(),
            oracle_packages().to_string_lossy().into_owned(),
            "--ipv4-apply".to_owned(),
            self.ipv4_apply.to_string_lossy().into_owned(),
            "--ipv4-cleanup".to_owned(),
            self.ipv4_cleanup.to_string_lossy().into_owned(),
        ];
        if include_ipv6 {
            arguments.extend([
                "--ipv6-apply".to_owned(),
                self.ipv6_apply.to_string_lossy().into_owned(),
                "--ipv6-cleanup".to_owned(),
                self.ipv6_cleanup.to_string_lossy().into_owned(),
            ]);
        }
        arguments
    }
}

fn run_attestation(environment: &TestEnvironment, arguments: &[String]) -> (i32, Vec<u8>, Vec<u8>) {
    let mut args = Vec::with_capacity(arguments.len() + 1);
    args.push("fluxd".to_owned());
    args.extend_from_slice(arguments);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_legacy_rules_attestation_cli(&args, environment, &mut stdout, &mut stderr);
    (exit, stdout, stderr)
}

fn replace_option(arguments: &mut [String], name: &str, value: &Path) {
    let index = arguments
        .iter()
        .position(|argument| argument == name)
        .expect("test option must exist");
    arguments[index + 1] = value.to_string_lossy().into_owned();
}

fn increment_manifest_field(manifest: &[u8], name: &str) -> Vec<u8> {
    let value = manifest_field(manifest, name) + 1;
    replace_manifest_field(manifest, name, &value.to_string())
}

fn manifest_field(manifest: &[u8], name: &str) -> usize {
    let prefix = format!("{name}=");
    std::str::from_utf8(manifest)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap()
        .parse()
        .unwrap()
}

fn replace_manifest_fields(manifest: &[u8], replacements: &[(&str, usize)]) -> Vec<u8> {
    replacements
        .iter()
        .fold(manifest.to_vec(), |manifest, (name, value)| {
            replace_manifest_field(&manifest, name, &value.to_string())
        })
}

fn replace_manifest_field(manifest: &[u8], name: &str, replacement: &str) -> Vec<u8> {
    let text = std::str::from_utf8(manifest).unwrap();
    let prefix = format!("{name}=");
    let mut replaced = false;
    let mut output = String::with_capacity(text.len() + 1);
    for line in text.lines() {
        if line.starts_with(&prefix) {
            output.push_str(&format!("{prefix}{replacement}\n"));
            replaced = true;
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    assert!(replaced, "manifest field {name} must exist");
    output.into_bytes()
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
