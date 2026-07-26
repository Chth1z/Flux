use std::error::Error;
use std::fs;
use std::io;
use std::time::Duration;

use flux_core::{
    AndroidUserSelection, CaptureApplicationMode, CaptureBackend, CaptureTrafficDomain,
    CaptureTransportProtocol, ConfigErrorKind, FailurePolicy, FluxConfig, NetworkAddressFamily,
};

const COMPLETE_CONFIG: &str = include_str!("../../../conf/flux.toml");

#[test]
fn parses_the_complete_desired_state_schema() {
    let config = FluxConfig::parse(COMPLETE_CONFIG).expect("complete schema should parse");

    assert_eq!(config.schema(), 3);
    assert_eq!(config.daemon().fail_policy(), FailurePolicy::Open);
    assert_eq!(
        config.daemon().reconcile_debounce().get(),
        Duration::from_millis(250)
    );
    assert_eq!(config.daemon().event_queue_capacity().get(), 256);
    assert_eq!(config.daemon().generation_history().get(), 2);
    assert_eq!(
        config.engine().binary().to_str(),
        Some("/data/adb/flux/bin/sing-box")
    );
    assert_eq!(config.engine().credentials().uid().get(), 0);
    assert_eq!(config.engine().credentials().gid().get(), 0);
    assert_eq!(config.capture().backend(), CaptureBackend::Xtables);
    assert!(
        config
            .capture()
            .scope()
            .includes_domain(CaptureTrafficDomain::LocalOutput)
    );
    assert!(
        config
            .capture()
            .scope()
            .includes_domain(CaptureTrafficDomain::ForwardedIngress)
    );
    assert!(
        config
            .capture()
            .scope()
            .includes_family(NetworkAddressFamily::Ipv4)
    );
    assert!(
        !config
            .capture()
            .scope()
            .includes_family(NetworkAddressFamily::Ipv6)
    );
    assert!(
        config
            .capture()
            .protocols()
            .contains(CaptureTransportProtocol::Tcp)
    );
    assert!(
        config
            .capture()
            .protocols()
            .contains(CaptureTransportProtocol::Udp)
    );
    assert_eq!(config.listener().port().get(), 1536);
    assert_eq!(config.applications().mode(), CaptureApplicationMode::All);
    assert_eq!(
        config.applications().android_users(),
        &AndroidUserSelection::Owner
    );
    assert!(config.applications().packages().is_empty());
    assert_eq!(config.interfaces().policy().forwarded_proxy().len(), 4);
    assert!(config.bypass().policy().prefixes().is_empty());
    assert!(!config.subscription().enabled());
    assert_eq!(config.subscription().max_download_bytes(), 16_777_216);
    assert_eq!(config.subscription().max_decoded_bytes(), 16_777_216);
    assert_eq!(config.subscription().max_nodes(), 10_000);
    assert!(!config.safety().respect_android_vpn());
    assert!(!config.safety().require_functional_canary());
}

#[test]
fn defers_closed_failure_policy_until_schema_has_a_safety_acknowledgement() {
    let input = COMPLETE_CONFIG.replacen("fail_policy = \"open\"", "fail_policy = \"closed\"", 1);

    let error = FluxConfig::parse(&input).expect_err("schema 3 cannot honor fail-closed safely");

    assert!(matches!(
        error.kind(),
        ConfigErrorKind::UnsupportedFailurePolicy { policy: "closed" }
    ));
}

#[test]
fn rejects_an_undocumented_failure_policy() {
    let input = COMPLETE_CONFIG.replacen("fail_policy = \"open\"", "fail_policy = \"repair\"", 1);

    let error = FluxConfig::parse(&input).expect_err("only open and closed are documented");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
}

#[test]
fn requires_the_schema_field() {
    let input = COMPLETE_CONFIG.replacen("schema = 3\n\n", "", 1);

    let error = FluxConfig::parse(&input).expect_err("schema is mandatory");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
}

#[test]
fn requires_every_daemon_field() {
    for field in [
        "fail_policy = \"open\"\n",
        "reconcile_debounce_ms = 250\n",
        "event_queue_capacity = 256\n",
        "generation_history = 2\n",
    ] {
        let input = COMPLETE_CONFIG.replacen(field, "", 1);

        assert!(
            FluxConfig::parse(&input).is_err(),
            "removing {field:?} must make the document invalid"
        );
    }
}

#[test]
fn rejects_duplicate_fields() {
    let input = COMPLETE_CONFIG.replacen("schema = 3", "schema = 3\nschema = 3", 1);

    let error = FluxConfig::parse(&input).expect_err("duplicate fields are ambiguous");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
}

#[test]
fn rejects_an_unsupported_schema_version() {
    let input = COMPLETE_CONFIG.replacen("schema = 3", "schema = 4", 1);

    let error = FluxConfig::parse(&input).expect_err("schema 4 is not supported");

    assert!(matches!(
        error.kind(),
        ConfigErrorKind::UnsupportedSchema {
            found: 4,
            supported: 3
        }
    ));
}

#[test]
fn rejects_unknown_top_level_sections() {
    let input = format!("{COMPLETE_CONFIG}\n[unknown]\nvalue = true\n");

    let error = FluxConfig::parse(&input).expect_err("unknown sections must fail");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
}

#[test]
fn rejects_unknown_daemon_fields() {
    let input = COMPLETE_CONFIG.replacen(
        "generation_history = 2",
        "generation_history = 2\nworker_threads = 4",
        1,
    );

    let error = FluxConfig::parse(&input).expect_err("schema 3 has no worker_threads setting");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
}

#[test]
fn requires_every_complete_desired_state_section() {
    for section in [
        "engine",
        "capture",
        "listener",
        "applications",
        "interfaces",
        "bypass",
        "subscription",
        "safety",
    ] {
        let input = without_section(COMPLETE_CONFIG, section);
        let error = FluxConfig::parse(&input)
            .expect_err("every complete Desired State section must be required");
        assert_eq!(
            error.kind(),
            ConfigErrorKind::InvalidToml,
            "removing [{section}] must fail"
        );
    }
}

#[test]
fn admits_only_the_explicit_xtables_backend() {
    for backend in ["auto", "nftables", "tun", "iptables_restore"] {
        let input = COMPLETE_CONFIG.replacen(
            "backend = \"xtables\"",
            &format!("backend = \"{backend}\""),
            1,
        );
        let error = FluxConfig::parse(&input).expect_err("deferred backend must fail closed");
        assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
    }
}

#[test]
fn capture_requires_a_family_domain_and_transport() {
    for (first, second, expected_field) in [
        ("ipv4 = true", "ipv4 = false", "capture.ipv4"),
        (
            "local_output = true",
            "local_output = false",
            "capture.local_output",
        ),
        ("tcp = true", "tcp = false", "capture.tcp"),
    ] {
        let mut input = COMPLETE_CONFIG.replacen(first, second, 1);
        input = match expected_field {
            "capture.ipv4" => input,
            "capture.local_output" => {
                input.replacen("forwarded_ingress = true", "forwarded_ingress = false", 1)
            }
            "capture.tcp" => input.replacen("udp = true", "udp = false", 1),
            _ => unreachable!(),
        };
        assert_invalid_field(&input, expected_field);
    }
}

#[test]
fn engine_paths_identities_and_restart_policy_are_bounded() {
    let relative = COMPLETE_CONFIG.replacen(
        "binary = \"/data/adb/flux/bin/sing-box\"",
        "binary = \"bin/sing-box\"",
        1,
    );
    assert_invalid_field(&relative, "engine.binary");

    let reserved_uid = COMPLETE_CONFIG.replacen("runtime_uid = 0", "runtime_uid = 4294967295", 1);
    assert!(matches!(
        FluxConfig::parse(&reserved_uid)
            .expect_err("reserved UID must fail")
            .kind(),
        ConfigErrorKind::ValueOutOfRange {
            field: "engine.runtime_uid",
            maximum: 4_294_967_294,
            ..
        }
    ));

    let reversed_backoff = COMPLETE_CONFIG.replacen(
        "restart_initial_backoff_ms = 1000",
        "restart_initial_backoff_ms = 30001",
        1,
    );
    assert_invalid_field(&reversed_backoff, "engine.restart_initial_backoff_ms");
}

#[test]
fn application_and_android_user_intent_is_not_silently_ignored() {
    let ignored_packages =
        COMPLETE_CONFIG.replacen("packages = []", "packages = [\"com.example.app\"]", 1);
    assert_invalid_field(&ignored_packages, "applications.packages");

    let empty_list =
        COMPLETE_CONFIG.replacen("android_users = \"owner\"", "android_users = \"list\"", 1);
    assert_invalid_field(&empty_list, "applications.user_ids");

    let explicit = COMPLETE_CONFIG
        .replacen("mode = \"all\"", "mode = \"allowlist\"", 1)
        .replacen("android_users = \"owner\"", "android_users = \"list\"", 1)
        .replacen("user_ids = []", "user_ids = [10, 0]", 1)
        .replacen(
            "packages = []",
            "packages = [\"com.example.second\", \"com.example.app\"]",
            1,
        );
    let config = FluxConfig::parse(&explicit).expect("bounded explicit app policy must parse");
    assert_eq!(
        config.applications().android_users().explicit_user_ids(),
        Some([0, 10].as_slice())
    );
    assert_eq!(
        config
            .applications()
            .packages()
            .iter()
            .map(|package| package.as_str())
            .collect::<Vec<_>>(),
        ["com.example.app", "com.example.second"]
    );
}

#[test]
fn interface_roles_require_bounded_unambiguous_patterns() {
    let ambiguous = COMPLETE_CONFIG.replacen("local_bypass = []", "local_bypass = [\"wlan0\"]", 1);
    assert_invalid_field(&ambiguous, "interfaces.local_bypass");

    let wildcard = COMPLETE_CONFIG.replacen("rmnet_data*", "rmnet*data", 1);
    assert_invalid_field(&wildcard, "interfaces.forwarded_proxy");

    let too_long = COMPLETE_CONFIG.replacen("wlan0", "interface-name-too-long", 1);
    assert_invalid_field(&too_long, "interfaces.forwarded_proxy");
}

#[test]
fn bypass_cidrs_are_canonical_and_duplicate_free() {
    let valid = COMPLETE_CONFIG.replacen(
        "cidrs = []",
        "cidrs = [\"10.0.0.0/8\", \"2001:db8::/32\"]",
        1,
    );
    let config = FluxConfig::parse(&valid).expect("canonical dual-family CIDRs must parse");
    assert_eq!(config.bypass().policy().prefixes().len(), 2);

    let host_bits = COMPLETE_CONFIG.replacen("cidrs = []", "cidrs = [\"10.1.2.3/8\"]", 1);
    assert_invalid_field(&host_bits, "bypass.cidrs");

    let duplicate =
        COMPLETE_CONFIG.replacen("cidrs = []", "cidrs = [\"10.0.0.0/8\", \"10.0.0.0/8\"]", 1);
    assert_invalid_field(&duplicate, "bypass.cidrs");
}

#[test]
fn listener_and_subscription_resources_are_bounded() {
    let zero_port = COMPLETE_CONFIG.replacen("port = 1536", "port = 0", 1);
    assert!(matches!(
        FluxConfig::parse(&zero_port)
            .expect_err("zero port must fail")
            .kind(),
        ConfigErrorKind::ValueOutOfRange {
            field: "listener.port",
            ..
        }
    ));

    let oversized_download = COMPLETE_CONFIG.replacen(
        "max_download_bytes = 16777216",
        "max_download_bytes = 67108865",
        1,
    );
    assert!(matches!(
        FluxConfig::parse(&oversized_download)
            .expect_err("oversized subscription must fail")
            .kind(),
        ConfigErrorKind::ValueOutOfRange {
            field: "subscription.max_download_bytes",
            maximum: 67_108_864,
            ..
        }
    ));

    let oversized_decoded = COMPLETE_CONFIG.replacen(
        "max_decoded_bytes = 16777216",
        "max_decoded_bytes = 67108865",
        1,
    );
    assert!(matches!(
        FluxConfig::parse(&oversized_decoded)
            .expect_err("oversized decoded subscription must fail")
            .kind(),
        ConfigErrorKind::ValueOutOfRange {
            field: "subscription.max_decoded_bytes",
            maximum: 67_108_864,
            ..
        }
    ));
}

#[test]
fn rejects_a_zero_reconcile_debounce() {
    let input = COMPLETE_CONFIG.replacen(
        "reconcile_debounce_ms = 250",
        "reconcile_debounce_ms = 0",
        1,
    );

    let error = FluxConfig::parse(&input).expect_err("debounce must be positive");

    assert!(matches!(
        error.kind(),
        ConfigErrorKind::ValueOutOfRange {
            field: "daemon.reconcile_debounce_ms",
            value: 0,
            minimum: 1,
            maximum: 4_294_967_295,
        }
    ));
}

#[test]
fn rejects_a_zero_event_queue_capacity() {
    let input =
        COMPLETE_CONFIG.replacen("event_queue_capacity = 256", "event_queue_capacity = 0", 1);

    let error = FluxConfig::parse(&input).expect_err("event queue must be bounded and non-empty");

    assert!(matches!(
        error.kind(),
        ConfigErrorKind::ValueOutOfRange {
            field: "daemon.event_queue_capacity",
            value: 0,
            minimum: 1,
            maximum: 4_096,
        }
    ));
}

#[test]
fn rejects_a_zero_generation_history() {
    let input = COMPLETE_CONFIG.replacen("generation_history = 2", "generation_history = 0", 1);

    let error = FluxConfig::parse(&input).expect_err("at least one generation must be retained");

    assert!(matches!(
        error.kind(),
        ConfigErrorKind::ValueOutOfRange {
            field: "daemon.generation_history",
            value: 0,
            minimum: 1,
            maximum: 32,
        }
    ));
}

#[test]
fn rejects_a_reconcile_debounce_larger_than_u32_milliseconds() {
    let input = COMPLETE_CONFIG.replacen(
        "reconcile_debounce_ms = 250",
        "reconcile_debounce_ms = 4294967296",
        1,
    );

    let error = FluxConfig::parse(&input).expect_err("debounce representation is bounded");

    assert!(matches!(
        error.kind(),
        ConfigErrorKind::ValueOutOfRange {
            field: "daemon.reconcile_debounce_ms",
            value: 4_294_967_296,
            maximum: 4_294_967_295,
            ..
        }
    ));
}

#[test]
fn rejects_an_event_queue_capacity_above_the_phase_one_resource_budget() {
    let input = COMPLETE_CONFIG.replacen(
        "event_queue_capacity = 256",
        "event_queue_capacity = 4097",
        1,
    );

    let error = FluxConfig::parse(&input).expect_err("queue representation is bounded");

    assert!(matches!(
        error.kind(),
        ConfigErrorKind::ValueOutOfRange {
            field: "daemon.event_queue_capacity",
            value: 4_097,
            maximum: 4_096,
            ..
        }
    ));
}

#[test]
fn rejects_generation_history_above_the_phase_one_resource_budget() {
    let input = COMPLETE_CONFIG.replacen("generation_history = 2", "generation_history = 33", 1);

    let error = FluxConfig::parse(&input).expect_err("history representation is bounded");

    assert!(matches!(
        error.kind(),
        ConfigErrorKind::ValueOutOfRange {
            field: "daemon.generation_history",
            value: 33,
            maximum: 32,
            ..
        }
    ));
}

#[test]
fn accepts_the_phase_one_resource_budget_boundaries() {
    let input = COMPLETE_CONFIG
        .replacen(
            "event_queue_capacity = 256",
            "event_queue_capacity = 4096",
            1,
        )
        .replacen("generation_history = 2", "generation_history = 32", 1);

    let config = FluxConfig::parse(&input).expect("resource budget boundaries are inclusive");

    assert_eq!(config.daemon().event_queue_capacity().get(), 4_096);
    assert_eq!(config.daemon().generation_history().get(), 32);
}

#[test]
fn loads_configuration_from_a_file() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("phase-one-flux.toml");
    fs::write(&path, COMPLETE_CONFIG).expect("write config fixture");

    let config = FluxConfig::load(&path).expect("load config fixture");

    assert_eq!(config.daemon().fail_policy(), FailurePolicy::Open);
    fs::remove_file(path).expect("remove config fixture");
}

#[test]
fn loads_configuration_from_a_relative_path() {
    let directory = tempfile::tempdir_in(".").expect("relative temporary directory");
    let absolute_path = directory.path().join("phase-one-flux.toml");
    let current_directory = std::env::current_dir().expect("current directory");
    let path = absolute_path
        .strip_prefix(current_directory)
        .expect("temporary directory is below the current directory");
    fs::write(&absolute_path, COMPLETE_CONFIG).expect("write relative config fixture");

    let config = FluxConfig::load(path).expect("load relative config fixture");

    assert_eq!(config.daemon().fail_policy(), FailurePolicy::Open);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn load_rejects_a_symbolic_link_without_following_it() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("temporary directory");
    let target = directory.path().join("target.toml");
    let link = directory.path().join("flux.toml");
    fs::write(&target, COMPLETE_CONFIG).expect("write target configuration");
    symlink(&target, &link).expect("create configuration symlink");

    let error = FluxConfig::load(&link).expect_err("configuration symlinks must be rejected");

    assert_eq!(error.kind(), ConfigErrorKind::UnsafeFileType);
    assert_eq!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<io::Error>())
            .and_then(io::Error::raw_os_error),
        Some(libc::ELOOP)
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn load_rejects_a_symbolic_link_in_an_ancestor_component() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("temporary directory");
    let real_parent = directory.path().join("real-parent");
    let linked_parent = directory.path().join("linked-parent");
    fs::create_dir(&real_parent).expect("create real configuration parent");
    fs::write(real_parent.join("flux.toml"), COMPLETE_CONFIG).expect("write target configuration");
    symlink(&real_parent, &linked_parent).expect("create ancestor symlink");

    let error = FluxConfig::load(linked_parent.join("flux.toml"))
        .expect_err("ancestor symlinks must be rejected");
    let raw_os_error = error
        .source()
        .and_then(|source| source.downcast_ref::<io::Error>())
        .and_then(io::Error::raw_os_error);

    assert_eq!(error.kind(), ConfigErrorKind::UnsafeFileType);
    assert!(
        matches!(raw_os_error, Some(libc::ELOOP) | Some(libc::ENOTDIR)),
        "unexpected ancestor-symlink error: {raw_os_error:?}"
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn load_rejects_parent_directory_components() {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::create_dir(directory.path().join("child")).expect("create child directory");
    fs::write(directory.path().join("flux.toml"), COMPLETE_CONFIG)
        .expect("write target configuration");
    let path = directory.path().join("child/../flux.toml");

    let error = FluxConfig::load(path).expect_err("parent traversal must be rejected");

    assert_eq!(error.kind(), ConfigErrorKind::UnsafeFileType);
    assert_eq!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<io::Error>())
            .map(io::Error::kind),
        Some(io::ErrorKind::InvalidInput)
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn load_rejects_a_fifo_without_blocking() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::mpsc;
    use std::time::Duration;

    let directory = tempfile::tempdir().expect("temporary directory");
    let fifo = directory.path().join("flux.toml");
    let fifo_name = CString::new(fifo.as_os_str().as_bytes()).expect("FIFO path without NUL");
    // SAFETY: `fifo_name` is a valid NUL-terminated pathname and the mode is
    // restricted to ordinary permission bits.
    let result = unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) };
    assert_eq!(result, 0, "create FIFO: {}", io::Error::last_os_error());

    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _ = sender.send(FluxConfig::load(fifo));
    });
    let error = receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("opening a FIFO must not block")
        .expect_err("a FIFO is not a configuration file");
    worker.join().expect("configuration loader worker");

    assert_eq!(error.kind(), ConfigErrorKind::UnsafeFileType);
    assert_eq!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<io::Error>())
            .map(io::Error::kind),
        Some(io::ErrorKind::InvalidInput)
    );
}

#[test]
fn parse_errors_preserve_the_toml_source() {
    let error = FluxConfig::parse("schema = [").expect_err("malformed TOML must fail");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
    assert!(error.source().is_some());
}

#[test]
fn load_errors_preserve_the_io_source() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join(format!(
        "missing-phase-one-flux-{}-{}.toml",
        std::process::id(),
        line!()
    ));

    let error = FluxConfig::load(path).expect_err("missing config must fail");
    let source = error
        .source()
        .and_then(|source| source.downcast_ref::<io::Error>())
        .expect("I/O source should be retained");

    assert_eq!(error.kind(), ConfigErrorKind::Io);
    assert_eq!(source.kind(), io::ErrorKind::NotFound);
}

#[test]
fn rejects_an_oversized_parse_document_before_toml_decoding() {
    let input = " ".repeat(65_537);

    let error = FluxConfig::parse(&input).expect_err("Phase-1 config is capped at 64 KiB");

    assert!(matches!(
        error.kind(),
        ConfigErrorKind::DocumentTooLarge {
            maximum_bytes: 65_536
        }
    ));
}

#[test]
fn rejects_an_oversized_loaded_document() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("oversized-phase-one-flux.toml");
    fs::write(&path, vec![b' '; 65_537]).expect("write oversized config fixture");

    let result = FluxConfig::load(&path);
    fs::remove_file(path).expect("remove oversized config fixture");
    let error = result.expect_err("Phase-1 config is capped at 64 KiB");

    assert!(matches!(
        error.kind(),
        ConfigErrorKind::DocumentTooLarge {
            maximum_bytes: 65_536
        }
    ));
}

#[test]
fn load_errors_preserve_the_utf8_source() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("invalid-utf8-phase-one-flux.toml");
    fs::write(&path, [0xff]).expect("write invalid UTF-8 config fixture");

    let result = FluxConfig::load(&path);
    fs::remove_file(path).expect("remove invalid UTF-8 config fixture");
    let error = result.expect_err("configuration must be UTF-8");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidUtf8);
    assert!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<std::str::Utf8Error>())
            .is_some()
    );
}

fn assert_invalid_field(input: &str, expected_field: &'static str) {
    let error = FluxConfig::parse(input).expect_err("configuration value must fail validation");
    assert!(
        matches!(
            error.kind(),
            ConfigErrorKind::InvalidValue { field, .. } if field == expected_field
        ),
        "expected invalid field {expected_field}, found {error}"
    );
}

fn without_section(input: &str, section: &str) -> String {
    let marker = format!("\n[{section}]\n");
    let start = input.find(&marker).expect("fixture section must exist");
    let content_start = start + marker.len();
    let end = input[content_start..]
        .find("\n[")
        .map_or(input.len(), |offset| content_start + offset);
    let mut output = String::with_capacity(input.len() - (end - start));
    output.push_str(&input[..start]);
    output.push_str(&input[end..]);
    output
}
