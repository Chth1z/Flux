use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use flux_core::{ConfigErrorKind, FailurePolicy, FluxConfig};

const MINIMAL_CONFIG: &str = r#"
schema = 1

[daemon]
fail_policy = "open"
reconcile_debounce_ms = 250
event_queue_capacity = 256
generation_history = 2
"#;

#[test]
fn parses_the_phase_one_configuration_schema() {
    let config = FluxConfig::parse(MINIMAL_CONFIG).expect("minimal schema should parse");

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
fn defers_closed_failure_policy_until_schema_has_a_safety_acknowledgement() {
    let input = MINIMAL_CONFIG.replacen("fail_policy = \"open\"", "fail_policy = \"closed\"", 1);

    let error = FluxConfig::parse(&input).expect_err("schema 1 cannot honor fail-closed safely");

    assert!(matches!(
        error.kind(),
        ConfigErrorKind::UnsupportedFailurePolicy { policy: "closed" }
    ));
}

#[test]
fn rejects_an_undocumented_failure_policy() {
    let input = MINIMAL_CONFIG.replacen("fail_policy = \"open\"", "fail_policy = \"repair\"", 1);

    let error = FluxConfig::parse(&input).expect_err("only open and closed are documented");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
}

#[test]
fn requires_the_schema_field() {
    let input = MINIMAL_CONFIG.replacen("schema = 1\n\n", "", 1);

    let error = FluxConfig::parse(&input).expect_err("schema is mandatory");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
}

#[test]
fn requires_every_phase_one_daemon_field() {
    for field in [
        "fail_policy = \"open\"\n",
        "reconcile_debounce_ms = 250\n",
        "event_queue_capacity = 256\n",
        "generation_history = 2\n",
    ] {
        let input = MINIMAL_CONFIG.replacen(field, "", 1);

        assert!(
            FluxConfig::parse(&input).is_err(),
            "removing {field:?} must make the document invalid"
        );
    }
}

#[test]
fn rejects_duplicate_fields() {
    let input = MINIMAL_CONFIG.replacen("schema = 1", "schema = 1\nschema = 1", 1);

    let error = FluxConfig::parse(&input).expect_err("duplicate fields are ambiguous");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
}

#[test]
fn rejects_an_unsupported_schema_version() {
    let input = MINIMAL_CONFIG.replacen("schema = 1", "schema = 2", 1);

    let error = FluxConfig::parse(&input).expect_err("schema 2 is not supported");

    assert!(matches!(
        error.kind(),
        ConfigErrorKind::UnsupportedSchema {
            found: 2,
            supported: 1
        }
    ));
}

#[test]
fn rejects_unknown_top_level_sections() {
    let input = format!("{MINIMAL_CONFIG}\n[engine]\nbinary = \"/data/adb/flux/bin/sing-box\"\n");

    let error = FluxConfig::parse(&input).expect_err("phase one has no engine section");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
}

#[test]
fn rejects_unknown_daemon_fields() {
    let input = format!("{MINIMAL_CONFIG}worker_threads = 4\n");

    let error = FluxConfig::parse(&input).expect_err("phase one has no worker_threads setting");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
}

#[test]
fn rejects_a_zero_reconcile_debounce() {
    let input = MINIMAL_CONFIG.replacen(
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
        MINIMAL_CONFIG.replacen("event_queue_capacity = 256", "event_queue_capacity = 0", 1);

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
    let input = MINIMAL_CONFIG.replacen("generation_history = 2", "generation_history = 0", 1);

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
    let input = MINIMAL_CONFIG.replacen(
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
    let input = MINIMAL_CONFIG.replacen(
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
    let input = MINIMAL_CONFIG.replacen("generation_history = 2", "generation_history = 33", 1);

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
    let input = MINIMAL_CONFIG
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
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("phase-one-flux.toml");
    fs::write(&path, MINIMAL_CONFIG).expect("write config fixture");

    let config = FluxConfig::load(&path).expect("load config fixture");

    assert_eq!(config.daemon().fail_policy(), FailurePolicy::Open);
    fs::remove_file(path).expect("remove config fixture");
}

#[test]
fn parse_errors_preserve_the_toml_source() {
    let error = FluxConfig::parse("schema = [").expect_err("malformed TOML must fail");

    assert_eq!(error.kind(), ConfigErrorKind::InvalidToml);
    assert!(error.source().is_some());
}

#[test]
fn load_errors_preserve_the_io_source() {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
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
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("oversized-phase-one-flux.toml");
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
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("invalid-utf8-phase-one-flux.toml");
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
