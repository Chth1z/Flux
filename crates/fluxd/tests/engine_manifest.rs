use std::error::Error;
use std::fs;
use std::num::NonZeroU16;
use std::time::Duration;

use flux_platform::{SingBoxLauncher, SingBoxReadiness};
use fluxd::{EngineManifest, EngineManifestErrorKind, MAX_ENGINE_MANIFEST_BYTES};
use tempfile::TempDir;

#[test]
fn valid_direct_listener_manifest_builds_an_engine_spec() {
    let fixture = ManifestFixture::new();
    let document = fixture.direct_listener_manifest();

    let prepared =
        EngineManifest::parse_prepared(document.as_bytes()).expect("valid engine manifest");
    assert_eq!(prepared.generation().get(), 7);
    let spec = prepared.engine();

    let process = spec.process();
    assert_eq!(process.binary, fixture.binary);
    assert_eq!(process.config, fixture.config);
    assert_eq!(process.working_directory, fixture.directory.path());
    assert_eq!(process.log, fixture.log);
    assert_eq!(process.launcher, SingBoxLauncher::Direct);
    assert_eq!(
        process.readiness,
        SingBoxReadiness::Listener {
            port: NonZeroU16::new(7893).expect("nonzero fixture port"),
        }
    );
    assert_eq!(process.startup_timeout, Duration::from_millis(8_000));
    assert_eq!(process.stop_timeout, Duration::from_millis(5_000));

    let restart = spec.restart_policy();
    assert_eq!(restart.max_attempts(), 3);
    assert_eq!(restart.window(), Duration::from_secs(60));
    assert_eq!(restart.initial_backoff(), Duration::from_secs(1));
    assert_eq!(restart.maximum_backoff(), Duration::from_secs(30));
    assert_eq!(restart.stable_reset(), Duration::from_secs(30));
}

#[test]
fn valid_busybox_tun_manifest_builds_an_engine_spec() {
    let fixture = ManifestFixture::new();
    let document = fixture.busybox_tun_manifest();

    let spec = EngineManifest::parse(document.as_bytes()).expect("valid engine manifest");

    assert_eq!(
        spec.process().launcher,
        SingBoxLauncher::BusyBoxSetuidgid {
            busybox: fixture.busybox,
            identity: "1000:net_admin".into(),
        }
    );
    assert_eq!(
        spec.process().readiness,
        SingBoxReadiness::TunInterface {
            name: "flux.tun-1".to_owned(),
        }
    );
}

#[test]
fn duplicate_unknown_and_missing_fields_are_rejected() {
    let fixture = ManifestFixture::new();
    let document = fixture.direct_listener_manifest();

    assert_manifest_error(
        &format!("{document}binary={}\n", fixture.binary.display()),
        EngineManifestErrorKind::DuplicateField,
    );
    assert_manifest_error(
        &format!("{document}future_field=value\n"),
        EngineManifestErrorKind::UnknownField,
    );
    assert_manifest_error(
        &without_field(&document, "config"),
        EngineManifestErrorKind::MissingField,
    );
}

#[test]
fn launcher_and_readiness_conditionals_are_exact() {
    let fixture = ManifestFixture::new();
    let direct = fixture.direct_listener_manifest();
    let busybox = fixture.busybox_tun_manifest();

    for extra in [
        format!("busybox={}", fixture.busybox.display()),
        "identity=1000:1000".to_owned(),
    ] {
        assert_manifest_error(
            &format!("{direct}{extra}\n"),
            EngineManifestErrorKind::ForbiddenField,
        );
    }
    for missing in ["busybox", "identity"] {
        assert_manifest_error(
            &without_field(&busybox, missing),
            EngineManifestErrorKind::MissingField,
        );
    }

    assert_manifest_error(
        &format!("{direct}tun_interface=flux0\n"),
        EngineManifestErrorKind::ForbiddenField,
    );
    assert_manifest_error(
        &without_field(&direct, "listener_port"),
        EngineManifestErrorKind::MissingField,
    );
    assert_manifest_error(
        &format!("{busybox}listener_port=7893\n"),
        EngineManifestErrorKind::ForbiddenField,
    );
    assert_manifest_error(
        &without_field(&busybox, "tun_interface"),
        EngineManifestErrorKind::MissingField,
    );
}

#[test]
fn paths_identity_interface_port_and_timeouts_are_strict() {
    let fixture = ManifestFixture::new();
    let direct = fixture.direct_listener_manifest();
    let busybox = fixture.busybox_tun_manifest();

    for field in ["binary", "config", "working_directory", "log"] {
        assert_manifest_error(
            &replace_field(&direct, field, "relative/path"),
            EngineManifestErrorKind::InvalidValue,
        );
    }
    assert_manifest_error(
        &replace_field(&busybox, "busybox", "relative/busybox"),
        EngineManifestErrorKind::InvalidValue,
    );

    for identity in [
        "root",
        "root:",
        ":root",
        "root:root:extra",
        "-root:root",
        "4294967296:0",
        "root:net-admin",
        "røøt:root",
    ] {
        assert_manifest_error(
            &replace_field(&busybox, "identity", identity),
            EngineManifestErrorKind::InvalidValue,
        );
    }

    for interface in [
        "",
        ".",
        "..",
        "-flux0",
        ".flux0",
        "flux/tun",
        "flux:tun",
        "flux tun",
        "interface-name-16",
        "flüx0",
    ] {
        assert_manifest_error(
            &replace_field(&busybox, "tun_interface", interface),
            EngineManifestErrorKind::InvalidValue,
        );
    }

    for port in ["", "0", "65536", "+1", "-1", "tcp"] {
        assert_manifest_error(
            &replace_field(&direct, "listener_port", port),
            EngineManifestErrorKind::InvalidValue,
        );
    }

    for field in ["startup_timeout_ms", "stop_timeout_ms"] {
        for timeout in ["", "0", "+1", "-1", "1.0", "60001", "4294967296"] {
            assert_manifest_error(
                &replace_field(&direct, field, timeout),
                EngineManifestErrorKind::InvalidValue,
            );
        }
    }
    for generation in ["", "0", "+1", "-1", "1.0", "2147483648", "4294967296"] {
        assert_manifest_error(
            &replace_field(&direct, "generation", generation),
            EngineManifestErrorKind::InvalidValue,
        );
    }
}

#[test]
fn encoding_header_and_line_grammar_are_strict() {
    let fixture = ManifestFixture::new();
    let document = fixture.direct_listener_manifest();

    let error = EngineManifest::parse(&[0xff]).expect_err("non-UTF-8 manifest must fail");
    assert_eq!(error.kind(), EngineManifestErrorKind::InvalidUtf8);
    assert_manifest_error(
        &document.replacen("FLUX_ENGINE_MANIFEST_V1", "FLUX_ENGINE_MANIFEST_V2", 1),
        EngineManifestErrorKind::InvalidHeader,
    );
    assert_manifest_error(
        &document.replacen(
            "FLUX_ENGINE_MANIFEST_V1\n",
            "FLUX_ENGINE_MANIFEST_V1\n\n",
            1,
        ),
        EngineManifestErrorKind::BlankLine,
    );
    assert_manifest_error(
        &format!("{document}not-a-key-value-line\n"),
        EngineManifestErrorKind::MalformedLine,
    );
    assert_manifest_error(
        &format!("{document}=empty-key\n"),
        EngineManifestErrorKind::MalformedLine,
    );
}

#[test]
fn oversized_inline_manifest_is_rejected_before_decoding() {
    let document = vec![0xff; MAX_ENGINE_MANIFEST_BYTES + 1];

    let error = EngineManifest::parse(&document).expect_err("oversized manifest must fail");

    assert_eq!(error.kind(), EngineManifestErrorKind::DocumentTooLarge);
}

#[test]
fn regular_manifest_file_loads_and_oversized_or_nonregular_files_do_not() {
    let fixture = ManifestFixture::new();
    let manifest = fixture.directory.path().join("engine.manifest");
    fs::write(&manifest, fixture.direct_listener_manifest()).expect("write engine manifest");

    let spec = EngineManifest::load(&manifest).expect("load regular engine manifest");
    assert_eq!(spec.process().binary, fixture.binary);

    let oversized = fixture.directory.path().join("oversized.manifest");
    fs::write(&oversized, vec![b'x'; MAX_ENGINE_MANIFEST_BYTES + 1])
        .expect("write oversized manifest");
    let error = EngineManifest::load(&oversized).expect_err("oversized file must fail");
    assert_eq!(error.kind(), EngineManifestErrorKind::DocumentTooLarge);

    let error =
        EngineManifest::load(fixture.directory.path()).expect_err("directory manifest must fail");
    assert_eq!(error.kind(), EngineManifestErrorKind::UnsafeFileType);
}

#[cfg(unix)]
#[test]
fn symbolic_link_manifest_is_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = ManifestFixture::new();
    let target = fixture.directory.path().join("engine.manifest");
    let link = fixture.directory.path().join("engine.link");
    fs::write(&target, fixture.direct_listener_manifest()).expect("write manifest target");
    symlink(&target, &link).expect("create manifest symlink");

    let error = EngineManifest::load(&link).expect_err("symlink manifest must fail");

    assert_eq!(error.kind(), EngineManifestErrorKind::UnsafeFileType);
}

#[test]
fn io_and_engine_spec_errors_preserve_their_source_chains() {
    let fixture = ManifestFixture::new();
    let missing_manifest = fixture.directory.path().join("missing.manifest");

    let error = EngineManifest::load(&missing_manifest).expect_err("missing manifest must fail");
    assert_eq!(error.kind(), EngineManifestErrorKind::Io);
    assert!(
        error
            .source()
            .is_some_and(|source| source.is::<std::io::Error>())
    );

    let missing_binary = fixture.directory.path().join("missing-sing-box");
    let document = replace_field(
        &fixture.direct_listener_manifest(),
        "binary",
        &missing_binary.display().to_string(),
    );
    let error = EngineManifest::parse(document.as_bytes())
        .expect_err("missing engine artifact must fail inspection");
    assert_eq!(error.kind(), EngineManifestErrorKind::EngineSpec);
    let engine_source = error.source().expect("nested EngineSpecError");
    assert!(
        engine_source
            .source()
            .is_some_and(|source| source.is::<std::io::Error>())
    );
}

struct ManifestFixture {
    directory: TempDir,
    binary: std::path::PathBuf,
    busybox: std::path::PathBuf,
    config: std::path::PathBuf,
    log: std::path::PathBuf,
}

impl ManifestFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("create manifest fixture");
        let binary = directory.path().join("sing-box");
        let busybox = directory.path().join("busybox");
        let config = directory.path().join("sing-box.json");
        let log = directory.path().join("sing-box.log");
        fs::write(&binary, b"sing-box fixture").expect("write binary fixture");
        fs::write(&busybox, b"busybox fixture").expect("write BusyBox fixture");
        fs::write(&config, br#"{"inbounds":[]}"#).expect("write config fixture");
        Self {
            directory,
            binary,
            busybox,
            config,
            log,
        }
    }

    fn direct_listener_manifest(&self) -> String {
        format!(
            "FLUX_ENGINE_MANIFEST_V1\n\
             generation=7\n\
             binary={}\n\
             config={}\n\
             working_directory={}\n\
             log={}\n\
             launcher=direct\n\
             readiness=listener\n\
             startup_timeout_ms=8000\n\
             stop_timeout_ms=5000\n\
             listener_port=7893\n",
            self.binary.display(),
            self.config.display(),
            self.directory.path().display(),
            self.log.display(),
        )
    }

    fn busybox_tun_manifest(&self) -> String {
        format!(
            "FLUX_ENGINE_MANIFEST_V1\n\
             generation=8\n\
             binary={}\n\
             config={}\n\
             working_directory={}\n\
             log={}\n\
             launcher=busybox-setuidgid\n\
             busybox={}\n\
             identity=1000:net_admin\n\
             readiness=tun\n\
             tun_interface=flux.tun-1\n\
             startup_timeout_ms=8000\n\
             stop_timeout_ms=5000\n",
            self.binary.display(),
            self.config.display(),
            self.directory.path().display(),
            self.log.display(),
            self.busybox.display(),
        )
    }
}

fn assert_manifest_error(document: &str, expected: EngineManifestErrorKind) {
    let error = EngineManifest::parse(document.as_bytes()).expect_err("manifest must be rejected");
    assert_eq!(error.kind(), expected, "unexpected error: {error}");
}

fn without_field(document: &str, field: &str) -> String {
    let prefix = format!("{field}=");
    let mut filtered = document
        .lines()
        .filter(|line| !line.starts_with(&prefix))
        .collect::<Vec<_>>()
        .join("\n");
    filtered.push('\n');
    filtered
}

fn replace_field(document: &str, field: &str, replacement: &str) -> String {
    let prefix = format!("{field}=");
    let mut replaced = false;
    let mut result = document
        .lines()
        .map(|line| {
            if line.starts_with(&prefix) {
                replaced = true;
                format!("{field}={replacement}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(replaced, "fixture did not contain field {field:?}");
    result.push('\n');
    result
}
