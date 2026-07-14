use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ORACLE_SCHEMA_VERSION: u32 = 1;
const ORACLE_PROFILE: &str = "maximal-zone-v1";
const ORACLE_MANIFEST: &str = "tests/oracle/xtables/manifest.json";
const ORACLE_GENERATOR: &str = "tests/oracle/xtables/generate.sh";
const ORACLE_SEMANTIC_TEST: &str = "tests/shell/rules_generation.sh";
const ORACLE_FIXTURE_DIRECTORY: &str = "tests/oracle/xtables/fixtures";
const ORACLE_PLATFORM: &str = "linux/amd64";
const BUSYBOX_PATH: &str = "/bin/busybox";
const BUSYBOX_SOURCE_INDEX: &str = "docker.io/library/busybox:1.37.0-uclibc@sha256:39e0df8c4d65953b55c344f017e1ff2e0031a7454b3c24e6b76d402f207e315a";
const BUSYBOX_PLATFORM_IMAGE: &str = "docker.io/library/busybox@sha256:dfb66b2b3e6981fefa54fd2cd4faf662c35b4a4baeff48295a9409ddf3224c48";
const BUSYBOX_LAYER_DIGEST: &str =
    "sha256:78e03862f96387ec7337a69b06a3509a8435e6d1cc0a7033fc7bab20c6550eb3";
const BUSYBOX_SHA256: &str = "c984eacc3b736fe1eeefe201f21b241932ef4c3c03fbb6869a4f156f32dd9716";
const BUSYBOX_VERSION: &str = "BusyBox v1.37.0 (2024-09-26 21:31:42 UTC) multi-call binary.";
const DOCKER_PROGRAM: &str = "docker";
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_INPUT_TOTAL_BYTES: usize = 128 * 1024;
const MAX_SNAPSHOT_ARCHIVE_BYTES: usize = 256 * 1024;
const MAX_ORACLE_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_PROBE_OUTPUT_BYTES: usize = 1024;
const MAX_SEMANTIC_OUTPUT_BYTES: usize = 4096;
const MAX_STDERR_CAPTURE_BYTES: usize = 16 * 1024;
const MAX_ORACLE_LINES: usize = 32_768;
const MAX_DIAGNOSTIC_BYTES: usize = 4096;
const MAX_DIAGNOSTIC_PREVIEW_BYTES: usize = 128;
const PARENT_TIMEOUT: Duration = Duration::from_secs(40);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(target_os = "linux")]
const LINUX_O_NOFOLLOW: i32 = 0o400000;
const EXPECTED_SEMANTIC_TEST_OUTPUT: &[u8] = b"rules generation shell tests: PASS\n";
const TAR_BLOCK_BYTES: usize = 512;
const TAR_END_BYTES: usize = TAR_BLOCK_BYTES * 2;
const TAR_OWNER_ID: u64 = 65_534;
const CONTAINER_WRAPPER: &str = concat!(
    "set -eu\n",
    "umask 077\n",
    "workspace=/tmp/workspace\n",
    "/bin/busybox mkdir -p \"${workspace}\"\n",
    "/bin/busybox tar -xof - -C \"${workspace}\"\n",
    "exec /bin/busybox timeout -s KILL 30s ",
    "/bin/busybox env -i HOME=/tmp PATH=/bin LANG=C LC_ALL=C TZ=UTC ",
    "ORACLE_WORKSPACE=\"${workspace}\" /bin/busybox \"$@\"\n",
);

const INPUT_SPECS: [InputSpec; 5] = [
    InputSpec {
        path: "scripts/rules",
        maximum_bytes: 64 * 1024,
    },
    InputSpec {
        path: ORACLE_SEMANTIC_TEST,
        maximum_bytes: 32 * 1024,
    },
    InputSpec {
        path: ORACLE_GENERATOR,
        maximum_bytes: 16 * 1024,
    },
    InputSpec {
        path: "tests/oracle/xtables/maximal-zone-v1.env",
        maximum_bytes: 16 * 1024,
    },
    InputSpec {
        path: "tests/oracle/xtables/packages.list",
        maximum_bytes: 4 * 1024,
    },
];

const ARCHIVE_DIRECTORIES: [&str; 5] = [
    "scripts/",
    "tests/",
    "tests/shell/",
    "tests/oracle/",
    "tests/oracle/xtables/",
];

const FIXTURE_SPECS: [FixtureSpec; 4] = [
    FixtureSpec {
        id: "maximal-zone-v1-ipv4-apply",
        path: "tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-apply.restore",
        action: OracleAction::Apply,
        family: OracleFamily::Ipv4,
    },
    FixtureSpec {
        id: "maximal-zone-v1-ipv4-cleanup",
        path: "tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-cleanup.restore",
        action: OracleAction::Cleanup,
        family: OracleFamily::Ipv4,
    },
    FixtureSpec {
        id: "maximal-zone-v1-ipv6-apply",
        path: "tests/oracle/xtables/fixtures/maximal-zone-v1-ipv6-apply.restore",
        action: OracleAction::Apply,
        family: OracleFamily::Ipv6,
    },
    FixtureSpec {
        id: "maximal-zone-v1-ipv6-cleanup",
        path: "tests/oracle/xtables/fixtures/maximal-zone-v1-ipv6-cleanup.restore",
        action: OracleAction::Cleanup,
        family: OracleFamily::Ipv6,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OracleMode {
    Check,
    Update,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OracleManifest {
    schema_version: u32,
    profile: String,
    environment: OracleEnvironment,
    inputs: Vec<OracleInput>,
    fixtures: Vec<OracleFixture>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OracleEnvironment {
    source_index: String,
    platform_image: String,
    platform: String,
    layer_digest: String,
    busybox_path: String,
    busybox_sha256: String,
    busybox_version: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OracleInput {
    path: String,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OracleAction {
    Apply,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OracleFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OracleFixture {
    id: String,
    path: String,
    action: OracleAction,
    family: OracleFamily,
    sha256: String,
    bytes: usize,
    lines: usize,
}

#[derive(Clone, Copy)]
struct FixtureSpec {
    id: &'static str,
    path: &'static str,
    action: OracleAction,
    family: OracleFamily,
}

struct GeneratedFixture {
    bytes: Vec<u8>,
    sha256: String,
    lines: usize,
}

#[derive(Clone, Copy)]
struct InputSpec {
    path: &'static str,
    maximum_bytes: usize,
}

struct SnapshotFile {
    path: &'static str,
    bytes: Box<[u8]>,
    sha256: String,
}

struct OracleSnapshot {
    files: Box<[SnapshotFile]>,
    archive: Arc<[u8]>,
}

struct BoundedCapture {
    retained: Vec<u8>,
    total_bytes: u64,
    sha256: String,
}

struct ProcessCapture {
    status: ExitStatus,
    stdout: BoundedCapture,
    stderr: BoundedCapture,
    stdin_error: Option<io::ErrorKind>,
    timed_out: bool,
}

pub(crate) fn parse_options(arguments: &[OsString]) -> Result<OracleMode, String> {
    match arguments {
        [argument] if argument == "--check" => Ok(OracleMode::Check),
        [argument] if argument == "--update" => Ok(OracleMode::Update),
        _ => Err("xtables-oracle requires exactly one of --check or --update".to_owned()),
    }
}

pub(crate) fn run(mode: OracleMode) -> Result<(), String> {
    if env::consts::OS != "linux" {
        return Err("xtables-oracle requires a Linux host with Docker".to_owned());
    }

    let root = workspace_root()?;
    let manifest_path = root.join(ORACLE_MANIFEST);
    let mut manifest = read_manifest(&manifest_path)?;
    validate_manifest(&manifest)?;
    let snapshot = read_input_snapshot(&root)?;
    validate_fixture_inventory(&root, mode == OracleMode::Update)?;

    if mode == OracleMode::Check {
        verify_input_hashes(&snapshot, &manifest)?;
        verify_checked_in_fixture_metadata(&root, &manifest)?;
    }

    verify_oracle_environment(&snapshot, &manifest.environment)?;
    run_semantic_test(&snapshot, &manifest.environment)?;
    let generated = generate_fixtures(&snapshot, &manifest.environment)?;
    verify_input_snapshot_unchanged(&root, &snapshot)?;

    match mode {
        OracleMode::Check => {
            verify_fixtures(&root, &manifest, &generated)?;
            println!("verified pinned xtables shell oracle fixtures");
        }
        OracleMode::Update => {
            update_manifest_inputs(&snapshot, &mut manifest);
            update_fixtures(&root, &mut manifest, &generated)?;
            write_manifest(&manifest_path, &manifest)?;
            println!("updated pinned xtables shell oracle fixtures");
        }
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "xtask manifest directory has no workspace parent".to_owned())?;
    fs::canonicalize(root).map_err(|error| {
        format!(
            "cannot canonicalize workspace root {}: {error}",
            root.display()
        )
    })
}

fn read_manifest(path: &Path) -> Result<OracleManifest, String> {
    let bytes = read_regular_file_bounded(path, "xtables oracle manifest", MAX_MANIFEST_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "invalid xtables oracle manifest {}: {error}",
            path.display()
        )
    })
}

fn validate_manifest(manifest: &OracleManifest) -> Result<(), String> {
    if manifest.schema_version != ORACLE_SCHEMA_VERSION {
        return Err(format!(
            "xtables oracle schema_version must be {ORACLE_SCHEMA_VERSION}, found {}",
            manifest.schema_version
        ));
    }
    if manifest.profile != ORACLE_PROFILE {
        return Err(format!(
            "xtables oracle profile must be {ORACLE_PROFILE}, found {}",
            manifest.profile
        ));
    }
    validate_environment(&manifest.environment)?;

    if manifest.inputs.len() != INPUT_SPECS.len()
        || manifest
            .inputs
            .iter()
            .zip(INPUT_SPECS)
            .any(|(input, expected)| input.path != expected.path)
    {
        return Err(format!(
            "xtables oracle inputs must be the exact ordered set {:?}",
            INPUT_SPECS.map(|input| input.path)
        ));
    }
    for input in &manifest.inputs {
        validate_sha256(&format!("input {}", input.path), &input.sha256)?;
    }

    if manifest.fixtures.len() != FIXTURE_SPECS.len() {
        return Err(format!(
            "xtables oracle manifest must contain exactly {} fixtures",
            FIXTURE_SPECS.len()
        ));
    }
    for (fixture, expected) in manifest.fixtures.iter().zip(FIXTURE_SPECS) {
        if fixture.id != expected.id
            || fixture.path != expected.path
            || fixture.action != expected.action
            || fixture.family != expected.family
        {
            return Err(format!(
                "xtables oracle fixture entry must exactly match {} ({}, {:?}, {:?})",
                expected.id, expected.path, expected.action, expected.family
            ));
        }
        validate_sha256(&format!("fixture {}", fixture.id), &fixture.sha256)?;
        if fixture.bytes == 0 || fixture.bytes > MAX_ORACLE_OUTPUT_BYTES {
            return Err(format!(
                "fixture {} byte count must be in 1..={MAX_ORACLE_OUTPUT_BYTES}",
                fixture.id
            ));
        }
        if fixture.lines == 0 || fixture.lines > MAX_ORACLE_LINES {
            return Err(format!(
                "fixture {} line count must be in 1..={MAX_ORACLE_LINES}",
                fixture.id
            ));
        }
    }
    Ok(())
}

fn validate_environment(environment: &OracleEnvironment) -> Result<(), String> {
    if environment.source_index != BUSYBOX_SOURCE_INDEX {
        return Err(format!(
            "xtables oracle source_index must be the reviewed pin {BUSYBOX_SOURCE_INDEX}"
        ));
    }
    if environment.platform_image != BUSYBOX_PLATFORM_IMAGE {
        return Err(format!(
            "xtables oracle platform_image must be the reviewed pin {BUSYBOX_PLATFORM_IMAGE}"
        ));
    }
    if environment.platform != ORACLE_PLATFORM {
        return Err(format!(
            "xtables oracle platform must be {ORACLE_PLATFORM}, found {}",
            environment.platform
        ));
    }
    if environment.layer_digest != BUSYBOX_LAYER_DIGEST {
        return Err(format!(
            "xtables oracle layer_digest must be the reviewed pin {BUSYBOX_LAYER_DIGEST}"
        ));
    }
    if environment.busybox_path != BUSYBOX_PATH {
        return Err(format!(
            "xtables oracle busybox_path must be {BUSYBOX_PATH}, found {}",
            environment.busybox_path
        ));
    }
    if environment.busybox_sha256 != BUSYBOX_SHA256 {
        return Err(format!(
            "xtables oracle busybox_sha256 must be the reviewed pin {BUSYBOX_SHA256}"
        ));
    }
    if environment.busybox_version != BUSYBOX_VERSION {
        return Err(format!(
            "xtables oracle busybox_version must be the reviewed identity {BUSYBOX_VERSION:?}"
        ));
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<(), String> {
    validate_digest_hex(label, value)
}

fn validate_digest_hex(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err(format!(
            "xtables oracle {label} must be a non-placeholder lowercase SHA-256 digest"
        ));
    }
    Ok(())
}

fn read_input_snapshot(root: &Path) -> Result<OracleSnapshot, String> {
    let mut total_bytes = 0usize;
    let mut files = Vec::with_capacity(INPUT_SPECS.len());
    for input in INPUT_SPECS {
        let remaining_total = MAX_INPUT_TOTAL_BYTES.saturating_sub(total_bytes);
        let effective_maximum = input.maximum_bytes.min(remaining_total);
        let bytes = read_workspace_file_bounded(
            root,
            input.path,
            "xtables oracle input",
            effective_maximum,
        )?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| "xtables oracle input byte count overflowed".to_owned())?;
        if total_bytes > MAX_INPUT_TOTAL_BYTES {
            return Err(format!(
                "xtables oracle inputs exceed the {MAX_INPUT_TOTAL_BYTES}-byte total limit"
            ));
        }
        files.push(SnapshotFile {
            path: input.path,
            sha256: sha256_bytes(&bytes),
            bytes: bytes.into_boxed_slice(),
        });
    }
    let archive = build_ustar(&files)?;
    Ok(OracleSnapshot {
        files: files.into_boxed_slice(),
        archive: Arc::from(archive),
    })
}

fn build_ustar(files: &[SnapshotFile]) -> Result<Vec<u8>, String> {
    if files.len() != INPUT_SPECS.len()
        || files
            .iter()
            .zip(INPUT_SPECS)
            .any(|(file, expected)| file.path != expected.path)
    {
        return Err(
            "xtables oracle snapshot does not contain the exact ordered input set".to_owned(),
        );
    }

    let mut capacity = ARCHIVE_DIRECTORIES
        .len()
        .checked_mul(TAR_BLOCK_BYTES)
        .and_then(|value| value.checked_add(TAR_END_BYTES))
        .ok_or_else(|| "xtables oracle archive size overflowed".to_owned())?;
    for file in files {
        let padded = round_up_tar_block(file.bytes.len())?;
        capacity = capacity
            .checked_add(TAR_BLOCK_BYTES)
            .and_then(|value| value.checked_add(padded))
            .ok_or_else(|| "xtables oracle archive size overflowed".to_owned())?;
    }
    if capacity > MAX_SNAPSHOT_ARCHIVE_BYTES {
        return Err(format!(
            "xtables oracle archive exceeds {MAX_SNAPSHOT_ARCHIVE_BYTES} bytes"
        ));
    }

    let mut archive = Vec::with_capacity(capacity);
    for directory in ARCHIVE_DIRECTORIES {
        append_ustar_entry(&mut archive, directory, 0o755, b'5', &[])?;
    }
    for file in files {
        append_ustar_entry(&mut archive, file.path, 0o444, b'0', &file.bytes)?;
    }
    archive.resize(
        archive
            .len()
            .checked_add(TAR_END_BYTES)
            .ok_or_else(|| "xtables oracle archive size overflowed".to_owned())?,
        0,
    );
    if archive.len() != capacity {
        return Err("xtables oracle archive length calculation diverged".to_owned());
    }
    Ok(archive)
}

fn append_ustar_entry(
    archive: &mut Vec<u8>,
    path: &str,
    mode: u64,
    entry_type: u8,
    contents: &[u8],
) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 100
        || path.starts_with('/')
        || path.split('/').any(|part| part == "..")
        || !path.bytes().all(|byte| (b' '..=b'~').contains(&byte))
    {
        return Err(format!("invalid fixed USTAR path {path:?}"));
    }
    if entry_type == b'5' && (!path.ends_with('/') || !contents.is_empty()) {
        return Err(format!("invalid USTAR directory entry {path:?}"));
    }
    if entry_type == b'0' && path.ends_with('/') {
        return Err(format!("invalid USTAR file entry {path:?}"));
    }

    let mut header = [0_u8; TAR_BLOCK_BYTES];
    write_tar_text(&mut header[0..100], path)?;
    write_tar_octal(&mut header[100..108], mode)?;
    write_tar_octal(&mut header[108..116], TAR_OWNER_ID)?;
    write_tar_octal(&mut header[116..124], TAR_OWNER_ID)?;
    write_tar_octal(
        &mut header[124..136],
        u64::try_from(contents.len())
            .map_err(|_| "xtables oracle USTAR content length overflowed".to_owned())?,
    )?;
    write_tar_octal(&mut header[136..148], 0)?;
    header[148..156].fill(b' ');
    header[156] = entry_type;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
    let rendered = format!("{checksum:06o}");
    if rendered.len() != 6 {
        return Err("xtables oracle USTAR checksum does not fit its field".to_owned());
    }
    header[148..154].copy_from_slice(rendered.as_bytes());
    header[154] = 0;
    header[155] = b' ';

    archive.extend_from_slice(&header);
    archive.extend_from_slice(contents);
    archive.resize(
        archive
            .len()
            .checked_add(round_up_tar_block(contents.len())? - contents.len())
            .ok_or_else(|| "xtables oracle archive size overflowed".to_owned())?,
        0,
    );
    if archive.len() > MAX_SNAPSHOT_ARCHIVE_BYTES {
        return Err(format!(
            "xtables oracle archive exceeds {MAX_SNAPSHOT_ARCHIVE_BYTES} bytes"
        ));
    }
    Ok(())
}

fn write_tar_text(field: &mut [u8], value: &str) -> Result<(), String> {
    if value.len() > field.len() {
        return Err("xtables oracle USTAR text field overflowed".to_owned());
    }
    field[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}

fn write_tar_octal(field: &mut [u8], value: u64) -> Result<(), String> {
    let digits = field
        .len()
        .checked_sub(1)
        .ok_or_else(|| "xtables oracle USTAR numeric field is empty".to_owned())?;
    let rendered = format!("{value:0digits$o}");
    if rendered.len() != digits {
        return Err("xtables oracle USTAR numeric field overflowed".to_owned());
    }
    field[..digits].copy_from_slice(rendered.as_bytes());
    field[digits] = 0;
    Ok(())
}

fn round_up_tar_block(length: usize) -> Result<usize, String> {
    length
        .checked_add(TAR_BLOCK_BYTES - 1)
        .map(|value| value / TAR_BLOCK_BYTES * TAR_BLOCK_BYTES)
        .ok_or_else(|| "xtables oracle archive size overflowed".to_owned())
}

fn validate_fixture_inventory(root: &Path, allow_missing: bool) -> Result<(), String> {
    let directory = root.join(ORACLE_FIXTURE_DIRECTORY);
    if !directory.exists() {
        if allow_missing {
            return Ok(());
        }
        return Err(format!(
            "xtables oracle fixture directory is missing: {}",
            directory.display()
        ));
    }
    let metadata = fs::symlink_metadata(&directory)
        .map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "xtables oracle fixture path must be a real directory: {}",
            directory.display()
        ));
    }

    let expected = FIXTURE_SPECS
        .iter()
        .map(|fixture| {
            Path::new(fixture.path)
                .file_name()
                .expect("fixture path has a file name")
                .to_os_string()
        })
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(&directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
    {
        let entry =
            entry.map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "xtables oracle fixture inventory contains a non-regular file: {}",
                entry.path().display()
            ));
        }
        actual.insert(entry.file_name());
        if actual.len() > expected.len() {
            return Err("xtables oracle fixture inventory exceeds its exact file limit".to_owned());
        }
    }
    if actual.difference(&expected).next().is_some() {
        return Err(format!(
            "xtables oracle fixture inventory contains an unexpected entry: {}",
            actual
                .difference(&expected)
                .next()
                .expect("difference checked")
                .to_string_lossy()
        ));
    }
    if !allow_missing && actual != expected {
        return Err("xtables oracle fixture inventory is incomplete".to_owned());
    }
    Ok(())
}

fn verify_input_hashes(snapshot: &OracleSnapshot, manifest: &OracleManifest) -> Result<(), String> {
    for (input, snapshotted) in manifest.inputs.iter().zip(snapshot.files.iter()) {
        if snapshotted.path != input.path || snapshotted.sha256 != input.sha256 {
            return Err(format!(
                "xtables oracle input hash mismatch for {}: expected {}, found {}",
                input.path, input.sha256, snapshotted.sha256
            ));
        }
    }
    Ok(())
}

fn verify_input_snapshot_unchanged(root: &Path, original: &OracleSnapshot) -> Result<(), String> {
    let current = read_input_snapshot(root)?;
    for (before, after) in original.files.iter().zip(current.files.iter()) {
        if before.path != after.path || before.bytes != after.bytes {
            return Err(format!(
                "xtables oracle input changed during execution: {} (before {}, after {})",
                before.path, before.sha256, after.sha256
            ));
        }
    }
    Ok(())
}

fn verify_checked_in_fixture_metadata(
    root: &Path,
    manifest: &OracleManifest,
) -> Result<(), String> {
    for (entry, expected) in manifest.fixtures.iter().zip(FIXTURE_SPECS) {
        let path = root.join(expected.path);
        let bytes =
            read_regular_file_bounded(&path, "xtables oracle fixture", MAX_ORACLE_OUTPUT_BYTES)?;
        let lines = validate_restore_bytes(expected.id, &bytes)?;
        let sha256 = sha256_bytes(&bytes);
        if entry.sha256 != sha256 || entry.bytes != bytes.len() || entry.lines != lines {
            return Err(format!(
                "checked-in fixture metadata mismatch for {}: expected hash/bytes/lines {}/{}/{}, found {}/{}/{}",
                expected.id,
                entry.sha256,
                entry.bytes,
                entry.lines,
                sha256,
                bytes.len(),
                lines
            ));
        }
    }
    Ok(())
}

fn verify_oracle_environment(
    snapshot: &OracleSnapshot,
    environment: &OracleEnvironment,
) -> Result<(), String> {
    let output = run_container(
        snapshot,
        environment,
        &[
            "ash",
            "/tmp/workspace/tests/oracle/xtables/generate.sh",
            "probe",
        ],
        MAX_PROBE_OUTPUT_BYTES,
    )?;
    let text = std::str::from_utf8(&output)
        .map_err(|error| format!("xtables oracle probe output is not UTF-8: {error}"))?;
    let expected = format!(
        "busybox_sha256={}\nbusybox_version={}\n",
        environment.busybox_sha256, environment.busybox_version
    );
    if text != expected {
        return Err(format!(
            "pinned BusyBox probe mismatch: expected sha256={}, found {}",
            sha256_bytes(expected.as_bytes()),
            bytes_summary(&output)
        ));
    }
    Ok(())
}

fn run_semantic_test(
    snapshot: &OracleSnapshot,
    environment: &OracleEnvironment,
) -> Result<(), String> {
    let output = run_container(
        snapshot,
        environment,
        &["ash", "/tmp/workspace/tests/shell/rules_generation.sh"],
        MAX_SEMANTIC_OUTPUT_BYTES,
    )?;
    if output != EXPECTED_SEMANTIC_TEST_OUTPUT {
        return Err(format!(
            "pinned shell semantic test output changed: expected sha256={}, found {}",
            sha256_bytes(EXPECTED_SEMANTIC_TEST_OUTPUT),
            bytes_summary(&output)
        ));
    }
    Ok(())
}

fn generate_fixtures(
    snapshot: &OracleSnapshot,
    environment: &OracleEnvironment,
) -> Result<Vec<GeneratedFixture>, String> {
    FIXTURE_SPECS
        .iter()
        .map(|fixture| {
            let bytes = run_generator(snapshot, environment, fixture.id)?;
            let lines = validate_restore_bytes(fixture.id, &bytes)?;
            Ok(GeneratedFixture {
                sha256: sha256_bytes(&bytes),
                bytes,
                lines,
            })
        })
        .collect()
}

fn run_generator(
    snapshot: &OracleSnapshot,
    environment: &OracleEnvironment,
    argument: &str,
) -> Result<Vec<u8>, String> {
    run_container(
        snapshot,
        environment,
        &[
            "ash",
            "/tmp/workspace/tests/oracle/xtables/generate.sh",
            argument,
        ],
        MAX_ORACLE_OUTPUT_BYTES,
    )
}

fn run_container(
    snapshot: &OracleSnapshot,
    environment: &OracleEnvironment,
    command: &[&str],
    stdout_limit: usize,
) -> Result<Vec<u8>, String> {
    let arguments = docker_arguments(environment, command);
    let mut docker = Command::new(DOCKER_PROGRAM);
    docker.args(&arguments);
    let output = run_bounded_command(
        docker,
        Arc::clone(&snapshot.archive),
        stdout_limit,
        PARENT_TIMEOUT,
    )
    .map_err(|error| {
        format!(
            "cannot execute the pinned xtables oracle with Docker: {error}; pull {} first",
            environment.platform_image
        )
    })?;
    if output.timed_out {
        return Err(format!(
            "pinned xtables oracle exceeded the {}-second parent deadline; stdout {}; stderr {}",
            PARENT_TIMEOUT.as_secs(),
            capture_summary(&output.stdout),
            capture_summary(&output.stderr)
        ));
    }
    if !output.status.success() {
        return Err(format!(
            "pinned xtables oracle container exited with {}; stdout {}; stderr {}",
            output.status,
            capture_summary(&output.stdout),
            capture_summary(&output.stderr)
        ));
    }
    if let Some(kind) = output.stdin_error {
        return Err(format!(
            "pinned xtables oracle snapshot stream failed after spawn ({kind:?})"
        ));
    }
    if output.stderr.total_bytes != 0 {
        return Err(format!(
            "pinned xtables oracle container wrote unexpected stderr: {}",
            capture_summary(&output.stderr)
        ));
    }
    if output.stdout.total_bytes > stdout_limit as u64 {
        return Err(format!(
            "pinned xtables oracle stdout exceeds {stdout_limit} bytes: {}",
            capture_summary(&output.stdout)
        ));
    }
    Ok(output.stdout.retained)
}

fn run_bounded_command(
    mut command: Command,
    stdin_bytes: Arc<[u8]>,
    stdout_limit: usize,
    timeout: Duration,
) -> Result<ProcessCapture, String> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("process spawn failed: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "process stdin pipe is unavailable".to_owned())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "process stdout pipe is unavailable".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "process stderr pipe is unavailable".to_owned())?;

    let stdin_thread = thread::spawn(move || {
        let result = stdin.write_all(&stdin_bytes).map_err(|error| error.kind());
        drop(stdin);
        result
    });
    let stdout_thread = thread::spawn(move || drain_bounded(stdout, stdout_limit));
    let stderr_thread = thread::spawn(move || drain_bounded(stderr, MAX_STDERR_CAPTURE_BYTES));

    let started = Instant::now();
    let mut timed_out = false;
    let mut wait_error = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() < timeout => thread::sleep(PROCESS_POLL_INTERVAL),
            Ok(None) => {
                timed_out = true;
                let _ = child.kill();
                match child.wait() {
                    Ok(status) => break Some(status),
                    Err(error) => {
                        wait_error = Some(error);
                        break None;
                    }
                }
            }
            Err(error) => {
                wait_error = Some(error);
                let _ = child.kill();
                break child.wait().ok();
            }
        }
    };

    let stdin_error = stdin_thread
        .join()
        .map_err(|_| "process stdin writer panicked".to_owned())?
        .err();
    let stdout = stdout_thread
        .join()
        .map_err(|_| "process stdout reader panicked".to_owned())?
        .map_err(|error| format!("process stdout read failed: {error}"))?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| "process stderr reader panicked".to_owned())?
        .map_err(|error| format!("process stderr read failed: {error}"))?;
    if let Some(error) = wait_error {
        return Err(format!("process wait failed: {error}"));
    }
    Ok(ProcessCapture {
        status: status.ok_or_else(|| "process exited without a wait status".to_owned())?,
        stdout,
        stderr,
        stdin_error,
        timed_out,
    })
}

fn drain_bounded(mut reader: impl Read, retain_limit: usize) -> io::Result<BoundedCapture> {
    let mut retained = Vec::with_capacity(retain_limit.min(16 * 1024));
    let mut total_bytes = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("capture byte count overflowed"))?;
        hasher.update(&buffer[..read]);
        let remaining = retain_limit.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..read.min(remaining)]);
    }
    Ok(BoundedCapture {
        retained,
        total_bytes,
        sha256: hex_digest(hasher.finalize().as_slice()),
    })
}

fn docker_arguments(environment: &OracleEnvironment, command: &[&str]) -> Vec<OsString> {
    let mut arguments = [
        "run",
        "--rm",
        "-i",
        "--pull=never",
        "--platform=linux/amd64",
        "--network=none",
        "--ipc=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--pids-limit=64",
        "--memory=64m",
        "--user=65534:65534",
        "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
        "--workdir=/tmp",
        "--entrypoint=/bin/busybox",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    arguments.push(OsString::from(&environment.platform_image));
    for argument in ["ash", "-c", CONTAINER_WRAPPER, "flux-oracle"] {
        arguments.push(OsString::from(argument));
    }
    arguments.extend(command.iter().map(OsString::from));
    arguments
}

fn validate_restore_bytes(id: &str, bytes: &[u8]) -> Result<usize, String> {
    if bytes.is_empty() || bytes.len() > MAX_ORACLE_OUTPUT_BYTES {
        return Err(format!(
            "fixture {id} byte count must be in 1..={MAX_ORACLE_OUTPUT_BYTES}"
        ));
    }
    if bytes.last() != Some(&b'\n') {
        return Err(format!("fixture {id} is missing its final LF"));
    }
    for (offset, byte) in bytes.iter().copied().enumerate() {
        if byte != b'\n' && !(b' '..=b'~').contains(&byte) {
            return Err(format!(
                "fixture {id} contains noncanonical byte 0x{byte:02x} at offset {offset}"
            ));
        }
    }
    let lines = bytes.iter().filter(|byte| **byte == b'\n').count();
    if lines == 0 || lines > MAX_ORACLE_LINES {
        return Err(format!(
            "fixture {id} line count must be in 1..={MAX_ORACLE_LINES}"
        ));
    }
    for (line_index, line) in bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        if line.is_empty()
            || line.first() == Some(&b' ')
            || line.last() == Some(&b' ')
            || line.windows(2).any(|window| window == b"  ")
        {
            return Err(format!(
                "fixture {id} has noncanonical line shape at line {}",
                line_index + 1
            ));
        }
    }
    Ok(lines)
}

fn verify_fixtures(
    root: &Path,
    manifest: &OracleManifest,
    generated: &[GeneratedFixture],
) -> Result<(), String> {
    for ((entry, expected), actual) in manifest.fixtures.iter().zip(FIXTURE_SPECS).zip(generated) {
        let path = root.join(expected.path);
        let checked_in =
            read_regular_file_bounded(&path, "xtables oracle fixture", MAX_ORACLE_OUTPUT_BYTES)?;
        if checked_in != actual.bytes {
            return Err(format!(
                "fixture {} differs from pinned shell/AWK output; review and run `cargo xtask xtables-oracle --update` intentionally",
                expected.id
            ));
        }
        if entry.sha256 != actual.sha256
            || entry.bytes != actual.bytes.len()
            || entry.lines != actual.lines
        {
            return Err(format!(
                "fixture metadata mismatch for {}: expected hash/bytes/lines {}/{}/{}, found {}/{}/{}",
                expected.id,
                entry.sha256,
                entry.bytes,
                entry.lines,
                actual.sha256,
                actual.bytes.len(),
                actual.lines
            ));
        }
    }
    Ok(())
}

fn update_manifest_inputs(snapshot: &OracleSnapshot, manifest: &mut OracleManifest) {
    for (input, snapshotted) in manifest.inputs.iter_mut().zip(snapshot.files.iter()) {
        debug_assert_eq!(input.path, snapshotted.path);
        input.sha256.clone_from(&snapshotted.sha256);
    }
}

fn update_fixtures(
    root: &Path,
    manifest: &mut OracleManifest,
    generated: &[GeneratedFixture],
) -> Result<(), String> {
    fs::create_dir_all(root.join(ORACLE_FIXTURE_DIRECTORY)).map_err(|error| {
        format!(
            "cannot create xtables oracle fixture directory {}: {error}",
            root.join(ORACLE_FIXTURE_DIRECTORY).display()
        )
    })?;
    for (((entry, expected), actual), index) in manifest
        .fixtures
        .iter_mut()
        .zip(FIXTURE_SPECS)
        .zip(generated)
        .zip(0usize..)
    {
        write_atomic(&root.join(expected.path), &actual.bytes, index)?;
        entry.sha256.clone_from(&actual.sha256);
        entry.bytes = actual.bytes.len();
        entry.lines = actual.lines;
    }
    Ok(())
}

fn write_manifest(path: &Path, manifest: &OracleManifest) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|error| format!("cannot encode xtables oracle manifest: {error}"))?;
    bytes.push(b'\n');
    write_atomic(path, &bytes, FIXTURE_SPECS.len())
}

fn write_atomic(path: &Path, bytes: &[u8], nonce: usize) -> Result<(), String> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "refusing to replace non-regular oracle file {}",
                path.display()
            ));
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("oracle path has no parent: {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("oracle path has no UTF-8 file name: {}", path.display()))?;
    let temporary = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync {}: {error}", temporary.display()))?;
        fs::rename(&temporary, path).map_err(|error| {
            format!(
                "cannot replace {} with {}: {error}",
                path.display(),
                temporary.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn require_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} must be a real file: {}", path.display()));
    }
    Ok(())
}

fn read_workspace_file_bounded(
    root: &Path,
    relative: &str,
    label: &str,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let relative_path = Path::new(relative);
    let components = relative_path.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err(format!("{label} path is empty"));
    }
    let mut current = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(component) = component else {
            return Err(format!(
                "{label} path is not a fixed relative path: {relative}"
            ));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("cannot inspect {label} {}: {error}", current.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "{label} path contains a symlink: {}",
                current.display()
            ));
        }
        let is_last = index + 1 == components.len();
        if (is_last && !metadata.is_file()) || (!is_last && !metadata.is_dir()) {
            return Err(format!(
                "{label} path has the wrong file type: {}",
                current.display()
            ));
        }
    }
    read_regular_file_bounded(&current, label, maximum)
}

fn read_regular_file_bounded(path: &Path, label: &str, maximum: usize) -> Result<Vec<u8>, String> {
    require_regular_file(path, label)?;
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    let declared = usize::try_from(metadata.len())
        .map_err(|_| format!("{label} is too large: {}", path.display()))?;
    if declared > maximum {
        return Err(format!(
            "{label} exceeds the {maximum}-byte limit: {}",
            path.display()
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(LINUX_O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|error| format!("cannot open {label} {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("cannot inspect opened {label} {}: {error}", path.display()))?;
    if !opened.is_file() || opened.len() > maximum as u64 {
        return Err(format!(
            "opened {label} exceeds the {maximum}-byte regular-file limit: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(declared);
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    if bytes.len() > maximum {
        return Err(format!(
            "{label} grew beyond the {maximum}-byte limit while reading: {}",
            path.display()
        ));
    }
    Ok(bytes)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_digest(hasher.finalize().as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn capture_summary(capture: &BoundedCapture) -> String {
    format!(
        "bytes={}, sha256={}, preview={}",
        capture.total_bytes,
        capture.sha256,
        escaped_preview(&capture.retained)
    )
}

fn bytes_summary(bytes: &[u8]) -> String {
    format!(
        "bytes={}, sha256={}, preview={}",
        bytes.len(),
        sha256_bytes(bytes),
        escaped_preview(bytes)
    )
}

fn escaped_preview(bytes: &[u8]) -> String {
    let limited = &bytes[..bytes
        .len()
        .min(MAX_DIAGNOSTIC_BYTES)
        .min(MAX_DIAGNOSTIC_PREVIEW_BYTES)];
    let mut rendered = String::with_capacity(limited.len().saturating_mul(4));
    rendered.push('"');
    for byte in limited {
        for escaped in byte.escape_ascii() {
            rendered.push(char::from(escaped));
        }
    }
    if bytes.len() > limited.len() {
        rendered.push_str("...[redacted]");
    }
    rendered.push('"');
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const HASH_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn valid_manifest() -> OracleManifest {
        OracleManifest {
            schema_version: ORACLE_SCHEMA_VERSION,
            profile: ORACLE_PROFILE.to_owned(),
            environment: OracleEnvironment {
                source_index: BUSYBOX_SOURCE_INDEX.to_owned(),
                platform_image: BUSYBOX_PLATFORM_IMAGE.to_owned(),
                platform: ORACLE_PLATFORM.to_owned(),
                layer_digest: BUSYBOX_LAYER_DIGEST.to_owned(),
                busybox_path: BUSYBOX_PATH.to_owned(),
                busybox_sha256: BUSYBOX_SHA256.to_owned(),
                busybox_version: BUSYBOX_VERSION.to_owned(),
            },
            inputs: INPUT_SPECS
                .into_iter()
                .map(|input| OracleInput {
                    path: input.path.to_owned(),
                    sha256: HASH_A.to_owned(),
                })
                .collect(),
            fixtures: FIXTURE_SPECS
                .into_iter()
                .map(|fixture| OracleFixture {
                    id: fixture.id.to_owned(),
                    path: fixture.path.to_owned(),
                    action: fixture.action,
                    family: fixture.family,
                    sha256: HASH_B.to_owned(),
                    bytes: 1,
                    lines: 1,
                })
                .collect(),
        }
    }

    struct ParsedTarEntry {
        path: String,
        mode: u64,
        uid: u64,
        gid: u64,
        mtime: u64,
        entry_type: u8,
        link_name: Vec<u8>,
        contents: Vec<u8>,
    }

    fn parse_tar_entries(archive: &[u8]) -> Vec<ParsedTarEntry> {
        assert_eq!(archive.len() % TAR_BLOCK_BYTES, 0);
        assert!(archive.ends_with(&[0_u8; TAR_END_BYTES]));
        let mut entries = Vec::new();
        let mut offset = 0usize;
        while offset + TAR_END_BYTES <= archive.len() {
            let header = &archive[offset..offset + TAR_BLOCK_BYTES];
            if header.iter().all(|byte| *byte == 0) {
                assert!(archive[offset..].iter().all(|byte| *byte == 0));
                break;
            }
            let mut checksum_header = header.to_vec();
            checksum_header[148..156].fill(b' ');
            let expected_checksum = parse_tar_octal(&header[148..156]);
            let actual_checksum = checksum_header
                .iter()
                .map(|byte| u64::from(*byte))
                .sum::<u64>();
            assert_eq!(actual_checksum, expected_checksum);
            assert_eq!(&header[257..263], b"ustar\0");
            assert_eq!(&header[263..265], b"00");

            let size = usize::try_from(parse_tar_octal(&header[124..136])).unwrap();
            let data_start = offset + TAR_BLOCK_BYTES;
            let data_end = data_start + size;
            entries.push(ParsedTarEntry {
                path: parse_tar_text(&header[0..100]),
                mode: parse_tar_octal(&header[100..108]),
                uid: parse_tar_octal(&header[108..116]),
                gid: parse_tar_octal(&header[116..124]),
                mtime: parse_tar_octal(&header[136..148]),
                entry_type: header[156],
                link_name: header[157..257].to_vec(),
                contents: archive[data_start..data_end].to_vec(),
            });
            offset = data_start + round_up_tar_block(size).unwrap();
        }
        entries
    }

    fn parse_tar_text(field: &[u8]) -> String {
        let end = field
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(field.len());
        String::from_utf8(field[..end].to_vec()).unwrap()
    }

    fn parse_tar_octal(field: &[u8]) -> u64 {
        let text = field
            .iter()
            .copied()
            .take_while(|byte| *byte != 0 && *byte != b' ')
            .map(char::from)
            .collect::<String>();
        let trimmed = text.trim_start_matches('0');
        u64::from_str_radix(if trimmed.is_empty() { "0" } else { trimmed }, 8).unwrap()
    }

    #[test]
    fn options_require_one_explicit_non_mutating_or_update_mode() {
        assert_eq!(
            parse_options(&[OsString::from("--check")]),
            Ok(OracleMode::Check)
        );
        assert_eq!(
            parse_options(&[OsString::from("--update")]),
            Ok(OracleMode::Update)
        );
        assert!(parse_options(&[]).is_err());
        assert!(parse_options(&[OsString::from("--check"), OsString::from("--update")]).is_err());
        assert!(parse_options(&[OsString::from("--write")]).is_err());
    }

    #[test]
    fn manifest_requires_exact_digest_pins_inputs_and_fixture_matrix() {
        let mut manifest = valid_manifest();
        validate_manifest(&manifest).expect("valid pinned oracle manifest");

        manifest.environment.platform_image = "docker.io/library/busybox:latest".to_owned();
        assert!(validate_manifest(&manifest).is_err());
        manifest = valid_manifest();
        manifest.environment.platform = "linux/arm64".to_owned();
        assert!(validate_manifest(&manifest).is_err());
        manifest = valid_manifest();
        manifest.inputs.swap(0, 1);
        assert!(validate_manifest(&manifest).is_err());
        manifest = valid_manifest();
        manifest.fixtures.pop();
        assert!(validate_manifest(&manifest).is_err());
        manifest = valid_manifest();
        manifest.fixtures[0].sha256 = "0".repeat(64);
        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn docker_invocation_is_read_only_networkless_capability_free_and_environment_scrubbed() {
        let manifest = valid_manifest();
        let arguments = docker_arguments(
            &manifest.environment,
            &["ash", "/tmp/workspace/generate.sh", "fixture"],
        )
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

        for required in [
            "--pull=never",
            "-i",
            "--platform=linux/amd64",
            "--network=none",
            "--ipc=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges=true",
            "--user=65534:65534",
            "--entrypoint=/bin/busybox",
            "--workdir=/tmp",
            "ash",
            "-c",
            CONTAINER_WRAPPER,
        ] {
            assert!(arguments.iter().any(|argument| argument == required));
        }
        assert!(arguments.iter().all(|argument| argument != "--privileged"));
        assert!(arguments.iter().all(|argument| argument != "--mount"));
        assert!(
            arguments
                .iter()
                .all(|argument| !argument.contains("type=bind"))
        );
        assert!(
            arguments
                .iter()
                .all(|argument| !argument.contains("/mnt/d/Github/Flux"))
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument == &manifest.environment.platform_image)
        );
        assert!(CONTAINER_WRAPPER.contains("tar -xof - -C"));
        assert!(CONTAINER_WRAPPER.contains("timeout -s KILL 30s"));
        assert!(CONTAINER_WRAPPER.contains("ORACLE_WORKSPACE=\"${workspace}\""));
    }

    #[test]
    fn snapshot_archive_is_deterministic_minimal_ustar_with_fixed_metadata() {
        let files = INPUT_SPECS
            .into_iter()
            .map(|input| {
                let bytes = format!("snapshot:{}\n", input.path).into_bytes();
                SnapshotFile {
                    path: input.path,
                    sha256: sha256_bytes(&bytes),
                    bytes: bytes.into_boxed_slice(),
                }
            })
            .collect::<Vec<_>>();
        let first = build_ustar(&files).expect("first deterministic archive");
        let second = build_ustar(&files).expect("second deterministic archive");
        assert_eq!(first, second);
        assert!(first.len() <= MAX_SNAPSHOT_ARCHIVE_BYTES);

        let entries = parse_tar_entries(&first);
        let expected_paths = ARCHIVE_DIRECTORIES
            .into_iter()
            .chain(INPUT_SPECS.into_iter().map(|input| input.path))
            .collect::<Vec<_>>();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            expected_paths
        );
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(entry.uid, TAR_OWNER_ID);
            assert_eq!(entry.gid, TAR_OWNER_ID);
            assert_eq!(entry.mtime, 0);
            assert!(entry.link_name.iter().all(|byte| *byte == 0));
            if index < ARCHIVE_DIRECTORIES.len() {
                assert_eq!(entry.entry_type, b'5');
                assert_eq!(entry.mode, 0o755);
                assert!(entry.contents.is_empty());
            } else {
                assert_eq!(entry.entry_type, b'0');
                assert_eq!(entry.mode, 0o444);
                assert_eq!(
                    entry.contents.as_slice(),
                    files[index - ARCHIVE_DIRECTORIES.len()].bytes.as_ref()
                );
            }
        }
    }

    #[test]
    fn bounded_capture_drains_full_stream_but_retains_only_its_limit() {
        let bytes = (0..10_000_u32)
            .map(|value| (value % 251) as u8)
            .collect::<Vec<_>>();
        let capture = drain_bounded(std::io::Cursor::new(bytes.clone()), 127)
            .expect("bounded in-memory capture");
        assert_eq!(capture.total_bytes, bytes.len() as u64);
        assert_eq!(capture.retained, bytes[..127]);
        assert_eq!(capture.sha256, sha256_bytes(&bytes));
    }

    #[cfg(unix)]
    #[test]
    fn parent_wall_clock_timeout_kills_the_child() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exec sleep 5"]);
        let started = Instant::now();
        let capture = run_bounded_command(
            command,
            Arc::from(Vec::<u8>::new()),
            128,
            Duration::from_millis(75),
        )
        .expect("bounded child capture");
        assert!(capture.timed_out);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires FLUX_ORACLE_BUSYBOX_ROOT and bubblewrap"]
    fn pinned_busybox_bwrap_replays_stdin_snapshot_without_a_repository_bind() {
        let rootfs = env::var_os("FLUX_ORACLE_BUSYBOX_ROOT")
            .map(PathBuf::from)
            .expect("FLUX_ORACLE_BUSYBOX_ROOT");
        let root = workspace_root().expect("workspace root");
        let snapshot = read_input_snapshot(&root).expect("bounded input snapshot");

        let run = |arguments: &[&str], limit: usize| {
            let mut command = Command::new("bwrap");
            command
                .arg("--unshare-all")
                .arg("--die-with-parent")
                .arg("--new-session")
                .arg("--ro-bind")
                .arg(&rootfs)
                .arg("/")
                .arg("--tmpfs")
                .arg("/tmp")
                .arg("--dev")
                .arg("/dev")
                .arg("--proc")
                .arg("/proc")
                .arg("--chdir")
                .arg("/tmp")
                .arg("--clearenv")
                .args([BUSYBOX_PATH, "ash", "-c", CONTAINER_WRAPPER, "flux-oracle"])
                .args(arguments);
            let capture = run_bounded_command(
                command,
                Arc::clone(&snapshot.archive),
                limit,
                PARENT_TIMEOUT,
            )
            .expect("bounded bwrap execution");
            assert!(!capture.timed_out, "bwrap execution timed out");
            assert!(capture.status.success(), "bwrap status: {}", capture.status);
            assert_eq!(capture.stderr.total_bytes, 0, "bwrap stderr");
            assert!(capture.stdout.total_bytes <= limit as u64);
            capture.stdout.retained
        };

        let probe = run(
            &[
                "ash",
                "/tmp/workspace/tests/oracle/xtables/generate.sh",
                "probe",
            ],
            MAX_PROBE_OUTPUT_BYTES,
        );
        let expected_probe =
            format!("busybox_sha256={BUSYBOX_SHA256}\nbusybox_version={BUSYBOX_VERSION}\n");
        assert_eq!(probe, expected_probe.as_bytes());
        assert_eq!(
            run(
                &["ash", "/tmp/workspace/tests/shell/rules_generation.sh"],
                MAX_SEMANTIC_OUTPUT_BYTES,
            ),
            EXPECTED_SEMANTIC_TEST_OUTPUT
        );
        for fixture in FIXTURE_SPECS {
            let generated = run(
                &[
                    "ash",
                    "/tmp/workspace/tests/oracle/xtables/generate.sh",
                    fixture.id,
                ],
                MAX_ORACLE_OUTPUT_BYTES,
            );
            let checked_in = read_regular_file_bounded(
                &root.join(fixture.path),
                "xtables oracle fixture",
                MAX_ORACLE_OUTPUT_BYTES,
            )
            .expect("checked-in fixture");
            assert_eq!(generated, checked_in, "{} bytes", fixture.id);
        }
    }

    #[test]
    fn raw_restore_validation_requires_printable_ascii_single_spacing_and_final_lf() {
        assert_eq!(
            validate_restore_bytes("valid", b"*mangle\n-A OUTPUT -j ACCEPT\nCOMMIT\n"),
            Ok(3)
        );
        for invalid in [
            b"*mangle\nCOMMIT".as_slice(),
            b"*mangle\r\nCOMMIT\r\n".as_slice(),
            b"*mangle\n\nCOMMIT\n".as_slice(),
            b"*mangle\n-A  OUTPUT -j ACCEPT\nCOMMIT\n".as_slice(),
            b"*mangle\n-A OUTPUT -j ACCEPT \nCOMMIT\n".as_slice(),
        ] {
            assert!(validate_restore_bytes("invalid", invalid).is_err());
        }
    }

    #[test]
    fn checked_in_manifest_fixtures_and_source_hashes_match_without_running_shell() {
        let root = workspace_root().expect("workspace root");
        let manifest = read_manifest(&root.join(ORACLE_MANIFEST)).expect("checked-in manifest");
        let snapshot = read_input_snapshot(&root).expect("bounded input snapshot");
        validate_manifest(&manifest).expect("strict manifest");
        validate_fixture_inventory(&root, false).expect("exact fixture inventory");
        verify_input_hashes(&snapshot, &manifest).expect("current input hashes");
        verify_checked_in_fixture_metadata(&root, &manifest)
            .expect("current fixture hashes and counts");
    }
}
