use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use toml::Value;

#[cfg(test)]
use super::ANDROID_RUSTFLAGS;
use super::android_artifact::AndroidArtifactIdentity;
use super::android_canary::{
    DeviceProfile, Options as AndroidTargetOptions, adb_root_shell_output, command_output_bounded,
    device_identity_function, push_artifact, revalidate_device, verify_device,
};
use super::android_remote::{
    FilesystemIdentity, OwnedRemoteDirectory, OwnedRemoteDirectorySpec,
    normalize_adb_shell_newlines, normalize_adb_shell_output,
    owned_root_functions_with_engine_group, parse_directory_identity, path_absence_function,
    process_absence_function, run_owned_remote_transaction, shell_single_quote,
};
use super::{
    ANDROID_NDK_REVISION, ANDROID_TARGET, ANDROID_TARGET_RUSTFLAGS_ENV,
    LINUX_ANDROID_HOST_BUILD_TMPDIR, android_linker, validate_aarch64_elf, validate_https_url,
    verify_ndk_revision, workspace_root,
};

pub(super) const COMMAND: &str = "qualify-functional-canary-android";

const CLANG_TARGET: &str = "aarch64-linux-android";
const LINKER_ENV: &str = "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER";
const CC_ENV: &str = "CC_aarch64_linux_android";
const QUALIFICATION_TARGET_DIRECTORY: &str = "target/android-functional-qualification";
const QUALIFICATION_RUSTFLAGS: &str = concat!(
    "-C link-arg=-Wl,-z,max-page-size=16384 ",
    "-C link-arg=-Wl,-z,common-page-size=16384 ",
    "--cfg flux_android_qualification"
);

const REMOTE_DIRECTORY_SPEC: OwnedRemoteDirectorySpec = OwnedRemoteDirectorySpec::new(
    "/data/local/tmp/flux-q11.",
    32,
    ".flux-q11-owner",
    "flux-android-production-canary-qualification-v1",
);
const REMOTE_IDENTITY_BEGIN: &str = "FLUX_ANDROID_Q11_DIRECTORY_BEGIN";
const REMOTE_IDENTITY_END: &str = "FLUX_ANDROID_Q11_DIRECTORY_END";
const REMOTE_FLUXD_NAME: &str = "fluxd-q11";
const REMOTE_PRODUCER_NAME: &str = "flux-sbox-q11";
const REMOTE_CONFIG_NAME: &str = "flux-q11.toml";
const REMOTE_RECOVERY_CONFIG_NAME: &str = "flux-q11-recovery.toml";
const REMOTE_TEMPLATE_NAME: &str = "template-q11.json";
const REMOTE_SUBSCRIPTION_NAME: &str = "subscription-q11.url";
const REMOTE_PROCESS_NAMES: [&str; 2] = [REMOTE_FLUXD_NAME, REMOTE_PRODUCER_NAME];
const QUALIFICATION_ENGINE_UID: u32 = 2_900_002;
const QUALIFICATION_ENGINE_GID: u32 = 2_900_002;
const TRUSTED_ANDROID_PATH: &str = concat!(
    "/product/bin:",
    "/apex/com.android.runtime/bin:",
    "/apex/com.android.art/bin:",
    "/system_ext/bin:",
    "/system/bin:",
    "/system/xbin:",
    "/odm/bin:",
    "/vendor/bin:",
    "/vendor/xbin"
);

const MAX_SUBSCRIPTION_URL_BYTES: usize = 8 * 1024;
const QUALIFICATION_DOWNLOAD_TIMEOUT_SECS: i64 = 60;
const MAX_CARGO_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const CARGO_BUILD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const ADB_QUERY_TIMEOUT: Duration = Duration::from_secs(15);
const PEER_NAMESPACE_ABSENCE_TIMEOUT: Duration = Duration::from_secs(60);
const ADB_EXECUTION_TIMEOUT: Duration = Duration::from_secs(180);
const ADB_CLEANUP_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_RUN_MANIFEST_BYTES: u64 = 512 * 1024;
#[cfg(test)]
const DIAGNOSTIC_STATUS_BEGIN: &str = "FLUX_ANDROID_Q11_STATUS_BEGIN";
#[cfg(test)]
const DIAGNOSTIC_STATUS_END: &str = "FLUX_ANDROID_Q11_STATUS_END";
#[cfg(test)]
const DIAGNOSTIC_STDERR_BEGIN: &str = "FLUX_ANDROID_Q11_STDERR_BEGIN";
#[cfg(test)]
const DIAGNOSTIC_STDERR_END: &str = "FLUX_ANDROID_Q11_STDERR_END";
const PEER_NAMESPACE_REPORT_MAGIC: &[u8; 8] = b"FLXQ11NS";
const PEER_NAMESPACE_REPORT_VERSION: u16 = 1;
const PEER_NAMESPACE_REPORT_PAYLOAD_BYTES: u16 = 16;
const PEER_NAMESPACE_REPORT_FRAME_BYTES: usize = 28;
const QUALIFICATION_PASS_RECEIPT: &str = "FLUX_ANDROID_Q11_PASS";
const QUALIFICATION_PASS_RECEIPT_LINE: &[u8] = b"FLUX_ANDROID_Q11_PASS\n";
const QUALIFICATION_DAEMON_EXITED_STATUS: i32 = 74;
const QUALIFICATION_READINESS_DEADLINE_STATUS: i32 = 75;
const QUALIFICATION_DAEMON_FAILURE_PREFIX: &[u8] = b"FLUX_ANDROID_Q11_FAILURE=";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Options {
    target: AndroidTargetOptions,
    producer: PathBuf,
    run_manifest: PathBuf,
    subscription: SubscriptionInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SubscriptionInput {
    File(PathBuf),
    Stdin,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PeerNetworkNamespaceIdentity {
    device: u64,
    inode: u64,
}

impl PeerNetworkNamespaceIdentity {
    fn new(device: u64, inode: u64) -> Option<Self> {
        (inode != 0).then_some(Self { device, inode })
    }

    fn canonical(self) -> String {
        format!("{}:{}", self.device, self.inode)
    }

    fn mount_device(self) -> String {
        format!(
            "{}:{}",
            linux_device_major(self.device),
            linux_device_minor(self.device)
        )
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct QualificationExecutionReceipt {
    peer_network_namespace: PeerNetworkNamespaceIdentity,
    passed: bool,
}

pub(super) fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    let mut serial = None;
    let mut adb = None;
    let mut producer = None;
    let mut run_manifest = None;
    let mut subscription_file = None;
    let mut subscription_stdin = false;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "Android qualification options must be UTF-8".to_owned())?;
        index += 1;
        if flag == "--subscription-stdin" {
            if subscription_stdin {
                return Err("--subscription-stdin may only be supplied once".to_owned());
            }
            subscription_stdin = true;
            continue;
        }
        let value = arguments
            .get(index)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        index += 1;
        match flag {
            "--serial" if serial.replace(value.clone()).is_none() => {}
            "--adb" if adb.replace(value.clone()).is_none() => {}
            "--producer"
                if producer
                    .replace(require_absolute_path(flag, value)?)
                    .is_none() => {}
            "--run-manifest"
                if run_manifest
                    .replace(require_absolute_path(flag, value)?)
                    .is_none() => {}
            "--subscription-file"
                if subscription_file
                    .replace(require_absolute_path(flag, value)?)
                    .is_none() => {}
            "--serial" | "--adb" | "--producer" | "--run-manifest" | "--subscription-file" => {
                return Err(format!("{flag} may only be supplied once"));
            }
            unknown => return Err(format!("unknown Android qualification option '{unknown}'")),
        }
    }
    let serial = serial
        .ok_or_else(|| format!("{COMMAND} requires --serial SERIAL"))?
        .into_string()
        .map_err(|_| "--serial must contain valid UTF-8".to_owned())?;
    let target = AndroidTargetOptions::for_shared_target(
        serial,
        adb.or_else(|| env::var_os("ADB"))
            .unwrap_or_else(|| OsString::from("adb")),
    )?;
    let subscription = match (subscription_file, subscription_stdin) {
        (Some(_), true) => {
            return Err(
                "--subscription-file and --subscription-stdin are mutually exclusive".to_owned(),
            );
        }
        (Some(path), false) => SubscriptionInput::File(path),
        (None, true) => SubscriptionInput::Stdin,
        (None, false) => {
            return Err(format!(
                "{COMMAND} requires --subscription-file FILE or --subscription-stdin"
            ));
        }
    };
    Ok(Options {
        target,
        producer: producer.ok_or_else(|| format!("{COMMAND} requires --producer FILE"))?,
        run_manifest: run_manifest
            .ok_or_else(|| format!("{COMMAND} requires --run-manifest FILE"))?,
        subscription,
    })
}

fn require_absolute_path(flag: &str, value: &OsStr) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(format!("{flag} must be an absolute file path"))
    }
}

fn validate_run_manifest(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect qualification run manifest: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_RUN_MANIFEST_BYTES
    {
        return Err(format!(
            "qualification run manifest must be one nonempty regular file of at most {MAX_RUN_MANIFEST_BYTES} bytes"
        ));
    }
    let manifest = fs::read_to_string(path)
        .map_err(|error| format!("read qualification run manifest: {error}"))?;
    validate_run_manifest_text(&manifest)
}

fn validate_run_manifest_text(manifest: &str) -> Result<(), String> {
    let mut pending_sha_declarations = 0usize;
    let mut saw_sha_declaration = false;
    let mut in_binding_table = false;

    for line in manifest.lines() {
        if line.starts_with("| Object | Path or identity | SHA-256 / Git tree |") {
            in_binding_table = true;
            continue;
        }
        if in_binding_table {
            if !line.starts_with('|') {
                in_binding_table = false;
            } else if !line.contains("|---") {
                validate_manifest_binding_row(line)?;
            }
        }

        let declaration_count = if line.contains("SHA-256 / Git tree") {
            0
        } else {
            line.matches("SHA-256").count()
        };
        if declaration_count == 0 && pending_sha_declarations == 0 {
            continue;
        }

        saw_sha_declaration |= declaration_count != 0;
        let expected = pending_sha_declarations.saturating_add(declaration_count);
        let spans = markdown_code_spans(line);
        let consumed = spans.len().min(expected);
        for span in spans.iter().take(consumed) {
            validate_manifest_sha256(span)?;
        }
        pending_sha_declarations = expected.saturating_sub(consumed);
    }

    if pending_sha_declarations != 0 {
        return Err(
            "qualification run manifest has an SHA-256 declaration without a code-span value"
                .to_owned(),
        );
    }
    if !saw_sha_declaration {
        return Err("qualification run manifest declares no SHA-256 values".to_owned());
    }
    Ok(())
}

fn validate_manifest_binding_row(line: &str) -> Result<(), String> {
    let cells = line.split('|').map(str::trim).collect::<Vec<_>>();
    if cells.len() < 5 {
        return Err(
            "qualification run manifest has a malformed source/artifact binding row".to_owned(),
        );
    }
    let kind = cells[2];
    let value = cells[3].trim_matches('`');
    if value == "—" || value.is_empty() {
        return Ok(());
    }
    if kind == "Git commit" || kind == "Git tree" {
        if value.len() != 40 || !value.bytes().all(is_lower_hex) {
            return Err(format!(
                "qualification run manifest {kind} binding must be exactly 40 lowercase hexadecimal characters"
            ));
        }
        return Ok(());
    }
    validate_manifest_sha256(value)
}

fn validate_manifest_sha256(value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(is_lower_hex) {
        Ok(())
    } else {
        Err(
            "qualification run manifest SHA-256 values must be exactly 64 lowercase hexadecimal characters"
                .to_owned(),
        )
    }
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn markdown_code_spans(line: &str) -> Vec<&str> {
    let mut spans = Vec::new();
    let mut opening = None;
    for (index, byte) in line.bytes().enumerate() {
        if byte != b'`' {
            continue;
        }
        match opening.take() {
            Some(start) => spans.push(&line[start..index]),
            None => opening = Some(index + 1),
        }
    }
    spans
}

pub(super) fn run(options: Options) -> Result<(), String> {
    if env::consts::OS != "linux" {
        return Err(
            "the ARM64 Android production-canary qualification requires Linux/WSL".to_owned(),
        );
    }

    validate_run_manifest(&options.run_manifest)?;
    let device = verify_device(&options.target)?;
    if device.target_rust_target() != ANDROID_TARGET {
        return Err(
            "the production-canary qualification accepts only an ARM64 Android kernel and ABI"
                .to_owned(),
        );
    }
    super::sing_box_producer::validate_android_artifact(&options.producer)?;
    let producer_identity = AndroidArtifactIdentity::from_file(
        &options.producer,
        "manifest-bound Android Sing-Box producer",
    )?;
    let stage = QualificationHostStage::new()?;
    let subscription = match &options.subscription {
        SubscriptionInput::File(path) => SecretSubscription::read_file(path)?,
        SubscriptionInput::Stdin => SecretSubscription::read_stdin(&stage)?,
    };

    let ndk_root = env::var_os("ANDROID_NDK_HOME")
        .or_else(|| env::var_os("ANDROID_NDK_ROOT"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            format!("ANDROID_NDK_HOME must point to Android NDK revision {ANDROID_NDK_REVISION}")
        })?;
    verify_ndk_revision(&ndk_root)?;
    let linker = android_linker(&ndk_root, ANDROID_TARGET, CLANG_TARGET)?;
    let root = workspace_root()?;
    let qualification_target = root.join(QUALIFICATION_TARGET_DIRECTORY);
    let fluxd = build_qualification_fluxd(&linker, &qualification_target)?;
    validate_aarch64_elf("qualification-only Android fluxd", &fluxd)?;
    let fluxd_identity =
        AndroidArtifactIdentity::from_file(&fluxd, "qualification-only Android fluxd")?;

    let remote = REMOTE_DIRECTORY_SPEC.generate("Android production-canary qualification")?;
    let staged = stage.prepare(&root, remote.path())?;
    let artifacts = QualificationArtifacts::new(
        fluxd,
        fluxd_identity,
        options.producer.clone(),
        producer_identity,
        staged,
        &subscription.path,
        subscription.identity.clone(),
    )?;
    artifacts.verify()?;
    revalidate_device(
        &options.target,
        &device,
        "before qualification remote transaction",
    )?;

    let mut remote = remote;
    preflight_remote_directory(&options.target, &device, &remote)?;
    let mut peer_network_namespace = None;
    let mut peer_namespace_receipt_required = false;
    let transaction = run_owned_remote_transaction(
        &mut remote,
        |remote| create_remote_directory(&options.target, &device, remote),
        |remote| {
            execute_qualification(
                &options.target,
                &device,
                remote,
                &artifacts,
                &mut peer_network_namespace,
                &mut peer_namespace_receipt_required,
            )
        },
        |remote| cleanup_qualification(&options.target, &device, remote, &artifacts),
    );
    let peer_namespace_absence = match peer_network_namespace {
        Some(identity) => prove_peer_network_namespace_absent(&options.target, &device, identity),
        None => {
            missing_peer_namespace_receipt_result(&transaction, peer_namespace_receipt_required)
        }
    };
    combine_transaction_and_peer_namespace_absence(transaction, peer_namespace_absence)?;
    revalidate_device(
        &options.target,
        &device,
        "after qualification absence proof",
    )?;

    println!(
        "qualification_fluxd_sha256={} qualification_fluxd_bytes={}",
        artifacts.fluxd_identity.sha256(),
        artifacts.fluxd_identity.size()
    );
    println!(
        "qualification_producer_sha256={} qualification_producer_bytes={}",
        artifacts.producer_identity.sha256(),
        artifacts.producer_identity.size()
    );
    println!(
        "Android production-canary qualification completed with exact owned-state cleanup; development evidence only"
    );
    Ok(())
}

fn build_qualification_fluxd(linker: &Path, target_directory: &Path) -> Result<PathBuf, String> {
    let mut command = qualification_build_command(linker, target_directory);
    let output = command_output_bounded(
        &mut command,
        None,
        CARGO_BUILD_TIMEOUT,
        MAX_CARGO_CAPTURE_BYTES,
        "cross-build qualification-only Android fluxd",
    )?;
    if !output.status.success() {
        return Err(format!(
            "qualification-only Android fluxd build exited with {}",
            output.status
        ));
    }
    let artifact = target_directory
        .join(ANDROID_TARGET)
        .join("release")
        .join("fluxd");
    if artifact.is_file() {
        Ok(artifact)
    } else {
        Err("qualification build did not produce the exact isolated fluxd artifact".to_owned())
    }
}

fn qualification_build_command(linker: &Path, target_directory: &Path) -> Command {
    let mut command = Command::new("cargo");
    command.args([
        "build",
        "-p",
        "fluxd",
        "--bin",
        "fluxd",
        "--release",
        "--target",
        ANDROID_TARGET,
    ]);
    command.env(LINKER_ENV, linker);
    command.env(CC_ENV, linker);
    command.env(ANDROID_TARGET_RUSTFLAGS_ENV, QUALIFICATION_RUSTFLAGS);
    command.env("CARGO_TARGET_DIR", target_directory);
    command.env("TMPDIR", LINUX_ANDROID_HOST_BUILD_TMPDIR);
    command
}

struct SecretSubscription {
    path: PathBuf,
    identity: AndroidArtifactIdentity,
}

impl SecretSubscription {
    fn read_file(path: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("inspect subscription credential file: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_SUBSCRIPTION_URL_BYTES as u64
        {
            return Err(format!(
                "subscription credential must be one nonempty regular file of at most {MAX_SUBSCRIPTION_URL_BYTES} bytes"
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        fs::File::open(path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(|error| format!("read subscription credential file: {error}"))?;
        Self::validate(&bytes)?;
        Ok(Self {
            path: path.to_owned(),
            identity: AndroidArtifactIdentity::from_file(path, "subscription credential")?,
        })
    }

    fn read_stdin(stage: &QualificationHostStage) -> Result<Self, String> {
        let mut bytes = Vec::new();
        let stdin = std::io::stdin();
        stdin
            .lock()
            .take((MAX_SUBSCRIPTION_URL_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)
            .map_err(|error| format!("read subscription credential from stdin: {error}"))?;
        if bytes.len() > MAX_SUBSCRIPTION_URL_BYTES {
            return Err(format!(
                "subscription credential exceeds the {MAX_SUBSCRIPTION_URL_BYTES}-byte limit"
            ));
        }
        Self::validate(&bytes)?;
        let path = stage.root.join(REMOTE_SUBSCRIPTION_NAME);
        write_private_file(&path, &bytes)?;
        Ok(Self {
            identity: AndroidArtifactIdentity::from_file(&path, "subscription credential")?,
            path,
        })
    }

    fn validate(bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Err("subscription credential must not be empty".to_owned());
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "subscription credential file must be UTF-8".to_owned())?;
        let url = text.strip_suffix('\n').unwrap_or(text);
        if url.contains(['\r', '\n']) {
            return Err(
                "subscription credential file must contain exactly one URL line".to_owned(),
            );
        }
        validate_https_url("subscription credential", url)?;
        Ok(())
    }
}

struct QualificationHostStage {
    root: PathBuf,
}

impl QualificationHostStage {
    fn new() -> Result<Self, String> {
        let mut nonce = [0_u8; 16];
        fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut nonce))
            .map_err(|error| format!("generate qualification host-stage identity: {error}"))?;
        let encoded = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let root = PathBuf::from(LINUX_ANDROID_HOST_BUILD_TMPDIR)
            .join(format!("flux-android-q11.{encoded}"));
        fs::create_dir(&root)
            .map_err(|error| format!("create qualification host stage: {error}"))?;
        #[cfg(unix)]
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("secure qualification host stage: {error}"))?;
        Ok(Self { root })
    }

    fn prepare(
        &self,
        workspace: &Path,
        remote_root: &str,
    ) -> Result<StagedQualificationFiles, String> {
        let config = self.root.join(REMOTE_CONFIG_NAME);
        let recovery_config = self.root.join(REMOTE_RECOVERY_CONFIG_NAME);
        write_private_file(
            &config,
            render_qualification_config(remote_root, true, true)?.as_bytes(),
        )?;
        write_private_file(
            &recovery_config,
            render_qualification_config(remote_root, false, false)?.as_bytes(),
        )?;
        let template = workspace.join("conf/template.json");
        if !template.is_file() {
            return Err("the checked engine template is missing".to_owned());
        }
        Ok(StagedQualificationFiles {
            config,
            recovery_config,
            template,
        })
    }
}

impl Drop for QualificationHostStage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| format!("create staged qualification configuration: {error}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("persist staged qualification configuration: {error}"))
}

fn render_qualification_config(
    remote_root: &str,
    require_functional_canary: bool,
    subscription_enabled: bool,
) -> Result<String, String> {
    let mut document: Value = toml::from_str(include_str!("../../conf/flux.toml"))
        .map_err(|error| format!("parse checked Flux configuration: {error}"))?;
    set_config_value(
        &mut document,
        "engine",
        "binary",
        Value::String(format!("{remote_root}/{REMOTE_PRODUCER_NAME}")),
    )?;
    set_config_value(
        &mut document,
        "engine",
        "template",
        Value::String(format!("{remote_root}/{REMOTE_TEMPLATE_NAME}")),
    )?;
    set_config_value(
        &mut document,
        "engine",
        "runtime_uid",
        Value::Integer(i64::from(QUALIFICATION_ENGINE_UID)),
    )?;
    set_config_value(
        &mut document,
        "engine",
        "runtime_gid",
        Value::Integer(i64::from(QUALIFICATION_ENGINE_GID)),
    )?;
    set_config_value(&mut document, "capture", "ipv6", Value::Boolean(true))?;
    set_config_value(
        &mut document,
        "subscription",
        "enabled",
        Value::Boolean(subscription_enabled),
    )?;
    set_config_value(
        &mut document,
        "subscription",
        "url_file",
        Value::String(format!("{remote_root}/{REMOTE_SUBSCRIPTION_NAME}")),
    )?;
    set_config_value(
        &mut document,
        "subscription",
        "download_timeout_secs",
        Value::Integer(QUALIFICATION_DOWNLOAD_TIMEOUT_SECS),
    )?;
    set_config_value(
        &mut document,
        "safety",
        "respect_android_vpn",
        Value::Boolean(false),
    )?;
    set_config_value(
        &mut document,
        "safety",
        "require_functional_canary",
        Value::Boolean(require_functional_canary),
    )?;
    toml::to_string_pretty(&document)
        .map_err(|error| format!("encode qualification Flux configuration: {error}"))
}

fn set_config_value(
    document: &mut Value,
    section: &str,
    field: &str,
    value: Value,
) -> Result<(), String> {
    let table = document
        .as_table_mut()
        .and_then(|root| root.get_mut(section))
        .and_then(Value::as_table_mut)
        .ok_or_else(|| format!("checked Flux configuration omits [{section}]"))?;
    if !table.contains_key(field) {
        return Err(format!(
            "checked Flux configuration omits [{section}].{field}"
        ));
    }
    table.insert(field.to_owned(), value);
    Ok(())
}

struct StagedQualificationFiles {
    config: PathBuf,
    recovery_config: PathBuf,
    template: PathBuf,
}

struct QualificationArtifacts {
    fluxd: PathBuf,
    fluxd_identity: AndroidArtifactIdentity,
    producer: PathBuf,
    producer_identity: AndroidArtifactIdentity,
    config: PathBuf,
    config_identity: AndroidArtifactIdentity,
    recovery_config: PathBuf,
    recovery_config_identity: AndroidArtifactIdentity,
    template: PathBuf,
    template_identity: AndroidArtifactIdentity,
    subscription: PathBuf,
    subscription_identity: AndroidArtifactIdentity,
}

impl QualificationArtifacts {
    fn new(
        fluxd: PathBuf,
        fluxd_identity: AndroidArtifactIdentity,
        producer: PathBuf,
        producer_identity: AndroidArtifactIdentity,
        staged: StagedQualificationFiles,
        subscription: &Path,
        subscription_identity: AndroidArtifactIdentity,
    ) -> Result<Self, String> {
        Ok(Self {
            fluxd,
            fluxd_identity,
            producer,
            producer_identity,
            config_identity: AndroidArtifactIdentity::from_file(
                &staged.config,
                "qualification configuration",
            )?,
            recovery_config_identity: AndroidArtifactIdentity::from_file(
                &staged.recovery_config,
                "qualification recovery configuration",
            )?,
            template_identity: AndroidArtifactIdentity::from_file(
                &staged.template,
                "checked engine template",
            )?,
            subscription_identity,
            config: staged.config,
            recovery_config: staged.recovery_config,
            template: staged.template,
            subscription: subscription.to_owned(),
        })
    }

    fn verify(&self) -> Result<(), String> {
        for (identity, path, description) in [
            (
                &self.fluxd_identity,
                self.fluxd.as_path(),
                "qualification fluxd",
            ),
            (
                &self.producer_identity,
                self.producer.as_path(),
                "manifest-bound producer",
            ),
            (
                &self.config_identity,
                self.config.as_path(),
                "qualification configuration",
            ),
            (
                &self.recovery_config_identity,
                self.recovery_config.as_path(),
                "qualification recovery configuration",
            ),
            (
                &self.template_identity,
                self.template.as_path(),
                "checked engine template",
            ),
            (
                &self.subscription_identity,
                self.subscription.as_path(),
                "subscription credential",
            ),
        ] {
            identity.verify_file(path, description)?;
        }
        Ok(())
    }
}

fn preflight_remote_directory(
    options: &AndroidTargetOptions,
    device: &DeviceProfile,
    remote: &OwnedRemoteDirectory,
) -> Result<(), String> {
    let script = qualification_preflight_script(remote, device);
    let output = normalize_adb_shell_output(adb_root_shell_output(
        options,
        script.as_bytes(),
        ADB_QUERY_TIMEOUT,
        "preflight Android production-canary qualification path",
    )?)?;
    require_silent_success(output, "qualification remote-path preflight")
}

fn qualification_preflight_script(remote: &OwnedRemoteDirectory, device: &DeviceProfile) -> String {
    let root = shell_single_quote(remote.path());
    format!(
        "set -eu\n\
         ROOT={root}\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         identity_matches\n\
         probe_process_absent\n\
         path_absent \"$ROOT\"\n",
        path_absence_function(),
        device_identity_function(device),
        process_absence_function(&REMOTE_PROCESS_NAMES),
    )
}

fn create_remote_directory(
    options: &AndroidTargetOptions,
    device: &DeviceProfile,
    remote: &OwnedRemoteDirectory,
) -> Result<FilesystemIdentity, String> {
    let script = qualification_create_directory_script(remote, device);
    let output = normalize_adb_shell_output(adb_root_shell_output(
        options,
        script.as_bytes(),
        ADB_QUERY_TIMEOUT,
        "create Android production-canary qualification directory",
    )?)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("qualification remote-directory creation failed".to_owned());
    }
    parse_directory_identity(
        &output.stdout,
        REMOTE_IDENTITY_BEGIN,
        REMOTE_IDENTITY_END,
        "directory_identity",
        "Android production-canary qualification directory",
    )
}

fn qualification_create_directory_script(
    remote: &OwnedRemoteDirectory,
    device: &DeviceProfile,
) -> String {
    format!(
        "set -eu\n\
         umask 077\n\
         {}\
         EXPECTED_SHELL_UID='{}'\n\
         EXPECTED_SHELL_GID='{}'\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         identity_matches\n\
         probe_process_absent\n\
         path_absent \"$ROOT\"\n\
         /system/bin/mkdir -m 700 \"$ROOT\"\n\
         CREATED_ID=$(/system/bin/stat -Lc '%d:%i' \"$ROOT\")\n\
         printf '%s\\n' \"$EXPECTED_OWNER_RECORD\" >\"$OWNER\"\n\
         /system/bin/chown 0:0 \"$OWNER\"\n\
         /system/bin/chmod 600 \"$OWNER\"\n\
         /system/bin/chown \"$EXPECTED_SHELL_UID:$EXPECTED_SHELL_GID\" \"$ROOT\"\n\
         echo '{REMOTE_IDENTITY_BEGIN}'\n\
         echo \"directory_identity=$CREATED_ID\"\n\
         echo '{REMOTE_IDENTITY_END}'\n",
        remote.shell_variables(device.shell_uid(), device.shell_gid()),
        device.shell_uid(),
        device.shell_gid(),
        path_absence_function(),
        device_identity_function(device),
        process_absence_function(&REMOTE_PROCESS_NAMES),
    )
}

fn execute_qualification(
    options: &AndroidTargetOptions,
    device: &DeviceProfile,
    remote: &OwnedRemoteDirectory,
    artifacts: &QualificationArtifacts,
    peer_network_namespace: &mut Option<PeerNetworkNamespaceIdentity>,
    peer_namespace_receipt_required: &mut bool,
) -> Result<(), String> {
    artifacts.verify()?;
    revalidate_device(options, device, "before qualification artifact push")?;
    for (path, identity, name, description) in [
        (
            artifacts.fluxd.as_path(),
            &artifacts.fluxd_identity,
            REMOTE_FLUXD_NAME,
            "qualification-only Android fluxd",
        ),
        (
            artifacts.producer.as_path(),
            &artifacts.producer_identity,
            REMOTE_PRODUCER_NAME,
            "manifest-bound Android Sing-Box producer",
        ),
        (
            artifacts.config.as_path(),
            &artifacts.config_identity,
            REMOTE_CONFIG_NAME,
            "qualification configuration",
        ),
        (
            artifacts.recovery_config.as_path(),
            &artifacts.recovery_config_identity,
            REMOTE_RECOVERY_CONFIG_NAME,
            "qualification recovery configuration",
        ),
        (
            artifacts.template.as_path(),
            &artifacts.template_identity,
            REMOTE_TEMPLATE_NAME,
            "checked engine template",
        ),
        (
            artifacts.subscription.as_path(),
            &artifacts.subscription_identity,
            REMOTE_SUBSCRIPTION_NAME,
            "runtime subscription credential",
        ),
    ] {
        push_artifact(
            options,
            path,
            identity,
            &format!("{}/{name}", remote.path()),
            description,
        )?;
    }
    revalidate_device(options, device, "after qualification artifact push")?;
    let script = qualification_execution_script(remote, device, artifacts);
    *peer_namespace_receipt_required = true;
    let mut output = adb_root_shell_output(
        options,
        script.as_bytes(),
        ADB_EXECUTION_TIMEOUT,
        "run Android production-canary qualification transaction",
    )
    .map_err(|_| "Android production-canary qualification transport failed".to_owned())?;
    let passed = if output.stdout.is_empty() {
        None
    } else {
        let (identity, suffix) = decode_qualification_peer_namespace_frame(&output.stdout)?;
        if peer_network_namespace.is_some() {
            return Err(
                "qualification returned a duplicate peer network-namespace receipt".to_owned(),
            );
        }
        // Bind the first complete binary frame before validating trailing shell output or
        // stderr. A malformed suffix must still retain the exact identity for post-cleanup audit.
        *peer_network_namespace = Some(identity);
        Some(parse_qualification_receipt_suffix(suffix)?)
    };
    output.stderr = normalize_adb_shell_newlines(output.stderr, "stderr")?;
    if output.status.success() && passed == Some(true) && output.stderr.is_empty() {
        Ok(())
    } else {
        // Never combine the peer namespace identity with status, stderr, or any other
        // diagnostic text. The independent audit receives it only through its private stdin
        // script after cleanup.
        let diagnostic = qualification_failure_diagnostic(
            output.status.code(),
            passed,
            output.stderr.as_slice(),
        );
        Err(format!(
            "Android production-canary qualification transaction failed at remote status {}; {diagnostic}",
            output.status.code().unwrap_or(-1),
        ))
    }
}

fn qualification_failure_diagnostic(
    status: Option<i32>,
    passed: Option<bool>,
    stderr: &[u8],
) -> String {
    if passed == Some(true) {
        return "diagnostic=qualification-receipt-boundary".to_owned();
    }
    match status {
        Some(QUALIFICATION_DAEMON_EXITED_STATUS) => qualification_daemon_exit_diagnostic(stderr),
        Some(QUALIFICATION_READINESS_DEADLINE_STATUS) if stderr.is_empty() => {
            "diagnostic=qualification-readiness-deadline-exceeded".to_owned()
        }
        _ => "diagnostic=qualification-receipt-boundary".to_owned(),
    }
}

fn qualification_daemon_exit_diagnostic(stderr: &[u8]) -> String {
    if stderr.is_empty() {
        return "diagnostic=qualification-daemon-exited-before-readiness".to_owned();
    }
    let Some(stage) = stderr
        .strip_prefix(QUALIFICATION_DAEMON_FAILURE_PREFIX)
        .and_then(|value| value.strip_suffix(b"\n"))
    else {
        return "diagnostic=qualification-receipt-boundary".to_owned();
    };
    if let Ok(stage) = std::str::from_utf8(stage)
        && let Some(token) = stage.strip_prefix("android-planning-authority/")
    {
        if let Some(token) = qualification_android_planning_failure_token(token) {
            return format!(
                "diagnostic=qualification-daemon-exited-android-planning-authority-{token}"
            );
        }
        return "diagnostic=qualification-receipt-boundary".to_owned();
    }
    match stage {
        b"facility-authority" => {
            "diagnostic=qualification-daemon-exited-facility-authority".to_owned()
        }
        b"native-startup-recovery" => {
            "diagnostic=qualification-daemon-exited-native-startup-recovery".to_owned()
        }
        b"android-planning-authority" => {
            "diagnostic=qualification-daemon-exited-android-planning-authority".to_owned()
        }
        b"native-runtime-composition" => {
            "diagnostic=qualification-daemon-exited-native-runtime-composition".to_owned()
        }
        b"android-planning-retention" => {
            "diagnostic=qualification-daemon-exited-android-planning-retention".to_owned()
        }
        b"subscription-runtime-start" => {
            "diagnostic=qualification-daemon-exited-subscription-runtime-start".to_owned()
        }
        b"runtime-coordinator-composition" => {
            "diagnostic=qualification-daemon-exited-runtime-coordinator-composition".to_owned()
        }
        b"initial-runtime-control" => {
            "diagnostic=qualification-daemon-exited-initial-runtime-control".to_owned()
        }
        b"daemon-configuration" => {
            "diagnostic=qualification-daemon-exited-daemon-configuration".to_owned()
        }
        b"daemon-invariant" => "diagnostic=qualification-daemon-exited-daemon-invariant".to_owned(),
        b"runtime-layout" => "diagnostic=qualification-daemon-exited-runtime-layout".to_owned(),
        b"administrative-intent" => {
            "diagnostic=qualification-daemon-exited-administrative-intent".to_owned()
        }
        b"control-reactor" => "diagnostic=qualification-daemon-exited-control-reactor".to_owned(),
        b"control-socket" => "diagnostic=qualification-daemon-exited-control-socket".to_owned(),
        b"unclassified-daemon-exit" => {
            "diagnostic=qualification-daemon-exited-unclassified-stage".to_owned()
        }
        _ => "diagnostic=qualification-receipt-boundary".to_owned(),
    }
}

fn qualification_android_planning_failure_token(token: &str) -> Option<String> {
    if token.is_empty() || token.len() > 192 || !token.is_ascii() {
        return None;
    }
    let parts = token.split('/').collect::<Vec<_>>();
    let valid = match parts.as_slice() {
        ["census", "collection", stage, source]
            if QUALIFICATION_CENSUS_COLLECTION_STAGES.contains(stage)
                && QUALIFICATION_CENSUS_SOURCE_KINDS.contains(source) =>
        {
            true
        }
        ["census", "external-snapshot-context-mismatch", phase]
            if matches!(*phase, "before" | "after") =>
        {
            true
        }
        ["census", "complete", kind, source, plane]
            if matches!(
                *kind,
                "duplicate-coverage"
                    | "missing-coverage"
                    | "present-coverage-has-no-mark-use"
                    | "absent-coverage-has-mark-use"
            ) && QUALIFICATION_FWMARK_SOURCES.contains(source)
                && QUALIFICATION_FWMARK_PLANES.contains(plane) =>
        {
            true
        }
        [
            "census",
            "complete",
            "noncomplete-coverage",
            source,
            plane,
            state,
        ] if QUALIFICATION_FWMARK_SOURCES.contains(source)
            && QUALIFICATION_FWMARK_PLANES.contains(plane)
            && QUALIFICATION_FWMARK_COVERAGE_STATES.contains(state) =>
        {
            true
        }
        ["census", "authorization", kind]
            if QUALIFICATION_AUTHORIZATION_FAILURES.contains(kind) =>
        {
            true
        }
        [
            "census",
            "authorization",
            "census-conflict",
            source,
            plane,
            operation,
            mask,
            overlap,
        ] => qualification_census_conflict_signature_is_valid(
            source, plane, operation, mask, overlap,
        ),
        _ => QUALIFICATION_ANDROID_PLANNING_STATIC_TOKENS.contains(&token),
    };
    valid.then(|| token.replace('/', "-"))
}

fn qualification_census_conflict_signature_is_valid(
    source: &str,
    plane: &str,
    operation: &str,
    mask: &str,
    overlap: &str,
) -> bool {
    if !QUALIFICATION_FWMARK_SOURCES.contains(&source)
        || !QUALIFICATION_FWMARK_PLANES.contains(&plane)
        || !QUALIFICATION_FWMARK_OPERATIONS.contains(&operation)
    {
        return false;
    }
    let Some(mask) = qualification_fwmark_token_value(mask, "mask-") else {
        return false;
    };
    let Some(overlap) = qualification_fwmark_token_value(overlap, "overlap-") else {
        return false;
    };
    mask != 0 && overlap != 0 && overlap & !mask == 0
}

fn qualification_fwmark_token_value(token: &str, prefix: &str) -> Option<u32> {
    let digits = token.strip_prefix(prefix)?;
    if digits.len() != 8
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

const QUALIFICATION_CENSUS_COLLECTION_STAGES: &[&str] = &[
    "capability-before",
    "external-before",
    "network-inventory",
    "existing-flux-ownership",
    "external-after",
    "capability-after",
];
const QUALIFICATION_CENSUS_SOURCE_KINDS: &[&str] = &[
    "invalid-capability-stage",
    "invalid-bound",
    "deadline-exceeded",
    "kernel-config",
    "nftables-gate",
    "xtables-process",
    "xtables-observation",
    "nftables-observation",
    "traffic-control-bpf-observation",
    "xfrm-observation",
    "network-inventory",
    "existing-flux-ownership",
];
const QUALIFICATION_FWMARK_SOURCES: &[&str] = &[
    "android-net-id",
    "rpdb",
    "device-mark-policy",
    "xtables",
    "nftables",
    "traffic-control-and-bpf",
    "xfrm",
    "connmark-and-socket-transfers",
    "existing-flux-ownership",
];
const QUALIFICATION_FWMARK_PLANES: &[&str] = &["packet", "socket", "conntrack"];
const QUALIFICATION_FWMARK_OPERATIONS: &[&str] = &[
    "predicate-read",
    "masked-write",
    "transfer-read",
    "transfer-write",
];
const QUALIFICATION_FWMARK_COVERAGE_STATES: &[&str] = &[
    "complete-present",
    "complete-absent",
    "incomplete",
    "opaque",
    "denied",
    "transient",
    "unavailable",
];
const QUALIFICATION_AUTHORIZATION_FAILURES: &[&str] = &[
    "no-positive-device-grant",
    "ineligible-candidate",
    "unverified-boot-identity",
    "stale-topology-scope",
    "topology-scope-not-all-residual",
    "malformed-positive-grant",
    "grant-candidate-mismatch",
    "grant-topology-scope-mismatch",
    "grant-boot-identity-mismatch",
    "grant-network-namespace-mismatch",
    "grant-capability-profile-mismatch",
    "grant-missing-planes",
    "census-inventory-mismatch",
    "census-boot-identity-mismatch",
    "census-network-namespace-mismatch",
    "census-capability-profile-mismatch",
    "census-device-policy-identity-mismatch",
    "census-device-policy-revision-mismatch",
    "census-collector-revision-mismatch",
    "census-ownership-journal-identity-mismatch",
    "census-ownership-journal-revision-mismatch",
    "partial-audit-conflict",
    "partial-audit-evidence-not-available",
    "census-conflict",
    "ordered-packet-write-qualification-required",
    "ordered-late-write-qualification-mismatch",
    "exact-mark-sentinel-qualification-mismatch",
    "non-fresh-census-observation",
];
const QUALIFICATION_ANDROID_PLANNING_STATIC_TOKENS: &[&str] = &[
    "local-output-required",
    "forwarded-ingress-unsupported",
    "unexpected-diagnostic",
    "capture-path-evidence",
    "census/capability-device-identity-unavailable",
    "census/capability-drift",
    "census/external-snapshot-drift",
    "census/platform-profile",
    "census/selected-netd-source-profile-mismatch",
    "census/reviewed-canary-facility-policy-mismatch",
    "census/reviewed-canary-rpdb",
    "census/topology",
    "census/rpdb",
    "census/assembly",
    "census/complete/unverified-boot-identity",
    "census/complete/unverified-device-identity",
    "census/complete/network-namespace-mismatch",
    "census/complete/too-many-coverage-records",
    "census/complete/too-many-mark-use-records",
    "census/complete/too-many-ordered-late-writes",
    "census/complete/duplicate-ordered-late-write",
    "census/complete/ordered-late-write-has-no-mark-use",
    "census/complete/too-many-exact-mark-sentinels",
    "census/complete/duplicate-exact-mark-sentinel",
    "census/complete/exact-mark-sentinel-has-no-mark-use",
    "census/complete/observation-id-exhausted",
    "placement/reviewed-classification",
    "placement/reviewed-planning",
    "placement/generic-planning",
];

#[cfg(test)]
fn parse_qualification_execution_receipt(
    bytes: &[u8],
) -> Result<QualificationExecutionReceipt, String> {
    let (peer_network_namespace, suffix) = decode_qualification_peer_namespace_frame(bytes)?;
    Ok(QualificationExecutionReceipt {
        peer_network_namespace,
        passed: parse_qualification_receipt_suffix(suffix)?,
    })
}

fn decode_qualification_peer_namespace_frame(
    bytes: &[u8],
) -> Result<(PeerNetworkNamespaceIdentity, &[u8]), String> {
    if bytes.len() < PEER_NAMESPACE_REPORT_FRAME_BYTES {
        return Err("qualification peer network-namespace receipt is truncated".to_owned());
    }
    let frame = &bytes[..PEER_NAMESPACE_REPORT_FRAME_BYTES];
    if &frame[..8] != PEER_NAMESPACE_REPORT_MAGIC
        || u16::from_be_bytes([frame[8], frame[9]]) != PEER_NAMESPACE_REPORT_VERSION
        || u16::from_be_bytes([frame[10], frame[11]]) != PEER_NAMESPACE_REPORT_PAYLOAD_BYTES
    {
        return Err(
            "qualification peer network-namespace receipt has an invalid schema".to_owned(),
        );
    }
    let device = u64::from_be_bytes(
        frame[12..20]
            .try_into()
            .expect("fixed peer namespace device field"),
    );
    let inode = u64::from_be_bytes(
        frame[20..28]
            .try_into()
            .expect("fixed peer namespace inode field"),
    );
    let peer_network_namespace = PeerNetworkNamespaceIdentity::new(device, inode)
        .ok_or_else(|| "qualification peer network-namespace receipt is invalid".to_owned())?;
    Ok((
        peer_network_namespace,
        &bytes[PEER_NAMESPACE_REPORT_FRAME_BYTES..],
    ))
}

fn parse_qualification_receipt_suffix(bytes: &[u8]) -> Result<bool, String> {
    let suffix =
        normalize_adb_shell_newlines(bytes.to_vec(), "qualification receipt").map_err(|_| {
            "qualification peer network-namespace receipt has invalid framing".to_owned()
        })?;
    match suffix.as_slice() {
        b"" => Ok(false),
        value if value == QUALIFICATION_PASS_RECEIPT_LINE => Ok(true),
        _ => Err(
            "qualification peer network-namespace receipt has unexpected trailing output"
                .to_owned(),
        ),
    }
}

#[cfg(test)]
fn qualification_failure_diagnostic_script(
    remote: &OwnedRemoteDirectory,
    device: &DeviceProfile,
) -> String {
    format!(
        "set -eu\n\
         ROOT={}\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         identity_matches\n\
         echo '{DIAGNOSTIC_STATUS_BEGIN}'\n\
         if [ -f \"$ROOT/status.json.tmp\" ] && [ ! -L \"$ROOT/status.json.tmp\" ]; then\n\
           /system/bin/tail -c 65536 \"$ROOT/status.json.tmp\"\n\
         elif [ -f \"$ROOT/status.running.json\" ] && [ ! -L \"$ROOT/status.running.json\" ]; then\n\
           /system/bin/tail -c 65536 \"$ROOT/status.running.json\"\n\
         fi\n\
         echo\n\
         echo '{DIAGNOSTIC_STATUS_END}'\n\
         echo '{DIAGNOSTIC_STDERR_BEGIN}'\n\
         if [ -f \"$ROOT/daemon.stderr\" ] && [ ! -L \"$ROOT/daemon.stderr\" ]; then\n\
           /system/bin/tail -c 8192 \"$ROOT/daemon.stderr\"\n\
         fi\n\
         echo\n\
         echo '{DIAGNOSTIC_STDERR_END}'\n",
        shell_single_quote(remote.path()),
        device_identity_function(device),
    )
}

#[cfg(test)]
fn summarize_qualification_diagnostic(
    status: &str,
    stderr: &str,
    remote_root: &str,
    secret: &str,
    device: &DeviceProfile,
) -> String {
    let status = serde_json::from_str::<serde_json::Value>(status).ok();
    let field = |pointer: &str| {
        status
            .as_ref()
            .and_then(|document| document.pointer(pointer))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unavailable")
    };
    let selector_mismatches = qualification_selector_mismatch_summary(status.as_ref());
    let raw = format!(
        "admission_state={} admission_reason={} selector_mismatches={} runtime_phase={} verification={} operation={} message={} recovery={} daemon_stderr={}",
        field("/native_admission/state"),
        field("/native_admission/reason"),
        selector_mismatches,
        field("/runtime/phase"),
        field("/runtime/verification"),
        field("/runtime/last_error/operation"),
        field("/runtime/last_error/message"),
        field("/runtime/last_error/recovery"),
        stderr,
    );
    let mut redacted = raw.replace(remote_root, "<redacted-owned-root>");
    if !secret.is_empty() {
        redacted = redacted.replace(secret, "<redacted-subscription>");
    }
    redacted = device.redact_sensitive_diagnostic(&redacted);
    let collapsed = redacted.split_whitespace().collect::<Vec<_>>().join(" ");
    let end = collapsed
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= 4_096)
        .last()
        .unwrap_or(0);
    if collapsed.len() <= 4_096 {
        collapsed
    } else {
        format!("{}<truncated>", &collapsed[..end])
    }
}

#[cfg(test)]
fn qualification_selector_mismatch_summary(status: Option<&serde_json::Value>) -> String {
    const ALLOWED_FIELDS: [&str; 12] = [
        "android_product",
        "android_build",
        "vendor_build",
        "security_patch",
        "kernel_build",
        "selinux_policy_sha256",
        "selinux_policy_size",
        "netd_sha256",
        "netd_size",
        "connectivity_sha256",
        "connectivity_size",
        "device_identity",
    ];
    let Some(fields) = status
        .and_then(|document| document.pointer("/qualification_selector_mismatches"))
        .and_then(serde_json::Value::as_array)
    else {
        return "unavailable".to_owned();
    };
    if fields.len() > ALLOWED_FIELDS.len() {
        return "unavailable".to_owned();
    }
    let mut accepted = Vec::with_capacity(fields.len());
    for value in fields {
        let Some(field) = value.as_str() else {
            return "unavailable".to_owned();
        };
        if !ALLOWED_FIELDS.contains(&field) || accepted.contains(&field) {
            return "unavailable".to_owned();
        }
        accepted.push(field);
    }
    if accepted.is_empty() {
        "none".to_owned()
    } else {
        accepted.join(",")
    }
}

fn qualification_execution_script(
    remote: &OwnedRemoteDirectory,
    device: &DeviceProfile,
    artifacts: &QualificationArtifacts,
) -> String {
    format!(
        "set -eu\n\
         umask 077\n\
         {}\
         FLUXD=\"$ROOT/{REMOTE_FLUXD_NAME}\"\n\
         PRODUCER=\"$ROOT/{REMOTE_PRODUCER_NAME}\"\n\
         CONFIG=\"$ROOT/{REMOTE_CONFIG_NAME}\"\n\
         RECOVERY_CONFIG=\"$ROOT/{REMOTE_RECOVERY_CONFIG_NAME}\"\n\
         TEMPLATE=\"$ROOT/{REMOTE_TEMPLATE_NAME}\"\n\
         SUBSCRIPTION=\"$ROOT/{REMOTE_SUBSCRIPTION_NAME}\"\n\
         SOCKET=\"$ROOT/run/fluxd.sock\"\n\
         PID_FILE=\"$ROOT/qualification-daemon.pid\"\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         {}\
         DAEMON_PID=''\n\
         shutdown_daemon() {{\n\
           [ -n \"$DAEMON_PID\" ] || return 0\n\
           if /system/bin/kill -0 \"$DAEMON_PID\" 2>/dev/null; then\n\
             /system/bin/kill -TERM \"$DAEMON_PID\" 2>/dev/null || true\n\
             N=0\n\
             while /system/bin/kill -0 \"$DAEMON_PID\" 2>/dev/null && [ \"$N\" -lt 10 ]; do\n\
               /system/bin/sleep 1\n\
               N=$((N + 1))\n\
             done\n\
             /system/bin/kill -KILL \"$DAEMON_PID\" 2>/dev/null || true\n\
           fi\n\
           wait \"$DAEMON_PID\" 2>/dev/null || true\n\
           DAEMON_PID=''\n\
         }}\n\
         planning_census_stage_allowed() {{\n\
           case \"$1\" in\n\
             capability-before|external-before|network-inventory|existing-flux-ownership|external-after|capability-after) return 0 ;;\n\
             *) return 1 ;;\n\
           esac\n\
         }}\n\
         planning_census_source_kind_allowed() {{\n\
           case \"$1\" in\n\
             invalid-capability-stage|invalid-bound|deadline-exceeded|kernel-config|nftables-gate|xtables-process|xtables-observation|nftables-observation|traffic-control-bpf-observation|xfrm-observation|network-inventory|existing-flux-ownership) return 0 ;;\n\
             *) return 1 ;;\n\
           esac\n\
         }}\n\
         planning_fwmark_source_allowed() {{\n\
           case \"$1\" in\n\
             android-net-id|rpdb|device-mark-policy|xtables|nftables|traffic-control-and-bpf|xfrm|connmark-and-socket-transfers|existing-flux-ownership) return 0 ;;\n\
             *) return 1 ;;\n\
           esac\n\
         }}\n\
         planning_fwmark_plane_allowed() {{\n\
           case \"$1\" in\n\
             packet|socket|conntrack) return 0 ;;\n\
             *) return 1 ;;\n\
           esac\n\
         }}\n\
         planning_fwmark_operation_allowed() {{\n\
           case \"$1\" in\n\
             predicate-read|masked-write|transfer-read|transfer-write) return 0 ;;\n\
             *) return 1 ;;\n\
           esac\n\
         }}\n\
         planning_fwmark_value_allowed() {{\n\
           case \"$1\" in\n\
             ????????) ;;\n\
             *) return 1 ;;\n\
           esac\n\
           case \"$1\" in\n\
             *[!0-9a-f]*|00000000) return 1 ;;\n\
             *) return 0 ;;\n\
           esac\n\
         }}\n\
         planning_coverage_state_allowed() {{\n\
           case \"$1\" in\n\
             complete-present|complete-absent|incomplete|opaque|denied|transient|unavailable) return 0 ;;\n\
             *) return 1 ;;\n\
           esac\n\
         }}\n\
         planning_authorization_failure_allowed() {{\n\
           case \"$1\" in\n\
             no-positive-device-grant|ineligible-candidate|unverified-boot-identity|stale-topology-scope|topology-scope-not-all-residual|malformed-positive-grant|grant-candidate-mismatch|grant-topology-scope-mismatch|grant-boot-identity-mismatch|grant-network-namespace-mismatch|grant-capability-profile-mismatch|grant-missing-planes|census-inventory-mismatch|census-boot-identity-mismatch|census-network-namespace-mismatch|census-capability-profile-mismatch|census-device-policy-identity-mismatch|census-device-policy-revision-mismatch|census-collector-revision-mismatch|census-ownership-journal-identity-mismatch|census-ownership-journal-revision-mismatch|partial-audit-conflict|partial-audit-evidence-not-available|census-conflict|ordered-packet-write-qualification-required|ordered-late-write-qualification-mismatch|exact-mark-sentinel-qualification-mismatch|non-fresh-census-observation) return 0 ;;\n\
             *) return 1 ;;\n\
           esac\n\
         }}\n\
         planning_failure_token_is_allowed() {{\n\
           TOKEN=\"$1\"\n\
           case \"$TOKEN\" in\n\
             local-output-required|forwarded-ingress-unsupported|unexpected-diagnostic|capture-path-evidence|census/capability-device-identity-unavailable|census/capability-drift|census/external-snapshot-drift|census/platform-profile|census/selected-netd-source-profile-mismatch|census/reviewed-canary-facility-policy-mismatch|census/reviewed-canary-rpdb|census/topology|census/rpdb|census/assembly|census/complete/unverified-boot-identity|census/complete/unverified-device-identity|census/complete/network-namespace-mismatch|census/complete/too-many-coverage-records|census/complete/too-many-mark-use-records|census/complete/too-many-ordered-late-writes|census/complete/duplicate-ordered-late-write|census/complete/ordered-late-write-has-no-mark-use|census/complete/too-many-exact-mark-sentinels|census/complete/duplicate-exact-mark-sentinel|census/complete/exact-mark-sentinel-has-no-mark-use|census/complete/observation-id-exhausted|placement/reviewed-classification|placement/reviewed-planning|placement/generic-planning) return 0 ;;\n\
           esac\n\
           case \"$TOKEN\" in\n\
             census/collection/*/*)\n\
               REST=${{TOKEN#census/collection/}}\n\
               STAGE=${{REST%%/*}}\n\
               SOURCE=${{REST#*/}}\n\
               [ \"$SOURCE\" != \"$REST\" ] && [ \"$SOURCE\" != '*/*' ] || return 1\n\
               planning_census_stage_allowed \"$STAGE\" || return 1\n\
               planning_census_source_kind_allowed \"$SOURCE\" || return 1\n\
               return 0\n\
               ;;\n\
             census/external-snapshot-context-mismatch/*)\n\
               PHASE=${{TOKEN#census/external-snapshot-context-mismatch/}}\n\
               [ \"$PHASE\" = before ] || [ \"$PHASE\" = after ] || return 1\n\
               return 0\n\
               ;;\n\
             census/complete/duplicate-coverage/*/*|census/complete/missing-coverage/*/*|census/complete/present-coverage-has-no-mark-use/*/*|census/complete/absent-coverage-has-mark-use/*/*)\n\
               REST=${{TOKEN#census/complete/}}\n\
               KIND=${{REST%%/*}}\n\
               REST=${{REST#*/}}\n\
               SOURCE=${{REST%%/*}}\n\
               PLANE=${{REST#*/}}\n\
               [ \"$PLANE\" != '*/*' ] || return 1\n\
               planning_fwmark_source_allowed \"$SOURCE\" || return 1\n\
               planning_fwmark_plane_allowed \"$PLANE\" || return 1\n\
               return 0\n\
               ;;\n\
             census/complete/noncomplete-coverage/*/*/*)\n\
               REST=${{TOKEN#census/complete/noncomplete-coverage/}}\n\
               SOURCE=${{REST%%/*}}\n\
               REST=${{REST#*/}}\n\
               PLANE=${{REST%%/*}}\n\
               STATE=${{REST#*/}}\n\
               [ \"$STATE\" != '*/*' ] || return 1\n\
               planning_fwmark_source_allowed \"$SOURCE\" || return 1\n\
               planning_fwmark_plane_allowed \"$PLANE\" || return 1\n\
               planning_coverage_state_allowed \"$STATE\" || return 1\n\
               return 0\n\
               ;;\n\
             census/authorization/census-conflict/*/*/*/mask-*/overlap-*)\n\
               REST=${{TOKEN#census/authorization/census-conflict/}}\n\
               SOURCE=${{REST%%/*}}\n\
               REST=${{REST#*/}}\n\
               PLANE=${{REST%%/*}}\n\
               REST=${{REST#*/}}\n\
               OPERATION=${{REST%%/*}}\n\
               REST=${{REST#*/}}\n\
               MASK_FIELD=${{REST%%/*}}\n\
               OVERLAP_FIELD=${{REST#*/}}\n\
               MASK=${{MASK_FIELD#mask-}}\n\
               OVERLAP=${{OVERLAP_FIELD#overlap-}}\n\
               planning_fwmark_source_allowed \"$SOURCE\" || return 1\n\
               planning_fwmark_plane_allowed \"$PLANE\" || return 1\n\
               planning_fwmark_operation_allowed \"$OPERATION\" || return 1\n\
               [ \"$MASK\" != \"$MASK_FIELD\" ] || return 1\n\
               [ \"$OVERLAP\" != \"$OVERLAP_FIELD\" ] || return 1\n\
               planning_fwmark_value_allowed \"$MASK\" || return 1\n\
               planning_fwmark_value_allowed \"$OVERLAP\" || return 1\n\
               [ $((0x$OVERLAP & ~0x$MASK)) -eq 0 ] || return 1\n\
               return 0\n\
               ;;\n\
             census/authorization/*)\n\
               FAILURE=${{TOKEN#census/authorization/}}\n\
               [ \"$FAILURE\" != '*/*' ] || return 1\n\
               planning_authorization_failure_allowed \"$FAILURE\" || return 1\n\
               return 0\n\
               ;;\n\
           esac\n\
           return 1\n\
         }}\n\
         classify_daemon_failure() {{\n\
           FAILURE_STAGE='unclassified-daemon-exit'\n\
           DAEMON_ERROR_FILE=\"$ROOT/daemon.stderr\"\n\
           if [ -f \"$DAEMON_ERROR_FILE\" ] && [ ! -L \"$DAEMON_ERROR_FILE\" ] &&\n\
              [ \"$(/system/bin/stat -c '%a:%u:%g' \"$DAEMON_ERROR_FILE\")\" = '600:0:0' ]; then\n\
             DAEMON_ERROR_BYTES=$(/system/bin/stat -c '%s' \"$DAEMON_ERROR_FILE\" 2>/dev/null || :)\n\
             DAEMON_ERROR_LINES=$(/system/bin/grep -c '^' \"$DAEMON_ERROR_FILE\" 2>/dev/null || :)\n\
             if [ \"$DAEMON_ERROR_BYTES\" -gt 0 ] 2>/dev/null &&\n\
                [ \"$DAEMON_ERROR_BYTES\" -le 8192 ] 2>/dev/null &&\n\
                [ \"$DAEMON_ERROR_LINES\" = '1' ]; then\n\
               DAEMON_ERROR=''\n\
               IFS= read -r DAEMON_ERROR <\"$DAEMON_ERROR_FILE\" || DAEMON_ERROR=''\n\
               case \"$DAEMON_ERROR\" in\n\
                 'fluxd: native startup cannot split native canary facility authority:'*) FAILURE_STAGE='facility-authority' ;;\n\
                 'fluxd: native startup cannot compose native startup recovery:'*|'fluxd: native startup cannot recover native startup state:'*) FAILURE_STAGE='native-startup-recovery' ;;\n\
                 'fluxd: native startup cannot mint initial Android planning authority: [qualification='*'] '*)\n\
                   PLANNING_ERROR_PREFIX='fluxd: native startup cannot mint initial Android planning authority: [qualification='\n\
                   PLANNING_ERROR_SUFFIX='] '\n\
                   PLANNING_FAILURE=${{DAEMON_ERROR#\"$PLANNING_ERROR_PREFIX\"}}\n\
                   PLANNING_FAILURE=${{PLANNING_FAILURE%%\"$PLANNING_ERROR_SUFFIX\"*}}\n\
                   if planning_failure_token_is_allowed \"$PLANNING_FAILURE\"; then\n\
                     FAILURE_STAGE=\"android-planning-authority/$PLANNING_FAILURE\"\n\
                   else\n\
                     FAILURE_STAGE='android-planning-authority'\n\
                   fi\n\
                   ;;\n\
                 'fluxd: native startup cannot mint initial Android planning authority:'*) FAILURE_STAGE='android-planning-authority' ;;\n\
                 'fluxd: native startup cannot compose native Android runtime:'*) FAILURE_STAGE='native-runtime-composition' ;;\n\
                 'fluxd: native startup cannot retain initial Android planning authority:'*) FAILURE_STAGE='android-planning-retention' ;;\n\
                 'fluxd: native startup cannot start subscription runtime:'*) FAILURE_STAGE='subscription-runtime-start' ;;\n\
                 'fluxd: native startup cannot compose native runtime coordinator:'*) FAILURE_STAGE='runtime-coordinator-composition' ;;\n\
                 'fluxd: runtime control:'*) FAILURE_STAGE='initial-runtime-control' ;;\n\
                 'fluxd: daemon configuration:'*) FAILURE_STAGE='daemon-configuration' ;;\n\
                 'fluxd: daemon invariant:'*) FAILURE_STAGE='daemon-invariant' ;;\n\
                 'fluxd: runtime layout:'*) FAILURE_STAGE='runtime-layout' ;;\n\
                 'fluxd: administrative intent:'*) FAILURE_STAGE='administrative-intent' ;;\n\
                 'fluxd: control reactor:'*) FAILURE_STAGE='control-reactor' ;;\n\
                 'fluxd: control socket:'*) FAILURE_STAGE='control-socket' ;;\n\
               esac\n\
             fi\n\
           fi\n\
           printf 'FLUX_ANDROID_Q11_FAILURE=%s\\n' \"$FAILURE_STAGE\" >&2\n\
         }}\n\
         trap 'STATUS=$?; shutdown_daemon; exit $STATUS' EXIT HUP INT TERM\n\
         identity_matches\n\
         probe_process_absent\n\
         owned_root_matches\n\
         {}\
         /system/bin/chown 0:0 \"$ROOT\" \"$FLUXD\" \"$CONFIG\" \"$RECOVERY_CONFIG\" \"$TEMPLATE\" \"$SUBSCRIPTION\"\n\
         /system/bin/chown 0:2900002 \"$PRODUCER\"\n\
         /system/bin/chmod 700 \"$ROOT\" \"$FLUXD\"\n\
         /system/bin/chmod 710 \"$PRODUCER\"\n\
         /system/bin/chmod 600 \"$CONFIG\" \"$RECOVERY_CONFIG\" \"$TEMPLATE\" \"$SUBSCRIPTION\"\n\
         run_flux() {{\n\
           FLUX_ROOT=\"$ROOT\" FLUXD_SOCKET=\"$SOCKET\" FLUXD_LEASE_PATH=\"$ROOT/run/fluxd.lease\" FLUXD_CONFIG_PATH=\"$CONFIG\" FLUXD_INTENT_PATH=\"$ROOT/state/administrative-intent.json\" FLUX_DISABLE_PATH=\"$ROOT/disable\" \"$@\"\n\
         }}\n\
         FLUX_Q11_NETNS_REPORT_FD=3 run_flux \"$FLUXD\" daemon 3>&1 </dev/null >\"$ROOT/daemon.stdout\" 2>\"$ROOT/daemon.stderr\" &\n\
         DAEMON_PID=$!\n\
         printf '%s\\n' \"$DAEMON_PID\" >\"$PID_FILE\"\n\
         /system/bin/chmod 600 \"$PID_FILE\"\n\
         READY=0\n\
         DAEMON_EXITED_BEFORE_READY=0\n\
         N=0\n\
         while [ \"$N\" -lt 120 ]; do\n\
           if ! /system/bin/kill -0 \"$DAEMON_PID\" 2>/dev/null; then\n\
             DAEMON_EXITED_BEFORE_READY=1\n\
             break\n\
           fi\n\
           if run_flux \"$FLUXD\" status --json >\"$ROOT/status.json.tmp\" 2>/dev/null &&\n\
              /system/bin/grep -F '\"state\":\"admitted\"' \"$ROOT/status.json.tmp\" >/dev/null &&\n\
              /system/bin/grep -F '\"phase\":\"running\"' \"$ROOT/status.json.tmp\" >/dev/null &&\n\
              /system/bin/grep -F '\"verification\":\"functional_passed\"' \"$ROOT/status.json.tmp\" >/dev/null; then\n\
             /system/bin/mv \"$ROOT/status.json.tmp\" \"$ROOT/status.running.json\"\n\
             READY=1\n\
             break\n\
           fi\n\
           N=$((N + 1))\n\
           /system/bin/sleep 1\n\
         done\n\
         if [ \"$DAEMON_EXITED_BEFORE_READY\" != '0' ]; then\n\
           classify_daemon_failure\n\
           exit {QUALIFICATION_DAEMON_EXITED_STATUS}\n\
         fi\n\
         [ \"$READY\" = '1' ] || exit {QUALIFICATION_READINESS_DEADLINE_STATUS}\n\
         run_flux \"$FLUXD\" stop >/dev/null 2>&1 || exit 76\n\
         run_flux \"$FLUXD\" status --json >\"$ROOT/status.stopped.json\" 2>/dev/null\n\
         /system/bin/grep -F '\"phase\":\"stopped\"' \"$ROOT/status.stopped.json\" >/dev/null\n\
         /system/bin/grep -F '\"capture\":\"detached\"' \"$ROOT/status.stopped.json\" >/dev/null\n\
         /system/bin/grep -F '\"engine\":\"stopped\"' \"$ROOT/status.stopped.json\" >/dev/null\n\
         shutdown_daemon\n\
         probe_process_absent\n\
         exact_flux_absence\n\
         echo '{QUALIFICATION_PASS_RECEIPT}'\n\
         trap - EXIT HUP INT TERM\n",
        remote.shell_variables(device.shell_uid(), device.shell_gid()),
        device_identity_function(device),
        process_absence_function(&REMOTE_PROCESS_NAMES),
        owned_root_functions_with_engine_group(QUALIFICATION_ENGINE_GID),
        exact_flux_absence_function(),
        remote_artifact_verification(artifacts),
    )
}

fn remote_artifact_verification(artifacts: &QualificationArtifacts) -> String {
    let rows = [
        (
            REMOTE_FLUXD_NAME,
            &artifacts.fluxd_identity,
            "qualification fluxd",
        ),
        (
            REMOTE_PRODUCER_NAME,
            &artifacts.producer_identity,
            "manifest-bound producer",
        ),
        (
            REMOTE_CONFIG_NAME,
            &artifacts.config_identity,
            "qualification config",
        ),
        (
            REMOTE_RECOVERY_CONFIG_NAME,
            &artifacts.recovery_config_identity,
            "recovery config",
        ),
        (
            REMOTE_TEMPLATE_NAME,
            &artifacts.template_identity,
            "engine template",
        ),
        (
            REMOTE_SUBSCRIPTION_NAME,
            &artifacts.subscription_identity,
            "subscription input",
        ),
    ];
    let mut script = String::new();
    for (name, identity, _description) in rows {
        script.push_str(&format!(
            "[ -f \"$ROOT/{name}\" ] && [ ! -L \"$ROOT/{name}\" ]\n\
             [ \"$(/system/bin/stat -c '%s' \"$ROOT/{name}\")\" = '{}' ]\n\
             [ \"$(/system/bin/sha256sum \"$ROOT/{name}\" | /system/bin/cut -d ' ' -f 1)\" = '{}' ]\n",
            identity.size(),
            identity.sha256(),
        ));
    }
    script
}

fn exact_flux_absence_function() -> &'static str {
    "exact_flux_absence_without_target_archive() {\n\
       [ ! -e \"$ROOT/run/canary-facility.owner\" ] && [ ! -L \"$ROOT/run/canary-facility.owner\" ] || return 1\n\
       for RECORD in native_xtables.journal native_xtables.lease native_xtables.attempt; do\n\
         [ ! -e \"$ROOT/run/$RECORD\" ] && [ ! -L \"$ROOT/run/$RECORD\" ] || return 1\n\
       done\n\
       ! /system/bin/ip link show dev fxq11d0 >/dev/null 2>&1 || return 1\n\
       ! /system/bin/ip link show dev fxq11p0 >/dev/null 2>&1 || return 1\n\
       ! /system/bin/ip -4 rule show | /system/bin/grep -E '^(30997|30998):' >/dev/null || return 1\n\
       ! /system/bin/ip -6 rule show | /system/bin/grep -E '^(30997|30998):' >/dev/null || return 1\n\
       [ -z \"$(/system/bin/ip -4 route show table 20253 2>/dev/null)\" ] || return 1\n\
       [ -z \"$(/system/bin/ip -4 route show table 20254 2>/dev/null)\" ] || return 1\n\
       [ -z \"$(/system/bin/ip -6 route show table 20253 2>/dev/null)\" ] || return 1\n\
       [ -z \"$(/system/bin/ip -6 route show table 20254 2>/dev/null)\" ] || return 1\n\
       ! /system/bin/iptables-save | /system/bin/grep -F 'FLX' >/dev/null || return 1\n\
       ! /system/bin/ip6tables-save | /system/bin/grep -F 'FLX' >/dev/null || return 1\n\
     }\n\
     exact_flux_absence() {\n\
       exact_flux_absence_without_target_archive || return 1\n\
       [ ! -e \"$ROOT/run/native_xtables.targets\" ] && [ ! -L \"$ROOT/run/native_xtables.targets\" ]\n\
     }\n"
}

fn cleanup_qualification(
    options: &AndroidTargetOptions,
    device: &DeviceProfile,
    remote: &OwnedRemoteDirectory,
    artifacts: &QualificationArtifacts,
) -> Result<(), String> {
    if !remote.matches_spec() {
        return Err("refusing cleanup for an invalid qualification directory".to_owned());
    }
    revalidate_device(options, device, "before qualification cleanup/recovery")?;
    let script = qualification_cleanup_script(remote, device, artifacts);
    let cleanup = normalize_adb_shell_output(adb_root_shell_output(
        options,
        script.as_bytes(),
        ADB_CLEANUP_TIMEOUT,
        "recover and remove exact Android production-canary qualification state",
    )?)?;
    require_silent_success(cleanup, "qualification cleanup/recovery")?;

    let absence = normalize_adb_shell_output(adb_root_shell_output(
        options,
        qualification_absence_script(remote, device).as_bytes(),
        ADB_QUERY_TIMEOUT,
        "independently prove Android production-canary qualification absence",
    )?)?;
    require_silent_success(absence, "independent qualification absence proof")
}

fn qualification_cleanup_script(
    remote: &OwnedRemoteDirectory,
    device: &DeviceProfile,
    _artifacts: &QualificationArtifacts,
) -> String {
    format!(
        "set -eu\n\
         {}\
         FLUXD=\"$ROOT/{REMOTE_FLUXD_NAME}\"\n\
         RECOVERY_CONFIG=\"$ROOT/{REMOTE_RECOVERY_CONFIG_NAME}\"\n\
         SOCKET=\"$ROOT/run/fluxd.sock\"\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         {}\
         identity_matches\n\
         if path_absent \"$ROOT\"; then probe_process_absent; exit 0; fi\n\
         owned_root_matches\n\
         kill_owned_processes() {{\n\
           SIGNAL=\"$1\"\n\
           for COMM in /proc/[0-9]*/comm; do\n\
             [ -e \"$COMM\" ] || continue\n\
             IFS= read -r NAME <\"$COMM\" || continue\n\
             [ \"$NAME\" = '{REMOTE_FLUXD_NAME}' ] || [ \"$NAME\" = '{REMOTE_PRODUCER_NAME}' ] || continue\n\
             PROC=${{COMM%/comm}}\n\
             PID=${{PROC##*/}}\n\
             EXE=$(/system/bin/readlink -f \"$PROC/exe\") || return 81\n\
             [ \"$EXE\" = \"$ROOT/{REMOTE_FLUXD_NAME}\" ] || [ \"$EXE\" = \"$ROOT/{REMOTE_PRODUCER_NAME}\" ] || return 82\n\
             /system/bin/kill \"-$SIGNAL\" \"$PID\" 2>/dev/null || true\n\
           done\n\
         }}\n\
         kill_owned_processes TERM\n\
         N=0\n\
         while ! probe_process_absent && [ \"$N\" -lt 10 ]; do /system/bin/sleep 1; N=$((N + 1)); done\n\
         kill_owned_processes KILL\n\
         N=0\n\
         while ! probe_process_absent && [ \"$N\" -lt 5 ]; do /system/bin/sleep 1; N=$((N + 1)); done\n\
         probe_process_absent\n\
         if ! exact_flux_absence; then\n\
           [ -f \"$FLUXD\" ] && [ ! -L \"$FLUXD\" ]\n\
           [ -f \"$RECOVERY_CONFIG\" ] && [ ! -L \"$RECOVERY_CONFIG\" ]\n\
           [ -e \"$ROOT/run/canary-facility.owner\" ] || [ -e \"$ROOT/run/native_xtables.journal\" ] || [ -e \"$ROOT/run/native_xtables.lease\" ] || return 83\n\
           : >\"$ROOT/disable\"\n\
           /system/bin/chown 0:0 \"$ROOT/disable\"\n\
           /system/bin/chmod 600 \"$ROOT/disable\"\n\
           FLUX_ROOT=\"$ROOT\" FLUXD_SOCKET=\"$SOCKET\" FLUXD_LEASE_PATH=\"$ROOT/run/fluxd.lease\" FLUXD_CONFIG_PATH=\"$RECOVERY_CONFIG\" FLUXD_INTENT_PATH=\"$ROOT/state/administrative-intent.json\" FLUX_DISABLE_PATH=\"$ROOT/disable\" \"$FLUXD\" daemon </dev/null >\"$ROOT/recovery.stdout\" 2>\"$ROOT/recovery.stderr\" &\n\
           RECOVERY_PID=$!\n\
           N=0\n\
           while /system/bin/kill -0 \"$RECOVERY_PID\" 2>/dev/null && ! exact_flux_absence && [ \"$N\" -lt 30 ]; do\n\
             /system/bin/sleep 1\n\
             N=$((N + 1))\n\
           done\n\
           /system/bin/kill -TERM \"$RECOVERY_PID\" 2>/dev/null || true\n\
           N=0\n\
           while /system/bin/kill -0 \"$RECOVERY_PID\" 2>/dev/null && [ \"$N\" -lt 10 ]; do /system/bin/sleep 1; N=$((N + 1)); done\n\
           /system/bin/kill -KILL \"$RECOVERY_PID\" 2>/dev/null || true\n\
           wait \"$RECOVERY_PID\" 2>/dev/null || true\n\
         fi\n\
         if ! exact_flux_absence; then\n\
           exact_flux_absence_without_target_archive\n\
           TARGET_ARCHIVE=\"$ROOT/run/native_xtables.targets\"\n\
           [ -f \"$TARGET_ARCHIVE\" ] && [ ! -L \"$TARGET_ARCHIVE\" ]\n\
           [ \"$(/system/bin/stat -c '%a:%u:%g' \"$TARGET_ARCHIVE\")\" = '600:0:0' ]\n\
           OFFLINE_RESULT=$(FLUX_ROOT=\"$ROOT\" FLUXD_SOCKET=\"$SOCKET\" FLUXD_LEASE_PATH=\"$ROOT/run/fluxd.lease\" FLUXD_CONFIG_PATH=\"$RECOVERY_CONFIG\" FLUXD_INTENT_PATH=\"$ROOT/state/administrative-intent.json\" FLUX_DISABLE_PATH=\"$ROOT/disable\" \"$FLUXD\" cleanup --offline)\n\
           [ \"$OFFLINE_RESULT\" = 'cleanup complete' ]\n\
           probe_process_absent\n\
           exact_flux_absence_without_target_archive\n\
           [ -f \"$TARGET_ARCHIVE\" ] && [ ! -L \"$TARGET_ARCHIVE\" ]\n\
           [ \"$(/system/bin/stat -c '%a:%u:%g' \"$TARGET_ARCHIVE\")\" = '600:0:0' ]\n\
           /system/bin/rm \"$ROOT/run/native_xtables.targets\"\n\
         fi\n\
         probe_process_absent\n\
         exact_flux_absence\n\
         remove_owned_root\n",
        remote.shell_variables(device.shell_uid(), device.shell_gid()),
        device_identity_function(device),
        process_absence_function(&REMOTE_PROCESS_NAMES),
        owned_root_functions_with_engine_group(QUALIFICATION_ENGINE_GID),
        exact_flux_absence_function(),
    )
}

fn qualification_absence_script(remote: &OwnedRemoteDirectory, device: &DeviceProfile) -> String {
    format!(
        "set -eu\n\
         ROOT={}\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         {}\
         identity_matches\n\
         probe_process_absent\n\
         path_absent \"$ROOT\"\n\
         exact_flux_absence\n",
        shell_single_quote(remote.path()),
        path_absence_function(),
        device_identity_function(device),
        process_absence_function(&REMOTE_PROCESS_NAMES),
        exact_flux_absence_function(),
    )
}

fn prove_peer_network_namespace_absent(
    options: &AndroidTargetOptions,
    device: &DeviceProfile,
    identity: PeerNetworkNamespaceIdentity,
) -> Result<(), String> {
    let script = peer_network_namespace_absence_script(device, identity);
    let output = adb_root_shell_output(
        options,
        script.as_bytes(),
        PEER_NAMESPACE_ABSENCE_TIMEOUT,
        "independently prove peer network-namespace absence",
    )
    .map_err(|_| "independent peer network-namespace audit transport failed".to_owned())?;
    let output = normalize_adb_shell_output(output)?;
    require_silent_success(output, "independent peer network-namespace absence proof")
}

fn peer_network_namespace_absence_script(
    device: &DeviceProfile,
    identity: PeerNetworkNamespaceIdentity,
) -> String {
    let expected_identity = shell_single_quote(&identity.canonical());
    let expected_mount_device = shell_single_quote(&identity.mount_device());
    let expected_inode = shell_single_quote(&identity.inode.to_string());
    format!(
        "set -eu\n\
         EXPECTED_PEER_NAMESPACE={expected_identity}\n\
         EXPECTED_PEER_MOUNT_DEVICE={expected_mount_device}\n\
         EXPECTED_PEER_INODE={expected_inode}\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         scan_process_mountinfo() {{\n\
           # Keep the private identity off argv. The shell builtin writes exactly two lines to\n\
           # this one audit process. A vanished process, or a terminal zombie whose file table\n\
           # and namespaces are already released, is the only admissible read-race outcome.\n\
           MOUNT_SCAN_ATTEMPT=0\n\
           while [ \"$MOUNT_SCAN_ATTEMPT\" -lt 3 ]; do\n\
             MOUNT_SCAN_ATTEMPT=$((MOUNT_SCAN_ATTEMPT + 1))\n\
             MOUNT_SCAN_STATUS=0\n\
             printf '%s\\n%s\\n' \"$EXPECTED_PEER_MOUNT_DEVICE\" \"$EXPECTED_PEER_INODE\" |\n\
             /system/bin/awk '\n\
               function process_released(process, path, result, line, fields, state) {{\n\
                 if (system(\"[ ! -d \" process \" ]\") == 0) return 1\n\
                 path = process \"/status\"\n\
                 while ((result = (getline line < path)) > 0) {{\n\
                   split(line, fields)\n\
                   if (fields[1] == \"State:\") {{\n\
                     state = fields[2]\n\
                     break\n\
                   }}\n\
                 }}\n\
                 close(path)\n\
                 if (state == \"Z\" || state == \"X\") return 1\n\
                 return system(\"[ ! -d \" process \" ]\") == 0\n\
               }}\n\
               function fail(code) {{\n\
                 failure = code\n\
                 exit code\n\
               }}\n\
               BEGIN {{\n\
                 identity_input = \"/proc/self/fd/0\"\n\
                 if ((getline expected_device < identity_input) != 1 ||\n\
                     (getline expected_inode < identity_input) != 1 ||\n\
                     (getline unexpected_identity_line < identity_input) != 0) fail(109)\n\
                 close(identity_input)\n\
                 for (argument = 1; argument < ARGC; argument++) {{\n\
                   process = ARGV[argument]\n\
                   ARGV[argument] = \"\"\n\
                   process_count++\n\
                   if (process_count > 65536) fail(105)\n\
                   path = process \"/mountinfo\"\n\
                   mountinfo_lines = 0\n\
                   while ((read_status = (getline line < path)) > 0) {{\n\
                     $0 = line\n\
                     mountinfo_lines++\n\
                     total_mountinfo_lines++\n\
                     if (NF < 10) fail(91)\n\
                     if (mountinfo_lines > 65536) fail(102)\n\
                     if (total_mountinfo_lines > 1048576) fail(107)\n\
                     separator = 0\n\
                     for (field = 7; field <= NF; field++) {{\n\
                       if ($field == \"-\") {{\n\
                         separator = field\n\
                         break\n\
                       }}\n\
                     }}\n\
                     if (separator == 0 || separator + 3 > NF) fail(91)\n\
                     if ($(separator + 1) == \"nsfs\" &&\n\
                         $3 == expected_device &&\n\
                         ($4 == \"net:[\" expected_inode \"]\" ||\n\
                          $4 == \"/net:[\" expected_inode \"]\")) fail(92)\n\
                   }}\n\
                   close(path)\n\
                   if (read_status < 0) {{\n\
                     if (process_released(process)) continue\n\
                     fail(101)\n\
                   }}\n\
                   if (mountinfo_lines == 0) {{\n\
                     if (process_released(process)) continue\n\
                     fail(103)\n\
                   }}\n\
                   scanned_mountinfo_files++\n\
                 }}\n\
                 if (scanned_mountinfo_files == 0) fail(100)\n\
                 exit 0\n\
               }}\n\
               END {{\n\
                 if (failure) exit failure\n\
               }}' /proc/[0-9]* 2>/dev/null || MOUNT_SCAN_STATUS=$?\n\
             [ \"$MOUNT_SCAN_STATUS\" = '0' ] && return 0\n\
             [ \"$MOUNT_SCAN_STATUS\" = '101' ] || return \"$MOUNT_SCAN_STATUS\"\n\
           done\n\
           return 101\n\
         }}\n\
         [ \"$(/system/bin/id -u)\" = '0' ]\n\
         identity_matches\n\
         scan_task_network_namespaces() {{\n\
           TASK_SCAN_ATTEMPT=0\n\
           while [ \"$TASK_SCAN_ATTEMPT\" -lt 3 ]; do\n\
             TASK_SCAN_ATTEMPT=$((TASK_SCAN_ATTEMPT + 1))\n\
             TASK_SCAN_STATUS=0\n\
             {{\n\
               printf 'I %s\\n' \"$EXPECTED_PEER_INODE\"\n\
               /system/bin/awk '\n\
                 BEGIN {{\n\
                   status_code = 0\n\
                   for (argument = 1; argument < ARGC; argument++) {{\n\
                     process = ARGV[argument]\n\
                     ARGV[argument] = \"\"\n\
                     process_count++\n\
                     if (process_count > 65536) {{ status_code = 104; break }}\n\
                     path = process \"/status\"\n\
                     state = \"\"\n\
                     threads = \"\"\n\
                     state_fields = 0\n\
                     thread_fields = 0\n\
                     status_lines = 0\n\
                     while ((read_status = (getline line < path)) > 0) {{\n\
                       status_lines++\n\
                       total_status_lines++\n\
                       if (status_lines > 4096 || total_status_lines > 1048576) {{\n\
                         status_code = 104\n\
                         break\n\
                       }}\n\
                       split(line, fields)\n\
                       if (fields[1] == \"State:\") {{\n\
                         state_fields++\n\
                         state = fields[2]\n\
                       }} else if (fields[1] == \"Threads:\") {{\n\
                         thread_fields++\n\
                         threads = fields[2]\n\
                       }}\n\
                     }}\n\
                     close(path)\n\
                     if (status_code != 0) break\n\
                     if (read_status < 0) {{\n\
                       if (state == \"Z\" || state == \"X\" ||\n\
                           system(\"[ ! -d \" process \" ]\") == 0) continue\n\
                       status_code = 94\n\
                       break\n\
                     }}\n\
                     if (state == \"Z\" || state == \"X\") continue\n\
                     if (state_fields != 1 || thread_fields != 1 ||\n\
                         threads !~ /^[0-9]+$/ || threads + 0 < 1) {{\n\
                       status_code = 93\n\
                       break\n\
                     }}\n\
                     task_count += threads\n\
                     if (task_count > 65536) {{ status_code = 104; break }}\n\
                   }}\n\
                   print \"C \" task_count \" \" status_code\n\
                   exit 0\n\
                 }}' /proc/[0-9]* 2>/dev/null\n\
               /system/bin/readlink -q /proc/[0-9]*/task/[0-9]*/ns/net 2>/dev/null || :\n\
             }} | /system/bin/awk '\n\
               function fail(code) {{\n\
                 failure = code\n\
                 exit code\n\
               }}\n\
               NR == 1 {{\n\
                 if ($1 != \"I\" || NF != 2 || $2 !~ /^[0-9]+$/ || $2 + 0 < 1) fail(109)\n\
                 expected_target = \"net:[\" $2 \"]\"\n\
                 next\n\
               }}\n\
               $1 == \"C\" {{\n\
                 if (NF != 3 || census_seen++ || $2 !~ /^[0-9]+$/ ||\n\
                     $3 !~ /^[0-9]+$/) fail(109)\n\
                 expected_task_count = $2 + 0\n\
                 census_status = $3 + 0\n\
                 next\n\
               }}\n\
               /^net:\\[[0-9]+\\]$/ {{\n\
                 observed_task_count++\n\
                 if (observed_task_count > 65536) fail(104)\n\
                 if ($0 == expected_target) fail(95)\n\
                 next\n\
               }}\n\
               {{ fail(93) }}\n\
               END {{\n\
                 if (failure) exit failure\n\
                 if (census_seen != 1) exit 109\n\
                 if (census_status != 0) exit census_status\n\
                 if (expected_task_count == 0 || observed_task_count == 0) exit 96\n\
                 if (expected_task_count != observed_task_count) exit 108\n\
               }}' 2>/dev/null || TASK_SCAN_STATUS=$?\n\
             [ \"$TASK_SCAN_STATUS\" = '0' ] && return 0\n\
             [ \"$TASK_SCAN_STATUS\" = '108' ] || return \"$TASK_SCAN_STATUS\"\n\
           done\n\
           return 108\n\
         }}\n\
         scan_task_network_namespaces || exit $?\n\
         PROCESS_COUNT=0\n\
         FD_COUNT=0\n\
         for PROCESS in /proc/[0-9]*; do\n\
           [ -d \"$PROCESS\" ] || continue\n\
           PROCESS_COUNT=$((PROCESS_COUNT + 1))\n\
           [ \"$PROCESS_COUNT\" -le 65536 ] || exit 105\n\
           FD_DIRECTORY=\"$PROCESS/fd\"\n\
           if [ ! -d \"$FD_DIRECTORY\" ]; then\n\
             [ ! -d \"$PROCESS\" ] && continue\n\
             exit 97\n\
           fi\n\
           # A failed numeric glob is ambiguous: it can mean an empty directory or a\n\
           # procfs readdir denied by hidepid/ptrace policy. Force one bounded directory\n\
           # read so an unreadable holder domain fails closed instead of looking empty.\n\
           if ! /system/bin/ls \"$FD_DIRECTORY\" >/dev/null 2>&1; then\n\
             [ ! -d \"$PROCESS\" ] && continue\n\
             exit 97\n\
           fi\n\
           set -- \"$FD_DIRECTORY\"/[0-9]*\n\
           if [ \"$1\" = \"$FD_DIRECTORY/[0-9]*\" ] && [ ! -e \"$1\" ] && [ ! -L \"$1\" ]; then\n\
             PROCESS_FD_COUNT=0\n\
           else\n\
             PROCESS_FD_COUNT=$#\n\
           fi\n\
           [ \"$PROCESS_FD_COUNT\" -le 8192 ] || exit 106\n\
           FD_COUNT=$((FD_COUNT + PROCESS_FD_COUNT))\n\
           [ \"$FD_COUNT\" -le 262144 ] || exit 106\n\
           if [ \"$PROCESS_FD_COUNT\" -gt 0 ]; then\n\
             if ! FD_IDENTITIES=$(/system/bin/stat -Lc '%d:%i' \"$FD_DIRECTORY\"/[0-9]* 2>/dev/null); then\n\
               [ ! -d \"$PROCESS\" ] && continue\n\
               exit 98\n\
             fi\n\
             OBSERVED_FD_COUNT=0\n\
             while IFS= read -r FD_ID; do\n\
               OBSERVED_FD_COUNT=$((OBSERVED_FD_COUNT + 1))\n\
               [ \"$FD_ID\" = \"$EXPECTED_PEER_NAMESPACE\" ] || continue\n\
               exit 99\n\
             done <<FD_IDENTITIES_END\n\
$FD_IDENTITIES\n\
FD_IDENTITIES_END\n\
             [ \"$OBSERVED_FD_COUNT\" = \"$PROCESS_FD_COUNT\" ] || exit 98\n\
           fi\n\
         done\n\
         scan_process_mountinfo || exit $?\n\
         scan_task_network_namespaces || exit $?\n",
        device_identity_function(device),
    )
}
fn combine_transaction_and_peer_namespace_absence(
    transaction: Result<(), String>,
    peer_namespace_absence: Result<(), String>,
) -> Result<(), String> {
    match (transaction, peer_namespace_absence) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(audit_error)) => Err(audit_error),
        (Err(error), Err(audit_error)) => Err(format!(
            "{error}; independent peer network-namespace absence proof also failed: {audit_error}"
        )),
    }
}

fn missing_peer_namespace_receipt_result(
    transaction: &Result<(), String>,
    receipt_required: bool,
) -> Result<(), String> {
    if receipt_required {
        Err(
            "qualification peer network-namespace receipt was unavailable; exact absence is unverified"
                .to_owned(),
        )
    } else if transaction.is_ok() {
        Err("qualification omitted the peer network-namespace receipt".to_owned())
    } else {
        Ok(())
    }
}

const fn linux_device_major(device: u64) -> u64 {
    ((device & 0x0000_0000_000f_ff00) >> 8) | ((device & 0xffff_f000_0000_0000) >> 32)
}

const fn linux_device_minor(device: u64) -> u64 {
    (device & 0x0000_0000_0000_00ff) | ((device & 0x0000_0fff_fff0_0000) >> 12)
}

fn require_silent_success(output: std::process::Output, description: &str) -> Result<(), String> {
    if output.status.success() && output.stdout.is_empty() && output.stderr.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{description} failed at remote status {}",
            output.status.code().unwrap_or(-1)
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::process::Stdio;

    use super::*;

    fn test_remote_directory() -> OwnedRemoteDirectory {
        let mut remote = REMOTE_DIRECTORY_SPEC
            .directory_for_token(&"a1".repeat(32), "qualification test")
            .expect("remote directory");
        remote
            .bind_identity(FilesystemIdentity::new(253, 91_337).expect("identity"))
            .expect("bind identity");
        remote
    }

    fn test_artifacts() -> QualificationArtifacts {
        let identity = || AndroidArtifactIdentity::for_test("11".repeat(32), 1);
        QualificationArtifacts {
            fluxd: PathBuf::from("/tmp/fluxd-q11"),
            fluxd_identity: identity(),
            producer: PathBuf::from("/tmp/flux-sbox-q11"),
            producer_identity: identity(),
            config: PathBuf::from("/tmp/flux-q11.toml"),
            config_identity: identity(),
            recovery_config: PathBuf::from("/tmp/flux-q11-recovery.toml"),
            recovery_config_identity: identity(),
            template: PathBuf::from("/tmp/template-q11.json"),
            template_identity: identity(),
            subscription: PathBuf::from("/tmp/subscription-q11.url"),
            subscription_identity: identity(),
        }
    }

    fn peer_namespace_frame(device: u64, inode: u64) -> Vec<u8> {
        let mut frame = Vec::from(*PEER_NAMESPACE_REPORT_MAGIC);
        frame.extend_from_slice(&PEER_NAMESPACE_REPORT_VERSION.to_be_bytes());
        frame.extend_from_slice(&PEER_NAMESPACE_REPORT_PAYLOAD_BYTES.to_be_bytes());
        frame.extend_from_slice(&device.to_be_bytes());
        frame.extend_from_slice(&inode.to_be_bytes());
        assert_eq!(frame.len(), PEER_NAMESPACE_REPORT_FRAME_BYTES);
        frame
    }

    #[test]
    fn options_require_explicit_artifact_secret_file_and_serial() {
        let parsed = parse_options(&[
            OsString::from("--serial"),
            OsString::from("device-1"),
            OsString::from("--producer"),
            OsString::from("/tmp/sing-box"),
            OsString::from("--run-manifest"),
            OsString::from("/tmp/run-manifest.md"),
            OsString::from("--subscription-file"),
            OsString::from("/tmp/subscription.url"),
        ])
        .expect("qualification options");
        assert_eq!(parsed.producer, PathBuf::from("/tmp/sing-box"));
        assert_eq!(parsed.run_manifest, PathBuf::from("/tmp/run-manifest.md"));
        assert_eq!(
            parsed.subscription,
            SubscriptionInput::File(PathBuf::from("/tmp/subscription.url"))
        );
        let stdin = parse_options(&[
            OsString::from("--serial"),
            OsString::from("device-1"),
            OsString::from("--producer"),
            OsString::from("/tmp/sing-box"),
            OsString::from("--run-manifest"),
            OsString::from("/tmp/run-manifest.md"),
            OsString::from("--subscription-stdin"),
        ])
        .expect("stdin qualification options");
        assert_eq!(stdin.subscription, SubscriptionInput::Stdin);
        assert!(parse_options(&[]).is_err());
        assert!(
            parse_options(&[
                OsString::from("--serial"),
                OsString::from("device-1"),
                OsString::from("--producer"),
                OsString::from("relative"),
                OsString::from("--run-manifest"),
                OsString::from("/tmp/run-manifest.md"),
                OsString::from("--subscription-file"),
                OsString::from("/tmp/subscription.url"),
            ])
            .is_err()
        );
        assert!(
            parse_options(&[
                OsString::from("--serial"),
                OsString::from("device-1"),
                OsString::from("--producer"),
                OsString::from("/tmp/sing-box"),
                OsString::from("--run-manifest"),
                OsString::from("/tmp/run-manifest.md"),
                OsString::from("--subscription-file"),
                OsString::from("/tmp/subscription.url"),
                OsString::from("--subscription-stdin"),
            ])
            .is_err()
        );
        assert!(
            parse_options(&[
                OsString::from("--serial"),
                OsString::from("device-1"),
                OsString::from("--producer"),
                OsString::from("/tmp/sing-box"),
                OsString::from("--subscription-file"),
                OsString::from("/tmp/subscription.url"),
            ])
            .is_err()
        );
    }

    #[test]
    fn run_manifest_requires_lowercase_sha256_values_and_valid_git_bindings() {
        let valid = r#"# Run

- Build SHA-256:
  `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`

| Object | Path or identity | SHA-256 / Git tree | Bytes |
|---|---|---|---:|
| Source | Git commit | `0123456789abcdef0123456789abcdef01234567` | — |
| Artifact | file | `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` | 1 |
"#;
        validate_run_manifest_text(valid).expect("valid manifest");

        let malformed = valid.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` | 1",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde` | 1",
        );
        let error = validate_run_manifest_text(&malformed)
            .expect_err("malformed producer-style digest must fail");
        assert!(error.contains("64 lowercase hexadecimal"));

        let uppercase = valid.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        assert!(validate_run_manifest_text(&uppercase).is_err());
    }

    #[test]
    fn binary_peer_namespace_receipt_is_parsed_before_text_newline_normalization() {
        let device = 0x010a_0d04_0506_0708;
        let inode = 0x1112_1314_150a_0d18;
        let mut output = peer_namespace_frame(device, inode);
        output.extend_from_slice(b"FLUX_ANDROID_Q11_PASS\r\n");

        let receipt =
            parse_qualification_execution_receipt(&output).expect("canonical binary receipt");
        assert_eq!(receipt.peer_network_namespace.device, device);
        assert_eq!(receipt.peer_network_namespace.inode, inode);
        assert!(receipt.passed);

        let incomplete =
            parse_qualification_execution_receipt(&peer_namespace_frame(device, inode))
                .expect("live identity remains available after a later transaction failure");
        assert!(!incomplete.passed);
        assert_eq!(incomplete.peer_network_namespace.device, device);
        assert_eq!(incomplete.peer_network_namespace.inode, inode);
    }

    #[test]
    fn valid_peer_namespace_prefix_is_bound_before_suffix_validation() {
        let identity = PeerNetworkNamespaceIdentity::new(41, 43).expect("namespace identity");
        let mut output = peer_namespace_frame(identity.device, identity.inode);
        output.extend_from_slice(b"unexpected");

        let (decoded, suffix) =
            decode_qualification_peer_namespace_frame(&output).expect("complete binary prefix");
        assert!(decoded == identity);
        assert!(parse_qualification_receipt_suffix(suffix).is_err());
    }

    #[test]
    fn missing_peer_namespace_receipt_is_uncertain_after_execution_begins() {
        let failed = Err("transaction failed".to_owned());
        assert!(
            missing_peer_namespace_receipt_result(&failed, true)
                .expect_err("started execution without receipt must be uncertain")
                .contains("exact absence is unverified")
        );
        assert!(missing_peer_namespace_receipt_result(&failed, false).is_ok());
        assert!(missing_peer_namespace_receipt_result(&Ok(()), false).is_err());
    }

    #[test]
    fn peer_namespace_receipt_rejects_missing_duplicate_malformed_and_substituted_output() {
        let valid = peer_namespace_frame(4, 4_026_531_999);
        for length in 0..PEER_NAMESPACE_REPORT_FRAME_BYTES {
            assert!(
                parse_qualification_execution_receipt(&valid[..length]).is_err(),
                "truncated frame length {length} must fail"
            );
        }
        assert!(parse_qualification_execution_receipt(QUALIFICATION_PASS_RECEIPT_LINE).is_err());

        let mut duplicate = valid.clone();
        duplicate.extend_from_slice(&valid);
        assert!(parse_qualification_execution_receipt(&duplicate).is_err());

        let mut malformed = valid.clone();
        malformed[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert!(parse_qualification_execution_receipt(&malformed).is_err());
        let mut zero_inode = valid.clone();
        zero_inode[20..28].fill(0);
        assert!(parse_qualification_execution_receipt(&zero_inode).is_err());

        let mut substituted = valid;
        substituted.extend_from_slice(&peer_namespace_frame(5, 4_026_532_000));
        substituted.extend_from_slice(QUALIFICATION_PASS_RECEIPT_LINE);
        let error = parse_qualification_execution_receipt(&substituted)
            .err()
            .expect("substituted receipt must fail");
        assert!(!error.contains("402653"));
        assert!(!error.contains("peer_network_namespace="));
    }

    #[test]
    fn qualification_build_is_isolated_and_appends_the_nonshipping_cfg() {
        let linker = Path::new("/ndk/aarch64-linux-android31-clang");
        let target = Path::new("/workspace/target/android-functional-qualification");
        let command = qualification_build_command(linker, target);
        let args = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "build",
                "-p",
                "fluxd",
                "--bin",
                "fluxd",
                "--release",
                "--target",
                ANDROID_TARGET,
            ]
        );
        let environment = command.get_envs().collect::<BTreeMap<_, _>>();
        assert_eq!(
            environment.get(OsStr::new(ANDROID_TARGET_RUSTFLAGS_ENV)),
            Some(&Some(OsStr::new(QUALIFICATION_RUSTFLAGS)))
        );
        assert_eq!(
            environment.get(OsStr::new("CARGO_TARGET_DIR")),
            Some(&Some(target.as_os_str()))
        );
        assert!(QUALIFICATION_RUSTFLAGS.starts_with(ANDROID_RUSTFLAGS));
        assert!(QUALIFICATION_RUSTFLAGS.ends_with("--cfg flux_android_qualification"));
    }

    #[test]
    fn main_and_recovery_configs_keep_shipping_and_secret_boundaries_explicit() {
        let root = "/data/local/tmp/flux-q11.test";
        let main = render_qualification_config(root, true, true).expect("main config");
        let recovery = render_qualification_config(root, false, false).expect("recovery config");
        let main: Value = toml::from_str(&main).expect("parse main config");
        let recovery: Value = toml::from_str(&recovery).expect("parse recovery config");
        assert_eq!(main["engine"]["runtime_uid"].as_integer(), Some(2_900_002));
        assert_eq!(main["engine"]["runtime_gid"].as_integer(), Some(2_900_002));
        assert_eq!(main["capture"]["ipv6"].as_bool(), Some(true));
        assert_eq!(main["subscription"]["enabled"].as_bool(), Some(true));
        assert_eq!(
            main["subscription"]["download_timeout_secs"].as_integer(),
            Some(QUALIFICATION_DOWNLOAD_TIMEOUT_SECS)
        );
        assert_eq!(
            main["subscription"]["url_file"].as_str(),
            Some("/data/local/tmp/flux-q11.test/subscription-q11.url")
        );
        assert_eq!(main["safety"]["respect_android_vpn"].as_bool(), Some(false));
        assert_eq!(
            main["safety"]["require_functional_canary"].as_bool(),
            Some(true)
        );
        assert_eq!(recovery["subscription"]["enabled"].as_bool(), Some(false));
        assert_eq!(
            recovery["subscription"]["download_timeout_secs"].as_integer(),
            Some(QUALIFICATION_DOWNLOAD_TIMEOUT_SECS)
        );
        assert_eq!(
            recovery["safety"]["require_functional_canary"].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn qualification_script_grants_only_the_producer_engine_execute_role() {
        let remote = test_remote_directory();
        let device = super::super::android_canary::arm64_test_device_profile();
        let artifacts = test_artifacts();
        let execution = qualification_execution_script(&remote, &device, &artifacts);
        let cleanup = qualification_cleanup_script(&remote, &device, &artifacts);

        assert!(execution.contains("/system/bin/chown 0:2900002 \"$PRODUCER\""));
        assert!(execution.contains("/system/bin/chmod 710 \"$PRODUCER\""));
        assert!(execution.contains(
            "/system/bin/chown 0:0 \"$ROOT\" \"$FLUXD\" \"$CONFIG\" \"$RECOVERY_CONFIG\" \"$TEMPLATE\" \"$SUBSCRIPTION\""
        ));
        assert!(execution.contains(
            "/system/bin/chmod 600 \"$CONFIG\" \"$RECOVERY_CONFIG\" \"$TEMPLATE\" \"$SUBSCRIPTION\""
        ));
        assert!(!execution.contains("chown 0:2900002 \"$CONFIG\""));
        assert!(!execution.contains("chown 0:2900002 \"$SUBSCRIPTION\""));
        assert!(execution.contains("710:0:2900002"));
        assert!(cleanup.contains("710:0:2900002"));
    }

    #[test]
    fn qualification_daemon_reports_only_through_private_fd_three() {
        let remote = test_remote_directory();
        let device = super::super::android_canary::arm64_test_device_profile();
        let artifacts = test_artifacts();
        let execution = qualification_execution_script(&remote, &device, &artifacts);

        assert!(execution.contains(
            "FLUX_Q11_NETNS_REPORT_FD=3 run_flux \"$FLUXD\" daemon 3>&1 </dev/null >\"$ROOT/daemon.stdout\" 2>\"$ROOT/daemon.stderr\" &"
        ));
        assert_eq!(execution.matches("FLUX_Q11_NETNS_REPORT_FD=3").count(), 1);
        assert!(!execution.contains("peer_network_namespace="));
    }

    #[test]
    fn qualification_runner_distinguishes_early_daemon_exit_from_readiness_deadline() {
        let remote = test_remote_directory();
        let device = super::super::android_canary::arm64_test_device_profile();
        let artifacts = test_artifacts();
        let execution = qualification_execution_script(&remote, &device, &artifacts);

        assert!(execution.contains("DAEMON_EXITED_BEFORE_READY=0"));
        assert!(execution.contains("DAEMON_EXITED_BEFORE_READY=1"));
        let early_failure = execution
            .find("if [ \"$DAEMON_EXITED_BEFORE_READY\" != '0' ]")
            .expect("early-exit branch");
        let classification = execution[early_failure..]
            .find("classify_daemon_failure")
            .expect("fixed daemon classifier");
        let early_exit = execution[early_failure..]
            .find("exit 74")
            .expect("dedicated early-exit status");
        assert!(classification < early_exit);
        assert!(execution.contains("[ \"$READY\" = '1' ] || exit 75"));
    }

    #[test]
    fn qualification_runner_reduces_daemon_error_to_one_fixed_stage_token() {
        let remote = test_remote_directory();
        let device = super::super::android_canary::arm64_test_device_profile();
        let artifacts = test_artifacts();
        let execution = qualification_execution_script(&remote, &device, &artifacts);

        assert!(execution.contains("classify_daemon_failure()"));
        assert!(execution.contains("planning_failure_token_is_allowed()"));
        assert!(execution.contains("android-planning-authority/$PLANNING_FAILURE"));
        assert!(execution.contains("FLUX_ANDROID_Q11_FAILURE=%s\\n"));
        for fixed_stage in [
            "facility-authority",
            "native-startup-recovery",
            "android-planning-authority",
            "native-runtime-composition",
            "android-planning-retention",
            "subscription-runtime-start",
            "runtime-coordinator-composition",
            "initial-runtime-control",
            "daemon-configuration",
            "daemon-invariant",
            "runtime-layout",
            "administrative-intent",
            "control-reactor",
            "control-socket",
            "unclassified-daemon-exit",
        ] {
            assert!(execution.contains(fixed_stage), "missing {fixed_stage}");
        }
        assert!(!execution.contains("tail -c"));
        assert!(!execution.contains("cat \"$ROOT/daemon.stderr\""));
    }

    #[test]
    fn generated_planning_failure_allowlist_accepts_only_closed_tokens() {
        let remote = test_remote_directory();
        let device = super::super::android_canary::arm64_test_device_profile();
        let artifacts = test_artifacts();
        let execution = qualification_execution_script(&remote, &device, &artifacts);
        let start = execution
            .find("planning_census_stage_allowed()")
            .expect("planning-token helper starts");
        let end = execution
            .find("classify_daemon_failure()")
            .expect("planning-token helper ends");
        let helpers = &execution[start..end];
        let script = format!(
            "set -eu\n{helpers}\nplanning_failure_token_is_allowed 'census/complete/noncomplete-coverage/device-mark-policy/packet/unavailable'\n! planning_failure_token_is_allowed 'census/complete/noncomplete-coverage/device-mark-policy/packet/credential'\n! planning_failure_token_is_allowed 'census/complete/noncomplete-coverage/device-mark-policy/packet/unavailable/extra'\nplanning_failure_token_is_allowed 'census/external-snapshot-context-mismatch/before'\n! planning_failure_token_is_allowed 'census/external-snapshot-context-mismatch/side-channel'\nplanning_failure_token_is_allowed 'census/authorization/census-conflict/xfrm/packet/transfer-read/mask-0c000000/overlap-04000000'\n! planning_failure_token_is_allowed 'census/authorization/census-conflict/xfrm/packet/unknown/mask-0c000000/overlap-04000000'\n! planning_failure_token_is_allowed 'census/authorization/census-conflict/xfrm/packet/transfer-read/mask-0C000000/overlap-04000000'\n! planning_failure_token_is_allowed 'census/authorization/census-conflict/xfrm/packet/transfer-read/mask-04000000/overlap-08000000'\n"
        );
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .status()
            .expect("run generated planning-token helper");
        assert!(status.success(), "generated helper rejected its contract");
    }

    #[test]
    fn qualification_failure_classes_are_fixed_and_require_a_clean_failure_boundary() {
        assert_eq!(
            qualification_failure_diagnostic(
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(false),
                b"",
            ),
            "diagnostic=qualification-daemon-exited-before-readiness"
        );
        assert_eq!(
            qualification_failure_diagnostic(
                Some(QUALIFICATION_READINESS_DEADLINE_STATUS),
                Some(false),
                b"",
            ),
            "diagnostic=qualification-readiness-deadline-exceeded"
        );
        for (stage, diagnostic) in [
            (
                "facility-authority",
                "diagnostic=qualification-daemon-exited-facility-authority",
            ),
            (
                "native-startup-recovery",
                "diagnostic=qualification-daemon-exited-native-startup-recovery",
            ),
            (
                "android-planning-authority",
                "diagnostic=qualification-daemon-exited-android-planning-authority",
            ),
            (
                "native-runtime-composition",
                "diagnostic=qualification-daemon-exited-native-runtime-composition",
            ),
            (
                "android-planning-retention",
                "diagnostic=qualification-daemon-exited-android-planning-retention",
            ),
            (
                "subscription-runtime-start",
                "diagnostic=qualification-daemon-exited-subscription-runtime-start",
            ),
            (
                "runtime-coordinator-composition",
                "diagnostic=qualification-daemon-exited-runtime-coordinator-composition",
            ),
            (
                "initial-runtime-control",
                "diagnostic=qualification-daemon-exited-initial-runtime-control",
            ),
            (
                "daemon-configuration",
                "diagnostic=qualification-daemon-exited-daemon-configuration",
            ),
            (
                "daemon-invariant",
                "diagnostic=qualification-daemon-exited-daemon-invariant",
            ),
            (
                "runtime-layout",
                "diagnostic=qualification-daemon-exited-runtime-layout",
            ),
            (
                "administrative-intent",
                "diagnostic=qualification-daemon-exited-administrative-intent",
            ),
            (
                "control-reactor",
                "diagnostic=qualification-daemon-exited-control-reactor",
            ),
            (
                "control-socket",
                "diagnostic=qualification-daemon-exited-control-socket",
            ),
            (
                "unclassified-daemon-exit",
                "diagnostic=qualification-daemon-exited-unclassified-stage",
            ),
            (
                "android-planning-authority/census/complete/noncomplete-coverage/device-mark-policy/packet/unavailable",
                "diagnostic=qualification-daemon-exited-android-planning-authority-census-complete-noncomplete-coverage-device-mark-policy-packet-unavailable",
            ),
            (
                "android-planning-authority/census/authorization/census-conflict/xfrm/packet/transfer-read/mask-0c000000/overlap-04000000",
                "diagnostic=qualification-daemon-exited-android-planning-authority-census-authorization-census-conflict-xfrm-packet-transfer-read-mask-0c000000-overlap-04000000",
            ),
        ] {
            let stderr = format!("FLUX_ANDROID_Q11_FAILURE={stage}\n");
            assert_eq!(
                qualification_failure_diagnostic(
                    Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                    Some(false),
                    stderr.as_bytes(),
                ),
                diagnostic
            );
        }
        for (status, passed, stderr) in [
            (Some(73), Some(false), b"".as_slice()),
            (
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(true),
                b"".as_slice(),
            ),
            (
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(false),
                b"unexpected".as_slice(),
            ),
            (
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(false),
                b"FLUX_ANDROID_Q11_FAILURE=facility-authority\nextra\n".as_slice(),
            ),
            (
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(false),
                b"FLUX_ANDROID_Q11_FAILURE=unknown-stage\n".as_slice(),
            ),
            (
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(false),
                b"FLUX_ANDROID_Q11_FAILURE=android-planning-authority/census/complete/noncomplete-coverage/device-mark-policy/packet/credential\n".as_slice(),
            ),
            (
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(false),
                b"FLUX_ANDROID_Q11_FAILURE=android-planning-authority/census/complete/noncomplete-coverage/device-mark-policy/packet/unavailable/extra\n".as_slice(),
            ),
            (
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(false),
                b"FLUX_ANDROID_Q11_FAILURE=android-planning-authority/census/authorization/census-conflict/xfrm/packet/unknown/mask-0c000000/overlap-04000000\n".as_slice(),
            ),
            (
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(false),
                b"FLUX_ANDROID_Q11_FAILURE=android-planning-authority/census/authorization/census-conflict/xfrm/packet/transfer-read/mask-0C000000/overlap-04000000\n".as_slice(),
            ),
            (
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(false),
                b"FLUX_ANDROID_Q11_FAILURE=android-planning-authority/census/authorization/census-conflict/xfrm/packet/transfer-read/mask-0c00000/overlap-04000000\n".as_slice(),
            ),
            (
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(false),
                b"FLUX_ANDROID_Q11_FAILURE=android-planning-authority/census/authorization/census-conflict/xfrm/packet/transfer-read/mask-00000000/overlap-00000000\n".as_slice(),
            ),
            (
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(false),
                b"FLUX_ANDROID_Q11_FAILURE=android-planning-authority/census/authorization/census-conflict/xfrm/packet/transfer-read/mask-04000000/overlap-08000000\n".as_slice(),
            ),
            (
                Some(QUALIFICATION_DAEMON_EXITED_STATUS),
                Some(false),
                b"FLUX_ANDROID_Q11_FAILURE=android-planning-authority/census/authorization/census-conflict/xfrm/packet/transfer-read/mask-0c000000/overlap-04000000/extra\n".as_slice(),
            ),
        ] {
            assert_eq!(
                qualification_failure_diagnostic(status, passed, stderr),
                "diagnostic=qualification-receipt-boundary"
            );
        }
    }

    #[test]
    fn peer_namespace_absence_audit_scans_every_holder_domain_without_output() {
        let device = super::super::android_canary::arm64_test_device_profile();
        let identity =
            PeerNetworkNamespaceIdentity::new(4, 4_026_531_999).expect("namespace identity");
        let script = peer_network_namespace_absence_script(&device, identity);

        for required in [
            "/proc/[0-9]*/task/[0-9]*/ns/net",
            "printf 'I %s\\n' \"$EXPECTED_PEER_INODE\"",
            "/system/bin/readlink -q",
            "fields[1] == \"Threads:\"",
            "expected_task_count != observed_task_count",
            "[ \"$TASK_SCAN_STATUS\" = '108' ]",
            "$PROCESS/fd",
            "/system/bin/ls \"$FD_DIRECTORY\" >/dev/null 2>&1",
            "/proc/[0-9]*",
            "process \"/mountinfo\"",
            "/system/bin/awk",
            "(getline expected_device < identity_input)",
            "(getline expected_inode < identity_input)",
            "process_released(process)",
            "state == \"Z\" || state == \"X\"",
            "stat -Lc '%d:%i'",
            "task_count > 65536",
            "PROCESS_COUNT=$((PROCESS_COUNT + 1))",
            "FD_COUNT=$((FD_COUNT + PROCESS_FD_COUNT))",
            "PROCESS_FD_COUNT=$#",
            "OBSERVED_FD_COUNT=$((OBSERVED_FD_COUNT + 1))",
            "[ \"$PROCESS_FD_COUNT\" -le 8192 ]",
            "mountinfo_lines++",
            "total_mountinfo_lines++",
            "total_mountinfo_lines > 1048576",
            "[ \"$MOUNT_SCAN_STATUS\" = '101' ]",
            "$(separator + 1) == \"nsfs\"",
            "EXPECTED_PEER_MOUNT_DEVICE='0:4'",
            "[ \"$(/system/bin/id -u)\" = '0' ]",
            "identity_matches",
        ] {
            assert!(script.contains(required), "missing {required}");
        }
        assert!(!script.contains("$TASK/fd"));
        assert!(!script.contains("$TASK/mountinfo"));
        assert!(!script.contains("echo "));
        assert_eq!(script.matches("printf '%s\\n%s\\n'").count(), 1);
        assert!(!script.contains("-v expected_"));
        assert!(!script.contains("\n+"));

        let task_scan = "scan_task_network_namespaces || exit $?";
        let first_task_scan = script.find(task_scan).expect("first task namespace scan");
        let process_fd_scan = script.find("for PROCESS in /proc/[0-9]*").expect("FD scan");
        let mount_scan = script
            .find("scan_process_mountinfo || exit $?")
            .expect("mountinfo scan");
        let second_task_scan = script.rfind(task_scan).expect("second task namespace scan");
        assert_eq!(script.matches(task_scan).count(), 2);
        assert!(first_task_scan < process_fd_scan);
        assert!(process_fd_scan < mount_scan);
        assert!(mount_scan < second_task_scan);
    }

    #[test]
    fn exact_absence_contract_names_every_owned_durable_and_kernel_domain() {
        let script = exact_flux_absence_function();
        for required in [
            "canary-facility.owner",
            "native_xtables.journal",
            "native_xtables.lease",
            "native_xtables.attempt",
            "native_xtables.targets",
            "fxq11d0",
            "fxq11p0",
            "30997",
            "30998",
            "20253",
            "20254",
            "iptables-save",
            "ip6tables-save",
        ] {
            assert!(script.contains(required), "missing {required}");
        }
    }

    #[test]
    fn cleanup_retires_a_targets_only_clean_settlement_through_offline_recovery() {
        let remote = test_remote_directory();
        let device = super::super::android_canary::arm64_test_device_profile();
        let artifacts = test_artifacts();
        let cleanup = qualification_cleanup_script(&remote, &device, &artifacts);

        assert!(cleanup.contains("native_xtables.targets"));
        assert!(cleanup.contains("\"$FLUXD\" cleanup --offline"));
        assert!(cleanup.contains("[ \"$OFFLINE_RESULT\" = 'cleanup complete' ]"));
        assert!(cleanup.contains("/system/bin/rm \"$ROOT/run/native_xtables.targets\""));
        assert!(
            cleanup.find("\"$FLUXD\" cleanup --offline")
                < cleanup.find("/system/bin/rm \"$ROOT/run/native_xtables.targets\"")
        );
    }

    #[test]
    fn failure_summary_retains_cause_but_redacts_every_runtime_identity() {
        let device = super::super::android_canary::arm64_test_device_profile();
        let secret = "https://provider.example/subscription?token=private";
        let root = "/data/local/tmp/flux-q11.private";
        let status = format!(
            "{{\"native_admission\":{{\"state\":\"admitted\"}},\"qualification_selector_mismatches\":[\"kernel_build\",\"selinux_policy_size\"],\"runtime\":{{\"phase\":\"failed\",\"verification\":\"functional_failed\",\"last_error\":{{\"operation\":\"start\",\"message\":\"subscription {secret} at {root} on samsung/dm3qzhx/dm3q:16/test/release-keys\",\"recovery\":\"retry after cleanup\"}}}}}}"
        );
        let summary = summarize_qualification_diagnostic(
            &status,
            "kernel 5.15.211-Qkernel boot 01234567-89ab-cdef-0123-456789abcdef",
            root,
            secret,
            &device,
        );
        assert!(summary.contains("operation=start"));
        assert!(summary.contains("runtime_phase=failed"));
        assert!(summary.contains("selector_mismatches=kernel_build,selinux_policy_size"));
        assert!(summary.contains("<redacted-subscription>"));
        assert!(summary.contains("<redacted-owned-root>"));
        for forbidden in [
            secret,
            root,
            "samsung/dm3qzhx/dm3q:16/test/release-keys",
            "5.15.211-Qkernel",
            "01234567-89ab-cdef-0123-456789abcdef",
        ] {
            assert!(!summary.contains(forbidden));
        }
    }

    #[test]
    fn selector_mismatch_summary_rejects_non_field_diagnostics() {
        let status = serde_json::json!({
            "qualification_selector_mismatches": ["kernel_build", "raw identity"]
        });
        assert_eq!(
            qualification_selector_mismatch_summary(Some(&status)),
            "unavailable"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_qualification_root_script_has_valid_posix_shell_syntax() {
        let remote = test_remote_directory();
        let device = super::super::android_canary::arm64_test_device_profile();
        let artifacts = test_artifacts();
        let scripts = [
            qualification_preflight_script(&remote, &device),
            qualification_create_directory_script(&remote, &device),
            qualification_execution_script(&remote, &device, &artifacts),
            qualification_failure_diagnostic_script(&remote, &device),
            qualification_cleanup_script(&remote, &device, &artifacts),
            qualification_absence_script(&remote, &device),
            peer_network_namespace_absence_script(
                &device,
                PeerNetworkNamespaceIdentity::new(4, 4_026_531_999)
                    .expect("peer namespace identity"),
            ),
        ];
        for script in scripts {
            let mut child = Command::new("/bin/sh")
                .arg("-n")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn shell syntax checker");
            child
                .stdin
                .take()
                .expect("piped shell stdin")
                .write_all(script.as_bytes())
                .expect("write qualification shell script");
            let output = child.wait_with_output().expect("wait for shell checker");
            assert!(
                output.status.success(),
                "qualification script failed shell syntax: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
