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
    FilesystemIdentity, OwnedRemoteDirectory, OwnedRemoteDirectorySpec, normalize_adb_shell_output,
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
const ADB_EXECUTION_TIMEOUT: Duration = Duration::from_secs(180);
const ADB_CLEANUP_TIMEOUT: Duration = Duration::from_secs(90);
const DIAGNOSTIC_STATUS_BEGIN: &str = "FLUX_ANDROID_Q11_STATUS_BEGIN";
const DIAGNOSTIC_STATUS_END: &str = "FLUX_ANDROID_Q11_STATUS_END";
const DIAGNOSTIC_STDERR_BEGIN: &str = "FLUX_ANDROID_Q11_STDERR_BEGIN";
const DIAGNOSTIC_STDERR_END: &str = "FLUX_ANDROID_Q11_STDERR_END";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Options {
    target: AndroidTargetOptions,
    producer: PathBuf,
    subscription: SubscriptionInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SubscriptionInput {
    File(PathBuf),
    Stdin,
}

pub(super) fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    let mut serial = None;
    let mut adb = None;
    let mut producer = None;
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
            "--subscription-file"
                if subscription_file
                    .replace(require_absolute_path(flag, value)?)
                    .is_none() => {}
            "--serial" | "--adb" | "--producer" | "--subscription-file" => {
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

pub(super) fn run(options: Options) -> Result<(), String> {
    if env::consts::OS != "linux" {
        return Err(
            "the ARM64 Android production-canary qualification requires Linux/WSL".to_owned(),
        );
    }

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
    run_owned_remote_transaction(
        &mut remote,
        |remote| create_remote_directory(&options.target, &device, remote),
        |remote| execute_qualification(&options.target, &device, remote, &artifacts),
        |remote| cleanup_qualification(&options.target, &device, remote, &artifacts),
    )?;
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
    let output = normalize_adb_shell_output(adb_root_shell_output(
        options,
        script.as_bytes(),
        ADB_EXECUTION_TIMEOUT,
        "run Android production-canary qualification transaction",
    )?)?;
    if output.status.success()
        && output.stdout == b"FLUX_ANDROID_Q11_PASS\n"
        && output.stderr.is_empty()
    {
        Ok(())
    } else {
        let diagnostic = collect_failure_diagnostic(options, device, remote, artifacts)
            .unwrap_or_else(|_| "diagnostic=unavailable".to_owned());
        Err(format!(
            "Android production-canary qualification transaction failed at remote status {}; {diagnostic}",
            output.status.code().unwrap_or(-1),
        ))
    }
}

fn collect_failure_diagnostic(
    options: &AndroidTargetOptions,
    device: &DeviceProfile,
    remote: &OwnedRemoteDirectory,
    artifacts: &QualificationArtifacts,
) -> Result<String, String> {
    let script = qualification_failure_diagnostic_script(remote, device);
    let output = normalize_adb_shell_output(adb_root_shell_output(
        options,
        script.as_bytes(),
        ADB_QUERY_TIMEOUT,
        "collect bounded Android qualification failure class",
    )?)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("bounded qualification diagnostic collection failed".to_owned());
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| "bounded qualification diagnostic is not UTF-8".to_owned())?;
    let status = extract_diagnostic_section(text, DIAGNOSTIC_STATUS_BEGIN, DIAGNOSTIC_STATUS_END)?;
    let stderr = extract_diagnostic_section(text, DIAGNOSTIC_STDERR_BEGIN, DIAGNOSTIC_STDERR_END)?;
    let secret = fs::read_to_string(&artifacts.subscription)
        .map_err(|error| format!("reopen runtime subscription only for redaction: {error}"))?;
    Ok(summarize_qualification_diagnostic(
        status,
        stderr,
        remote.path(),
        secret.trim(),
        device,
    ))
}

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

fn extract_diagnostic_section<'a>(
    text: &'a str,
    begin: &str,
    end: &str,
) -> Result<&'a str, String> {
    let start = text
        .find(begin)
        .map(|index| index + begin.len())
        .ok_or_else(|| format!("qualification diagnostic omitted {begin}"))?;
    let remaining = &text[start..];
    let finish = remaining
        .find(end)
        .ok_or_else(|| format!("qualification diagnostic omitted {end}"))?;
    Ok(remaining[..finish].trim())
}

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
         run_flux \"$FLUXD\" daemon </dev/null >\"$ROOT/daemon.stdout\" 2>\"$ROOT/daemon.stderr\" &\n\
         DAEMON_PID=$!\n\
         printf '%s\\n' \"$DAEMON_PID\" >\"$PID_FILE\"\n\
         /system/bin/chmod 600 \"$PID_FILE\"\n\
         READY=0\n\
         N=0\n\
         while [ \"$N\" -lt 120 ]; do\n\
           /system/bin/kill -0 \"$DAEMON_PID\" 2>/dev/null || break\n\
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
         [ \"$READY\" = '1' ] || exit 75\n\
         run_flux \"$FLUXD\" stop >/dev/null 2>&1 || exit 76\n\
         run_flux \"$FLUXD\" status --json >\"$ROOT/status.stopped.json\" 2>/dev/null\n\
         /system/bin/grep -F '\"phase\":\"stopped\"' \"$ROOT/status.stopped.json\" >/dev/null\n\
         /system/bin/grep -F '\"capture\":\"detached\"' \"$ROOT/status.stopped.json\" >/dev/null\n\
         /system/bin/grep -F '\"engine\":\"stopped\"' \"$ROOT/status.stopped.json\" >/dev/null\n\
         shutdown_daemon\n\
         probe_process_absent\n\
         exact_flux_absence\n\
         echo 'FLUX_ANDROID_Q11_PASS'\n\
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

    #[test]
    fn options_require_explicit_artifact_secret_file_and_serial() {
        let parsed = parse_options(&[
            OsString::from("--serial"),
            OsString::from("device-1"),
            OsString::from("--producer"),
            OsString::from("/tmp/sing-box"),
            OsString::from("--subscription-file"),
            OsString::from("/tmp/subscription.url"),
        ])
        .expect("qualification options");
        assert_eq!(parsed.producer, PathBuf::from("/tmp/sing-box"));
        assert_eq!(
            parsed.subscription,
            SubscriptionInput::File(PathBuf::from("/tmp/subscription.url"))
        );
        let stdin = parse_options(&[
            OsString::from("--serial"),
            OsString::from("device-1"),
            OsString::from("--producer"),
            OsString::from("/tmp/sing-box"),
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
                OsString::from("--subscription-file"),
                OsString::from("/tmp/subscription.url"),
                OsString::from("--subscription-stdin"),
            ])
            .is_err()
        );
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
