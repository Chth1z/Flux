use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::Duration;

use flux_platform::{
    AndroidFwmarkCensusProbeReports, parse_android_fwmark_census_probe_reports,
    validate_android_fwmark_census_probe_reports,
};
use serde_json::Value;

use super::android_artifact::AndroidArtifactIdentity as ArtifactIdentity;
use super::android_canary::{
    Options, adb_root_shell_output, adb_text, artifact_path_for_adb, bounded_diagnostic,
    command_output_bounded,
};
use super::android_remote::{
    FilesystemIdentity, OwnedRemoteDirectory as RemoteDirectory, OwnedRemoteDirectorySpec,
    normalize_adb_shell_output, owned_root_functions, parse_canonical_u64,
    parse_directory_identity, path_absence_function, process_absence_function,
    run_owned_remote_transaction, shell_single_quote, valid_boot_id, validate_profile_text,
};
use super::{
    ANDROID_MIN_LOAD_ALIGNMENT, ANDROID_RUSTFLAGS, ANDROID_TARGET, ANDROID_TARGET_RUSTFLAGS_ENV,
    LINUX_ANDROID_HOST_BUILD_TMPDIR, android_linker, validate_aarch64_elf, verify_ndk_revision,
};

const COMMAND: &str = "collect-android-arm64-fwmark-census";
const CLANG_TARGET: &str = "aarch64-linux-android";
const LINKER_ENV: &str = "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER";
const CC_ENV: &str = "CC_aarch64_linux_android";
const REQUIRED_ENV: &str = "FLUX_ANDROID_FWMARK_CENSUS_REQUIRED";
const PROBE_BINARY_TARGET: &str = "android-fwmark-census-probe";
const PROCESS_AND_REMOTE_BINARY_NAME: &str = "flx-census";
const REMOTE_DIRECTORY_SPEC: OwnedRemoteDirectorySpec = OwnedRemoteDirectorySpec::new(
    "/data/local/tmp/flux-census.",
    32,
    ".flux-census-owner",
    "flux-android-fwmark-census-owner-v1",
);
const REMOTE_DIRECTORY_IDENTITY_BEGIN: &str = "FLUX_ANDROID_FWMARK_CENSUS_DIRECTORY_BEGIN";
const REMOTE_DIRECTORY_IDENTITY_END: &str = "FLUX_ANDROID_FWMARK_CENSUS_DIRECTORY_END";
const ROOT_IDENTITY_BEGIN: &str = "FLUX_ANDROID_ROOT_IDENTITY_BEGIN";
const ROOT_IDENTITY_END: &str = "FLUX_ANDROID_ROOT_IDENTITY_END";
const REMOTE_ABSENCE_PROVED: &str = "FLUX_ANDROID_FWMARK_CENSUS_REMOTE_ABSENT";
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
const MINIMUM_ANDROID_SDK: u32 = 31;
const MAX_ADB_CAPTURE_BYTES: usize = 256 * 1024;
const MAX_CARGO_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const ADB_QUERY_TIMEOUT: Duration = Duration::from_secs(20);
const ADB_PUSH_TIMEOUT: Duration = Duration::from_secs(120);
const ADB_EXEC_TIMEOUT: Duration = Duration::from_secs(240);
const ADB_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const CARGO_BUILD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const REMOTE_TEST_TIMEOUT_SECONDS: u64 = 210;
const REMOTE_TEST_KILL_GRACE_SECONDS: u64 = 5;
const PROBE_ERROR_PREFIX: &[u8] = b"Android fwmark census probe: ";
const SANITIZED_PROBE_FAILURE_PREFIX: &str = "fwmark census probe stopped before reports: ";
const SANITIZED_POST_REPORT_FAILURE_PREFIX: &str = "fwmark census probe stopped after reports: ";
const RUNNER_STAGE_FAILURE_PREFIX: &str = "fwmark census runner stopped at ";
const MAX_PROBE_ERROR_LABEL_BYTES: usize = 160;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeTermination {
    Success,
    TimedOut,
    Aborted,
    Killed,
    SegmentationFault,
    RemoteIdentityChanged,
    RemoteProcessCheckFailed,
    RemoteProcessResidue,
    RemoteOwnerCheckFailed,
    Failed,
}

impl ProbeTermination {
    fn from_exit_status(status: ExitStatus) -> Self {
        if status.success() {
            return Self::Success;
        }
        match status.code() {
            Some(124) => Self::TimedOut,
            Some(134) => Self::Aborted,
            Some(137) => Self::Killed,
            Some(139) => Self::SegmentationFault,
            Some(70) => Self::RemoteIdentityChanged,
            Some(71) => Self::RemoteProcessCheckFailed,
            Some(72) => Self::RemoteProcessResidue,
            Some(73) => Self::RemoteOwnerCheckFailed,
            _ => Self::Failed,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Success => "probe-noncanonical-report",
            Self::TimedOut => "probe-timeout",
            Self::Aborted => "probe-aborted",
            Self::Killed => "probe-killed",
            Self::SegmentationFault => "probe-segfault",
            Self::RemoteIdentityChanged => "remote-identity-changed",
            Self::RemoteProcessCheckFailed => "remote-process-check-failed",
            Self::RemoteProcessResidue => "remote-process-residue",
            Self::RemoteOwnerCheckFailed => "remote-owner-check-failed",
            Self::Failed => "probe-failed-without-label",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunnerStage {
    DeviceProfile,
    PrebuildProcessAbsence,
    NdkEnvironment,
    NdkRevision,
    AndroidLinker,
    ProbeBuild,
    ArtifactIdentity,
    ArtifactElfValidation,
    PrecreateDeviceIdentity,
    RemoteToken,
    RemotePathPreflight,
    RemoteDirectoryCreate,
    RemoteProbeExecution,
    RemoteCleanup,
    RemoteTransaction,
}

impl RunnerStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceProfile => "device-profile",
            Self::PrebuildProcessAbsence => "prebuild-process-absence",
            Self::NdkEnvironment => "ndk-environment",
            Self::NdkRevision => "ndk-revision",
            Self::AndroidLinker => "android-linker",
            Self::ProbeBuild => "probe-build",
            Self::ArtifactIdentity => "artifact-identity",
            Self::ArtifactElfValidation => "artifact-elf-validation",
            Self::PrecreateDeviceIdentity => "precreate-device-identity",
            Self::RemoteToken => "remote-token",
            Self::RemotePathPreflight => "remote-path-preflight",
            Self::RemoteDirectoryCreate => "remote-directory-create",
            Self::RemoteProbeExecution => "remote-probe-execution",
            Self::RemoteCleanup => "remote-cleanup",
            Self::RemoteTransaction => "remote-transaction",
        }
    }
}

pub(super) fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    Options::parse(arguments, COMMAND)
}

pub(super) fn run(options: Options) -> Result<(), String> {
    if env::consts::OS != "linux" {
        return Err("the ARM64 Android fwmark census runner requires a Linux/WSL host".to_owned());
    }
    let device = at_runner_stage(RunnerStage::DeviceProfile, verify_device(&options))?;
    at_runner_stage(
        RunnerStage::PrebuildProcessAbsence,
        prove_process_absent(&options, "before building the probe"),
    )?;
    let ndk_root = env::var_os("ANDROID_NDK_HOME")
        .or_else(|| env::var_os("ANDROID_NDK_ROOT"))
        .map(PathBuf::from)
        .ok_or_else(|| runner_stage_error(RunnerStage::NdkEnvironment))?;
    at_runner_stage(RunnerStage::NdkRevision, verify_ndk_revision(&ndk_root))?;
    let linker = at_runner_stage(
        RunnerStage::AndroidLinker,
        android_linker(&ndk_root, ANDROID_TARGET, CLANG_TARGET),
    )?;
    let artifact = at_runner_stage(RunnerStage::ProbeBuild, build_probe_artifact(&linker))?;
    let artifact_identity = at_runner_stage(
        RunnerStage::ArtifactIdentity,
        ArtifactIdentity::from_file(&artifact, "exact census probe"),
    )?;
    at_runner_stage(
        RunnerStage::ArtifactElfValidation,
        validate_aarch64_elf(PROBE_BINARY_TARGET, &artifact),
    )?;
    at_runner_stage(
        RunnerStage::PrecreateDeviceIdentity,
        revalidate_device(&options, &device, "before creating the remote directory"),
    )?;

    println!(
        "validated rooted ARM64 target model={} sdk={} abi={} kernel_arch={} kernel_release={}",
        device.model, device.sdk, device.abi_list, device.kernel_arch, device.kernel_release,
    );
    println!(
        "validated stripped release census ELF sha256={} size={} minimum_load_alignment={ANDROID_MIN_LOAD_ALIGNMENT}",
        artifact_identity.sha256(),
        artifact_identity.size(),
    );

    let mut remote = at_runner_stage(
        RunnerStage::RemoteToken,
        REMOTE_DIRECTORY_SPEC.generate("fwmark census directory"),
    )?;
    at_runner_stage(
        RunnerStage::RemotePathPreflight,
        preflight_remote_directory(&options, &device, &remote),
    )?;
    let result = run_owned_remote_transaction(
        &mut remote,
        |remote| {
            at_runner_stage(
                RunnerStage::RemoteDirectoryCreate,
                create_remote_directory(&options, &device, remote),
            )
        },
        |remote| {
            push_execute_and_validate(&options, &artifact, &artifact_identity, &device, remote)
                .map_err(sanitize_probe_execution_error)
        },
        |remote| {
            at_runner_stage(
                RunnerStage::RemoteCleanup,
                cleanup_remote_directory(&options, &device, remote),
            )
        },
    )
    .map_err(sanitize_remote_transaction_error);
    match result {
        Ok(()) => {
            println!(
                "read-only ARM64 fwmark census passed and independently proved process, binary, and directory absence"
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn at_runner_stage<T>(stage: RunnerStage, result: Result<T, String>) -> Result<T, String> {
    result.map_err(|_| runner_stage_error(stage))
}

fn runner_stage_error(stage: RunnerStage) -> String {
    format!("{RUNNER_STAGE_FAILURE_PREFIX}{}", stage.as_str())
}

fn sanitize_probe_execution_error(error: String) -> String {
    if is_sanitized_probe_failure(&error) {
        error
    } else {
        runner_stage_error(RunnerStage::RemoteProbeExecution)
    }
}

fn sanitize_remote_transaction_error(error: String) -> String {
    if error.contains("; mandatory remote cleanup also failed: ") {
        return runner_stage_error(RunnerStage::RemoteCleanup);
    }
    if is_runner_stage_error(&error) || is_sanitized_probe_failure(&error) {
        error
    } else {
        runner_stage_error(RunnerStage::RemoteTransaction)
    }
}

fn is_sanitized_probe_failure(error: &str) -> bool {
    [
        SANITIZED_PROBE_FAILURE_PREFIX,
        SANITIZED_POST_REPORT_FAILURE_PREFIX,
    ]
    .into_iter()
    .any(|prefix| {
        error
            .strip_prefix(prefix)
            .is_some_and(canonical_probe_error_label)
    })
}

fn is_runner_stage_error(error: &str) -> bool {
    error
        .strip_prefix(RUNNER_STAGE_FAILURE_PREFIX)
        .is_some_and(|stage| {
            matches!(
                stage,
                "device-profile"
                    | "prebuild-process-absence"
                    | "ndk-environment"
                    | "ndk-revision"
                    | "android-linker"
                    | "probe-build"
                    | "artifact-identity"
                    | "artifact-elf-validation"
                    | "precreate-device-identity"
                    | "remote-token"
                    | "remote-path-preflight"
                    | "remote-directory-create"
                    | "remote-probe-execution"
                    | "remote-cleanup"
                    | "remote-transaction"
            )
        })
}

fn canonical_probe_error_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_PROBE_ERROR_LABEL_BYTES
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NetworkNamespaceIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Eq, PartialEq)]
struct DeviceProfile {
    model: String,
    sdk: u32,
    abi_list: String,
    kernel_arch: String,
    kernel_release: String,
    build_fingerprint: String,
    boot_id: String,
    network_namespace: NetworkNamespaceIdentity,
    shell_uid: u32,
    shell_gid: u32,
}

fn verify_device(options: &Options) -> Result<DeviceProfile, String> {
    let state = adb_text(options, &["-s", options.serial(), "get-state"])?;
    if state != "device" {
        return Err("the explicit ADB target is not in device state".to_owned());
    }
    let abi_list = adb_text(
        options,
        &[
            "-s",
            options.serial(),
            "shell",
            "getprop",
            "ro.product.cpu.abilist",
        ],
    )?;
    validate_profile_text("ABI list", &abi_list, 1024)?;
    if !abi_list
        .split(',')
        .any(|candidate| candidate.trim() == "arm64-v8a")
    {
        return Err("the explicit Android target does not advertise arm64-v8a".to_owned());
    }
    let kernel_arch = adb_text(options, &["-s", options.serial(), "shell", "uname", "-m"])?;
    if !matches!(kernel_arch.as_str(), "aarch64" | "arm64") {
        return Err("the explicit Android target is not running an ARM64 kernel".to_owned());
    }
    let kernel_release = adb_text(options, &["-s", options.serial(), "shell", "uname", "-r"])?;
    validate_profile_text("kernel release", &kernel_release, 256)?;
    let sdk_text = adb_text(
        options,
        &[
            "-s",
            options.serial(),
            "shell",
            "getprop",
            "ro.build.version.sdk",
        ],
    )?;
    let sdk = sdk_text
        .parse::<u32>()
        .map_err(|_| "the explicit Android target returned a malformed SDK".to_owned())?;
    if sdk < MINIMUM_ANDROID_SDK {
        return Err(format!(
            "the explicit Android target SDK is below qualification minimum {MINIMUM_ANDROID_SDK}"
        ));
    }
    let model = adb_text(
        options,
        &[
            "-s",
            options.serial(),
            "shell",
            "getprop",
            "ro.product.model",
        ],
    )?;
    validate_profile_text("product model", &model, 256)?;
    let build_fingerprint = adb_text(
        options,
        &[
            "-s",
            options.serial(),
            "shell",
            "getprop",
            "ro.build.fingerprint",
        ],
    )?;
    validate_profile_text("build fingerprint", &build_fingerprint, 1024)?;
    let boot_id = adb_text(
        options,
        &[
            "-s",
            options.serial(),
            "shell",
            "cat",
            "/proc/sys/kernel/random/boot_id",
        ],
    )?;
    if !valid_boot_id(&boot_id) {
        return Err("the explicit Android target returned a malformed boot identity".to_owned());
    }
    let shell_uid = parse_canonical_u32(
        &adb_text(
            options,
            &["-s", options.serial(), "shell", "/system/bin/id", "-u"],
        )?,
        "ADB shell UID",
    )?;
    let shell_gid = parse_canonical_u32(
        &adb_text(
            options,
            &["-s", options.serial(), "shell", "/system/bin/id", "-g"],
        )?,
        "ADB shell GID",
    )?;
    let network_namespace = collect_root_identity(options)?;
    Ok(DeviceProfile {
        model,
        sdk,
        abi_list,
        kernel_arch,
        kernel_release,
        build_fingerprint,
        boot_id,
        network_namespace,
        shell_uid,
        shell_gid,
    })
}

fn collect_root_identity(options: &Options) -> Result<NetworkNamespaceIdentity, String> {
    let output = normalize_adb_shell_output(adb_root_shell_output(
        options,
        root_identity_script().as_bytes(),
        ADB_QUERY_TIMEOUT,
        "collect bounded root and network-namespace identity",
    )?)?;
    if !output.status.success() {
        return Err(
            "the explicit Android target did not provide root identity evidence".to_owned(),
        );
    }
    if !output.stderr.is_empty() {
        return Err("root identity collection emitted unexpected diagnostics".to_owned());
    }
    parse_root_identity(&output.stdout)
}

fn root_identity_script() -> String {
    format!(
        "set -eu\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         echo '{ROOT_IDENTITY_BEGIN}'\n\
         echo \"uid=$(/system/bin/id -u)\"\n\
         echo \"self_namespace=$(/system/bin/stat -Lc '%d:%i' /proc/self/ns/net)\"\n\
         echo \"pid1_namespace=$(/system/bin/stat -Lc '%d:%i' /proc/1/ns/net)\"\n\
         echo '{ROOT_IDENTITY_END}'\n"
    )
}

fn parse_root_identity(bytes: &[u8]) -> Result<NetworkNamespaceIdentity, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "root identity evidence is not UTF-8".to_owned())?;
    let lines = text.trim_end_matches('\n').split('\n').collect::<Vec<_>>();
    let [begin, uid, self_namespace, pid1_namespace, end] = lines.as_slice() else {
        return Err("root identity evidence has an invalid line count".to_owned());
    };
    if *begin != ROOT_IDENTITY_BEGIN || *end != ROOT_IDENTITY_END || *uid != "uid=0" {
        return Err("root identity evidence does not match the exact schema".to_owned());
    }
    let self_namespace = parse_namespace_field(self_namespace, "self_namespace")?;
    let pid1_namespace = parse_namespace_field(pid1_namespace, "pid1_namespace")?;
    if self_namespace != pid1_namespace {
        return Err("root shell is not in PID 1's network namespace".to_owned());
    }
    Ok(self_namespace)
}

fn parse_namespace_field(line: &str, key: &str) -> Result<NetworkNamespaceIdentity, String> {
    let value = line
        .strip_prefix(key)
        .and_then(|suffix| suffix.strip_prefix('='))
        .ok_or_else(|| format!("root identity field {key} is missing"))?;
    let (device, inode) = value
        .split_once(':')
        .ok_or_else(|| format!("root identity field {key} is malformed"))?;
    let device = parse_canonical_u64(device, key)?;
    let inode = parse_canonical_u64(inode, key)?;
    if inode == 0 {
        return Err(format!("root identity field {key} has a zero inode"));
    }
    Ok(NetworkNamespaceIdentity { device, inode })
}

fn revalidate_device(
    options: &Options,
    expected: &DeviceProfile,
    boundary: &str,
) -> Result<(), String> {
    let actual = verify_device(options)
        .map_err(|error| format!("revalidate exact Android identity {boundary}: {error}"))?;
    if &actual == expected {
        Ok(())
    } else {
        Err(format!("exact Android identity changed {boundary}"))
    }
}

fn android_build_command(linker: &Path) -> Command {
    let mut command = Command::new("cargo");
    command.args([
        "build",
        "-p",
        "flux-platform",
        "--bin",
        PROBE_BINARY_TARGET,
        "--release",
        "--target",
        ANDROID_TARGET,
        "--message-format=json-render-diagnostics",
    ]);
    command.env(LINKER_ENV, linker.as_os_str());
    command.env(CC_ENV, linker.as_os_str());
    command.env(ANDROID_TARGET_RUSTFLAGS_ENV, ANDROID_RUSTFLAGS);
    command.env("TMPDIR", LINUX_ANDROID_HOST_BUILD_TMPDIR);
    command
}

fn build_probe_artifact(linker: &Path) -> Result<PathBuf, String> {
    let mut command = android_build_command(linker);
    let output = command_output_bounded(
        &mut command,
        None,
        CARGO_BUILD_TIMEOUT,
        MAX_CARGO_CAPTURE_BYTES,
        &format!("cross-build {ANDROID_TARGET} fwmark census probe ELF"),
    )?;
    if !output.stderr.is_empty() {
        std::io::stderr()
            .write_all(&output.stderr)
            .map_err(|error| format!("forward Cargo diagnostics: {error}"))?;
    }
    if !output.status.success() {
        return Err(format!(
            "cross-build of {ANDROID_TARGET} fwmark census probe ELF exited with {}: {}",
            output.status,
            bounded_diagnostic(&output.stdout)
        ));
    }
    let artifact = artifact_from_cargo_messages(&output.stdout)?;
    if !artifact.is_file() {
        return Err("Cargo reported a missing Android fwmark census probe".to_owned());
    }
    Ok(artifact)
}

fn artifact_from_cargo_messages(messages: &[u8]) -> Result<PathBuf, String> {
    let mut artifacts = BTreeSet::new();
    for line in messages.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let message: Value = serde_json::from_slice(line).map_err(|error| {
            format!(
                "decode Cargo JSON message {:?}: {error}",
                bounded_diagnostic(line)
            )
        })?;
        if message.get("reason").and_then(Value::as_str) != Some("compiler-artifact")
            || message.pointer("/target/name").and_then(Value::as_str) != Some(PROBE_BINARY_TARGET)
            || !message
                .pointer("/target/kind")
                .and_then(Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("bin")))
            || message.pointer("/profile/test").and_then(Value::as_bool) != Some(false)
        {
            continue;
        }
        if let Some(executable) = message.get("executable").and_then(Value::as_str) {
            artifacts.insert(PathBuf::from(executable));
        }
    }
    let artifacts = artifacts.into_iter().collect::<Vec<_>>();
    let [artifact] = artifacts.as_slice() else {
        return Err(
            "Cargo JSON did not report exactly one release fwmark census probe executable"
                .to_owned(),
        );
    };
    Ok(artifact.clone())
}

fn prove_process_absent(options: &Options, boundary: &str) -> Result<(), String> {
    let output = normalize_adb_shell_output(adb_root_shell_output(
        options,
        process_absence_script().as_bytes(),
        ADB_QUERY_TIMEOUT,
        "prove exact fwmark census process absence",
    )?)?;
    if output.status.success() && output.stdout.is_empty() && output.stderr.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "could not prove exact {PROCESS_AND_REMOTE_BINARY_NAME} process absence {boundary}"
        ))
    }
}

fn process_absence_script() -> String {
    format!(
        "set -eu\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         probe_process_absent\n",
        process_absence_function(&[PROCESS_AND_REMOTE_BINARY_NAME])
    )
}

fn preflight_remote_directory(
    options: &Options,
    expected_device: &DeviceProfile,
    remote: &RemoteDirectory,
) -> Result<(), String> {
    if !remote.matches_spec() {
        return Err("refusing to preflight an invalid fwmark census directory".to_owned());
    }
    revalidate_device(options, expected_device, "before remote-path preflight")?;
    let output = normalize_adb_shell_output(adb_root_shell_output(
        options,
        preflight_remote_directory_script(remote, expected_device).as_bytes(),
        ADB_QUERY_TIMEOUT,
        "prove the generated fwmark census path absent",
    )?)?;
    if !output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty() {
        return Err("generated fwmark census path is not cleanly absent".to_owned());
    }
    revalidate_device(options, expected_device, "after remote-path preflight")
}

fn create_remote_directory(
    options: &Options,
    expected_device: &DeviceProfile,
    remote: &RemoteDirectory,
) -> Result<FilesystemIdentity, String> {
    let output = normalize_adb_shell_output(adb_root_shell_output(
        options,
        create_remote_directory_script(remote, expected_device).as_bytes(),
        ADB_QUERY_TIMEOUT,
        "create exact owner-marked fwmark census directory",
    )?)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("owner-marked fwmark census directory creation failed".to_owned());
    }
    parse_remote_directory_identity(&output.stdout)
}

fn parse_remote_directory_identity(bytes: &[u8]) -> Result<FilesystemIdentity, String> {
    parse_directory_identity(
        bytes,
        REMOTE_DIRECTORY_IDENTITY_BEGIN,
        REMOTE_DIRECTORY_IDENTITY_END,
        "directory_identity",
        "fwmark census directory",
    )
}

fn push_execute_and_validate(
    options: &Options,
    artifact: &Path,
    artifact_identity: &ArtifactIdentity,
    expected_device: &DeviceProfile,
    remote: &RemoteDirectory,
) -> Result<(), String> {
    let remote_binary = format!("{}/{}", remote.path(), PROCESS_AND_REMOTE_BINARY_NAME);
    let adb_artifact = artifact_path_for_adb(options, artifact)
        .map_err(|_| sanitized_probe_failure("remote-artifact-path"))?;
    let mut push = Command::new(options.adb());
    push.args(["-s", options.serial(), "push"])
        .arg(adb_artifact)
        .arg(&remote_binary);
    let output = command_output_bounded(
        &mut push,
        None,
        ADB_PUSH_TIMEOUT,
        MAX_ADB_CAPTURE_BYTES,
        "push exact ARM64 fwmark census probe ELF",
    )
    .map_err(|_| sanitized_probe_failure("remote-push-transport"))?;
    if !output.status.success() {
        return Err("ADB push of the exact fwmark census probe failed".to_owned());
    }
    revalidate_device(options, expected_device, "after the remote push")
        .map_err(|_| sanitized_probe_failure("remote-post-push-identity"))?;

    let script = remote_script(remote, artifact_identity, expected_device)
        .map_err(|_| sanitized_probe_failure("remote-script"))?;
    let output = adb_root_shell_output(
        options,
        script.as_bytes(),
        ADB_EXEC_TIMEOUT,
        "run bounded read-only ARM64 fwmark census",
    )
    .map_err(|_| sanitized_probe_failure("remote-execution-transport"))?;
    let output = normalize_adb_shell_output(output)
        .map_err(|_| sanitized_probe_failure("remote-execution-newlines"))?;
    let termination = ProbeTermination::from_exit_status(output.status);
    let reports =
        parse_probe_reports_or_sanitized_failure(termination, &output.stdout, &output.stderr)?;
    std::io::stdout()
        .write_all(&output.stdout)
        .map_err(|error| format!("forward sanitized census reports: {error}"))?;
    validate_post_report_probe_result(
        termination,
        validate_android_fwmark_census_probe_reports(&reports),
        &output.stderr,
    )
}

fn validate_post_report_probe_result(
    termination: ProbeTermination,
    validation: Result<(), String>,
    stderr: &[u8],
) -> Result<(), String> {
    match validation {
        Ok(()) if termination == ProbeTermination::Success && stderr.is_empty() => Ok(()),
        Ok(()) if termination == ProbeTermination::Success => Err(sanitized_post_report_failure(
            "probe-valid-reports-diagnostics",
        )),
        Ok(()) => Err(sanitized_post_report_failure("probe-valid-reports-failed")),
        Err(expected)
            if termination != ProbeTermination::Success
                && canonical_probe_error_label(&expected)
                && sanitized_probe_error_label(stderr) == Some(expected.as_str()) =>
        {
            Err(sanitized_post_report_failure(&expected))
        }
        Err(_) => Err(sanitized_post_report_failure(
            "probe-report-validation-mismatch",
        )),
    }
}

fn parse_probe_reports_or_sanitized_failure(
    termination: ProbeTermination,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<AndroidFwmarkCensusProbeReports, String> {
    match parse_android_fwmark_census_probe_reports(stdout) {
        Ok(reports) => Ok(reports),
        Err(_) if termination == ProbeTermination::Success => {
            Err(sanitized_probe_failure(termination.label()))
        }
        Err(_) => match sanitized_probe_error_label(stderr) {
            Some(label) => Err(format!("{SANITIZED_PROBE_FAILURE_PREFIX}{label}")),
            None if termination != ProbeTermination::Failed => {
                Err(sanitized_probe_failure(termination.label()))
            }
            None if !stderr.is_empty() => {
                Err(sanitized_probe_failure("probe-noncanonical-diagnostics"))
            }
            None if !stdout.is_empty() => Err(sanitized_probe_failure("probe-noncanonical-report")),
            None => Err(sanitized_probe_failure(termination.label())),
        },
    }
}

fn sanitized_probe_failure(label: &'static str) -> String {
    debug_assert!(canonical_probe_error_label(label));
    format!("{SANITIZED_PROBE_FAILURE_PREFIX}{label}")
}

fn sanitized_post_report_failure(label: &str) -> String {
    debug_assert!(canonical_probe_error_label(label));
    format!("{SANITIZED_POST_REPORT_FAILURE_PREFIX}{label}")
}

fn sanitized_probe_error_label(stderr: &[u8]) -> Option<&str> {
    let line = stderr
        .strip_suffix(b"\n")?
        .strip_prefix(PROBE_ERROR_PREFIX)?;
    let label = std::str::from_utf8(line).ok()?;
    canonical_probe_error_label(label).then_some(label)
}

fn preflight_remote_directory_script(
    remote: &RemoteDirectory,
    expected_device: &DeviceProfile,
) -> String {
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
        device_identity_function(expected_device),
        process_absence_function(&[PROCESS_AND_REMOTE_BINARY_NAME]),
    )
}

fn create_remote_directory_script(
    remote: &RemoteDirectory,
    expected_device: &DeviceProfile,
) -> String {
    let remote_variables =
        remote.shell_variables(expected_device.shell_uid, expected_device.shell_gid);
    let shell_uid = expected_device.shell_uid;
    let shell_gid = expected_device.shell_gid;
    format!(
        "set -eu\n\
         umask 077\n\
         {remote_variables}\
         OWNER_TMP=\"$OWNER.tmp\"\n\
         EXPECTED_SHELL_UID='{shell_uid}'\n\
         EXPECTED_SHELL_GID='{shell_gid}'\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         CREATED='0'\n\
         CREATED_ID=''\n\
         cleanup_partial() {{\n\
           [ \"$CREATED\" = '1' ] || return 0\n\
           identity_matches || return 70\n\
           probe_process_absent\n\
           [ -d \"$ROOT\" ] && [ ! -L \"$ROOT\" ]\n\
           [ \"$(/system/bin/stat -Lc '%d:%i' \"$ROOT\")\" = \"$CREATED_ID\" ]\n\
           /system/bin/rm -rf \"$ROOT\"\n\
         }}\n\
         trap cleanup_partial EXIT\n\
         trap 'exit 70' HUP INT TERM\n\
         identity_matches\n\
         probe_process_absent\n\
         path_absent \"$ROOT\"\n\
         /system/bin/mkdir -m 700 \"$ROOT\"\n\
         CREATED='1'\n\
         CREATED_ID=$(/system/bin/stat -Lc '%d:%i' \"$ROOT\")\n\
         printf '%s\\n' \"$EXPECTED_OWNER_RECORD\" >\"$OWNER_TMP\"\n\
         /system/bin/chown 0:0 \"$OWNER_TMP\"\n\
         /system/bin/chmod 600 \"$OWNER_TMP\"\n\
         /system/bin/mv \"$OWNER_TMP\" \"$OWNER\"\n\
         /system/bin/chown \"$EXPECTED_SHELL_UID:$EXPECTED_SHELL_GID\" \"$ROOT\"\n\
         [ \"$(/system/bin/stat -c '%a:%u:%g' \"$ROOT\")\" = \"700:$EXPECTED_SHELL_UID:$EXPECTED_SHELL_GID\" ]\n\
         [ -f \"$OWNER\" ] && [ ! -L \"$OWNER\" ]\n\
         [ \"$(/system/bin/stat -c '%a:%u:%g' \"$OWNER\")\" = '600:0:0' ]\n\
         [ \"$(/system/bin/cat \"$OWNER\")\" = \"$EXPECTED_OWNER_RECORD\" ]\n\
         echo '{REMOTE_DIRECTORY_IDENTITY_BEGIN}'\n\
         echo \"directory_identity=$CREATED_ID\"\n\
         echo '{REMOTE_DIRECTORY_IDENTITY_END}'\n\
         CREATED='0'\n\
         trap - EXIT HUP INT TERM\n",
        path_absence_function(),
        device_identity_function(expected_device),
        process_absence_function(&[PROCESS_AND_REMOTE_BINARY_NAME]),
    )
}

fn remote_script(
    remote: &RemoteDirectory,
    artifact: &ArtifactIdentity,
    expected_device: &DeviceProfile,
) -> Result<String, String> {
    if remote.identity().is_none() {
        return Err("fwmark census directory identity is unavailable before execution".to_owned());
    }
    let expected_sha256 = shell_single_quote(artifact.sha256());
    let expected_size = artifact.size();
    Ok(format!(
        "set -eu\n\
         umask 077\n\
         {}\
         BIN=\"$ROOT/{PROCESS_AND_REMOTE_BINARY_NAME}\"\n\
         TMPDIR=\"$ROOT/tmp\"\n\
         EXPECTED_SHA256={expected_sha256}\n\
         EXPECTED_SIZE='{expected_size}'\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         trap remove_owned_root EXIT\n\
         trap 'exit 70' HUP INT TERM\n\
         identity_matches\n\
         probe_process_absent\n\
         owned_root_matches\n\
         [ -f \"$BIN\" ] && [ ! -L \"$BIN\" ]\n\
         /system/bin/chown -R 0:0 \"$ROOT\"\n\
         /system/bin/chmod 700 \"$ROOT\" \"$BIN\"\n\
         owned_root_matches\n\
         [ \"$(/system/bin/stat -c '%a:%u:%g' \"$BIN\")\" = '700:0:0' ]\n\
         ACTUAL_SHA256=$(/system/bin/sha256sum \"$BIN\" | /system/bin/cut -d ' ' -f 1)\n\
         [ \"$ACTUAL_SHA256\" = \"$EXPECTED_SHA256\" ]\n\
         [ \"$(/system/bin/stat -c '%s' \"$BIN\")\" = \"$EXPECTED_SIZE\" ]\n\
         /system/bin/mkdir \"$TMPDIR\"\n\
         /system/bin/chmod 700 \"$TMPDIR\"\n\
         export TMPDIR {REQUIRED_ENV}=1\n\
         set +e\n\
         /system/bin/timeout -k {REMOTE_TEST_KILL_GRACE_SECONDS} {REMOTE_TEST_TIMEOUT_SECONDS} \"$BIN\"\n\
         STATUS=$?\n\
         set -e\n\
         probe_process_absent\n\
         remove_owned_root\n\
         path_absent \"$BIN\"\n\
         path_absent \"$ROOT\"\n\
         probe_process_absent\n\
         identity_matches\n\
         trap - EXIT HUP INT TERM\n\
         exit \"$STATUS\"\n",
        remote_directory_variables(remote, expected_device),
        device_identity_function(expected_device),
        process_absence_function(&[PROCESS_AND_REMOTE_BINARY_NAME]),
        owned_root_functions(),
    ))
}

fn cleanup_remote_directory(
    options: &Options,
    expected_device: &DeviceProfile,
    remote: &RemoteDirectory,
) -> Result<(), String> {
    if !remote.matches_spec() {
        return Err("refusing cleanup for an invalid fwmark census directory".to_owned());
    }

    let before = verify_device(options)
        .map_err(|error| format!("revalidate Android identity before cleanup: {error}"))?;
    require_expected_device(
        expected_device,
        &before,
        "before cleanup; no cleanup mutation was attempted",
    )?;

    let removal = adb_root_shell_output(
        options,
        cleanup_script(remote, expected_device).as_bytes(),
        ADB_CLEANUP_TIMEOUT,
        "remove exact owner-marked fwmark census directory",
    )
    .and_then(normalize_adb_shell_output);
    let absence = adb_root_shell_output(
        options,
        remote_absence_script(remote, expected_device).as_bytes(),
        ADB_CLEANUP_TIMEOUT,
        "independently prove fwmark census process and path absence",
    )
    .and_then(normalize_adb_shell_output);
    let identity_after = verify_device(options);

    let after = identity_after
        .map_err(|error| format!("revalidate Android identity after cleanup: {error}"))?;
    require_expected_device(expected_device, &after, "after cleanup")?;

    let removal =
        removal.map_err(|error| format!("remove exact remote census directory: {error}"))?;
    if !removal.status.success() || !removal.stdout.is_empty() || !removal.stderr.is_empty() {
        return Err(
            "exact owner-marked census directory removal did not complete cleanly".to_owned(),
        );
    }
    let absence = absence.map_err(|error| format!("prove remote census absence: {error}"))?;
    if !absence.status.success()
        || absence.stdout != format!("{REMOTE_ABSENCE_PROVED}\n").as_bytes()
        || !absence.stderr.is_empty()
    {
        return Err(
            "independent remote proof did not confirm process, binary, and directory absence"
                .to_owned(),
        );
    }
    Ok(())
}

fn require_expected_device(
    expected: &DeviceProfile,
    actual: &DeviceProfile,
    boundary: &str,
) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "Android build, boot, architecture, or namespace drifted {boundary}"
        ))
    }
}

fn cleanup_script(remote: &RemoteDirectory, expected_device: &DeviceProfile) -> String {
    format!(
        "set -eu\n\
         {}\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         identity_matches\n\
         remove_owned_root\n",
        remote_directory_variables(remote, expected_device),
        device_identity_function(expected_device),
        process_absence_function(&[PROCESS_AND_REMOTE_BINARY_NAME]),
        owned_root_functions(),
    )
}

fn remote_absence_script(remote: &RemoteDirectory, expected_device: &DeviceProfile) -> String {
    format!(
        "set -eu\n\
         {}\
         BIN=\"$ROOT/{PROCESS_AND_REMOTE_BINARY_NAME}\"\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         identity_matches\n\
         path_absent \"$BIN\"\n\
         path_absent \"$ROOT\"\n\
         probe_process_absent\n\
         echo '{REMOTE_ABSENCE_PROVED}'\n",
        remote_directory_variables(remote, expected_device),
        path_absence_function(),
        device_identity_function(expected_device),
        process_absence_function(&[PROCESS_AND_REMOTE_BINARY_NAME]),
    )
}

fn remote_directory_variables(remote: &RemoteDirectory, expected_device: &DeviceProfile) -> String {
    remote.shell_variables(expected_device.shell_uid, expected_device.shell_gid)
}

fn device_identity_function(expected_device: &DeviceProfile) -> String {
    let expected_boot_id = shell_single_quote(&expected_device.boot_id);
    let expected_fingerprint = shell_single_quote(&expected_device.build_fingerprint);
    let expected_arch = shell_single_quote(&expected_device.kernel_arch);
    let expected_namespace = shell_single_quote(&format!(
        "{}:{}",
        expected_device.network_namespace.device, expected_device.network_namespace.inode
    ));
    format!(
        "EXPECTED_BOOT_ID={expected_boot_id}\n\
         EXPECTED_FINGERPRINT={expected_fingerprint}\n\
         EXPECTED_ARCH={expected_arch}\n\
         EXPECTED_NAMESPACE={expected_namespace}\n\
         identity_matches() {{\n\
           [ \"$(/system/bin/cat /proc/sys/kernel/random/boot_id)\" = \"$EXPECTED_BOOT_ID\" ] &&\n\
           [ \"$(/system/bin/getprop ro.build.fingerprint)\" = \"$EXPECTED_FINGERPRINT\" ] &&\n\
           [ \"$(/system/bin/uname -m)\" = \"$EXPECTED_ARCH\" ] &&\n\
           [ \"$(/system/bin/stat -Lc '%d:%i' /proc/self/ns/net)\" = \"$EXPECTED_NAMESPACE\" ]\n\
         }}\n"
    )
}

fn parse_canonical_u32(value: &str, field: &str) -> Result<u32, String> {
    u32::try_from(parse_canonical_u64(value, field)?)
        .map_err(|_| format!("{field} exceeds the u32 domain"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::fs;

    use crate::android_remote::normalize_adb_shell_newlines;

    fn expected_device() -> DeviceProfile {
        DeviceProfile {
            model: "SM-S9180".to_owned(),
            sdk: 36,
            abi_list: "arm64-v8a,armeabi-v7a".to_owned(),
            kernel_arch: "aarch64".to_owned(),
            kernel_release: "5.15.207-test".to_owned(),
            build_fingerprint: "vendor/product/device:16/BUILD/1:user/release-keys".to_owned(),
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            network_namespace: NetworkNamespaceIdentity {
                device: 4,
                inode: 4_026_531_840,
            },
            shell_uid: 2000,
            shell_gid: 2000,
        }
    }

    fn remote_directory() -> RemoteDirectory {
        let mut remote = REMOTE_DIRECTORY_SPEC
            .directory_for_token(&"a1".repeat(32), "fwmark census directory")
            .expect("remote token");
        remote
            .bind_identity(FilesystemIdentity::new(253, 91_337).expect("filesystem identity"))
            .expect("bind filesystem identity");
        remote
    }

    #[cfg(target_os = "linux")]
    struct FakeAdb {
        root: PathBuf,
        program: PathBuf,
        log: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl FakeAdb {
        fn new(boot_id: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            use std::sync::atomic::{AtomicU64, Ordering};

            static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = env::temp_dir().join(format!(
                "flux-fwmark-census-fake-adb-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create fake ADB directory");
            let program = root.join("adb");
            let log = root.join("calls.log");
            let log_value = shell_single_quote(log.to_str().expect("UTF-8 fake ADB log path"));
            let boot_value = shell_single_quote(boot_id);
            let script = format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 LOG={log_value}\n\
                 BOOT_ID={boot_value}\n\
                 [ \"$1\" = '-s' ]\n\
                 shift 2\n\
                 ARGS=\"$*\"\n\
                 case \"$ARGS\" in\n\
                   'get-state') echo device ;;\n\
                   'shell getprop ro.product.cpu.abilist') echo 'arm64-v8a,armeabi-v7a' ;;\n\
                   'shell uname -m') echo aarch64 ;;\n\
                   'shell uname -r') echo '5.15.207-test' ;;\n\
                   'shell getprop ro.build.version.sdk') echo 36 ;;\n\
                   'shell getprop ro.product.model') echo 'SM-S9180' ;;\n\
                   'shell getprop ro.build.fingerprint') echo 'vendor/product/device:16/BUILD/1:user/release-keys' ;;\n\
                   'shell cat /proc/sys/kernel/random/boot_id') echo \"$BOOT_ID\" ;;\n\
                   'shell /system/bin/id -u') echo 2000 ;;\n\
                   'shell /system/bin/id -g') echo 2000 ;;\n\
                   'shell su -c /system/bin/sh')\n\
                     SCRIPT=$(/bin/cat)\n\
                     case \"$SCRIPT\" in\n\
                       *FLUX_ANDROID_ROOT_IDENTITY_BEGIN*)\n\
                         echo identity >>\"$LOG\"\n\
                         echo FLUX_ANDROID_ROOT_IDENTITY_BEGIN\n\
                         echo uid=0\n\
                         echo self_namespace=4:4026531840\n\
                         echo pid1_namespace=4:4026531840\n\
                         echo FLUX_ANDROID_ROOT_IDENTITY_END\n\
                         ;;\n\
                       *FLUX_ANDROID_FWMARK_CENSUS_DIRECTORY_BEGIN*)\n\
                         echo create >>\"$LOG\"\n\
                         echo malformed-directory-identity\n\
                         ;;\n\
                       *FLUX_ANDROID_FWMARK_CENSUS_REMOTE_ABSENT*)\n\
                         echo absence >>\"$LOG\"\n\
                         echo FLUX_ANDROID_FWMARK_CENSUS_REMOTE_ABSENT\n\
                         ;;\n\
                       *remove_owned_root*) echo cleanup >>\"$LOG\" ;;\n\
                       *) exit 91 ;;\n\
                     esac\n\
                     ;;\n\
                   *) exit 92 ;;\n\
                 esac\n"
            );
            fs::write(&program, script).expect("write fake ADB");
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700))
                .expect("make fake ADB executable");
            Self { root, program, log }
        }

        fn options(&self) -> Options {
            Options::parse(
                &[
                    OsString::from("--serial"),
                    OsString::from("fixture-serial"),
                    OsString::from("--adb"),
                    self.program.as_os_str().to_owned(),
                ],
                COMMAND,
            )
            .expect("fake ADB options")
        }

        fn calls(&self) -> Vec<String> {
            fs::read_to_string(&self.log)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for FakeAdb {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn build_command_uses_the_pinned_release_arm64_toolchain_and_host_tmpdir() {
        let linker = Path::new("/ndk/toolchains/llvm/bin/aarch64-linux-android31-clang");
        let command = android_build_command(linker);
        let arguments = command.get_args().collect::<Vec<_>>();
        assert!(
            arguments
                .windows(2)
                .any(|args| { args == [OsStr::new("--bin"), OsStr::new(PROBE_BINARY_TARGET),] })
        );
        assert!(arguments.contains(&OsStr::new("--release")));
        let environment = command
            .get_envs()
            .collect::<std::collections::BTreeMap<_, _>>();
        for name in [LINKER_ENV, CC_ENV] {
            assert_eq!(
                environment.get(OsStr::new(name)),
                Some(&Some(linker.as_os_str()))
            );
        }
        assert_eq!(
            environment.get(OsStr::new(ANDROID_TARGET_RUSTFLAGS_ENV)),
            Some(&Some(OsStr::new(ANDROID_RUSTFLAGS)))
        );
        assert_eq!(
            environment.get(OsStr::new("TMPDIR")),
            Some(&Some(OsStr::new(LINUX_ANDROID_HOST_BUILD_TMPDIR)))
        );
    }

    #[test]
    fn cargo_json_selects_exactly_one_release_probe_binary() {
        let artifact = "/tmp/android-fwmark-census-probe";
        let messages = format!(
            "{{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"other\",\"kind\":[\"bin\"]}},\"profile\":{{\"test\":false}},\"executable\":\"/tmp/other\"}}\n\
             {{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"{PROBE_BINARY_TARGET}\",\"kind\":[\"bin\"]}},\"profile\":{{\"test\":false}},\"executable\":\"{artifact}\"}}\n"
        );
        assert_eq!(
            artifact_from_cargo_messages(messages.as_bytes()).expect("exact artifact"),
            PathBuf::from(artifact)
        );
        let second = messages.replace(artifact, "/tmp/second-android-fwmark-census-probe");
        let ambiguous = format!("{messages}{second}");
        assert!(artifact_from_cargo_messages(ambiguous.as_bytes()).is_err());
    }

    #[test]
    fn pre_report_probe_failure_surfaces_only_the_sanitized_probe_label() {
        let error = match parse_probe_reports_or_sanitized_failure(
            ProbeTermination::Failed,
            b"",
            b"Android fwmark census probe: collection-external-before-nftables-observation\n",
        ) {
            Ok(_) => panic!("a pre-report probe failure must stop"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            "fwmark census probe stopped before reports: collection-external-before-nftables-observation"
        );

        let hostile = b"Android fwmark census probe: secret=/data/user/0/private\n";
        let error = match parse_probe_reports_or_sanitized_failure(
            ProbeTermination::Failed,
            b"",
            hostile,
        ) {
            Ok(_) => panic!("hostile diagnostics must not become a report"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            "fwmark census probe stopped before reports: probe-noncanonical-diagnostics"
        );
        assert!(!error.contains("private"));
    }

    #[test]
    fn pre_report_termination_classes_are_bounded_and_payload_free() {
        for (termination, stdout, stderr, expected) in [
            (
                ProbeTermination::TimedOut,
                b"".as_slice(),
                b"timeout: private diagnostics\n".as_slice(),
                "probe-timeout",
            ),
            (
                ProbeTermination::Aborted,
                b"".as_slice(),
                b"abort at /data/private\n".as_slice(),
                "probe-aborted",
            ),
            (
                ProbeTermination::SegmentationFault,
                b"".as_slice(),
                b"".as_slice(),
                "probe-segfault",
            ),
            (
                ProbeTermination::Failed,
                b"noncanonical report\n".as_slice(),
                b"".as_slice(),
                "probe-noncanonical-report",
            ),
            (
                ProbeTermination::Failed,
                b"".as_slice(),
                b"".as_slice(),
                "probe-failed-without-label",
            ),
            (
                ProbeTermination::Success,
                b"".as_slice(),
                b"".as_slice(),
                "probe-noncanonical-report",
            ),
        ] {
            let error = parse_probe_reports_or_sanitized_failure(termination, stdout, stderr)
                .expect_err("a pre-report termination must stop");
            assert_eq!(error, format!("{SANITIZED_PROBE_FAILURE_PREFIX}{expected}"));
            assert!(!error.contains("private"));
            assert!(canonical_probe_error_label(expected));
        }
    }

    #[test]
    fn post_report_validation_preserves_only_the_independently_derived_probe_label() {
        let expected = "primary-noncomplete-cell-traffic-control-and-bpf-packet-opaque";
        let stderr = format!("Android fwmark census probe: {expected}\n");
        let error = validate_post_report_probe_result(
            ProbeTermination::Failed,
            Err(expected.to_owned()),
            stderr.as_bytes(),
        )
        .expect_err("matching report validation must stop with its bounded label");
        assert_eq!(
            error,
            format!("{SANITIZED_POST_REPORT_FAILURE_PREFIX}{expected}")
        );

        for (termination, validation, diagnostics) in [
            (
                ProbeTermination::Failed,
                Err(expected.to_owned()),
                b"Android fwmark census probe: different-canonical-label\n".as_slice(),
            ),
            (
                ProbeTermination::Failed,
                Err(expected.to_owned()),
                b"Android fwmark census probe: secret=/data/user/0/private\n".as_slice(),
            ),
            (
                ProbeTermination::Success,
                Err(expected.to_owned()),
                stderr.as_bytes(),
            ),
            (
                ProbeTermination::Failed,
                Err("host validation leaked /data/user/0/private".to_owned()),
                stderr.as_bytes(),
            ),
        ] {
            let error = validate_post_report_probe_result(termination, validation, diagnostics)
                .expect_err("inconsistent post-report output must stop");
            assert_eq!(
                error,
                format!("{SANITIZED_POST_REPORT_FAILURE_PREFIX}probe-report-validation-mismatch")
            );
            assert!(!error.contains("private"), "{error}");
        }
    }

    #[test]
    fn post_report_success_requires_successful_silent_probe_termination() {
        validate_post_report_probe_result(ProbeTermination::Success, Ok(()), b"")
            .expect("valid reports and silent successful termination");
        assert_eq!(
            validate_post_report_probe_result(
                ProbeTermination::Success,
                Ok(()),
                b"unexpected /data/private diagnostics\n",
            )
            .expect_err("diagnostics after valid reports must stop"),
            format!("{SANITIZED_POST_REPORT_FAILURE_PREFIX}probe-valid-reports-diagnostics")
        );
        assert_eq!(
            validate_post_report_probe_result(ProbeTermination::Killed, Ok(()), b"")
                .expect_err("nonzero termination after valid reports must stop"),
            format!("{SANITIZED_POST_REPORT_FAILURE_PREFIX}probe-valid-reports-failed")
        );
    }

    #[test]
    fn runner_stage_errors_discard_serials_paths_and_low_level_diagnostics() {
        let hostile =
            "adb -s fixture-serial shell cat /data/user/0/private: permission denied".to_owned();
        for stage in [
            RunnerStage::DeviceProfile,
            RunnerStage::PrebuildProcessAbsence,
            RunnerStage::NdkEnvironment,
            RunnerStage::NdkRevision,
            RunnerStage::AndroidLinker,
            RunnerStage::ProbeBuild,
            RunnerStage::ArtifactIdentity,
            RunnerStage::ArtifactElfValidation,
            RunnerStage::PrecreateDeviceIdentity,
            RunnerStage::RemoteToken,
            RunnerStage::RemotePathPreflight,
            RunnerStage::RemoteDirectoryCreate,
            RunnerStage::RemoteCleanup,
        ] {
            let error = at_runner_stage::<()>(stage, Err(hostile.clone()))
                .expect_err("every detailed runner failure must stop");
            assert_eq!(error, runner_stage_error(stage));
            assert!(is_runner_stage_error(&error));
            assert!(!error.contains("fixture-serial"), "{error}");
            assert!(!error.contains("/data/"), "{error}");
        }
    }

    #[test]
    fn remote_error_sanitizer_preserves_only_a_canonical_probe_class() {
        let bounded =
            format!("{SANITIZED_PROBE_FAILURE_PREFIX}collection-external-before-kernel-config");
        assert_eq!(sanitize_probe_execution_error(bounded.clone()), bounded);
        let bounded = format!(
            "{SANITIZED_POST_REPORT_FAILURE_PREFIX}primary-noncomplete-cell-traffic-control-and-bpf-packet-opaque"
        );
        assert_eq!(sanitize_probe_execution_error(bounded.clone()), bounded);

        for hostile in [
            "adb -s fixture-serial shell su -c /system/bin/sh",
            "fwmark census probe stopped before reports: secret=/data/private",
            "fwmark census probe stopped before reports: valid-label; extra",
            "fwmark census probe stopped after reports: secret=/data/private",
            "fwmark census probe stopped after reports: valid-label; extra",
        ] {
            let error = sanitize_probe_execution_error(hostile.to_owned());
            assert_eq!(error, runner_stage_error(RunnerStage::RemoteProbeExecution));
            assert!(!error.contains("fixture-serial"), "{error}");
            assert!(!error.contains("/data/"), "{error}");
        }
    }

    #[test]
    fn remote_cleanup_failure_takes_precedence_without_forwarding_payloads() {
        let error = sanitize_remote_transaction_error(format!(
            "{}; mandatory remote cleanup also failed: serial=fixture-serial path=/data/private",
            runner_stage_error(RunnerStage::RemoteProbeExecution)
        ));
        assert_eq!(error, runner_stage_error(RunnerStage::RemoteCleanup));
        assert!(!error.contains("fixture-serial"), "{error}");
        assert!(!error.contains("/data/"), "{error}");
    }

    #[test]
    fn documented_census_invocation_suppresses_cargo_argument_echo() {
        let readme = include_str!("../../README.md");
        assert!(readme.contains(
            "cargo --quiet xtask collect-android-arm64-fwmark-census --serial SERIAL --adb PROGRAM"
        ));
        assert!(!readme.contains(
            "cargo xtask collect-android-arm64-fwmark-census --serial SERIAL --adb PROGRAM"
        ));
    }

    #[test]
    fn root_identity_requires_uid_zero_and_pid1_network_namespace() {
        let valid = format!(
            "{ROOT_IDENTITY_BEGIN}\nuid=0\nself_namespace=4:4026531840\npid1_namespace=4:4026531840\n{ROOT_IDENTITY_END}\n"
        );
        assert_eq!(
            parse_root_identity(valid.as_bytes()).expect("root identity"),
            NetworkNamespaceIdentity {
                device: 4,
                inode: 4_026_531_840,
            }
        );
        assert!(parse_root_identity(valid.replace("uid=0", "uid=2000").as_bytes()).is_err());
        assert!(
            parse_root_identity(
                valid
                    .replace("pid1_namespace=4:4026531840", "pid1_namespace=4:99")
                    .as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn adb_shell_text_accepts_uniform_lf_or_crlf_and_rejects_ambiguous_framing() {
        let lf = format!(
            "{ROOT_IDENTITY_BEGIN}\nuid=0\nself_namespace=4:4026531840\npid1_namespace=4:4026531840\n{ROOT_IDENTITY_END}\n"
        );
        assert_eq!(
            normalize_adb_shell_newlines(lf.as_bytes().to_vec(), "stdout").expect("canonical LF"),
            lf.as_bytes()
        );

        let crlf = lf.replace('\n', "\r\n");
        let normalized = normalize_adb_shell_newlines(crlf.into_bytes(), "stdout")
            .expect("uniform Windows ADB CRLF");
        assert_eq!(normalized, lf.as_bytes());
        parse_root_identity(&normalized).expect("normalized root identity");

        let probe_error =
            b"Android fwmark census probe: collection-external-before-kernel-config\r\n".to_vec();
        let normalized =
            normalize_adb_shell_newlines(probe_error, "stderr").expect("uniform probe-error CRLF");
        assert_eq!(
            sanitized_probe_error_label(&normalized),
            Some("collection-external-before-kernel-config")
        );

        for ambiguous in [b"one\rbare".as_slice(), b"one\r\ntwo\n".as_slice()] {
            assert!(
                normalize_adb_shell_newlines(ambiguous.to_vec(), "stdout").is_err(),
                "ambiguous framing must fail closed: {ambiguous:?}"
            );
        }
    }

    #[test]
    fn remote_path_scripts_pin_owner_only_execution_and_independent_cleanup() {
        let remote = remote_directory();
        assert!(REMOTE_DIRECTORY_SPEC.matches_path(remote.path()));
        assert!(!REMOTE_DIRECTORY_SPEC.matches_path(&format!("{}/child", remote.path())));
        assert!(
            !REMOTE_DIRECTORY_SPEC
                .matches_path(&format!("/data/local/tmp/other.{}", remote.token()))
        );
        assert!(PROCESS_AND_REMOTE_BINARY_NAME.len() <= 15);
        let script = remote_script(
            &remote,
            &ArtifactIdentity::for_test("11".repeat(32), 4096),
            &expected_device(),
        )
        .expect("remote script");
        for required in [
            "trap remove_owned_root EXIT",
            "EXPECTED_OWNER_RECORD=",
            "EXPECTED_DIRECTORY_ID=",
            "owned_root_matches",
            "identity_matches",
            "stat -c '%a:%u:%g'",
            "sha256sum \"$BIN\"",
            "FLUX_ANDROID_FWMARK_CENSUS_REQUIRED=1",
            "probe_process_absent",
            "path_absent \"$BIN\"",
            "path_absent \"$ROOT\"",
            "stat -Lc '%d:%i' /proc/self/ns/net",
        ] {
            assert!(script.contains(required), "missing {required:?}");
        }
        for forbidden in ["iptables-restore", "ip rule add", "/data/adb/flux/scripts"] {
            assert!(!script.contains(forbidden), "unexpected {forbidden:?}");
        }
        let cleanup = cleanup_script(&remote, &expected_device());
        assert!(cleanup.find("identity_matches").unwrap() < cleanup.find("rm -rf").unwrap());
        assert!(cleanup.find("probe_process_absent").unwrap() < cleanup.find("rm -rf").unwrap());
        let absence = remote_absence_script(&remote, &expected_device());
        assert!(absence.contains("probe_process_absent"));
        assert!(absence.contains(path_absence_function()));
        assert!(absence.contains("path_absent \"$BIN\""));
        assert!(absence.contains("path_absent \"$ROOT\""));
        assert!(!absence.contains("kill"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_generated_root_script_has_valid_posix_shell_syntax() {
        use std::process::Stdio;

        let remote = remote_directory();
        let device = expected_device();
        let scripts = [
            root_identity_script(),
            process_absence_script(),
            preflight_remote_directory_script(&remote, &device),
            create_remote_directory_script(&remote, &device),
            remote_script(
                &remote,
                &ArtifactIdentity::for_test("11".repeat(32), 4096),
                &device,
            )
            .expect("remote script"),
            cleanup_script(&remote, &device),
            remote_absence_script(&remote, &device),
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
                .expect("write generated shell script");
            let output = child.wait_with_output().expect("wait for shell checker");
            assert!(
                output.status.success(),
                "generated script failed shell syntax: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn remote_transaction_attempts_cleanup_after_lost_creation_output() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let mut remote = REMOTE_DIRECTORY_SPEC
            .directory_for_token(&"b2".repeat(32), "fwmark census directory")
            .expect("remote token");
        let error = run_owned_remote_transaction(
            &mut remote,
            |_| {
                events.borrow_mut().push("create");
                Err("creation output was lost".to_owned())
            },
            |_| panic!("execution must not follow uncertain creation"),
            |remote| {
                events.borrow_mut().push("cleanup");
                assert!(remote.identity().is_none());
                Ok(())
            },
        )
        .expect_err("lost creation output must fail");
        assert_eq!(error, "creation output was lost");
        assert_eq!(*events.borrow(), ["create", "cleanup"]);
    }

    #[test]
    fn remote_transaction_cleans_execution_failure_and_preserves_dual_failure() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let mut remote = REMOTE_DIRECTORY_SPEC
            .directory_for_token(&"c3".repeat(32), "fwmark census directory")
            .expect("remote token");
        let error = run_owned_remote_transaction(
            &mut remote,
            |_| {
                events.borrow_mut().push("create");
                FilesystemIdentity::new(7, 11)
            },
            |remote| {
                events.borrow_mut().push("execute");
                assert!(remote.identity().is_some());
                Err("probe execution timed out".to_owned())
            },
            |remote| {
                events.borrow_mut().push("cleanup");
                assert!(remote.identity().is_some());
                Err("process residue survived".to_owned())
            },
        )
        .expect_err("dual failure must remain visible");
        assert!(error.contains("probe execution timed out"), "{error}");
        assert!(error.contains("process residue survived"), "{error}");
        assert_eq!(*events.borrow(), ["create", "execute", "cleanup"]);
    }

    #[test]
    fn cleanup_identity_gate_rejects_drift_before_mutation() {
        let expected = expected_device();
        let mut drifted = expected.clone();
        drifted.boot_id = "fedcba98-7654-3210-fedc-ba9876543210".to_owned();
        let error = require_expected_device(
            &expected,
            &drifted,
            "before cleanup; no cleanup mutation was attempted",
        )
        .expect_err("identity drift must stop cleanup");
        assert!(
            error.contains("no cleanup mutation was attempted"),
            "{error}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fake_adb_lost_creation_output_still_runs_cleanup_and_absence_proof() {
        let fake = FakeAdb::new("01234567-89ab-cdef-0123-456789abcdef");
        let options = fake.options();
        let device = expected_device();
        let mut remote = REMOTE_DIRECTORY_SPEC
            .directory_for_token(&"d4".repeat(32), "fwmark census directory")
            .expect("remote directory token");
        let error = run_owned_remote_transaction(
            &mut remote,
            |remote| create_remote_directory(&options, &device, remote),
            |_| panic!("execution must not follow malformed creation output"),
            |remote| cleanup_remote_directory(&options, &device, remote),
        )
        .expect_err("malformed creation output must fail");
        assert!(
            error.contains("directory identity has an invalid line count"),
            "{error}"
        );
        let calls = fake.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.as_str() == "cleanup")
                .count(),
            1
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.as_str() == "absence")
                .count(),
            1
        );
        assert!(
            calls.iter().position(|call| call == "create")
                < calls.iter().position(|call| call == "cleanup")
        );
        assert!(
            calls.iter().position(|call| call == "cleanup")
                < calls.iter().position(|call| call == "absence")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fake_adb_identity_drift_stops_before_cleanup_dispatch() {
        let fake = FakeAdb::new("fedcba98-7654-3210-fedc-ba9876543210");
        let error =
            cleanup_remote_directory(&fake.options(), &expected_device(), &remote_directory())
                .expect_err("boot drift must stop cleanup");
        assert!(
            error.contains("no cleanup mutation was attempted"),
            "{error}"
        );
        let calls = fake.calls();
        assert!(calls.iter().any(|call| call == "identity"));
        assert!(!calls.iter().any(|call| call == "cleanup"));
        assert!(!calls.iter().any(|call| call == "absence"));
    }
}
