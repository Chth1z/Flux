use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;

use serde_json::Value;

use flux_platform::internal::{
    ENGINE_CREDENTIAL_PROBE_STAGE_RECEIPT_NAME, EngineCredentialProbeStage,
};

use super::android_artifact::AndroidArtifactIdentity;
use super::android_remote::{
    FilesystemIdentity, OwnedRemoteDirectory, OwnedRemoteDirectorySpec, normalize_adb_shell_output,
    owned_root_functions, parse_directory_identity, path_absence_function,
    process_absence_function, run_owned_remote_transaction, shell_single_quote,
};
use super::{
    ANDROID_ENGINE_CREDENTIAL_CANARY_TEST, ANDROID_RUSTFLAGS,
    ANDROID_SUPERVISED_PRODUCER_CANARY_TEST, ANDROID_TARGET, ANDROID_TARGET_RUSTFLAGS_ENV,
    LINUX_ANDROID_HOST_BUILD_TMPDIR, LINUX_CANARY_INTERNAL_ENVS, LINUX_OUTPUT_TPROXY_CANARY_TEST,
    android_kernel, android_linker, sing_box_producer, validate_aarch64_elf, verify_ndk_revision,
};

pub(super) const COMMAND: &str = "test-functional-canary-android-output-tproxy";
const MINIMUM_ANDROID_SDK: u32 = 31;
const REMOTE_DIRECTORY_SPEC: OwnedRemoteDirectorySpec = OwnedRemoteDirectorySpec::new(
    "/data/local/tmp/flux-output-tproxy.",
    32,
    ".flux-output-tproxy-owner",
    "flux-android-output-tproxy-owner-v1",
);
const REMOTE_DIRECTORY_IDENTITY_BEGIN: &str = "FLUX_ANDROID_CANARY_DIRECTORY_BEGIN";
const REMOTE_DIRECTORY_IDENTITY_END: &str = "FLUX_ANDROID_CANARY_DIRECTORY_END";
const REMOTE_TEST_BINARY_NAME: &str = "fluxd-test";
const CREDENTIAL_PROBE_TARGET_NAME: &str = "flux-engine-credential-probe";
const REMOTE_CREDENTIAL_PROBE_BINARY_NAME: &str = CREDENTIAL_PROBE_TARGET_NAME;
const REMOTE_CREDENTIAL_PROBE_PROCESS_NAME: &str = "flux-cred-probe";
const REMOTE_PRODUCER_BINARY_NAME: &str = "flux-sbox-p01";
const REAL_PRODUCER_BINARY_ENV: &str = "FLUX_TEST_SING_BOX_PRODUCER_BINARY";
const REMOTE_PROCESS_NAMES: [&str; 3] = [
    REMOTE_TEST_BINARY_NAME,
    REMOTE_CREDENTIAL_PROBE_PROCESS_NAME,
    REMOTE_PRODUCER_BINARY_NAME,
];
const TRUSTED_ANDROID_PATH: &str = concat!(
    "/product/bin:",
    "/apex/com.android.runtime/bin:",
    "/apex/com.android.art/bin:",
    "/system_ext/bin:",
    "/system/bin:",
    "/system/xbin:",
    "/odm/bin:",
    "/vendor/bin:",
    "/vendor/xbin",
);
const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024;
const MAX_ADB_CAPTURE_BYTES: usize = 256 * 1024;
const MAX_CARGO_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const ADB_QUERY_TIMEOUT: Duration = Duration::from_secs(15);
const ADB_PUSH_TIMEOUT: Duration = Duration::from_secs(120);
const REMOTE_OUTPUT_TEST_TIMEOUT_SECONDS: u64 = 60;
const REMOTE_CREDENTIAL_TEST_TIMEOUT_SECONDS: u64 = 25;
const REMOTE_SUPERVISED_TEST_TIMEOUT_SECONDS: u64 = 60;
const REMOTE_TEST_KILL_GRACE_SECONDS: u64 = 5;
const REMOTE_PREFLIGHT_IDENTITY_FAILURE_STATUS: i32 = 70;
const REMOTE_PREFLIGHT_PROCESS_FAILURE_STATUS: i32 = 71;
const REMOTE_PREFLIGHT_PATH_FAILURE_STATUS: i32 = 72;
const REMOTE_CONTRACT_FAILURE_STATUS: i32 = 70;
const REMOTE_OUTPUT_TEST_FAILURE_STATUS: i32 = 74;
const REMOTE_CREDENTIAL_TEST_FAILURE_STATUS: i32 = 75;
const REMOTE_SUPERVISED_TEST_FAILURE_STATUS: i32 = 76;
const REMOTE_CREDENTIAL_STAGE_OUTPUT_PREFIX: &str = "flux-engine-credential-stage:";
const ADB_EXEC_TIMEOUT: Duration = Duration::from_secs(115);
const ADB_SUPERVISED_EXEC_TIMEOUT: Duration = Duration::from_secs(180);
const ADB_CLEANUP_TIMEOUT: Duration = Duration::from_secs(20);
const CARGO_BUILD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const HOST_POLL_INTERVAL: Duration = Duration::from_millis(25);
const HOST_OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(2);
const RUNNER_STAGE_FAILURE_PREFIX: &str = "Android canary runner stopped at ";

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct Options {
    serial: String,
    adb: OsString,
    producer: Option<PathBuf>,
}

pub(super) fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    Options::parse(arguments, COMMAND)
}

impl Options {
    pub(super) fn for_shared_target(serial: String, adb: OsString) -> Result<Self, String> {
        validate_serial(&serial)?;
        Ok(Self {
            serial,
            adb,
            producer: None,
        })
    }

    pub(super) fn parse(arguments: &[OsString], command: &str) -> Result<Self, String> {
        let mut serial = None;
        let mut adb = None;
        let mut producer = None;
        let mut index = 0;
        while index < arguments.len() {
            let flag = arguments[index].to_string_lossy();
            let value = arguments
                .get(index.saturating_add(1))
                .ok_or_else(|| format!("{flag} requires a value"))?;
            match flag.as_ref() {
                "--serial" if serial.is_none() => {
                    let value = value
                        .to_str()
                        .ok_or_else(|| "--serial must contain valid UTF-8".to_owned())?;
                    validate_serial(value)?;
                    serial = Some(value.to_owned());
                }
                "--adb" if adb.is_none() => adb = Some(value.clone()),
                "--producer" if command == COMMAND && producer.is_none() => {
                    let path = PathBuf::from(value);
                    if !path.is_absolute() {
                        return Err("--producer must be an absolute file path".to_owned());
                    }
                    producer = Some(path);
                }
                "--serial" | "--adb" => {
                    return Err(format!("{flag} may only be supplied once"));
                }
                "--producer" if command == COMMAND => {
                    return Err(format!("{flag} may only be supplied once"));
                }
                unknown => return Err(format!("unknown Android target option '{unknown}'")),
            }
            index = index.saturating_add(2);
        }
        Ok(Self {
            serial: serial.ok_or_else(|| format!("{command} requires --serial SERIAL"))?,
            adb: adb
                .or_else(|| env::var_os("ADB"))
                .unwrap_or_else(|| OsString::from("adb")),
            producer,
        })
    }

    pub(super) fn serial(&self) -> &str {
        &self.serial
    }

    pub(super) fn adb(&self) -> &OsString {
        &self.adb
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunnerStage {
    DeviceProfile,
    NdkEnvironment,
    NdkRevision,
    AndroidLinker,
    ArtifactBuild,
    ArtifactIdentity,
    ArtifactElfValidation,
    PrecreateDeviceIdentity,
    RemoteToken,
    RemotePathPreflightIdentityBefore,
    RemotePathPreflightRootIdentity,
    RemotePathPreflightProcessAbsence,
    RemotePathPreflightPathAbsence,
    RemotePathPreflightContract,
    RemotePathPreflightTransport,
    RemotePathPreflightNormalization,
    RemotePathPreflightUnexpectedStatus,
    RemotePathPreflightUnexpectedOutput,
    RemotePathPreflightIdentityAfter,
    RemoteDirectoryCreate,
    RemoteExecution,
    RemoteExecutionPreflight,
    RemoteTestArtifactPush,
    RemoteCredentialArtifactPush,
    RemoteProducerArtifactPush,
    RemoteCheckpointTransport,
    RemoteContract,
    RemoteShell,
    RemoteTimeout,
    LocalOutputCheckpoint,
    SupervisedProducerCheckpoint,
    EngineCredentialCheckpoint,
    EngineCredential(EngineCredentialProbeStage),
    RemoteCleanup,
    RemoteTransaction,
}

impl RunnerStage {
    fn as_str(self) -> String {
        match self {
            Self::DeviceProfile => "device-profile".to_owned(),
            Self::NdkEnvironment => "ndk-environment".to_owned(),
            Self::NdkRevision => "ndk-revision".to_owned(),
            Self::AndroidLinker => "android-linker".to_owned(),
            Self::ArtifactBuild => "artifact-build".to_owned(),
            Self::ArtifactIdentity => "artifact-identity".to_owned(),
            Self::ArtifactElfValidation => "artifact-elf-validation".to_owned(),
            Self::PrecreateDeviceIdentity => "precreate-device-identity".to_owned(),
            Self::RemoteToken => "remote-token".to_owned(),
            Self::RemotePathPreflightIdentityBefore => {
                "remote-path-preflight-identity-before".to_owned()
            }
            Self::RemotePathPreflightRootIdentity => {
                "remote-path-preflight-root-identity".to_owned()
            }
            Self::RemotePathPreflightProcessAbsence => {
                "remote-path-preflight-process-absence".to_owned()
            }
            Self::RemotePathPreflightPathAbsence => "remote-path-preflight-path-absence".to_owned(),
            Self::RemotePathPreflightContract => "remote-path-preflight-contract".to_owned(),
            Self::RemotePathPreflightTransport => "remote-path-preflight-transport".to_owned(),
            Self::RemotePathPreflightNormalization => {
                "remote-path-preflight-normalization".to_owned()
            }
            Self::RemotePathPreflightUnexpectedStatus => {
                "remote-path-preflight-unexpected-status".to_owned()
            }
            Self::RemotePathPreflightUnexpectedOutput => {
                "remote-path-preflight-unexpected-output".to_owned()
            }
            Self::RemotePathPreflightIdentityAfter => {
                "remote-path-preflight-identity-after".to_owned()
            }
            Self::RemoteDirectoryCreate => "remote-directory-create".to_owned(),
            Self::RemoteExecution => "remote-execution".to_owned(),
            Self::RemoteExecutionPreflight => "remote-execution-preflight".to_owned(),
            Self::RemoteTestArtifactPush => "remote-test-artifact-push".to_owned(),
            Self::RemoteCredentialArtifactPush => "remote-credential-artifact-push".to_owned(),
            Self::RemoteProducerArtifactPush => "remote-producer-artifact-push".to_owned(),
            Self::RemoteCheckpointTransport => "remote-checkpoint-transport".to_owned(),
            Self::RemoteContract => "remote-contract".to_owned(),
            Self::RemoteShell => "remote-shell".to_owned(),
            Self::RemoteTimeout => "remote-timeout".to_owned(),
            Self::LocalOutputCheckpoint => "local-output-checkpoint".to_owned(),
            Self::SupervisedProducerCheckpoint => "supervised-producer-checkpoint".to_owned(),
            Self::EngineCredentialCheckpoint => "engine-credential-checkpoint".to_owned(),
            Self::EngineCredential(stage) => format!("engine-credential-{}", stage.as_str()),
            Self::RemoteCleanup => "remote-cleanup".to_owned(),
            Self::RemoteTransaction => "remote-transaction".to_owned(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct AndroidCanaryArtifactPaths {
    test: PathBuf,
    credential_probe: PathBuf,
    producer: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AndroidCanaryArtifactIdentities {
    test: AndroidArtifactIdentity,
    credential_probe: AndroidArtifactIdentity,
    producer: Option<AndroidArtifactIdentity>,
}

impl AndroidCanaryArtifactIdentities {
    fn from_paths(paths: &AndroidCanaryArtifactPaths) -> Result<Self, String> {
        Ok(Self {
            test: AndroidArtifactIdentity::from_file(&paths.test, "exact Android canary test ELF")?,
            credential_probe: AndroidArtifactIdentity::from_file(
                &paths.credential_probe,
                "exact Android credential-probe ELF",
            )?,
            producer: paths
                .producer
                .as_deref()
                .map(|path| {
                    AndroidArtifactIdentity::from_file(
                        path,
                        "exact manifest-bound Android Sing-Box producer",
                    )
                })
                .transpose()?,
        })
    }

    fn verify_paths(&self, paths: &AndroidCanaryArtifactPaths) -> Result<(), String> {
        self.test
            .verify_file(&paths.test, "exact Android canary test ELF")?;
        self.credential_probe.verify_file(
            &paths.credential_probe,
            "exact Android credential-probe ELF",
        )?;
        match (&self.producer, &paths.producer) {
            (Some(identity), Some(path)) => {
                identity.verify_file(path, "exact manifest-bound Android Sing-Box producer")
            }
            (None, None) => Ok(()),
            _ => {
                Err("Android producer artifact presence changed after identity capture".to_owned())
            }
        }
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self {
            test: AndroidArtifactIdentity::for_test("11".repeat(32), 4096),
            credential_probe: AndroidArtifactIdentity::for_test("22".repeat(32), 2048),
            producer: None,
        }
    }

    #[cfg(test)]
    fn with_producer_for_test() -> Self {
        Self {
            producer: Some(AndroidArtifactIdentity::for_test("33".repeat(32), 8192)),
            ..Self::for_test()
        }
    }
}

pub(super) fn run(options: Options) -> Result<(), String> {
    if env::consts::OS != "linux" {
        return Err("the Android canary runner currently requires a Linux/WSL host".to_owned());
    }
    let device = at_runner_stage(RunnerStage::DeviceProfile, verify_device(&options))?;
    let ndk_root = env::var_os("ANDROID_NDK_HOME")
        .or_else(|| env::var_os("ANDROID_NDK_ROOT"))
        .map(PathBuf::from)
        .ok_or_else(|| runner_stage_error(RunnerStage::NdkEnvironment))?;
    at_runner_stage(RunnerStage::NdkRevision, verify_ndk_revision(&ndk_root))?;
    let target = device.target;
    let linker = at_runner_stage(
        RunnerStage::AndroidLinker,
        android_linker(&ndk_root, target.rust_target, target.clang_target),
    )?;
    let mut artifacts =
        at_runner_stage(RunnerStage::ArtifactBuild, build_artifacts(&linker, target))?;
    if let Some(producer) = options.producer.clone() {
        if target != &ARM64_TARGET {
            return Err(runner_stage_error(RunnerStage::ArtifactElfValidation));
        }
        at_runner_stage(
            RunnerStage::ArtifactElfValidation,
            sing_box_producer::validate_android_artifact(&producer),
        )?;
        artifacts.producer = Some(producer);
    }
    let artifact_identities = at_runner_stage(
        RunnerStage::ArtifactIdentity,
        AndroidCanaryArtifactIdentities::from_paths(&artifacts),
    )?;
    if target.validate_aarch64_elf {
        at_runner_stage(
            RunnerStage::ArtifactElfValidation,
            validate_aarch64_elf("fluxd Android canary test", &artifacts.test),
        )?;
        at_runner_stage(
            RunnerStage::ArtifactElfValidation,
            validate_aarch64_elf(
                "Android engine credential probe",
                &artifacts.credential_probe,
            ),
        )?;
    }
    at_runner_stage(
        RunnerStage::PrecreateDeviceIdentity,
        revalidate_device(&options, &device, "before remote mutation"),
    )?;

    println!(
        "validated rooted {} Android target meeting SDK and kernel floors",
        target.label
    );
    println!(
        "validated exact Android canary test ELF sha256={} size={}",
        artifact_identities.test.sha256(),
        artifact_identities.test.size(),
    );
    println!(
        "validated exact Android credential-probe ELF sha256={} size={}",
        artifact_identities.credential_probe.sha256(),
        artifact_identities.credential_probe.size(),
    );
    if let Some(producer) = &artifact_identities.producer {
        println!(
            "validated exact manifest-bound Android Sing-Box producer sha256={} size={}",
            producer.sha256(),
            producer.size(),
        );
    }

    let mut remote = at_runner_stage(
        RunnerStage::RemoteToken,
        REMOTE_DIRECTORY_SPEC.generate("Android canary directory"),
    )?;
    preflight_remote_directory(&options, &device, &remote)?;
    let result = run_owned_remote_transaction(
        &mut remote,
        |remote| {
            at_runner_stage(
                RunnerStage::RemoteDirectoryCreate,
                create_remote_directory(&options, &device, remote),
            )
        },
        |remote| {
            push_and_execute(&options, &artifacts, &artifact_identities, &device, remote)
                .map_err(classify_remote_execution_error)
        },
        |remote| {
            at_runner_stage(
                RunnerStage::RemoteCleanup,
                cleanup_remote_directory(&options, &device, remote),
            )
        },
    )
    .map_err(sanitize_remote_transaction_error);
    result?;
    if artifact_identities.producer.is_some() {
        println!(
            "rooted {} Android local-OUTPUT TPROXY, engine-credential, and supervised-producer checkpoints passed with independently proved process and path absence",
            target.label
        );
    } else {
        println!(
            "rooted {} Android local-OUTPUT TPROXY and engine-credential checkpoints passed with independently proved process and path absence",
            target.label
        );
    }
    Ok(())
}

fn at_runner_stage<T>(stage: RunnerStage, result: Result<T, String>) -> Result<T, String> {
    result.map_err(|_| runner_stage_error(stage))
}

fn runner_stage_error(stage: RunnerStage) -> String {
    format!("{RUNNER_STAGE_FAILURE_PREFIX}{}", stage.as_str())
}

fn sanitize_remote_transaction_error(error: String) -> String {
    if error.contains("; mandatory remote cleanup also failed: ") {
        runner_stage_error(RunnerStage::RemoteCleanup)
    } else if error.starts_with(RUNNER_STAGE_FAILURE_PREFIX) {
        error
    } else {
        runner_stage_error(RunnerStage::RemoteTransaction)
    }
}

fn classify_remote_execution_error(error: String) -> String {
    for stage in [
        RunnerStage::RemoteExecutionPreflight,
        RunnerStage::RemoteTestArtifactPush,
        RunnerStage::RemoteCredentialArtifactPush,
        RunnerStage::RemoteProducerArtifactPush,
        RunnerStage::RemoteCheckpointTransport,
        RunnerStage::RemoteContract,
        RunnerStage::RemoteShell,
        RunnerStage::RemoteTimeout,
        RunnerStage::LocalOutputCheckpoint,
        RunnerStage::SupervisedProducerCheckpoint,
        RunnerStage::EngineCredentialCheckpoint,
    ] {
        if error == runner_stage_error(stage) {
            return error;
        }
    }
    for stage in EngineCredentialProbeStage::all() {
        if error == runner_stage_error(RunnerStage::EngineCredential(stage)) {
            return error;
        }
    }
    runner_stage_error(RunnerStage::RemoteExecution)
}

fn credential_stage_from_remote_output(output: &[u8]) -> Option<EngineCredentialProbeStage> {
    let output = std::str::from_utf8(output).ok()?;
    let token = output
        .strip_prefix(REMOTE_CREDENTIAL_STAGE_OUTPUT_PREFIX)?
        .strip_suffix('\n')?;
    if token.is_empty() || token.contains(['\r', '\n']) {
        return None;
    }
    EngineCredentialProbeStage::all().find(|stage| stage.as_str() == token)
}

fn checkpoint_stage_for_remote_output(
    code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> RunnerStage {
    if !stderr.is_empty() {
        return RunnerStage::RemoteExecution;
    }
    if code == Some(REMOTE_CREDENTIAL_TEST_FAILURE_STATUS) {
        return credential_stage_from_remote_output(stdout).map_or(
            RunnerStage::EngineCredentialCheckpoint,
            RunnerStage::EngineCredential,
        );
    }
    if !stdout.is_empty() {
        return RunnerStage::RemoteExecution;
    }
    match code {
        Some(REMOTE_CONTRACT_FAILURE_STATUS) => RunnerStage::RemoteContract,
        Some(1 | 2) => RunnerStage::RemoteShell,
        Some(124 | 137) => RunnerStage::RemoteTimeout,
        Some(REMOTE_OUTPUT_TEST_FAILURE_STATUS) => RunnerStage::LocalOutputCheckpoint,
        Some(REMOTE_SUPERVISED_TEST_FAILURE_STATUS) => RunnerStage::SupervisedProducerCheckpoint,
        _ => RunnerStage::RemoteExecution,
    }
}

fn preflight_stage_for_remote_status(code: Option<i32>) -> RunnerStage {
    match code {
        Some(REMOTE_PREFLIGHT_IDENTITY_FAILURE_STATUS) => {
            RunnerStage::RemotePathPreflightRootIdentity
        }
        Some(REMOTE_PREFLIGHT_PROCESS_FAILURE_STATUS) => {
            RunnerStage::RemotePathPreflightProcessAbsence
        }
        Some(REMOTE_PREFLIGHT_PATH_FAILURE_STATUS) => RunnerStage::RemotePathPreflightPathAbsence,
        _ => RunnerStage::RemotePathPreflightUnexpectedStatus,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AndroidTargetSpec {
    label: &'static str,
    required_abi: &'static str,
    rust_target: &'static str,
    clang_target: &'static str,
    cargo_linker_env: &'static str,
    cc_env: &'static str,
    rustflags_env: &'static str,
    validate_aarch64_elf: bool,
}

const ARM64_TARGET: AndroidTargetSpec = AndroidTargetSpec {
    label: "ARM64",
    required_abi: "arm64-v8a",
    rust_target: ANDROID_TARGET,
    clang_target: ANDROID_TARGET,
    cargo_linker_env: "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER",
    cc_env: "CC_aarch64_linux_android",
    rustflags_env: ANDROID_TARGET_RUSTFLAGS_ENV,
    validate_aarch64_elf: true,
};

const X86_64_TARGET: AndroidTargetSpec = AndroidTargetSpec {
    label: "x86_64",
    required_abi: "x86_64",
    rust_target: "x86_64-linux-android",
    clang_target: "x86_64-linux-android",
    cargo_linker_env: "CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER",
    cc_env: "CC_x86_64_linux_android",
    rustflags_env: "CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS",
    validate_aarch64_elf: false,
};

fn target_from_device(
    abi_list: &str,
    kernel_arch: &str,
) -> Result<&'static AndroidTargetSpec, String> {
    let target = match kernel_arch {
        "aarch64" => &ARM64_TARGET,
        "x86_64" => &X86_64_TARGET,
        _ => {
            return Err(format!(
                "Android kernel architecture {kernel_arch:?} is unsupported; expected aarch64 or x86_64"
            ));
        }
    };
    if !abi_list
        .split(',')
        .any(|candidate| candidate.trim() == target.required_abi)
    {
        return Err(format!(
            "Android kernel architecture {kernel_arch:?} requires ABI {} in ro.product.cpu.abilist={abi_list:?}",
            target.required_abi,
        ));
    }
    Ok(target)
}

fn validate_serial(serial: &str) -> Result<(), String> {
    if serial.is_empty()
        || serial.len() > 128
        || !serial
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-'))
    {
        return Err(
            "--serial must be 1..=128 ASCII letters, digits, '.', ':', '_', or '-'".to_owned(),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct DeviceProfile {
    target: &'static AndroidTargetSpec,
    model: String,
    sdk: u32,
    abi_list: String,
    kernel_arch: String,
    kernel_release: String,
    build_fingerprint: String,
    boot_id: String,
    shell_uid: u32,
    shell_gid: u32,
}

impl DeviceProfile {
    pub(super) const fn target_rust_target(&self) -> &'static str {
        self.target.rust_target
    }

    pub(super) const fn shell_uid(&self) -> u32 {
        self.shell_uid
    }

    pub(super) const fn shell_gid(&self) -> u32 {
        self.shell_gid
    }

    #[cfg(test)]
    pub(super) fn redact_sensitive_diagnostic(&self, text: &str) -> String {
        [
            (self.model.as_str(), "<redacted-model>"),
            (self.abi_list.as_str(), "<redacted-abi-list>"),
            (self.kernel_arch.as_str(), "<redacted-kernel-arch>"),
            (self.kernel_release.as_str(), "<redacted-kernel-release>"),
            (
                self.build_fingerprint.as_str(),
                "<redacted-build-fingerprint>",
            ),
            (self.boot_id.as_str(), "<redacted-boot-id>"),
        ]
        .into_iter()
        .fold(text.to_owned(), |redacted, (value, replacement)| {
            redacted.replace(value, replacement)
        })
    }
}

#[cfg(test)]
pub(super) fn arm64_test_device_profile() -> DeviceProfile {
    DeviceProfile {
        target: &ARM64_TARGET,
        model: "SM-S9180".to_owned(),
        sdk: 36,
        abi_list: "arm64-v8a,armeabi-v7a".to_owned(),
        kernel_arch: "aarch64".to_owned(),
        kernel_release: "5.15.211-Qkernel".to_owned(),
        build_fingerprint: "samsung/dm3qzhx/dm3q:16/test/release-keys".to_owned(),
        boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
        shell_uid: 2000,
        shell_gid: 2000,
    }
}

pub(super) fn verify_device(options: &Options) -> Result<DeviceProfile, String> {
    let state = adb_text(options, &["-s", &options.serial, "get-state"])?;
    if state != "device" {
        return Err(format!(
            "ADB serial {} is not ready: state={state:?}",
            options.serial
        ));
    }
    let abi_list = adb_text(
        options,
        &[
            "-s",
            &options.serial,
            "shell",
            "getprop",
            "ro.product.cpu.abilist",
        ],
    )?;
    validate_profile_text("ABI list", &abi_list, 1024)?;
    let kernel_arch = adb_text(options, &["-s", &options.serial, "shell", "uname", "-m"])?;
    validate_profile_text("kernel architecture", &kernel_arch, 64)?;
    let target = target_from_device(&abi_list, &kernel_arch)?;
    let kernel_release = adb_text(options, &["-s", &options.serial, "shell", "uname", "-r"])?;
    validate_profile_text("kernel release", &kernel_release, 256)?;
    android_kernel::validate_supported_release(&kernel_release)?;
    let sdk_text = adb_text(
        options,
        &[
            "-s",
            &options.serial,
            "shell",
            "getprop",
            "ro.build.version.sdk",
        ],
    )?;
    let sdk = sdk_text
        .parse::<u32>()
        .map_err(|error| format!("parse Android SDK {sdk_text:?}: {error}"))?;
    if sdk < MINIMUM_ANDROID_SDK {
        return Err(format!(
            "ADB serial {} runs SDK {sdk}, below development lane minimum {MINIMUM_ANDROID_SDK}",
            options.serial
        ));
    }
    let root = adb_text(options, &["-s", &options.serial, "shell", "su", "-c", "id"])?;
    if !root
        .split_whitespace()
        .any(|field| field.starts_with("uid=0("))
    {
        return Err(format!(
            "ADB serial {} did not provide Magisk/root UID 0: {root:?}",
            options.serial
        ));
    }
    let model = adb_text(
        options,
        &[
            "-s",
            &options.serial,
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
            &options.serial,
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
            &options.serial,
            "shell",
            "cat",
            "/proc/sys/kernel/random/boot_id",
        ],
    )?;
    if !valid_boot_id(&boot_id) {
        return Err(format!(
            "ADB serial {} returned non-canonical boot_id {boot_id:?}",
            options.serial
        ));
    }
    let shell_uid = parse_canonical_u32(
        &adb_text(
            options,
            &["-s", &options.serial, "shell", "/system/bin/id", "-u"],
        )?,
        "ADB shell UID",
    )?;
    let shell_gid = parse_canonical_u32(
        &adb_text(
            options,
            &["-s", &options.serial, "shell", "/system/bin/id", "-g"],
        )?,
        "ADB shell GID",
    )?;
    if shell_gid == 0 {
        return Err(
            "ADB shell primary GID must be nonzero for credential qualification".to_owned(),
        );
    }
    Ok(DeviceProfile {
        target,
        model,
        sdk,
        abi_list,
        kernel_arch,
        kernel_release,
        build_fingerprint,
        boot_id,
        shell_uid,
        shell_gid,
    })
}

fn parse_canonical_u32(value: &str, field: &str) -> Result<u32, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{field} is not a canonical unsigned decimal"));
    }
    value
        .parse::<u32>()
        .map_err(|_| format!("{field} exceeds the u32 domain"))
}

fn validate_profile_text(label: &str, value: &str, maximum_bytes: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.chars().any(|character| character.is_control())
    {
        return Err(format!(
            "Android {label} must be one non-empty control-free line of at most {maximum_bytes} bytes, got {value:?}"
        ));
    }
    Ok(())
}

fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

pub(super) fn revalidate_device(
    options: &Options,
    expected: &DeviceProfile,
    boundary: &str,
) -> Result<(), String> {
    let actual = verify_device(options)
        .map_err(|error| format!("revalidate exact Android device {boundary}: {error}"))?;
    if actual == *expected {
        Ok(())
    } else {
        Err(format!("exact Android target identity changed {boundary}"))
    }
}

fn android_test_build_command(linker: &Path, target: &AndroidTargetSpec) -> Command {
    let mut command = Command::new("cargo");
    command.args([
        "test",
        "-p",
        "fluxd",
        "--lib",
        "--release",
        "--target",
        target.rust_target,
        "--no-run",
        "--message-format=json-render-diagnostics",
    ]);
    configure_android_build_environment(&mut command, linker, target);
    command
}

fn android_credential_probe_build_command(linker: &Path, target: &AndroidTargetSpec) -> Command {
    let mut command = Command::new("cargo");
    command.args([
        "build",
        "-p",
        "flux-platform",
        "--bin",
        CREDENTIAL_PROBE_TARGET_NAME,
        "--release",
        "--target",
        target.rust_target,
        "--message-format=json-render-diagnostics",
    ]);
    configure_android_build_environment(&mut command, linker, target);
    command
}

fn configure_android_build_environment(
    command: &mut Command,
    linker: &Path,
    target: &AndroidTargetSpec,
) {
    command.env(target.cargo_linker_env, linker.as_os_str());
    command.env(target.cc_env, linker.as_os_str());
    command.env(target.rustflags_env, ANDROID_RUSTFLAGS);
    command.env("TMPDIR", LINUX_ANDROID_HOST_BUILD_TMPDIR);
}

fn build_artifacts(
    linker: &Path,
    target: &AndroidTargetSpec,
) -> Result<AndroidCanaryArtifactPaths, String> {
    let test = build_cargo_artifact(
        android_test_build_command(linker, target),
        target,
        "test ELF",
        test_artifact_from_cargo_messages,
    )?;
    let credential_probe = build_cargo_artifact(
        android_credential_probe_build_command(linker, target),
        target,
        "credential-probe ELF",
        credential_probe_artifact_from_cargo_messages,
    )?;
    Ok(AndroidCanaryArtifactPaths {
        test,
        credential_probe,
        producer: None,
    })
}

fn build_cargo_artifact(
    mut command: Command,
    target: &AndroidTargetSpec,
    description: &str,
    select: fn(&[u8]) -> Result<PathBuf, String>,
) -> Result<PathBuf, String> {
    let rust_target = target.rust_target;
    let output = command_output_bounded(
        &mut command,
        None,
        CARGO_BUILD_TIMEOUT,
        MAX_CARGO_CAPTURE_BYTES,
        &format!("cross-build {rust_target} {description}"),
    )?;
    if !output.stderr.is_empty() {
        std::io::stderr()
            .write_all(&output.stderr)
            .map_err(|error| format!("forward Cargo diagnostics: {error}"))?;
    }
    if !output.status.success() {
        return Err(format!(
            "cross-build of {rust_target} {description} exited with {}: {}",
            output.status,
            bounded_diagnostic(&output.stdout)
        ));
    }
    let artifact = select(&output.stdout)?;
    if !artifact.is_file() {
        return Err(format!(
            "Cargo reported Android {description} {}, but it is missing",
            artifact.display()
        ));
    }
    Ok(artifact)
}

fn test_artifact_from_cargo_messages(messages: &[u8]) -> Result<PathBuf, String> {
    exact_artifact_from_cargo_messages(messages, "fluxd", "lib", true, "fluxd library-test")
}

fn credential_probe_artifact_from_cargo_messages(messages: &[u8]) -> Result<PathBuf, String> {
    exact_artifact_from_cargo_messages(
        messages,
        CREDENTIAL_PROBE_TARGET_NAME,
        "bin",
        false,
        "credential-probe binary",
    )
}

fn exact_artifact_from_cargo_messages(
    messages: &[u8],
    target_name: &str,
    target_kind: &str,
    test_profile: bool,
    description: &str,
) -> Result<PathBuf, String> {
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
            || message.pointer("/target/name").and_then(Value::as_str) != Some(target_name)
            || message
                .pointer("/target/kind")
                .and_then(Value::as_array)
                .is_none_or(|kinds| kinds.len() != 1 || kinds[0].as_str() != Some(target_kind))
            || message.pointer("/profile/test").and_then(Value::as_bool) != Some(test_profile)
        {
            continue;
        }
        if let Some(executable) = message.get("executable").and_then(Value::as_str) {
            artifacts.insert(PathBuf::from(executable));
        }
    }
    let artifacts = artifacts.into_iter().collect::<Vec<_>>();
    let [artifact] = artifacts.as_slice() else {
        return Err(format!(
            "Cargo JSON did not report exactly one {description} executable"
        ));
    };
    Ok(artifact.clone())
}

fn preflight_remote_directory(
    options: &Options,
    expected_device: &DeviceProfile,
    remote: &OwnedRemoteDirectory,
) -> Result<(), String> {
    if !remote.matches_spec() {
        return Err(runner_stage_error(RunnerStage::RemotePathPreflightContract));
    }
    at_runner_stage(
        RunnerStage::RemotePathPreflightIdentityBefore,
        revalidate_device(options, expected_device, "before remote-path preflight"),
    )?;
    let output = at_runner_stage(
        RunnerStage::RemotePathPreflightTransport,
        adb_root_shell_output(
            options,
            preflight_remote_directory_script(remote, expected_device).as_bytes(),
            ADB_QUERY_TIMEOUT,
            "prove generated Android canary path absent",
        ),
    )?;
    let output = at_runner_stage(
        RunnerStage::RemotePathPreflightNormalization,
        normalize_adb_shell_output(output),
    )?;
    if !output.status.success() {
        return Err(runner_stage_error(preflight_stage_for_remote_status(
            output.status.code(),
        )));
    }
    if !output.stdout.is_empty() || !output.stderr.is_empty() {
        return Err(runner_stage_error(
            RunnerStage::RemotePathPreflightUnexpectedOutput,
        ));
    }
    at_runner_stage(
        RunnerStage::RemotePathPreflightIdentityAfter,
        revalidate_device(options, expected_device, "after remote-path preflight"),
    )
}

fn create_remote_directory(
    options: &Options,
    expected_device: &DeviceProfile,
    remote: &OwnedRemoteDirectory,
) -> Result<FilesystemIdentity, String> {
    let output = normalize_adb_shell_output(adb_root_shell_output(
        options,
        create_remote_directory_script(remote, expected_device).as_bytes(),
        ADB_QUERY_TIMEOUT,
        "create exact owner-marked Android canary directory",
    )?)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("owner-marked Android canary directory creation failed".to_owned());
    }
    parse_directory_identity(
        &output.stdout,
        REMOTE_DIRECTORY_IDENTITY_BEGIN,
        REMOTE_DIRECTORY_IDENTITY_END,
        "directory_identity",
        "Android canary directory",
    )
}

fn push_and_execute(
    options: &Options,
    artifacts: &AndroidCanaryArtifactPaths,
    artifact_identities: &AndroidCanaryArtifactIdentities,
    expected_device: &DeviceProfile,
    remote: &OwnedRemoteDirectory,
) -> Result<(), String> {
    if remote.identity().is_none() {
        return Err("Android canary directory identity is unavailable before execution".to_owned());
    }
    at_runner_stage(
        RunnerStage::RemoteExecutionPreflight,
        artifact_identities.verify_paths(artifacts),
    )?;
    at_runner_stage(
        RunnerStage::RemoteExecutionPreflight,
        revalidate_device(options, expected_device, "before remote push"),
    )?;
    let preflight = at_runner_stage(
        RunnerStage::RemoteExecutionPreflight,
        adb_root_shell_output(
            options,
            execution_preflight_script(remote, expected_device).as_bytes(),
            ADB_QUERY_TIMEOUT,
            "validate exact owner-marked Android canary directory before push",
        )
        .and_then(normalize_adb_shell_output),
    )?;
    if !preflight.status.success() || !preflight.stdout.is_empty() || !preflight.stderr.is_empty() {
        return Err(runner_stage_error(RunnerStage::RemoteExecutionPreflight));
    }
    let remote_test = format!("{}/{REMOTE_TEST_BINARY_NAME}", remote.path());
    at_runner_stage(
        RunnerStage::RemoteTestArtifactPush,
        revalidate_device(
            options,
            expected_device,
            "immediately before canary-test push",
        ),
    )?;
    at_runner_stage(
        RunnerStage::RemoteTestArtifactPush,
        push_artifact(
            options,
            &artifacts.test,
            &artifact_identities.test,
            &remote_test,
            "Android canary test ELF",
        ),
    )?;
    at_runner_stage(
        RunnerStage::RemoteTestArtifactPush,
        revalidate_device(options, expected_device, "after canary-test push"),
    )?;

    let remote_probe = format!("{}/{REMOTE_CREDENTIAL_PROBE_BINARY_NAME}", remote.path());
    at_runner_stage(
        RunnerStage::RemoteCredentialArtifactPush,
        revalidate_device(
            options,
            expected_device,
            "immediately before credential-probe push",
        ),
    )?;
    at_runner_stage(
        RunnerStage::RemoteCredentialArtifactPush,
        push_artifact(
            options,
            &artifacts.credential_probe,
            &artifact_identities.credential_probe,
            &remote_probe,
            "Android credential-probe ELF",
        ),
    )?;
    at_runner_stage(
        RunnerStage::RemoteCredentialArtifactPush,
        revalidate_device(options, expected_device, "after credential-probe push"),
    )?;

    if let (Some(producer), Some(identity)) = (
        artifacts.producer.as_deref(),
        artifact_identities.producer.as_ref(),
    ) {
        let remote_producer = format!("{}/{REMOTE_PRODUCER_BINARY_NAME}", remote.path());
        at_runner_stage(
            RunnerStage::RemoteProducerArtifactPush,
            revalidate_device(options, expected_device, "immediately before producer push"),
        )?;
        at_runner_stage(
            RunnerStage::RemoteProducerArtifactPush,
            push_artifact(
                options,
                producer,
                identity,
                &remote_producer,
                "manifest-bound Android Sing-Box producer",
            ),
        )?;
        at_runner_stage(
            RunnerStage::RemoteProducerArtifactPush,
            revalidate_device(options, expected_device, "after producer push"),
        )?;
    }

    let script = at_runner_stage(
        RunnerStage::RemoteCheckpointTransport,
        remote_script(remote, artifact_identities, expected_device),
    )?;
    let output = at_runner_stage(
        RunnerStage::RemoteCheckpointTransport,
        adb_root_shell_output(
            options,
            script.as_bytes(),
            if artifact_identities.producer.is_some() {
                ADB_SUPERVISED_EXEC_TIMEOUT
            } else {
                ADB_EXEC_TIMEOUT
            },
            "run rooted Android checkpoint shell",
        )
        .and_then(normalize_adb_shell_output),
    )?;
    if output.status.success() && output.stdout.is_empty() && output.stderr.is_empty() {
        Ok(())
    } else {
        Err(runner_stage_error(checkpoint_stage_for_remote_output(
            output.status.code(),
            &output.stdout,
            &output.stderr,
        )))
    }
}

pub(super) fn push_artifact(
    options: &Options,
    artifact: &Path,
    identity: &AndroidArtifactIdentity,
    remote_path: &str,
    description: &str,
) -> Result<(), String> {
    identity.verify_file(artifact, &format!("exact {description} before ADB push"))?;
    let adb_artifact = artifact_path_for_adb(options, artifact)?;
    let mut push = Command::new(&options.adb);
    push.args(["-s", &options.serial, "push"])
        .arg(adb_artifact)
        .arg(remote_path);
    let output = command_output_bounded(
        &mut push,
        None,
        ADB_PUSH_TIMEOUT,
        MAX_ADB_CAPTURE_BYTES,
        &format!("push {description}"),
    )?;
    if !output.status.success() {
        return Err(format!("ADB push of the exact {description} failed"));
    }
    Ok(())
}

pub(super) fn artifact_path_for_adb(
    options: &Options,
    artifact: &Path,
) -> Result<OsString, String> {
    if !uses_windows_adb(&options.adb) {
        return Ok(artifact.as_os_str().to_os_string());
    }
    let mut command = Command::new("wslpath");
    command.arg("-w").arg(artifact);
    let output = command_output_bounded(
        &mut command,
        None,
        ADB_QUERY_TIMEOUT,
        MAX_ADB_CAPTURE_BYTES,
        "translate Android test ELF for Windows ADB",
    )?;
    if !output.status.success() {
        return Err(format!(
            "wslpath -w {} exited with {}: stdout={} stderr={}",
            artifact.display(),
            output.status,
            bounded_diagnostic(&output.stdout),
            bounded_diagnostic(&output.stderr)
        ));
    }
    let translated = String::from_utf8(output.stdout)
        .map_err(|error| format!("wslpath returned non-UTF-8 output: {error}"))?;
    let translated = translated.trim();
    if translated.is_empty() {
        return Err("wslpath returned an empty Windows artifact path".to_owned());
    }
    Ok(OsString::from(translated))
}

fn uses_windows_adb(adb: &OsString) -> bool {
    adb.to_string_lossy().to_ascii_lowercase().ends_with(".exe")
}

fn credential_stage_shell_functions() -> String {
    let stages = EngineCredentialProbeStage::all()
        .map(|stage| stage.as_str())
        .collect::<Vec<_>>();
    let accepted_pattern = stages
        .iter()
        .map(|stage| shell_single_quote(stage))
        .collect::<Vec<_>>()
        .join("|");
    let maximum_frame_bytes = stages
        .iter()
        .map(|stage| stage.len().saturating_add(1))
        .max()
        .expect("credential probe stage catalog is nonempty");
    format!(
        "read_credential_stage() {{\n\
           CREDENTIAL_STAGE=\n\
           if [ -f \"$CREDENTIAL_STAGE_RECEIPT\" ] && [ ! -L \"$CREDENTIAL_STAGE_RECEIPT\" ]; then\n\
             CREDENTIAL_STAGE_SIZE=$(wc -c <\"$CREDENTIAL_STAGE_RECEIPT\") || return 1\n\
             CREDENTIAL_STAGE_LINES=$(wc -l <\"$CREDENTIAL_STAGE_RECEIPT\") || return 1\n\
             [ \"$CREDENTIAL_STAGE_SIZE\" -ge 2 ] &&\n\
             [ \"$CREDENTIAL_STAGE_SIZE\" -le {maximum_frame_bytes} ] &&\n\
             [ \"$CREDENTIAL_STAGE_LINES\" -eq 1 ] || return 1\n\
             CREDENTIAL_STAGE=$(cat \"$CREDENTIAL_STAGE_RECEIPT\") || return 1\n\
           else\n\
             return 1\n\
           fi\n\
           case \"$CREDENTIAL_STAGE\" in\n\
             {accepted_pattern}) printf '%s\\n' \"$CREDENTIAL_STAGE\" ;;\n\
             *) return 1 ;;\n\
           esac\n\
         }}\n"
    )
}

fn remote_script(
    remote: &OwnedRemoteDirectory,
    artifacts: &AndroidCanaryArtifactIdentities,
    expected_device: &DeviceProfile,
) -> Result<String, String> {
    if remote.identity().is_none() {
        return Err("Android canary directory identity is unavailable before execution".to_owned());
    }
    if expected_device.shell_gid == 0 {
        return Err("Android credential probe requires a nonzero device shell GID".to_owned());
    }
    let output_test = shell_single_quote(LINUX_OUTPUT_TPROXY_CANARY_TEST);
    let credential_test = shell_single_quote(ANDROID_ENGINE_CREDENTIAL_CANARY_TEST);
    let credential_stage_receipt_name =
        shell_single_quote(ENGINE_CREDENTIAL_PROBE_STAGE_RECEIPT_NAME);
    let credential_stage_shell_functions = credential_stage_shell_functions();
    let final_credential_stage =
        shell_single_quote(&EngineCredentialProbeStage::ParentDeathContainment.as_str());
    let credential_stage_output_prefix = shell_single_quote(REMOTE_CREDENTIAL_STAGE_OUTPUT_PREFIX);
    let expected_test_sha256 = shell_single_quote(artifacts.test.sha256());
    let expected_test_size = artifacts.test.size();
    let expected_probe_sha256 = shell_single_quote(artifacts.credential_probe.sha256());
    let expected_probe_size = artifacts.credential_probe.size();
    let expected_probe_gid = expected_device.shell_gid;
    let internal_envs = LINUX_CANARY_INTERNAL_ENVS.join(" ");
    let (producer_contract, producer_checkpoint) = match &artifacts.producer {
        Some(producer) => {
            let expected_sha256 = shell_single_quote(producer.sha256());
            let expected_size = producer.size();
            let test = shell_single_quote(ANDROID_SUPERVISED_PRODUCER_CANARY_TEST);
            (
                format!(
                    "[ -f \"$PRODUCER_BIN\" ] && [ ! -L \"$PRODUCER_BIN\" ]\n\
                     /system/bin/chmod 700 \"$PRODUCER_BIN\"\n\
                     [ \"$(/system/bin/stat -c '%a:%u:%g' \"$PRODUCER_BIN\")\" = '700:0:0' ]\n\
                     ACTUAL_PRODUCER_SHA256=$(/system/bin/sha256sum \"$PRODUCER_BIN\" | /system/bin/cut -d ' ' -f 1)\n\
                     [ \"$ACTUAL_PRODUCER_SHA256\" = {expected_sha256} ]\n\
                     [ \"$(/system/bin/stat -c '%s' \"$PRODUCER_BIN\")\" = '{expected_size}' ]\n"
                ),
                format!(
                    "PRODUCER_TEST={test}\n\
                     require_exact_test \"$PRODUCER_TEST\" \"$TMPDIR/producer-list\" || exit {REMOTE_CONTRACT_FAILURE_STATUS}\n\
                     export {REAL_PRODUCER_BINARY_ENV}=\"$PRODUCER_BIN\"\n\
                     if ! run_exact_test {REMOTE_SUPERVISED_TEST_TIMEOUT_SECONDS} \"$PRODUCER_TEST\" >/dev/null 2>&1; then\n\
                       exit {REMOTE_SUPERVISED_TEST_FAILURE_STATUS}\n\
                     fi\n\
                     unset {REAL_PRODUCER_BINARY_ENV}\n\
                     probe_process_absent\n"
                ),
            )
        }
        None => ("path_absent \"$PRODUCER_BIN\"\n".to_owned(), String::new()),
    };
    Ok(format!(
        "set -eu\n\
         umask 077\n\
         {}\
         TEST_BIN=\"$ROOT/{REMOTE_TEST_BINARY_NAME}\"\n\
         CREDENTIAL_PROBE=\"$ROOT/{REMOTE_CREDENTIAL_PROBE_BINARY_NAME}\"\n\
         PRODUCER_BIN=\"$ROOT/{REMOTE_PRODUCER_BINARY_NAME}\"\n\
         TMPDIR=\"$ROOT/tmp\"\n\
         CREDENTIAL_STAGE_RECEIPT=\"$TMPDIR\"/{credential_stage_receipt_name}\n\
         CREDENTIAL_FINAL_STAGE={final_credential_stage}\n\
         CREDENTIAL_STAGE_OUTPUT_PREFIX={credential_stage_output_prefix}\n\
         EXPECTED_TEST_SHA256={expected_test_sha256}\n\
         EXPECTED_TEST_SIZE='{expected_test_size}'\n\
         EXPECTED_PROBE_SHA256={expected_probe_sha256}\n\
         EXPECTED_PROBE_SIZE='{expected_probe_size}'\n\
         EXPECTED_PROBE_GID='{expected_probe_gid}'\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         trap remove_owned_root EXIT\n\
         trap 'exit {REMOTE_CONTRACT_FAILURE_STATUS}' HUP INT TERM\n\
         identity_matches\n\
         probe_process_absent\n\
         owned_root_matches\n\
         [ -f \"$TEST_BIN\" ] && [ ! -L \"$TEST_BIN\" ]\n\
         [ -f \"$CREDENTIAL_PROBE\" ] && [ ! -L \"$CREDENTIAL_PROBE\" ]\n\
         /system/bin/chown -R 0:0 \"$ROOT\"\n\
         /system/bin/chmod 700 \"$ROOT\" \"$TEST_BIN\" \"$CREDENTIAL_PROBE\"\n\
         {producer_contract}\
         owned_root_matches\n\
         [ \"$(/system/bin/stat -c '%a:%u:%g' \"$TEST_BIN\")\" = '700:0:0' ]\n\
         [ \"$(/system/bin/stat -c '%a:%u:%g' \"$CREDENTIAL_PROBE\")\" = '700:0:0' ]\n\
         ACTUAL_TEST_SHA256=$(/system/bin/sha256sum \"$TEST_BIN\" | /system/bin/cut -d ' ' -f 1)\n\
         [ \"$ACTUAL_TEST_SHA256\" = \"$EXPECTED_TEST_SHA256\" ]\n\
         [ \"$(/system/bin/stat -c '%s' \"$TEST_BIN\")\" = \"$EXPECTED_TEST_SIZE\" ]\n\
         ACTUAL_PROBE_SHA256=$(/system/bin/sha256sum \"$CREDENTIAL_PROBE\" | /system/bin/cut -d ' ' -f 1)\n\
         [ \"$ACTUAL_PROBE_SHA256\" = \"$EXPECTED_PROBE_SHA256\" ]\n\
         [ \"$(/system/bin/stat -c '%s' \"$CREDENTIAL_PROBE\")\" = \"$EXPECTED_PROBE_SIZE\" ]\n\
         /system/bin/mkdir \"$TMPDIR\"\n\
         /system/bin/chmod 700 \"$TMPDIR\"\n\
         export TMPDIR\n\
         unset {internal_envs}\n\
         export FLUX_LINUX_CANARY_REQUIRED=1\n\
         export FLUX_ENGINE_CREDENTIAL_PROBE_REQUIRED=1\n\
         export FLUX_ENGINE_CREDENTIAL_PROBE_PATH=\"$CREDENTIAL_PROBE\"\n\
         export FLUX_ENGINE_CREDENTIAL_PROBE_GID=\"$EXPECTED_PROBE_GID\"\n\
         OUTPUT_TEST={output_test}\n\
         CREDENTIAL_TEST={credential_test}\n\
         require_exact_test() {{\n\
           REQUIRED_TEST=$1\n\
           REQUIRED_LIST_FILE=$2\n\
           if ! \"$TEST_BIN\" --ignored --exact \"$REQUIRED_TEST\" --list >\"$REQUIRED_LIST_FILE\"; then\n\
             return 1\n\
           fi\n\
           LIST_OUTPUT=$(/system/bin/tr -d '\\r' <\"$REQUIRED_LIST_FILE\")\n\
           EXPECTED_LIST=$(printf '%s: test\\n\\n1 test, 0 benchmarks' \"$REQUIRED_TEST\")\n\
           [ \"$LIST_OUTPUT\" = \"$EXPECTED_LIST\" ]\n\
         }}\n\
         run_exact_test() {{\n\
           TEST_TIMEOUT=$1\n\
           REQUIRED_TEST=$2\n\
           /system/bin/timeout -k {REMOTE_TEST_KILL_GRACE_SECONDS} \"$TEST_TIMEOUT\" \"$TEST_BIN\" --ignored --exact \"$REQUIRED_TEST\" --nocapture --test-threads=1\n\
         }}\n\
         {credential_stage_shell_functions}\
         require_exact_test \"$OUTPUT_TEST\" \"$TMPDIR/output-list\" || exit {REMOTE_CONTRACT_FAILURE_STATUS}\n\
         require_exact_test \"$CREDENTIAL_TEST\" \"$TMPDIR/credential-list\" || exit {REMOTE_CONTRACT_FAILURE_STATUS}\n\
         if ! run_exact_test {REMOTE_CREDENTIAL_TEST_TIMEOUT_SECONDS} \"$CREDENTIAL_TEST\" >/dev/null 2>&1; then\n\
           CREDENTIAL_STAGE=$(read_credential_stage) || CREDENTIAL_STAGE=\n\
           printf '%s%s\\n' \"$CREDENTIAL_STAGE_OUTPUT_PREFIX\" \"$CREDENTIAL_STAGE\"\n\
           exit {REMOTE_CREDENTIAL_TEST_FAILURE_STATUS}\n\
         fi\n\
         CREDENTIAL_STAGE=$(read_credential_stage) || exit {REMOTE_CREDENTIAL_TEST_FAILURE_STATUS}\n\
         [ \"$CREDENTIAL_STAGE\" = \"$CREDENTIAL_FINAL_STAGE\" ] || exit {REMOTE_CREDENTIAL_TEST_FAILURE_STATUS}\n\
         probe_process_absent\n\
         if ! run_exact_test {REMOTE_OUTPUT_TEST_TIMEOUT_SECONDS} \"$OUTPUT_TEST\" >/dev/null 2>&1; then\n\
           exit {REMOTE_OUTPUT_TEST_FAILURE_STATUS}\n\
         fi\n\
         probe_process_absent\n\
         {producer_checkpoint}\
         remove_owned_root\n\
         path_absent \"$TEST_BIN\"\n\
         path_absent \"$CREDENTIAL_PROBE\"\n\
         path_absent \"$PRODUCER_BIN\"\n\
         path_absent \"$ROOT\"\n\
         identity_matches\n\
         trap - EXIT HUP INT TERM\n\
         exit 0\n",
        remote.shell_variables(expected_device.shell_uid, expected_device.shell_gid),
        device_identity_function(expected_device),
        process_absence_function(&REMOTE_PROCESS_NAMES),
        owned_root_functions(),
    ))
}

fn cleanup_remote_directory(
    options: &Options,
    expected_device: &DeviceProfile,
    remote: &OwnedRemoteDirectory,
) -> Result<(), String> {
    if !remote.matches_spec() {
        return Err("refusing cleanup for an invalid Android canary directory".to_owned());
    }
    revalidate_device(options, expected_device, "before remote cleanup")?;
    let removal = adb_root_shell_output(
        options,
        cleanup_script(remote, expected_device).as_bytes(),
        ADB_CLEANUP_TIMEOUT,
        "remove exact owner-marked Android canary directory",
    )
    .and_then(normalize_adb_shell_output);
    let absence = adb_root_shell_output(
        options,
        remote_absence_script(remote, expected_device).as_bytes(),
        ADB_CLEANUP_TIMEOUT,
        "independently prove Android canary process and path absence",
    )
    .and_then(normalize_adb_shell_output);
    revalidate_device(options, expected_device, "after remote cleanup proof")?;

    let removal = removal.map_err(|error| format!("remove owned canary directory: {error}"))?;
    if !removal.status.success() || !removal.stdout.is_empty() || !removal.stderr.is_empty() {
        return Err("owner-marked Android canary directory removal failed".to_owned());
    }
    let absence = absence.map_err(|error| format!("prove Android canary absence: {error}"))?;
    if !absence.status.success() || !absence.stdout.is_empty() || !absence.stderr.is_empty() {
        return Err("independent Android canary process and path absence proof failed".to_owned());
    }
    Ok(())
}

fn preflight_remote_directory_script(
    remote: &OwnedRemoteDirectory,
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
         identity_matches || exit {REMOTE_PREFLIGHT_IDENTITY_FAILURE_STATUS}\n\
         probe_process_absent || exit {REMOTE_PREFLIGHT_PROCESS_FAILURE_STATUS}\n\
         path_absent \"$ROOT\" || exit {REMOTE_PREFLIGHT_PATH_FAILURE_STATUS}\n",
        path_absence_function(),
        device_identity_function(expected_device),
        process_absence_function(&REMOTE_PROCESS_NAMES),
    )
}

fn create_remote_directory_script(
    remote: &OwnedRemoteDirectory,
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
           identity_matches || return {REMOTE_CONTRACT_FAILURE_STATUS}\n\
           probe_process_absent\n\
           [ -d \"$ROOT\" ] && [ ! -L \"$ROOT\" ]\n\
           [ \"$(/system/bin/stat -Lc '%d:%i' \"$ROOT\")\" = \"$CREATED_ID\" ]\n\
           /system/bin/rm -rf \"$ROOT\"\n\
         }}\n\
         trap cleanup_partial EXIT\n\
         trap 'exit {REMOTE_CONTRACT_FAILURE_STATUS}' HUP INT TERM\n\
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
        process_absence_function(&REMOTE_PROCESS_NAMES),
    )
}

fn execution_preflight_script(
    remote: &OwnedRemoteDirectory,
    expected_device: &DeviceProfile,
) -> String {
    format!(
        "set -eu\n\
         {}\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         identity_matches\n\
         probe_process_absent\n\
         owned_root_matches\n",
        remote.shell_variables(expected_device.shell_uid, expected_device.shell_gid),
        device_identity_function(expected_device),
        process_absence_function(&REMOTE_PROCESS_NAMES),
        owned_root_functions(),
    )
}

fn cleanup_script(remote: &OwnedRemoteDirectory, expected_device: &DeviceProfile) -> String {
    format!(
        "set -eu\n\
         {}\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         identity_matches\n\
         remove_owned_root\n",
        remote.shell_variables(expected_device.shell_uid, expected_device.shell_gid),
        device_identity_function(expected_device),
        process_absence_function(&REMOTE_PROCESS_NAMES),
        owned_root_functions(),
    )
}

fn remote_absence_script(remote: &OwnedRemoteDirectory, expected_device: &DeviceProfile) -> String {
    format!(
        "set -eu\n\
         ROOT={}\n\
         TEST_BIN=\"$ROOT/{REMOTE_TEST_BINARY_NAME}\"\n\
         CREDENTIAL_PROBE=\"$ROOT/{REMOTE_CREDENTIAL_PROBE_BINARY_NAME}\"\n\
         PRODUCER_BIN=\"$ROOT/{REMOTE_PRODUCER_BINARY_NAME}\"\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         {}\
         {}\
         {}\
         identity_matches\n\
         path_absent \"$TEST_BIN\"\n\
         path_absent \"$CREDENTIAL_PROBE\"\n\
         path_absent \"$PRODUCER_BIN\"\n\
         path_absent \"$ROOT\"\n\
         probe_process_absent\n",
        shell_single_quote(remote.path()),
        path_absence_function(),
        device_identity_function(expected_device),
        process_absence_function(&REMOTE_PROCESS_NAMES),
    )
}

pub(super) fn device_identity_function(expected_device: &DeviceProfile) -> String {
    let expected_boot_id = shell_single_quote(&expected_device.boot_id);
    let expected_fingerprint = shell_single_quote(&expected_device.build_fingerprint);
    let expected_arch = shell_single_quote(&expected_device.kernel_arch);
    let expected_kernel_release = shell_single_quote(&expected_device.kernel_release);
    format!(
        "EXPECTED_BOOT_ID={expected_boot_id}\n\
         EXPECTED_FINGERPRINT={expected_fingerprint}\n\
         EXPECTED_ARCH={expected_arch}\n\
         EXPECTED_KERNEL_RELEASE={expected_kernel_release}\n\
         identity_matches() {{\n\
           [ \"$(/system/bin/cat /proc/sys/kernel/random/boot_id)\" = \"$EXPECTED_BOOT_ID\" ] &&\n\
           [ \"$(/system/bin/getprop ro.build.fingerprint)\" = \"$EXPECTED_FINGERPRINT\" ] &&\n\
           [ \"$(/system/bin/uname -m)\" = \"$EXPECTED_ARCH\" ] &&\n\
           [ \"$(/system/bin/uname -r)\" = \"$EXPECTED_KERNEL_RELEASE\" ]\n\
         }}\n"
    )
}

pub(super) fn adb_text(options: &Options, arguments: &[&str]) -> Result<String, String> {
    let output = adb_output(options, arguments, ADB_QUERY_TIMEOUT)?;
    if !output.status.success() {
        return Err(format!(
            "{} exited with {}: stdout={} stderr={}",
            render_adb_command(options, arguments),
            output.status,
            bounded_diagnostic(&output.stdout),
            bounded_diagnostic(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map(|text| text.trim().to_owned())
        .map_err(|error| {
            format!(
                "{} produced non-UTF-8 output: {error}",
                render_adb_command(options, arguments)
            )
        })
}

pub(super) fn adb_success_with_timeout(
    options: &Options,
    arguments: &[&str],
    timeout: Duration,
) -> Result<(), String> {
    let output = adb_output(options, arguments, timeout)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} exited with {}: stdout={} stderr={}",
            render_adb_command(options, arguments),
            output.status,
            bounded_diagnostic(&output.stdout),
            bounded_diagnostic(&output.stderr)
        ))
    }
}

fn adb_output(options: &Options, arguments: &[&str], timeout: Duration) -> Result<Output, String> {
    let rendered = render_adb_command(options, arguments);
    let mut command = Command::new(&options.adb);
    command.args(arguments);
    command_output_bounded(
        &mut command,
        None,
        timeout,
        MAX_ADB_CAPTURE_BYTES,
        &rendered,
    )
}

type OutputReader = JoinHandle<std::io::Result<Vec<u8>>>;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    #[link_name = "kill"]
    fn c_kill(pid: i32, signal: i32) -> i32;
}

pub(super) fn adb_root_shell_output(
    options: &Options,
    script: &[u8],
    timeout: Duration,
    description: &str,
) -> Result<Output, String> {
    adb_root_shell_output_with_limit(options, script, timeout, MAX_ADB_CAPTURE_BYTES, description)
}

pub(super) fn adb_root_shell_output_with_limit(
    options: &Options,
    script: &[u8],
    timeout: Duration,
    capture_limit: usize,
    description: &str,
) -> Result<Output, String> {
    let mut command = Command::new(options.adb());
    command
        .args([
            "-s",
            options.serial(),
            "shell",
            "su",
            "-c",
            "/system/bin/sh",
        ])
        .stdin(Stdio::piped());
    command_output_bounded(
        &mut command,
        Some(script),
        timeout,
        capture_limit,
        description,
    )
}

pub(super) fn command_output_bounded(
    command: &mut Command,
    input: Option<&[u8]>,
    timeout: Duration,
    capture_limit: usize,
    description: &str,
) -> Result<Output, String> {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let deadline = started
        .checked_add(timeout)
        .ok_or_else(|| format!("timeout overflow while preparing {description}"))?;
    configure_host_process_group(command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to execute {description}: {error}"))?;

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return Err(terminate_without_capture(
                &mut child,
                format!("{description} omitted piped stdout after spawn"),
            ));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            drop(stdout);
            return Err(terminate_without_capture(
                &mut child,
                format!("{description} omitted piped stderr after spawn"),
            ));
        }
    };
    let stdout_reader = match spawn_output_reader(stdout, capture_limit, "stdout") {
        Ok(reader) => reader,
        Err(error) => {
            drop(stderr);
            return Err(terminate_without_capture(
                &mut child,
                format!("start bounded stdout drain for {description}: {error}"),
            ));
        }
    };
    let stderr_reader = match spawn_output_reader(stderr, capture_limit, "stderr") {
        Ok(reader) => reader,
        Err(error) => {
            let reap = kill_and_reap(&mut child);
            let stdout = join_output_reader_until(
                stdout_reader,
                "stdout",
                Instant::now() + HOST_OUTPUT_DRAIN_GRACE,
            );
            return Err(format!(
                "start bounded stderr drain for {description}: {error}; {}; {}",
                reap_summary(&reap),
                reader_summary("stdout", &stdout),
            ));
        }
    };

    if let Some(input) = input {
        let Some(mut child_stdin) = child.stdin.take() else {
            return Err(terminate_with_capture(
                &mut child,
                stdout_reader,
                stderr_reader,
                format!("{description} omitted piped stdin after spawn"),
            ));
        };
        if let Err(error) = child_stdin.write_all(input) {
            drop(child_stdin);
            return Err(terminate_with_capture(
                &mut child,
                stdout_reader,
                stderr_reader,
                format!("write stdin for {description}: {error}"),
            ));
        }
        drop(child_stdin);
    }

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                return Err(terminate_with_capture(
                    &mut child,
                    stdout_reader,
                    stderr_reader,
                    format!(
                        "{description} timed out after {} milliseconds",
                        timeout.as_millis()
                    ),
                ));
            }
            Ok(None) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                thread::sleep(HOST_POLL_INTERVAL.min(remaining));
            }
            Err(error) => {
                return Err(terminate_with_capture(
                    &mut child,
                    stdout_reader,
                    stderr_reader,
                    format!("poll {description}: {error}"),
                ));
            }
        }
    };

    match collect_output_until(stdout_reader, stderr_reader, deadline) {
        Ok((stdout, stderr)) => Ok(Output {
            status,
            stdout,
            stderr,
        }),
        Err(error) => {
            let reap = kill_and_reap(&mut child);
            Err(format!(
                "collect bounded output for {description}: {error}; {}",
                reap_summary(&reap)
            ))
        }
    }
}

fn spawn_output_reader<R>(
    reader: R,
    capture_limit: usize,
    stream_name: &str,
) -> std::io::Result<OutputReader>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(format!("flux-android-{stream_name}"))
        .spawn(move || drain_bounded(reader, capture_limit))
}

fn drain_bounded(mut reader: impl Read, capture_limit: usize) -> std::io::Result<Vec<u8>> {
    let mut captured = Vec::with_capacity(capture_limit.min(16 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(captured);
        }
        let retained = capture_limit.saturating_sub(captured.len()).min(read);
        captured.extend_from_slice(&buffer[..retained]);
    }
}

fn collect_output(
    stdout_reader: OutputReader,
    stderr_reader: OutputReader,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let stdout = join_output_reader(stdout_reader, "stdout");
    let stderr = join_output_reader(stderr_reader, "stderr");
    match (stdout, stderr) {
        (Ok(stdout), Ok(stderr)) => Ok((stdout, stderr)),
        (Err(stdout_error), Ok(_)) => Err(stdout_error),
        (Ok(_), Err(stderr_error)) => Err(stderr_error),
        (Err(stdout_error), Err(stderr_error)) => Err(format!("{stdout_error}; {stderr_error}")),
    }
}

fn collect_output_until(
    stdout_reader: OutputReader,
    stderr_reader: OutputReader,
    deadline: Instant,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    while !stdout_reader.is_finished() || !stderr_reader.is_finished() {
        let now = Instant::now();
        if now >= deadline {
            return Err("bounded stdout/stderr drain timed out after the child exited".to_owned());
        }
        thread::sleep(HOST_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
    collect_output(stdout_reader, stderr_reader)
}

fn join_output_reader_until(
    reader: OutputReader,
    stream_name: &str,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    while !reader.is_finished() {
        let now = Instant::now();
        if now >= deadline {
            return Err(format!("bounded {stream_name} drain timed out"));
        }
        thread::sleep(HOST_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
    join_output_reader(reader, stream_name)
}

fn join_output_reader(reader: OutputReader, stream_name: &str) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| format!("bounded {stream_name} drain panicked"))?
        .map_err(|error| format!("bounded {stream_name} drain failed: {error}"))
}

#[cfg(target_os = "linux")]
fn configure_host_process_group(command: &mut Command) {
    command.process_group(0);
}

#[cfg(not(target_os = "linux"))]
fn configure_host_process_group(_command: &mut Command) {}

#[cfg(target_os = "linux")]
fn kill_host_process_group(process_id: u32) -> Option<String> {
    const SIGKILL: i32 = 9;
    const ESRCH: i32 = 3;

    let process_group = match i32::try_from(process_id) {
        Ok(process_group) => process_group,
        Err(error) => return Some(format!("convert process group {process_id}: {error}")),
    };
    // SAFETY: the negative PID targets only the process group created for this command, and
    // `SIGKILL` has no borrowed memory or lifetime requirements.
    if unsafe { c_kill(-process_group, SIGKILL) } == 0 {
        return None;
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(ESRCH) {
        None
    } else {
        Some(format!("kill process group {process_group}: {error}"))
    }
}

#[cfg(not(target_os = "linux"))]
fn kill_host_process_group(_process_id: u32) -> Option<String> {
    None
}

fn kill_and_reap(child: &mut Child) -> Result<ExitStatus, String> {
    let group_kill_error = kill_host_process_group(child.id());
    let kill_error = child.kill().err();
    match child.wait() {
        Ok(status) => match group_kill_error {
            None => Ok(status),
            Some(error) => Err(format!(
                "{error}; direct child wait/reaped with {status} after fallback kill={kill_error:?}"
            )),
        },
        Err(wait_error) => {
            let group_detail = group_kill_error
                .map(|error| format!("{error}; "))
                .unwrap_or_default();
            let kill_detail = kill_error
                .map(|error| format!("kill failed: {error}; "))
                .unwrap_or_default();
            Err(format!(
                "{group_detail}{kill_detail}wait/reap failed: {wait_error}"
            ))
        }
    }
}

fn terminate_without_capture(child: &mut Child, cause: String) -> String {
    let reap = kill_and_reap(child);
    format!("{cause}; {}", reap_summary(&reap))
}

fn terminate_with_capture(
    child: &mut Child,
    stdout_reader: OutputReader,
    stderr_reader: OutputReader,
    cause: String,
) -> String {
    let reap = kill_and_reap(child);
    let output = collect_output_until(
        stdout_reader,
        stderr_reader,
        Instant::now() + HOST_OUTPUT_DRAIN_GRACE,
    );
    match output {
        Ok((stdout, stderr)) => format!(
            "{cause}; {}; stdout={} stderr={}",
            reap_summary(&reap),
            bounded_diagnostic(&stdout),
            bounded_diagnostic(&stderr),
        ),
        Err(error) => format!(
            "{cause}; {}; output collection also failed: {error}",
            reap_summary(&reap)
        ),
    }
}

fn reap_summary(reap: &Result<ExitStatus, String>) -> String {
    match reap {
        Ok(status) => format!("child killed and wait/reaped with {status}"),
        Err(error) => format!("child termination failed: {error}"),
    }
}

fn reader_summary(stream_name: &str, output: &Result<Vec<u8>, String>) -> String {
    match output {
        Ok(bytes) => format!("{stream_name}={}", bounded_diagnostic(bytes)),
        Err(error) => format!("{stream_name} collection failed: {error}"),
    }
}

fn render_adb_command(options: &Options, arguments: &[&str]) -> String {
    let mut rendered = Vec::with_capacity(arguments.len());
    let mut redact_next = None;
    for argument in arguments {
        if let Some(label) = redact_next.take() {
            rendered.push(label);
            continue;
        }
        rendered.push(*argument);
        redact_next = match *argument {
            "-s" => Some("<redacted-serial>"),
            "-c" => Some("<redacted-shell-command>"),
            _ => None,
        };
    }
    format!("{} {}", options.adb.to_string_lossy(), rendered.join(" "))
}

pub(super) fn forward_output(output: &Output) -> Result<(), String> {
    std::io::stdout()
        .write_all(&output.stdout)
        .and_then(|()| std::io::stderr().write_all(&output.stderr))
        .map_err(|error| format!("forward ADB output: {error}"))
}

pub(super) fn bounded_diagnostic(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_DIAGNOSTIC_BYTES);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_device_profile() -> DeviceProfile {
        DeviceProfile {
            target: &X86_64_TARGET,
            model: "Windows Subsystem for Android".to_owned(),
            sdk: 33,
            abi_list: "x86_64,arm64-v8a".to_owned(),
            kernel_arch: "x86_64".to_owned(),
            kernel_release: "5.15.104-wsa".to_owned(),
            build_fingerprint: "flux/wsa/device:13/test-keys".to_owned(),
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            shell_uid: 2000,
            shell_gid: 2000,
        }
    }

    fn expected_remote_directory() -> OwnedRemoteDirectory {
        let mut remote = REMOTE_DIRECTORY_SPEC
            .directory_for_token(&"a1".repeat(32), "Android canary directory")
            .expect("remote token");
        remote
            .bind_identity(FilesystemIdentity::new(253, 91_337).expect("filesystem identity"))
            .expect("bind filesystem identity");
        remote
    }

    #[test]
    fn architecture_requires_kernel_and_abi_agreement() {
        assert_eq!(
            target_from_device("arm64-v8a,armeabi-v7a", "aarch64").expect("ARM64 target"),
            &ARM64_TARGET
        );
        assert_eq!(
            target_from_device("x86_64,arm64-v8a", "x86_64").expect("x86_64 target"),
            &X86_64_TARGET
        );
        assert!(target_from_device("x86_64", "aarch64").is_err());
        assert!(target_from_device("arm64-v8a", "riscv64").is_err());
    }

    #[test]
    fn options_require_one_explicit_bounded_serial() {
        let options = parse_options(&[
            OsString::from("--serial"),
            OsString::from("127.0.0.1:58526"),
            OsString::from("--adb"),
            OsString::from("custom-adb"),
        ])
        .expect("valid options");
        assert_eq!(options.serial, "127.0.0.1:58526");
        assert_eq!(options.adb, OsString::from("custom-adb"));
        assert_eq!(options.producer, None);
        let with_producer = parse_options(&[
            OsString::from("--serial"),
            OsString::from("device"),
            OsString::from("--producer"),
            OsString::from("/tmp/sing-box"),
        ])
        .expect("producer qualification options");
        assert_eq!(with_producer.producer, Some(PathBuf::from("/tmp/sing-box")));
        assert!(parse_options(&[]).is_err());
        assert!(
            parse_options(&[OsString::from("--serial"), OsString::from("unsafe serial"),]).is_err()
        );
        assert!(
            parse_options(&[
                OsString::from("--serial"),
                OsString::from("device"),
                OsString::from("--producer"),
                OsString::from("relative/sing-box"),
            ])
            .is_err()
        );
    }

    #[test]
    fn cargo_json_selects_both_exact_artifacts() {
        let test_messages = br#"{"reason":"compiler-artifact","target":{"name":"fluxd","kind":["lib"]},"profile":{"test":true},"executable":"/tmp/fluxd-test"}
{"reason":"build-finished","success":true}
"#;
        assert_eq!(
            test_artifact_from_cargo_messages(test_messages).expect("one test artifact"),
            PathBuf::from("/tmp/fluxd-test")
        );
        let probe_messages = br#"{"reason":"compiler-artifact","target":{"name":"flux-engine-credential-probe","kind":["bin"]},"profile":{"test":false},"executable":"/tmp/flux-engine-credential-probe"}
{"reason":"build-finished","success":true}
"#;
        assert_eq!(
            credential_probe_artifact_from_cargo_messages(probe_messages)
                .expect("one credential-probe artifact"),
            PathBuf::from("/tmp/flux-engine-credential-probe")
        );
        assert!(test_artifact_from_cargo_messages(b"{}").is_err());
        assert!(credential_probe_artifact_from_cargo_messages(test_messages).is_err());
        assert!(test_artifact_from_cargo_messages(probe_messages).is_err());
    }

    #[test]
    fn both_android_builds_use_exact_release_targets_and_matching_pinned_compilers() {
        for target in [&ARM64_TARGET, &X86_64_TARGET] {
            let linker_path = format!("/ndk/toolchains/llvm/bin/{}31-clang", target.clang_target);
            let linker = Path::new(&linker_path);
            let commands = [
                (
                    android_test_build_command(linker, target),
                    vec![
                        "test",
                        "-p",
                        "fluxd",
                        "--lib",
                        "--release",
                        "--target",
                        target.rust_target,
                        "--no-run",
                        "--message-format=json-render-diagnostics",
                    ],
                ),
                (
                    android_credential_probe_build_command(linker, target),
                    vec![
                        "build",
                        "-p",
                        "flux-platform",
                        "--bin",
                        CREDENTIAL_PROBE_TARGET_NAME,
                        "--release",
                        "--target",
                        target.rust_target,
                        "--message-format=json-render-diagnostics",
                    ],
                ),
            ];
            for (command, expected_arguments) in commands {
                let environment = command
                    .get_envs()
                    .collect::<std::collections::BTreeMap<_, _>>();
                let arguments = command
                    .get_args()
                    .map(|argument| argument.to_string_lossy().into_owned())
                    .collect::<Vec<_>>();

                assert_eq!(arguments, expected_arguments);
                assert_eq!(
                    environment.get(std::ffi::OsStr::new(target.cargo_linker_env)),
                    Some(&Some(linker.as_os_str()))
                );
                assert_eq!(
                    environment.get(std::ffi::OsStr::new(target.cc_env)),
                    Some(&Some(linker.as_os_str()))
                );
                assert_eq!(
                    environment.get(std::ffi::OsStr::new(target.rustflags_env)),
                    Some(&Some(std::ffi::OsStr::new(ANDROID_RUSTFLAGS)))
                );
                assert_eq!(
                    environment.get(std::ffi::OsStr::new("TMPDIR")),
                    Some(&Some(std::ffi::OsStr::new(LINUX_ANDROID_HOST_BUILD_TMPDIR)))
                );
            }
        }
        assert!(ANDROID_RUSTFLAGS.contains("max-page-size=16384"));
        assert!(ANDROID_RUSTFLAGS.contains("common-page-size=16384"));
    }

    #[test]
    fn boot_id_requires_uuid_like_canonical_shape() {
        assert!(valid_boot_id("01234567-89ab-cdef-0123-456789abcdef"));
        assert!(valid_boot_id("01234567-89AB-CDEF-0123-456789ABCDEF"));
        assert!(!valid_boot_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_boot_id("01234567-89ab-cdef-0123-456789abcdeg"));
        assert!(!valid_boot_id("01234567-89ab-cdef-0123-456789abcdef\n"));
    }

    #[test]
    fn timeout_constants_leave_remote_and_cleanup_grace() {
        assert_eq!(ADB_QUERY_TIMEOUT, Duration::from_secs(15));
        assert_eq!(ADB_CLEANUP_TIMEOUT, Duration::from_secs(20));
        assert_eq!(ADB_EXEC_TIMEOUT, Duration::from_secs(115));
        assert_eq!(ADB_SUPERVISED_EXEC_TIMEOUT, Duration::from_secs(180));
        assert_eq!(ADB_PUSH_TIMEOUT, Duration::from_secs(120));
        assert_eq!(REMOTE_OUTPUT_TEST_TIMEOUT_SECONDS, 60);
        assert_eq!(REMOTE_CREDENTIAL_TEST_TIMEOUT_SECONDS, 25);
        assert_eq!(REMOTE_SUPERVISED_TEST_TIMEOUT_SECONDS, 60);
        assert_eq!(REMOTE_TEST_KILL_GRACE_SECONDS, 5);
        assert_eq!(HOST_POLL_INTERVAL, Duration::from_millis(25));
        assert_eq!(HOST_OUTPUT_DRAIN_GRACE, Duration::from_secs(2));
        assert!(ADB_QUERY_TIMEOUT < ADB_CLEANUP_TIMEOUT);
        assert!(
            Duration::from_secs(
                REMOTE_OUTPUT_TEST_TIMEOUT_SECONDS
                    + REMOTE_CREDENTIAL_TEST_TIMEOUT_SECONDS
                    + (2 * REMOTE_TEST_KILL_GRACE_SECONDS)
            ) < ADB_EXEC_TIMEOUT
        );
        assert!(ADB_EXEC_TIMEOUT < ADB_PUSH_TIMEOUT);
        assert!(
            Duration::from_secs(
                REMOTE_OUTPUT_TEST_TIMEOUT_SECONDS
                    + REMOTE_CREDENTIAL_TEST_TIMEOUT_SECONDS
                    + REMOTE_SUPERVISED_TEST_TIMEOUT_SECONDS
                    + (3 * REMOTE_TEST_KILL_GRACE_SECONDS)
            ) < ADB_SUPERVISED_EXEC_TIMEOUT
        );
        assert!(ADB_PUSH_TIMEOUT < CARGO_BUILD_TIMEOUT);
        assert!(HOST_POLL_INTERVAL < ADB_QUERY_TIMEOUT);
    }

    #[test]
    fn remote_contract_is_owner_marked_inode_bound_and_process_clean() {
        let remote = expected_remote_directory();
        assert!(remote.matches_spec());
        assert!(!REMOTE_DIRECTORY_SPEC.matches_path(&format!("{}/extra", remote.path())));
        let device = expected_device_profile();
        let artifacts = AndroidCanaryArtifactIdentities::for_test();
        let script = remote_script(&remote, &artifacts, &device).expect("remote script");
        let internal_envs = LINUX_CANARY_INTERNAL_ENVS.join(" ");
        for required in [
            "EXPECTED_OWNER_RECORD=",
            "EXPECTED_DIRECTORY_ID='253:91337'",
            "owned_root_matches",
            "trap remove_owned_root EXIT",
            "probe_process_absent",
            "identity_matches",
            "sha256sum \"$TEST_BIN\"",
            "sha256sum \"$CREDENTIAL_PROBE\"",
            "stat -c '%a:%u:%g' \"$TEST_BIN\"",
            "stat -c '%a:%u:%g' \"$CREDENTIAL_PROBE\"",
            "FLUX_LINUX_CANARY_REQUIRED=1",
            "FLUX_ENGINE_CREDENTIAL_PROBE_REQUIRED=1",
            "FLUX_ENGINE_CREDENTIAL_PROBE_PATH=\"$CREDENTIAL_PROBE\"",
            "FLUX_ENGINE_CREDENTIAL_PROBE_GID=\"$EXPECTED_PROBE_GID\"",
            &format!("unset {internal_envs}"),
            &format!("OUTPUT_TEST='{LINUX_OUTPUT_TPROXY_CANARY_TEST}'"),
            &format!("CREDENTIAL_TEST='{ANDROID_ENGINE_CREDENTIAL_CANARY_TEST}'"),
            "CREDENTIAL_STAGE_RECEIPT=\"$TMPDIR\"/'credential-stage'",
            "CREDENTIAL_FINAL_STAGE='parent-death-containment'",
            "CREDENTIAL_STAGE_OUTPUT_PREFIX='flux-engine-credential-stage:'",
            "read_credential_stage",
            "require_exact_test \"$OUTPUT_TEST\" \"$TMPDIR/output-list\"",
            "require_exact_test \"$CREDENTIAL_TEST\" \"$TMPDIR/credential-list\"",
            &format!("run_exact_test {REMOTE_OUTPUT_TEST_TIMEOUT_SECONDS} \"$OUTPUT_TEST\""),
            &format!(
                "run_exact_test {REMOTE_CREDENTIAL_TEST_TIMEOUT_SECONDS} \"$CREDENTIAL_TEST\""
            ),
            "CREDENTIAL_STAGE=$(read_credential_stage) || CREDENTIAL_STAGE=",
            "printf '%s%s\\n' \"$CREDENTIAL_STAGE_OUTPUT_PREFIX\" \"$CREDENTIAL_STAGE\"",
            "[ \"$CREDENTIAL_STAGE\" = \"$CREDENTIAL_FINAL_STAGE\" ]",
            "path_absent \"$TEST_BIN\"",
            "path_absent \"$CREDENTIAL_PROBE\"",
            "path_absent \"$PRODUCER_BIN\"",
            "path_absent \"$ROOT\"",
        ] {
            assert!(script.contains(required), "missing {required:?}");
        }
        let credential_functions = credential_stage_shell_functions();
        assert!(script.contains(&credential_functions));
        for stage in EngineCredentialProbeStage::all() {
            let stage_case = shell_single_quote(&stage.as_str());
            assert!(
                credential_functions.contains(&stage_case),
                "missing credential stage case {stage_case:?}"
            );
        }
        assert!(script.find("owned_root_matches").unwrap() < script.find("chown -R").unwrap());
        assert!(
            script
                .find("run_exact_test 25 \"$CREDENTIAL_TEST\"")
                .unwrap()
                < script.find("run_exact_test 60 \"$OUTPUT_TEST\"").unwrap()
        );
        assert!(script.contains("for COMM in /proc/[0-9]*/comm"));
        assert!(script.contains("'fluxd-test' 'flux-cred-probe' 'flux-sbox-p01'"));
        assert!(!script.contains("pidof"));
        let cleanup = cleanup_script(&remote, &device);
        assert!(cleanup.find("owned_root_matches").unwrap() < cleanup.find("rm -rf").unwrap());
        assert!(cleanup.contains("'fluxd-test' 'flux-cred-probe' 'flux-sbox-p01'"));
        for (boundary, proof) in [
            (
                "preflight",
                preflight_remote_directory_script(&remote, &device),
            ),
            ("final", remote_absence_script(&remote, &device)),
        ] {
            assert!(
                proof.contains(path_absence_function()),
                "{boundary} proof lacks the shared shell predicate"
            );
            assert!(
                proof.contains("path_absent \"$ROOT\""),
                "{boundary} proof does not reject root path entries"
            );
            assert!(
                proof.contains("'fluxd-test' 'flux-cred-probe' 'flux-sbox-p01'"),
                "{boundary} proof does not reject every process name"
            );
        }
        let final_proof = remote_absence_script(&remote, &device);
        assert!(final_proof.contains("path_absent \"$TEST_BIN\""));
        assert!(final_proof.contains("path_absent \"$CREDENTIAL_PROBE\""));
        assert!(final_proof.contains("path_absent \"$PRODUCER_BIN\""));
        let mut root_gid = device.clone();
        root_gid.shell_gid = 0;
        assert!(remote_script(&remote, &artifacts, &root_gid).is_err());
        assert!(!script.contains("sudo"));
        assert!(!script.contains("PRODUCER_TEST="));
        assert!(!script.contains(&format!("export {REAL_PRODUCER_BINARY_ENV}=")));
        assert!(uses_windows_adb(&OsString::from("adb.exe")));
        assert!(uses_windows_adb(&OsString::from(
            "/mnt/c/Android/platform-tools/ADB.EXE"
        )));
        assert!(!uses_windows_adb(&OsString::from("custom-adb")));
        assert!(!uses_windows_adb(&OsString::from("adb")));
        assert_eq!(shell_single_quote("flux/o'hare"), "'flux/o'\\''hare'");
    }

    #[test]
    fn supervised_producer_uses_the_same_owned_remote_contract() {
        let remote = expected_remote_directory();
        let device = expected_device_profile();
        let artifacts = AndroidCanaryArtifactIdentities::with_producer_for_test();
        let script =
            remote_script(&remote, &artifacts, &device).expect("supervised producer remote script");
        for required in [
            "[ -f \"$PRODUCER_BIN\" ] && [ ! -L \"$PRODUCER_BIN\" ]",
            "/system/bin/chmod 700 \"$PRODUCER_BIN\"",
            "stat -c '%a:%u:%g' \"$PRODUCER_BIN\"",
            "sha256sum \"$PRODUCER_BIN\"",
            &format!("PRODUCER_TEST='{ANDROID_SUPERVISED_PRODUCER_CANARY_TEST}'"),
            "require_exact_test \"$PRODUCER_TEST\" \"$TMPDIR/producer-list\"",
            &format!("export {REAL_PRODUCER_BINARY_ENV}=\"$PRODUCER_BIN\""),
            &format!("run_exact_test {REMOTE_SUPERVISED_TEST_TIMEOUT_SECONDS} \"$PRODUCER_TEST\""),
            &format!("unset {REAL_PRODUCER_BINARY_ENV}"),
            "path_absent \"$PRODUCER_BIN\"",
        ] {
            assert!(script.contains(required), "missing {required:?}");
        }
        assert!(
            script
                .find("run_exact_test 60 \"$OUTPUT_TEST\"")
                .expect("mechanism test")
                < script
                    .find("run_exact_test 60 \"$PRODUCER_TEST\"")
                    .expect("producer test")
        );
        assert!(script.contains("probe_process_absent"));
        assert!(script.contains("trap remove_owned_root EXIT"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_stage_shell_contract_accepts_exact_receipts_only() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        let receipt = env::temp_dir().join(format!(
            "flux-credential-stage-{}-{nonce}",
            std::process::id()
        ));
        let receipt_argument =
            shell_single_quote(receipt.to_str().expect("temporary receipt path is UTF-8"));
        let functions = credential_stage_shell_functions();
        let run_reader = || {
            Command::new("/bin/sh")
                .args([
                    "-c",
                    &format!(
                        "set -eu\nCREDENTIAL_STAGE_RECEIPT={receipt_argument}\n{functions}read_credential_stage\n"
                    ),
                ])
                .output()
                .expect("execute credential stage shell contract")
        };
        for stage in EngineCredentialProbeStage::all() {
            std::fs::write(&receipt, format!("{}\n", stage.as_str()))
                .expect("write canonical credential stage");
            let output = run_reader();
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            assert_eq!(output.stdout, format!("{}\n", stage.as_str()).as_bytes());
        }

        std::fs::remove_file(&receipt)
            .expect("remove credential stage fixture before absence test");
        let missing = run_reader();
        assert!(!missing.status.success());
        assert!(missing.stdout.is_empty());
        assert!(missing.stderr.is_empty());

        for malformed in [
            b"".as_slice(),
            b"unknown-stage\n".as_slice(),
            b"root-validation".as_slice(),
            b"root-validation\r\n".as_slice(),
            b"root-validation\n\n".as_slice(),
            b"root-validation\ntrailing".as_slice(),
        ] {
            std::fs::write(&receipt, malformed).expect("write malformed credential stage");
            let output = run_reader();
            assert!(!output.status.success(), "accepted frame {malformed:?}");
            assert!(output.stdout.is_empty());
            assert!(output.stderr.is_empty());
        }
        std::fs::remove_file(&receipt).expect("remove credential stage fixture");
    }

    #[test]
    fn remote_checkpoint_outputs_are_canonical_and_detail_free() {
        assert_eq!(
            preflight_stage_for_remote_status(Some(REMOTE_PREFLIGHT_IDENTITY_FAILURE_STATUS)),
            RunnerStage::RemotePathPreflightRootIdentity
        );
        assert_eq!(
            preflight_stage_for_remote_status(Some(REMOTE_PREFLIGHT_PROCESS_FAILURE_STATUS)),
            RunnerStage::RemotePathPreflightProcessAbsence
        );
        assert_eq!(
            preflight_stage_for_remote_status(Some(REMOTE_PREFLIGHT_PATH_FAILURE_STATUS)),
            RunnerStage::RemotePathPreflightPathAbsence
        );
        assert_eq!(
            preflight_stage_for_remote_status(Some(1)),
            RunnerStage::RemotePathPreflightUnexpectedStatus
        );
        assert_eq!(
            checkpoint_stage_for_remote_output(Some(REMOTE_CONTRACT_FAILURE_STATUS), b"", b""),
            RunnerStage::RemoteContract
        );
        assert_eq!(
            checkpoint_stage_for_remote_output(Some(1), b"", b""),
            RunnerStage::RemoteShell
        );
        assert_eq!(
            checkpoint_stage_for_remote_output(Some(124), b"", b""),
            RunnerStage::RemoteTimeout
        );
        assert_eq!(
            checkpoint_stage_for_remote_output(Some(REMOTE_OUTPUT_TEST_FAILURE_STATUS), b"", b""),
            RunnerStage::LocalOutputCheckpoint
        );
        assert_eq!(
            checkpoint_stage_for_remote_output(
                Some(REMOTE_SUPERVISED_TEST_FAILURE_STATUS),
                b"",
                b""
            ),
            RunnerStage::SupervisedProducerCheckpoint
        );
        assert_eq!(
            checkpoint_stage_for_remote_output(
                Some(REMOTE_CREDENTIAL_TEST_FAILURE_STATUS),
                b"",
                b""
            ),
            RunnerStage::EngineCredentialCheckpoint
        );
        for stage in EngineCredentialProbeStage::all() {
            let output = format!(
                "{REMOTE_CREDENTIAL_STAGE_OUTPUT_PREFIX}{}\n",
                stage.as_str()
            );
            assert_eq!(
                checkpoint_stage_for_remote_output(
                    Some(REMOTE_CREDENTIAL_TEST_FAILURE_STATUS),
                    output.as_bytes(),
                    b""
                ),
                RunnerStage::EngineCredential(stage)
            );
        }
        for malformed in [
            b"flux-engine-credential-stage:unknown-stage\n".as_slice(),
            b"flux-engine-credential-stage:root-validation".as_slice(),
            b"flux-engine-credential-stage:root-validation\r\n".as_slice(),
            b"flux-engine-credential-stage:root-validation\n\n".as_slice(),
            b"root-validation\n".as_slice(),
            b"\xff".as_slice(),
        ] {
            assert_eq!(
                checkpoint_stage_for_remote_output(
                    Some(REMOTE_CREDENTIAL_TEST_FAILURE_STATUS),
                    malformed,
                    b""
                ),
                RunnerStage::EngineCredentialCheckpoint,
                "accepted output {malformed:?}"
            );
        }
        assert_eq!(
            checkpoint_stage_for_remote_output(
                Some(REMOTE_CREDENTIAL_TEST_FAILURE_STATUS),
                b"flux-engine-credential-stage:root-validation\n",
                b"unexpected stderr"
            ),
            RunnerStage::RemoteExecution
        );
        assert_eq!(
            checkpoint_stage_for_remote_output(Some(71), b"", b""),
            RunnerStage::RemoteExecution
        );
        assert_eq!(
            checkpoint_stage_for_remote_output(
                Some(REMOTE_OUTPUT_TEST_FAILURE_STATUS),
                b"unexpected stdout",
                b""
            ),
            RunnerStage::RemoteExecution
        );
        assert_eq!(
            classify_remote_execution_error(runner_stage_error(
                RunnerStage::EngineCredentialCheckpoint
            )),
            runner_stage_error(RunnerStage::EngineCredentialCheckpoint)
        );
        assert_eq!(
            classify_remote_execution_error(runner_stage_error(RunnerStage::EngineCredential(
                EngineCredentialProbeStage::DeviceGidReport
            ))),
            runner_stage_error(RunnerStage::EngineCredential(
                EngineCredentialProbeStage::DeviceGidReport
            ))
        );
        assert_eq!(
            classify_remote_execution_error("raw device failure".to_owned()),
            runner_stage_error(RunnerStage::RemoteExecution)
        );
    }

    #[test]
    fn diagnostics_redact_device_identity_and_runner_stages_discard_details() {
        let options = Options {
            serial: "secret-serial".to_owned(),
            adb: OsString::from("adb"),
            producer: None,
        };
        let rendered = render_adb_command(
            &options,
            &[
                "-s",
                options.serial(),
                "shell",
                "su",
                "-c",
                "fingerprint=secret-fingerprint boot=secret-boot",
            ],
        );
        assert_eq!(
            rendered,
            "adb -s <redacted-serial> shell su -c <redacted-shell-command>"
        );
        for stage in [
            RunnerStage::DeviceProfile,
            RunnerStage::RemotePathPreflightIdentityBefore,
            RunnerStage::RemotePathPreflightRootIdentity,
            RunnerStage::RemotePathPreflightProcessAbsence,
            RunnerStage::RemotePathPreflightPathAbsence,
            RunnerStage::RemotePathPreflightContract,
            RunnerStage::RemotePathPreflightTransport,
            RunnerStage::RemotePathPreflightNormalization,
            RunnerStage::RemotePathPreflightUnexpectedStatus,
            RunnerStage::RemotePathPreflightUnexpectedOutput,
            RunnerStage::RemotePathPreflightIdentityAfter,
            RunnerStage::RemoteDirectoryCreate,
            RunnerStage::RemoteExecution,
            RunnerStage::RemoteExecutionPreflight,
            RunnerStage::RemoteTestArtifactPush,
            RunnerStage::RemoteCredentialArtifactPush,
            RunnerStage::RemoteProducerArtifactPush,
            RunnerStage::RemoteCheckpointTransport,
            RunnerStage::EngineCredential(EngineCredentialProbeStage::RootValidation),
            RunnerStage::EngineCredential(EngineCredentialProbeStage::DeviceGidReport),
            RunnerStage::EngineCredential(EngineCredentialProbeStage::ParentDeathContainment),
            RunnerStage::SupervisedProducerCheckpoint,
            RunnerStage::RemoteCleanup,
        ] {
            let error = at_runner_stage::<()>(
                stage,
                Err("secret-serial secret-fingerprint secret-boot /data/private".to_owned()),
            )
            .expect_err("stage must sanitize details");
            assert_eq!(error, runner_stage_error(stage));
            assert!(!error.contains("secret"));
            assert!(!error.contains("/data/"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_generated_root_script_has_valid_posix_shell_syntax() {
        let remote = expected_remote_directory();
        let device = expected_device_profile();
        let scripts = [
            preflight_remote_directory_script(&remote, &device),
            create_remote_directory_script(&remote, &device),
            execution_preflight_script(&remote, &device),
            remote_script(
                &remote,
                &AndroidCanaryArtifactIdentities::for_test(),
                &device,
            )
            .expect("remote script"),
            remote_script(
                &remote,
                &AndroidCanaryArtifactIdentities::with_producer_for_test(),
                &device,
            )
            .expect("supervised producer remote script"),
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

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_command_timeout_kills_and_reaps_the_child() {
        let mut command = Command::new(env::current_exe().expect("current xtask test executable"));
        command
            .args([
                "--ignored",
                "--exact",
                "android_canary::tests::bounded_command_timeout_fixture",
                "--nocapture",
            ])
            .env("FLUX_ANDROID_CANARY_TIMEOUT_FIXTURE", "1");
        let error = command_output_bounded(
            &mut command,
            None,
            Duration::from_millis(150),
            MAX_ADB_CAPTURE_BYTES,
            "bounded timeout fixture",
        )
        .expect_err("fixture must time out");
        assert!(error.contains("timed out"), "{error}");
        assert!(error.contains("wait/reaped"), "{error}");
        let marker = "FLUX_ANDROID_CANARY_FIXTURE_PID=";
        let pid = error
            .split_once(marker)
            .and_then(|(_, suffix)| suffix.lines().next())
            .and_then(|pid| pid.parse::<u32>().ok())
            .unwrap_or_else(|| panic!("fixture PID missing from timeout diagnostics: {error}"));
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "timed-out fixture process {pid} was not reaped"
        );
    }

    #[test]
    #[ignore = "process fixture invoked by bounded_command_timeout_kills_and_reaps_the_child"]
    fn bounded_command_timeout_fixture() {
        if env::var_os("FLUX_ANDROID_CANARY_TIMEOUT_FIXTURE").is_none() {
            return;
        }
        println!("FLUX_ANDROID_CANARY_FIXTURE_PID={}", std::process::id());
        std::io::stdout().flush().expect("flush fixture PID");
        thread::sleep(Duration::from_secs(30));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_command_kills_descendant_that_inherits_output_pipe() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        let pid_path = env::temp_dir().join(format!(
            "flux-android-canary-descendant-{}-{nonce}.pid",
            std::process::id()
        ));
        let mut command = Command::new(env::current_exe().expect("current xtask test executable"));
        command
            .args([
                "--ignored",
                "--exact",
                "android_canary::tests::bounded_command_descendant_pipe_fixture",
                "--nocapture",
            ])
            .env("FLUX_ANDROID_CANARY_DESCENDANT_FIXTURE", "1")
            .env("FLUX_ANDROID_CANARY_DESCENDANT_PID_PATH", &pid_path);
        let started = Instant::now();
        let error = command_output_bounded(
            &mut command,
            None,
            Duration::from_millis(300),
            MAX_ADB_CAPTURE_BYTES,
            "inherited output pipe fixture",
        )
        .expect_err("inherited descendant pipe must exhaust the command deadline");
        assert!(error.contains("drain timed out"), "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "bounded command exceeded its deadline: {} milliseconds",
            started.elapsed().as_millis()
        );

        let descendant_pid = std::fs::read_to_string(&pid_path)
            .unwrap_or_else(|error| panic!("read descendant PID {}: {error}", pid_path.display()))
            .trim()
            .parse::<u32>()
            .expect("parse descendant PID");
        let descendant_proc = format!("/proc/{descendant_pid}");
        let disappearance_deadline = Instant::now() + Duration::from_secs(2);
        while Path::new(&descendant_proc).exists() && Instant::now() < disappearance_deadline {
            thread::sleep(HOST_POLL_INTERVAL);
        }
        let _ = std::fs::remove_file(&pid_path);
        assert!(
            !Path::new(&descendant_proc).exists(),
            "descendant {descendant_pid} survived process-group termination"
        );
    }

    #[test]
    #[ignore = "process fixture invoked by bounded_command_kills_descendant_that_inherits_output_pipe"]
    #[allow(
        clippy::zombie_processes,
        reason = "the fixture must exit without waiting so its descendant alone retains the inherited output pipe"
    )]
    fn bounded_command_descendant_pipe_fixture() {
        if env::var_os("FLUX_ANDROID_CANARY_DESCENDANT_FIXTURE").is_none() {
            return;
        }
        let pid_path = env::var_os("FLUX_ANDROID_CANARY_DESCENDANT_PID_PATH")
            .map(PathBuf::from)
            .expect("descendant PID path");
        let descendant = Command::new(env::current_exe().expect("current xtask test executable"))
            .args([
                "--ignored",
                "--exact",
                "android_canary::tests::bounded_command_descendant_sleeper_fixture",
                "--nocapture",
            ])
            .env("FLUX_ANDROID_CANARY_DESCENDANT_SLEEPER", "1")
            .spawn()
            .expect("spawn inherited-pipe descendant");
        std::fs::write(&pid_path, descendant.id().to_string())
            .unwrap_or_else(|error| panic!("write descendant PID {}: {error}", pid_path.display()));
    }

    #[test]
    #[ignore = "descendant fixture invoked by bounded_command_descendant_pipe_fixture"]
    fn bounded_command_descendant_sleeper_fixture() {
        if env::var_os("FLUX_ANDROID_CANARY_DESCENDANT_SLEEPER").is_none() {
            return;
        }
        thread::sleep(Duration::from_secs(30));
    }
}
