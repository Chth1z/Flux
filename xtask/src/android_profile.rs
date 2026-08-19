use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use flux_core::CAPABILITY_PROFILE_SCHEMA_VERSION;
use serde_json::Value;

use super::android_artifact::AndroidArtifactIdentity as ArtifactIdentity;
use super::android_canary::{
    Options, adb_root_shell_output, adb_success_with_timeout, adb_text, artifact_path_for_adb,
    bounded_diagnostic, command_output_bounded, forward_output,
};
use super::android_remote::{shell_single_quote, valid_boot_id, validate_profile_text};
use super::{
    ANDROID_NDK_REVISION, ANDROID_RUSTFLAGS, ANDROID_TARGET, ANDROID_TARGET_RUSTFLAGS_ENV,
    LINUX_ANDROID_HOST_BUILD_TMPDIR, android_linker, verify_ndk_revision,
};

const COMMAND: &str = "collect-android-arm64-profile";
const CLANG_TARGET: &str = "aarch64-linux-android";
const LINKER_ENV: &str = "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER";
const CC_ENV: &str = "CC_aarch64_linux_android";
const REQUIRED_ENV: &str = "FLUX_ANDROID_PROFILE_REQUIRED";
const PROBE_BINARY_TARGET: &str = "android-profile-probe";
const REPORT_BEGIN: &str = "FLUX_ANDROID_PROFILE_BEGIN";
const REPORT_END: &str = "FLUX_ANDROID_PROFILE_END";
const REMOTE_DIRECTORY_TEMPLATE: &str = "/data/local/tmp/flux-profile.XXXXXX";
const REMOTE_DIRECTORY_PREFIX: &str = "/data/local/tmp/flux-profile.";
const REMOTE_BINARY_NAME: &str = "fluxd-profile-probe";
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
const MINIMUM_ANDROID_SDK: u32 = 31;
const MAX_ADB_CAPTURE_BYTES: usize = 256 * 1024;
const MAX_CARGO_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const ADB_PUSH_TIMEOUT: Duration = Duration::from_secs(120);
const ADB_EXEC_TIMEOUT: Duration = Duration::from_secs(115);
const ADB_CLEANUP_TIMEOUT: Duration = Duration::from_secs(20);
const CARGO_BUILD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const REMOTE_TEST_TIMEOUT_SECONDS: u64 = 90;
const REMOTE_TEST_KILL_GRACE_SECONDS: u64 = 5;

pub(super) fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    Options::parse(arguments, COMMAND)
}

pub(super) fn run(options: Options) -> Result<(), String> {
    if env::consts::OS != "linux" {
        return Err("the ARM64 Android profile runner requires a Linux/WSL host".to_owned());
    }
    let device = verify_device(&options)?;
    let ndk_root = env::var_os("ANDROID_NDK_HOME")
        .or_else(|| env::var_os("ANDROID_NDK_ROOT"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            format!("ANDROID_NDK_HOME must point to Android NDK revision {ANDROID_NDK_REVISION}")
        })?;
    verify_ndk_revision(&ndk_root)?;
    let linker = android_linker(&ndk_root, ANDROID_TARGET, CLANG_TARGET)?;
    let artifact = build_probe_artifact(&linker)?;
    let artifact_identity = ArtifactIdentity::from_file(&artifact, "exact profile probe")?;
    revalidate_device(&options, &device, "before remote mutation")?;

    println!(
        "validated explicit ARM64 target model={} sdk={} abi={} kernel_arch={} kernel_release={}",
        device.model, device.sdk, device.abi_list, device.kernel_arch, device.kernel_release,
    );
    println!(
        "cross-built exact profile probe ELF sha256={} size={}",
        artifact_identity.sha256(),
        artifact_identity.size(),
    );

    let remote = create_remote_directory(&options)?;
    let execution =
        push_execute_and_validate(&options, &artifact, &artifact_identity, &device, &remote);
    let cleanup = cleanup_remote_directory(&options, &device, &remote);
    match (execution, cleanup) {
        (Ok(()), Ok(())) => {
            println!(
                "production ARM64 capability profile collected and exact remote directory removed"
            );
            Ok(())
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; remote cleanup also failed: {cleanup_error}"
        )),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeviceProfile {
    model: String,
    sdk: u32,
    abi_list: String,
    kernel_arch: String,
    kernel_release: String,
    build_fingerprint: String,
    boot_id: String,
}

fn verify_device(options: &Options) -> Result<DeviceProfile, String> {
    let state = adb_text(options, &["-s", options.serial(), "get-state"])?;
    if state != "device" {
        return Err(format!(
            "ADB serial {} is not ready: state={state:?}",
            options.serial()
        ));
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
        return Err(format!(
            "ADB serial {} does not advertise arm64-v8a in ro.product.cpu.abilist={abi_list:?}",
            options.serial()
        ));
    }
    let kernel_arch = adb_text(options, &["-s", options.serial(), "shell", "uname", "-m"])?;
    if !matches!(kernel_arch.as_str(), "aarch64" | "arm64") {
        return Err(format!(
            "ADB serial {} runs kernel architecture {kernel_arch:?}, expected ARM64",
            options.serial()
        ));
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
        .map_err(|error| format!("parse Android SDK {sdk_text:?}: {error}"))?;
    if sdk < MINIMUM_ANDROID_SDK {
        return Err(format!(
            "ADB serial {} runs SDK {sdk}, below qualification minimum {MINIMUM_ANDROID_SDK}",
            options.serial()
        ));
    }
    let root = adb_text(
        options,
        &["-s", options.serial(), "shell", "su", "-c", "id"],
    )?;
    if !root
        .split_whitespace()
        .any(|field| field.starts_with("uid=0("))
    {
        return Err(format!(
            "ADB serial {} did not provide root UID 0: {root:?}",
            options.serial()
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
        return Err(format!(
            "ADB serial {} returned non-canonical boot_id {boot_id:?}",
            options.serial()
        ));
    }
    Ok(DeviceProfile {
        model,
        sdk,
        abi_list,
        kernel_arch,
        kernel_release,
        build_fingerprint,
        boot_id,
    })
}

fn revalidate_device(
    options: &Options,
    expected: &DeviceProfile,
    boundary: &str,
) -> Result<(), String> {
    let actual = verify_device(options)
        .map_err(|error| format!("revalidate exact Android device {boundary}: {error}"))?;
    if &actual == expected {
        Ok(())
    } else {
        Err(format!(
            "ADB serial {} changed identity {boundary}; expected {expected:?}, got {actual:?}",
            options.serial()
        ))
    }
}

fn android_test_build_command(linker: &Path) -> Command {
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
    let mut command = android_test_build_command(linker);
    let output = command_output_bounded(
        &mut command,
        None,
        CARGO_BUILD_TIMEOUT,
        MAX_CARGO_CAPTURE_BYTES,
        &format!("cross-build {ANDROID_TARGET} profile probe ELF"),
    )?;
    if !output.stderr.is_empty() {
        std::io::stderr()
            .write_all(&output.stderr)
            .map_err(|error| format!("forward Cargo diagnostics: {error}"))?;
    }
    if !output.status.success() {
        return Err(format!(
            "cross-build of {ANDROID_TARGET} profile probe ELF exited with {}: {}",
            output.status,
            bounded_diagnostic(&output.stdout)
        ));
    }
    let artifact = test_artifact_from_cargo_messages(&output.stdout)?;
    if !artifact.is_file() {
        return Err(format!(
            "Cargo reported Android profile probe {}, but it is missing",
            artifact.display()
        ));
    }
    Ok(artifact)
}

fn test_artifact_from_cargo_messages(messages: &[u8]) -> Result<PathBuf, String> {
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
            "Cargo JSON did not report exactly one Android profile probe executable".to_owned(),
        );
    };
    Ok(artifact.clone())
}

fn create_remote_directory(options: &Options) -> Result<String, String> {
    let remote = adb_text(
        options,
        &[
            "-s",
            options.serial(),
            "shell",
            "/system/bin/mktemp",
            "-d",
            REMOTE_DIRECTORY_TEMPLATE,
        ],
    )?;
    if valid_remote_directory(&remote) {
        Ok(remote)
    } else {
        Err(format!(
            "ADB returned an invalid profile temporary directory {remote:?}"
        ))
    }
}

fn valid_remote_directory(path: &str) -> bool {
    path.strip_prefix(REMOTE_DIRECTORY_PREFIX)
        .is_some_and(|suffix| {
            suffix.len() == 6 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn push_execute_and_validate(
    options: &Options,
    artifact: &Path,
    artifact_identity: &ArtifactIdentity,
    expected_device: &DeviceProfile,
    remote: &str,
) -> Result<(), String> {
    let remote_binary = format!("{remote}/{REMOTE_BINARY_NAME}");
    let adb_artifact = artifact_path_for_adb(options, artifact)?;
    let mut push = Command::new(options.adb());
    push.args(["-s", options.serial(), "push"])
        .arg(adb_artifact)
        .arg(&remote_binary);
    let output = command_output_bounded(
        &mut push,
        None,
        ADB_PUSH_TIMEOUT,
        MAX_ADB_CAPTURE_BYTES,
        "push exact ARM64 profile probe ELF",
    )?;
    forward_output(&output)?;
    if !output.status.success() {
        return Err(format!(
            "ADB push to {remote_binary} exited with {}",
            output.status
        ));
    }
    revalidate_device(options, expected_device, "after remote push")?;

    let script = remote_script(remote, expected_device);
    let output = adb_root_shell_output(
        options,
        script.as_bytes(),
        ADB_EXEC_TIMEOUT,
        "run production ARM64 capability profile checkpoint",
    )?;
    if !output.status.success() {
        forward_output(&output)?;
        return Err(format!(
            "rooted ARM64 profile checkpoint exited with {}",
            output.status
        ));
    }
    validate_profile_report(&output.stdout, expected_device, artifact_identity)?;
    forward_output(&output)
}

fn remote_script(remote: &str, expected_device: &DeviceProfile) -> String {
    let root = shell_single_quote(remote);
    let expected_boot_id = shell_single_quote(&expected_device.boot_id);
    let expected_fingerprint = shell_single_quote(&expected_device.build_fingerprint);
    format!(
        "set -eu\n\
         umask 077\n\
         ROOT={root}\n\
         BIN=\"$ROOT/{REMOTE_BINARY_NAME}\"\n\
         TMPDIR=\"$ROOT/tmp\"\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         EXPECTED_BOOT_ID={expected_boot_id}\n\
         EXPECTED_FINGERPRINT={expected_fingerprint}\n\
         cleanup() {{ /system/bin/rm -rf \"$ROOT\"; }}\n\
         trap cleanup EXIT HUP INT TERM\n\
         if [ \"$(/system/bin/cat /proc/sys/kernel/random/boot_id)\" != \"$EXPECTED_BOOT_ID\" ] || \
            [ \"$(/system/bin/getprop ro.build.fingerprint)\" != \"$EXPECTED_FINGERPRINT\" ]; then\n\
           echo \"exact Android identity changed before profile collection\" >&2\n\
           exit 70\n\
         fi\n\
         /system/bin/chown -R 0:0 \"$ROOT\"\n\
         /system/bin/chmod 700 \"$ROOT\" \"$BIN\"\n\
         if [ \"$(/system/bin/stat -c '%a:%u:%g' \"$ROOT\")\" != '700:0:0' ]; then\n\
           echo \"profile directory ownership contract failed\" >&2\n\
           exit 70\n\
         fi\n\
         /system/bin/mkdir \"$TMPDIR\"\n\
         /system/bin/chmod 700 \"$TMPDIR\"\n\
         export TMPDIR {REQUIRED_ENV}=1\n\
         /system/bin/timeout -k {REMOTE_TEST_KILL_GRACE_SECONDS} {REMOTE_TEST_TIMEOUT_SECONDS} \
           \"$BIN\"\n"
    )
}

fn validate_profile_report(
    bytes: &[u8],
    expected_device: &DeviceProfile,
    expected_artifact: &ArtifactIdentity,
) -> Result<(), String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| format!("Android profile checkpoint output is not UTF-8: {error}"))?;
    if text.matches(REPORT_BEGIN).count() != 1 || text.matches(REPORT_END).count() != 1 {
        return Err("Android profile checkpoint emitted an invalid report marker count".to_owned());
    }
    let (_, report) = text
        .split_once(REPORT_BEGIN)
        .ok_or_else(|| "Android profile report begin marker is missing".to_owned())?;
    let (document, _) = report
        .split_once(REPORT_END)
        .ok_or_else(|| "Android profile report end marker is missing".to_owned())?;
    let fields = parse_profile_fields(document)?;
    require_field(
        &fields,
        "authority",
        "read_only_profile_evidence_no_mutation_authority",
    )?;
    require_field(&fields, "schema_version", "1")?;
    let capability_schema_version = CAPABILITY_PROFILE_SCHEMA_VERSION.to_string();
    require_field(
        &fields,
        "capability_schema_version",
        &capability_schema_version,
    )?;
    require_positive_u64(&fields, "capability_revision")?;
    require_lower_sha256(&fields, "capability_profile_sha256")?;
    require_field(&fields, "boot_id", &expected_device.boot_id)?;
    require_field(&fields, "android_build", &expected_device.build_fingerprint)?;
    require_field(&fields, "kernel_release", &expected_device.kernel_release)?;
    require_field(&fields, "selinux", "enforcing")?;
    for key in [
        "android_product",
        "vendor_build",
        "security_patch",
        "kernel_build",
    ] {
        require_nonempty_field(&fields, key)?;
    }
    let verified_boot_state = require_nonempty_field(&fields, "verified_boot_state")?;
    if !matches!(verified_boot_state, "green" | "yellow" | "orange" | "red") {
        return Err(format!(
            "Android profile verified_boot_state is invalid: {verified_boot_state:?}"
        ));
    }
    let device_locked = require_nonempty_field(&fields, "device_locked")?;
    if !matches!(device_locked, "0" | "1") {
        return Err(format!(
            "Android profile device_locked is invalid: {device_locked:?}"
        ));
    }
    for key in [
        "vbmeta_sha256",
        "selinux_policy_sha256",
        "netd_sha256",
        "connectivity_sha256",
        "tool_sha256",
    ] {
        require_lower_sha256(&fields, key)?;
    }
    for key in [
        "selinux_policy_size",
        "netd_size",
        "connectivity_size",
        "tool_size",
        "network_namespace_inode",
    ] {
        require_positive_u64(&fields, key)?;
    }
    require_u64(&fields, "network_namespace_device")?;
    require_field(&fields, "tool_id", "fluxd")?;
    require_field(&fields, "tool_sha256", expected_artifact.sha256())?;
    require_field(&fields, "tool_size", &expected_artifact.size().to_string())
}

const EXPECTED_PROFILE_FIELDS: [&str; 27] = [
    "authority",
    "schema_version",
    "capability_schema_version",
    "capability_revision",
    "capability_profile_sha256",
    "boot_id",
    "android_product",
    "android_build",
    "vendor_build",
    "security_patch",
    "verified_boot_state",
    "device_locked",
    "vbmeta_sha256",
    "kernel_build",
    "kernel_release",
    "selinux",
    "selinux_policy_sha256",
    "selinux_policy_size",
    "netd_sha256",
    "netd_size",
    "connectivity_sha256",
    "connectivity_size",
    "tool_id",
    "tool_sha256",
    "tool_size",
    "network_namespace_device",
    "network_namespace_inode",
];

fn parse_profile_fields(document: &str) -> Result<BTreeMap<String, String>, String> {
    let mut fields = BTreeMap::new();
    for (index, line) in document.trim().lines().enumerate() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("Android profile report line {} is malformed", index + 1))?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || value.is_empty()
            || value.chars().any(char::is_control)
        {
            return Err(format!(
                "Android profile report line {} has an invalid field",
                index + 1
            ));
        }
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("Android profile field {key:?} is duplicated"));
        }
    }
    let expected = EXPECTED_PROFILE_FIELDS.into_iter().collect::<BTreeSet<_>>();
    let actual = fields.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "Android profile fields differ from the exact schema: missing={:?} unexpected={:?}",
            expected.difference(&actual).collect::<Vec<_>>(),
            actual.difference(&expected).collect::<Vec<_>>(),
        ));
    }
    Ok(fields)
}

fn require_nonempty_field<'a>(
    fields: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, String> {
    fields
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("Android profile field {key:?} is missing"))
}

fn require_field(
    fields: &BTreeMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<(), String> {
    let actual = fields.get(key).map(String::as_str);
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(format!(
            "Android profile field {key:?} is {actual:?}, expected {expected:?}"
        ))
    }
}

fn require_u64(fields: &BTreeMap<String, String>, key: &str) -> Result<u64, String> {
    require_nonempty_field(fields, key)?
        .parse::<u64>()
        .map_err(|error| format!("Android profile field {key:?} is not u64: {error}"))
}

fn require_positive_u64(fields: &BTreeMap<String, String>, key: &str) -> Result<u64, String> {
    let value = require_u64(fields, key)?;
    if value == 0 {
        Err(format!("Android profile field {key:?} must be nonzero"))
    } else {
        Ok(value)
    }
}

fn require_lower_sha256(fields: &BTreeMap<String, String>, key: &str) -> Result<(), String> {
    let value = require_nonempty_field(fields, key)?;
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "Android profile SHA-256 field {key:?} is not canonical lowercase hexadecimal"
        ))
    }
}

fn cleanup_remote_directory(
    options: &Options,
    expected_device: &DeviceProfile,
    remote: &str,
) -> Result<(), String> {
    if !valid_remote_directory(remote) {
        return Err(format!(
            "refusing cleanup for invalid Android profile directory {remote:?}"
        ));
    }
    let identity_before = verify_device(options);
    let remove = format!("/system/bin/rm -rf {remote}");
    let removal = adb_success_with_timeout(
        options,
        &["-s", options.serial(), "shell", "su", "-c", &remove],
        ADB_CLEANUP_TIMEOUT,
    );
    let absent = format!("test ! -e {remote}");
    let absence = adb_success_with_timeout(
        options,
        &["-s", options.serial(), "shell", "su", "-c", &absent],
        ADB_CLEANUP_TIMEOUT,
    );
    let identity_after = verify_device(options);

    removal.map_err(|error| format!("remove exact remote profile directory: {error}"))?;
    absence.map_err(|error| {
        format!("remote cleanup could not prove exact profile directory absent: {error}")
    })?;
    let before = identity_before
        .map_err(|error| format!("revalidate exact device before cleanup: {error}"))?;
    let after = identity_after
        .map_err(|error| format!("revalidate exact device after cleanup: {error}"))?;
    if &before != expected_device || &after != expected_device {
        return Err(format!(
            "exact Android device identity drifted across cleanup; expected {expected_device:?}, before={before:?}, after={after:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn expected_device() -> DeviceProfile {
        DeviceProfile {
            model: "physical".to_owned(),
            sdk: 36,
            abi_list: "arm64-v8a,armeabi-v7a".to_owned(),
            kernel_arch: "aarch64".to_owned(),
            kernel_release: "5.15.207-test".to_owned(),
            build_fingerprint: "vendor/product/device:16/BUILD/1:user/release-keys".to_owned(),
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
        }
    }

    #[test]
    fn build_command_uses_the_pinned_arm64_toolchain_and_host_tmpdir() {
        let linker = Path::new("/ndk/toolchains/llvm/bin/aarch64-linux-android31-clang");
        let command = android_test_build_command(linker);
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
    fn remote_directory_and_script_are_exact_and_cleanup_bounded() {
        assert!(valid_remote_directory(
            "/data/local/tmp/flux-profile.A1b2C3"
        ));
        assert!(!valid_remote_directory(
            "/data/local/tmp/flux-profile.A1b2C3/child"
        ));
        assert!(!valid_remote_directory("/data/local/tmp/other.A1b2C3"));
        let script = remote_script("/data/local/tmp/flux-profile.A1b2C3", &expected_device());
        assert!(script.contains("trap cleanup EXIT HUP INT TERM"));
        assert!(script.contains("stat -c '%a:%u:%g'"));
        assert!(script.contains("FLUX_ANDROID_PROFILE_REQUIRED=1"));
        assert!(!script.contains("/data/adb/flux/scripts"));
        assert!(!script.contains("iptables"));
        assert!(!script.contains("ip rule"));
    }

    #[test]
    fn profile_report_binds_boot_build_kernel_and_exact_probe_elf() {
        let expected = expected_device();
        let artifact = ArtifactIdentity::for_test("11".repeat(32), 4096);
        let report = [
            "authority=read_only_profile_evidence_no_mutation_authority".to_owned(),
            "schema_version=1".to_owned(),
            format!("capability_schema_version={CAPABILITY_PROFILE_SCHEMA_VERSION}"),
            "capability_revision=7".to_owned(),
            format!("capability_profile_sha256={}", "22".repeat(32)),
            format!("boot_id={}", expected.boot_id),
            "android_product=vendor/product/device".to_owned(),
            format!("android_build={}", expected.build_fingerprint),
            "vendor_build=vendor/product/device:16/BUILD/1:user/release-keys".to_owned(),
            "security_patch=2026-04-05".to_owned(),
            "verified_boot_state=orange".to_owned(),
            "device_locked=0".to_owned(),
            format!("vbmeta_sha256={}", "33".repeat(32)),
            "kernel_build=Linux version 5.15.207-test".to_owned(),
            format!("kernel_release={}", expected.kernel_release),
            "selinux=enforcing".to_owned(),
            format!("selinux_policy_sha256={}", "44".repeat(32)),
            "selinux_policy_size=1".to_owned(),
            format!("netd_sha256={}", "55".repeat(32)),
            "netd_size=2".to_owned(),
            format!("connectivity_sha256={}", "66".repeat(32)),
            "connectivity_size=3".to_owned(),
            "tool_id=fluxd".to_owned(),
            format!("tool_sha256={}", artifact.sha256()),
            format!("tool_size={}", artifact.size()),
            "network_namespace_device=4".to_owned(),
            "network_namespace_inode=40".to_owned(),
        ]
        .join("\n");
        let output = format!("running profile probe\n{REPORT_BEGIN}\n{report}\n{REPORT_END}\nok\n");
        validate_profile_report(output.as_bytes(), &expected, &artifact)
            .expect("exact profile report");
    }

    #[test]
    fn profile_report_field_names_remain_ascii_and_bounded_to_the_exact_schema() {
        let malformed = format!(
            "{REPORT_BEGIN}\ncapability-profile-sha256={}\n{REPORT_END}\n",
            "11".repeat(32)
        );
        let error = validate_profile_report(
            malformed.as_bytes(),
            &expected_device(),
            &ArtifactIdentity::for_test("22".repeat(32), 1),
        )
        .expect_err("hyphenated field must be rejected");
        assert!(error.contains("invalid field"));
    }
}
