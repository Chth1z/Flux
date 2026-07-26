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

use super::{
    ANDROID_NDK_REVISION, ANDROID_RUSTFLAGS, LINUX_CANARY_INTERNAL_ENVS,
    LINUX_OUTPUT_TPROXY_CANARY_TEST, android_linker, verify_ndk_revision,
};

pub(super) const TARGET: &str = "x86_64-linux-android";
const CLANG_TARGET: &str = "x86_64-linux-android";
const MINIMUM_ANDROID_SDK: u32 = 31;
const REMOTE_DIRECTORY_TEMPLATE: &str = "/data/local/tmp/flux-output-tproxy.XXXXXX";
const REMOTE_DIRECTORY_PREFIX: &str = "/data/local/tmp/flux-output-tproxy.";
const REMOTE_BINARY_NAME: &str = "fluxd-test";
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
const REMOTE_TEST_TIMEOUT_SECONDS: u64 = 90;
const REMOTE_TEST_KILL_GRACE_SECONDS: u64 = 5;
const ADB_EXEC_TIMEOUT: Duration = Duration::from_secs(115);
const ADB_CLEANUP_TIMEOUT: Duration = Duration::from_secs(20);
const CARGO_BUILD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const HOST_POLL_INTERVAL: Duration = Duration::from_millis(25);
const HOST_OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(2);
const HOST_BUILD_TMPDIR: &str = "/tmp";

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct Options {
    serial: String,
    adb: OsString,
}

pub(super) fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    Options::parse(
        arguments,
        "test-functional-canary-android-x86_64-output-tproxy",
    )
}

impl Options {
    pub(super) fn parse(arguments: &[OsString], command: &str) -> Result<Self, String> {
        let mut serial = None;
        let mut adb = None;
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
                "--serial" | "--adb" => return Err(format!("{flag} may only be supplied once")),
                unknown => return Err(format!("unknown Android checkpoint option '{unknown}'")),
            }
            index = index.saturating_add(2);
        }
        Ok(Self {
            serial: serial.ok_or_else(|| format!("{command} requires --serial SERIAL"))?,
            adb: adb
                .or_else(|| env::var_os("ADB"))
                .unwrap_or_else(|| OsString::from("adb")),
        })
    }

    pub(super) fn serial(&self) -> &str {
        &self.serial
    }

    pub(super) fn adb(&self) -> &OsString {
        &self.adb
    }
}

pub(super) fn run(options: Options) -> Result<(), String> {
    if env::consts::OS != "linux" {
        return Err(
            "the x86_64 Android canary runner currently requires a Linux/WSL host".to_owned(),
        );
    }
    let device = verify_device(&options)?;
    let ndk_root = env::var_os("ANDROID_NDK_HOME")
        .or_else(|| env::var_os("ANDROID_NDK_ROOT"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            format!("ANDROID_NDK_HOME must point to Android NDK revision {ANDROID_NDK_REVISION}")
        })?;
    verify_ndk_revision(&ndk_root)?;
    let linker = android_linker(&ndk_root, TARGET, CLANG_TARGET)?;
    let artifact = build_test_artifact(&linker)?;
    revalidate_device(&options, &device, "before remote mutation")?;

    println!(
        "validated development target serial={} model={} sdk={} abi={} kernel_arch={} kernel_release={} fingerprint={} boot_id={}",
        options.serial,
        device.model,
        device.sdk,
        device.abi,
        device.kernel_arch,
        device.kernel_release,
        device.build_fingerprint,
        device.boot_id,
    );
    println!(
        "cross-built exact Android test ELF at {}",
        artifact.display()
    );

    let remote = create_remote_directory(&options)?;
    let execution = push_and_execute(&options, &artifact, &device, &remote);
    let cleanup = cleanup_remote_directory(&options, &device, &remote);
    match (execution, cleanup) {
        (Ok(()), Ok(())) => {
            println!(
                "rooted x86_64 Android local-OUTPUT TPROXY checkpoint passed and removed {remote}"
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
struct DeviceProfile {
    model: String,
    sdk: u32,
    abi: String,
    kernel_arch: String,
    kernel_release: String,
    build_fingerprint: String,
    boot_id: String,
}

fn verify_device(options: &Options) -> Result<DeviceProfile, String> {
    let state = adb_text(options, &["-s", &options.serial, "get-state"])?;
    if state != "device" {
        return Err(format!(
            "ADB serial {} is not ready: state={state:?}",
            options.serial
        ));
    }
    let abi = adb_text(
        options,
        &[
            "-s",
            &options.serial,
            "shell",
            "getprop",
            "ro.product.cpu.abilist",
        ],
    )?;
    if !abi.split(',').any(|candidate| candidate.trim() == "x86_64") {
        return Err(format!(
            "ADB serial {} does not advertise x86_64 in ro.product.cpu.abilist={abi:?}",
            options.serial
        ));
    }
    validate_profile_text("ABI list", &abi, 1024)?;
    let kernel_arch = adb_text(options, &["-s", &options.serial, "shell", "uname", "-m"])?;
    if kernel_arch != "x86_64" {
        return Err(format!(
            "ADB serial {} runs kernel architecture {kernel_arch:?}, expected x86_64",
            options.serial
        ));
    }
    let kernel_release = adb_text(options, &["-s", &options.serial, "shell", "uname", "-r"])?;
    validate_profile_text("kernel release", &kernel_release, 256)?;
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
    Ok(DeviceProfile {
        model,
        sdk,
        abi,
        kernel_arch,
        kernel_release,
        build_fingerprint,
        boot_id,
    })
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

fn revalidate_device(
    options: &Options,
    expected: &DeviceProfile,
    boundary: &str,
) -> Result<(), String> {
    let actual = verify_device(options)
        .map_err(|error| format!("revalidate exact Android device {boundary}: {error}"))?;
    if actual == *expected {
        Ok(())
    } else {
        Err(format!(
            "ADB serial {} changed identity {boundary}; expected {expected:?}, got {actual:?}",
            options.serial
        ))
    }
}

fn android_test_build_command(linker: &Path) -> Command {
    let mut command = Command::new("cargo");
    command.args([
        "test",
        "-p",
        "fluxd",
        "--lib",
        "--target",
        TARGET,
        "--no-run",
        "--message-format=json-render-diagnostics",
    ]);
    command.env(
        "CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER",
        linker.as_os_str(),
    );
    command.env("CC_x86_64_linux_android", linker.as_os_str());
    command.env(
        "CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS",
        ANDROID_RUSTFLAGS,
    );
    command.env("TMPDIR", HOST_BUILD_TMPDIR);
    command
}

fn build_test_artifact(linker: &Path) -> Result<PathBuf, String> {
    let mut command = android_test_build_command(linker);
    let output = command_output_bounded(
        &mut command,
        None,
        CARGO_BUILD_TIMEOUT,
        MAX_CARGO_CAPTURE_BYTES,
        &format!("cross-build {TARGET} test ELF"),
    )?;
    if !output.stderr.is_empty() {
        std::io::stderr()
            .write_all(&output.stderr)
            .map_err(|error| format!("forward Cargo diagnostics: {error}"))?;
    }
    if !output.status.success() {
        return Err(format!(
            "cross-build of {TARGET} test ELF exited with {}: {}",
            output.status,
            bounded_diagnostic(&output.stdout)
        ));
    }
    let artifact = test_artifact_from_cargo_messages(&output.stdout)?;
    if !artifact.is_file() {
        return Err(format!(
            "Cargo reported Android test executable {}, but it is missing",
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
            || message.pointer("/target/name").and_then(Value::as_str) != Some("fluxd")
            || !message
                .pointer("/target/kind")
                .and_then(Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("lib")))
            || message.pointer("/profile/test").and_then(Value::as_bool) != Some(true)
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
            "Cargo JSON did not report exactly one fluxd library-test executable".to_owned(),
        );
    };
    Ok(artifact.clone())
}

fn create_remote_directory(options: &Options) -> Result<String, String> {
    let remote = adb_text(
        options,
        &[
            "-s",
            &options.serial,
            "shell",
            "/system/bin/mktemp",
            "-d",
            REMOTE_DIRECTORY_TEMPLATE,
        ],
    )?;
    if !valid_remote_directory(&remote) {
        return Err(format!(
            "ADB returned an invalid remote temporary directory {remote:?}"
        ));
    }
    Ok(remote)
}

fn valid_remote_directory(path: &str) -> bool {
    path.strip_prefix(REMOTE_DIRECTORY_PREFIX)
        .is_some_and(|suffix| {
            suffix.len() == 6 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn push_and_execute(
    options: &Options,
    artifact: &Path,
    expected_device: &DeviceProfile,
    remote: &str,
) -> Result<(), String> {
    let remote_binary = format!("{remote}/{REMOTE_BINARY_NAME}");
    let adb_artifact = artifact_path_for_adb(options, artifact)?;
    let mut push = Command::new(&options.adb);
    push.args(["-s", &options.serial, "push"])
        .arg(adb_artifact)
        .arg(&remote_binary);
    let output = command_output_bounded(
        &mut push,
        None,
        ADB_PUSH_TIMEOUT,
        MAX_ADB_CAPTURE_BYTES,
        "push Android test ELF",
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
    let mut command = Command::new(&options.adb);
    command
        .args(["-s", &options.serial, "shell", "su", "-c", "/system/bin/sh"])
        .stdin(Stdio::piped());
    let output = command_output_bounded(
        &mut command,
        Some(script.as_bytes()),
        ADB_EXEC_TIMEOUT,
        MAX_ADB_CAPTURE_BYTES,
        "run rooted Android checkpoint shell",
    )?;
    forward_output(&output)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "rooted Android exact checkpoint exited with {}",
            output.status
        ))
    }
}

fn artifact_path_for_adb(options: &Options, artifact: &Path) -> Result<OsString, String> {
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

fn remote_script(remote: &str, expected_device: &DeviceProfile) -> String {
    let root = shell_single_quote(remote);
    let test = shell_single_quote(LINUX_OUTPUT_TPROXY_CANARY_TEST);
    let expected_boot_id = shell_single_quote(&expected_device.boot_id);
    let expected_fingerprint = shell_single_quote(&expected_device.build_fingerprint);
    let internal_envs = LINUX_CANARY_INTERNAL_ENVS.join(" ");
    format!(
        "set -eu\n\
         umask 077\n\
         ROOT={root}\n\
         BIN=\"$ROOT/{REMOTE_BINARY_NAME}\"\n\
         TMPDIR=\"$ROOT/tmp\"\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         EXPECTED_BOOT_ID={expected_boot_id}\n\
         EXPECTED_FINGERPRINT={expected_fingerprint}\n\
         if [ \"$(/system/bin/cat /proc/sys/kernel/random/boot_id)\" != \"$EXPECTED_BOOT_ID\" ] || \
            [ \"$(/system/bin/getprop ro.build.fingerprint)\" != \"$EXPECTED_FINGERPRINT\" ]; then\n\
           echo \"exact Android device identity changed before rooted execution\" >&2\n\
           exit 70\n\
         fi\n\
         cleanup() {{ rm -rf \"$ROOT\"; }}\n\
         trap cleanup EXIT HUP INT TERM\n\
         chown -R 0:0 \"$ROOT\"\n\
         chmod 700 \"$ROOT\" \"$BIN\"\n\
         mkdir \"$TMPDIR\"\n\
         chmod 700 \"$TMPDIR\"\n\
         export TMPDIR\n\
         unset {internal_envs}\n\
         export FLUX_LINUX_CANARY_REQUIRED=1\n\
         TEST={test}\n\
         LIST_FILE=\"$TMPDIR/list\"\n\
         if ! \"$BIN\" --ignored --exact \"$TEST\" --list >\"$LIST_FILE\"; then\n\
           echo \"exact Android checkpoint list command failed\" >&2\n\
           exit 70\n\
         fi\n\
         LIST_OUTPUT=$(tr -d '\\r' <\"$LIST_FILE\")\n\
         printf '%s\\n' \"$LIST_OUTPUT\"\n\
         EXPECTED_LIST=$(printf '%s: test\\n\\n1 test, 0 benchmarks' \"$TEST\")\n\
         if [ \"$LIST_OUTPUT\" != \"$EXPECTED_LIST\" ]; then\n\
           echo \"exact Android checkpoint list contract mismatch\" >&2\n\
           exit 70\n\
         fi\n\
         timeout -k {REMOTE_TEST_KILL_GRACE_SECONDS} {REMOTE_TEST_TIMEOUT_SECONDS} \"$BIN\" --ignored --exact \"$TEST\" --nocapture --test-threads=1\n"
    )
}

fn cleanup_remote_directory(
    options: &Options,
    expected_device: &DeviceProfile,
    remote: &str,
) -> Result<(), String> {
    revalidate_device(options, expected_device, "before remote cleanup")?;
    let expected_boot_id = shell_single_quote(&expected_device.boot_id);
    let remove = format!(
        "test \"$(/system/bin/cat /proc/sys/kernel/random/boot_id)\" = {expected_boot_id} && /system/bin/rm -rf {remote}"
    );
    adb_success_with_timeout(
        options,
        &["-s", &options.serial, "shell", "su", "-c", &remove],
        ADB_CLEANUP_TIMEOUT,
    )?;
    revalidate_device(options, expected_device, "after remote cleanup mutation")?;
    let absent = format!("test ! -e {remote}");
    adb_success_with_timeout(
        options,
        &["-s", &options.serial, "shell", "su", "-c", &absent],
        ADB_CLEANUP_TIMEOUT,
    )
    .map_err(|error| {
        format!("remote cleanup could not prove {remote} absent; inspect it manually: {error}")
    })?;
    revalidate_device(options, expected_device, "after remote cleanup proof")
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

fn adb_success_with_timeout(
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
        MAX_ADB_CAPTURE_BYTES,
        description,
    )
}

fn command_output_bounded(
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
    format!("{} {}", options.adb.to_string_lossy(), arguments.join(" "))
}

fn forward_output(output: &Output) -> Result<(), String> {
    std::io::stdout()
        .write_all(&output.stdout)
        .and_then(|()| std::io::stderr().write_all(&output.stderr))
        .map_err(|error| format!("forward ADB output: {error}"))
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
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
            model: "Windows Subsystem for Android".to_owned(),
            sdk: 33,
            abi: "x86_64,arm64-v8a".to_owned(),
            kernel_arch: "x86_64".to_owned(),
            kernel_release: "5.15.104-wsa".to_owned(),
            build_fingerprint: "flux/wsa/device:13/test-keys".to_owned(),
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
        }
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
        assert!(parse_options(&[]).is_err());
        assert!(
            parse_options(&[OsString::from("--serial"), OsString::from("unsafe serial"),]).is_err()
        );
    }

    #[test]
    fn cargo_json_selects_one_exact_library_test_executable() {
        let messages = br#"{"reason":"compiler-artifact","target":{"name":"fluxd","kind":["lib"]},"profile":{"test":true},"executable":"/tmp/fluxd-test"}
{"reason":"build-finished","success":true}
"#;
        assert_eq!(
            test_artifact_from_cargo_messages(messages).expect("one artifact"),
            PathBuf::from("/tmp/fluxd-test")
        );
        assert!(test_artifact_from_cargo_messages(b"{}").is_err());
    }

    #[test]
    fn android_test_build_uses_pinned_compiler_for_rust_and_native_code() {
        let linker = Path::new("/ndk/toolchains/llvm/bin/x86_64-linux-android31-clang");
        let command = android_test_build_command(linker);
        let environment = command
            .get_envs()
            .collect::<std::collections::BTreeMap<_, _>>();

        assert_eq!(
            environment.get(std::ffi::OsStr::new(
                "CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER"
            )),
            Some(&Some(linker.as_os_str()))
        );
        assert_eq!(
            environment.get(std::ffi::OsStr::new("CC_x86_64_linux_android")),
            Some(&Some(linker.as_os_str()))
        );
        assert_eq!(
            environment.get(std::ffi::OsStr::new(
                "CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS"
            )),
            Some(&Some(std::ffi::OsStr::new(ANDROID_RUSTFLAGS)))
        );
        assert_eq!(
            environment.get(std::ffi::OsStr::new("TMPDIR")),
            Some(&Some(std::ffi::OsStr::new(HOST_BUILD_TMPDIR)))
        );
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
        assert_eq!(ADB_PUSH_TIMEOUT, Duration::from_secs(120));
        assert_eq!(REMOTE_TEST_TIMEOUT_SECONDS, 90);
        assert_eq!(REMOTE_TEST_KILL_GRACE_SECONDS, 5);
        assert_eq!(HOST_POLL_INTERVAL, Duration::from_millis(25));
        assert_eq!(HOST_OUTPUT_DRAIN_GRACE, Duration::from_secs(2));
        assert!(ADB_QUERY_TIMEOUT < ADB_CLEANUP_TIMEOUT);
        assert!(
            Duration::from_secs(REMOTE_TEST_TIMEOUT_SECONDS + REMOTE_TEST_KILL_GRACE_SECONDS)
                < ADB_EXEC_TIMEOUT
        );
        assert!(ADB_EXEC_TIMEOUT < ADB_PUSH_TIMEOUT);
        assert!(ADB_PUSH_TIMEOUT < CARGO_BUILD_TIMEOUT);
        assert!(HOST_POLL_INTERVAL < ADB_QUERY_TIMEOUT);
    }

    #[test]
    fn remote_contract_is_exact_and_fixed_to_private_data_local_tmp() {
        assert!(valid_remote_directory(
            "/data/local/tmp/flux-output-tproxy.a1B2c3"
        ));
        assert!(!valid_remote_directory(
            "/data/local/tmp/flux-output-tproxy.a1B2c3/extra"
        ));
        let device = expected_device_profile();
        let script = remote_script("/data/local/tmp/flux-output-tproxy.a1B2c3", &device);
        let internal_envs = LINUX_CANARY_INTERNAL_ENVS.join(" ");
        let expected = format!(
            "set -eu\n\
             umask 077\n\
             ROOT='/data/local/tmp/flux-output-tproxy.a1B2c3'\n\
             BIN=\"$ROOT/{REMOTE_BINARY_NAME}\"\n\
             TMPDIR=\"$ROOT/tmp\"\n\
             export PATH='{TRUSTED_ANDROID_PATH}'\n\
             EXPECTED_BOOT_ID='01234567-89ab-cdef-0123-456789abcdef'\n\
             EXPECTED_FINGERPRINT='flux/wsa/device:13/test-keys'\n\
             if [ \"$(/system/bin/cat /proc/sys/kernel/random/boot_id)\" != \"$EXPECTED_BOOT_ID\" ] || \
                [ \"$(/system/bin/getprop ro.build.fingerprint)\" != \"$EXPECTED_FINGERPRINT\" ]; then\n\
               echo \"exact Android device identity changed before rooted execution\" >&2\n\
               exit 70\n\
             fi\n\
             cleanup() {{ rm -rf \"$ROOT\"; }}\n\
             trap cleanup EXIT HUP INT TERM\n\
             chown -R 0:0 \"$ROOT\"\n\
             chmod 700 \"$ROOT\" \"$BIN\"\n\
             mkdir \"$TMPDIR\"\n\
             chmod 700 \"$TMPDIR\"\n\
             export TMPDIR\n\
             unset {internal_envs}\n\
             export FLUX_LINUX_CANARY_REQUIRED=1\n\
             TEST='{LINUX_OUTPUT_TPROXY_CANARY_TEST}'\n\
             LIST_FILE=\"$TMPDIR/list\"\n\
             if ! \"$BIN\" --ignored --exact \"$TEST\" --list >\"$LIST_FILE\"; then\n\
               echo \"exact Android checkpoint list command failed\" >&2\n\
               exit 70\n\
             fi\n\
             LIST_OUTPUT=$(tr -d '\\r' <\"$LIST_FILE\")\n\
             printf '%s\\n' \"$LIST_OUTPUT\"\n\
             EXPECTED_LIST=$(printf '%s: test\\n\\n1 test, 0 benchmarks' \"$TEST\")\n\
             if [ \"$LIST_OUTPUT\" != \"$EXPECTED_LIST\" ]; then\n\
               echo \"exact Android checkpoint list contract mismatch\" >&2\n\
               exit 70\n\
             fi\n\
             timeout -k {REMOTE_TEST_KILL_GRACE_SECONDS} {REMOTE_TEST_TIMEOUT_SECONDS} \"$BIN\" --ignored --exact \"$TEST\" --nocapture --test-threads=1\n"
        );
        assert_eq!(script, expected);
        assert!(!script.contains("sudo"));
        assert!(uses_windows_adb(&OsString::from("adb.exe")));
        assert!(uses_windows_adb(&OsString::from(
            "/mnt/c/Android/platform-tools/ADB.EXE"
        )));
        assert!(!uses_windows_adb(&OsString::from("custom-adb")));
        assert!(!uses_windows_adb(&OsString::from("adb")));
        assert_eq!(shell_single_quote("flux/o'hare"), "'flux/o'\\''hare'");
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
