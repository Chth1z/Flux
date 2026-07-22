use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::io::Write;
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};

use flux_platform::internal::{
    ANDROID_IDENTITY_PROPERTY_NAMES, MAX_ANDROID_IDENTITY_PROPERTY_BYTES,
    validate_android_identity_properties, validate_android_verified_boot_properties,
};

use super::android_canary::{self, Options};

const COMMAND: &str = "preflight-android-arm64-mark-ordering";
const MINIMUM_ANDROID_SDK: u32 = 31;
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(30);
const SNAPSHOT_HEADER: &str = "FLUX_ANDROID_MARK_PREFLIGHT_V1";
const SNAPSHOT_COMPLETE: &str = "FLUX_ANDROID_MARK_PREFLIGHT_COMPLETE";
const IPV4_BEGIN: &str = "FLUX_IPV4_MANGLE_BEGIN";
const IPV4_END: &str = "FLUX_IPV4_MANGLE_END";
const IPV6_BEGIN: &str = "FLUX_IPV6_MANGLE_BEGIN";
const IPV6_END: &str = "FLUX_IPV6_MANGLE_END";
const ROUTECTRL_INPUT_CHAIN: &str = "routectrl_mangle_INPUT";
const ANDROID_12_13_INCOMING_MASK: u32 = 0xffef_ffff;
const PINNED_2025_INCOMING_MASK: u32 = 0x7fef_ffff;
const FLUX_CANDIDATE_ENVELOPE: u32 = 0x7fe0_0000;
const MAX_MANGLE_LINES: usize = 4_096;
const MAX_MANGLE_LINE_BYTES: usize = 8 * 1_024;
const MAX_INCOMING_WRITERS: usize = 256;
const EMULATOR_PROPERTY: &str = "ro.kernel.qemu";
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

pub(super) fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    Options::parse(arguments, COMMAND)
}

pub(super) fn run(options: Options) -> Result<(), String> {
    if env::consts::OS != "linux" {
        return Err("the Android ARM64 mark preflight requires a Linux/WSL host".to_owned());
    }

    let before = collect_device_profile(&options)?;
    let script = remote_snapshot_script();
    let output = android_canary::adb_root_shell_output(
        &options,
        script.as_bytes(),
        SNAPSHOT_TIMEOUT,
        "collect read-only Android mark-ordering preflight snapshot",
    )?;
    if !output.status.success() {
        return Err(format!(
            "read-only Android mark-ordering snapshot exited with {}: stdout_bytes={} stdout_sha256={} stderr={}",
            output.status,
            output.stdout.len(),
            hex_digest(&output.stdout),
            android_canary::bounded_diagnostic(&output.stderr),
        ));
    }
    if !output.stderr.is_empty() {
        std::io::stderr()
            .write_all(&output.stderr)
            .map_err(|error| format!("forward Android preflight stderr: {error}"))?;
    }
    let snapshot = parse_remote_snapshot(&output.stdout)?;
    let after = collect_device_profile(&options)
        .map_err(|error| format!("revalidate Android device after read-only snapshot: {error}"))?;
    if before != after {
        return Err(format!(
            "ADB serial {} changed identity during read-only preflight; before={before:?} after={after:?}",
            options.serial()
        ));
    }
    if snapshot.boot_id_before != before.boot_id
        || snapshot.boot_id_after != before.boot_id
        || snapshot.fingerprint_before != before.build_fingerprint
        || snapshot.fingerprint_after != before.build_fingerprint
    {
        return Err(
            "rooted snapshot did not bind the exact host-observed boot and fingerprint".to_owned(),
        );
    }

    let report = build_report(options.serial(), before, snapshot);
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("encode Android mark preflight report: {error}"))?
    );
    if report.blocking_reasons.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Android mark-ordering target is not yet viable: {}",
            report.blocking_reasons.join("; ")
        ))
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

fn collect_device_profile(options: &Options) -> Result<DeviceProfile, String> {
    let state = adb_text(options, &["get-state"])?;
    if state != "device" {
        return Err(format!(
            "ADB serial {} is not ready: state={state:?}",
            options.serial()
        ));
    }
    let root = adb_text(options, &["shell", "su", "-c", "id"])?;
    if !root
        .split_whitespace()
        .any(|field| field.starts_with("uid=0("))
    {
        return Err(format!(
            "ADB serial {} did not provide Magisk/root UID 0: {root:?}",
            options.serial()
        ));
    }

    let model = validated_adb_text(
        options,
        &["shell", "getprop", "ro.product.model"],
        "product model",
        256,
    )?;
    let abi_list = validated_adb_text(
        options,
        &["shell", "getprop", "ro.product.cpu.abilist"],
        "ABI list",
        1_024,
    )?;
    let kernel_arch = validated_adb_text(
        options,
        &["shell", "uname", "-m"],
        "kernel architecture",
        64,
    )?;
    let kernel_release =
        validated_adb_text(options, &["shell", "uname", "-r"], "kernel release", 256)?;
    let sdk_text = validated_adb_text(
        options,
        &["shell", "getprop", "ro.build.version.sdk"],
        "SDK level",
        16,
    )?;
    let sdk = sdk_text
        .parse::<u32>()
        .map_err(|error| format!("parse Android SDK {sdk_text:?}: {error}"))?;
    let build_fingerprint = validated_adb_text(
        options,
        &["shell", "getprop", "ro.build.fingerprint"],
        "build fingerprint",
        1_024,
    )?;
    let boot_id = validated_adb_text(
        options,
        &["shell", "cat", "/proc/sys/kernel/random/boot_id"],
        "boot ID",
        64,
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

fn adb_text(options: &Options, arguments: &[&str]) -> Result<String, String> {
    let mut selected = vec!["-s", options.serial()];
    selected.extend_from_slice(arguments);
    android_canary::adb_text(options, &selected)
}

fn validated_adb_text(
    options: &Options,
    arguments: &[&str],
    label: &str,
    maximum_bytes: usize,
) -> Result<String, String> {
    let value = adb_text(options, arguments)?;
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(format!(
            "Android {label} must be one non-empty control-free line of at most {maximum_bytes} bytes, got {value:?}"
        ));
    }
    Ok(value)
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

fn preflight_property_names() -> impl Iterator<Item = &'static str> {
    ANDROID_IDENTITY_PROPERTY_NAMES
        .into_iter()
        .chain([EMULATOR_PROPERTY])
}

fn remote_snapshot_script() -> String {
    let properties = preflight_property_names()
        .map(|name| format!("property {name}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "set -eu\n\
         export PATH='{TRUSTED_ANDROID_PATH}'\n\
         property() {{ value=$(/system/bin/getprop \"$1\"); printf 'property.%s=%s\\n' \"$1\" \"$value\"; }}\n\
         readable() {{ if [ -r \"$2\" ]; then printf 'artifact.%s=1\\n' \"$1\"; else printf 'artifact.%s=0\\n' \"$1\"; fi; }}\n\
         tool() {{ if command -v \"$2\" >/dev/null 2>&1; then printf 'tool.%s=1\\n' \"$1\"; else printf 'tool.%s=0\\n' \"$1\"; fi; }}\n\
         printf '{SNAPSHOT_HEADER}\\n'\n\
         printf 'boot_id_before=%s\\n' \"$(/system/bin/cat /proc/sys/kernel/random/boot_id)\"\n\
         printf 'fingerprint_before=%s\\n' \"$(/system/bin/getprop ro.build.fingerprint)\"\n\
         printf 'selinux_mode=%s\\n' \"$(getenforce)\"\n\
         printf 'pid1_netns=%s\\n' \"$(readlink /proc/1/ns/net)\"\n\
         printf 'self_netns=%s\\n' \"$(readlink /proc/self/ns/net)\"\n\
         readable selinux_policy /sys/fs/selinux/policy\n\
         readable netd /system/bin/netd\n\
         readable apex_info /apex/apex-info-list.xml\n\
         tool iptables_save iptables-save\n\
         tool ip6tables_save ip6tables-save\n\
         if [ -r /proc/net/ip_tables_names ] && grep -qx mangle /proc/net/ip_tables_names; then printf 'ipv4_table_initialized=1\\n'; else printf 'ipv4_table_initialized=0\\n'; fi\n\
         if [ -r /proc/net/ip6_tables_names ] && grep -qx mangle /proc/net/ip6_tables_names; then printf 'ipv6_table_initialized=1\\n'; else printf 'ipv6_table_initialized=0\\n'; fi\n\
         {properties}\n\
         printf '{IPV4_BEGIN}\\n'\n\
         if [ -r /proc/net/ip_tables_names ] && grep -qx mangle /proc/net/ip_tables_names && command -v iptables-save >/dev/null 2>&1; then iptables-save -t mangle; fi\n\
         printf '{IPV4_END}\\n'\n\
         printf '{IPV6_BEGIN}\\n'\n\
         if [ -r /proc/net/ip6_tables_names ] && grep -qx mangle /proc/net/ip6_tables_names && command -v ip6tables-save >/dev/null 2>&1; then ip6tables-save -t mangle; fi\n\
         printf '{IPV6_END}\\n'\n\
         printf 'boot_id_after=%s\\n' \"$(/system/bin/cat /proc/sys/kernel/random/boot_id)\"\n\
         printf 'fingerprint_after=%s\\n' \"$(/system/bin/getprop ro.build.fingerprint)\"\n\
         printf '{SNAPSHOT_COMPLETE}\\n'\n"
    )
}

#[derive(Debug, Eq, PartialEq)]
struct RemoteSnapshot {
    boot_id_before: String,
    boot_id_after: String,
    fingerprint_before: String,
    fingerprint_after: String,
    selinux_mode: String,
    pid1_netns: String,
    self_netns: String,
    selinux_policy_readable: bool,
    netd_readable: bool,
    apex_info_readable: bool,
    iptables_save_available: bool,
    ip6tables_save_available: bool,
    ipv4_table_initialized: bool,
    ipv6_table_initialized: bool,
    properties: BTreeMap<String, String>,
    ipv4_mangle: String,
    ipv6_mangle: String,
}

fn parse_remote_snapshot(bytes: &[u8]) -> Result<RemoteSnapshot, String> {
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|error| format!("Android preflight snapshot is not UTF-8: {error}"))?;
    let text = normalize_line_endings(&text)?;
    let text = text
        .strip_prefix(&format!("{SNAPSHOT_HEADER}\n"))
        .ok_or_else(|| "Android preflight snapshot header is missing".to_owned())?;
    let (metadata, rest) = text
        .split_once(&format!("{IPV4_BEGIN}\n"))
        .ok_or_else(|| "Android preflight IPv4 begin marker is missing".to_owned())?;
    let (ipv4_mangle, rest) = rest
        .split_once(&format!("{IPV4_END}\n"))
        .ok_or_else(|| "Android preflight IPv4 end marker is missing".to_owned())?;
    let rest = rest
        .strip_prefix(&format!("{IPV6_BEGIN}\n"))
        .ok_or_else(|| "Android preflight IPv6 begin marker is misplaced".to_owned())?;
    let (ipv6_mangle, tail) = rest
        .split_once(&format!("{IPV6_END}\n"))
        .ok_or_else(|| "Android preflight IPv6 end marker is missing".to_owned())?;
    let tail = tail
        .strip_suffix(&format!("{SNAPSHOT_COMPLETE}\n"))
        .ok_or_else(|| "Android preflight completion marker is missing".to_owned())?;

    let mut fields = parse_fields(metadata)?;
    fields.extend(parse_fields(tail)?);
    let mut properties = BTreeMap::new();
    for name in preflight_property_names() {
        let key = format!("property.{name}");
        let value = take_field(&mut fields, &key)?;
        if value.len() > MAX_ANDROID_IDENTITY_PROPERTY_BYTES {
            return Err(format!(
                "Android preflight property {name:?} exceeds {MAX_ANDROID_IDENTITY_PROPERTY_BYTES} bytes"
            ));
        }
        properties.insert(name.to_owned(), value);
    }
    let snapshot = RemoteSnapshot {
        boot_id_before: take_field(&mut fields, "boot_id_before")?,
        boot_id_after: take_field(&mut fields, "boot_id_after")?,
        fingerprint_before: take_field(&mut fields, "fingerprint_before")?,
        fingerprint_after: take_field(&mut fields, "fingerprint_after")?,
        selinux_mode: take_field(&mut fields, "selinux_mode")?,
        pid1_netns: take_field(&mut fields, "pid1_netns")?,
        self_netns: take_field(&mut fields, "self_netns")?,
        selinux_policy_readable: take_bool(&mut fields, "artifact.selinux_policy")?,
        netd_readable: take_bool(&mut fields, "artifact.netd")?,
        apex_info_readable: take_bool(&mut fields, "artifact.apex_info")?,
        iptables_save_available: take_bool(&mut fields, "tool.iptables_save")?,
        ip6tables_save_available: take_bool(&mut fields, "tool.ip6tables_save")?,
        ipv4_table_initialized: take_bool(&mut fields, "ipv4_table_initialized")?,
        ipv6_table_initialized: take_bool(&mut fields, "ipv6_table_initialized")?,
        properties,
        ipv4_mangle: ipv4_mangle.to_owned(),
        ipv6_mangle: ipv6_mangle.to_owned(),
    };
    if fields.is_empty() {
        Ok(snapshot)
    } else {
        Err(format!(
            "Android preflight snapshot contains {} unknown fields",
            fields.len()
        ))
    }
}

fn normalize_line_endings(text: &str) -> Result<String, String> {
    let normalized = text.replace("\r\n", "\n");
    if normalized.contains('\r') {
        Err("Android preflight snapshot contains a bare carriage return".to_owned())
    } else if normalized.ends_with('\n') {
        Ok(normalized)
    } else {
        Err("Android preflight snapshot is missing its final line feed".to_owned())
    }
}

fn parse_fields(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut fields = BTreeMap::new();
    for (line_index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!(
                "Android preflight field on line {} lacks '='",
                line_index + 1
            )
        })?;
        if key.is_empty()
            || key.chars().any(char::is_control)
            || value.chars().any(char::is_control)
        {
            return Err(format!(
                "Android preflight field on line {} is malformed",
                line_index + 1
            ));
        }
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!(
                "Android preflight field on line {} is duplicated",
                line_index + 1
            ));
        }
    }
    Ok(fields)
}

fn take_field(fields: &mut BTreeMap<String, String>, key: &str) -> Result<String, String> {
    fields
        .remove(key)
        .ok_or_else(|| format!("Android preflight field {key:?} is missing"))
}

fn take_bool(fields: &mut BTreeMap<String, String>, key: &str) -> Result<bool, String> {
    match take_field(fields, key)?.as_str() {
        "0" => Ok(false),
        "1" => Ok(true),
        value => Err(format!(
            "Android preflight boolean field {key:?} has value {value:?}"
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Disposition {
    ViableForFullQualification,
    Blocked,
}

#[derive(Debug, Serialize)]
struct PreflightReport {
    schema_version: u16,
    authority: &'static str,
    disposition: Disposition,
    serial: String,
    device: DeviceReport,
    profile_inputs: ProfileInputReport,
    ipv4: FamilyReport,
    ipv6: FamilyReport,
    blocking_reasons: Vec<String>,
    deferred_qualification: [&'static str; 4],
}

#[derive(Debug, Serialize)]
struct DeviceReport {
    model: String,
    sdk: u32,
    abi_list: String,
    kernel_arch: String,
    kernel_release: String,
    build_fingerprint: String,
    boot_id: String,
    selinux_mode: String,
    network_namespace: String,
}

#[derive(Debug, Serialize)]
struct ProfileInputReport {
    required_properties_present: bool,
    verified_boot_inputs_complete: bool,
    selinux_policy_readable: bool,
    netd_readable: bool,
    apex_info_readable: bool,
}

#[derive(Debug, Serialize)]
struct FamilyReport {
    family: &'static str,
    table_initialized: bool,
    save_tool_available: bool,
    snapshot_sha256: Option<String>,
    chain_declarations: usize,
    input_hook_ordinal: Option<u32>,
    input_hook_references: usize,
    writer_count: usize,
    writer_interfaces: Vec<String>,
    writer_mask: Option<String>,
    mask_semantics: Option<MaskSemantics>,
    unknown_child_rules: usize,
    blocking_reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MaskSemantics {
    Android12Or13IncomingWriter,
    PinnedMarch2025IncomingWriter,
}

fn build_report(serial: &str, device: DeviceProfile, snapshot: RemoteSnapshot) -> PreflightReport {
    let mut blocking_reasons = Vec::new();
    if !device
        .abi_list
        .split(',')
        .any(|abi| abi.trim() == "arm64-v8a")
    {
        blocking_reasons.push("device does not advertise arm64-v8a".to_owned());
    }
    if !matches!(device.kernel_arch.as_str(), "aarch64" | "arm64") {
        blocking_reasons.push(format!(
            "kernel architecture {:?} is not ARM64",
            device.kernel_arch
        ));
    }
    if device.sdk < MINIMUM_ANDROID_SDK {
        blocking_reasons.push(format!(
            "Android SDK {} is below {}",
            device.sdk, MINIMUM_ANDROID_SDK
        ));
    }
    if !kernel_meets_floor(&device.kernel_release) {
        blocking_reasons.push(format!(
            "kernel release {:?} is below or outside the Linux 5.10 floor grammar",
            device.kernel_release
        ));
    }
    if snapshot.selinux_mode != "Enforcing" {
        blocking_reasons.push(format!(
            "SELinux mode {:?} is not Enforcing",
            snapshot.selinux_mode
        ));
    }
    if snapshot.pid1_netns != snapshot.self_netns {
        blocking_reasons
            .push("rooted preflight shell is not in PID 1's network namespace".to_owned());
    }
    if snapshot
        .properties
        .get(EMULATOR_PROPERTY)
        .is_some_and(|value| value == "1")
    {
        blocking_reasons.push("ro.kernel.qemu=1 identifies an emulator target".to_owned());
    }

    let required_properties_present = validate_android_identity_properties(|name| {
        preflight_identity_property(&snapshot.properties, name)
    })
    .is_ok();
    if !required_properties_present {
        blocking_reasons.push(
            "production Android identity collector properties are missing or malformed".to_owned(),
        );
    }
    if snapshot.properties.get("ro.build.fingerprint") != Some(&device.build_fingerprint) {
        blocking_reasons.push(
            "rooted property snapshot does not match the boundary build fingerprint".to_owned(),
        );
    }
    let verified_boot_inputs_complete = verified_boot_inputs_complete(&snapshot.properties);
    if !verified_boot_inputs_complete {
        blocking_reasons.push(
            "verified-boot inputs are not recognized, internally consistent, nonzero SHA-256 facts"
                .to_owned(),
        );
    }
    for (available, label) in [
        (snapshot.selinux_policy_readable, "SELinux policy"),
        (snapshot.netd_readable, "netd artifact"),
        (snapshot.apex_info_readable, "APEX info"),
    ] {
        if !available {
            blocking_reasons.push(format!("{label} is not readable by the rooted preflight"));
        }
    }

    let ipv4 = build_family_report(
        "ipv4",
        snapshot.ipv4_table_initialized,
        snapshot.iptables_save_available,
        &snapshot.ipv4_mangle,
    );
    let ipv6 = build_family_report(
        "ipv6",
        snapshot.ipv6_table_initialized,
        snapshot.ip6tables_save_available,
        &snapshot.ipv6_mangle,
    );
    blocking_reasons.extend(
        ipv4.blocking_reasons
            .iter()
            .map(|reason| format!("IPv4: {reason}")),
    );
    blocking_reasons.extend(
        ipv6.blocking_reasons
            .iter()
            .map(|reason| format!("IPv6: {reason}")),
    );
    if ipv4.writer_mask.is_some()
        && ipv6.writer_mask.is_some()
        && ipv4.writer_mask != ipv6.writer_mask
    {
        blocking_reasons.push("IPv4 and IPv6 incoming writers use different masks".to_owned());
    }
    if !ipv4.writer_interfaces.is_empty()
        && !ipv6.writer_interfaces.is_empty()
        && ipv4.writer_interfaces != ipv6.writer_interfaces
    {
        blocking_reasons
            .push("IPv4 and IPv6 incoming writers select different interface sets".to_owned());
    }

    let disposition = if blocking_reasons.is_empty() {
        Disposition::ViableForFullQualification
    } else {
        Disposition::Blocked
    };
    PreflightReport {
        schema_version: 1,
        authority: "diagnostic_only_no_authority_conversion",
        disposition,
        serial: serial.to_owned(),
        device: DeviceReport {
            model: device.model,
            sdk: device.sdk,
            abi_list: device.abi_list,
            kernel_arch: device.kernel_arch,
            kernel_release: device.kernel_release,
            build_fingerprint: device.build_fingerprint,
            boot_id: device.boot_id,
            selinux_mode: snapshot.selinux_mode,
            network_namespace: snapshot.self_netns,
        },
        profile_inputs: ProfileInputReport {
            required_properties_present,
            verified_boot_inputs_complete,
            selinux_policy_readable: snapshot.selinux_policy_readable,
            netd_readable: snapshot.netd_readable,
            apex_info_readable: snapshot.apex_info_readable,
        },
        ipv4,
        ipv6,
        blocking_reasons,
        deferred_qualification: [
            "runtime_artifact_digest_and_source_profile_binding",
            "exact_capture_hook_and_route_order_binding",
            "listener_observer_mark_preservation_canary",
            "vpn_netd_coexistence_canary",
        ],
    }
}

fn verified_boot_inputs_complete(properties: &BTreeMap<String, String>) -> bool {
    validate_android_verified_boot_properties(|name| preflight_identity_property(properties, name))
        .is_ok()
}

fn preflight_identity_property<'a>(
    properties: &'a BTreeMap<String, String>,
    name: &'static str,
) -> Option<Option<&'a [u8]>> {
    properties
        .get(name)
        .map(|value| (!value.is_empty()).then_some(value.as_bytes()))
}

fn kernel_meets_floor(release: &str) -> bool {
    let mut components = release.split('.');
    let Some(major) = components.next().and_then(decimal_component) else {
        return false;
    };
    let Some(minor) = components.next().and_then(decimal_component) else {
        return false;
    };
    if components.next().and_then(decimal_prefix).is_none() {
        return false;
    }
    (major, minor) >= (5, 10)
}

fn decimal_component(component: &str) -> Option<u32> {
    (!component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| component.parse::<u32>().ok())
        .flatten()
}

fn decimal_prefix(component: &str) -> Option<u32> {
    let digits = component
        .bytes()
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    (!digits.is_empty())
        .then(|| std::str::from_utf8(&digits).ok()?.parse::<u32>().ok())
        .flatten()
}

fn build_family_report(
    family: &'static str,
    table_initialized: bool,
    save_tool_available: bool,
    dump: &str,
) -> FamilyReport {
    let mut report = FamilyReport {
        family,
        table_initialized,
        save_tool_available,
        snapshot_sha256: None,
        chain_declarations: 0,
        input_hook_ordinal: None,
        input_hook_references: 0,
        writer_count: 0,
        writer_interfaces: Vec::new(),
        writer_mask: None,
        mask_semantics: None,
        unknown_child_rules: 0,
        blocking_reasons: Vec::new(),
    };
    if !table_initialized {
        report
            .blocking_reasons
            .push("mangle table was not already initialized".to_owned());
    }
    if !save_tool_available {
        report
            .blocking_reasons
            .push("legacy tables save tool is unavailable".to_owned());
    }
    if !table_initialized || !save_tool_available {
        if !dump.is_empty() {
            report.blocking_reasons.push(
                "snapshot bytes were returned despite an unavailable table or save tool".to_owned(),
            );
        }
        return report;
    }
    report.snapshot_sha256 = Some(hex_digest(dump.as_bytes()));
    let observation = match parse_mangle_dump(dump) {
        Ok(observation) => observation,
        Err(error) => {
            report
                .blocking_reasons
                .push(format!("invalid mangle snapshot: {error}"));
            return report;
        }
    };
    report.chain_declarations = observation.chain_declarations;
    report.input_hook_references = observation.input_hook_references;
    report.input_hook_ordinal = observation.input_hook_ordinal;
    report.writer_count = observation.writer_count;
    report.writer_interfaces = observation.writer_interfaces;
    report.unknown_child_rules = observation.unknown_child_rules;
    if observation.chain_declarations != 1 {
        report.blocking_reasons.push(format!(
            "routectrl_mangle_INPUT has {} declarations rather than exactly one",
            observation.chain_declarations
        ));
    }
    if observation.input_hook_references != 1 || observation.input_hook_ordinal.is_none() {
        report.blocking_reasons.push(
            "routectrl_mangle_INPUT must have exactly one reference: an unconditional built-in INPUT jump"
                .to_owned(),
        );
    }
    if observation.writer_count == 0 {
        report
            .blocking_reasons
            .push("no incoming packet MARK writer is currently observable".to_owned());
    }
    if observation.writer_count != report.writer_interfaces.len() {
        report
            .blocking_reasons
            .push("incoming packet writers contain duplicate interface selectors".to_owned());
    }
    if observation.unknown_child_rules != 0 {
        report.blocking_reasons.push(format!(
            "routectrl_mangle_INPUT contains {} unknown rules",
            observation.unknown_child_rules
        ));
    }
    if observation.writer_masks.len() != 1 {
        report.blocking_reasons.push(format!(
            "incoming packet writers use {} distinct masks",
            observation.writer_masks.len()
        ));
    } else {
        let mask = *observation
            .writer_masks
            .iter()
            .next()
            .expect("one mask checked above");
        report.writer_mask = Some(format!("0x{mask:08x}"));
        report.mask_semantics = match mask {
            ANDROID_12_13_INCOMING_MASK => Some(MaskSemantics::Android12Or13IncomingWriter),
            PINNED_2025_INCOMING_MASK => Some(MaskSemantics::PinnedMarch2025IncomingWriter),
            _ => {
                report.blocking_reasons.push(format!(
                    "incoming packet writer mask 0x{mask:08x} is not source-pinned"
                ));
                None
            }
        };
    }
    report
}

#[derive(Debug, Eq, PartialEq)]
struct MangleObservation {
    chain_declarations: usize,
    input_hook_references: usize,
    input_hook_ordinal: Option<u32>,
    writer_count: usize,
    writer_interfaces: Vec<String>,
    writer_masks: BTreeSet<u32>,
    unknown_child_rules: usize,
}

fn parse_mangle_dump(dump: &str) -> Result<MangleObservation, String> {
    if dump.is_empty() || !dump.ends_with('\n') || !dump.is_ascii() {
        return Err("snapshot must be non-empty ASCII with a final line feed".to_owned());
    }
    let mut in_mangle = false;
    let mut saw_mangle = false;
    let mut saw_commit = false;
    let mut chain_declarations = 0_usize;
    let mut input_ordinal = 0_u32;
    let mut input_hook_references = 0_usize;
    let mut input_hook_ordinal = None;
    let mut writer_count = 0_usize;
    let mut writer_interfaces = BTreeSet::new();
    let mut writer_masks = BTreeSet::new();
    let mut unknown_child_rules = 0_usize;

    for (line_index, line) in dump.lines().enumerate() {
        if line_index >= MAX_MANGLE_LINES {
            return Err(format!("mangle snapshot exceeds {MAX_MANGLE_LINES} lines"));
        }
        if line.len() > MAX_MANGLE_LINE_BYTES {
            return Err(format!(
                "mangle line {} exceeds {MAX_MANGLE_LINE_BYTES} bytes",
                line_index + 1
            ));
        }
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line == "*mangle" {
            if saw_mangle || in_mangle {
                return Err("duplicate mangle table".to_owned());
            }
            saw_mangle = true;
            in_mangle = true;
            continue;
        }
        if line == "COMMIT" {
            if !in_mangle || saw_commit {
                return Err("misplaced or duplicate COMMIT".to_owned());
            }
            saw_commit = true;
            in_mangle = false;
            continue;
        }
        if !in_mangle {
            return Err(format!(
                "content outside mangle table on line {}",
                line_index + 1
            ));
        }
        if let Some(declaration) = line.strip_prefix(':') {
            let chain = declaration
                .split_ascii_whitespace()
                .next()
                .ok_or_else(|| format!("invalid chain declaration on line {}", line_index + 1))?;
            if chain == ROUTECTRL_INPUT_CHAIN {
                chain_declarations = chain_declarations
                    .checked_add(1)
                    .ok_or_else(|| "routectrl chain declaration count overflow".to_owned())?;
            }
            continue;
        }

        let tokens = line.split_ascii_whitespace().collect::<Vec<_>>();
        if tokens.len() < 2 || tokens[0] != "-A" {
            return Err(format!(
                "unsupported mangle syntax on line {}",
                line_index + 1
            ));
        }
        let references = rule_target_references(&tokens, ROUTECTRL_INPUT_CHAIN);
        input_hook_references = input_hook_references
            .checked_add(references)
            .ok_or_else(|| "routectrl chain reference count overflow".to_owned())?;
        if tokens[1] == "INPUT" {
            input_ordinal = input_ordinal
                .checked_add(1)
                .ok_or_else(|| "INPUT rule ordinal overflow".to_owned())?;
            if tokens == ["-A", "INPUT", "-j", ROUTECTRL_INPUT_CHAIN] {
                input_hook_ordinal = Some(input_ordinal);
            }
            continue;
        }
        if tokens[1] != ROUTECTRL_INPUT_CHAIN {
            continue;
        }
        match parse_incoming_writer(&tokens) {
            Ok(writer) => {
                writer_count = writer_count
                    .checked_add(1)
                    .filter(|count| *count <= MAX_INCOMING_WRITERS)
                    .ok_or_else(|| {
                        format!("incoming writer count exceeds {MAX_INCOMING_WRITERS}")
                    })?;
                writer_interfaces.insert(writer.interface);
                writer_masks.insert(writer.mask);
            }
            Err(()) => unknown_child_rules += 1,
        }
    }
    if !saw_mangle || !saw_commit || in_mangle {
        return Err("snapshot lacks one complete mangle transaction".to_owned());
    }
    Ok(MangleObservation {
        chain_declarations,
        input_hook_references,
        input_hook_ordinal,
        writer_count,
        writer_interfaces: writer_interfaces.into_iter().collect(),
        writer_masks,
        unknown_child_rules,
    })
}

fn rule_target_references(tokens: &[&str], target: &str) -> usize {
    tokens
        .windows(2)
        .filter(|pair| matches!(pair[0], "-j" | "-g") && pair[1] == target)
        .count()
}

struct IncomingWriter {
    interface: String,
    mask: u32,
}

fn parse_incoming_writer(tokens: &[&str]) -> Result<IncomingWriter, ()> {
    let mut interface = None;
    let mut target = None;
    let mut mark = None;
    let mut index = 2;
    while index < tokens.len() {
        let flag = tokens[index];
        let value = *tokens.get(index + 1).ok_or(())?;
        match flag {
            "-i" if interface.is_none() => interface = Some(value),
            "-j" if target.is_none() => target = Some(value),
            "--set-xmark" | "--set-mark" if mark.is_none() => mark = Some(value),
            _ => return Err(()),
        }
        index += 2;
    }
    let interface = interface.ok_or(())?;
    if interface == "lo"
        || interface.contains(['+', '!', '*'])
        || interface.is_empty()
        || interface.len() > 15
        || target != Some("MARK")
    {
        return Err(());
    }
    let (value, mask) = parse_mark(mark.ok_or(())?)?;
    if value & !mask != 0 || value & FLUX_CANDIDATE_ENVELOPE != 0 {
        return Err(());
    }
    Ok(IncomingWriter {
        interface: interface.to_owned(),
        mask,
    })
}

fn parse_mark(value: &str) -> Result<(u32, u32), ()> {
    let (value, mask) = value.split_once('/').ok_or(())?;
    Ok((parse_u32(value)?, parse_u32(mask)?))
}

fn parse_u32(value: &str) -> Result<u32, ()> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse::<u32>().map_err(|_| ()),
            |hex| u32::from_str_radix(hex, 16).map_err(|_| ()),
        )
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("write to String");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> DeviceProfile {
        DeviceProfile {
            model: "Physical ARM64".to_owned(),
            sdk: 35,
            abi_list: "arm64-v8a,armeabi-v7a".to_owned(),
            kernel_arch: "aarch64".to_owned(),
            kernel_release: "5.10.210-android13".to_owned(),
            build_fingerprint: "vendor/product/device:15/build/123:user/release-keys".to_owned(),
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
        }
    }

    fn properties() -> BTreeMap<String, String> {
        [
            ("ro.product.brand", "vendor"),
            ("ro.product.name", "product"),
            ("ro.product.device", "device"),
            (
                "ro.build.fingerprint",
                "vendor/product/device:15/build/123:user/release-keys",
            ),
            (
                "ro.vendor.build.fingerprint",
                "vendor/product/device:15/build/123:user/release-keys",
            ),
            ("ro.build.version.security_patch", "2026-07-05"),
            ("ro.boot.verifiedbootstate", "green"),
            ("ro.boot.vbmeta.device_state", "locked"),
            ("ro.boot.flash.locked", "1"),
            ("ro.boot.vbmeta.hash_alg", "sha256"),
            (
                "ro.boot.vbmeta.digest",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            ("ro.kernel.qemu", "0"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
    }

    fn mangle(mask: u32, extra_child_rule: &str) -> String {
        format!(
            "# Generated by iptables-save v1.8.11\n\
             *mangle\n\
             :INPUT ACCEPT [0:0]\n\
             :routectrl_mangle_INPUT - [0:0]\n\
             -A INPUT -j bw_mangle_INPUT\n\
             -A INPUT -j routectrl_mangle_INPUT\n\
             -A routectrl_mangle_INPUT -i rmnet_data0 -j MARK --set-xmark 0x00000064/0x{mask:08x}\n\
             -A routectrl_mangle_INPUT -i wlan0 -j MARK --set-xmark 0x00000065/0x{mask:08x}\n\
             {extra_child_rule}COMMIT\n"
        )
    }

    fn snapshot(mask: u32) -> RemoteSnapshot {
        RemoteSnapshot {
            boot_id_before: device().boot_id.clone(),
            boot_id_after: device().boot_id.clone(),
            fingerprint_before: device().build_fingerprint.clone(),
            fingerprint_after: device().build_fingerprint.clone(),
            selinux_mode: "Enforcing".to_owned(),
            pid1_netns: "net:[4026531993]".to_owned(),
            self_netns: "net:[4026531993]".to_owned(),
            selinux_policy_readable: true,
            netd_readable: true,
            apex_info_readable: true,
            iptables_save_available: true,
            ip6tables_save_available: true,
            ipv4_table_initialized: true,
            ipv6_table_initialized: true,
            properties: properties(),
            ipv4_mangle: mangle(mask, ""),
            ipv6_mangle: mangle(mask, ""),
        }
    }

    #[test]
    fn exact_dual_family_snapshot_is_only_viable_for_full_qualification() {
        let report = build_report("SERIAL", device(), snapshot(PINNED_2025_INCOMING_MASK));
        assert_eq!(report.disposition, Disposition::ViableForFullQualification);
        assert!(report.blocking_reasons.is_empty());
        assert_eq!(report.ipv4.input_hook_ordinal, Some(2));
        assert_eq!(report.ipv4.writer_count, 2);
        assert_eq!(
            report.ipv4.writer_interfaces,
            ["rmnet_data0".to_owned(), "wlan0".to_owned()]
        );
        assert_eq!(
            report.ipv4.mask_semantics,
            Some(MaskSemantics::PinnedMarch2025IncomingWriter)
        );
        assert_eq!(report.deferred_qualification.len(), 4);
        let encoded = serde_json::to_string(&report).expect("serialize report");
        assert!(encoded.contains("diagnostic_only_no_authority_conversion"));
        assert!(encoded.contains("viable_for_full_qualification"));
    }

    #[test]
    fn rooted_property_snapshot_must_match_the_boundary_fingerprint() {
        let mut snapshot = snapshot(PINNED_2025_INCOMING_MASK);
        snapshot.properties.insert(
            "ro.build.fingerprint".to_owned(),
            "vendor/product/device:15/build/changed:user/release-keys".to_owned(),
        );
        let report = build_report("SERIAL", device(), snapshot);
        assert_eq!(report.disposition, Disposition::Blocked);
        assert!(
            report
                .blocking_reasons
                .iter()
                .any(|reason| reason.contains("boundary build fingerprint"))
        );
    }

    #[test]
    fn options_reuse_explicit_serial_and_bounded_adb_contract() {
        let options = parse_options(&[
            OsString::from("--serial"),
            OsString::from("R58M1234ABC"),
            OsString::from("--adb"),
            OsString::from("adb.exe"),
        ])
        .expect("valid preflight options");
        assert_eq!(options.serial(), "R58M1234ABC");
        assert_eq!(options.adb(), &OsString::from("adb.exe"));
        let error = parse_options(&[]).expect_err("serial selection must be explicit");
        assert!(error.contains(COMMAND));
    }

    #[test]
    fn unknown_child_rules_loopback_and_cross_family_mask_drift_block() {
        let mut snapshot = snapshot(PINNED_2025_INCOMING_MASK);
        snapshot.ipv4_mangle = mangle(
            PINNED_2025_INCOMING_MASK,
            "-A routectrl_mangle_INPUT -j CONNMARK --restore-mark\n",
        );
        snapshot.ipv6_mangle = mangle(ANDROID_12_13_INCOMING_MASK, "");
        let report = build_report("SERIAL", device(), snapshot);
        assert_eq!(report.disposition, Disposition::Blocked);
        assert!(
            report
                .blocking_reasons
                .iter()
                .any(|reason| reason.contains("unknown rules"))
        );
        assert!(
            report
                .blocking_reasons
                .iter()
                .any(|reason| reason.contains("different masks"))
        );

        let loopback = mangle(PINNED_2025_INCOMING_MASK, "").replace("-i wlan0", "-i lo");
        let observation = parse_mangle_dump(&loopback).expect("well-framed snapshot");
        assert_eq!(observation.writer_count, 1);
        assert_eq!(observation.unknown_child_rules, 1);

        let candidate_value =
            mangle(PINNED_2025_INCOMING_MASK, "").replace("0x00000065", "0x00200065");
        let observation = parse_mangle_dump(&candidate_value).expect("well-framed snapshot");
        assert_eq!(observation.writer_count, 1);
        assert_eq!(observation.unknown_child_rules, 1);
    }

    #[test]
    fn duplicate_chain_or_interface_and_cross_family_interface_drift_block() {
        let mut duplicate_chain = snapshot(PINNED_2025_INCOMING_MASK);
        duplicate_chain.ipv4_mangle = duplicate_chain.ipv4_mangle.replace(
            ":routectrl_mangle_INPUT - [0:0]\n",
            ":routectrl_mangle_INPUT - [0:0]\n:routectrl_mangle_INPUT - [0:0]\n",
        );
        let report = build_report("SERIAL", device(), duplicate_chain);
        assert!(
            report
                .blocking_reasons
                .iter()
                .any(|reason| reason.contains("2 declarations"))
        );

        let mut duplicate_interface = snapshot(PINNED_2025_INCOMING_MASK);
        duplicate_interface.ipv4_mangle = duplicate_interface
            .ipv4_mangle
            .replace("-i wlan0", "-i rmnet_data0");
        let report = build_report("SERIAL", device(), duplicate_interface);
        assert!(
            report
                .blocking_reasons
                .iter()
                .any(|reason| reason.contains("duplicate interface selectors"))
        );

        let mut cross_family = snapshot(PINNED_2025_INCOMING_MASK);
        cross_family.ipv6_mangle = cross_family.ipv6_mangle.replace("-i wlan0", "-i wlan1");
        let report = build_report("SERIAL", device(), cross_family);
        assert!(
            report
                .blocking_reasons
                .iter()
                .any(|reason| reason.contains("different interface sets"))
        );
    }

    #[test]
    fn hook_must_be_one_exact_unconditional_reference() {
        let selected = mangle(PINNED_2025_INCOMING_MASK, "").replace(
            "-A INPUT -j routectrl_mangle_INPUT",
            "-A INPUT -i wlan0 -j routectrl_mangle_INPUT",
        );
        let observation = parse_mangle_dump(&selected).expect("well-framed snapshot");
        assert_eq!(observation.input_hook_references, 1);
        assert_eq!(observation.input_hook_ordinal, None);

        let duplicate = mangle(PINNED_2025_INCOMING_MASK, "").replace(
            "-A INPUT -j routectrl_mangle_INPUT\n",
            "-A INPUT -j routectrl_mangle_INPUT\n-A INPUT -j routectrl_mangle_INPUT\n",
        );
        let observation = parse_mangle_dump(&duplicate).expect("well-framed snapshot");
        assert_eq!(observation.input_hook_references, 2);
    }

    #[test]
    fn goto_and_non_input_references_to_the_child_chain_block_viability() {
        for extra_reference in [
            "-A INPUT -g routectrl_mangle_INPUT\n",
            "-A OUTPUT -j routectrl_mangle_INPUT\n",
        ] {
            let mut candidate = snapshot(PINNED_2025_INCOMING_MASK);
            candidate.ipv4_mangle = candidate.ipv4_mangle.replace(
                "-A INPUT -j routectrl_mangle_INPUT\n",
                &format!("-A INPUT -j routectrl_mangle_INPUT\n{extra_reference}"),
            );

            let report = build_report("SERIAL", device(), candidate);

            assert_eq!(report.disposition, Disposition::Blocked);
            assert!(report.ipv4.blocking_reasons.iter().any(|reason| {
                reason.contains(
                    "routectrl_mangle_INPUT must have exactly one reference: an unconditional built-in INPUT jump",
                )
            }));
        }
    }

    #[test]
    fn snapshot_parser_accepts_windows_line_endings_and_rejects_truncation() {
        let script_output = format!(
            "{SNAPSHOT_HEADER}\n\
             boot_id_before={}\n\
             fingerprint_before={}\n\
             selinux_mode=Enforcing\n\
             pid1_netns=net:[1]\n\
             self_netns=net:[1]\n\
             artifact.selinux_policy=1\n\
             artifact.netd=1\n\
             artifact.apex_info=1\n\
             tool.iptables_save=1\n\
             tool.ip6tables_save=1\n\
             ipv4_table_initialized=1\n\
             ipv6_table_initialized=1\n\
             {}\
             {IPV4_BEGIN}\n{}\
             {IPV4_END}\n\
             {IPV6_BEGIN}\n{}\
             {IPV6_END}\n\
             boot_id_after={}\n\
             fingerprint_after={}\n\
             {SNAPSHOT_COMPLETE}\n",
            device().boot_id,
            device().build_fingerprint,
            properties()
                .iter()
                .map(|(key, value)| format!("property.{key}={value}\n"))
                .collect::<String>(),
            mangle(PINNED_2025_INCOMING_MASK, ""),
            mangle(PINNED_2025_INCOMING_MASK, ""),
            device().boot_id,
            device().build_fingerprint,
        );
        let windows = script_output.replace('\n', "\r\n");
        let parsed = parse_remote_snapshot(windows.as_bytes()).expect("complete CRLF snapshot");
        assert_eq!(parsed.ipv4_mangle, mangle(PINNED_2025_INCOMING_MASK, ""));
        assert!(
            parse_remote_snapshot(
                script_output
                    .replace(SNAPSHOT_COMPLETE, "TRUNCATED")
                    .as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn remote_contract_is_read_only_and_never_requests_uninitialized_tables() {
        let script = remote_snapshot_script();
        for forbidden in [
            "iptables-restore",
            "ip6tables-restore",
            " --append ",
            " --insert ",
            " --delete ",
            "-A routectrl",
            "mktemp",
            "chmod",
            "chown",
            "rm -rf",
            "mount ",
            "unshare",
        ] {
            assert!(!script.contains(forbidden), "forbidden token {forbidden:?}");
        }
        assert!(script.contains("/proc/net/ip_tables_names"));
        assert!(script.contains("/proc/net/ip6_tables_names"));
        assert!(script.contains("iptables-save -t mangle"));
        assert!(script.contains("ip6tables-save -t mangle"));

        #[cfg(target_os = "linux")]
        {
            use std::process::{Command, Stdio};

            let mut child = Command::new("/bin/sh")
                .arg("-n")
                .stdin(Stdio::piped())
                .spawn()
                .expect("spawn host shell syntax check");
            child
                .stdin
                .take()
                .expect("piped shell stdin")
                .write_all(script.as_bytes())
                .expect("write preflight script");
            assert!(
                child.wait().expect("wait for shell syntax check").success(),
                "generated preflight script must be valid POSIX shell syntax"
            );
        }
    }

    #[test]
    fn kernel_floor_and_verified_boot_inputs_are_strict() {
        assert!(kernel_meets_floor("5.10.1-android"));
        assert!(kernel_meets_floor("6.1.0"));
        assert!(!kernel_meets_floor("5.9.999"));
        assert!(!kernel_meets_floor("5x.10.1"));
        assert!(!kernel_meets_floor("5.10x.1"));
        assert!(!kernel_meets_floor("5.10"));
        assert!(!kernel_meets_floor("unknown"));
        assert!(verified_boot_inputs_complete(&properties()));

        let mut rooted_unlocked = properties();
        rooted_unlocked.insert("ro.boot.verifiedbootstate".to_owned(), "orange".to_owned());
        rooted_unlocked.insert(
            "ro.boot.vbmeta.device_state".to_owned(),
            "unlocked".to_owned(),
        );
        rooted_unlocked.insert("ro.boot.flash.locked".to_owned(), "0".to_owned());
        assert!(verified_boot_inputs_complete(&rooted_unlocked));

        let mut incomplete = properties();
        incomplete.insert("ro.boot.vbmeta.digest".to_owned(), "abcd".to_owned());
        assert!(!verified_boot_inputs_complete(&incomplete));

        let mut inconsistent = rooted_unlocked;
        inconsistent.insert("ro.boot.flash.locked".to_owned(), "1".to_owned());
        assert!(!verified_boot_inputs_complete(&inconsistent));

        let mut uppercase = properties();
        uppercase.insert(
            "ro.boot.vbmeta.digest".to_owned(),
            "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
        );
        assert!(!verified_boot_inputs_complete(&uppercase));
    }

    #[test]
    fn one_valid_lock_property_matches_the_production_identity_contract() {
        for absent_property in ["ro.boot.vbmeta.device_state", "ro.boot.flash.locked"] {
            let mut candidate = snapshot(PINNED_2025_INCOMING_MASK);
            candidate
                .properties
                .insert(absent_property.to_owned(), String::new());

            let report = build_report("SERIAL", device(), candidate);

            assert_eq!(
                report.disposition,
                Disposition::ViableForFullQualification,
                "{absent_property}: {:?}",
                report.blocking_reasons
            );
            assert!(report.profile_inputs.required_properties_present);
            assert!(report.profile_inputs.verified_boot_inputs_complete);
        }
    }

    #[test]
    fn malformed_production_identity_property_blocks_viability() {
        let mut candidate = snapshot(PINNED_2025_INCOMING_MASK);
        candidate
            .properties
            .insert("ro.product.brand".to_owned(), "vendor/other".to_owned());

        let report = build_report("SERIAL", device(), candidate);

        assert_eq!(report.disposition, Disposition::Blocked);
        assert!(!report.profile_inputs.required_properties_present);
        assert!(report.blocking_reasons.iter().any(|reason| {
            reason.contains("identity collector properties are missing or malformed")
        }));
    }

    #[test]
    fn malformed_snapshot_diagnostics_do_not_echo_raw_lines() {
        let raw_rule = "SECRET_RAW_MANGLE_RULE";
        let dump = format!("*mangle\n{raw_rule}\nCOMMIT\n");
        let error = parse_mangle_dump(&dump).expect_err("unsupported rule must fail");
        assert!(!error.contains(raw_rule), "{error}");

        let raw_field = "SECRET_RAW_METADATA";
        let error = parse_fields(raw_field).expect_err("malformed field must fail");
        assert!(!error.contains(raw_field), "{error}");
    }
}
