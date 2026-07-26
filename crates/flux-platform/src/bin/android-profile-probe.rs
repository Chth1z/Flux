#[cfg(target_os = "android")]
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "android")]
use flux_core::{CapabilityProfileSource, Observation, SelinuxMode, VerifiedBootState};
#[cfg(target_os = "android")]
use flux_platform::SystemCapabilityProfileSource;

#[cfg(target_os = "android")]
const REQUIRED_ENV: &str = "FLUX_ANDROID_PROFILE_REQUIRED";
#[cfg(target_os = "android")]
const REPORT_BEGIN: &str = "FLUX_ANDROID_PROFILE_BEGIN";
#[cfg(target_os = "android")]
const REPORT_END: &str = "FLUX_ANDROID_PROFILE_END";

#[cfg(not(target_os = "android"))]
fn main() {
    eprintln!("android-profile-probe is available only on Android");
    std::process::exit(2);
}

#[cfg(target_os = "android")]
fn main() {
    if std::env::var(REQUIRED_ENV).as_deref() != Ok("1") {
        eprintln!("Android profile probe requires explicit runner authority");
        std::process::exit(2);
    }
    if let Err(error) = collect_and_print() {
        eprintln!("Android profile probe: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "android")]
fn collect_and_print() -> Result<(), String> {
    let profile = SystemCapabilityProfileSource::default().collect_capability_profile();
    let boot = profile
        .boot_identity()
        .verified()
        .ok_or_else(|| "production collector did not verify boot identity".to_owned())?;
    let device = profile
        .device_identity()
        .verified()
        .ok_or_else(|| "production collector did not verify Android device identity".to_owned())?;
    if profile.selinux() != &Observation::Verified(SelinuxMode::Enforcing) {
        return Err("physical qualification requires enforcing SELinux".to_owned());
    }
    let kernel_release = profile
        .kernel()
        .release()
        .verified()
        .ok_or_else(|| "production collector did not verify kernel release".to_owned())?;
    let pid1_namespace = std::fs::metadata("/proc/1/ns/net")
        .map_err(|error| format!("inspect PID 1 network namespace: {error}"))?;
    if (
        device.network_namespace().device(),
        device.network_namespace().inode(),
    ) != (pid1_namespace.dev(), pid1_namespace.ino())
    {
        return Err("profile probe is not in PID 1's network namespace".to_owned());
    }
    let mut tools = device.tools().iter();
    let (tool_id, tool_artifact) = tools
        .next()
        .ok_or_else(|| "profile probe requires exactly one executing-tool identity".to_owned())?;
    if tools.next().is_some() {
        return Err("profile probe requires exactly one executing-tool identity".to_owned());
    }
    if tool_id.as_str() != "fluxd" {
        return Err("production collector returned an unexpected executing-tool ID".to_owned());
    }
    let verified_boot = device.verified_boot();

    println!("{REPORT_BEGIN}");
    field(
        "authority",
        "read_only_profile_evidence_no_mutation_authority",
    );
    field("schema_version", "1");
    field(
        "capability_schema_version",
        &profile.schema_version().to_string(),
    );
    field("capability_revision", &profile.revision().get().to_string());
    field(
        "capability_profile_sha256",
        &hex(profile.digest().as_bytes()),
    );
    field("boot_id", boot.as_str());
    field("android_product", device.android_product().as_str());
    field("android_build", device.android_build().as_str());
    field("vendor_build", device.vendor_build().as_str());
    field("security_patch", device.security_patch().as_str());
    field(
        "verified_boot_state",
        match verified_boot.state() {
            VerifiedBootState::Green => "green",
            VerifiedBootState::Yellow => "yellow",
            VerifiedBootState::Orange => "orange",
            VerifiedBootState::Red => "red",
        },
    );
    field(
        "device_locked",
        if verified_boot.device_locked() {
            "1"
        } else {
            "0"
        },
    );
    field(
        "vbmeta_sha256",
        &hex(verified_boot.vbmeta_digest().as_bytes()),
    );
    field("kernel_build", device.kernel_build().as_str());
    field("kernel_release", kernel_release.as_str());
    field("selinux", "enforcing");
    artifact_fields("selinux_policy", device.selinux_policy().artifact());
    artifact_fields("netd", device.netd());
    artifact_fields("connectivity", device.connectivity());
    field("tool_id", tool_id.as_str());
    artifact_fields("tool", *tool_artifact);
    field(
        "network_namespace_device",
        &device.network_namespace().device().to_string(),
    );
    field(
        "network_namespace_inode",
        &device.network_namespace().inode().to_string(),
    );
    println!("{REPORT_END}");
    Ok(())
}

#[cfg(target_os = "android")]
fn field(name: &str, value: &str) {
    println!("{name}={value}");
}

#[cfg(target_os = "android")]
fn artifact_fields(prefix: &str, artifact: flux_core::ArtifactIdentity) {
    field(
        &format!("{prefix}_sha256"),
        &hex(artifact.digest().as_bytes()),
    );
    field(&format!("{prefix}_size"), &artifact.size().to_string());
}

#[cfg(target_os = "android")]
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
