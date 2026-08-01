use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use serde::Deserialize;
use sha2::{Digest, Sha256};

mod android_artifact;
mod android_canary;
mod android_fwmark_census;
mod android_kernel;
mod android_mark_preflight;
mod android_profile;
mod android_remote;
mod platform_glue;

const ANDROID_TARGET: &str = "aarch64-linux-android";
const ANDROID_API_LEVEL: &str = "31";
const ANDROID_NDK_REVISION: &str = "27.3.13750724";
const LINUX_ANDROID_HOST_BUILD_TMPDIR: &str = "/tmp";
const RELEASE_MANIFEST_SCHEMA_VERSION: u32 = 4;
const ANDROID_MIN_LOAD_ALIGNMENT: u64 = 1 << 14;
const ANDROID_RUSTFLAGS: &str = concat!(
    "-C link-arg=-Wl,-z,max-page-size=16384 ",
    "-C link-arg=-Wl,-z,common-page-size=16384"
);
const ANDROID_TARGET_RUSTFLAGS_ENV: &str = "CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS";
const PACKAGE_METADATA_FILES: [&str; 3] =
    ["SBOM.spdx.json", "checksums.sha256", "build-metadata.json"];
const NATIVE_PLATFORM_GLUE_FILES: [&str; 4] = [
    "META-INF/com/google/android/update-binary",
    "customize.sh",
    "flux_service.sh",
    "uninstall.sh",
];
const NATIVE_REQUIRED_FILES: [&str; 13] = [
    "META-INF/com/google/android/update-binary",
    "META-INF/com/google/android/updater-script",
    "bin/fluxd",
    "bin/sing-box",
    "conf/flux.toml",
    "conf/template.json",
    "conf/manifest.json",
    "webroot/index.html",
    "customize.sh",
    "flux_service.sh",
    "uninstall.sh",
    "module.prop",
    "LICENSE",
];
const MAX_PLATFORM_GLUE_SOURCE_BYTES: usize = 128 * 1024;
const FORBIDDEN_PLATFORM_GLUE_EXECUTABLES: [(&str, &str); 16] = [
    ("networking mutation", "ip"),
    ("networking mutation", "iptables"),
    ("networking mutation", "ip6tables"),
    ("networking mutation", "iptables-restore"),
    ("networking mutation", "ip6tables-restore"),
    ("networking mutation", "nft"),
    ("networking mutation", "tc"),
    ("networking mutation", "bpftool"),
    ("kernel mutation", "insmod"),
    ("kernel mutation", "modprobe"),
    ("kernel mutation", "rmmod"),
    ("subscription retrieval", "curl"),
    ("subscription retrieval", "wget"),
    ("configuration compilation", "jq"),
    ("configuration compilation", "awk"),
    ("dynamic command construction", "eval"),
];
const FORBIDDEN_PLATFORM_GLUE_FRAGMENTS: [(&str, &str); 18] = [
    ("networking mutation", "/proc/sys/net/"),
    ("networking mutation", "/sys/fs/bpf"),
    ("networking mutation", "fwmark"),
    ("networking mutation", "tproxy"),
    ("subscription retrieval", "subscription"),
    ("subscription retrieval", "updater.sh"),
    ("configuration compilation", "settings.ini"),
    ("configuration compilation", "addrsyncd.toml"),
    ("configuration compilation", "singbox.json"),
    ("configuration compilation", "render-legacy"),
    ("owned-state cleanup", "/run/active_"),
    ("owned-state cleanup", "cache_cleanup"),
    ("owned-state cleanup", "startup-recover"),
    ("legacy runtime", "/scripts/"),
    ("legacy runtime", "addrsyncd"),
    ("runtime orchestration", "/data/adb/flux/bin/sing-box"),
    ("dynamic command construction", "sh -c "),
    ("dynamic command construction", "`"),
];
const REQUIRED_DEVICE_TESTS: [&str; 7] = [
    "module_boot",
    "status",
    "enable_disable",
    "restart",
    "abnormal_sing_box_exit",
    "dual_stack_tcp_udp_dns",
    "cleanup",
];
const LINUX_CANARY_REQUIRED_ENV: &str = "FLUX_LINUX_CANARY_REQUIRED";
const LINUX_CANARY_TEST: &str = "functional_canary::linux_namespace_harness::privileged_dual_stack_canary_exercises_real_topology_and_cleanup";
const LINUX_TPROXY_CANARY_TEST: &str = "functional_canary::linux_namespace_harness::privileged_ingress_tproxy_checkpoint_exercises_real_capture_counters_and_cleanup";
const LINUX_OUTPUT_TPROXY_CANARY_TEST: &str = "functional_canary::linux_namespace_harness::privileged_local_output_tproxy_checkpoint_exercises_loopback_reinjection_and_cleanup";
const ANDROID_ENGINE_CREDENTIAL_CANARY_TEST: &str = "functional_canary::linux_namespace_harness::privileged_android_engine_credentials_exercise_exact_cleanup";
const LINUX_OUTPUT_UID_PREFLIGHT_TEST: &str = "functional_canary::linux_namespace_harness::privileged_local_output_distinct_uid_capability_preflight";
const NATIVE_COMPOSITION_REQUIRED_ENV: &str = "FLUX_NATIVE_COMPOSITION_REQUIRED";
const NATIVE_COMPOSITION_TEST: &str = "functional_canary::linux_namespace_harness::privileged_native_composition_exercises_lifecycle_recovery_and_exact_cleanup";
const NATIVE_COMPOSITION_FEATURE: &str = "native-composition-test";
const NATIVE_COMPOSITION_ENGINE_BIN: &str = "flux-native-composition-engine";
const PARSER_FUZZ_SMOKE_TESTS: [&str; 8] = [
    "address_sync::tests::deterministic_arbitrary_datagrams_never_panic",
    "netlink::link::tests::deterministic_arbitrary_datagrams_never_panic",
    "netlink::route::tests::deterministic_arbitrary_datagrams_never_panic",
    "netlink::rule::tests::deterministic_arbitrary_datagrams_never_panic",
    "netlink::route::tests::complex_route_prefixes_and_structured_mutations_are_atomic_and_panic_free",
    "netlink::rule::tests::complex_rule_prefixes_and_structured_mutations_are_atomic_and_panic_free",
    "seqpacket::implementation::record_control_tests::deterministic_arbitrary_control_layouts_never_panic",
    "socket_diagnostics::tests::deterministic_arbitrary_datagrams_never_panic",
];
const LINUX_CANARY_INTERNAL_ENVS: [&str; 27] = [
    "FLUX_LINUX_CANARY_HARNESS_MODE",
    "FLUX_LINUX_CANARY_HARNESS_CONFIG",
    "FLUX_LINUX_CANARY_REENTRY_TOKEN",
    "FLUX_LINUX_CANARY_OUTER_NETNS",
    "FLUX_LINUX_CANARY_OUTER_USERNS",
    "FLUX_LINUX_CANARY_OUTER_MOUNTNS",
    "FLUX_LINUX_CANARY_OUTER_PID",
    "FLUX_LINUX_CANARY_REENTRY_AUTHORITY",
    "FLUX_LINUX_CANARY_EXPECTED_UID_MAP",
    "FLUX_LINUX_CANARY_EXPECTED_GID_MAP",
    "FLUX_LINUX_CANARY_MAPPING_MECHANISM",
    "FLUX_LINUX_CANARY_ROLE_UID",
    "FLUX_LINUX_CANARY_ROLE_GID",
    "FLUX_LINUX_CANARY_OUTER_SUPPLEMENTARY_GROUPS",
    "FLUX_LINUX_CANARY_INNER_NETNS",
    "FLUX_LINUX_CANARY_INNER_USERNS",
    "FLUX_LINUX_CANARY_INNER_MOUNTNS",
    "FLUX_ENGINE_CREDENTIAL_PROBE_REQUIRED",
    "FLUX_ENGINE_CREDENTIAL_PROBE_PATH",
    "FLUX_ENGINE_CREDENTIAL_PROBE_GID",
    "FLUX_ENGINE_CREDENTIAL_PARENT_DEATH_HELPER",
    "FLUX_ENGINE_CREDENTIAL_CONFIG",
    "FLUX_ENGINE_CREDENTIAL_REPORT",
    "FLUX_ENGINE_CREDENTIAL_LOG",
    "FLUX_ENGINE_CREDENTIAL_IDENTITY",
    "FLUX_ENGINE_CREDENTIAL_IDENTITY_TMP",
    "FLUX_ENGINE_CREDENTIAL_PORT",
];
const NATIVE_COMPOSITION_INTERNAL_ENVS: [&str; 9] = [
    "FLUX_NATIVE_COMPOSITION_HARNESS_MODE",
    "FLUX_NATIVE_COMPOSITION_ROOT",
    "FLUX_NATIVE_COMPOSITION_REENTRY_TOKEN",
    "FLUX_NATIVE_COMPOSITION_OUTER_NETNS",
    "FLUX_NATIVE_COMPOSITION_OUTER_USERNS",
    "FLUX_NATIVE_COMPOSITION_ENGINE_BIN",
    "FLUX_NATIVE_COMPOSITION_EXEC_AUDIT",
    "FLUX_NATIVE_COMPOSITION_ENGINE_PID_LOG",
    "FLUX_NATIVE_COMPOSITION_FAIL_CHECK",
];

fn main() {
    if let Err(error) = run(env::args_os().skip(1)) {
        eprintln!("xtask: {error}");
        std::process::exit(1);
    }
}

fn run(args: impl IntoIterator<Item = OsString>) -> Result<(), String> {
    let mut args = args.into_iter();
    let command = args.next().unwrap_or_else(|| OsString::from("help"));
    let arguments = args.collect::<Vec<_>>();

    match command.to_string_lossy().as_ref() {
        "help" | "--help" | "-h" => {
            require_no_arguments(&arguments)?;
            print_help();
            Ok(())
        }
        "fmt" => {
            require_no_arguments(&arguments)?;
            cargo(["fmt", "--all", "--", "--check"], &[])
        }
        "check-host" => {
            require_no_arguments(&arguments)?;
            cargo(["check", "--workspace", "--all-targets"], &[])
        }
        "test-host" => {
            require_no_arguments(&arguments)?;
            cargo(["test", "--workspace"], &[])
        }
        "clippy" => {
            require_no_arguments(&arguments)?;
            cargo(
                [
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
                &[],
            )
        }
        "check-android" => {
            require_no_arguments(&arguments)?;
            check_android()
        }
        "build-android" => {
            require_no_arguments(&arguments)?;
            build_android()
        }
        "test-functional-canary-linux" => {
            require_no_arguments(&arguments)?;
            test_functional_canary_linux()
        }
        "test-functional-canary-linux-tproxy" => {
            require_no_arguments(&arguments)?;
            test_functional_canary_linux_tproxy()
        }
        "test-functional-canary-linux-output-tproxy" => {
            require_no_arguments(&arguments)?;
            test_functional_canary_linux_output_tproxy()
        }
        "test-functional-canary-linux-output-preflight" => {
            require_no_arguments(&arguments)?;
            test_functional_canary_linux_output_preflight()
        }
        "test-native-composition-linux" => {
            require_no_arguments(&arguments)?;
            test_native_composition_linux()
        }
        "test-parser-fuzz-smoke" => {
            require_no_arguments(&arguments)?;
            test_parser_fuzz_smoke()
        }
        android_canary::COMMAND => android_canary::run(android_canary::parse_options(&arguments)?),
        "preflight-android-arm64-mark-ordering" => {
            android_mark_preflight::run(android_mark_preflight::parse_options(&arguments)?)
        }
        "collect-android-arm64-profile" => {
            android_profile::run(android_profile::parse_options(&arguments)?)
        }
        "collect-android-arm64-fwmark-census" => {
            android_fwmark_census::run(android_fwmark_census::parse_options(&arguments)?)
        }
        "stage-module" => stage_module(parse_stage_module_options(&arguments)?),
        "verify-package" => verify_package(parse_verify_package_options(&arguments)?),
        "ci" => {
            require_no_arguments(&arguments)?;
            cargo(["fmt", "--all", "--", "--check"], &[])?;
            cargo(["check", "--workspace", "--all-targets"], &[])?;
            cargo(["test", "--workspace"], &[])?;
            cargo(
                [
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
                &[],
            )?;
            check_android()
        }
        unknown => Err(format!(
            "unknown command '{unknown}'; run `cargo xtask help`"
        )),
    }
}

fn test_functional_canary_linux() -> Result<(), String> {
    test_linux_canary(LINUX_CANARY_TEST)
}

fn test_functional_canary_linux_tproxy() -> Result<(), String> {
    test_linux_canary(LINUX_TPROXY_CANARY_TEST)
}

fn test_functional_canary_linux_output_tproxy() -> Result<(), String> {
    test_linux_canary(LINUX_OUTPUT_TPROXY_CANARY_TEST)
}

fn test_functional_canary_linux_output_preflight() -> Result<(), String> {
    test_linux_canary(LINUX_OUTPUT_UID_PREFLIGHT_TEST)
}

fn test_native_composition_linux() -> Result<(), String> {
    let required = native_composition_required()?;
    if env::consts::OS != "linux" {
        return linux_canary_skip_or_fail(
            required,
            "the native composition checkpoint requires a Linux host",
        );
    }

    cargo_scrubbed([
        "build",
        "-p",
        "fluxd",
        "--features",
        NATIVE_COMPOSITION_FEATURE,
        "--bin",
        NATIVE_COMPOSITION_ENGINE_BIN,
    ])?;
    let listed = cargo_stdout([
        "test",
        "-p",
        "fluxd",
        "--features",
        NATIVE_COMPOSITION_FEATURE,
        "--lib",
        NATIVE_COMPOSITION_TEST,
        "--",
        "--ignored",
        "--exact",
        "--list",
    ])?;
    if !linux_canary_test_is_listed(&listed, NATIVE_COMPOSITION_TEST) {
        return linux_canary_skip_or_fail(
            required,
            "the privileged Linux native-composition harness is not implemented in this checkout",
        );
    }

    cargo_scrubbed([
        "test",
        "-p",
        "fluxd",
        "--features",
        NATIVE_COMPOSITION_FEATURE,
        "--lib",
        NATIVE_COMPOSITION_TEST,
        "--",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ])
}

fn test_parser_fuzz_smoke() -> Result<(), String> {
    for test in PARSER_FUZZ_SMOKE_TESTS {
        cargo(
            [
                "test",
                "-p",
                "flux-platform",
                "--lib",
                test,
                "--",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ],
            &[],
        )?;
    }
    Ok(())
}

fn test_linux_canary(test_name: &str) -> Result<(), String> {
    let required = linux_canary_required()?;
    if env::consts::OS != "linux" {
        return linux_canary_skip_or_fail(
            required,
            "the functional canary harness requires a Linux host",
        );
    }

    let listed = cargo_stdout([
        "test",
        "-p",
        "fluxd",
        "--lib",
        test_name,
        "--",
        "--ignored",
        "--exact",
        "--list",
    ])?;
    if !linux_canary_test_is_listed(&listed, test_name) {
        return linux_canary_skip_or_fail(
            required,
            "the privileged Linux functional-canary harness is not implemented in this checkout",
        );
    }

    cargo_scrubbed([
        "test",
        "-p",
        "fluxd",
        "--lib",
        test_name,
        "--",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ])
}

fn linux_canary_required() -> Result<bool, String> {
    match env::var(LINUX_CANARY_REQUIRED_ENV) {
        Ok(value) => parse_linux_canary_required(Some(&value)),
        Err(env::VarError::NotPresent) => parse_linux_canary_required(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!(
            "{LINUX_CANARY_REQUIRED_ENV} must contain valid UTF-8"
        )),
    }
}

fn parse_linux_canary_required(value: Option<&str>) -> Result<bool, String> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(_) => Err(format!("{LINUX_CANARY_REQUIRED_ENV} must be 0 or 1")),
    }
}

fn native_composition_required() -> Result<bool, String> {
    match env::var(NATIVE_COMPOSITION_REQUIRED_ENV) {
        Ok(value) => parse_native_composition_required(Some(&value)),
        Err(env::VarError::NotPresent) => parse_native_composition_required(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!(
            "{NATIVE_COMPOSITION_REQUIRED_ENV} must contain valid UTF-8"
        )),
    }
}

fn parse_native_composition_required(value: Option<&str>) -> Result<bool, String> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(_) => Err(format!("{NATIVE_COMPOSITION_REQUIRED_ENV} must be 0 or 1")),
    }
}

fn linux_canary_test_is_listed(listing: &str, test_name: &str) -> bool {
    let expected = format!("{test_name}: test");
    listing.lines().any(|line| line.trim() == expected)
}

fn linux_canary_skip_or_fail(required: bool, reason: &str) -> Result<(), String> {
    if required {
        Err(reason.to_owned())
    } else {
        eprintln!("SKIP: {reason}");
        Ok(())
    }
}

fn require_no_arguments(arguments: &[OsString]) -> Result<(), String> {
    if arguments.is_empty() {
        Ok(())
    } else {
        Err("command does not accept arguments".to_owned())
    }
}

#[derive(Debug)]
struct StageModuleOptions {
    stage: PathBuf,
    runtime_binaries: PathBuf,
}

#[derive(Debug)]
struct VerifyPackageOptions {
    stage: PathBuf,
}

#[derive(Debug)]
struct WorkspaceSourceRevisions {
    fluxd: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    schema_version: u32,
    project: String,
    generated_by: String,
    #[serde(default)]
    note: String,
    binaries: Vec<BinaryManifest>,
    device_test_evidence: Vec<DeviceEvidenceManifest>,
    package_profile: PackageProfile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryManifest {
    name: String,
    path: String,
    source: String,
    source_revision: String,
    version: String,
    target: String,
    sha256: String,
    license: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceEvidenceManifest {
    path: String,
    sha256: String,
    source_revision: String,
    payload_sha256: String,
    device_profile: String,
    android_build_fingerprint: String,
    kernel_release: String,
    boot_id: String,
    verified_boot_state: String,
    selinux_enforcing: bool,
    captured_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProfile {
    name: PackageProfileName,
    status: PackageProfileStatus,
    description: String,
    required_files: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum PackageProfileName {
    Native,
}

impl PackageProfileName {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum PackageProfileStatus {
    DevelopmentOnly,
}

#[derive(Debug, Deserialize)]
struct SpdxDocument {
    #[serde(rename = "spdxVersion")]
    spdx_version: String,
    #[serde(rename = "dataLicense")]
    data_license: String,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "documentNamespace")]
    document_namespace: String,
    #[serde(rename = "creationInfo")]
    creation_info: SpdxCreationInfo,
    #[serde(rename = "documentDescribes")]
    document_describes: Vec<String>,
    packages: Vec<SpdxPackage>,
    #[serde(default, rename = "hasExtractedLicensingInfos")]
    extracted_licensing_infos: Vec<SpdxExtractedLicense>,
}

#[derive(Debug, Deserialize)]
struct SpdxCreationInfo {
    created: String,
    creators: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "versionInfo")]
    version_info: String,
    #[serde(rename = "downloadLocation")]
    download_location: String,
    #[serde(rename = "licenseConcluded")]
    license_concluded: String,
    #[serde(rename = "licenseDeclared")]
    license_declared: String,
    #[serde(rename = "filesAnalyzed")]
    files_analyzed: bool,
    #[serde(default, rename = "packageVerificationCode")]
    package_verification_code: Option<serde_json::Value>,
    #[serde(default, rename = "licenseInfoFromFiles")]
    license_info_from_files: Vec<String>,
    #[serde(rename = "copyrightText")]
    copyright_text: String,
    checksums: Vec<SpdxChecksum>,
}

#[derive(Debug, Deserialize)]
struct SpdxChecksum {
    algorithm: String,
    #[serde(rename = "checksumValue")]
    checksum_value: String,
}

#[derive(Debug, Deserialize)]
struct SpdxExtractedLicense {
    #[serde(rename = "licenseId")]
    license_id: String,
    #[serde(rename = "extractedText")]
    extracted_text: String,
}

#[derive(Debug, Deserialize)]
struct BuildMetadata {
    schema_version: u32,
    source_revision: String,
    rust_toolchain: String,
    android_ndk_revision: String,
    android_target: String,
    built_at_utc: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceEvidenceDocument {
    schema_version: u32,
    source_revision: String,
    payload_sha256: String,
    device_profile: String,
    android_build_fingerprint: String,
    kernel_release: String,
    boot_id: String,
    verified_boot_state: String,
    selinux_enforcing: bool,
    captured_at_utc: String,
    result: String,
    tests: Vec<DeviceEvidenceTest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceEvidenceTest {
    id: String,
    result: String,
}

fn parse_stage_module_options(arguments: &[OsString]) -> Result<StageModuleOptions, String> {
    let mut stage = None;
    let mut runtime_binaries = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].to_string_lossy();
        let value = arguments
            .get(index.saturating_add(1))
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_ref() {
            "--stage" if stage.is_none() => stage = Some(PathBuf::from(value)),
            "--runtime-binaries" if runtime_binaries.is_none() => {
                runtime_binaries = Some(PathBuf::from(value));
            }
            "--stage" | "--runtime-binaries" => {
                return Err(format!("{flag} may only be supplied once"));
            }
            unknown => return Err(format!("unknown stage-module option '{unknown}'")),
        }
        index = index.saturating_add(2);
    }

    Ok(StageModuleOptions {
        stage: stage.ok_or_else(|| "stage-module requires --stage DIR".to_owned())?,
        runtime_binaries: runtime_binaries
            .ok_or_else(|| "stage-module requires --runtime-binaries DIR".to_owned())?,
    })
}

fn parse_verify_package_options(arguments: &[OsString]) -> Result<VerifyPackageOptions, String> {
    let mut stage = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].to_string_lossy();
        let value = arguments
            .get(index.saturating_add(1))
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_ref() {
            "--stage" if stage.is_none() => stage = Some(PathBuf::from(value)),
            "--stage" => return Err(format!("{flag} may only be supplied once")),
            unknown => return Err(format!("unknown verify-package option '{unknown}'")),
        }
        index = index.saturating_add(2);
    }

    Ok(VerifyPackageOptions {
        stage: stage.ok_or_else(|| "verify-package requires --stage DIR".to_owned())?,
    })
}

fn read_release_manifest(path: &Path) -> Result<ReleaseManifest, String> {
    serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("invalid {}: {error}", path.display()))
}

fn profile_requires(profile: &PackageProfile, relative: &str) -> bool {
    profile
        .required_files
        .iter()
        .any(|required| required == relative)
}

fn validate_package_contract(manifest: &ReleaseManifest) -> Result<(), String> {
    if manifest.schema_version != RELEASE_MANIFEST_SCHEMA_VERSION {
        return Err(format!(
            "unsupported manifest schema version {}",
            manifest.schema_version
        ));
    }
    validate_package_profile(&manifest.package_profile)
}

fn validate_package_profile(profile: &PackageProfile) -> Result<(), String> {
    if profile.name != PackageProfileName::Native {
        return Err("release manifest package profile must be native".to_owned());
    }
    if profile.status != PackageProfileStatus::DevelopmentOnly {
        return Err("native package profile must be marked development-only".to_owned());
    }
    require_manifest_text("package_profile.description", &profile.description)?;
    let actual = validate_profile_path_list(
        profile.name,
        "required_files",
        &profile.required_files,
        false,
    )?;
    let expected = NATIVE_REQUIRED_FILES
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if actual != expected {
        let missing = expected.difference(&actual).next().copied();
        let extra = actual.difference(&expected).next().copied();
        return Err(format!(
            "native package required files changed (missing={}, extra={})",
            missing.unwrap_or("none"),
            extra.unwrap_or("none")
        ));
    }
    Ok(())
}

fn validate_profile_path_list<'a>(
    profile: PackageProfileName,
    field: &str,
    paths: &'a [String],
    allow_empty: bool,
) -> Result<std::collections::BTreeSet<&'a str>, String> {
    if paths.is_empty() && !allow_empty {
        return Err(format!(
            "{} package profile {field} must not be empty",
            profile.as_str()
        ));
    }
    let mut unique = std::collections::BTreeSet::new();
    for path in paths {
        validated_relative_path(
            &format!("package_profile[{}].{field}", profile.as_str()),
            path,
        )?;
        if !unique.insert(path.as_str()) {
            return Err(format!(
                "{} package profile {field} contains duplicate path {path}",
                profile.as_str()
            ));
        }
    }
    Ok(unique)
}

fn android_compiler_from_environment() -> Result<PathBuf, String> {
    let ndk_root = env::var_os("ANDROID_NDK_HOME")
        .or_else(|| env::var_os("ANDROID_NDK_ROOT"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            "ANDROID_NDK_HOME must point to Android NDK revision 27.3.13750724".to_owned()
        })?;

    verify_ndk_revision(&ndk_root)?;
    android_linker(&ndk_root, ANDROID_TARGET, "aarch64-linux-android")
}

fn check_android() -> Result<(), String> {
    let compiler = android_compiler_from_environment()?.into_os_string();
    let envs = android_cargo_environment(compiler.as_os_str());
    cargo(["check", "-p", "fluxd", "--target", ANDROID_TARGET], &envs)
}

fn build_android() -> Result<(), String> {
    let compiler = android_compiler_from_environment()?.into_os_string();
    let envs = android_cargo_environment(compiler.as_os_str());
    cargo(
        [
            "build",
            "-p",
            "fluxd",
            "--release",
            "--target",
            ANDROID_TARGET,
        ],
        &envs,
    )?;

    let artifact = workspace_root()?
        .join("target")
        .join(ANDROID_TARGET)
        .join("release")
        .join("fluxd");
    validate_aarch64_elf("fluxd", &artifact)?;
    println!(
        "validated Android fluxd ELF with PT_LOAD alignment of at least {} bytes at {}",
        ANDROID_MIN_LOAD_ALIGNMENT,
        artifact.display()
    );
    Ok(())
}

fn android_cargo_environment(compiler: &std::ffi::OsStr) -> Vec<(&'static str, &std::ffi::OsStr)> {
    let mut environment = vec![
        ("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER", compiler),
        ("CC_aarch64_linux_android", compiler),
        (
            ANDROID_TARGET_RUSTFLAGS_ENV,
            std::ffi::OsStr::new(ANDROID_RUSTFLAGS),
        ),
    ];
    if let Some(tmpdir) = android_host_build_tmpdir(env::consts::OS) {
        environment.push(("TMPDIR", tmpdir));
    }
    environment
}

fn android_host_build_tmpdir(host_os: &str) -> Option<&'static std::ffi::OsStr> {
    (host_os == "linux").then_some(std::ffi::OsStr::new(LINUX_ANDROID_HOST_BUILD_TMPDIR))
}

fn stage_module(options: StageModuleOptions) -> Result<(), String> {
    let root = workspace_root()?;
    let source_manifest = read_release_manifest(&root.join("conf/manifest.json"))?;
    validate_package_contract(&source_manifest)?;
    let profile = &source_manifest.package_profile;

    build_android()?;

    let fluxd_source = root
        .join("target")
        .join(ANDROID_TARGET)
        .join("release")
        .join("fluxd");
    stage_module_from_artifacts(
        &root,
        &options.stage,
        &options.runtime_binaries,
        &fluxd_source,
        profile,
    )?;

    let status = match profile.status {
        PackageProfileStatus::DevelopmentOnly => "development-only",
    };
    println!(
        "staged {status} {} Android module at {}",
        profile.name.as_str(),
        options.stage.display()
    );
    println!(
        "check it with `cargo xtask verify-package --stage {}`",
        options.stage.display(),
    );
    Ok(())
}

fn stage_module_from_artifacts(
    root: &Path,
    stage: &Path,
    runtime_binaries: &Path,
    fluxd_source: &Path,
    profile: &PackageProfile,
) -> Result<(), String> {
    if !fluxd_source.is_file() {
        return Err(format!(
            "Android build succeeded but {} is missing",
            fluxd_source.display()
        ));
    }

    require_empty_stage(stage)?;
    for relative in &profile.required_files {
        if relative.starts_with("bin/") {
            continue;
        }
        let source = authoritative_module_source_path(root, relative);
        copy_entry(&source, &stage.join(relative))?;
    }

    for relative in profile
        .required_files
        .iter()
        .filter(|relative| relative.starts_with("bin/") && relative.as_str() != "bin/fluxd")
    {
        let file_name = Path::new(relative)
            .file_name()
            .ok_or_else(|| format!("package binary path {relative} has no file name"))?;
        copy_entry(&runtime_binaries.join(file_name), &stage.join(relative))?;
    }

    copy_entry(fluxd_source, &stage.join("bin/fluxd"))?;

    require_package_layout(stage, profile)?;
    validate_staged_runtime_inventory(stage, profile)
}

fn verify_package(options: VerifyPackageOptions) -> Result<(), String> {
    let source_root = workspace_root()?;
    let source_manifest = read_release_manifest(&source_root.join("conf/manifest.json"))?;
    validate_package_contract(&source_manifest)?;
    let profile = &source_manifest.package_profile;
    let source_revisions = verify_workspace_source_state(&source_root)?;
    verify_package_dir_with_source(&options.stage, &source_root)?;
    validate_package_source_revisions(&options.stage, &source_revisions)?;

    match profile.status {
        PackageProfileStatus::DevelopmentOnly => {
            println!(
                "verified development-only native package at {}; this is not release evidence",
                options.stage.display()
            );
            Ok(())
        }
    }
}

fn verify_workspace_source_state(root: &Path) -> Result<WorkspaceSourceRevisions, String> {
    require_clean_git_worktree(root, "Flux workspace")?;
    let fluxd_revision = git_stdout(root, &["rev-parse", "HEAD"])?;
    validate_source_revision("Flux workspace HEAD", &fluxd_revision)?;
    Ok(WorkspaceSourceRevisions {
        fluxd: fluxd_revision,
    })
}

fn require_clean_git_worktree(root: &Path, label: &str) -> Result<(), String> {
    let status = git_stdout(
        root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )?;
    if status.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{label} must be clean before release verification; first dirty entry: {}",
            status.lines().next().unwrap_or("unknown")
        ))
    }
}

fn git_stdout(root: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot execute git in {}: {error}", root.display()))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed in {}: {}",
            arguments.join(" "),
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("git output in {} is not UTF-8: {error}", root.display()))?;
    Ok(stdout.trim().to_owned())
}

fn validate_package_source_revisions(
    stage: &Path,
    revisions: &WorkspaceSourceRevisions,
) -> Result<(), String> {
    let manifest_path = stage.join("conf/manifest.json");
    let manifest = read_release_manifest(&manifest_path)?;
    validate_first_party_source_revisions(&manifest, revisions)
}

fn validate_first_party_source_revisions(
    manifest: &ReleaseManifest,
    revisions: &WorkspaceSourceRevisions,
) -> Result<(), String> {
    let name = "fluxd";
    let expected = revisions.fluxd.as_str();
    let actual = manifest
        .binaries
        .iter()
        .find(|binary| binary.name == name)
        .map(|binary| binary.source_revision.as_str())
        .ok_or_else(|| format!("release manifest is missing first-party binary '{name}'"))?;
    if actual != expected {
        return Err(format!(
            "manifest source_revision for '{name}' must equal the clean workspace revision {expected}, found {actual}"
        ));
    }
    Ok(())
}

fn verify_package_dir_with_source(stage: &Path, source_root: &Path) -> Result<(), String> {
    let stage_metadata = fs::symlink_metadata(stage)
        .map_err(|error| format!("cannot inspect package stage {}: {error}", stage.display()))?;
    if stage_metadata.file_type().is_symlink() || !stage_metadata.is_dir() {
        return Err(format!(
            "package stage {} must be a real directory, not a symlink",
            stage.display()
        ));
    }

    let source_manifest = read_release_manifest(&source_root.join("conf/manifest.json"))?;
    validate_package_contract(&source_manifest)?;
    let source_profile = &source_manifest.package_profile;

    require_package_layout(stage, source_profile)?;
    reject_unsafe_package_entries(stage, stage)?;
    validate_source_bound_module_files(stage, source_root, source_profile)?;
    for relative in PACKAGE_METADATA_FILES {
        let path = stage.join(relative);
        if !path.is_file() {
            return Err(format!(
                "release package is missing required file {relative}"
            ));
        }
        if fs::metadata(&path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?
            .len()
            == 0
        {
            return Err(format!("release package file {relative} is empty"));
        }
    }

    let manifest_path = stage.join("conf/manifest.json");
    let manifest = read_release_manifest(&manifest_path)?;
    validate_package_contract(&manifest)?;
    if manifest.package_profile != source_manifest.package_profile {
        return Err(
            "staged package path policy differs from checked-in conf/manifest.json".to_owned(),
        );
    }
    let profile = &manifest.package_profile;
    validate_package_file_inventory(stage, &manifest, profile)?;
    validate_release_manifest(stage, &manifest, profile)?;
    validate_spdx_document(&stage.join("SBOM.spdx.json"), &manifest)?;
    validate_build_metadata(&stage.join("build-metadata.json"), &manifest)?;
    validate_package_checksums(stage, &stage.join("checksums.sha256"))
}

fn validate_package_file_inventory(
    stage: &Path,
    manifest: &ReleaseManifest,
    profile: &PackageProfile,
) -> Result<(), String> {
    let mut allowed = profile
        .required_files
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    for relative in PACKAGE_METADATA_FILES {
        allowed.insert(relative.to_owned());
    }
    for evidence in &manifest.device_test_evidence {
        let relative = validated_relative_path("device_test_evidence.path", &evidence.path)?;
        allowed.insert(portable_relative_path(relative)?);
    }

    let mut actual = std::collections::BTreeSet::new();
    collect_package_files(stage, stage, &mut actual)?;
    if actual != allowed {
        let missing = allowed.difference(&actual).next();
        let extra = actual.difference(&allowed).next();
        return Err(format!(
            "release package file inventory differs from the reviewed {} profile (missing={}, extra={})",
            profile.name.as_str(),
            missing.map_or("none", String::as_str),
            extra.map_or("none", String::as_str)
        ));
    }
    Ok(())
}

fn validate_staged_runtime_inventory(stage: &Path, profile: &PackageProfile) -> Result<(), String> {
    let expected = profile
        .required_files
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut actual = std::collections::BTreeSet::new();
    collect_package_files(stage, stage, &mut actual)?;
    if actual != expected {
        let missing = expected.difference(&actual).next();
        let extra = actual.difference(&expected).next();
        return Err(format!(
            "staged module file inventory differs from the {} profile (missing={}, extra={})",
            profile.name.as_str(),
            missing.map_or("none", String::as_str),
            extra.map_or("none", String::as_str)
        ));
    }
    Ok(())
}

fn reject_unsafe_package_entries(root: &Path, current: &Path) -> Result<(), String> {
    for entry in fs::read_dir(current).map_err(|error| {
        format!(
            "cannot read package directory {}: {error}",
            current.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "cannot enumerate package directory {}: {error}",
                current.display()
            )
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        let relative = path.strip_prefix(root).unwrap_or(&path);
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "release package contains symbolic link {}",
                relative.display()
            ));
        }
        if metadata.is_dir() {
            reject_unsafe_package_entries(root, &path)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(format!(
                "release package contains non-file entry {}",
                relative.display()
            ));
        }
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if extension.eq_ignore_ascii_case("ko")
            || extension.eq_ignore_ascii_case("kpm")
            || file_name == ".ko"
            || file_name == ".kpm"
            || file_name.contains(".ko.")
            || file_name.contains(".kpm.")
            || file_name == "kpm"
        {
            return Err(format!(
                "production package contains forbidden kernel payload {}",
                relative.display()
            ));
        }
    }
    Ok(())
}

fn validate_release_manifest(
    stage: &Path,
    manifest: &ReleaseManifest,
    profile: &PackageProfile,
) -> Result<(), String> {
    validate_package_contract(manifest)?;
    require_manifest_text("project", &manifest.project)?;
    if manifest.project != "Flux" {
        return Err(format!(
            "manifest project must be Flux, found '{}'",
            manifest.project
        ));
    }
    require_non_placeholder("generated_by", &manifest.generated_by)?;
    let _ = &manifest.note;
    if manifest.device_test_evidence.is_empty() {
        return Err("release manifest has no required device-test evidence".to_owned());
    }
    let fluxd_revision = manifest
        .binaries
        .iter()
        .find(|binary| binary.name == "fluxd")
        .map(|binary| binary.source_revision.as_str())
        .ok_or_else(|| "device evidence cannot bind a missing fluxd manifest record".to_owned())?;
    let payload_sha256 = operational_payload_sha256(stage, profile)?;
    for evidence in &manifest.device_test_evidence {
        let relative = validated_relative_path("device_test_evidence.path", &evidence.path)?;
        if !relative.starts_with("evidence")
            || relative.extension().and_then(|value| value.to_str()) != Some("json")
        {
            return Err(format!(
                "device-test evidence must be a JSON file under evidence/: {}",
                evidence.path
            ));
        }
        validate_sha256("device-test evidence", &evidence.sha256)?;
        validate_source_revision("device-test evidence", &evidence.source_revision)?;
        validate_sha256("device-test payload", &evidence.payload_sha256)?;
        if evidence.source_revision != fluxd_revision
            || !evidence
                .payload_sha256
                .eq_ignore_ascii_case(&payload_sha256)
        {
            return Err(format!(
                "device-test evidence {} does not bind the release source revision and operational payload",
                evidence.path
            ));
        }
        require_non_placeholder(
            "device_test_evidence.device_profile",
            &evidence.device_profile,
        )?;
        require_android_build_fingerprint(&evidence.android_build_fingerprint)?;
        require_non_placeholder(
            "device_test_evidence.kernel_release",
            &evidence.kernel_release,
        )?;
        android_kernel::validate_supported_release(&evidence.kernel_release)?;
        validate_boot_id(&evidence.boot_id)?;
        if !matches!(
            evidence.verified_boot_state.as_str(),
            "green" | "yellow" | "orange"
        ) {
            return Err(format!(
                "device-test evidence {} has an invalid verified_boot_state",
                evidence.path
            ));
        }
        if !evidence.selinux_enforcing {
            return Err(format!(
                "device-test evidence {} must record SELinux enforcing",
                evidence.path
            ));
        }
        validate_utc_timestamp(
            "device_test_evidence.captured_at_utc",
            &evidence.captured_at_utc,
        )?;
        let path = stage.join(relative);
        if !path.is_file() {
            return Err(format!(
                "device-test evidence file is missing: {}",
                path.display()
            ));
        }
        let actual = sha256_file(&path)?;
        if !actual.eq_ignore_ascii_case(&evidence.sha256) {
            return Err(format!(
                "device-test evidence hash mismatch for {}: expected {}, found {actual}",
                evidence.path, evidence.sha256
            ));
        }
        validate_device_evidence_document(&path, evidence)?;
    }

    let mut names = std::collections::BTreeSet::new();
    let mut paths = std::collections::BTreeSet::new();
    for binary in &manifest.binaries {
        require_manifest_text("binary name", &binary.name)?;
        if !names.insert(binary.name.as_str()) {
            return Err(format!("duplicate manifest binary name '{}'", binary.name));
        }
        let relative = validated_relative_path("binary path", &binary.path)?;
        if !relative.starts_with("bin") {
            return Err(format!(
                "manifest binary '{}' must be installed under bin/",
                binary.name
            ));
        }
        if !paths.insert(binary.path.as_str()) {
            return Err(format!("duplicate manifest binary path '{}'", binary.path));
        }
        require_https_source(&binary.name, &binary.source)?;
        validate_source_revision(&binary.name, &binary.source_revision)?;
        require_non_placeholder(&format!("{} version", binary.name), &binary.version)?;
        if binary.target != ANDROID_TARGET {
            return Err(format!(
                "manifest target for '{}' must be {ANDROID_TARGET}, found {}",
                binary.name, binary.target
            ));
        }
        validate_spdx_license(&binary.name, &binary.license)?;
        validate_sha256(&binary.name, &binary.sha256)?;

        let binary_path = stage.join(relative);
        if !binary_path.is_file() {
            return Err(format!(
                "manifest binary '{}' is missing at {}",
                binary.name,
                binary_path.display()
            ));
        }
        let actual = sha256_file(&binary_path)?;
        if !actual.eq_ignore_ascii_case(&binary.sha256) {
            return Err(format!(
                "manifest hash mismatch for '{}': expected {}, found {actual}",
                binary.name, binary.sha256
            ));
        }
        validate_aarch64_elf(&binary.name, &binary_path)?;
    }

    let required_binaries = profile_binary_inventory(profile)?;
    let required_names = required_binaries
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if names != required_names {
        let missing = required_names.difference(&names).next();
        let extra = names.difference(&required_names).next();
        return Err(format!(
            "release manifest binary inventory must exactly match the {} profile (missing={}, extra={})",
            profile.name.as_str(),
            missing.map_or("none", |value| *value),
            extra.map_or("none", |value| *value)
        ));
    }
    for (required, required_path) in required_binaries {
        if !names.contains(required.as_str()) {
            return Err(format!(
                "release manifest is missing required binary '{required}'"
            ));
        }
        let path = manifest
            .binaries
            .iter()
            .find(|binary| binary.name == required)
            .map(|binary| binary.path.as_str())
            .expect("required name was just found");
        if path != required_path {
            return Err(format!(
                "release manifest binary '{required}' must use path {required_path}, found {path}"
            ));
        }
    }
    reject_unmanifested_binaries(stage, &paths)
}

fn profile_binary_inventory(profile: &PackageProfile) -> Result<Vec<(String, String)>, String> {
    let mut binaries = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for path in profile
        .required_files
        .iter()
        .filter(|path| path.starts_with("bin/"))
    {
        let relative = Path::new(path);
        if relative.parent() != Some(Path::new("bin")) {
            return Err(format!(
                "{} package binary path must be directly below bin/: {path}",
                profile.name.as_str()
            ));
        }
        let name = relative
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| format!("package binary path {path} has no UTF-8 file name"))?
            .to_owned();
        if !names.insert(name.clone()) {
            return Err(format!(
                "{} package profile contains duplicate binary name {name}",
                profile.name.as_str()
            ));
        }
        binaries.push((name, path.clone()));
    }
    Ok(binaries)
}

fn require_package_layout(stage: &Path, profile: &PackageProfile) -> Result<(), String> {
    for relative in &profile.required_files {
        let path = stage.join(relative);
        if !path.is_file() {
            return Err(format!(
                "{} package is missing required file {relative}",
                profile.name.as_str()
            ));
        }
        if fs::metadata(&path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?
            .len()
            == 0
        {
            return Err(format!(
                "{} package required file {relative} is empty",
                profile.name.as_str()
            ));
        }
    }
    validate_module_content(stage, profile)
}

fn validate_source_bound_module_files(
    stage: &Path,
    source_root: &Path,
    profile: &PackageProfile,
) -> Result<(), String> {
    for relative in profile.required_files.iter().filter(|relative| {
        !relative.starts_with("bin/") && relative.as_str() != "conf/manifest.json"
    }) {
        let source_path = authoritative_module_source_path(source_root, relative);
        let source_metadata = fs::symlink_metadata(&source_path)
            .map_err(|error| format!("cannot inspect {}: {error}", source_path.display()))?;
        if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
            return Err(format!(
                "authoritative source-bound module path must be a regular file: {}",
                source_path.display()
            ));
        }
        let source = fs::read(&source_path)
            .map_err(|error| format!("cannot read {}: {error}", source_path.display()))?;
        let staged_path = stage.join(relative);
        let staged = fs::read(&staged_path)
            .map_err(|error| format!("cannot read {}: {error}", staged_path.display()))?;
        if staged != source {
            return Err(format!(
                "release package tracked module file {relative} differs from authoritative source {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn authoritative_module_source_path(source_root: &Path, relative: &str) -> PathBuf {
    source_root.join(relative)
}

fn validate_module_content(stage: &Path, profile: &PackageProfile) -> Result<(), String> {
    for relative in [
        "META-INF/com/google/android/update-binary",
        "customize.sh",
        "flux_service.sh",
        "uninstall.sh",
    ]
    .into_iter()
    .filter(|relative| profile_requires(profile, relative))
    {
        let path = stage.join(relative);
        let contents =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if !contents.starts_with(b"#!") {
            return Err(format!(
                "release package shell entry {relative} is missing a shebang"
            ));
        }
    }

    validate_native_platform_glue(stage)?;

    if profile_requires(profile, "META-INF/com/google/android/updater-script") {
        let updater = fs::read_to_string(stage.join("META-INF/com/google/android/updater-script"))
            .map_err(|error| format!("cannot read updater-script: {error}"))?;
        if updater.trim() != "#MAGISK" {
            return Err("META-INF updater-script must contain exactly #MAGISK".to_owned());
        }
    }

    if profile_requires(profile, "module.prop") {
        let module_prop = fs::read_to_string(stage.join("module.prop"))
            .map_err(|error| format!("cannot read module.prop: {error}"))?;
        let properties = module_prop
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<std::collections::BTreeMap<_, _>>();
        for key in [
            "id",
            "name",
            "version",
            "versionCode",
            "author",
            "description",
        ] {
            if properties
                .get(key)
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(format!("module.prop is missing required property {key}"));
            }
        }
        if properties.get("id") != Some(&"flux")
            || properties["versionCode"]
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .is_none()
        {
            return Err(
                "module.prop must bind id=flux and a positive numeric versionCode".to_owned(),
            );
        }
    }

    if profile_requires(profile, "conf/template.json") {
        let template = fs::read(stage.join("conf/template.json"))
            .map_err(|error| format!("cannot read conf/template.json: {error}"))?;
        let template: serde_json::Value = serde_json::from_slice(&template)
            .map_err(|error| format!("invalid conf/template.json: {error}"))?;
        if !template.is_object() {
            return Err("conf/template.json must contain a JSON object".to_owned());
        }
    }
    let relative = "conf/flux.toml";
    let contents = fs::read_to_string(stage.join(relative))
        .map_err(|error| format!("cannot read {relative}: {error}"))?;
    contents
        .parse::<toml::Value>()
        .map_err(|error| format!("invalid {relative}: {error}"))?;
    Ok(())
}

fn validate_native_platform_glue(stage: &Path) -> Result<(), String> {
    for relative in NATIVE_PLATFORM_GLUE_FILES {
        let path = stage.join(relative);
        let bytes = fs::read(&path)
            .map_err(|error| format!("cannot read native platform glue {relative}: {error}"))?;
        if bytes.len() > MAX_PLATFORM_GLUE_SOURCE_BYTES {
            return Err(format!(
                "native platform glue {relative} exceeds {MAX_PLATFORM_GLUE_SOURCE_BYTES} bytes"
            ));
        }
        let source = std::str::from_utf8(&bytes)
            .map_err(|_| format!("native platform glue {relative} must be UTF-8"))?;
        if !source.is_ascii() || source.contains('\0') {
            return Err(format!(
                "native platform glue {relative} must contain only non-NUL ASCII text"
            ));
        }
        platform_glue::validate_structure(relative, source)?;
    }
    Ok(())
}

fn require_manifest_text(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("manifest field {field} must not be blank"))
    } else {
        Ok(())
    }
}

fn require_non_placeholder(field: &str, value: &str) -> Result<(), String> {
    require_manifest_text(field, value)?;
    match value.trim().to_ascii_lowercase().as_str() {
        "manual" | "placeholder" | "unknown" | "unset" | "tbd" | "none" => Err(format!(
            "manifest field {field} contains a placeholder value"
        )),
        _ => Ok(()),
    }
}

fn require_https_source(name: &str, source: &str) -> Result<(), String> {
    validate_https_url(&format!("manifest source for '{name}'"), source)
}

fn validate_https_url(field: &str, value: &str) -> Result<(), String> {
    require_manifest_text(field, value)?;
    let remainder = value
        .strip_prefix("https://")
        .ok_or_else(|| format!("{field} must be an HTTPS URL with a nonempty host and path"))?;
    if value
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'\\')
    {
        return Err(format!(
            "{field} must be an HTTPS URL with a nonempty host and path"
        ));
    }
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let path = &remainder[authority_end..];
    if authority.is_empty()
        || authority.contains('@')
        || !valid_https_authority(authority)
        || !path.starts_with('/')
        || path == "/"
    {
        return Err(format!(
            "{field} must be an HTTPS URL with a nonempty host and path"
        ));
    }
    Ok(())
}

fn valid_https_authority(authority: &str) -> bool {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some(closing) = bracketed.find(']') else {
            return false;
        };
        let host = &bracketed[..closing];
        let suffix = &bracketed[closing + 1..];
        return host.parse::<std::net::Ipv6Addr>().is_ok()
            && (suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_https_port));
    }

    if authority.contains('[') || authority.contains(']') || authority.matches(':').count() > 1 {
        return false;
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if host.is_empty() || port.is_some_and(|value| !valid_https_port(value)) {
        return false;
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn valid_https_port(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u16>().is_ok_and(|port| port != 0)
}

fn validate_source_revision(name: &str, value: &str) -> Result<(), String> {
    let length = value.len();
    if matches!(length, 40 | 64)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0')
    {
        Ok(())
    } else {
        Err(format!(
            "manifest source_revision for '{name}' must be a 40- or 64-character immutable hexadecimal revision"
        ))
    }
}

fn validate_spdx_license(name: &str, value: &str) -> Result<(), String> {
    require_manifest_text(&format!("{name} license"), value)?;
    const KNOWN_IDS: &[&str] = &[
        "0BSD",
        "Apache-2.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "ISC",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MIT",
        "MPL-2.0",
        "Unlicense",
    ];
    const REVIEWED_LICENSE_REFS: &[&str] = &[];
    let custom = REVIEWED_LICENSE_REFS.contains(&value);
    if KNOWN_IDS.contains(&value) || custom {
        Ok(())
    } else {
        Err(format!(
            "manifest license for '{name}' must be a recognized SPDX identifier or explicitly reviewed LicenseRef"
        ))
    }
}

fn validate_utc_timestamp(field: &str, value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let structure_valid = bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        });
    if !structure_valid {
        return Err(format!(
            "manifest field {field} must be an exact RFC3339 UTC second timestamp"
        ));
    }
    let parse = |range: std::ops::Range<usize>| {
        value[range]
            .parse::<u32>()
            .map_err(|_| format!("manifest field {field} contains an invalid UTC timestamp"))
    };
    let year = parse(0..4)?;
    let month = parse(5..7)?;
    let day = parse(8..10)?;
    let hour = parse(11..13)?;
    let minute = parse(14..16)?;
    let second = parse(17..19)?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year < 1970 || day == 0 || day > max_day || hour > 23 || minute > 59 || second > 59 {
        return Err(format!(
            "manifest field {field} contains an invalid UTC timestamp"
        ));
    }
    Ok(())
}

fn require_android_build_fingerprint(value: &str) -> Result<(), String> {
    require_non_placeholder("device_test_evidence.android_build_fingerprint", value)?;
    if value.contains('/')
        && value.contains(':')
        && !value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        Ok(())
    } else {
        Err("device-test evidence must contain a normalized Android build fingerprint".to_owned())
    }
}

fn validate_boot_id(value: &str) -> Result<(), String> {
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
        && value.bytes().any(|byte| byte != b'0' && byte != b'-');
    if valid {
        Ok(())
    } else {
        Err("device-test evidence boot_id must be a nonzero UUID".to_owned())
    }
}

fn validated_relative_path<'a>(field: &str, value: &'a str) -> Result<&'a Path, String> {
    require_manifest_text(field, value)?;
    let path = Path::new(value);
    if value.contains('\\')
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "manifest field {field} must be a safe relative path"
        ));
    }
    let normalized = portable_relative_path(path)?;
    if normalized != value {
        return Err(format!(
            "manifest field {field} must use normalized forward-slash path syntax"
        ));
    }
    Ok(path)
}

fn validate_sha256(name: &str, value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "manifest sha256 for '{name}' must contain exactly 64 hexadecimal characters"
        ))
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("cannot open {} for hashing: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn operational_payload_sha256(stage: &Path, profile: &PackageProfile) -> Result<String, String> {
    let mut hasher = Sha256::new();
    for relative in &profile.required_files {
        if relative == "conf/manifest.json" {
            continue;
        }
        let artifact_hash = sha256_file(&stage.join(relative))?;
        let path_length = u64::try_from(relative.len())
            .map_err(|_| "operational payload path length does not fit u64".to_owned())?;
        hasher.update(path_length.to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(artifact_hash.as_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_aarch64_elf(name: &str, path: &Path) -> Result<(), String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("cannot open binary {}: {error}", path.display()))?;
    let file_len = file
        .metadata()
        .map_err(|error| format!("cannot inspect binary {}: {error}", path.display()))?
        .len();
    let mut header = [0_u8; 64];
    file.read_exact(&mut header).map_err(|error| {
        format!(
            "manifest binary '{name}' is not a complete ELF header at {}: {error}",
            path.display()
        )
    })?;
    let object_type = u16::from_le_bytes([header[16], header[17]]);
    let machine = u16::from_le_bytes([header[18], header[19]]);
    let elf_version = u32::from_le_bytes(header[20..24].try_into().expect("fixed ELF field"));
    let entry_point = u64::from_le_bytes(header[24..32].try_into().expect("fixed ELF field"));
    let program_offset = u64::from_le_bytes(header[32..40].try_into().expect("fixed ELF field"));
    let header_size = u16::from_le_bytes(header[52..54].try_into().expect("fixed ELF field"));
    let program_entry_size =
        u16::from_le_bytes(header[54..56].try_into().expect("fixed ELF field"));
    let program_count = u16::from_le_bytes(header[56..58].try_into().expect("fixed ELF field"));
    if &header[0..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || !matches!(object_type, 2 | 3)
        || machine != 183
        || elf_version != 1
        || entry_point == 0
        || header_size != 64
        || program_entry_size != 56
        || program_count == 0
        || program_count == u16::MAX
    {
        return Err(format!(
            "manifest binary '{name}' must have a complete ELF64 little-endian AArch64 executable/shared-object header"
        ));
    }

    let table_size = u64::from(program_entry_size)
        .checked_mul(u64::from(program_count))
        .ok_or_else(|| format!("manifest binary '{name}' program table overflows"))?;
    let table_end = program_offset
        .checked_add(table_size)
        .ok_or_else(|| format!("manifest binary '{name}' program table overflows"))?;
    if program_offset < u64::from(header_size) || table_end > file_len {
        return Err(format!(
            "manifest binary '{name}' has an out-of-bounds ELF program table"
        ));
    }

    let mut loadable = false;
    let mut executable_entry = false;
    let mut interpreter_seen = false;
    for index in 0..program_count {
        let offset = program_offset + u64::from(index) * u64::from(program_entry_size);
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| format!("cannot seek {}: {error}", path.display()))?;
        let mut program = [0_u8; 56];
        file.read_exact(&mut program)
            .map_err(|error| format!("cannot read {} program header: {error}", path.display()))?;
        let program_type = u32::from_le_bytes(program[0..4].try_into().expect("fixed ELF field"));
        let flags = u32::from_le_bytes(program[4..8].try_into().expect("fixed ELF field"));
        let segment_offset =
            u64::from_le_bytes(program[8..16].try_into().expect("fixed ELF field"));
        let virtual_address =
            u64::from_le_bytes(program[16..24].try_into().expect("fixed ELF field"));
        let file_size = u64::from_le_bytes(program[32..40].try_into().expect("fixed ELF field"));
        let memory_size = u64::from_le_bytes(program[40..48].try_into().expect("fixed ELF field"));
        let alignment = u64::from_le_bytes(program[48..56].try_into().expect("fixed ELF field"));
        let segment_end = segment_offset
            .checked_add(file_size)
            .ok_or_else(|| format!("manifest binary '{name}' load segment overflows"))?;
        if program_type == 3 {
            if interpreter_seen || !(2..=4096).contains(&file_size) || segment_end > file_len {
                return Err(format!(
                    "manifest binary '{name}' has an invalid PT_INTERP segment"
                ));
            }
            let mut interpreter = vec![
                0_u8;
                usize::try_from(file_size).map_err(|_| format!(
                    "manifest binary '{name}' interpreter is oversized"
                ))?
            ];
            file.seek(SeekFrom::Start(segment_offset))
                .map_err(|error| format!("cannot seek {} interpreter: {error}", path.display()))?;
            file.read_exact(&mut interpreter)
                .map_err(|error| format!("cannot read {} interpreter: {error}", path.display()))?;
            let allowed = [
                b"/system/bin/linker64\0".as_slice(),
                b"/apex/com.android.runtime/bin/linker64\0".as_slice(),
            ];
            if !allowed.contains(&interpreter.as_slice()) {
                return Err(format!(
                    "manifest binary '{name}' uses a non-Android program interpreter"
                ));
            }
            interpreter_seen = true;
            continue;
        }
        if program_type != 1 {
            continue;
        }
        let memory_end = virtual_address
            .checked_add(memory_size)
            .ok_or_else(|| format!("manifest binary '{name}' load address overflows"))?;
        if alignment < ANDROID_MIN_LOAD_ALIGNMENT {
            return Err(format!(
                "manifest binary '{name}' has PT_LOAD alignment {alignment} below the Android {}-byte requirement",
                ANDROID_MIN_LOAD_ALIGNMENT
            ));
        }
        let alignment_valid = alignment.is_power_of_two()
            && segment_offset % alignment == virtual_address % alignment;
        if file_size > 0 && memory_size >= file_size && segment_end <= file_len && alignment_valid {
            loadable = true;
            let file_backed_end = virtual_address
                .checked_add(file_size)
                .ok_or_else(|| format!("manifest binary '{name}' file-backed address overflows"))?;
            if flags & 1 != 0
                && entry_point >= virtual_address
                && entry_point < memory_end
                && entry_point < file_backed_end
            {
                let entry_file_offset = segment_offset
                    .checked_add(entry_point - virtual_address)
                    .ok_or_else(|| {
                    format!("manifest binary '{name}' entry offset overflows")
                })?;
                if entry_file_offset
                    .checked_add(4)
                    .is_some_and(|end| end <= segment_end)
                {
                    file.seek(SeekFrom::Start(entry_file_offset))
                        .map_err(|error| {
                            format!("cannot seek {} executable entry: {error}", path.display())
                        })?;
                    let mut instruction = [0_u8; 4];
                    file.read_exact(&mut instruction).map_err(|error| {
                        format!("cannot read {} executable entry: {error}", path.display())
                    })?;
                    if instruction != [0; 4] {
                        executable_entry = true;
                    }
                }
            }
        } else {
            return Err(format!(
                "manifest binary '{name}' has an invalid PT_LOAD segment"
            ));
        }
    }
    if !loadable {
        return Err(format!(
            "manifest binary '{name}' has no bounded non-empty PT_LOAD segment"
        ));
    }
    if !executable_entry {
        return Err(format!(
            "manifest binary '{name}' entry point is not inside an executable PT_LOAD segment"
        ));
    }
    Ok(())
}

fn validate_device_evidence_document(
    path: &Path,
    manifest: &DeviceEvidenceManifest,
) -> Result<(), String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read device evidence {}: {error}", path.display()))?;
    let document: DeviceEvidenceDocument = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid device evidence {}: {error}", path.display()))?;
    let mut test_ids = std::collections::BTreeSet::new();
    let tests_valid = document.tests.iter().all(|test| {
        !test.id.trim().is_empty() && test.result == "passed" && test_ids.insert(test.id.as_str())
    });
    let required_test_ids = REQUIRED_DEVICE_TESTS
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if document.schema_version != 1
        || document.source_revision != manifest.source_revision
        || !document
            .payload_sha256
            .eq_ignore_ascii_case(&manifest.payload_sha256)
        || document.device_profile != manifest.device_profile
        || document.android_build_fingerprint != manifest.android_build_fingerprint
        || document.kernel_release != manifest.kernel_release
        || document.boot_id != manifest.boot_id
        || document.verified_boot_state != manifest.verified_boot_state
        || document.selinux_enforcing != manifest.selinux_enforcing
        || document.captured_at_utc != manifest.captured_at_utc
        || document.result != "passed"
        || !tests_valid
        || test_ids != required_test_ids
    {
        return Err(format!(
            "device evidence {} is not a matching payload-bound passed schema-1 result with the exact required test set",
            path.display()
        ));
    }
    Ok(())
}

fn validate_spdx_document(path: &Path, manifest: &ReleaseManifest) -> Result<(), String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read SPDX document {}: {error}", path.display()))?;
    let document: SpdxDocument = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid SPDX document {}: {error}", path.display()))?;
    validate_https_url("SPDX documentNamespace", &document.document_namespace)?;
    let creators_valid = !document.creation_info.creators.is_empty()
        && document.creation_info.creators.iter().all(|creator| {
            ["Tool: ", "Organization: ", "Person: "]
                .into_iter()
                .any(|prefix| creator.starts_with(prefix) && creator.len() > prefix.len())
        });
    if document.spdx_version != "SPDX-2.3"
        || document.data_license != "CC0-1.0"
        || document.spdx_id != "SPDXRef-DOCUMENT"
        || document.name.trim().is_empty()
        || validate_utc_timestamp("SPDX creationInfo.created", &document.creation_info.created)
            .is_err()
        || !creators_valid
    {
        return Err(format!(
            "SPDX document {} is missing its required SPDX-2.3 document identity or creation information",
            path.display()
        ));
    }

    let mut spdx_ids = std::collections::BTreeSet::new();
    for package in &document.packages {
        let package_id_valid = package
            .spdx_id
            .strip_prefix("SPDXRef-Package-")
            .is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            });
        let checksum_valid = package.checksums.len() == 1
            && package.checksums[0].algorithm == "SHA256"
            && validate_sha256(&package.name, &package.checksums[0].checksum_value).is_ok();
        if !package_id_valid
            || package.name.trim().is_empty()
            || package.version_info.trim().is_empty()
            || package.download_location.trim().is_empty()
            || package.files_analyzed
            || package.package_verification_code.is_some()
            || !package.license_info_from_files.is_empty()
            || package.copyright_text.trim().is_empty()
            || !checksum_valid
            || !spdx_ids.insert(package.spdx_id.as_str())
        {
            return Err(format!(
                "SPDX document {} contains an incomplete or duplicate package record",
                path.display()
            ));
        }
    }
    let described = document
        .document_describes
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if document.document_describes.len() != described.len() || described != spdx_ids {
        return Err(format!(
            "SPDX document {} documentDescribes must exactly match every unique package SPDXID",
            path.display()
        ));
    }
    if document.packages.len() != manifest.binaries.len() {
        return Err(format!(
            "SPDX document {} package inventory must exactly match the release manifest",
            path.display()
        ));
    }

    for binary in &manifest.binaries {
        let mut matches = document
            .packages
            .iter()
            .filter(|package| package.name == binary.name);
        let package = matches
            .next()
            .ok_or_else(|| format!("SPDX document is missing package '{}'", binary.name))?;
        if matches.next().is_some()
            || package.version_info != binary.version
            || package.download_location != binary.source
            || package.license_declared != binary.license
            || package.license_concluded != binary.license
            || !package.checksums[0]
                .checksum_value
                .eq_ignore_ascii_case(&binary.sha256)
        {
            return Err(format!(
                "SPDX package '{}' does not match manifest version/source/license/hash",
                binary.name
            ));
        }
        if binary.license.starts_with("LicenseRef-")
            && !document.extracted_licensing_infos.iter().any(|license| {
                license.license_id == binary.license && !license.extracted_text.trim().is_empty()
            })
        {
            return Err(format!(
                "SPDX document is missing extracted text for {}",
                binary.license
            ));
        }
    }
    Ok(())
}

fn validate_build_metadata(path: &Path, manifest: &ReleaseManifest) -> Result<(), String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read build metadata {}: {error}", path.display()))?;
    let metadata: BuildMetadata = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid build metadata {}: {error}", path.display()))?;
    if metadata.schema_version != 1 {
        return Err("build metadata schema_version must be 1".to_owned());
    }
    validate_source_revision("build metadata", &metadata.source_revision)?;
    let fluxd_revision = manifest
        .binaries
        .iter()
        .find(|binary| binary.name == "fluxd")
        .map(|binary| binary.source_revision.as_str())
        .ok_or_else(|| "build metadata cannot bind a missing fluxd manifest record".to_owned())?;
    if metadata.source_revision != fluxd_revision {
        return Err("build metadata source_revision does not match the fluxd artifact".to_owned());
    }
    if metadata.rust_toolchain != "1.93.0"
        || metadata.android_ndk_revision != ANDROID_NDK_REVISION
        || metadata.android_target != ANDROID_TARGET
    {
        return Err(format!(
            "build metadata must bind Rust 1.93.0, Android NDK {ANDROID_NDK_REVISION}, and target {ANDROID_TARGET}"
        ));
    }
    validate_utc_timestamp("build_metadata.built_at_utc", &metadata.built_at_utc)
}

fn validate_package_checksums(stage: &Path, checksum_path: &Path) -> Result<(), String> {
    let contents = fs::read_to_string(checksum_path)
        .map_err(|error| format!("cannot read {}: {error}", checksum_path.display()))?;
    let mut declared = std::collections::BTreeSet::new();
    for (index, line) in contents.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let (hash, relative) = line.split_once("  ").ok_or_else(|| {
            format!(
                "{} line {} must use '<sha256>  <relative-path>' syntax",
                checksum_path.display(),
                index + 1
            )
        })?;
        validate_sha256("package checksum", hash)?;
        let relative_path = validated_relative_path("package checksum path", relative)?;
        if relative == "checksums.sha256" {
            return Err("checksums.sha256 must not contain a self-referential checksum".to_owned());
        }
        if !declared.insert(relative.to_owned()) {
            return Err(format!("duplicate package checksum path '{relative}'"));
        }
        let path = stage.join(relative_path);
        if !path.is_file() {
            return Err(format!(
                "package checksum references missing file {relative}"
            ));
        }
        let actual = sha256_file(&path)?;
        if !actual.eq_ignore_ascii_case(hash) {
            return Err(format!(
                "package checksum mismatch for {relative}: expected {hash}, found {actual}"
            ));
        }
    }

    let mut expected = std::collections::BTreeSet::new();
    collect_package_files(stage, stage, &mut expected)?;
    expected.remove("checksums.sha256");
    if declared != expected {
        let missing = expected.difference(&declared).next();
        let extra = declared.difference(&expected).next();
        return Err(format!(
            "package checksum inventory is incomplete or stale (missing={}, extra={})",
            missing.map_or("none", String::as_str),
            extra.map_or("none", String::as_str)
        ));
    }
    Ok(())
}

fn collect_package_files(
    root: &Path,
    current: &Path,
    files: &mut std::collections::BTreeSet<String>,
) -> Result<(), String> {
    for entry in fs::read_dir(current)
        .map_err(|error| format!("cannot read {}: {error}", current.display()))?
    {
        let entry =
            entry.map_err(|error| format!("cannot enumerate {}: {error}", current.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_package_files(root, &path, files)?;
        } else if path.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| format!("cannot relativize {}: {error}", path.display()))?;
            files.insert(portable_relative_path(relative)?);
        }
    }
    Ok(())
}

fn portable_relative_path(path: &Path) -> Result<String, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(value) => parts.push(
                value
                    .to_str()
                    .ok_or_else(|| format!("package path is not UTF-8: {}", path.display()))?,
            ),
            std::path::Component::CurDir => {}
            _ => return Err(format!("package path is not relative: {}", path.display())),
        }
    }
    if parts.is_empty() {
        return Err("package path must not be empty".to_owned());
    }
    Ok(parts.join("/"))
}

fn reject_unmanifested_binaries(
    stage: &Path,
    manifest_paths: &std::collections::BTreeSet<&str>,
) -> Result<(), String> {
    let bin = stage.join("bin");
    reject_unmanifested_binaries_in(stage, &bin, manifest_paths)
}

fn reject_unmanifested_binaries_in(
    stage: &Path,
    current: &Path,
    manifest_paths: &std::collections::BTreeSet<&str>,
) -> Result<(), String> {
    for entry in fs::read_dir(current).map_err(|error| {
        format!(
            "cannot read package binary directory {}: {error}",
            current.display()
        )
    })? {
        let entry =
            entry.map_err(|error| format!("cannot enumerate {}: {error}", current.display()))?;
        let path = entry.path();
        if path.is_dir() {
            reject_unmanifested_binaries_in(stage, &path, manifest_paths)?;
        } else if path.is_file() {
            let relative = path
                .strip_prefix(stage)
                .map_err(|error| format!("cannot relativize {}: {error}", path.display()))?;
            let rendered = portable_relative_path(relative)?;
            if !manifest_paths.contains(rendered.as_str()) {
                return Err(format!(
                    "package binary '{}' has no manifest entry",
                    rendered
                ));
            }
        }
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_owned)
        .ok_or_else(|| "xtask manifest directory has no workspace parent".to_owned())
}

fn require_empty_stage(stage: &Path) -> Result<(), String> {
    if stage.exists() {
        if !stage.is_dir() {
            return Err(format!("stage path {} is not a directory", stage.display()));
        }
        let mut entries = fs::read_dir(stage)
            .map_err(|error| format!("cannot read stage directory {}: {error}", stage.display()))?;
        if entries.next().is_some() {
            return Err(format!("stage directory {} must be empty", stage.display()));
        }
    } else {
        fs::create_dir_all(stage).map_err(|error| {
            format!("cannot create stage directory {}: {error}", stage.display())
        })?;
    }
    Ok(())
}

fn copy_entry(source: &Path, target: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect {}: {error}", source.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing to stage symbolic link {}",
            source.display()
        ));
    }
    if metadata.is_dir() {
        fs::create_dir_all(target)
            .map_err(|error| format!("cannot create {}: {error}", target.display()))?;
        for entry in fs::read_dir(source)
            .map_err(|error| format!("cannot read {}: {error}", source.display()))?
        {
            let entry = entry.map_err(|error| {
                format!("cannot enumerate directory {}: {error}", source.display())
            })?;
            copy_entry(&entry.path(), &target.join(entry.file_name()))?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(format!(
            "refusing to stage non-file entry {}",
            source.display()
        ));
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    fs::copy(source, target).map_err(|error| {
        format!(
            "cannot copy {} to {}: {error}",
            source.display(),
            target.display()
        )
    })?;
    Ok(())
}

fn verify_ndk_revision(ndk_root: &Path) -> Result<(), String> {
    let properties_path = ndk_root.join("source.properties");
    let properties = std::fs::read_to_string(&properties_path)
        .map_err(|error| format!("cannot read {}: {error}", properties_path.display()))?;
    let revision = properties.lines().find_map(|line| {
        line.split_once('=')
            .filter(|(key, _)| key.trim() == "Pkg.Revision")
            .map(|(_, value)| value.trim())
    });
    match revision {
        Some(ANDROID_NDK_REVISION) => Ok(()),
        Some(found) => Err(format!(
            "Android NDK revision {found} is installed; expected {ANDROID_NDK_REVISION}"
        )),
        None => Err(format!(
            "{} does not declare Pkg.Revision",
            properties_path.display()
        )),
    }
}

fn android_linker(ndk_root: &Path, target: &str, clang_target: &str) -> Result<PathBuf, String> {
    let host = match env::consts::OS {
        "windows" => "windows-x86_64",
        "linux" => "linux-x86_64",
        "macos" => "darwin-x86_64",
        other => return Err(format!("unsupported NDK host platform '{other}'")),
    };
    let bin = ndk_root
        .join("toolchains/llvm/prebuilt")
        .join(host)
        .join("bin");
    let base = format!("{clang_target}{ANDROID_API_LEVEL}-clang");
    let candidates = if env::consts::OS == "windows" {
        vec![
            bin.join(format!("{base}.cmd")),
            bin.join(format!("{base}.exe")),
        ]
    } else {
        vec![bin.join(base)]
    };
    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            format!(
                "NDK linker for {target} API {ANDROID_API_LEVEL} was not found under {}",
                bin.display()
            )
        })
}

fn cargo<const N: usize>(args: [&str; N], envs: &[(&str, &std::ffi::OsStr)]) -> Result<(), String> {
    let mut command = cargo_command(args, envs);
    let rendered = format!("cargo {}", args.join(" "));
    let status = command
        .status()
        .map_err(|error| format!("failed to execute `{rendered}`: {error}"))?;
    require_success(&rendered, status)
}

fn cargo_command<const N: usize>(args: [&str; N], envs: &[(&str, &std::ffi::OsStr)]) -> Command {
    let mut command = Command::new("cargo");
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    command
}

fn cargo_stdout<const N: usize>(args: [&str; N]) -> Result<String, String> {
    let rendered = format!("cargo {}", args.join(" "));
    let mut command = Command::new("cargo");
    command.args(args);
    scrub_linux_canary_internal_environment(&mut command);
    let output = command
        .output()
        .map_err(|error| format!("failed to execute `{rendered}`: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "`{rendered}` exited with {}: {}",
            output.status,
            stderr.trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("`{rendered}` produced non-UTF-8 test-list output: {error}"))
}

fn cargo_scrubbed<const N: usize>(args: [&str; N]) -> Result<(), String> {
    let rendered = format!("cargo {}", args.join(" "));
    let mut command = Command::new("cargo");
    command.args(args);
    scrub_linux_canary_internal_environment(&mut command);
    let status = command
        .status()
        .map_err(|error| format!("failed to execute `{rendered}`: {error}"))?;
    require_success(&rendered, status)
}

fn scrub_linux_canary_internal_environment(command: &mut Command) {
    for variable in LINUX_CANARY_INTERNAL_ENVS {
        command.env_remove(variable);
    }
    for variable in NATIVE_COMPOSITION_INTERNAL_ENVS {
        command.env_remove(variable);
    }
}

fn require_success(command: &str, status: ExitStatus) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{command}` exited with {status}"))
    }
}

fn print_help() {
    println!("{}", help_text());
}

fn help_text() -> String {
    let android_canary_command = android_canary::COMMAND;
    format!(
        "Flux build tasks\n\n\
         Usage: cargo xtask <COMMAND>\n\n\
         Commands:\n\
           fmt            Check Rust formatting\n\
           check-host     Type-check the host workspace\n\
           test-host      Run host tests\n\
           clippy         Run Clippy with warnings denied\n\
           check-android  Type-check fluxd with pinned NDK {ANDROID_NDK_REVISION}, API {ANDROID_API_LEVEL}\n\
           build-android  Build release fluxd with NDK {ANDROID_NDK_REVISION}, API {ANDROID_API_LEVEL}\n\
           test-functional-canary-linux  Run the opt-in ignored privileged Linux canary checkpoint\n\
           test-functional-canary-linux-tproxy  Run the ingress-only Linux TPROXY checkpoint\n\
           test-functional-canary-linux-output-tproxy  Run the local-OUTPUT loopback TPROXY checkpoint\n\
           test-functional-canary-linux-output-preflight  Preflight distinct local-OUTPUT credentials (no traffic)\n\
           test-native-composition-linux  Run the single-owner native lifecycle and recovery checkpoint\n\
           test-parser-fuzz-smoke  Run bounded deterministic parser no-panic smoke tests\n\
           {android_canary_command}  Cross-build and run the exact checkpoint on one explicit rooted ARM64 or x86_64 Android serial\n\
           preflight-android-arm64-mark-ordering  Read-only ADR-0013 target viability report for one explicit rooted ARM64 Android serial\n\
           collect-android-arm64-profile  Run the production profile collector in one cleaned explicit-serial ARM64 test directory\n\
           collect-android-arm64-fwmark-census  Run the coherent read-only fwmark census in one cleaned explicit-serial ARM64 test directory\n\
           stage-module   Build and stage the native Magisk tree; requires --stage DIR --runtime-binaries DIR\n\
           verify-package Verify the native package contract; requires --stage DIR\n\
           ci             Run host gates plus the pinned-NDK Android cross-check"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let unique = format!(
                "flux-xtask-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time after epoch")
                    .as_nanos()
            );
            let path = env::temp_dir().join(unique);
            fs::create_dir_all(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_fixture_checksums(stage: &Path) {
        let mut files = std::collections::BTreeSet::new();
        collect_package_files(stage, stage, &mut files).expect("collect fixture files");
        files.remove("checksums.sha256");
        let mut contents = String::new();
        for relative in files {
            let hash = sha256_file(&stage.join(&relative)).expect("hash fixture file");
            contents.push_str(&format!("{hash}  {relative}\n"));
        }
        fs::write(stage.join("checksums.sha256"), contents).expect("write checksums");
    }

    fn write_aarch64_elf(path: &Path, label: &str) {
        write_aarch64_elf_with_load_alignments(path, label, [ANDROID_MIN_LOAD_ALIGNMENT; 2]);
    }

    fn write_aarch64_elf_with_load_alignments(path: &Path, label: &str, alignments: [u64; 2]) {
        let mut bytes = vec![0_u8; 192];
        bytes.extend_from_slice(&0xd65f03c0_u32.to_le_bytes());
        bytes.extend_from_slice(label.as_bytes());
        let file_size = u64::try_from(bytes.len()).expect("fixture length");
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&183_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&192_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&file_size.to_le_bytes());
        bytes[104..112].copy_from_slice(&file_size.to_le_bytes());
        bytes[112..120].copy_from_slice(&alignments[0].to_le_bytes());
        bytes[120..124].copy_from_slice(&1_u32.to_le_bytes());
        bytes[124..128].copy_from_slice(&4_u32.to_le_bytes());
        bytes[128..136].copy_from_slice(&0_u64.to_le_bytes());
        bytes[152..160].copy_from_slice(&file_size.to_le_bytes());
        bytes[160..168].copy_from_slice(&file_size.to_le_bytes());
        bytes[168..176].copy_from_slice(&alignments[1].to_le_bytes());
        fs::write(path, bytes).expect("write AArch64 ELF fixture");
    }

    fn checked_release_manifest() -> ReleaseManifest {
        serde_json::from_str(include_str!("../../conf/manifest.json"))
            .expect("checked release manifest must parse")
    }

    fn checked_profile() -> PackageProfile {
        checked_release_manifest().package_profile
    }

    fn checked_package_profile_json() -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(include_str!("../../conf/manifest.json"))
            .expect("checked release manifest JSON must parse")["package_profile"]
            .clone()
    }

    fn write_required_module_fixture(stage: &Path, profile: &PackageProfile) {
        for relative in &profile.required_files {
            if relative == "conf/manifest.json" || relative.starts_with("bin/") {
                continue;
            }
            let path = stage.join(relative);
            fs::create_dir_all(path.parent().expect("required file parent"))
                .expect("create required fixture parent");
            let contents = match relative.as_str() {
                "META-INF/com/google/android/update-binary" => {
                    "#!/sbin/sh\ninstall_module\n".to_owned()
                }
                "customize.sh" => concat!(
                    "#!/system/bin/sh\n",
                    "[ -x \"${MODPATH}/bin/fluxd\" ] || abort \"missing fluxd\"\n",
                    "[ -f \"${MODPATH}/flux_service.sh\" ] || abort \"missing service\"\n",
                    "[ -f \"${MODPATH}/uninstall.sh\" ] || abort \"missing uninstall\"\n"
                )
                .to_owned(),
                "flux_service.sh" => {
                    "#!/system/bin/sh\nexec /data/adb/flux/bin/fluxd daemon\n".to_owned()
                }
                "uninstall.sh" => concat!(
                    "#!/system/bin/sh\n",
                    "if /data/adb/flux/bin/fluxd ping; then\n",
                    "    /data/adb/flux/bin/fluxd stop && exit 0\n",
                    "fi\n",
                    "exec /data/adb/flux/bin/fluxd cleanup --offline\n"
                )
                .to_owned(),
                "META-INF/com/google/android/updater-script" => "#MAGISK\n".to_owned(),
                "module.prop" => concat!(
                    "id=flux\n",
                    "name=Flux\n",
                    "version=v1.0.0\n",
                    "versionCode=1\n",
                    "author=Flux\n",
                    "description=fixture\n"
                )
                .to_owned(),
                "conf/template.json" => "{}\n".to_owned(),
                "conf/flux.toml" => "fixture = true\n".to_owned(),
                "webroot/index.html" => "<html></html>\n".to_owned(),
                "LICENSE" => "fixture license\n".to_owned(),
                other => panic!("unhandled required fixture file {other}"),
            };
            fs::write(&path, contents).expect("write required fixture file");
        }
    }

    fn write_staging_binary_fixtures(
        artifacts: &Path,
        profile: &PackageProfile,
    ) -> (PathBuf, PathBuf) {
        let runtime_binaries = artifacts.join("runtime-binaries");
        fs::create_dir_all(&runtime_binaries).expect("create runtime binary fixture directory");
        let fluxd = artifacts.join("fluxd");
        fs::write(&fluxd, "fixture fluxd\n").expect("write fluxd fixture");
        for (name, _) in profile_binary_inventory(profile).expect("profile binary inventory") {
            if name != "fluxd" {
                fs::write(runtime_binaries.join(&name), format!("fixture {name}\n"))
                    .expect("write runtime binary fixture");
            }
        }
        (runtime_binaries, fluxd)
    }

    fn assert_exact_staged_inventory(stage: &Path, profile: &PackageProfile) {
        let expected = profile
            .required_files
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let mut actual = std::collections::BTreeSet::new();
        collect_package_files(stage, stage, &mut actual).expect("collect staged fixture inventory");
        assert_eq!(actual, expected);
    }

    #[test]
    fn linux_canary_required_contract_accepts_only_zero_one_or_unset() {
        assert_eq!(parse_linux_canary_required(None), Ok(false));
        assert_eq!(parse_linux_canary_required(Some("0")), Ok(false));
        assert_eq!(parse_linux_canary_required(Some("1")), Ok(true));
        assert!(parse_linux_canary_required(Some("true")).is_err());
    }

    #[test]
    fn native_composition_required_contract_accepts_only_zero_one_or_unset() {
        assert_eq!(parse_native_composition_required(None), Ok(false));
        assert_eq!(parse_native_composition_required(Some("0")), Ok(false));
        assert_eq!(parse_native_composition_required(Some("1")), Ok(true));
        assert!(parse_native_composition_required(Some("true")).is_err());
    }

    #[test]
    fn android_canary_exposes_one_current_command_without_a_compatibility_alias() {
        let help = help_text();
        assert_eq!(help.matches(android_canary::COMMAND).count(), 1);
        assert!(!help.contains("test-functional-canary-android-x86_64-output-tproxy"));

        let current = run([OsString::from(android_canary::COMMAND)])
            .expect_err("the current command still requires an explicit serial");
        assert!(current.contains("requires --serial SERIAL"), "{current}");

        let retired = run([OsString::from(
            "test-functional-canary-android-x86_64-output-tproxy",
        )])
        .expect_err("the retired command must not dispatch");
        assert!(retired.starts_with("unknown command"), "{retired}");
    }

    #[test]
    fn android_build_environment_sets_pinned_compilers_and_16k_linker_flag() {
        let compiler =
            std::ffi::OsStr::new("/ndk/toolchains/llvm/bin/aarch64-linux-android31-clang");
        let envs = android_cargo_environment(compiler);
        let command = cargo_command(
            [
                "build",
                "-p",
                "fluxd",
                "--release",
                "--target",
                ANDROID_TARGET,
            ],
            &envs,
        );
        let environment = command
            .get_envs()
            .collect::<std::collections::BTreeMap<_, _>>();

        assert_eq!(
            environment.get(std::ffi::OsStr::new(
                "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
            )),
            Some(&Some(compiler))
        );
        assert_eq!(
            environment.get(std::ffi::OsStr::new("CC_aarch64_linux_android")),
            Some(&Some(compiler))
        );
        assert_eq!(
            environment.get(std::ffi::OsStr::new(ANDROID_TARGET_RUSTFLAGS_ENV)),
            Some(&Some(std::ffi::OsStr::new(ANDROID_RUSTFLAGS)))
        );
        match android_host_build_tmpdir(env::consts::OS) {
            Some(tmpdir) => assert_eq!(
                environment.get(std::ffi::OsStr::new("TMPDIR")),
                Some(&Some(tmpdir))
            ),
            None => assert!(!environment.contains_key(std::ffi::OsStr::new("TMPDIR"))),
        }
        assert_eq!(
            android_host_build_tmpdir("linux"),
            Some(std::ffi::OsStr::new(LINUX_ANDROID_HOST_BUILD_TMPDIR))
        );
        assert_eq!(android_host_build_tmpdir("windows"), None);
        assert_eq!(android_host_build_tmpdir("macos"), None);
        assert!(ANDROID_RUSTFLAGS.contains("max-page-size=16384"));
        assert!(ANDROID_RUSTFLAGS.contains("common-page-size=16384"));
    }

    #[test]
    fn package_commands_accept_only_native_contract_arguments() {
        parse_stage_module_options(&[
            OsString::from("--stage"),
            OsString::from("stage"),
            OsString::from("--runtime-binaries"),
            OsString::from("runtime"),
        ])
        .expect("native stage options must parse");

        parse_verify_package_options(&[OsString::from("--stage"), OsString::from("stage")])
            .expect("native verify options must parse");

        let error = parse_verify_package_options(&[
            OsString::from("--stage"),
            OsString::from("stage"),
            OsString::from("--profile"),
            OsString::from("bridge"),
        ])
        .expect_err("removed profile selector must fail");
        assert!(error.contains("unknown verify-package option '--profile'"));
    }

    #[test]
    fn checked_package_contract_is_the_exact_native_inventory() {
        let manifest = checked_release_manifest();
        validate_package_contract(&manifest).expect("checked native profile must be complete");
        let profile = &manifest.package_profile;
        assert_eq!(profile.name, PackageProfileName::Native);
        assert_eq!(profile.status, PackageProfileStatus::DevelopmentOnly);
        assert_eq!(profile.required_files.len(), NATIVE_REQUIRED_FILES.len());
        for required in NATIVE_PLATFORM_GLUE_FILES {
            assert!(
                profile.required_files.iter().any(|path| path == required),
                "native contract must require platform glue {required}"
            );
        }

        let mut incomplete = checked_release_manifest();
        incomplete
            .package_profile
            .required_files
            .retain(|path| path != "bin/sing-box");
        let error = validate_package_contract(&incomplete)
            .expect_err("missing native path must fail the contract");
        assert!(error.contains("missing=bin/sing-box"));
    }

    #[test]
    fn native_platform_glue_accepts_delegation_and_rejects_owned_behavior() {
        let directory = TestDirectory::new("native-platform-glue");
        let stage = &directory.0;
        let native = checked_profile();
        write_required_module_fixture(stage, &native);
        validate_native_platform_glue(stage)
            .expect("minimal native platform glue must delegate directly to fluxd");

        let hostile_cases = [
            (
                "continued iptables-restore",
                "IPTABLES\\\n-RESTORE < \"${MODPATH}/rules\"\n",
                "networking mutation",
            ),
            (
                "absolute curl",
                "/system/bin/curl https://example.invalid/subscription\n",
                "subscription retrieval",
            ),
            (
                "jq compilation",
                "jq '.route' \"${MODPATH}/conf/template.json\"\n",
                "configuration compilation",
            ),
            (
                "awk compilation",
                "awk '{ print $1 }' \"${MODPATH}/conf/flux.toml\"\n",
                "configuration compilation",
            ),
            (
                "owned runtime cleanup",
                "rm -f /data/adb/flux/run/active_runtime\n",
                "owned-state cleanup",
            ),
            (
                "legacy runtime source",
                ". /data/adb/flux/scripts/lib\n",
                "legacy runtime",
            ),
            (
                "eval command construction",
                "eval \"${command}\"\n",
                "dynamic command construction",
            ),
            (
                "continued sh -c command construction",
                "sh \\\n-c \"${command}\"\n",
                "dynamic command construction",
            ),
            (
                "adjacent quote command concatenation",
                "ip\"\"tables -L\n",
                "networking mutation",
            ),
            (
                "variable executable",
                "tool=iptables\n\"${tool}\" -L\n",
                "dynamic command construction",
            ),
            (
                "function indirection",
                "mutate() { iptables -L; }\nmutate\n",
                "networking mutation",
            ),
            (
                "command substitution",
                "probe=\"$(iptables -L)\"\n",
                "dynamic command construction",
            ),
        ];

        for (label, hostile_source, expected_category) in hostile_cases {
            write_required_module_fixture(stage, &native);
            let path = stage.join("customize.sh");
            let mut source = fs::read_to_string(&path).expect("read clean glue fixture");
            source.push_str(hostile_source);
            fs::write(&path, source).expect("write hostile glue fixture");
            let error = validate_native_platform_glue(stage)
                .expect_err("platform glue ownership drift must fail");
            assert!(
                error.contains(expected_category),
                "{label} returned unexpected policy error: {error}"
            );
        }
    }

    #[test]
    fn native_platform_glue_uses_commands_not_comments_or_strings_as_delegation() {
        let directory = TestDirectory::new("native-platform-glue-structure");
        let stage = &directory.0;
        let native = checked_profile();
        write_required_module_fixture(stage, &native);

        let customize = stage.join("customize.sh");
        let mut source = fs::read_to_string(&customize).expect("read clean customize fixture");
        source.push_str("# iptables and /scripts/ are comments, not commands\n");
        fs::write(&customize, source).expect("write comment fixture");
        validate_native_platform_glue(stage)
            .expect("forbidden words in comments must not invent runtime behavior");

        fs::write(
            stage.join("flux_service.sh"),
            concat!(
                "#!/system/bin/sh\n",
                "# /data/adb/flux/bin/fluxd daemon\n",
                "echo '/data/adb/flux/bin/fluxd daemon'\n",
            ),
        )
        .expect("write comment-only delegation fixture");
        let error = validate_native_platform_glue(stage)
            .expect_err("comment and string markers must not satisfy delegation");
        assert!(
            error.contains("missing required direct delegation command"),
            "unexpected structural policy error: {error}"
        );
    }

    #[test]
    fn native_platform_glue_rejects_unbounded_or_non_ascii_source() {
        let directory = TestDirectory::new("native-platform-glue-text");
        let stage = &directory.0;
        let native = checked_profile();
        write_required_module_fixture(stage, &native);

        fs::write(
            stage.join("customize.sh"),
            vec![b'a'; MAX_PLATFORM_GLUE_SOURCE_BYTES + 1],
        )
        .expect("write oversized glue fixture");
        let oversized =
            validate_native_platform_glue(stage).expect_err("oversized platform glue must fail");
        assert!(oversized.contains("exceeds 131072 bytes"));

        write_required_module_fixture(stage, &native);
        let path = stage.join("customize.sh");
        let mut source = fs::read(&path).expect("read clean glue fixture");
        source.extend_from_slice(&[0xc3, 0xa9]);
        fs::write(&path, source).expect("write non-ASCII glue fixture");
        let non_ascii =
            validate_native_platform_glue(stage).expect_err("non-ASCII platform glue must fail");
        assert!(non_ascii.contains("non-NUL ASCII text"));
    }

    #[test]
    fn staging_uses_the_exact_native_source_inventory() {
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask must be directly below the workspace root");
        let stage_directory = TestDirectory::new("native-stage");
        let artifact_directory = TestDirectory::new("native-artifacts");
        let profile = checked_profile();
        let (runtime_binaries, fluxd) =
            write_staging_binary_fixtures(&artifact_directory.0, &profile);

        stage_module_from_artifacts(
            source_root,
            &stage_directory.0,
            &runtime_binaries,
            &fluxd,
            &profile,
        )
        .expect("native profile must stage from authoritative sources");
        assert_exact_staged_inventory(&stage_directory.0, &profile);
        validate_source_bound_module_files(&stage_directory.0, source_root, &profile)
            .expect("staged source-owned files must retain authoritative bytes");
    }

    #[test]
    fn native_stage_rejects_undeclared_residue_and_binds_root_sources() {
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask must be directly below the workspace root");
        let stage_directory = TestDirectory::new("native-residue-stage");
        let artifact_directory = TestDirectory::new("native-residue-artifacts");
        let native = checked_profile();
        let (runtime_binaries, fluxd) =
            write_staging_binary_fixtures(&artifact_directory.0, &native);
        stage_module_from_artifacts(
            source_root,
            &stage_directory.0,
            &runtime_binaries,
            &fluxd,
            &native,
        )
        .expect("native fixture must stage exactly");

        let residue = stage_directory.0.join("bin/undeclared-helper");
        fs::write(&residue, "undeclared residue\n").expect("write residue fixture");
        let residue_error = validate_staged_runtime_inventory(&stage_directory.0, &native)
            .expect_err("undeclared package residue must fail exact inventory");
        assert!(residue_error.contains("extra=bin/undeclared-helper"));
        fs::remove_file(&residue).expect("remove residue fixture");

        let customize = stage_directory.0.join("customize.sh");
        let original = fs::read(&customize).expect("read staged native installer");
        let mut tampered = original.clone();
        tampered.extend_from_slice(b"# package-only drift\n");
        fs::write(&customize, tampered).expect("tamper staged native installer");
        let error = validate_source_bound_module_files(&stage_directory.0, source_root, &native)
            .expect_err("staged native source drift must fail binding");
        assert!(error.contains("customize.sh"));
        fs::write(&customize, original).expect("restore staged native installer");
        validate_source_bound_module_files(&stage_directory.0, source_root, &native)
            .expect("restored native installer must match its authoritative source");
    }

    #[test]
    fn linux_canary_listing_requires_the_exact_ignored_test_name() {
        let exact = format!("{LINUX_CANARY_TEST}: test\n");
        assert!(linux_canary_test_is_listed(&exact, LINUX_CANARY_TEST));
        assert!(!linux_canary_test_is_listed(
            "functional_canary::linux_namespace_harness::other: test\n",
            LINUX_CANARY_TEST,
        ));
        let tproxy = format!("{LINUX_TPROXY_CANARY_TEST}: test\n");
        assert!(linux_canary_test_is_listed(
            &tproxy,
            LINUX_TPROXY_CANARY_TEST
        ));
        assert!(!linux_canary_test_is_listed(&tproxy, LINUX_CANARY_TEST));
        let output_tproxy = format!("{LINUX_OUTPUT_TPROXY_CANARY_TEST}: test\n");
        assert!(linux_canary_test_is_listed(
            &output_tproxy,
            LINUX_OUTPUT_TPROXY_CANARY_TEST
        ));
        assert!(!linux_canary_test_is_listed(
            &output_tproxy,
            LINUX_TPROXY_CANARY_TEST
        ));
        let output_preflight = format!("{LINUX_OUTPUT_UID_PREFLIGHT_TEST}: test\n");
        assert!(linux_canary_test_is_listed(
            &output_preflight,
            LINUX_OUTPUT_UID_PREFLIGHT_TEST
        ));
        assert!(!linux_canary_test_is_listed(
            &output_preflight,
            LINUX_TPROXY_CANARY_TEST
        ));
        let native_composition = format!("{NATIVE_COMPOSITION_TEST}: test\n");
        assert!(linux_canary_test_is_listed(
            &native_composition,
            NATIVE_COMPOSITION_TEST
        ));
        assert!(!linux_canary_test_is_listed(
            &native_composition,
            LINUX_CANARY_TEST
        ));
    }

    #[test]
    fn linux_canary_invocation_scrubs_internal_reentry_environment() {
        let mut command = Command::new("cargo");
        for variable in LINUX_CANARY_INTERNAL_ENVS {
            command.env(variable, "hostile-parent-value");
        }
        for variable in NATIVE_COMPOSITION_INTERNAL_ENVS {
            command.env(variable, "hostile-parent-value");
        }

        scrub_linux_canary_internal_environment(&mut command);

        for variable in LINUX_CANARY_INTERNAL_ENVS {
            assert!(command.get_envs().any(|(name, value)| {
                name == std::ffi::OsStr::new(variable) && value.is_none()
            }));
        }
        for variable in NATIVE_COMPOSITION_INTERNAL_ENVS {
            assert!(command.get_envs().any(|(name, value)| {
                name == std::ffi::OsStr::new(variable) && value.is_none()
            }));
        }
    }

    #[test]
    fn release_verifier_binds_tracked_module_files_to_authoritative_source() {
        let stage_directory = TestDirectory::new("release-source-stage");
        let source_directory = TestDirectory::new("release-source-root");
        let stage = &stage_directory.0;
        let source_root = &source_directory.0;
        let native = checked_profile();
        write_required_module_fixture(stage, &native);
        write_required_module_fixture(source_root, &native);

        fs::write(stage.join("conf/manifest.json"), "release-populated\n")
            .expect("write staged manifest");
        fs::write(
            source_root.join("conf/manifest.json"),
            "source-placeholder\n",
        )
        .expect("write source manifest");
        validate_source_bound_module_files(stage, source_root, &native)
            .expect("matching tracked module files must verify");

        fs::write(stage.join("customize.sh"), "#!/system/bin/sh\nexit 0\n")
            .expect("tamper staged tracked file");
        let error = validate_source_bound_module_files(stage, source_root, &native)
            .expect_err("staged tracked file divergence must fail");
        assert!(error.contains("customize.sh differs from authoritative source"));
    }

    #[test]
    fn release_verifier_accepts_complete_provenance_and_rejects_kernel_payloads() {
        let directory = TestDirectory::new("release-verifier");
        let stage = &directory.0;
        for relative in ["bin", "conf", "evidence"] {
            fs::create_dir_all(stage.join(relative)).expect("create fixture directory");
        }
        let native = checked_profile();
        write_required_module_fixture(stage, &native);
        for name in ["fluxd", "sing-box"] {
            write_aarch64_elf(&stage.join("bin").join(name), name);
        }
        fs::write(
            stage.join("build-metadata.json"),
            r#"{
                "schema_version":1,
                "source_revision":"0123456789abcdef0123456789abcdef01234567",
                "rust_toolchain":"1.93.0",
                "android_ndk_revision":"27.3.13750724",
                "android_target":"aarch64-linux-android",
                "built_at_utc":"2026-07-14T00:00:00Z"
            }"#,
        )
        .expect("write metadata");
        let payload_sha256 =
            operational_payload_sha256(stage, &native).expect("hash operational payload");
        let evidence_tests = REQUIRED_DEVICE_TESTS
            .into_iter()
            .map(|id| format!("{{\"id\":\"{id}\",\"result\":\"passed\"}}"))
            .collect::<Vec<_>>()
            .join(",");
        let evidence = format!(
            "{{\"schema_version\":1,\"source_revision\":\"0123456789abcdef0123456789abcdef01234567\",\"payload_sha256\":\"{payload_sha256}\",\"device_profile\":\"test-gki-arm64\",\"android_build_fingerprint\":\"flux/test/device:14/UP1A.231005.007/1234567:user/release-keys\",\"kernel_release\":\"5.10.198-android12-9-gki\",\"boot_id\":\"12345678-1234-4abc-8def-1234567890ab\",\"verified_boot_state\":\"green\",\"selinux_enforcing\":true,\"captured_at_utc\":\"2026-07-14T00:00:00Z\",\"result\":\"passed\",\"tests\":[{evidence_tests}]}}"
        );
        fs::write(stage.join("evidence/device.json"), &evidence).expect("write evidence");
        let evidence_hash =
            sha256_file(&stage.join("evidence/device.json")).expect("hash evidence");

        let artifacts = ["fluxd", "sing-box"]
            .into_iter()
            .map(|name| {
                let hash = sha256_file(&stage.join("bin").join(name)).expect("hash fixture");
                let source = format!("https://github.com/Chth1z/Flux/{name}");
                (
                    format!(
                        "{{\"name\":\"{name}\",\"path\":\"bin/{name}\",\"source\":\"{source}\",\"source_revision\":\"0123456789abcdef0123456789abcdef01234567\",\"version\":\"1.0.0\",\"target\":\"aarch64-linux-android\",\"sha256\":\"{hash}\",\"license\":\"GPL-3.0-only\"}}"
                    ),
                    format!(
                        "{{\"SPDXID\":\"SPDXRef-Package-{name}\",\"name\":\"{name}\",\"versionInfo\":\"1.0.0\",\"downloadLocation\":\"{source}\",\"licenseConcluded\":\"GPL-3.0-only\",\"licenseDeclared\":\"GPL-3.0-only\",\"filesAnalyzed\":false,\"copyrightText\":\"Copyright Flux test fixture\",\"checksums\":[{{\"algorithm\":\"SHA256\",\"checksumValue\":\"{hash}\"}}]}}"
                    ),
                )
            })
            .collect::<Vec<_>>();
        let binaries = artifacts
            .iter()
            .map(|(binary, _)| binary.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let spdx_packages = artifacts
            .iter()
            .map(|(_, package)| package.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let spdx_describes = ["fluxd", "sing-box"]
            .into_iter()
            .map(|name| format!("\"SPDXRef-Package-{name}\""))
            .collect::<Vec<_>>()
            .join(",");
        let sbom = format!(
            "{{\"spdxVersion\":\"SPDX-2.3\",\"dataLicense\":\"CC0-1.0\",\"SPDXID\":\"SPDXRef-DOCUMENT\",\"name\":\"Flux release fixture\",\"documentNamespace\":\"https://github.com/Chth1z/Flux/spdx/0123456789abcdef0123456789abcdef01234567\",\"creationInfo\":{{\"created\":\"2026-07-14T00:00:00Z\",\"creators\":[\"Tool: cargo xtask package-magisk\"]}},\"documentDescribes\":[{spdx_describes}],\"packages\":[{spdx_packages}]}}"
        );
        fs::write(stage.join("SBOM.spdx.json"), &sbom).expect("write SBOM");
        let package_profile = checked_package_profile_json();
        let manifest = format!(
            "{{\"schema_version\":4,\"project\":\"Flux\",\"generated_by\":\"cargo xtask package-magisk\",\"binaries\":[{binaries}],\"device_test_evidence\":[{{\"path\":\"evidence/device.json\",\"sha256\":\"{evidence_hash}\",\"source_revision\":\"0123456789abcdef0123456789abcdef01234567\",\"payload_sha256\":\"{payload_sha256}\",\"device_profile\":\"test-gki-arm64\",\"android_build_fingerprint\":\"flux/test/device:14/UP1A.231005.007/1234567:user/release-keys\",\"kernel_release\":\"5.10.198-android12-9-gki\",\"boot_id\":\"12345678-1234-4abc-8def-1234567890ab\",\"verified_boot_state\":\"green\",\"selinux_enforcing\":true,\"captured_at_utc\":\"2026-07-14T00:00:00Z\"}}],\"package_profile\":{package_profile}}}"
        );
        fs::write(stage.join("conf/manifest.json"), &manifest).expect("write manifest");
        let parsed_manifest: ReleaseManifest =
            serde_json::from_str(&manifest).expect("parse complete manifest");
        let expected_revisions = WorkspaceSourceRevisions {
            fluxd: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        };
        validate_first_party_source_revisions(&parsed_manifest, &expected_revisions)
            .expect("matching first-party revisions must verify");
        let wrong_revisions = WorkspaceSourceRevisions {
            fluxd: "1123456789abcdef0123456789abcdef01234567".to_owned(),
        };
        let revision_error =
            validate_first_party_source_revisions(&parsed_manifest, &wrong_revisions)
                .expect_err("mismatched workspace revision must fail");
        assert!(revision_error.contains("must equal the clean workspace revision"));
        let mut incomplete_evidence: serde_json::Value =
            serde_json::from_str(&evidence).expect("parse evidence fixture");
        incomplete_evidence["tests"]
            .as_array_mut()
            .expect("evidence tests array")
            .pop();
        fs::write(
            stage.join("evidence/device.json"),
            serde_json::to_vec(&incomplete_evidence).expect("encode incomplete evidence"),
        )
        .expect("write incomplete evidence");
        let evidence_error = validate_device_evidence_document(
            &stage.join("evidence/device.json"),
            &parsed_manifest.device_test_evidence[0],
        )
        .expect_err("incomplete device test set must fail");
        assert!(evidence_error.contains("exact required test set"));
        fs::write(stage.join("evidence/device.json"), &evidence).expect("restore evidence");
        write_fixture_checksums(stage);

        verify_package_dir_with_source(stage, stage).expect("complete native fixture must verify");

        fs::write(stage.join("post-fs-data.sh"), "#!/system/bin/sh\nexit 0\n")
            .expect("write unreviewed Magisk root payload");
        let error = verify_package_dir_with_source(stage, stage)
            .expect_err("unreviewed package-root payload must fail");
        assert!(error.contains("extra=post-fs-data.sh"));
        fs::remove_file(stage.join("post-fs-data.sh"))
            .expect("remove unreviewed Magisk root payload");

        let mut dangling_description: serde_json::Value =
            serde_json::from_str(&sbom).expect("parse fixture SBOM");
        dangling_description["documentDescribes"]
            .as_array_mut()
            .expect("documentDescribes array")
            .push(serde_json::Value::String("SPDXRef-Package-missing".into()));
        fs::write(
            stage.join("SBOM.spdx.json"),
            serde_json::to_vec(&dangling_description).expect("encode dangling SPDX reference"),
        )
        .expect("write dangling SPDX reference");
        let error = verify_package_dir_with_source(stage, stage)
            .expect_err("dangling documentDescribes reference must fail");
        assert!(error.contains("documentDescribes must exactly match"));
        fs::write(stage.join("SBOM.spdx.json"), &sbom).expect("restore SBOM");

        let customize = fs::read(stage.join("customize.sh")).expect("read required file");
        fs::remove_file(stage.join("customize.sh")).expect("remove required file");
        write_fixture_checksums(stage);
        let error = verify_package_dir_with_source(stage, stage)
            .expect_err("incomplete full layout must fail");
        assert!(error.contains("missing required file customize.sh"));
        fs::write(stage.join("customize.sh"), customize).expect("restore required file");
        write_fixture_checksums(stage);

        let module_prop = fs::read(stage.join("module.prop")).expect("read module.prop");
        fs::write(stage.join("module.prop"), b"").expect("empty required file");
        write_fixture_checksums(stage);
        let error = verify_package_dir_with_source(stage, stage)
            .expect_err("empty required file must fail");
        assert!(error.contains("required file module.prop is empty"));
        fs::write(stage.join("module.prop"), module_prop).expect("restore module.prop");
        write_fixture_checksums(stage);

        let mut wrong_path: serde_json::Value =
            serde_json::from_str(&manifest).expect("parse fixture manifest");
        wrong_path["binaries"][0]["path"] = serde_json::Value::String("bin/not-fluxd".into());
        fs::copy(stage.join("bin/fluxd"), stage.join("bin/not-fluxd"))
            .expect("copy renamed binary fixture");
        fs::write(
            stage.join("conf/manifest.json"),
            serde_json::to_vec(&wrong_path).expect("encode wrong-path manifest"),
        )
        .expect("write wrong-path manifest");
        let error = verify_package_dir_with_source(stage, stage)
            .expect_err("required path substitution must fail");
        assert!(error.contains("extra=bin/not-fluxd"));
        fs::remove_file(stage.join("bin/not-fluxd")).expect("remove renamed fixture");
        fs::write(stage.join("conf/manifest.json"), &manifest).expect("restore manifest");

        fs::write(stage.join("bin/extension.ko"), "forbidden\n").expect("write payload");
        let error =
            verify_package_dir_with_source(stage, stage).expect_err("kernel payload must fail");
        assert!(error.contains("forbidden kernel payload"));

        fs::remove_file(stage.join("bin/extension.ko")).expect("remove payload");
        fs::write(stage.join("bin/.ko"), "forbidden\n").expect("write hidden payload");
        let error = verify_package_dir_with_source(stage, stage)
            .expect_err("hidden kernel payload must fail");
        assert!(error.contains("forbidden kernel payload bin/.ko"));
        fs::remove_file(stage.join("bin/.ko")).expect("remove hidden payload");
        fs::create_dir(stage.join("bin/helpers")).expect("create nested binary directory");
        fs::write(stage.join("bin/helpers/unmanifested"), "unexpected\n")
            .expect("write unmanifested binary");
        let error = verify_package_dir_with_source(stage, stage)
            .expect_err("nested unmanifested binary must fail");
        assert!(error.contains("extra=bin/helpers/unmanifested"));

        fs::remove_dir_all(stage.join("bin/helpers")).expect("remove nested binary directory");
        let mut metadata = fs::read(stage.join("build-metadata.json")).expect("read metadata");
        metadata.push(b'\n');
        fs::write(stage.join("build-metadata.json"), metadata).expect("tamper metadata");
        let error = verify_package_dir_with_source(stage, stage)
            .expect_err("stale checksum inventory must fail");
        assert!(error.contains("package checksum mismatch"));
    }

    #[test]
    fn release_manifest_rejects_blank_device_evidence_and_machine_local_sources() {
        let mut manifest_value: serde_json::Value =
            serde_json::from_str(include_str!("../../conf/manifest.json"))
                .expect("parse checked manifest fixture");
        manifest_value["generated_by"] = serde_json::Value::String("test".to_owned());
        manifest_value["binaries"] = serde_json::json!([{
            "name": "fluxd",
            "path": "bin/fluxd",
            "source": "D:/Github/Flux",
            "source_revision": "0123456789abcdef0123456789abcdef01234567",
            "version": "0.1.0",
            "target": "aarch64-linux-android",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "license": "GPL-3.0-only"
        }]);
        let manifest: ReleaseManifest =
            serde_json::from_value(manifest_value).expect("parse manifest fixture");
        let directory = TestDirectory::new("invalid-manifest");
        let error = validate_release_manifest(&directory.0, &manifest, &manifest.package_profile)
            .expect_err("missing evidence must fail before source acceptance");
        assert!(error.contains("no required device-test evidence"));

        let source_error = require_https_source("fluxd", "D:/Github/Flux")
            .expect_err("machine-local source must fail");
        assert!(source_error.contains("HTTPS URL"));
        let hostless_source = require_https_source("fluxd", "https:///D:/Github/Flux")
            .expect_err("hostless HTTPS source must fail");
        assert!(hostless_source.contains("nonempty host and path"));
        require_https_source("fluxd", "https://[::1/path")
            .expect_err("unclosed IPv6 authority must fail");
        require_https_source("fluxd", "https://example.com:notaport/path")
            .expect_err("nonnumeric HTTPS port must fail");

        let license_error =
            validate_spdx_license("fluxd", "NOT-A-REAL-LICENSE").expect_err("invalid SPDX id");
        assert!(license_error.contains("recognized SPDX identifier"));
        let unlicensed_error = validate_spdx_license("fixture", "LicenseRef-UNLICENSED")
            .expect_err("unlicensed placeholder must not become a reviewed custom license");
        assert!(unlicensed_error.contains("explicitly reviewed LicenseRef"));

        let revision_error =
            validate_source_revision("fluxd", "0000000000000000000000000000000000000000")
                .expect_err("zero revision must fail");
        assert!(revision_error.contains("immutable hexadecimal revision"));

        let timestamp_error = validate_utc_timestamp("test", "2026-02-30T25:00:00Z")
            .expect_err("invalid calendar and hour values must fail");
        assert!(timestamp_error.contains("invalid UTC timestamp"));

        let text_binary = directory.0.join("not-elf");
        fs::write(&text_binary, "not an executable\n").expect("write text binary");
        let elf_error =
            validate_aarch64_elf("fluxd", &text_binary).expect_err("text must not pass as ELF");
        assert!(elf_error.contains("not a complete ELF header"));

        let no_entry_binary = directory.0.join("no-entry-elf");
        write_aarch64_elf(&no_entry_binary, "no-entry");
        let mut no_entry = fs::read(&no_entry_binary).expect("read ELF fixture");
        no_entry[24..32].fill(0);
        fs::write(&no_entry_binary, no_entry).expect("write zero-entry ELF fixture");
        let no_entry_error = validate_aarch64_elf("fluxd", &no_entry_binary)
            .expect_err("ELF without an executable entry point must fail");
        assert!(no_entry_error.contains("executable/shared-object header"));
    }

    #[test]
    fn aarch64_elf_alignment_checks_every_load_segment_against_16k_minimum() {
        let directory = TestDirectory::new("elf-load-alignment");

        for (name, alignment) in [("16k", 1 << 14), ("64k", 1 << 16)] {
            let binary = directory.0.join(format!("{name}-aligned-elf"));
            write_aarch64_elf_with_load_alignments(&binary, name, [alignment, alignment]);
            validate_aarch64_elf("fluxd", &binary)
                .expect("at-least-16 KiB-aligned ELF fixture must pass");
        }

        let under_aligned = directory.0.join("8k-aligned-elf");
        write_aarch64_elf_with_load_alignments(&under_aligned, "8k", [1 << 13, 1 << 14]);
        let alignment_error = validate_aarch64_elf("fluxd", &under_aligned)
            .expect_err("8 KiB PT_LOAD alignment must fail");
        assert!(alignment_error.contains("below the Android 16384-byte requirement"));

        let later_under_aligned = directory.0.join("later-4k-aligned-elf");
        write_aarch64_elf_with_load_alignments(
            &later_under_aligned,
            "later-4k",
            [1 << 14, 1 << 12],
        );
        let later_error = validate_aarch64_elf("sing-box", &later_under_aligned)
            .expect_err("later 4 KiB PT_LOAD alignment must fail");
        assert!(later_error.contains("below the Android 16384-byte requirement"));
    }
}
