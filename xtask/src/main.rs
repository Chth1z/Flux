use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use serde::Deserialize;
use sha2::{Digest, Sha256};

mod xtables_oracle;

const ANDROID_TARGET: &str = "aarch64-linux-android";
const ANDROID_API_LEVEL: &str = "31";
const ANDROID_NDK_REVISION: &str = "27.3.13750724";
const REQUIRED_MODULE_FILES: [&str; 28] = [
    "META-INF/com/google/android/update-binary",
    "META-INF/com/google/android/updater-script",
    "bin/fluxd",
    "bin/addrsyncd",
    "bin/jq",
    "bin/sing-box",
    "conf/flux.toml",
    "conf/settings.ini",
    "conf/addrsyncd.toml",
    "conf/template.json",
    "conf/manifest.json",
    "scripts/addrsync",
    "scripts/config",
    "scripts/core",
    "scripts/dispatcher",
    "scripts/flux-event",
    "scripts/fluxctl",
    "scripts/init",
    "scripts/lib",
    "scripts/log",
    "scripts/rules",
    "scripts/tproxy",
    "scripts/updater.sh",
    "webroot/index.html",
    "customize.sh",
    "flux_service.sh",
    "module.prop",
    "LICENSE",
];
const SOURCE_BOUND_MODULE_ENTRIES: [&str; 8] = [
    "META-INF",
    "conf",
    "scripts",
    "webroot",
    "customize.sh",
    "flux_service.sh",
    "module.prop",
    "LICENSE",
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
const LINUX_OUTPUT_UID_PREFLIGHT_TEST: &str = "functional_canary::linux_namespace_harness::privileged_local_output_distinct_uid_capability_preflight";
const LINUX_CANARY_INTERNAL_ENVS: [&str; 15] = [
    "FLUX_LINUX_CANARY_HARNESS_MODE",
    "FLUX_LINUX_CANARY_HARNESS_CONFIG",
    "FLUX_LINUX_CANARY_REENTRY_TOKEN",
    "FLUX_LINUX_CANARY_OUTER_NETNS",
    "FLUX_LINUX_CANARY_OUTER_USERNS",
    "FLUX_LINUX_CANARY_OUTER_MOUNTNS",
    "FLUX_LINUX_CANARY_EXPECTED_UID_MAP",
    "FLUX_LINUX_CANARY_EXPECTED_GID_MAP",
    "FLUX_LINUX_CANARY_MAPPING_MECHANISM",
    "FLUX_LINUX_CANARY_ROLE_UID",
    "FLUX_LINUX_CANARY_ROLE_GID",
    "FLUX_LINUX_CANARY_OUTER_SUPPLEMENTARY_GROUPS",
    "FLUX_LINUX_CANARY_INNER_NETNS",
    "FLUX_LINUX_CANARY_INNER_USERNS",
    "FLUX_LINUX_CANARY_INNER_MOUNTNS",
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
            cargo(["check", "-p", "fluxd", "--target", ANDROID_TARGET], &[])
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
        "test-functional-canary-linux-output-preflight" => {
            require_no_arguments(&arguments)?;
            test_functional_canary_linux_output_preflight()
        }
        "xtables-oracle" => {
            let mode = xtables_oracle::parse_options(&arguments)?;
            xtables_oracle::run(mode)
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
            cargo(["check", "-p", "fluxd", "--target", ANDROID_TARGET], &[])
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

fn test_functional_canary_linux_output_preflight() -> Result<(), String> {
    test_linux_canary(LINUX_OUTPUT_UID_PREFLIGHT_TEST)
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
    addrsyncd: String,
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
    default_package_profiles: Vec<PackageProfile>,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProfile {
    name: String,
    description: String,
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
            .ok_or_else(|| format!("{flag} requires a path"))?;
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
            .ok_or_else(|| format!("{flag} requires a path"))?;
        match flag.as_ref() {
            "--stage" if stage.is_none() => stage = Some(PathBuf::from(value)),
            "--stage" => return Err("--stage may only be supplied once".to_owned()),
            unknown => return Err(format!("unknown verify-package option '{unknown}'")),
        }
        index = index.saturating_add(2);
    }

    Ok(VerifyPackageOptions {
        stage: stage.ok_or_else(|| "verify-package requires --stage DIR".to_owned())?,
    })
}

fn build_android() -> Result<(), String> {
    let ndk_root = env::var_os("ANDROID_NDK_HOME")
        .or_else(|| env::var_os("ANDROID_NDK_ROOT"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            "ANDROID_NDK_HOME must point to Android NDK revision 27.3.13750724".to_owned()
        })?;

    verify_ndk_revision(&ndk_root)?;
    let linker = android_linker(&ndk_root)?;
    let linker_env = linker.into_os_string();
    cargo(
        [
            "build",
            "-p",
            "fluxd",
            "--release",
            "--target",
            ANDROID_TARGET,
        ],
        &[(
            "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER",
            linker_env.as_os_str(),
        )],
    )
}

fn stage_module(options: StageModuleOptions) -> Result<(), String> {
    build_android()?;

    require_empty_stage(&options.stage)?;
    let root = workspace_root()?;
    for relative in [
        "META-INF",
        "conf",
        "scripts",
        "webroot",
        "customize.sh",
        "flux_service.sh",
        "module.prop",
        "LICENSE",
    ] {
        copy_entry(&root.join(relative), &options.stage.join(relative))?;
    }
    copy_entry(&options.runtime_binaries, &options.stage.join("bin"))?;

    let fluxd_source = root
        .join("target")
        .join(ANDROID_TARGET)
        .join("release")
        .join("fluxd");
    if !fluxd_source.is_file() {
        return Err(format!(
            "Android build succeeded but {} is missing",
            fluxd_source.display()
        ));
    }
    let fluxd_target = options.stage.join("bin/fluxd");
    if let Some(parent) = fluxd_target.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    fs::copy(&fluxd_source, &fluxd_target).map_err(|error| {
        format!(
            "cannot copy {} to {}: {error}",
            fluxd_source.display(),
            fluxd_target.display()
        )
    })?;

    for relative in REQUIRED_MODULE_FILES {
        let required = options.stage.join(relative);
        if !required.is_file() {
            return Err(format!(
                "staged module is missing required file {}",
                required.display()
            ));
        }
    }

    println!(
        "staged development Android module at {}",
        options.stage.display()
    );
    println!(
        "release publication still requires `cargo xtask verify-package --stage {}`",
        options.stage.display()
    );
    Ok(())
}

fn verify_package(options: VerifyPackageOptions) -> Result<(), String> {
    let source_root = workspace_root()?;
    let source_revisions = verify_workspace_source_state(&source_root)?;
    verify_package_dir_with_source(&options.stage, &source_root)?;
    validate_package_source_revisions(&options.stage, &source_revisions)?;
    println!("verified release package at {}", options.stage.display());
    Ok(())
}

fn verify_workspace_source_state(root: &Path) -> Result<WorkspaceSourceRevisions, String> {
    require_clean_git_worktree(root, "Flux workspace")?;
    let addrsyncd = root.join("addrsyncd");
    require_clean_git_worktree(&addrsyncd, "addrsyncd submodule")?;
    let fluxd_revision = git_stdout(root, &["rev-parse", "HEAD"])?;
    let addrsyncd_revision = git_stdout(&addrsyncd, &["rev-parse", "HEAD"])?;
    validate_source_revision("Flux workspace HEAD", &fluxd_revision)?;
    validate_source_revision("addrsyncd submodule HEAD", &addrsyncd_revision)?;
    Ok(WorkspaceSourceRevisions {
        fluxd: fluxd_revision,
        addrsyncd: addrsyncd_revision,
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
    let manifest: ReleaseManifest = serde_json::from_slice(
        &fs::read(&manifest_path)
            .map_err(|error| format!("cannot read {}: {error}", manifest_path.display()))?,
    )
    .map_err(|error| format!("invalid {}: {error}", manifest_path.display()))?;
    validate_first_party_source_revisions(&manifest, revisions)
}

fn validate_first_party_source_revisions(
    manifest: &ReleaseManifest,
    revisions: &WorkspaceSourceRevisions,
) -> Result<(), String> {
    for (name, expected) in [
        ("fluxd", revisions.fluxd.as_str()),
        ("addrsyncd", revisions.addrsyncd.as_str()),
    ] {
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

    require_package_layout(stage)?;
    reject_unsafe_package_entries(stage, stage)?;
    validate_source_bound_module_files(stage, source_root)?;
    for relative in [
        "conf/manifest.json",
        "SBOM.spdx.json",
        "checksums.sha256",
        "build-metadata.json",
    ] {
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
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("cannot read {}: {error}", manifest_path.display()))?;
    let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid {}: {error}", manifest_path.display()))?;
    validate_package_file_inventory(stage, &manifest)?;
    validate_release_manifest(stage, &manifest)?;
    validate_spdx_document(&stage.join("SBOM.spdx.json"), &manifest)?;
    validate_build_metadata(&stage.join("build-metadata.json"), &manifest)?;
    validate_package_checksums(stage, &stage.join("checksums.sha256"))
}

fn validate_package_file_inventory(stage: &Path, manifest: &ReleaseManifest) -> Result<(), String> {
    let mut allowed = REQUIRED_MODULE_FILES
        .into_iter()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    for relative in ["SBOM.spdx.json", "checksums.sha256", "build-metadata.json"] {
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
            "release package file inventory differs from the reviewed full profile (missing={}, extra={})",
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

fn validate_release_manifest(stage: &Path, manifest: &ReleaseManifest) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err(format!(
            "unsupported manifest schema version {}",
            manifest.schema_version
        ));
    }
    require_manifest_text("project", &manifest.project)?;
    if manifest.project != "Flux" {
        return Err(format!(
            "manifest project must be Flux, found '{}'",
            manifest.project
        ));
    }
    require_non_placeholder("generated_by", &manifest.generated_by)?;
    let _ = &manifest.note;

    if manifest.default_package_profiles.len() != 1
        || manifest.default_package_profiles[0].name != "full"
    {
        return Err("release manifest must declare exactly the full package profile".to_owned());
    }
    require_manifest_text(
        "default_package_profiles[0].description",
        &manifest.default_package_profiles[0].description,
    )?;

    if manifest.device_test_evidence.is_empty() {
        return Err("release manifest has no required device-test evidence".to_owned());
    }
    let fluxd_revision = manifest
        .binaries
        .iter()
        .find(|binary| binary.name == "fluxd")
        .map(|binary| binary.source_revision.as_str())
        .ok_or_else(|| "device evidence cannot bind a missing fluxd manifest record".to_owned())?;
    let payload_sha256 = operational_payload_sha256(stage)?;
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
        validate_kernel_release_floor(&evidence.kernel_release)?;
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

    let required_binaries = [
        ("fluxd", "bin/fluxd"),
        ("sing-box", "bin/sing-box"),
        ("jq", "bin/jq"),
        ("addrsyncd", "bin/addrsyncd"),
    ];
    let required_names = required_binaries
        .iter()
        .map(|(name, _)| *name)
        .collect::<std::collections::BTreeSet<_>>();
    if names != required_names {
        let missing = required_names.difference(&names).next();
        let extra = names.difference(&required_names).next();
        return Err(format!(
            "release manifest binary inventory must exactly match the full bridge profile (missing={}, extra={})",
            missing.map_or("none", |value| *value),
            extra.map_or("none", |value| *value)
        ));
    }
    for (required, required_path) in required_binaries {
        if !names.contains(required) {
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

fn require_package_layout(stage: &Path) -> Result<(), String> {
    for relative in REQUIRED_MODULE_FILES {
        let path = stage.join(relative);
        if !path.is_file() {
            return Err(format!(
                "full release package is missing required file {relative}"
            ));
        }
        if fs::metadata(&path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?
            .len()
            == 0
        {
            return Err(format!(
                "full release package required file {relative} is empty"
            ));
        }
    }
    validate_module_content(stage)
}

fn validate_source_bound_module_files(stage: &Path, source_root: &Path) -> Result<(), String> {
    let expected_files = REQUIRED_MODULE_FILES
        .into_iter()
        .filter(|relative| !relative.starts_with("bin/") && *relative != "conf/manifest.json")
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    let source_files = collect_source_bound_module_files(source_root)?;
    let staged_files = collect_source_bound_module_files(stage)?;
    if source_files != expected_files {
        let missing = expected_files.difference(&source_files).next();
        let extra = source_files.difference(&expected_files).next();
        return Err(format!(
            "authoritative source-bound module inventory differs from the reviewed package inventory (missing={}, extra={})",
            missing.map_or("none", String::as_str),
            extra.map_or("none", String::as_str)
        ));
    }
    if staged_files != expected_files {
        let missing = expected_files.difference(&staged_files).next();
        let extra = staged_files.difference(&expected_files).next();
        return Err(format!(
            "release package source-bound module inventory differs from the reviewed package inventory (missing={}, extra={})",
            missing.map_or("none", String::as_str),
            extra.map_or("none", String::as_str)
        ));
    }

    for relative in expected_files {
        let source_path = source_root.join(&relative);
        let source = fs::read(&source_path)
            .map_err(|error| format!("cannot read {}: {error}", source_path.display()))?;
        let staged_path = stage.join(&relative);
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

fn collect_source_bound_module_files(
    root: &Path,
) -> Result<std::collections::BTreeSet<String>, String> {
    let mut files = std::collections::BTreeSet::new();
    for relative in SOURCE_BOUND_MODULE_ENTRIES {
        collect_source_bound_module_entry(root, &root.join(relative), &mut files)?;
    }
    files.remove("conf/manifest.json");
    Ok(files)
}

fn collect_source_bound_module_entry(
    root: &Path,
    path: &Path,
    files: &mut std::collections::BTreeSet<String>,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect source-bound module entry {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "source-bound module entry is a symbolic link: {}",
            path.display()
        ));
    }
    if metadata.is_file() {
        let relative = path
            .strip_prefix(root)
            .map_err(|error| format!("cannot relativize {}: {error}", path.display()))?;
        files.insert(portable_relative_path(relative)?);
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(format!(
            "source-bound module entry is not a regular file or directory: {}",
            path.display()
        ));
    }
    for entry in fs::read_dir(path).map_err(|error| {
        format!(
            "cannot read source-bound directory {}: {error}",
            path.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "cannot enumerate source-bound directory {}: {error}",
                path.display()
            )
        })?;
        collect_source_bound_module_entry(root, &entry.path(), files)?;
    }
    Ok(())
}

fn validate_module_content(stage: &Path) -> Result<(), String> {
    for relative in [
        "META-INF/com/google/android/update-binary",
        "customize.sh",
        "flux_service.sh",
        "scripts/addrsync",
        "scripts/config",
        "scripts/core",
        "scripts/dispatcher",
        "scripts/flux-event",
        "scripts/fluxctl",
        "scripts/init",
        "scripts/lib",
        "scripts/log",
        "scripts/rules",
        "scripts/tproxy",
        "scripts/updater.sh",
    ] {
        let path = stage.join(relative);
        let contents =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if !contents.starts_with(b"#!") {
            return Err(format!(
                "release package shell entry {relative} is missing a shebang"
            ));
        }
    }

    let updater = fs::read_to_string(stage.join("META-INF/com/google/android/updater-script"))
        .map_err(|error| format!("cannot read updater-script: {error}"))?;
    if updater.trim() != "#MAGISK" {
        return Err("META-INF updater-script must contain exactly #MAGISK".to_owned());
    }

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
        return Err("module.prop must bind id=flux and a positive numeric versionCode".to_owned());
    }

    let template = fs::read(stage.join("conf/template.json"))
        .map_err(|error| format!("cannot read conf/template.json: {error}"))?;
    let template: serde_json::Value = serde_json::from_slice(&template)
        .map_err(|error| format!("invalid conf/template.json: {error}"))?;
    if !template.is_object() {
        return Err("conf/template.json must contain a JSON object".to_owned());
    }
    for relative in ["conf/flux.toml", "conf/addrsyncd.toml"] {
        let contents = fs::read_to_string(stage.join(relative))
            .map_err(|error| format!("cannot read {relative}: {error}"))?;
        contents
            .parse::<toml::Value>()
            .map_err(|error| format!("invalid {relative}: {error}"))?;
    }
    let settings = fs::read_to_string(stage.join("conf/settings.ini"))
        .map_err(|error| format!("cannot read conf/settings.ini: {error}"))?;
    for key in ["PROXY_MODE", "BYPASS_SET_BACKEND"] {
        if !settings
            .lines()
            .any(|line| line.starts_with(&format!("{key}=")))
        {
            return Err(format!(
                "conf/settings.ini is missing required setting {key}"
            ));
        }
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

fn validate_kernel_release_floor(value: &str) -> Result<(), String> {
    let mut components = value.split('.');
    let major = components
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .ok_or_else(|| "device-test kernel release has no numeric major version".to_owned())?;
    let minor_text = components
        .next()
        .ok_or_else(|| "device-test kernel release has no minor version".to_owned())?;
    let minor_digits = minor_text
        .bytes()
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    let minor = std::str::from_utf8(&minor_digits)
        .ok()
        .and_then(|part| part.parse::<u32>().ok())
        .ok_or_else(|| "device-test kernel release has no numeric minor version".to_owned())?;
    if (major, minor) < (5, 10) {
        return Err(format!(
            "device-test kernel release {value} is below the supported 5.10 floor"
        ));
    }
    Ok(())
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

fn operational_payload_sha256(stage: &Path) -> Result<String, String> {
    let mut hasher = Sha256::new();
    for relative in REQUIRED_MODULE_FILES {
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
        let alignment_valid = alignment <= 1
            || (alignment.is_power_of_two()
                && segment_offset % alignment == virtual_address % alignment);
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

fn android_linker(ndk_root: &Path) -> Result<PathBuf, String> {
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
    let base = format!("aarch64-linux-android{ANDROID_API_LEVEL}-clang");
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
                "NDK linker for {ANDROID_TARGET} API {ANDROID_API_LEVEL} was not found under {}",
                bin.display()
            )
        })
}

fn cargo<const N: usize>(args: [&str; N], envs: &[(&str, &std::ffi::OsStr)]) -> Result<(), String> {
    let mut command = Command::new("cargo");
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let rendered = format!("cargo {}", args.join(" "));
    let status = command
        .status()
        .map_err(|error| format!("failed to execute `{rendered}`: {error}"))?;
    require_success(&rendered, status)
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
}

fn require_success(command: &str, status: ExitStatus) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{command}` exited with {status}"))
    }
}

fn print_help() {
    println!(
        "Flux build tasks\n\n\
         Usage: cargo xtask <COMMAND>\n\n\
         Commands:\n\
           fmt            Check Rust formatting\n\
           check-host     Type-check the host workspace\n\
           test-host      Run host tests\n\
           clippy         Run Clippy with warnings denied\n\
           check-android  Type-check fluxd for aarch64-linux-android\n\
           build-android  Build release fluxd with NDK {ANDROID_NDK_REVISION}, API {ANDROID_API_LEVEL}\n\
           test-functional-canary-linux  Run the opt-in ignored privileged Linux canary checkpoint\n\
           test-functional-canary-linux-tproxy  Run the ingress-only Linux TPROXY checkpoint\n\
           test-functional-canary-linux-output-preflight  Preflight distinct local-OUTPUT credentials (no traffic)\n\
           xtables-oracle Verify or explicitly update pinned shell-generated restore fixtures; requires --check or --update\n\
           stage-module   Build and stage a Magisk tree; requires --stage DIR --runtime-binaries DIR\n\
           verify-package Verify a populated release stage; requires --stage DIR\n\
           ci             Run all checks that do not require an NDK linker"
    );
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
        let mut bytes = vec![0_u8; 128];
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
        bytes[24..32].copy_from_slice(&128_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&file_size.to_le_bytes());
        bytes[104..112].copy_from_slice(&file_size.to_le_bytes());
        bytes[112..120].copy_from_slice(&4096_u64.to_le_bytes());
        fs::write(path, bytes).expect("write AArch64 ELF fixture");
    }

    fn write_required_module_fixture(stage: &Path) {
        for relative in REQUIRED_MODULE_FILES {
            if relative == "conf/manifest.json" || relative.starts_with("bin/") {
                continue;
            }
            let path = stage.join(relative);
            fs::create_dir_all(path.parent().expect("required file parent"))
                .expect("create required fixture parent");
            let contents = match relative {
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
                "conf/flux.toml" | "conf/addrsyncd.toml" => "fixture = true\n".to_owned(),
                "conf/settings.ini" => {
                    "PROXY_MODE=\"tproxy\"\nBYPASS_SET_BACKEND=\"zone\"\n".to_owned()
                }
                value
                    if value == "META-INF/com/google/android/update-binary"
                        || value == "customize.sh"
                        || value == "flux_service.sh"
                        || value.starts_with("scripts/") =>
                {
                    "#!/system/bin/sh\nexit 0\n".to_owned()
                }
                "webroot/index.html" => "<html></html>\n".to_owned(),
                "LICENSE" => "fixture license\n".to_owned(),
                other => panic!("unhandled required fixture file {other}"),
            };
            fs::write(&path, contents).expect("write required fixture file");
        }
    }

    #[test]
    fn linux_canary_required_contract_accepts_only_zero_one_or_unset() {
        assert_eq!(parse_linux_canary_required(None), Ok(false));
        assert_eq!(parse_linux_canary_required(Some("0")), Ok(false));
        assert_eq!(parse_linux_canary_required(Some("1")), Ok(true));
        assert!(parse_linux_canary_required(Some("true")).is_err());
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
        let output_preflight = format!("{LINUX_OUTPUT_UID_PREFLIGHT_TEST}: test\n");
        assert!(linux_canary_test_is_listed(
            &output_preflight,
            LINUX_OUTPUT_UID_PREFLIGHT_TEST
        ));
        assert!(!linux_canary_test_is_listed(
            &output_preflight,
            LINUX_TPROXY_CANARY_TEST
        ));
    }

    #[test]
    fn linux_canary_invocation_scrubs_internal_reentry_environment() {
        let mut command = Command::new("cargo");
        for variable in LINUX_CANARY_INTERNAL_ENVS {
            command.env(variable, "hostile-parent-value");
        }

        scrub_linux_canary_internal_environment(&mut command);

        for variable in LINUX_CANARY_INTERNAL_ENVS {
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
        write_required_module_fixture(stage);
        write_required_module_fixture(source_root);

        fs::write(stage.join("conf/manifest.json"), "release-populated\n")
            .expect("write staged manifest");
        fs::write(
            source_root.join("conf/manifest.json"),
            "source-placeholder\n",
        )
        .expect("write source manifest");
        validate_source_bound_module_files(stage, source_root)
            .expect("matching tracked module files must verify");

        fs::write(
            stage.join("scripts/unreviewed"),
            "#!/system/bin/sh\nexit 0\n",
        )
        .expect("write staged unreviewed file");
        fs::write(
            source_root.join("scripts/unreviewed"),
            "#!/system/bin/sh\nexit 0\n",
        )
        .expect("write source unreviewed file");
        let error = validate_source_bound_module_files(stage, source_root)
            .expect_err("an unreviewed source-owned file must fail");
        assert!(error.contains("extra=scripts/unreviewed"));
        fs::remove_file(stage.join("scripts/unreviewed")).expect("remove staged extra file");
        fs::remove_file(source_root.join("scripts/unreviewed")).expect("remove source extra file");

        fs::write(
            stage.join("scripts/config"),
            "#!/system/bin/sh\n# package-only change\nexit 0\n",
        )
        .expect("tamper staged tracked file");
        let error = validate_source_bound_module_files(stage, source_root)
            .expect_err("staged tracked file divergence must fail");
        assert!(error.contains("scripts/config differs from authoritative source"));
    }

    #[test]
    fn release_verifier_accepts_complete_provenance_and_rejects_kernel_payloads() {
        let directory = TestDirectory::new("release-verifier");
        let stage = &directory.0;
        for relative in ["bin", "conf", "evidence"] {
            fs::create_dir_all(stage.join(relative)).expect("create fixture directory");
        }
        write_required_module_fixture(stage);
        for name in ["fluxd", "sing-box", "jq", "addrsyncd"] {
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
        let payload_sha256 = operational_payload_sha256(stage).expect("hash operational payload");
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

        let artifacts = ["fluxd", "sing-box", "jq", "addrsyncd"]
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
        let spdx_describes = ["fluxd", "sing-box", "jq", "addrsyncd"]
            .into_iter()
            .map(|name| format!("\"SPDXRef-Package-{name}\""))
            .collect::<Vec<_>>()
            .join(",");
        let sbom = format!(
            "{{\"spdxVersion\":\"SPDX-2.3\",\"dataLicense\":\"CC0-1.0\",\"SPDXID\":\"SPDXRef-DOCUMENT\",\"name\":\"Flux release fixture\",\"documentNamespace\":\"https://github.com/Chth1z/Flux/spdx/0123456789abcdef0123456789abcdef01234567\",\"creationInfo\":{{\"created\":\"2026-07-14T00:00:00Z\",\"creators\":[\"Tool: cargo xtask package-magisk\"]}},\"documentDescribes\":[{spdx_describes}],\"packages\":[{spdx_packages}]}}"
        );
        fs::write(stage.join("SBOM.spdx.json"), &sbom).expect("write SBOM");
        let manifest = format!(
            "{{\"schema_version\":1,\"project\":\"Flux\",\"generated_by\":\"cargo xtask package-magisk\",\"binaries\":[{binaries}],\"device_test_evidence\":[{{\"path\":\"evidence/device.json\",\"sha256\":\"{evidence_hash}\",\"source_revision\":\"0123456789abcdef0123456789abcdef01234567\",\"payload_sha256\":\"{payload_sha256}\",\"device_profile\":\"test-gki-arm64\",\"android_build_fingerprint\":\"flux/test/device:14/UP1A.231005.007/1234567:user/release-keys\",\"kernel_release\":\"5.10.198-android12-9-gki\",\"boot_id\":\"12345678-1234-4abc-8def-1234567890ab\",\"verified_boot_state\":\"green\",\"selinux_enforcing\":true,\"captured_at_utc\":\"2026-07-14T00:00:00Z\"}}],\"default_package_profiles\":[{{\"name\":\"full\",\"description\":\"Complete package\"}}]}}"
        );
        fs::write(stage.join("conf/manifest.json"), &manifest).expect("write manifest");
        let parsed_manifest: ReleaseManifest =
            serde_json::from_str(&manifest).expect("parse complete manifest");
        let expected_revisions = WorkspaceSourceRevisions {
            fluxd: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            addrsyncd: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        };
        validate_first_party_source_revisions(&parsed_manifest, &expected_revisions)
            .expect("matching first-party revisions must verify");
        let wrong_revisions = WorkspaceSourceRevisions {
            fluxd: "1123456789abcdef0123456789abcdef01234567".to_owned(),
            addrsyncd: expected_revisions.addrsyncd.clone(),
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

        verify_package_dir_with_source(stage, stage).expect("complete fixture must verify");

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
        let manifest: ReleaseManifest = serde_json::from_str(
            r#"{
                "schema_version": 1,
                "project": "Flux",
                "generated_by": "test",
                "binaries": [{
                    "name": "fluxd",
                    "path": "bin/fluxd",
                    "source": "D:/Github/Flux",
                    "source_revision": "0123456789abcdef0123456789abcdef01234567",
                    "version": "0.1.0",
                    "target": "aarch64-linux-android",
                    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                    "license": "GPL-3.0-only"
                }],
                "device_test_evidence": [],
                "default_package_profiles": [{
                    "name": "full",
                    "description": "Complete package"
                }]
            }"#,
        )
        .expect("parse manifest fixture");
        let directory = TestDirectory::new("invalid-manifest");
        let error = validate_release_manifest(&directory.0, &manifest)
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
        let unlicensed_error = validate_spdx_license("addrsyncd", "LicenseRef-UNLICENSED")
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
}
