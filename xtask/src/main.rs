use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const ANDROID_TARGET: &str = "aarch64-linux-android";
const ANDROID_API_LEVEL: &str = "31";
const ANDROID_NDK_REVISION: &str = "27.3.13750724";
const LINUX_CANARY_REQUIRED_ENV: &str = "FLUX_LINUX_CANARY_REQUIRED";
const LINUX_CANARY_TEST: &str = "functional_canary::linux_namespace_harness::privileged_dual_stack_canary_exercises_real_topology_and_cleanup";
const LINUX_TPROXY_CANARY_TEST: &str = "functional_canary::linux_namespace_harness::privileged_ingress_tproxy_checkpoint_exercises_real_capture_counters_and_cleanup";
const LINUX_CANARY_INTERNAL_ENVS: [&str; 5] = [
    "FLUX_LINUX_CANARY_HARNESS_MODE",
    "FLUX_LINUX_CANARY_HARNESS_CONFIG",
    "FLUX_LINUX_CANARY_REENTRY_TOKEN",
    "FLUX_LINUX_CANARY_OUTER_NETNS",
    "FLUX_LINUX_CANARY_OUTER_USERNS",
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
        "stage-module" => stage_module(parse_stage_module_options(&arguments)?),
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

    for relative in [
        "bin/fluxd",
        "bin/addrsyncd",
        "bin/jq",
        "bin/sing-box",
        "scripts/fluxctl",
        "scripts/flux-event",
        "customize.sh",
        "flux_service.sh",
    ] {
        let required = options.stage.join(relative);
        if !required.is_file() {
            return Err(format!(
                "staged module is missing required file {}",
                required.display()
            ));
        }
    }

    println!("staged Android module at {}", options.stage.display());
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
           stage-module   Build and stage a Magisk tree; requires --stage DIR --runtime-binaries DIR\n\
           ci             Run all checks that do not require an NDK linker"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
