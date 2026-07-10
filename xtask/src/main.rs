use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const ANDROID_TARGET: &str = "aarch64-linux-android";
const ANDROID_API_LEVEL: &str = "31";
const ANDROID_NDK_REVISION: &str = "27.3.13750724";

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
           stage-module   Build and stage a Magisk tree; requires --stage DIR --runtime-binaries DIR\n\
           ci             Run all checks that do not require an NDK linker"
    );
}
