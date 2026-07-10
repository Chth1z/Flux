use std::env;
use std::ffi::OsString;
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
    if args.next().is_some() {
        return Err("commands do not accept positional arguments".to_owned());
    }

    match command.to_string_lossy().as_ref() {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "fmt" => cargo(["fmt", "--all", "--", "--check"], &[]),
        "check-host" => cargo(["check", "--workspace", "--all-targets"], &[]),
        "test-host" => cargo(["test", "--workspace"], &[]),
        "clippy" => cargo(
            [
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
            &[],
        ),
        "check-android" => cargo(["check", "-p", "fluxd", "--target", ANDROID_TARGET], &[]),
        "build-android" => build_android(),
        "ci" => {
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
           ci             Run all checks that do not require an NDK linker"
    );
}
