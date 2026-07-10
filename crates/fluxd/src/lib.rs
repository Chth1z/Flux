use std::io::Write;

use flux_core::{
    ControlClient, ControlError, KernelSupport, LegacyIntent, MIN_SUPPORTED_KERNEL, Reason,
};
use flux_platform::KernelReleaseSource;
use serde::Serialize;

const EXIT_SUCCESS: i32 = 0;
const EXIT_RUNTIME_ERROR: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_UNSUPPORTED: i32 = 3;

pub fn run_cli<I, T, S, O, E>(args: I, kernel_source: &S, stdout: &mut O, stderr: &mut E) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    S: KernelReleaseSource,
    O: Write,
    E: Write,
{
    run_cli_with_control(
        args,
        kernel_source,
        &UnavailableControlClient,
        stdout,
        stderr,
    )
}

pub fn run_cli_with_control<I, T, S, C, O, E>(
    args: I,
    kernel_source: &S,
    control: &C,
    stdout: &mut O,
    stderr: &mut E,
) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    S: KernelReleaseSource,
    C: ControlClient,
    O: Write,
    E: Write,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(command) = args.next() else {
        return write_help(stdout);
    };

    match command.as_ref() {
        "status" => run_status(args, kernel_source, stdout, stderr),
        "control" => run_control(args, kernel_source, control, stdout, stderr),
        "--help" | "-h" | "help" => write_help(stdout),
        "--version" | "-V" | "version" => {
            let _ = writeln!(stdout, "fluxd {}", env!("CARGO_PKG_VERSION"));
            EXIT_SUCCESS
        }
        unknown => {
            let _ = writeln!(stderr, "fluxd: unknown command '{unknown}'");
            EXIT_USAGE
        }
    }
}

fn run_control<I, T, S, C, O, E>(
    args: I,
    kernel_source: &S,
    control: &C,
    stdout: &mut O,
    stderr: &mut E,
) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    S: KernelReleaseSource,
    C: ControlClient,
    O: Write,
    E: Write,
{
    let mut args = args.into_iter();
    let Some(action) = args.next() else {
        let _ = writeln!(stderr, "fluxd: control action is required");
        return EXIT_USAGE;
    };
    if let Some(extra) = args.next() {
        let _ = writeln!(
            stderr,
            "fluxd: unexpected control argument '{}'",
            extra.as_ref()
        );
        return EXIT_USAGE;
    }

    let intent = match action.as_ref() {
        "start" => LegacyIntent::Running {
            reason: Reason::Fluxctl,
        },
        "stop" => LegacyIntent::Stopped {
            reason: Reason::Fluxctl,
        },
        "restart" | "reload" => LegacyIntent::Reload {
            reason: Reason::Fluxctl,
        },
        "resync" => LegacyIntent::ResyncAddresses {
            reason: Reason::Fluxctl,
        },
        unknown => {
            let _ = writeln!(stderr, "fluxd: unknown control action '{unknown}'");
            return EXIT_USAGE;
        }
    };

    let release = match kernel_source.kernel_release() {
        Ok(release) => release,
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: unable to read kernel release: {error}");
            return EXIT_RUNTIME_ERROR;
        }
    };
    let support = match KernelSupport::evaluate(&release) {
        Ok(support) => support,
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: {error}");
            return EXIT_RUNTIME_ERROR;
        }
    };
    if let KernelSupport::Unsupported { found, minimum } = support {
        let _ = writeln!(stderr, "fluxd: kernel {found} is below minimum {minimum}");
        return EXIT_UNSUPPORTED;
    }

    match control.submit_and_wait(intent) {
        Ok(report) => {
            if writeln!(stdout, "completed revision {}", report.revision).is_ok() {
                EXIT_SUCCESS
            } else {
                EXIT_RUNTIME_ERROR
            }
        }
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: {error}");
            EXIT_RUNTIME_ERROR
        }
    }
}

fn run_status<I, T, S, O, E>(args: I, kernel_source: &S, stdout: &mut O, stderr: &mut E) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    S: KernelReleaseSource,
    O: Write,
    E: Write,
{
    let mut json = false;
    for argument in args {
        match argument.as_ref() {
            "--json" if !json => json = true,
            unknown => {
                let _ = writeln!(stderr, "fluxd: unknown status option '{unknown}'");
                return EXIT_USAGE;
            }
        }
    }

    let release = match kernel_source.kernel_release() {
        Ok(release) => release,
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: unable to read kernel release: {error}");
            return EXIT_RUNTIME_ERROR;
        }
    };
    let support = match KernelSupport::evaluate(&release) {
        Ok(support) => support,
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: {error}");
            return EXIT_RUNTIME_ERROR;
        }
    };

    let (daemon, version, supported) = match support {
        KernelSupport::Supported(version) => ("stopped", version, true),
        KernelSupport::Unsupported { found, .. } => ("unsupported_kernel", found, false),
    };

    if json {
        let document = StatusDocument {
            daemon,
            kernel: KernelDocument {
                release: &release,
                version: version.to_string(),
                minimum: MIN_SUPPORTED_KERNEL.to_string(),
                supported,
            },
        };
        if serde_json::to_writer(&mut *stdout, &document).is_err() || writeln!(stdout).is_err() {
            return EXIT_RUNTIME_ERROR;
        }
        return EXIT_SUCCESS;
    }

    let supported_label = if supported { "yes" } else { "no" };
    if writeln!(stdout, "daemon: {daemon}").is_err()
        || writeln!(stdout, "kernel release: {release}").is_err()
        || writeln!(stdout, "kernel version: {version}").is_err()
        || writeln!(stdout, "minimum kernel: {MIN_SUPPORTED_KERNEL}").is_err()
        || writeln!(stdout, "kernel supported: {supported_label}").is_err()
    {
        return EXIT_RUNTIME_ERROR;
    }

    EXIT_SUCCESS
}

fn write_help(output: &mut impl Write) -> i32 {
    let result = writeln!(
        output,
        "Usage: fluxd <COMMAND>\n\nCommands:\n  status [--json]\n  control <start|stop|restart|reload|resync>\n  help\n  version"
    );
    if result.is_ok() {
        EXIT_SUCCESS
    } else {
        EXIT_RUNTIME_ERROR
    }
}

#[derive(Serialize)]
struct StatusDocument<'a> {
    daemon: &'static str,
    kernel: KernelDocument<'a>,
}

#[derive(Serialize)]
struct KernelDocument<'a> {
    release: &'a str,
    version: String,
    minimum: String,
    supported: bool,
}

struct UnavailableControlClient;

impl ControlClient for UnavailableControlClient {
    fn submit_and_wait(
        &self,
        _intent: LegacyIntent,
    ) -> Result<flux_core::OperationReport, ControlError> {
        Err(ControlError::BridgeStopped)
    }
}
