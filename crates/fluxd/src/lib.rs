use std::io::Write;

use flux_core::{
    AdministrativeState, ControlClient, ControlError, ControlSnapshot, KernelSupport, LegacyIntent,
    MIN_SUPPORTED_KERNEL, OperationReport, Reason,
};
use flux_platform::KernelReleaseSource;
use serde::Serialize;

mod daemon;
mod intent_store;
mod protocol;
mod socket;

pub use daemon::{DaemonError, DaemonOptions, run_daemon};
pub use intent_store::{AdministrativeIntentStore, IntentStoreError};
pub use protocol::{
    DaemonSnapshot, EventDisposition, EventReport, MAX_CONTROL_PACKET_BYTES, ProtocolHandler,
    RequestPeerId,
};
pub use socket::{ControlConnectionHandler, ControlSocketError, SocketControlClient};

pub trait DaemonClient: ControlClient {
    fn ping(&self) -> Result<(), ControlError>;
    fn status(&self) -> Result<DaemonSnapshot, ControlError>;
    fn send_event(
        &self,
        event_type: &str,
        watched_path: &str,
        event_name: &str,
    ) -> Result<EventReport, ControlError>;
}

impl DaemonClient for SocketControlClient {
    fn ping(&self) -> Result<(), ControlError> {
        SocketControlClient::ping(self)
    }

    fn status(&self) -> Result<DaemonSnapshot, ControlError> {
        SocketControlClient::status(self)
    }

    fn send_event(
        &self,
        event_type: &str,
        watched_path: &str,
        event_name: &str,
    ) -> Result<EventReport, ControlError> {
        SocketControlClient::send_event(self, event_type, watched_path, event_name)
    }
}

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
    run_cli_internal(
        args,
        kernel_source,
        &UnavailableControlClient,
        None,
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
    run_cli_internal(args, kernel_source, control, None, stdout, stderr)
}

pub fn run_cli_with_daemon<I, T, S, C, O, E>(
    args: I,
    kernel_source: &S,
    client: &C,
    stdout: &mut O,
    stderr: &mut E,
) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    S: KernelReleaseSource,
    C: DaemonClient,
    O: Write,
    E: Write,
{
    run_cli_internal(args, kernel_source, client, Some(client), stdout, stderr)
}

fn run_cli_internal<I, T, S, O, E>(
    args: I,
    kernel_source: &S,
    control: &dyn ControlClient,
    daemon: Option<&dyn DaemonClient>,
    stdout: &mut O,
    stderr: &mut E,
) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    S: KernelReleaseSource,
    O: Write,
    E: Write,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(command) = args.next() else {
        return write_help(stdout);
    };

    match command.as_ref() {
        "status" => match daemon {
            Some(daemon) => run_daemon_status(args, daemon, stdout, stderr),
            None => run_status(args, kernel_source, stdout, stderr),
        },
        "control" => run_control(args, kernel_source, control, stdout, stderr),
        "ping" => match daemon {
            Some(daemon) => run_ping(args, daemon, stdout, stderr),
            None => unavailable_online_command("ping", stderr),
        },
        "event" => match daemon {
            Some(daemon) => run_event(args, daemon, stdout, stderr),
            None => unavailable_online_command("event", stderr),
        },
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
    C: ControlClient + ?Sized,
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

fn run_ping<I, T, O, E>(args: I, daemon: &dyn DaemonClient, stdout: &mut O, stderr: &mut E) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    O: Write,
    E: Write,
{
    if let Some(extra) = args.into_iter().next() {
        let _ = writeln!(
            stderr,
            "fluxd: unexpected ping argument '{}'",
            extra.as_ref()
        );
        return EXIT_USAGE;
    }
    match daemon.ping() {
        Ok(()) if writeln!(stdout, "pong").is_ok() => EXIT_SUCCESS,
        Ok(()) => EXIT_RUNTIME_ERROR,
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: {error}");
            EXIT_RUNTIME_ERROR
        }
    }
}

fn run_event<I, T, O, E>(args: I, daemon: &dyn DaemonClient, stdout: &mut O, stderr: &mut E) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    O: Write,
    E: Write,
{
    let arguments = args.into_iter().collect::<Vec<_>>();
    if arguments.len() != 3 {
        let _ = writeln!(
            stderr,
            "fluxd: event requires EVENT_TYPE WATCHED_PATH EVENT_NAME"
        );
        return EXIT_USAGE;
    }
    match daemon.send_event(
        arguments[0].as_ref(),
        arguments[1].as_ref(),
        arguments[2].as_ref(),
    ) {
        Ok(report) => {
            let disposition = match report.disposition {
                EventDisposition::Applied => "applied",
                EventDisposition::Deferred => "deferred",
                EventDisposition::Ignored => "ignored",
            };
            if writeln!(stdout, "event {disposition} revision {}", report.revision).is_ok() {
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

fn run_daemon_status<I, T, O, E>(
    args: I,
    daemon: &dyn DaemonClient,
    stdout: &mut O,
    stderr: &mut E,
) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    O: Write,
    E: Write,
{
    let Some(json) = parse_status_options(args, stderr) else {
        return EXIT_USAGE;
    };
    let snapshot = match daemon.status() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: {error}");
            return EXIT_RUNTIME_ERROR;
        }
    };
    let (daemon_state, version, supported) = match snapshot.kernel_support {
        KernelSupport::Supported(version) => ("running", version, true),
        KernelSupport::Unsupported { found, .. } => ("unsupported_kernel", found, false),
    };

    if json {
        let document = OnlineStatusDocument {
            daemon: daemon_state,
            kernel: OnlineKernelDocument {
                version: version.to_string(),
                minimum: MIN_SUPPORTED_KERNEL.to_string(),
                supported,
            },
            control: OnlineControlDocument::from(snapshot.control),
        };
        if serde_json::to_writer(&mut *stdout, &document).is_err() || writeln!(stdout).is_err() {
            return EXIT_RUNTIME_ERROR;
        }
        return EXIT_SUCCESS;
    }

    let supported_label = if supported { "yes" } else { "no" };
    let administrative_state = administrative_state_label(snapshot.control.administrative_state);
    if writeln!(stdout, "daemon: {daemon_state}").is_err()
        || writeln!(stdout, "kernel version: {version}").is_err()
        || writeln!(stdout, "minimum kernel: {MIN_SUPPORTED_KERNEL}").is_err()
        || writeln!(stdout, "kernel supported: {supported_label}").is_err()
        || writeln!(stdout, "administrative state: {administrative_state}").is_err()
        || writeln!(
            stdout,
            "configuration dirty: {}",
            if snapshot.control.configuration_dirty {
                "yes"
            } else {
                "no"
            }
        )
        .is_err()
        || writeln!(stdout, "revision: {}", snapshot.control.revision).is_err()
    {
        return EXIT_RUNTIME_ERROR;
    }
    EXIT_SUCCESS
}

fn unavailable_online_command(command: &str, stderr: &mut impl Write) -> i32 {
    let _ = writeln!(stderr, "fluxd: {command} requires the daemon transport");
    EXIT_RUNTIME_ERROR
}

fn run_status<I, T, S, O, E>(args: I, kernel_source: &S, stdout: &mut O, stderr: &mut E) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    S: KernelReleaseSource,
    O: Write,
    E: Write,
{
    let Some(json) = parse_status_options(args, stderr) else {
        return EXIT_USAGE;
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

fn parse_status_options<I, T>(args: I, stderr: &mut impl Write) -> Option<bool>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let mut json = false;
    for argument in args {
        match argument.as_ref() {
            "--json" if !json => json = true,
            unknown => {
                let _ = writeln!(stderr, "fluxd: unknown status option '{unknown}'");
                return None;
            }
        }
    }
    Some(json)
}

fn write_help(output: &mut impl Write) -> i32 {
    let result = writeln!(
        output,
        "Usage: fluxd <COMMAND>\n\nCommands:\n  status [--json]\n  control <start|stop|restart|reload|resync>\n  ping\n  event <EVENT_TYPE> <WATCHED_PATH> <EVENT_NAME>\n  help\n  version"
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

#[derive(Serialize)]
struct OnlineStatusDocument {
    daemon: &'static str,
    kernel: OnlineKernelDocument,
    control: OnlineControlDocument,
}

#[derive(Serialize)]
struct OnlineKernelDocument {
    version: String,
    minimum: String,
    supported: bool,
}

#[derive(Serialize)]
struct OnlineControlDocument {
    revision: u64,
    administrative_state: &'static str,
    configuration_dirty: bool,
    in_flight: Option<OnlineIntentDocument>,
    last_completed: Option<OnlineOperationDocument>,
}

impl From<ControlSnapshot> for OnlineControlDocument {
    fn from(snapshot: ControlSnapshot) -> Self {
        Self {
            revision: snapshot.revision,
            administrative_state: administrative_state_label(snapshot.administrative_state),
            configuration_dirty: snapshot.configuration_dirty,
            in_flight: snapshot.in_flight.map(Into::into),
            last_completed: snapshot.last_completed.map(Into::into),
        }
    }
}

#[derive(Serialize)]
struct OnlineIntentDocument {
    action: &'static str,
    reason: &'static str,
}

impl From<LegacyIntent> for OnlineIntentDocument {
    fn from(intent: LegacyIntent) -> Self {
        let (action, reason) = match intent {
            LegacyIntent::Running { reason } => ("start", reason),
            LegacyIntent::Stopped { reason } => ("stop", reason),
            LegacyIntent::Reload { reason } => ("reload", reason),
            LegacyIntent::ResyncAddresses { reason } => ("resync", reason),
        };
        Self {
            action,
            reason: reason.as_token(),
        }
    }
}

#[derive(Serialize)]
struct OnlineOperationDocument {
    intent: OnlineIntentDocument,
    revision: u64,
}

impl From<OperationReport> for OnlineOperationDocument {
    fn from(report: OperationReport) -> Self {
        Self {
            intent: report.intent.into(),
            revision: report.revision,
        }
    }
}

const fn administrative_state_label(state: AdministrativeState) -> &'static str {
    match state {
        AdministrativeState::Unknown => "unknown",
        AdministrativeState::Running => "running",
        AdministrativeState::Stopped => "stopped",
    }
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
