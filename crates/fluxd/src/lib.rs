use std::io::Write;

use flux_core::{
    AdministrativeState, ControlClient, ControlError, ControlSnapshot, KernelMutationStatus,
    KernelSupport, MIN_SUPPORTED_KERNEL, MutationGate, Observation, OperationReport, Reason,
    RuntimeIntent, SelinuxMode,
};
use flux_platform::KernelReleaseSource;
use serde::Serialize;

mod daemon;
mod engine_supervisor;
mod generation_engine_config;
// The required Stage 1 gate is wired behind an explicit coordinator seam, but
// production remains structural-only until a platform adapter is qualified.
#[allow(dead_code)]
mod functional_canary;
mod inspection;
mod intent_store;
mod native_admission;
mod native_canary_facility;
mod native_generation_source;
mod native_runtime_writer;
mod offline_cleanup;
mod process_authority;
mod protocol;
mod runtime_coordinator;
mod runtime_layout;
mod runtime_logging;
mod runtime_status;
mod socket;
mod subscription;
mod traffic_observation;

use protocol::WireCapabilityProfile;

pub use daemon::{DaemonError, DaemonOptions, run_daemon};
pub use engine_supervisor::{
    CaptureBlockedAction, CaptureObservation, DesiredEngine, EngineArtifact, EngineArtifactDigest,
    EngineArtifactSetIdentity, EnginePhase, EngineReport, EngineSnapshot, EngineSpec,
    EngineSpecError, EngineSpecIoOperation, EngineSupervisor, EngineSupervisorError,
    EngineSupervisorErrorKind, MAX_ENGINE_BINARY_BYTES, MAX_ENGINE_CONFIG_BYTES,
    MAX_ENGINE_DIAGNOSTIC_BYTES, OwnedEngineIdentity, RestartPolicy, RestartPolicyError,
    SHA256_DIGEST_BYTES,
};
pub use generation_engine_config::{
    CAPTURE_PATH_SELECTION_EVIDENCE_DIGEST_BYTES, CapturePathCandidateStatus, CapturePathDecision,
    CapturePathKernelGap, CapturePathRejection, CapturePathRejectionReason, CapturePathSelection,
    CapturePathSelectionDecodeError, CapturePathSelectionEvidenceDigest,
    CapturePathSelectionReason,
};
pub use inspection::{
    DEFAULT_LOG_LINES, DiagnosticItem, DiagnosticReport, DiagnosticState, ExplainAddressFamilies,
    ExplainApplicationMode, ExplainCapturePathRequestRelation, ExplainReport, LogReport, LogStream,
    MAX_LOG_LINES, MAX_LOG_TAIL_BYTES,
};
pub use intent_store::{AdministrativeIntentStore, IntentStoreError};
pub use native_admission::{NativeAdmissionRejection, NativeAdmissionState};
pub use offline_cleanup::{
    DaemonLeaseError, DaemonLeaseErrorKind, OFFLINE_CLEANUP_BUSY_EXIT, OfflineCleanupDisposition,
    OfflineCleanupError, OfflineCleanupErrorKind, OfflineCleanupReport, run_offline_cleanup,
    run_offline_cleanup_cli,
};
pub use protocol::{DaemonSnapshot, MAX_CONTROL_PACKET_BYTES, ProtocolHandler, RequestPeerId};
pub use runtime_layout::{RuntimeLayoutError, RuntimeLayoutErrorKind};
pub use runtime_logging::{
    MAX_RUNTIME_LOG_FILE_BYTES, MAX_RUNTIME_LOG_RECORD_BYTES, RuntimeLogError, RuntimeLogErrorKind,
};
pub use runtime_status::{
    RuntimeCaptureState, RuntimeEngineState, RuntimeFailure, RuntimeGenerationBinding,
    RuntimePhase, RuntimeSnapshot, RuntimeSnapshotSource, RuntimeVerificationState,
};
pub use socket::{ControlConnectionHandler, ControlSocketError, SocketControlClient};
pub use subscription::{SubscriptionRefreshDisposition, SubscriptionRefreshReport};
pub use traffic_observation::{
    AutomationAction, AutomationActionRequest, AutomationDecisionDisposition,
    AutomationDecisionJournalSnapshot, AutomationDecisionRecord, AutomationDecisionSequence,
    AutomationEvaluation, AutomationEvaluationContext, AutomationLimits, AutomationPolicy,
    AutomationPolicyDecision, AutomationPolicyRevision, AutomationProposal, AutomationRejection,
    AutomationRuleId, MAX_AUTOMATION_ACCEPTED_ACTION_ENTRIES,
    MAX_AUTOMATION_DECISION_JOURNAL_ENTRIES, TrafficObservationError, TrafficObservationModule,
    TrafficObservationPublication, TrafficObservationUpdate, TrafficStatisticsSnapshotSource,
};

#[doc(hidden)]
pub mod internal {
    /// Dispatches the packaged canary's private self-exec child mode before
    /// ordinary user-facing CLI parsing.
    #[must_use]
    pub fn try_run_packaged_canary_child(args: &[String]) -> Option<i32> {
        crate::functional_canary::try_run_internal_driver_child(args)
    }
}

pub trait DaemonClient: ControlClient {
    fn ping(&self) -> Result<(), ControlError>;
    fn status(&self) -> Result<DaemonSnapshot, ControlError>;
    fn update_subscription(&self) -> Result<SubscriptionRefreshReport, ControlError>;
    fn diagnose(&self) -> Result<DiagnosticReport, ControlError> {
        Err(inspection_unavailable())
    }
    fn logs(&self, _stream: LogStream, _lines: u16) -> Result<LogReport, ControlError> {
        Err(inspection_unavailable())
    }
    fn explain(&self) -> Result<ExplainReport, ControlError> {
        Err(inspection_unavailable())
    }
}

fn inspection_unavailable() -> ControlError {
    ControlError::request_rejected(
        "inspection_unavailable",
        "read-only inspection is unavailable for this daemon client",
    )
}

impl DaemonClient for SocketControlClient {
    fn ping(&self) -> Result<(), ControlError> {
        SocketControlClient::ping(self)
    }

    fn status(&self) -> Result<DaemonSnapshot, ControlError> {
        SocketControlClient::status(self)
    }

    fn update_subscription(&self) -> Result<SubscriptionRefreshReport, ControlError> {
        SocketControlClient::update_subscription(self)
    }

    fn diagnose(&self) -> Result<DiagnosticReport, ControlError> {
        SocketControlClient::diagnose(self)
    }

    fn logs(&self, stream: LogStream, lines: u16) -> Result<LogReport, ControlError> {
        SocketControlClient::logs(self, stream, lines)
    }

    fn explain(&self) -> Result<ExplainReport, ControlError> {
        SocketControlClient::explain(self)
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
        "start" | "stop" | "restart" | "reload" | "resync" => run_control_action(
            command.as_ref(),
            args,
            kernel_source,
            control,
            stdout,
            stderr,
        ),
        "ping" => match daemon {
            Some(daemon) => run_ping(args, daemon, stdout, stderr),
            None => unavailable_online_command("ping", stderr),
        },
        "subscription" => match daemon {
            Some(daemon) => run_subscription(args, daemon, stdout, stderr),
            None => unavailable_online_command("subscription", stderr),
        },
        "diagnose" => match daemon {
            Some(daemon) => run_diagnose(args, daemon, stdout, stderr),
            None => unavailable_online_command("diagnose", stderr),
        },
        "logs" => match daemon {
            Some(daemon) => run_logs(args, daemon, stdout, stderr),
            None => unavailable_online_command("logs", stderr),
        },
        "backend" => match daemon {
            Some(daemon) => run_backend(args, daemon, stdout, stderr),
            None => unavailable_online_command("backend", stderr),
        },
        "plan" | "rules-preview" | "preview" => match daemon {
            Some(daemon) => run_explain(args, daemon, stdout, stderr),
            None => unavailable_online_command("explain", stderr),
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
    run_control_action(
        action.as_ref(),
        args,
        kernel_source,
        control,
        stdout,
        stderr,
    )
}

fn run_control_action<I, T, S, C, O, E>(
    action: &str,
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
    if let Some(extra) = args.into_iter().next() {
        let _ = writeln!(
            stderr,
            "fluxd: unexpected control argument '{}'",
            extra.as_ref()
        );
        return EXIT_USAGE;
    }

    let intent = match action {
        "start" => RuntimeIntent::Running {
            reason: Reason::UserControl,
        },
        "stop" => RuntimeIntent::Stopped {
            reason: Reason::UserControl,
        },
        "restart" | "reload" => RuntimeIntent::Reload {
            reason: Reason::UserControl,
        },
        "resync" => RuntimeIntent::ResyncAddresses {
            reason: Reason::UserControl,
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
            let written = match report.address_resync {
                Some(disposition) => writeln!(
                    stdout,
                    "completed revision {} resync {}",
                    report.revision,
                    disposition.as_token()
                ),
                None => writeln!(stdout, "completed revision {}", report.revision),
            };
            if written.is_ok() {
                EXIT_SUCCESS
            } else {
                EXIT_RUNTIME_ERROR
            }
        }
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: {error}");
            mutating_error_exit(&error)
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

fn run_subscription<I, T, O, E>(
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
    let mut args = args.into_iter();
    let Some(action) = args.next() else {
        let _ = writeln!(stderr, "fluxd: subscription action is required");
        return EXIT_USAGE;
    };
    if action.as_ref() != "update" {
        let _ = writeln!(
            stderr,
            "fluxd: unknown subscription action '{}'",
            action.as_ref()
        );
        return EXIT_USAGE;
    }
    if let Some(extra) = args.next() {
        let _ = writeln!(
            stderr,
            "fluxd: unexpected subscription argument '{}'",
            extra.as_ref()
        );
        return EXIT_USAGE;
    }

    let report = match daemon.update_subscription() {
        Ok(report) => report,
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: subscription update failed: {error}");
            return mutating_error_exit(&error);
        }
    };
    let cleanup_pending = report.cleanup_pending();
    let result = match report.disposition() {
        SubscriptionRefreshDisposition::Updated => writeln!(
            stdout,
            "subscription updated generation={} nodes={} cleanup_pending={cleanup_pending}",
            report
                .generation()
                .expect("updated subscription report has a Generation"),
            report
                .node_count()
                .expect("updated subscription report has a node count")
        ),
        SubscriptionRefreshDisposition::UpdatedDeferred => writeln!(
            stdout,
            "subscription updated_deferred nodes={} cleanup_pending={cleanup_pending}",
            report
                .node_count()
                .expect("deferred subscription report has a node count")
        ),
        SubscriptionRefreshDisposition::Unchanged => writeln!(
            stdout,
            "subscription unchanged nodes={} cleanup_pending={cleanup_pending}",
            report
                .node_count()
                .expect("unchanged subscription report has a node count")
        ),
        SubscriptionRefreshDisposition::Disabled => writeln!(
            stdout,
            "subscription disabled cleanup_pending={cleanup_pending}"
        ),
        SubscriptionRefreshDisposition::Busy => {
            let _ = writeln!(stderr, "fluxd: subscription busy");
            return EXIT_RUNTIME_ERROR;
        }
    };
    if result.is_ok() {
        EXIT_SUCCESS
    } else {
        EXIT_RUNTIME_ERROR
    }
}

fn run_diagnose<I, T, O, E>(
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
    let Some(json) = parse_flag_options(args, false, stderr, "diagnose") else {
        return EXIT_USAGE;
    };
    let snapshot = match daemon.status() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: diagnose status failed: {error}");
            return EXIT_RUNTIME_ERROR;
        }
    };
    let diagnostics = match daemon.diagnose() {
        Ok(report) => report,
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: diagnose failed: {error}");
            return EXIT_RUNTIME_ERROR;
        }
    };

    if json {
        let document = DiagnosticCliDocument {
            status: online_status_document(snapshot),
            diagnostics,
        };
        if serde_json::to_writer(&mut *stdout, &document).is_err() || writeln!(stdout).is_err() {
            return EXIT_RUNTIME_ERROR;
        }
        return EXIT_SUCCESS;
    }

    let daemon_state = daemon_state_label(snapshot.native_admission);
    let generation = snapshot
        .runtime
        .generation()
        .map_or_else(|| "none".to_owned(), |value| value.to_string());
    if writeln!(stdout, "[status]").is_err()
        || writeln!(stdout, "daemon: {daemon_state}").is_err()
        || writeln!(stdout, "control revision: {}", snapshot.control.revision).is_err()
        || writeln!(stdout, "runtime revision: {}", snapshot.runtime.revision).is_err()
        || writeln!(
            stdout,
            "runtime phase: {}",
            runtime_phase_label(snapshot.runtime.phase)
        )
        .is_err()
        || writeln!(
            stdout,
            "runtime verification: {}",
            runtime_verification_label(snapshot.runtime.verification)
        )
        .is_err()
        || writeln!(stdout, "runtime generation: {generation}").is_err()
        || writeln!(stdout, "\n[checks]").is_err()
        || write_diagnostic_item(stdout, "desired state", diagnostics.desired_state()).is_err()
        || write_diagnostic_item(stdout, "runtime log", diagnostics.runtime_log()).is_err()
        || write_diagnostic_item(stdout, "daemon log", diagnostics.daemon_log()).is_err()
        || write_diagnostic_item(stdout, "engine log", diagnostics.engine_log()).is_err()
    {
        return EXIT_RUNTIME_ERROR;
    }
    EXIT_SUCCESS
}

fn run_logs<I, T, O, E>(args: I, daemon: &dyn DaemonClient, stdout: &mut O, stderr: &mut E) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    O: Write,
    E: Write,
{
    let arguments = args
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect::<Vec<_>>();
    let mut stream = LogStream::Runtime;
    let mut stream_set = false;
    let mut lines = DEFAULT_LOG_LINES;
    let mut lines_set = false;
    let mut json = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "runtime" | "daemon" | "engine" if !stream_set => {
                stream = match arguments[index].as_str() {
                    "runtime" => LogStream::Runtime,
                    "daemon" => LogStream::Daemon,
                    "engine" => LogStream::Engine,
                    _ => unreachable!(),
                };
                stream_set = true;
            }
            "--lines" if !lines_set => {
                let Some(value) = arguments.get(index + 1) else {
                    let _ = writeln!(stderr, "fluxd: logs --lines requires a value");
                    return EXIT_USAGE;
                };
                lines = match value.parse::<u16>() {
                    Ok(value) if (1..=MAX_LOG_LINES).contains(&value) => value,
                    _ => {
                        let _ =
                            writeln!(stderr, "fluxd: logs --lines must be in 1..={MAX_LOG_LINES}");
                        return EXIT_USAGE;
                    }
                };
                lines_set = true;
                index += 1;
            }
            "--json" if !json => json = true,
            unknown => {
                let _ = writeln!(stderr, "fluxd: unknown logs option '{unknown}'");
                return EXIT_USAGE;
            }
        }
        index += 1;
    }

    let report = match daemon.logs(stream, lines) {
        Ok(report) => report,
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: logs failed: {error}");
            return EXIT_RUNTIME_ERROR;
        }
    };
    if json {
        if serde_json::to_writer(&mut *stdout, &report).is_err() || writeln!(stdout).is_err() {
            return EXIT_RUNTIME_ERROR;
        }
        return EXIT_SUCCESS;
    }
    if stdout.write_all(report.content().as_bytes()).is_err() {
        return EXIT_RUNTIME_ERROR;
    }
    if !report.content().is_empty()
        && !report.content().ends_with('\n')
        && writeln!(stdout).is_err()
    {
        return EXIT_RUNTIME_ERROR;
    }
    EXIT_SUCCESS
}

fn run_backend<I, T, O, E>(
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
    let mut args = args.into_iter();
    let Some(action) = args.next() else {
        let _ = writeln!(stderr, "fluxd: backend action is required");
        return EXIT_USAGE;
    };
    if action.as_ref() != "explain" {
        let _ = writeln!(
            stderr,
            "fluxd: unknown backend action '{}'",
            action.as_ref()
        );
        return EXIT_USAGE;
    }
    run_explain(args, daemon, stdout, stderr)
}

fn run_explain<I, T, O, E>(
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
    let Some(json) = parse_flag_options(args, true, stderr, "explain") else {
        return EXIT_USAGE;
    };
    let report = match daemon.explain() {
        Ok(report) => report,
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: explain failed: {error}");
            return EXIT_RUNTIME_ERROR;
        }
    };
    if json {
        if serde_json::to_writer(&mut *stdout, &report).is_err() || writeln!(stdout).is_err() {
            return EXIT_RUNTIME_ERROR;
        }
        return EXIT_SUCCESS;
    }

    if writeln!(stdout, "authorization: non_authorizing").is_err()
        || writeln!(
            stdout,
            "desired state schema: {}",
            report.desired_state_schema()
        )
        .is_err()
        || writeln!(
            stdout,
            "capture path request: {}",
            report.capture_path_request()
        )
        .is_err()
        || writeln!(stdout, "runtime revision: {}", report.runtime_revision()).is_err()
        || writeln!(
            stdout,
            "active generation: {}",
            report.active_generation().map_or_else(
                || "none".to_owned(),
                |binding| binding.generation().to_string()
            )
        )
        .is_err()
        || writeln!(
            stdout,
            "active capture path selected: {}",
            report
                .active_capture_path_selection()
                .map_or("unavailable", |selection| selection.selected().as_token())
        )
        .is_err()
        || writeln!(
            stdout,
            "active capture path request relation: {}",
            explain_capture_path_request_relation_label(
                report.active_capture_path_request_relation()
            )
        )
        .is_err()
        || writeln!(
            stdout,
            "latest capture path decision: {}",
            explain_capture_path_decision_label(report.latest_capture_path_decision())
        )
        .is_err()
        || writeln!(
            stdout,
            "latest capture path request relation: {}",
            explain_capture_path_request_relation_label(
                report.latest_capture_path_request_relation()
            )
        )
        .is_err()
        || writeln!(stdout, "listener port: {}", report.listener_port()).is_err()
        || writeln!(
            stdout,
            "address families: {}",
            explain_families_label(report.address_families())
        )
        .is_err()
        || writeln!(
            stdout,
            "traffic domains: local_output={} forwarded_ingress={}",
            report.local_output(),
            report.forwarded_ingress()
        )
        .is_err()
        || writeln!(
            stdout,
            "protocols: tcp={} udp={}",
            report.tcp(),
            report.udp()
        )
        .is_err()
        || writeln!(
            stdout,
            "applications: mode={} packages={}",
            explain_application_mode_label(report.application_mode()),
            report.application_packages()
        )
        .is_err()
        || writeln!(
            stdout,
            "interfaces: excluded={} forwarded_proxy={} local_bypass={}",
            report.excluded_interfaces(),
            report.forwarded_proxy_interfaces(),
            report.local_bypass_interfaces()
        )
        .is_err()
        || writeln!(
            stdout,
            "configured bypass prefixes: {}",
            report.configured_bypass_prefixes()
        )
        .is_err()
        || writeln!(
            stdout,
            "subscription enabled: {}",
            report.subscription_enabled()
        )
        .is_err()
        || writeln!(
            stdout,
            "respect Android VPN: {}",
            report.respect_android_vpn()
        )
        .is_err()
        || writeln!(
            stdout,
            "functional canary required: {}",
            report.require_functional_canary()
        )
        .is_err()
        || writeln!(
            stdout,
            "engine config: schema={} bytes={} digest={}",
            report.engine_config_schema(),
            report.engine_config_bytes(),
            report.engine_config_digest()
        )
        .is_err()
    {
        return EXIT_RUNTIME_ERROR;
    }
    EXIT_SUCCESS
}

fn parse_flag_options<I, T>(
    args: I,
    allow_dry_run: bool,
    stderr: &mut impl Write,
    command: &str,
) -> Option<bool>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let mut json = false;
    let mut dry_run = false;
    for argument in args {
        match argument.as_ref() {
            "--json" if !json => json = true,
            "--dry-run" if allow_dry_run && !dry_run => dry_run = true,
            unknown => {
                let _ = writeln!(stderr, "fluxd: unknown {command} option '{unknown}'");
                return None;
            }
        }
    }
    Some(json)
}

fn write_diagnostic_item(
    output: &mut impl Write,
    label: &str,
    item: &DiagnosticItem,
) -> std::io::Result<()> {
    writeln!(
        output,
        "{label}: {} ({})",
        diagnostic_state_label(item.state()),
        item.detail()
    )
}

const fn diagnostic_state_label(state: DiagnosticState) -> &'static str {
    match state {
        DiagnosticState::Ready => "ready",
        DiagnosticState::Missing => "missing",
        DiagnosticState::Invalid => "invalid",
        DiagnosticState::Unsafe => "unsafe",
        DiagnosticState::Unavailable => "unavailable",
    }
}

const fn explain_families_label(families: ExplainAddressFamilies) -> &'static str {
    match families {
        ExplainAddressFamilies::Ipv4 => "ipv4",
        ExplainAddressFamilies::Ipv6 => "ipv6",
        ExplainAddressFamilies::DualStack => "dual_stack",
    }
}

const fn explain_application_mode_label(mode: ExplainApplicationMode) -> &'static str {
    match mode {
        ExplainApplicationMode::All => "all",
        ExplainApplicationMode::Allowlist => "allowlist",
        ExplainApplicationMode::Denylist => "denylist",
    }
}

const fn explain_capture_path_request_relation_label(
    relation: ExplainCapturePathRequestRelation,
) -> &'static str {
    match relation {
        ExplainCapturePathRequestRelation::Unavailable => "unavailable",
        ExplainCapturePathRequestRelation::MatchesDesiredState => "matches_desired_state",
        ExplainCapturePathRequestRelation::DiffersFromDesiredState => "differs_from_desired_state",
    }
}

fn explain_capture_path_decision_label(decision: Option<CapturePathDecision>) -> String {
    match decision {
        Some(CapturePathDecision::Selected { selection }) => {
            format!("selected:{}", selection.selected().as_token())
        }
        Some(CapturePathDecision::Rejected { rejection }) => {
            format!("rejected:{:?}", rejection.reason())
        }
        None => "unavailable".to_owned(),
    }
}

fn mutating_error_exit(error: &ControlError) -> i32 {
    if error.rejection_code() == Some("unsupported_kernel") {
        EXIT_UNSUPPORTED
    } else {
        EXIT_RUNTIME_ERROR
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
    let capability_profile = &snapshot.capability_profile;
    let daemon_state = daemon_state_label(snapshot.native_admission);

    if json {
        let document = online_status_document(snapshot);
        if serde_json::to_writer(&mut *stdout, &document).is_err() || writeln!(stdout).is_err() {
            return EXIT_RUNTIME_ERROR;
        }
        return EXIT_SUCCESS;
    }

    let administrative_state = administrative_state_label(snapshot.control.administrative_state);
    let runtime_generation = snapshot
        .runtime
        .generation()
        .map_or_else(|| "none".to_owned(), |generation| generation.to_string());
    let runtime_capture_path = snapshot
        .runtime
        .active_capture_path_selection()
        .map_or("unavailable", |selection| selection.selected().as_token());
    let latest_capture_path_decision =
        explain_capture_path_decision_label(snapshot.runtime.latest_capture_path_decision);
    let runtime_error = snapshot
        .runtime
        .last_error
        .as_ref()
        .map_or_else(|| "none".to_owned(), format_runtime_failure);
    let address_resync = snapshot
        .control
        .last_completed
        .and_then(|report| report.address_resync)
        .map_or("none", flux_core::AddressResyncDisposition::as_token);
    if writeln!(stdout, "daemon: {daemon_state}").is_err()
        || writeln!(
            stdout,
            "capability profile schema: {}",
            capability_profile.schema_version()
        )
        .is_err()
        || writeln!(
            stdout,
            "capability profile revision: {}",
            capability_profile.revision().get()
        )
        .is_err()
        || writeln!(
            stdout,
            "kernel release: {}",
            format_observation(capability_profile.kernel().release(), |release| {
                release.as_str().to_owned()
            })
        )
        .is_err()
        || writeln!(
            stdout,
            "kernel version: {}",
            format_observation(capability_profile.kernel().version(), ToString::to_string)
        )
        .is_err()
        || writeln!(stdout, "minimum kernel: {MIN_SUPPORTED_KERNEL}").is_err()
        || writeln!(
            stdout,
            "mutation gate: {}",
            mutation_gate_label(capability_profile.mutation_gate())
        )
        .is_err()
        || writeln!(
            stdout,
            "native admission: {}",
            snapshot.native_admission.as_token()
        )
        .is_err()
        || writeln!(
            stdout,
            "boot identity: {}",
            format_observation(capability_profile.boot_identity(), |identity| {
                identity.as_str().to_owned()
            })
        )
        .is_err()
        || writeln!(
            stdout,
            "device identity: {}",
            format_observation(capability_profile.device_identity(), |identity| {
                format!(
                    "product={} build={} vendor={} patch={} kernel={} namespace={}:{} tools={}",
                    identity.android_product(),
                    identity.android_build(),
                    identity.vendor_build(),
                    identity.security_patch(),
                    identity.kernel_build(),
                    identity.network_namespace().device(),
                    identity.network_namespace().inode(),
                    identity.tools().len()
                )
            })
        )
        .is_err()
        || writeln!(
            stdout,
            "SELinux: {}",
            format_observation(capability_profile.selinux(), |mode| {
                selinux_mode_label(*mode).to_owned()
            })
        )
        .is_err()
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
        || writeln!(stdout, "last address resync: {address_resync}").is_err()
        || writeln!(stdout, "runtime revision: {}", snapshot.runtime.revision).is_err()
        || writeln!(
            stdout,
            "runtime phase: {}",
            runtime_phase_label(snapshot.runtime.phase)
        )
        .is_err()
        || writeln!(
            stdout,
            "runtime capture: {}",
            runtime_capture_label(snapshot.runtime.capture)
        )
        .is_err()
        || writeln!(
            stdout,
            "runtime engine: {}",
            runtime_engine_label(snapshot.runtime.engine)
        )
        .is_err()
        || writeln!(
            stdout,
            "runtime verification: {}",
            runtime_verification_label(snapshot.runtime.verification)
        )
        .is_err()
        || writeln!(stdout, "runtime generation: {runtime_generation}").is_err()
        || writeln!(
            stdout,
            "runtime active capture path: {runtime_capture_path}"
        )
        .is_err()
        || writeln!(
            stdout,
            "runtime latest capture path decision: {latest_capture_path_decision}"
        )
        .is_err()
        || writeln!(stdout, "runtime last error: {runtime_error}").is_err()
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
        "Usage: fluxd <COMMAND>\n\nCommands:\n  status [--json]\n  start|stop|restart|reload|resync\n  control <start|stop|restart|reload|resync>\n  diagnose [--json]\n  logs [runtime|daemon|engine] [--lines N] [--json]\n  backend explain [--json]\n  plan [--dry-run] [--json]\n  rules-preview [--json]\n  ping\n  subscription update\n  cleanup --offline\n  help\n  version"
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
    native_admission: OnlineNativeAdmissionDocument,
    #[cfg(flux_android_qualification)]
    qualification_selector_mismatches: Vec<&'static str>,
    capability_profile: WireCapabilityProfile,
    control: OnlineControlDocument,
    runtime: OnlineRuntimeDocument,
}

#[derive(Serialize)]
struct DiagnosticCliDocument {
    status: OnlineStatusDocument,
    diagnostics: DiagnosticReport,
}

fn online_status_document(snapshot: DaemonSnapshot) -> OnlineStatusDocument {
    OnlineStatusDocument {
        daemon: daemon_state_label(snapshot.native_admission),
        native_admission: snapshot.native_admission.into(),
        #[cfg(flux_android_qualification)]
        qualification_selector_mismatches: flux_core::qualification_selector_mismatch_fields(
            &snapshot.capability_profile,
        ),
        capability_profile: (&snapshot.capability_profile).into(),
        control: OnlineControlDocument::from(snapshot.control),
        runtime: OnlineRuntimeDocument::from(snapshot.runtime),
    }
}

fn daemon_state_label(admission: NativeAdmissionState) -> &'static str {
    match admission {
        NativeAdmissionState::Admitted => "running",
        NativeAdmissionState::Rejected(reason) => reason.as_token(),
    }
}

#[derive(Serialize)]
struct OnlineNativeAdmissionDocument {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

impl From<NativeAdmissionState> for OnlineNativeAdmissionDocument {
    fn from(admission: NativeAdmissionState) -> Self {
        match admission {
            NativeAdmissionState::Admitted => Self {
                state: "admitted",
                reason: None,
            },
            NativeAdmissionState::Rejected(reason) => Self {
                state: "rejected",
                reason: Some(reason.as_token()),
            },
        }
    }
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
struct OnlineRuntimeDocument {
    revision: u64,
    phase: &'static str,
    capture: &'static str,
    engine: &'static str,
    verification: &'static str,
    active_generation: Option<RuntimeGenerationBinding>,
    latest_capture_path_decision: Option<CapturePathDecision>,
    last_error: Option<OnlineRuntimeFailureDocument>,
}

impl From<RuntimeSnapshot> for OnlineRuntimeDocument {
    fn from(snapshot: RuntimeSnapshot) -> Self {
        Self {
            revision: snapshot.revision,
            phase: runtime_phase_label(snapshot.phase),
            capture: runtime_capture_label(snapshot.capture),
            engine: runtime_engine_label(snapshot.engine),
            verification: runtime_verification_label(snapshot.verification),
            active_generation: snapshot.active_generation,
            latest_capture_path_decision: snapshot.latest_capture_path_decision,
            last_error: snapshot.last_error.map(Into::into),
        }
    }
}

#[derive(Serialize)]
struct OnlineRuntimeFailureDocument {
    operation: String,
    message: String,
    recovery: String,
}

impl From<RuntimeFailure> for OnlineRuntimeFailureDocument {
    fn from(failure: RuntimeFailure) -> Self {
        Self {
            operation: failure.operation,
            message: failure.message,
            recovery: failure.recovery,
        }
    }
}

#[derive(Serialize)]
struct OnlineIntentDocument {
    action: &'static str,
    reason: &'static str,
}

impl From<RuntimeIntent> for OnlineIntentDocument {
    fn from(intent: RuntimeIntent) -> Self {
        let (action, reason) = match intent {
            RuntimeIntent::Running { reason } => ("start", reason),
            RuntimeIntent::Stopped { reason } => ("stop", reason),
            RuntimeIntent::Reload { reason } => ("reload", reason),
            RuntimeIntent::ResyncAddresses { reason } => ("resync", reason),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    address_resync: Option<&'static str>,
}

impl From<OperationReport> for OnlineOperationDocument {
    fn from(report: OperationReport) -> Self {
        Self {
            intent: report.intent.into(),
            revision: report.revision,
            address_resync: report
                .address_resync
                .map(flux_core::AddressResyncDisposition::as_token),
        }
    }
}

fn format_observation<T>(observation: &Observation<T>, map: impl FnOnce(&T) -> String) -> String {
    match observation {
        Observation::Verified(value) => format!("{} (verified)", map(value)),
        Observation::Absent => "absent".to_owned(),
        Observation::Denied => "denied".to_owned(),
        Observation::Malformed => "malformed".to_owned(),
        Observation::Unavailable => "unavailable".to_owned(),
    }
}

fn format_runtime_failure(failure: &RuntimeFailure) -> String {
    format!(
        "{}: {}; recovery: {}",
        failure.operation, failure.message, failure.recovery
    )
}

const fn runtime_phase_label(phase: RuntimePhase) -> &'static str {
    match phase {
        RuntimePhase::Unknown => "unknown",
        RuntimePhase::Bootstrapping => "bootstrapping",
        RuntimePhase::Stopped => "stopped",
        RuntimePhase::Preparing => "preparing",
        RuntimePhase::Activating => "activating",
        RuntimePhase::Verifying => "verifying",
        RuntimePhase::Running => "running",
        RuntimePhase::Degraded => "degraded",
        RuntimePhase::Repairing => "repairing",
        RuntimePhase::Stopping => "stopping",
        RuntimePhase::Failed => "failed",
    }
}

const fn runtime_capture_label(capture: RuntimeCaptureState) -> &'static str {
    match capture {
        RuntimeCaptureState::Unknown => "unknown",
        RuntimeCaptureState::Detached => "detached",
        RuntimeCaptureState::Published => "published",
    }
}

const fn runtime_engine_label(engine: RuntimeEngineState) -> &'static str {
    match engine {
        RuntimeEngineState::Unknown => "unknown",
        RuntimeEngineState::Stopped => "stopped",
        RuntimeEngineState::Starting => "starting",
        RuntimeEngineState::Ready => "ready",
        RuntimeEngineState::Exited => "exited",
        RuntimeEngineState::BackingOff => "backing_off",
        RuntimeEngineState::Stopping => "stopping",
        RuntimeEngineState::Failed => "failed",
    }
}

const fn runtime_verification_label(verification: RuntimeVerificationState) -> &'static str {
    match verification {
        RuntimeVerificationState::StructuralOnly => "structural_only",
        RuntimeVerificationState::FunctionalPending => "functional_pending",
        RuntimeVerificationState::FunctionalPassed => "functional_passed",
        RuntimeVerificationState::FunctionalFailed => "functional_failed",
    }
}

const fn mutation_gate_label(gate: MutationGate) -> &'static str {
    match gate {
        MutationGate::Allowed => "allowed",
        MutationGate::ReadOnly {
            kernel: KernelMutationStatus::Unsupported { .. },
            ..
        } => "unsupported_kernel",
        MutationGate::ReadOnly { .. } => "read_only_profile",
    }
}

const fn selinux_mode_label(mode: SelinuxMode) -> &'static str {
    match mode {
        SelinuxMode::Enforcing => "enforcing",
        SelinuxMode::Permissive => "permissive",
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
        _intent: RuntimeIntent,
    ) -> Result<flux_core::OperationReport, ControlError> {
        Err(ControlError::RuntimeStopped)
    }
}
