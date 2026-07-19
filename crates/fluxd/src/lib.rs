use std::io::Write;

use flux_core::{
    AdministrativeState, ControlClient, ControlError, ControlSnapshot, KernelMutationStatus,
    KernelSupport, LegacyAddressSynchronization, LegacyArtifactReadiness, LegacyArtifactResolution,
    LegacyIntent, LegacyMutationGate, LegacyMutationWriter, LegacyRuleBackend,
    MIN_SUPPORTED_KERNEL, Observation, OperationReport, Reason, SelinuxMode,
};
use flux_platform::KernelReleaseSource;
use serde::Serialize;

mod daemon;
mod engine_manifest;
mod engine_supervisor;
// The required Stage 1 gate is wired behind an explicit coordinator seam, but
// production remains structural-only until a platform adapter is qualified.
#[allow(dead_code)]
mod functional_canary;
mod intent_store;
mod legacy_rules_cli;
mod legacy_rules_manifest;
mod protocol;
mod runtime_coordinator;
mod runtime_status;
mod socket;

use protocol::WireCapabilityProfile;

pub use daemon::{DaemonError, DaemonOptions, run_daemon};
pub use engine_manifest::{
    EngineManifest, EngineManifestError, EngineManifestErrorKind, EngineManifestIoOperation,
    MAX_ENGINE_MANIFEST_BYTES, MAX_ENGINE_TIMEOUT_MS, PreparedEngineManifest,
};
pub use engine_supervisor::{
    CaptureBlockedAction, CaptureObservation, DesiredEngine, EngineArtifact, EngineArtifactDigest,
    EnginePhase, EngineReport, EngineSnapshot, EngineSpec, EngineSpecError, EngineSpecIoOperation,
    EngineSupervisor, EngineSupervisorError, EngineSupervisorErrorKind, MAX_ENGINE_BINARY_BYTES,
    MAX_ENGINE_CONFIG_BYTES, MAX_ENGINE_DIAGNOSTIC_BYTES, OwnedEngineIdentity, RestartPolicy,
    RestartPolicyError, SHA256_DIGEST_BYTES,
};
pub use intent_store::{AdministrativeIntentStore, IntentStoreError};
pub use legacy_rules_cli::{
    LegacyRulesEnvironment, ProcessLegacyRulesEnvironment, run_legacy_package_snapshot_cli,
    run_legacy_rules_attestation_cli, run_legacy_rules_cli,
};
pub use legacy_rules_manifest::{
    LEGACY_RULES_SET_MANIFEST_SCHEMA_VERSION, LegacyRulesArtifactManifest, LegacyRulesFamilyShape,
    LegacyRulesManifestDigest, LegacyRulesManifestResourceTotals, LegacyRulesPairManifest,
    LegacyRulesSetManifest, LegacyRulesSetManifestError, LegacyRulesSetManifestErrorKind,
    MAX_LEGACY_RULES_SET_MANIFEST_BYTES,
};
pub use protocol::{
    DaemonSnapshot, EventDisposition, EventReport, MAX_CONTROL_PACKET_BYTES, ProtocolHandler,
    RequestPeerId,
};
pub use runtime_status::{
    RuntimeCaptureState, RuntimeEngineState, RuntimeFailure, RuntimePhase, RuntimeSnapshot,
    RuntimeSnapshotSource, RuntimeVerificationState,
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
            mutating_error_exit(&error)
        }
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
    let daemon_state = match capability_profile.legacy_mutation_gate() {
        LegacyMutationGate::Allowed => "running",
        LegacyMutationGate::ReadOnly {
            kernel: KernelMutationStatus::Unsupported { .. },
            ..
        } => "unsupported_kernel",
        LegacyMutationGate::ReadOnly { .. } => "read_only_profile",
    };

    if json {
        let document = OnlineStatusDocument {
            daemon: daemon_state,
            kernel: online_kernel_document(capability_profile),
            capability_profile: capability_profile.into(),
            control: OnlineControlDocument::from(snapshot.control),
            runtime: OnlineRuntimeDocument::from(snapshot.runtime),
        };
        if serde_json::to_writer(&mut *stdout, &document).is_err() || writeln!(stdout).is_err() {
            return EXIT_RUNTIME_ERROR;
        }
        return EXIT_SUCCESS;
    }

    let bridge = capability_profile.legacy_bridge();
    let administrative_state = administrative_state_label(snapshot.control.administrative_state);
    let runtime_generation = snapshot
        .runtime
        .generation
        .map_or_else(|| "none".to_owned(), |generation| generation.to_string());
    let runtime_error = snapshot
        .runtime
        .last_error
        .as_ref()
        .map_or_else(|| "none".to_owned(), format_runtime_failure);
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
            mutation_gate_label(capability_profile.legacy_mutation_gate())
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
        || writeln!(
            stdout,
            "legacy mutation writer: {}",
            legacy_mutation_writer_label(bridge.mutation_writer())
        )
        .is_err()
        || writeln!(
            stdout,
            "legacy rule backend: {}",
            legacy_rule_backend_label(bridge.rule_backend())
        )
        .is_err()
        || writeln!(
            stdout,
            "legacy address synchronization: {}",
            legacy_address_synchronization_label(bridge.address_synchronization())
        )
        .is_err()
        || writeln!(
            stdout,
            "legacy shell: {}",
            format_legacy_artifact(bridge.shell())
        )
        .is_err()
        || writeln!(
            stdout,
            "legacy dispatcher: {}",
            format_legacy_artifact(bridge.dispatcher())
        )
        .is_err()
        || writeln!(
            stdout,
            "legacy addrsync: {}",
            format_legacy_artifact(bridge.addrsync())
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
        "Usage: fluxd <COMMAND>\n\nCommands:\n  status [--json]\n  control <start|stop|restart|reload|resync>\n  ping\n  event <EVENT_TYPE> <WATCHED_PATH> <EVENT_NAME>\n  render-legacy-rules --packages-list PATH --family 4|6 --action apply|cleanup\n  snapshot-legacy-packages --source PATH\n  attest-legacy-rules-set --generation ID --packages-list PATH --ipv4-apply PATH --ipv4-cleanup PATH [--ipv6-apply PATH --ipv6-cleanup PATH]\n  help\n  version"
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
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel: Option<OnlineKernelDocument>,
    capability_profile: WireCapabilityProfile,
    control: OnlineControlDocument,
    runtime: OnlineRuntimeDocument,
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
struct OnlineRuntimeDocument {
    revision: u64,
    phase: &'static str,
    capture: &'static str,
    engine: &'static str,
    verification: &'static str,
    generation: Option<u64>,
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
            generation: snapshot.generation,
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

fn online_kernel_document(profile: &flux_core::CapabilityProfile) -> Option<OnlineKernelDocument> {
    match profile.kernel_support()? {
        KernelSupport::Supported(version) => Some(OnlineKernelDocument {
            version: version.to_string(),
            minimum: MIN_SUPPORTED_KERNEL.to_string(),
            supported: true,
        }),
        KernelSupport::Unsupported { found, minimum } => Some(OnlineKernelDocument {
            version: found.to_string(),
            minimum: minimum.to_string(),
            supported: false,
        }),
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

fn format_legacy_artifact(observation: &Observation<LegacyArtifactReadiness>) -> String {
    match observation {
        Observation::Verified(artifact) => format!(
            "{} ({}, verified)",
            if artifact.is_ready() {
                "ready"
            } else {
                "not ready"
            },
            legacy_artifact_resolution_label(artifact.resolution())
        ),
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

const fn mutation_gate_label(gate: LegacyMutationGate) -> &'static str {
    match gate {
        LegacyMutationGate::Allowed => "allowed",
        LegacyMutationGate::ReadOnly {
            kernel: KernelMutationStatus::Unsupported { .. },
            ..
        } => "unsupported_kernel",
        LegacyMutationGate::ReadOnly { .. } => "read_only_profile",
    }
}

const fn selinux_mode_label(mode: SelinuxMode) -> &'static str {
    match mode {
        SelinuxMode::Enforcing => "enforcing",
        SelinuxMode::Permissive => "permissive",
    }
}

const fn legacy_mutation_writer_label(writer: LegacyMutationWriter) -> &'static str {
    match writer {
        LegacyMutationWriter::Dispatcher => "dispatcher",
    }
}

const fn legacy_rule_backend_label(backend: LegacyRuleBackend) -> &'static str {
    match backend {
        LegacyRuleBackend::IptablesRestore => "iptables_restore",
    }
}

const fn legacy_address_synchronization_label(
    synchronization: LegacyAddressSynchronization,
) -> &'static str {
    match synchronization {
        LegacyAddressSynchronization::StandaloneAddrsyncdViaScript => {
            "standalone_addrsyncd_via_script"
        }
    }
}

const fn legacy_artifact_resolution_label(resolution: LegacyArtifactResolution) -> &'static str {
    match resolution {
        LegacyArtifactResolution::Direct => "direct",
        LegacyArtifactResolution::SymbolicLink => "symbolic_link",
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
