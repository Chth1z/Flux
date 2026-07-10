use flux_core::{
    AdministrativeState, ConfigurationChangeReport, ControlClient, ControlError, ControlSnapshot,
    KernelSupport, KernelVersion, LegacyIntent, OperationReport, Reason,
};
use serde::{Deserialize, Serialize};

const PROTOCOL_VERSION: u16 = 1;
pub const MAX_CONTROL_PACKET_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonSnapshot {
    pub kernel_support: KernelSupport,
    pub control: ControlSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventDisposition {
    Applied,
    Deferred,
    Ignored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventReport {
    pub disposition: EventDisposition,
    pub revision: u64,
}

pub struct ProtocolHandler<C> {
    kernel_support: KernelSupport,
    control: C,
}

impl<C> ProtocolHandler<C>
where
    C: ControlClient,
{
    #[must_use]
    pub const fn new(kernel_support: KernelSupport, control: C) -> Self {
        Self {
            kernel_support,
            control,
        }
    }

    #[must_use]
    pub const fn control(&self) -> &C {
        &self.control
    }

    #[must_use]
    pub fn handle(&self, packet: &[u8]) -> Vec<u8> {
        if packet.len() > MAX_CONTROL_PACKET_BYTES {
            return encode_response(ResponseEnvelope::error(
                0,
                "packet_too_large",
                format!("control packet exceeds {MAX_CONTROL_PACKET_BYTES} bytes"),
            ));
        }

        let request = match serde_json::from_slice::<RequestEnvelope>(packet) {
            Ok(request) => request,
            Err(error) => {
                return encode_response(ResponseEnvelope::error(
                    0,
                    "invalid_request",
                    format!("invalid control request: {error}"),
                ));
            }
        };

        if request.protocol_version != PROTOCOL_VERSION {
            return encode_response(ResponseEnvelope::error(
                request.request_id,
                "unsupported_protocol",
                format!(
                    "protocol version {} is unsupported; expected {PROTOCOL_VERSION}",
                    request.protocol_version
                ),
            ));
        }

        match request.command {
            WireCommand::Ping => {
                encode_response(ResponseEnvelope::ok(request.request_id, ResponseBody::Pong))
            }
            WireCommand::Status => encode_response(ResponseEnvelope::ok(
                request.request_id,
                ResponseBody::Snapshot {
                    kernel: self.kernel_support.into(),
                    control: self.control.snapshot().as_ref().into(),
                },
            )),
            WireCommand::Control { action, reason } => {
                self.handle_control(request.request_id, action, reason)
            }
            WireCommand::Event {
                event_type,
                watched_path: _,
                event_name,
            } => self.handle_event(request.request_id, &event_type, &event_name),
        }
    }

    fn handle_control(&self, request_id: u64, action: WireAction, reason: WireReason) -> Vec<u8> {
        if let Some(response) = self.unsupported_kernel_response(request_id) {
            return response;
        }

        let reason = reason.into();
        let intent = match action {
            WireAction::Start => LegacyIntent::Running { reason },
            WireAction::Stop => LegacyIntent::Stopped { reason },
            WireAction::Restart | WireAction::Reload => LegacyIntent::Reload { reason },
            WireAction::Resync => LegacyIntent::ResyncAddresses { reason },
        };
        match self.control.submit_and_wait(intent) {
            Ok(report) => encode_response(ResponseEnvelope::ok(
                request_id,
                ResponseBody::Operation {
                    revision: report.revision,
                },
            )),
            Err(error) => encode_response(ResponseEnvelope::error(
                request_id,
                "control_failed",
                error.to_string(),
            )),
        }
    }

    fn handle_event(&self, request_id: u64, event_type: &str, event_name: &str) -> Vec<u8> {
        match (event_name, event_type) {
            ("disable", "n") => self.handle_event_intent(
                request_id,
                LegacyIntent::Stopped {
                    reason: Reason::DisableCreated,
                },
            ),
            ("disable", "d") => self.handle_event_intent(
                request_id,
                LegacyIntent::Running {
                    reason: Reason::DisableRemoved,
                },
            ),
            ("settings.ini" | "config.json" | "addrsyncd.toml", "y") => {
                self.handle_configuration_event(request_id)
            }
            _ => encode_response(ResponseEnvelope::ok(
                request_id,
                ResponseBody::Event {
                    disposition: WireEventDisposition::Ignored,
                    revision: self.control.snapshot().revision,
                },
            )),
        }
    }

    fn handle_event_intent(&self, request_id: u64, intent: LegacyIntent) -> Vec<u8> {
        if let Some(response) = self.unsupported_kernel_response(request_id) {
            return response;
        }
        match self.control.submit_and_wait(intent) {
            Ok(report) => encode_response(ResponseEnvelope::ok(
                request_id,
                ResponseBody::Event {
                    disposition: WireEventDisposition::Applied,
                    revision: report.revision,
                },
            )),
            Err(error) => encode_response(ResponseEnvelope::error(
                request_id,
                "event_failed",
                error.to_string(),
            )),
        }
    }

    fn handle_configuration_event(&self, request_id: u64) -> Vec<u8> {
        if let Some(response) = self.unsupported_kernel_response(request_id) {
            return response;
        }
        match self.control.configuration_changed(Reason::ConfigChanged) {
            Ok(ConfigurationChangeReport::Reloaded(report)) => {
                encode_response(ResponseEnvelope::ok(
                    request_id,
                    ResponseBody::Event {
                        disposition: WireEventDisposition::Applied,
                        revision: report.revision,
                    },
                ))
            }
            Ok(ConfigurationChangeReport::Deferred { revision }) => {
                encode_response(ResponseEnvelope::ok(
                    request_id,
                    ResponseBody::Event {
                        disposition: WireEventDisposition::Deferred,
                        revision,
                    },
                ))
            }
            Err(error) => encode_response(ResponseEnvelope::error(
                request_id,
                "event_failed",
                error.to_string(),
            )),
        }
    }

    fn unsupported_kernel_response(&self, request_id: u64) -> Option<Vec<u8>> {
        let KernelSupport::Unsupported { found, minimum } = self.kernel_support else {
            return None;
        };
        Some(encode_response(ResponseEnvelope::error(
            request_id,
            "unsupported_kernel",
            format!("kernel {found} is below minimum {minimum}"),
        )))
    }
}

#[derive(Deserialize, Serialize)]
struct RequestEnvelope {
    protocol_version: u16,
    request_id: u64,
    command: WireCommand,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WireCommand {
    Ping,
    Status,
    Control {
        action: WireAction,
        reason: WireReason,
    },
    Event {
        event_type: String,
        watched_path: String,
        event_name: String,
    },
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireAction {
    Start,
    Stop,
    Restart,
    Reload,
    Resync,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireReason {
    Boot,
    Fluxctl,
    ConfigChanged,
    DisableCreated,
    DisableRemoved,
    EngineExited,
    DaemonRecovery,
}

impl From<WireReason> for Reason {
    fn from(reason: WireReason) -> Self {
        match reason {
            WireReason::Boot => Self::Boot,
            WireReason::Fluxctl => Self::Fluxctl,
            WireReason::ConfigChanged => Self::ConfigChanged,
            WireReason::DisableCreated => Self::DisableCreated,
            WireReason::DisableRemoved => Self::DisableRemoved,
            WireReason::EngineExited => Self::EngineExited,
            WireReason::DaemonRecovery => Self::DaemonRecovery,
        }
    }
}

impl From<Reason> for WireReason {
    fn from(reason: Reason) -> Self {
        match reason {
            Reason::Boot => Self::Boot,
            Reason::Fluxctl => Self::Fluxctl,
            Reason::ConfigChanged => Self::ConfigChanged,
            Reason::DisableCreated => Self::DisableCreated,
            Reason::DisableRemoved => Self::DisableRemoved,
            Reason::EngineExited => Self::EngineExited,
            Reason::DaemonRecovery => Self::DaemonRecovery,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct ResponseEnvelope {
    protocol_version: u16,
    request_id: u64,
    result: WireResult,
}

impl ResponseEnvelope {
    fn ok(request_id: u64, body: ResponseBody) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: WireResult::Ok { body },
        }
    }

    fn error(request_id: u64, code: impl Into<String>, message: String) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: WireResult::Error {
                code: code.into(),
                message,
            },
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum WireResult {
    Ok { body: ResponseBody },
    Error { code: String, message: String },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ResponseBody {
    Pong,
    Snapshot {
        kernel: WireKernelSupport,
        control: WireControlSnapshot,
    },
    Operation {
        revision: u64,
    },
    Event {
        disposition: WireEventDisposition,
        revision: u64,
    },
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireEventDisposition {
    Applied,
    Deferred,
    Ignored,
}

impl From<WireEventDisposition> for EventDisposition {
    fn from(disposition: WireEventDisposition) -> Self {
        match disposition {
            WireEventDisposition::Applied => Self::Applied,
            WireEventDisposition::Deferred => Self::Deferred,
            WireEventDisposition::Ignored => Self::Ignored,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum WireKernelSupport {
    Supported { version: String },
    Unsupported { found: String, minimum: String },
}

impl From<KernelSupport> for WireKernelSupport {
    fn from(support: KernelSupport) -> Self {
        match support {
            KernelSupport::Supported(version) => Self::Supported {
                version: version.to_string(),
            },
            KernelSupport::Unsupported { found, minimum } => Self::Unsupported {
                found: found.to_string(),
                minimum: minimum.to_string(),
            },
        }
    }
}

impl TryFrom<WireKernelSupport> for KernelSupport {
    type Error = ControlError;

    fn try_from(support: WireKernelSupport) -> Result<Self, Self::Error> {
        match support {
            WireKernelSupport::Supported { version } => KernelVersion::parse_release(&version)
                .map(Self::Supported)
                .map_err(|error| {
                    ControlError::dispatcher(format!("invalid daemon kernel version: {error}"))
                }),
            WireKernelSupport::Unsupported { found, minimum } => {
                let found = KernelVersion::parse_release(&found).map_err(|error| {
                    ControlError::dispatcher(format!("invalid daemon kernel version: {error}"))
                })?;
                let minimum = KernelVersion::parse_release(&minimum).map_err(|error| {
                    ControlError::dispatcher(format!("invalid daemon minimum kernel: {error}"))
                })?;
                Ok(Self::Unsupported { found, minimum })
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
struct WireControlSnapshot {
    revision: u64,
    administrative_state: WireAdministrativeState,
    configuration_dirty: bool,
    in_flight: Option<WireIntent>,
    last_completed: Option<WireOperationReport>,
}

impl From<&ControlSnapshot> for WireControlSnapshot {
    fn from(snapshot: &ControlSnapshot) -> Self {
        Self {
            revision: snapshot.revision,
            administrative_state: snapshot.administrative_state.into(),
            configuration_dirty: snapshot.configuration_dirty,
            in_flight: snapshot.in_flight.map(Into::into),
            last_completed: snapshot.last_completed.map(Into::into),
        }
    }
}

impl From<WireControlSnapshot> for ControlSnapshot {
    fn from(snapshot: WireControlSnapshot) -> Self {
        Self {
            revision: snapshot.revision,
            administrative_state: snapshot.administrative_state.into(),
            configuration_dirty: snapshot.configuration_dirty,
            in_flight: snapshot.in_flight.map(Into::into),
            last_completed: snapshot.last_completed.map(Into::into),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireAdministrativeState {
    Unknown,
    Running,
    Stopped,
}

impl From<AdministrativeState> for WireAdministrativeState {
    fn from(state: AdministrativeState) -> Self {
        match state {
            AdministrativeState::Unknown => Self::Unknown,
            AdministrativeState::Running => Self::Running,
            AdministrativeState::Stopped => Self::Stopped,
        }
    }
}

impl From<WireAdministrativeState> for AdministrativeState {
    fn from(state: WireAdministrativeState) -> Self {
        match state {
            WireAdministrativeState::Unknown => Self::Unknown,
            WireAdministrativeState::Running => Self::Running,
            WireAdministrativeState::Stopped => Self::Stopped,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct WireIntent {
    action: WireAction,
    reason: WireReason,
}

impl From<LegacyIntent> for WireIntent {
    fn from(intent: LegacyIntent) -> Self {
        let (action, reason) = match intent {
            LegacyIntent::Running { reason } => (WireAction::Start, reason),
            LegacyIntent::Stopped { reason } => (WireAction::Stop, reason),
            LegacyIntent::Reload { reason } => (WireAction::Reload, reason),
            LegacyIntent::ResyncAddresses { reason } => (WireAction::Resync, reason),
        };
        Self {
            action,
            reason: reason.into(),
        }
    }
}

impl From<WireIntent> for LegacyIntent {
    fn from(intent: WireIntent) -> Self {
        let reason = intent.reason.into();
        match intent.action {
            WireAction::Start => Self::Running { reason },
            WireAction::Stop => Self::Stopped { reason },
            WireAction::Restart | WireAction::Reload => Self::Reload { reason },
            WireAction::Resync => Self::ResyncAddresses { reason },
        }
    }
}

#[derive(Deserialize, Serialize)]
struct WireOperationReport {
    intent: WireIntent,
    revision: u64,
}

impl From<OperationReport> for WireOperationReport {
    fn from(report: OperationReport) -> Self {
        Self {
            intent: report.intent.into(),
            revision: report.revision,
        }
    }
}

impl From<WireOperationReport> for OperationReport {
    fn from(report: WireOperationReport) -> Self {
        Self {
            intent: report.intent.into(),
            revision: report.revision,
        }
    }
}

fn encode_response(response: ResponseEnvelope) -> Vec<u8> {
    let mut encoded = serde_json::to_vec(&response)
        .unwrap_or_else(|_| br#"{"protocol_version":1,"request_id":0,"result":{"status":"error","code":"internal","message":"response encoding failed"}}"#.to_vec());
    encoded.push(b'\n');
    encoded
}

pub(crate) fn encode_control_request(
    request_id: u64,
    intent: LegacyIntent,
) -> Result<Vec<u8>, ControlError> {
    let (action, reason) = match intent {
        LegacyIntent::Running { reason } => (WireAction::Start, reason),
        LegacyIntent::Stopped { reason } => (WireAction::Stop, reason),
        LegacyIntent::Reload { reason } => (WireAction::Reload, reason),
        LegacyIntent::ResyncAddresses { reason } => (WireAction::Resync, reason),
    };
    encode_request(RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        command: WireCommand::Control {
            action,
            reason: reason.into(),
        },
    })
}

pub(crate) fn encode_ping_request(request_id: u64) -> Result<Vec<u8>, ControlError> {
    encode_request(RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        command: WireCommand::Ping,
    })
}

pub(crate) fn encode_status_request(request_id: u64) -> Result<Vec<u8>, ControlError> {
    encode_request(RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        command: WireCommand::Status,
    })
}

pub(crate) fn encode_event_request(
    request_id: u64,
    event_type: &str,
    watched_path: &str,
    event_name: &str,
) -> Result<Vec<u8>, ControlError> {
    encode_request(RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        command: WireCommand::Event {
            event_type: event_type.to_owned(),
            watched_path: watched_path.to_owned(),
            event_name: event_name.to_owned(),
        },
    })
}

pub(crate) fn decode_control_response(
    packet: &[u8],
    expected_request_id: u64,
    intent: LegacyIntent,
) -> Result<OperationReport, ControlError> {
    let response = decode_response(packet, expected_request_id)?;
    match response.result {
        WireResult::Ok {
            body: ResponseBody::Operation { revision },
        } => Ok(OperationReport { intent, revision }),
        WireResult::Ok { .. } => Err(unexpected_response("control")),
        WireResult::Error { code, message } => Err(rejected_response(code, message)),
    }
}

pub(crate) fn decode_ping_response(
    packet: &[u8],
    expected_request_id: u64,
) -> Result<(), ControlError> {
    let response = decode_response(packet, expected_request_id)?;
    match response.result {
        WireResult::Ok {
            body: ResponseBody::Pong,
        } => Ok(()),
        WireResult::Ok { .. } => Err(unexpected_response("ping")),
        WireResult::Error { code, message } => Err(rejected_response(code, message)),
    }
}

pub(crate) fn decode_status_response(
    packet: &[u8],
    expected_request_id: u64,
) -> Result<DaemonSnapshot, ControlError> {
    let response = decode_response(packet, expected_request_id)?;
    match response.result {
        WireResult::Ok {
            body: ResponseBody::Snapshot { kernel, control },
        } => Ok(DaemonSnapshot {
            kernel_support: kernel.try_into()?,
            control: control.into(),
        }),
        WireResult::Ok { .. } => Err(unexpected_response("status")),
        WireResult::Error { code, message } => Err(rejected_response(code, message)),
    }
}

pub(crate) fn decode_event_response(
    packet: &[u8],
    expected_request_id: u64,
) -> Result<EventReport, ControlError> {
    let response = decode_response(packet, expected_request_id)?;
    match response.result {
        WireResult::Ok {
            body:
                ResponseBody::Event {
                    disposition,
                    revision,
                },
        } => Ok(EventReport {
            disposition: disposition.into(),
            revision,
        }),
        WireResult::Ok { .. } => Err(unexpected_response("event")),
        WireResult::Error { code, message } => Err(rejected_response(code, message)),
    }
}

fn encode_request(request: RequestEnvelope) -> Result<Vec<u8>, ControlError> {
    serde_json::to_vec(&request)
        .map_err(|error| ControlError::dispatcher(format!("encode control request: {error}")))
}

fn decode_response(
    packet: &[u8],
    expected_request_id: u64,
) -> Result<ResponseEnvelope, ControlError> {
    let response = serde_json::from_slice::<ResponseEnvelope>(packet)
        .map_err(|error| ControlError::dispatcher(format!("decode control response: {error}")))?;
    if response.protocol_version != PROTOCOL_VERSION {
        return Err(ControlError::dispatcher(format!(
            "daemon protocol version {} does not match {PROTOCOL_VERSION}",
            response.protocol_version
        )));
    }
    if response.request_id != expected_request_id {
        return Err(ControlError::dispatcher(format!(
            "daemon response request ID {} does not match {expected_request_id}",
            response.request_id
        )));
    }
    Ok(response)
}

fn unexpected_response(request_kind: &str) -> ControlError {
    ControlError::dispatcher(format!(
        "daemon returned an unexpected body for a {request_kind} request"
    ))
}

fn rejected_response(code: String, message: String) -> ControlError {
    ControlError::dispatcher(format!(
        "daemon rejected control request ({code}): {message}"
    ))
}
