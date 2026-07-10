use flux_core::{
    ControlClient, ControlError, KernelSupport, LegacyIntent, OperationReport, Reason,
};
use serde::{Deserialize, Serialize};

const PROTOCOL_VERSION: u16 = 1;
pub const MAX_CONTROL_PACKET_BYTES: usize = 1024 * 1024;

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
            WireCommand::Control { action, reason } => {
                self.handle_control(request.request_id, action, reason)
            }
        }
    }

    fn handle_control(&self, request_id: u64, action: WireAction, reason: WireReason) -> Vec<u8> {
        if let KernelSupport::Unsupported { found, minimum } = self.kernel_support {
            return encode_response(ResponseEnvelope::error(
                request_id,
                "unsupported_kernel",
                format!("kernel {found} is below minimum {minimum}"),
            ));
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
    Control {
        action: WireAction,
        reason: WireReason,
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
    Operation { revision: u64 },
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
    let request = RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        command: WireCommand::Control {
            action,
            reason: reason.into(),
        },
    };
    serde_json::to_vec(&request)
        .map_err(|error| ControlError::dispatcher(format!("encode control request: {error}")))
}

pub(crate) fn decode_control_response(
    packet: &[u8],
    expected_request_id: u64,
    intent: LegacyIntent,
) -> Result<OperationReport, ControlError> {
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
    match response.result {
        WireResult::Ok {
            body: ResponseBody::Operation { revision },
        } => Ok(OperationReport { intent, revision }),
        WireResult::Ok {
            body: ResponseBody::Pong,
        } => Err(ControlError::dispatcher(
            "daemon returned pong for a control request",
        )),
        WireResult::Error { code, message } => Err(ControlError::dispatcher(format!(
            "daemon rejected control request ({code}): {message}"
        ))),
    }
}
