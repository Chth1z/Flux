use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use flux_core::{
    AdministrativeState, ConfigurationChangeReport, ControlError, ControlService, ControlSnapshot,
    KernelSupport, KernelVersion, LegacyIntent, OperationReport, Reason,
};
use flux_platform::Uid;
use serde::{Deserialize, Serialize};

const PROTOCOL_VERSION: u16 = 1;
const RECENT_RESULT_CAPACITY: usize = 128;
const RECENT_RESULT_FINGERPRINT_BYTES: usize = MAX_CONTROL_PACKET_BYTES;
const RECENT_RESULT_RESPONSE_BYTES: usize = MAX_CONTROL_PACKET_BYTES;
const DUPLICATE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_CONTROL_PACKET_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestPeerId(u64);

impl RequestPeerId {
    const IN_PROCESS: Self = Self(0);

    #[must_use]
    pub const fn new(uid: Uid, pid: u32) -> Self {
        Self((uid.as_raw() as u64) << 32 | pid as u64)
    }
}

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
    recent_results: Mutex<RecentResults>,
}

impl<C> ProtocolHandler<C>
where
    C: ControlService,
{
    #[must_use]
    pub fn new(kernel_support: KernelSupport, control: C) -> Self {
        Self {
            kernel_support,
            control,
            recent_results: Mutex::new(RecentResults::default()),
        }
    }

    #[must_use]
    pub const fn control(&self) -> &C {
        &self.control
    }

    #[must_use]
    pub fn handle(&self, packet: &[u8]) -> Vec<u8> {
        self.handle_for_peer(packet, RequestPeerId::IN_PROCESS)
    }

    #[must_use]
    pub fn handle_for_peer(&self, packet: &[u8], peer: RequestPeerId) -> Vec<u8> {
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

        if request.command.is_mutating() {
            let key = RecentRequestKey {
                peer,
                request_id: request.request_id,
            };
            let decision = match self.recent_results.lock() {
                Ok(mut recent) => recent.begin(key, packet),
                Err(poisoned) => poisoned.into_inner().begin(key, packet),
            };
            match decision {
                RecentDecision::Owner(completion) => {
                    let response = self.dispatch(request);
                    match self.recent_results.lock() {
                        Ok(mut recent) => recent.complete(key, &completion, &response),
                        Err(poisoned) => {
                            poisoned.into_inner().complete(key, &completion, &response)
                        }
                    }
                    return response;
                }
                RecentDecision::Duplicate(completion) => {
                    return completion.wait().unwrap_or_else(|| {
                        encode_response(ResponseEnvelope::error(
                            request.request_id,
                            "request_in_flight",
                            "timed out waiting for the original request".to_owned(),
                        ))
                    });
                }
                RecentDecision::Conflict => {
                    return encode_response(ResponseEnvelope::error(
                        request.request_id,
                        "request_id_conflict",
                        "request ID was already used for a different mutation".to_owned(),
                    ));
                }
                RecentDecision::Busy => {
                    return encode_response(ResponseEnvelope::error(
                        request.request_id,
                        "recent_result_cache_full",
                        "too many mutating requests are still in flight".to_owned(),
                    ));
                }
            }
        }

        self.dispatch(request)
    }

    fn dispatch(&self, request: RequestEnvelope) -> Vec<u8> {
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

impl WireCommand {
    const fn is_mutating(&self) -> bool {
        matches!(self, Self::Control { .. } | Self::Event { .. })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RecentRequestKey {
    peer: RequestPeerId,
    request_id: u64,
}

#[derive(Default)]
struct RecentResults {
    entries: HashMap<RecentRequestKey, RecentEntry>,
    order: VecDeque<RecentRequestKey>,
    fingerprint_bytes: usize,
    response_bytes: usize,
}

impl RecentResults {
    fn begin(&mut self, key: RecentRequestKey, packet: &[u8]) -> RecentDecision {
        if let Some(entry) = self.entries.get(&key) {
            return if entry.fingerprint.as_ref() == packet {
                RecentDecision::Duplicate(Arc::clone(&entry.completion))
            } else {
                RecentDecision::Conflict
            };
        }

        self.evict_completed_for(1, packet.len(), 0);
        if self.entries.len().saturating_add(1) > RECENT_RESULT_CAPACITY
            || self.fingerprint_bytes.saturating_add(packet.len()) > RECENT_RESULT_FINGERPRINT_BYTES
        {
            return RecentDecision::Busy;
        }

        let completion = Arc::new(RequestCompletion::default());
        self.fingerprint_bytes = self.fingerprint_bytes.saturating_add(packet.len());
        self.order.push_back(key);
        self.entries.insert(
            key,
            RecentEntry {
                fingerprint: packet.to_vec().into_boxed_slice(),
                completion: Arc::clone(&completion),
                response_bytes: 0,
            },
        );
        RecentDecision::Owner(completion)
    }

    fn complete(
        &mut self,
        key: RecentRequestKey,
        completion: &Arc<RequestCompletion>,
        response: &[u8],
    ) {
        self.evict_completed_for(0, 0, response.len());
        let can_retain = response.len() <= RECENT_RESULT_RESPONSE_BYTES
            && self.response_bytes.saturating_add(response.len()) <= RECENT_RESULT_RESPONSE_BYTES;

        if can_retain {
            if let Some(entry) = self.entries.get_mut(&key) {
                debug_assert!(Arc::ptr_eq(&entry.completion, completion));
                debug_assert_eq!(entry.response_bytes, 0);
                entry.response_bytes = response.len();
                self.response_bytes = self.response_bytes.saturating_add(response.len());
            } else {
                completion.finish(response);
                return;
            }
        } else {
            self.order.retain(|candidate| *candidate != key);
            self.remove_entry(key);
        }

        // Publication occurs while the recent-results lock is still held. This
        // keeps response accounting and completion visibility one atomic cache
        // transition while waiters use only the completion lock.
        completion.finish(response);
        debug_assert!(self.response_bytes <= RECENT_RESULT_RESPONSE_BYTES);
    }

    fn evict_completed_for(
        &mut self,
        incoming_entries: usize,
        incoming_fingerprint_bytes: usize,
        incoming_response_bytes: usize,
    ) {
        let mut examined = 0;
        while (self.entries.len().saturating_add(incoming_entries) > RECENT_RESULT_CAPACITY
            || self
                .fingerprint_bytes
                .saturating_add(incoming_fingerprint_bytes)
                > RECENT_RESULT_FINGERPRINT_BYTES
            || self.response_bytes.saturating_add(incoming_response_bytes)
                > RECENT_RESULT_RESPONSE_BYTES)
            && examined < self.order.len()
        {
            let Some(key) = self.order.pop_front() else {
                break;
            };
            let completed = self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.completion.is_finished());
            if completed {
                self.remove_entry(key);
            } else {
                self.order.push_back(key);
                examined = examined.saturating_add(1);
            }
        }
    }

    fn remove_entry(&mut self, key: RecentRequestKey) {
        if let Some(entry) = self.entries.remove(&key) {
            self.fingerprint_bytes = self
                .fingerprint_bytes
                .saturating_sub(entry.fingerprint.len());
            self.response_bytes = self.response_bytes.saturating_sub(entry.response_bytes);
        }
    }
}

struct RecentEntry {
    fingerprint: Box<[u8]>,
    completion: Arc<RequestCompletion>,
    response_bytes: usize,
}

enum RecentDecision {
    Owner(Arc<RequestCompletion>),
    Duplicate(Arc<RequestCompletion>),
    Conflict,
    Busy,
}

#[derive(Default)]
struct RequestCompletion {
    response: Mutex<Option<Arc<[u8]>>>,
    ready: Condvar,
}

impl RequestCompletion {
    fn finish(&self, response: &[u8]) {
        let mut slot = match self.response.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        *slot = Some(Arc::from(response));
        self.ready.notify_all();
    }

    fn is_finished(&self) -> bool {
        match self.response.lock() {
            Ok(response) => response.is_some(),
            Err(poisoned) => poisoned.into_inner().is_some(),
        }
    }

    fn wait(&self) -> Option<Vec<u8>> {
        let deadline = Instant::now() + DUPLICATE_WAIT_TIMEOUT;
        let mut slot = match self.response.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        loop {
            if let Some(response) = slot.as_ref() {
                return Some(response.to_vec());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let waited = self.ready.wait_timeout(slot, remaining);
            let (next, timeout) = match waited {
                Ok(waited) => waited,
                Err(poisoned) => poisoned.into_inner(),
            };
            slot = next;
            if timeout.timed_out() && slot.is_none() {
                return None;
            }
        }
    }
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
    let request_id = response.request_id;
    let mut encoded = match serde_json::to_vec(&response) {
        Ok(encoded) if encoded.len() < MAX_CONTROL_PACKET_BYTES => encoded,
        Ok(_) => {
            return encode_fixed_error_response(
                request_id,
                "response_too_large",
                format!("control response exceeds {MAX_CONTROL_PACKET_BYTES} bytes"),
            );
        }
        Err(_) => {
            return encode_fixed_error_response(
                request_id,
                "internal",
                "response encoding failed".to_owned(),
            );
        }
    };
    encoded.push(b'\n');
    encoded
}

fn encode_fixed_error_response(request_id: u64, code: &'static str, message: String) -> Vec<u8> {
    let fallback = ResponseEnvelope::error(request_id, code, message);
    let mut encoded = serde_json::to_vec(&fallback).unwrap_or_else(|_| {
        format!(
            "{{\"protocol_version\":{PROTOCOL_VERSION},\"request_id\":{request_id},\"result\":{{\"status\":\"error\",\"code\":\"internal\",\"message\":\"response encoding failed\"}}}}"
        )
        .into_bytes()
    });
    debug_assert!(encoded.len() < MAX_CONTROL_PACKET_BYTES);
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
