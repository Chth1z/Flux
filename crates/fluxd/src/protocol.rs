use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use flux_core::{
    AddressResyncDisposition, AdministrativeState, AndroidBuildIdentity, AndroidProductIdentity,
    ArtifactIdentity, BootIdentity, BootIdentityMutationStatus, CAPABILITY_PROFILE_SCHEMA_VERSION,
    CapabilityProfile, ControlError, ControlService, ControlSnapshot, DeviceIdentity,
    KernelBuildIdentity, KernelFacts, KernelMutationStatus, KernelRelease, KernelVersion,
    MIN_SUPPORTED_KERNEL, MutationGate, NetworkNamespaceIdentity, Observation, OperationReport,
    Reason, RuntimeIntent, SecurityPatchLevel, SelinuxMode, SelinuxPolicyIdentity, Sha256Digest,
    ToolId, VendorBuildIdentity, VerifiedBootIdentity, VerifiedBootState,
};
use flux_platform::Uid;
use serde::{Deserialize, Serialize};

use crate::inspection::InspectionSource;
use crate::subscription::{
    SubscriptionRefreshClient, SubscriptionRefreshDisposition, SubscriptionRefreshReport,
};
use crate::{
    DiagnosticReport, ExplainReport, LogReport, LogStream, NativeAdmissionRejection,
    NativeAdmissionState, RuntimeCaptureState, RuntimeEngineState, RuntimeFailure, RuntimePhase,
    RuntimeSnapshot, RuntimeSnapshotSource, RuntimeVerificationState,
};

const PROTOCOL_VERSION: u16 = 5;
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonSnapshot {
    pub capability_profile: CapabilityProfile,
    pub native_admission: NativeAdmissionState,
    pub control: ControlSnapshot,
    pub runtime: RuntimeSnapshot,
}

pub struct ProtocolHandler<C> {
    capability_profile: Arc<CapabilityProfile>,
    native_admission: NativeAdmissionState,
    control: C,
    runtime: RuntimeSnapshotSource,
    subscription: Option<SubscriptionRefreshClient>,
    inspection: Option<Arc<dyn InspectionSource>>,
    recent_results: Mutex<RecentResults>,
}

impl<C> ProtocolHandler<C>
where
    C: ControlService,
{
    #[must_use]
    pub fn new(
        capability_profile: Arc<CapabilityProfile>,
        native_admission: NativeAdmissionState,
        control: C,
    ) -> Self {
        Self::with_runtime_snapshot_source(
            capability_profile,
            native_admission,
            control,
            RuntimeSnapshotSource::default(),
        )
    }

    #[must_use]
    pub fn with_runtime_snapshot_source(
        capability_profile: Arc<CapabilityProfile>,
        native_admission: NativeAdmissionState,
        control: C,
        runtime: RuntimeSnapshotSource,
    ) -> Self {
        Self::with_runtime_snapshot_and_subscription(
            capability_profile,
            native_admission,
            control,
            runtime,
            None,
        )
    }

    #[must_use]
    pub(crate) fn with_runtime_snapshot_and_subscription(
        capability_profile: Arc<CapabilityProfile>,
        native_admission: NativeAdmissionState,
        control: C,
        runtime: RuntimeSnapshotSource,
        subscription: Option<SubscriptionRefreshClient>,
    ) -> Self {
        Self::with_runtime_subscription_and_inspection(
            capability_profile,
            native_admission,
            control,
            runtime,
            subscription,
            None,
        )
    }

    #[must_use]
    pub(crate) fn with_runtime_subscription_and_inspection(
        capability_profile: Arc<CapabilityProfile>,
        native_admission: NativeAdmissionState,
        control: C,
        runtime: RuntimeSnapshotSource,
        subscription: Option<SubscriptionRefreshClient>,
        inspection: Option<Arc<dyn InspectionSource>>,
    ) -> Self {
        Self {
            capability_profile,
            native_admission,
            control,
            runtime,
            subscription,
            inspection,
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
                    capability_profile: Box::new(self.capability_profile.as_ref().into()),
                    native_admission: self.native_admission.into(),
                    control: self.control.snapshot().as_ref().into(),
                    runtime: self.runtime.snapshot().as_ref().into(),
                },
            )),
            WireCommand::Control { action, reason } => {
                self.handle_control(request.request_id, action, reason)
            }
            WireCommand::SubscriptionUpdate => self.handle_subscription_update(request.request_id),
            WireCommand::Diagnose => self.handle_diagnose(request.request_id),
            WireCommand::Logs { stream, lines } => {
                self.handle_logs(request.request_id, stream, lines)
            }
            WireCommand::Explain => self.handle_explain(request.request_id),
        }
    }

    fn handle_diagnose(&self, request_id: u64) -> Vec<u8> {
        let Some(inspection) = self.inspection.as_ref() else {
            return inspection_unavailable_response(request_id);
        };
        encode_response(ResponseEnvelope::ok(
            request_id,
            ResponseBody::Diagnostics {
                report: inspection.diagnose(),
            },
        ))
    }

    fn handle_logs(&self, request_id: u64, stream: LogStream, lines: u16) -> Vec<u8> {
        let Some(inspection) = self.inspection.as_ref() else {
            return inspection_unavailable_response(request_id);
        };
        match inspection.logs(stream, lines) {
            Ok(report) => encode_response(ResponseEnvelope::ok(
                request_id,
                ResponseBody::Logs { report },
            )),
            Err(error) => encode_response(ResponseEnvelope::error(
                request_id,
                error.kind().rejection_code(),
                error.to_string(),
            )),
        }
    }

    fn handle_explain(&self, request_id: u64) -> Vec<u8> {
        let Some(inspection) = self.inspection.as_ref() else {
            return inspection_unavailable_response(request_id);
        };
        match inspection.explain() {
            Ok(report) => encode_response(ResponseEnvelope::ok(
                request_id,
                ResponseBody::Explain { report },
            )),
            Err(error) => encode_response(ResponseEnvelope::error(
                request_id,
                error.kind().rejection_code(),
                error.to_string(),
            )),
        }
    }

    fn handle_subscription_update(&self, request_id: u64) -> Vec<u8> {
        if let Some(response) = self.mutation_gate_response(request_id) {
            return response;
        }
        let Some(subscription) = self.subscription.as_ref() else {
            return encode_response(ResponseEnvelope::error(
                request_id,
                "subscription_unavailable",
                "subscription refresh is unavailable in this daemon runtime".to_owned(),
            ));
        };
        match subscription.refresh() {
            Ok(report) => encode_response(ResponseEnvelope::ok(
                request_id,
                ResponseBody::SubscriptionUpdate {
                    disposition: report.disposition().into(),
                    generation: report.generation(),
                    node_count: report.node_count(),
                    cleanup_pending: report.cleanup_pending(),
                },
            )),
            Err(error) => encode_response(ResponseEnvelope::error(
                request_id,
                error.kind().rejection_code(),
                error.to_string(),
            )),
        }
    }

    fn handle_control(&self, request_id: u64, action: WireAction, reason: WireReason) -> Vec<u8> {
        if let Some(response) = self.mutation_gate_response(request_id) {
            return response;
        }

        let reason = reason.into();
        let intent = match action {
            WireAction::Start => RuntimeIntent::Running { reason },
            WireAction::Stop => RuntimeIntent::Stopped { reason },
            WireAction::Restart | WireAction::Reload => RuntimeIntent::Reload { reason },
            WireAction::Resync => RuntimeIntent::ResyncAddresses { reason },
        };
        match self
            .control
            .submit_and_wait(intent)
            .and_then(validate_operation_report)
        {
            Ok(report) => encode_response(ResponseEnvelope::ok(
                request_id,
                ResponseBody::Operation {
                    revision: report.revision,
                    address_resync: report.address_resync.map(Into::into),
                },
            )),
            Err(error) => encode_response(ResponseEnvelope::error(
                request_id,
                "control_failed",
                error.to_string(),
            )),
        }
    }

    fn mutation_gate_response(&self, request_id: u64) -> Option<Vec<u8>> {
        let reason = self.native_admission.rejection()?;
        let message = if reason == NativeAdmissionRejection::UnsupportedKernel {
            match self.capability_profile.mutation_gate() {
                MutationGate::ReadOnly {
                    kernel: KernelMutationStatus::Unsupported { found, minimum },
                    ..
                } => format!("kernel {found} is below minimum {minimum}"),
                _ => format!("native admission rejected: {reason}"),
            }
        } else {
            format!("native admission rejected: {reason}")
        };
        Some(encode_response(ResponseEnvelope::error(
            request_id,
            reason.as_token(),
            message,
        )))
    }
}

fn inspection_unavailable_response(request_id: u64) -> Vec<u8> {
    encode_response(ResponseEnvelope::error(
        request_id,
        "inspection_unavailable",
        "read-only inspection is unavailable in this daemon runtime".to_owned(),
    ))
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
    SubscriptionUpdate,
    Diagnose,
    Logs {
        stream: LogStream,
        lines: u16,
    },
    Explain,
}

impl WireCommand {
    const fn is_mutating(&self) -> bool {
        matches!(self, Self::Control { .. } | Self::SubscriptionUpdate)
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
    UserControl,
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
            WireReason::UserControl => Self::UserControl,
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
            Reason::UserControl => Self::UserControl,
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
        capability_profile: Box<WireCapabilityProfile>,
        native_admission: WireNativeAdmission,
        control: WireControlSnapshot,
        runtime: WireRuntimeSnapshot,
    },
    Operation {
        revision: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        address_resync: Option<WireAddressResyncDisposition>,
    },
    SubscriptionUpdate {
        disposition: WireSubscriptionRefreshDisposition,
        generation: Option<u64>,
        node_count: Option<u32>,
        cleanup_pending: bool,
    },
    Diagnostics {
        report: DiagnosticReport,
    },
    Logs {
        report: LogReport,
    },
    Explain {
        report: ExplainReport,
    },
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireAddressResyncDisposition {
    CompleteNoChange,
    SuccessorConverged,
    AcceptedDeferred,
}

impl From<AddressResyncDisposition> for WireAddressResyncDisposition {
    fn from(disposition: AddressResyncDisposition) -> Self {
        match disposition {
            AddressResyncDisposition::CompleteNoChange => Self::CompleteNoChange,
            AddressResyncDisposition::SuccessorConverged => Self::SuccessorConverged,
            AddressResyncDisposition::AcceptedDeferred => Self::AcceptedDeferred,
        }
    }
}

impl From<WireAddressResyncDisposition> for AddressResyncDisposition {
    fn from(disposition: WireAddressResyncDisposition) -> Self {
        match disposition {
            WireAddressResyncDisposition::CompleteNoChange => Self::CompleteNoChange,
            WireAddressResyncDisposition::SuccessorConverged => Self::SuccessorConverged,
            WireAddressResyncDisposition::AcceptedDeferred => Self::AcceptedDeferred,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct WireCapabilityProfile {
    schema_version: u16,
    revision: u64,
    boot_identity: WireObservation<String>,
    device_identity: Option<WireObservation<WireDeviceIdentity>>,
    kernel: WireKernelFacts,
    selinux: WireObservation<WireSelinuxMode>,
}

impl From<&CapabilityProfile> for WireCapabilityProfile {
    fn from(profile: &CapabilityProfile) -> Self {
        Self {
            schema_version: profile.schema_version(),
            revision: profile.revision().get(),
            boot_identity: wire_boot_identity(profile.boot_identity()),
            device_identity: Some(wire_device_identity(profile.device_identity())),
            kernel: WireKernelFacts {
                release: wire_kernel_release(profile.kernel().release()),
                version: wire_kernel_version(profile.kernel().version()),
                minimum: MIN_SUPPORTED_KERNEL.to_string(),
                gate: profile.mutation_gate().into(),
            },
            selinux: wire_selinux(profile.selinux()),
        }
    }
}

impl TryFrom<WireCapabilityProfile> for CapabilityProfile {
    type Error = ControlError;

    fn try_from(wire: WireCapabilityProfile) -> Result<Self, Self::Error> {
        let WireCapabilityProfile {
            schema_version,
            revision,
            boot_identity,
            device_identity,
            kernel,
            selinux,
        } = wire;
        if schema_version != CAPABILITY_PROFILE_SCHEMA_VERSION {
            return Err(invalid_capability_profile(format!(
                "schema version {} is unsupported; expected {CAPABILITY_PROFILE_SCHEMA_VERSION}",
                schema_version
            )));
        }
        let revision = flux_core::CapabilityProfileRevision::new(revision)
            .ok_or_else(|| invalid_capability_profile("revision must be nonzero".to_owned()))?;

        let boot_identity = boot_identity.try_map(|value| {
            BootIdentity::parse(&value).map_err(|error| {
                invalid_capability_profile(format!("invalid boot identity: {error}"))
            })
        })?;
        let device_identity = device_identity
            .ok_or_else(|| {
                invalid_capability_profile(
                    "capability profile is missing device identity".to_owned(),
                )
            })?
            .try_map(DeviceIdentity::try_from)?;
        let WireKernelFacts {
            release,
            version,
            minimum,
            gate,
        } = kernel;
        let release = release.try_map(|value| {
            KernelRelease::new(value).map_err(|error| {
                invalid_capability_profile(format!("invalid kernel release: {error}"))
            })
        })?;
        let kernel = KernelFacts::from_release(release);
        if version != wire_kernel_version(kernel.version()) {
            return Err(invalid_capability_profile(
                "kernel release and parsed version observations disagree".to_owned(),
            ));
        }
        let minimum = KernelVersion::parse_release(&minimum).map_err(|error| {
            invalid_capability_profile(format!("invalid minimum kernel version: {error}"))
        })?;
        if minimum != MIN_SUPPORTED_KERNEL {
            return Err(invalid_capability_profile(format!(
                "minimum kernel {minimum} does not match {MIN_SUPPORTED_KERNEL}"
            )));
        }

        let selinux = selinux.try_map(|mode| Ok(mode.into()))?;
        let profile =
            CapabilityProfile::new(revision, boot_identity, device_identity, kernel, selinux);
        if gate != profile.mutation_gate().into() {
            return Err(invalid_capability_profile(
                "reported mutation gate disagrees with kernel and boot observations".to_owned(),
            ));
        }
        Ok(profile)
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireSubscriptionRefreshDisposition {
    Updated,
    UpdatedDeferred,
    Unchanged,
    Disabled,
    Busy,
}

impl From<SubscriptionRefreshDisposition> for WireSubscriptionRefreshDisposition {
    fn from(disposition: SubscriptionRefreshDisposition) -> Self {
        match disposition {
            SubscriptionRefreshDisposition::Updated => Self::Updated,
            SubscriptionRefreshDisposition::UpdatedDeferred => Self::UpdatedDeferred,
            SubscriptionRefreshDisposition::Unchanged => Self::Unchanged,
            SubscriptionRefreshDisposition::Disabled => Self::Disabled,
            SubscriptionRefreshDisposition::Busy => Self::Busy,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct WireDeviceIdentity {
    android_product: String,
    android_build: String,
    vendor_build: String,
    security_patch: String,
    verified_boot: WireVerifiedBootIdentity,
    kernel_build: String,
    selinux_policy: WireArtifactIdentity,
    netd: WireArtifactIdentity,
    connectivity: WireArtifactIdentity,
    tools: Vec<WireToolIdentity>,
    network_namespace: WireNetworkNamespaceIdentity,
}

impl From<&DeviceIdentity> for WireDeviceIdentity {
    fn from(identity: &DeviceIdentity) -> Self {
        Self {
            android_product: identity.android_product().as_str().to_owned(),
            android_build: identity.android_build().as_str().to_owned(),
            vendor_build: identity.vendor_build().as_str().to_owned(),
            security_patch: identity.security_patch().as_str().to_owned(),
            verified_boot: identity.verified_boot().into(),
            kernel_build: identity.kernel_build().as_str().to_owned(),
            selinux_policy: identity.selinux_policy().artifact().into(),
            netd: identity.netd().into(),
            connectivity: identity.connectivity().into(),
            tools: identity
                .tools()
                .iter()
                .map(|(id, artifact)| WireToolIdentity {
                    id: id.as_str().to_owned(),
                    artifact: (*artifact).into(),
                })
                .collect(),
            network_namespace: identity.network_namespace().into(),
        }
    }
}

impl TryFrom<WireDeviceIdentity> for DeviceIdentity {
    type Error = ControlError;

    fn try_from(identity: WireDeviceIdentity) -> Result<Self, Self::Error> {
        let tools = identity
            .tools
            .into_iter()
            .map(|tool| {
                Ok((
                    ToolId::new(&tool.id).map_err(|error| {
                        invalid_capability_profile(format!("invalid tool identity: {error}"))
                    })?,
                    tool.artifact.try_into()?,
                ))
            })
            .collect::<Result<Vec<_>, ControlError>>()?;
        DeviceIdentity::new(
            AndroidProductIdentity::new(&identity.android_product).map_err(|error| {
                invalid_capability_profile(format!("invalid Android product identity: {error}"))
            })?,
            AndroidBuildIdentity::new(&identity.android_build).map_err(|error| {
                invalid_capability_profile(format!("invalid Android build identity: {error}"))
            })?,
            VendorBuildIdentity::new(&identity.vendor_build).map_err(|error| {
                invalid_capability_profile(format!("invalid vendor build identity: {error}"))
            })?,
            SecurityPatchLevel::new(&identity.security_patch).map_err(|error| {
                invalid_capability_profile(format!("invalid security patch identity: {error}"))
            })?,
            identity.verified_boot.try_into()?,
            KernelBuildIdentity::new(&identity.kernel_build).map_err(|error| {
                invalid_capability_profile(format!("invalid kernel build identity: {error}"))
            })?,
            SelinuxPolicyIdentity::from(ArtifactIdentity::try_from(identity.selinux_policy)?),
            identity.netd.try_into()?,
            identity.connectivity.try_into()?,
            tools,
            identity.network_namespace.try_into()?,
        )
        .map_err(|error| invalid_capability_profile(format!("invalid device identity: {error}")))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireVerifiedBootState {
    Green,
    Yellow,
    Orange,
    Red,
}

impl From<VerifiedBootState> for WireVerifiedBootState {
    fn from(state: VerifiedBootState) -> Self {
        match state {
            VerifiedBootState::Green => Self::Green,
            VerifiedBootState::Yellow => Self::Yellow,
            VerifiedBootState::Orange => Self::Orange,
            VerifiedBootState::Red => Self::Red,
        }
    }
}

impl From<WireVerifiedBootState> for VerifiedBootState {
    fn from(state: WireVerifiedBootState) -> Self {
        match state {
            WireVerifiedBootState::Green => Self::Green,
            WireVerifiedBootState::Yellow => Self::Yellow,
            WireVerifiedBootState::Orange => Self::Orange,
            WireVerifiedBootState::Red => Self::Red,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct WireVerifiedBootIdentity {
    state: WireVerifiedBootState,
    device_locked: bool,
    vbmeta_sha256: String,
}

impl From<VerifiedBootIdentity> for WireVerifiedBootIdentity {
    fn from(identity: VerifiedBootIdentity) -> Self {
        Self {
            state: identity.state().into(),
            device_locked: identity.device_locked(),
            vbmeta_sha256: encode_digest(identity.vbmeta_digest()),
        }
    }
}

impl TryFrom<WireVerifiedBootIdentity> for VerifiedBootIdentity {
    type Error = ControlError;

    fn try_from(identity: WireVerifiedBootIdentity) -> Result<Self, Self::Error> {
        Ok(Self::new(
            identity.state.into(),
            identity.device_locked,
            decode_digest(&identity.vbmeta_sha256, "verified-boot vbmeta digest")?,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct WireArtifactIdentity {
    sha256: String,
    size: u64,
}

impl From<ArtifactIdentity> for WireArtifactIdentity {
    fn from(identity: ArtifactIdentity) -> Self {
        Self {
            sha256: encode_digest(identity.digest()),
            size: identity.size(),
        }
    }
}

impl TryFrom<WireArtifactIdentity> for ArtifactIdentity {
    type Error = ControlError;

    fn try_from(identity: WireArtifactIdentity) -> Result<Self, Self::Error> {
        ArtifactIdentity::new(
            decode_digest(&identity.sha256, "artifact digest")?,
            identity.size,
        )
        .map_err(|error| invalid_capability_profile(format!("invalid artifact identity: {error}")))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct WireToolIdentity {
    id: String,
    artifact: WireArtifactIdentity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct WireNetworkNamespaceIdentity {
    device: u64,
    inode: u64,
}

impl From<NetworkNamespaceIdentity> for WireNetworkNamespaceIdentity {
    fn from(identity: NetworkNamespaceIdentity) -> Self {
        Self {
            device: identity.device(),
            inode: identity.inode(),
        }
    }
}

impl TryFrom<WireNetworkNamespaceIdentity> for NetworkNamespaceIdentity {
    type Error = ControlError;

    fn try_from(identity: WireNetworkNamespaceIdentity) -> Result<Self, Self::Error> {
        Self::new(identity.device, identity.inode).ok_or_else(|| {
            invalid_capability_profile("network namespace inode must be nonzero".to_owned())
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct WireKernelFacts {
    release: WireObservation<String>,
    version: WireObservation<String>,
    minimum: String,
    gate: WireMutationGate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
enum WireObservation<T> {
    Verified(T),
    Absent,
    Denied,
    Malformed,
    Unavailable,
}

impl<T> WireObservation<T> {
    fn try_map<U, E>(self, map: impl FnOnce(T) -> Result<U, E>) -> Result<Observation<U>, E> {
        match self {
            Self::Verified(value) => map(value).map(Observation::Verified),
            Self::Absent => Ok(Observation::Absent),
            Self::Denied => Ok(Observation::Denied),
            Self::Malformed => Ok(Observation::Malformed),
            Self::Unavailable => Ok(Observation::Unavailable),
        }
    }
}

impl<T> From<Observation<T>> for WireObservation<T> {
    fn from(observation: Observation<T>) -> Self {
        match observation {
            Observation::Verified(value) => Self::Verified(value),
            Observation::Absent => Self::Absent,
            Observation::Denied => Self::Denied,
            Observation::Malformed => Self::Malformed,
            Observation::Unavailable => Self::Unavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireSelinuxMode {
    Enforcing,
    Permissive,
}

impl From<WireSelinuxMode> for SelinuxMode {
    fn from(mode: WireSelinuxMode) -> Self {
        match mode {
            WireSelinuxMode::Enforcing => Self::Enforcing,
            WireSelinuxMode::Permissive => Self::Permissive,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum WireMutationGate {
    Allowed,
    ReadOnly {
        kernel: WireKernelMutationStatus,
        boot_identity: WireBootIdentityMutationStatus,
    },
}

impl From<MutationGate> for WireMutationGate {
    fn from(gate: MutationGate) -> Self {
        match gate {
            MutationGate::Allowed => Self::Allowed,
            MutationGate::ReadOnly {
                kernel,
                boot_identity,
            } => Self::ReadOnly {
                kernel: kernel.into(),
                boot_identity: boot_identity.into(),
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum WireKernelMutationStatus {
    Eligible,
    Unsupported { found: String, minimum: String },
    Unverified,
}

impl From<KernelMutationStatus> for WireKernelMutationStatus {
    fn from(status: KernelMutationStatus) -> Self {
        match status {
            KernelMutationStatus::Eligible => Self::Eligible,
            KernelMutationStatus::Unsupported { found, minimum } => Self::Unsupported {
                found: found.to_string(),
                minimum: minimum.to_string(),
            },
            KernelMutationStatus::Unverified => Self::Unverified,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireBootIdentityMutationStatus {
    Verified,
    Unverified,
}

impl From<BootIdentityMutationStatus> for WireBootIdentityMutationStatus {
    fn from(status: BootIdentityMutationStatus) -> Self {
        match status {
            BootIdentityMutationStatus::Verified => Self::Verified,
            BootIdentityMutationStatus::Unverified => Self::Unverified,
        }
    }
}

fn wire_boot_identity(identity: &Observation<BootIdentity>) -> WireObservation<String> {
    wire_observation(identity, |identity| identity.as_str().to_owned())
}

fn wire_device_identity(
    identity: &Observation<DeviceIdentity>,
) -> WireObservation<WireDeviceIdentity> {
    wire_observation(identity, |identity| identity.into())
}

fn encode_digest(digest: Sha256Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest.as_bytes() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_digest(value: &str, field: &'static str) -> Result<Sha256Digest, ControlError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_capability_profile(format!(
            "{field} must be exactly 64 hexadecimal characters"
        )));
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| {
            invalid_capability_profile(format!("{field} contains invalid hexadecimal"))
        })?;
    }
    Sha256Digest::new(bytes)
        .map_err(|error| invalid_capability_profile(format!("invalid {field}: {error}")))
}

fn wire_kernel_release(release: &Observation<KernelRelease>) -> WireObservation<String> {
    wire_observation(release, |release| release.as_str().to_owned())
}

fn wire_kernel_version(version: &Observation<KernelVersion>) -> WireObservation<String> {
    wire_observation(version, ToString::to_string)
}

fn wire_selinux(mode: &Observation<SelinuxMode>) -> WireObservation<WireSelinuxMode> {
    wire_observation(mode, |mode| match mode {
        SelinuxMode::Enforcing => WireSelinuxMode::Enforcing,
        SelinuxMode::Permissive => WireSelinuxMode::Permissive,
    })
}

fn wire_observation<T, U>(
    observation: &Observation<T>,
    map: impl FnOnce(&T) -> U,
) -> WireObservation<U> {
    observation.map_ref(map).into()
}

fn invalid_capability_profile(message: String) -> ControlError {
    ControlError::protocol(format!("invalid daemon capability profile: {message}"))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum WireNativeAdmission {
    Admitted,
    Rejected {
        reason: WireNativeAdmissionRejection,
    },
}

impl From<NativeAdmissionState> for WireNativeAdmission {
    fn from(admission: NativeAdmissionState) -> Self {
        match admission {
            NativeAdmissionState::Admitted => Self::Admitted,
            NativeAdmissionState::Rejected(reason) => Self::Rejected {
                reason: reason.into(),
            },
        }
    }
}

impl From<WireNativeAdmission> for NativeAdmissionState {
    fn from(admission: WireNativeAdmission) -> Self {
        match admission {
            WireNativeAdmission::Admitted => Self::Admitted,
            WireNativeAdmission::Rejected { reason } => Self::Rejected(reason.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireNativeAdmissionRejection {
    UnsupportedKernel,
    UnverifiedKernel,
    UnverifiedBootIdentity,
    UnverifiedDeviceIdentity,
    AndroidVpnPolicyUnavailable,
    FunctionalCanaryUnavailable,
    NetworkInventoryUnavailable,
}

impl From<NativeAdmissionRejection> for WireNativeAdmissionRejection {
    fn from(reason: NativeAdmissionRejection) -> Self {
        match reason {
            NativeAdmissionRejection::UnsupportedKernel => Self::UnsupportedKernel,
            NativeAdmissionRejection::UnverifiedKernel => Self::UnverifiedKernel,
            NativeAdmissionRejection::UnverifiedBootIdentity => Self::UnverifiedBootIdentity,
            NativeAdmissionRejection::UnverifiedDeviceIdentity => Self::UnverifiedDeviceIdentity,
            NativeAdmissionRejection::AndroidVpnPolicyUnavailable => {
                Self::AndroidVpnPolicyUnavailable
            }
            NativeAdmissionRejection::FunctionalCanaryUnavailable => {
                Self::FunctionalCanaryUnavailable
            }
            NativeAdmissionRejection::NetworkInventoryUnavailable => {
                Self::NetworkInventoryUnavailable
            }
        }
    }
}

impl From<WireNativeAdmissionRejection> for NativeAdmissionRejection {
    fn from(reason: WireNativeAdmissionRejection) -> Self {
        match reason {
            WireNativeAdmissionRejection::UnsupportedKernel => Self::UnsupportedKernel,
            WireNativeAdmissionRejection::UnverifiedKernel => Self::UnverifiedKernel,
            WireNativeAdmissionRejection::UnverifiedBootIdentity => Self::UnverifiedBootIdentity,
            WireNativeAdmissionRejection::UnverifiedDeviceIdentity => {
                Self::UnverifiedDeviceIdentity
            }
            WireNativeAdmissionRejection::AndroidVpnPolicyUnavailable => {
                Self::AndroidVpnPolicyUnavailable
            }
            WireNativeAdmissionRejection::FunctionalCanaryUnavailable => {
                Self::FunctionalCanaryUnavailable
            }
            WireNativeAdmissionRejection::NetworkInventoryUnavailable => {
                Self::NetworkInventoryUnavailable
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

impl TryFrom<WireControlSnapshot> for ControlSnapshot {
    type Error = ControlError;

    fn try_from(snapshot: WireControlSnapshot) -> Result<Self, Self::Error> {
        Ok(Self {
            revision: snapshot.revision,
            administrative_state: snapshot.administrative_state.into(),
            configuration_dirty: snapshot.configuration_dirty,
            in_flight: snapshot.in_flight.map(Into::into),
            last_completed: snapshot
                .last_completed
                .map(Into::into)
                .map(validate_operation_report)
                .transpose()?,
        })
    }
}

#[derive(Default, Deserialize, Serialize)]
struct WireRuntimeSnapshot {
    revision: u64,
    phase: WireRuntimePhase,
    capture: WireRuntimeCaptureState,
    engine: WireRuntimeEngineState,
    verification: WireRuntimeVerificationState,
    generation: Option<u64>,
    last_error: Option<WireRuntimeFailure>,
}

impl From<&RuntimeSnapshot> for WireRuntimeSnapshot {
    fn from(snapshot: &RuntimeSnapshot) -> Self {
        Self {
            revision: snapshot.revision,
            phase: snapshot.phase.into(),
            capture: snapshot.capture.into(),
            engine: snapshot.engine.into(),
            verification: snapshot.verification.into(),
            generation: snapshot.generation,
            last_error: snapshot.last_error.as_ref().map(Into::into),
        }
    }
}

impl From<WireRuntimeSnapshot> for RuntimeSnapshot {
    fn from(snapshot: WireRuntimeSnapshot) -> Self {
        Self {
            revision: snapshot.revision,
            phase: snapshot.phase.into(),
            capture: snapshot.capture.into(),
            engine: snapshot.engine.into(),
            verification: snapshot.verification.into(),
            generation: snapshot.generation,
            last_error: snapshot.last_error.map(Into::into),
        }
    }
}

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireRuntimePhase {
    #[default]
    Unknown,
    Bootstrapping,
    Stopped,
    Preparing,
    Activating,
    Verifying,
    Running,
    Degraded,
    Repairing,
    Stopping,
    Failed,
}

impl From<RuntimePhase> for WireRuntimePhase {
    fn from(phase: RuntimePhase) -> Self {
        match phase {
            RuntimePhase::Unknown => Self::Unknown,
            RuntimePhase::Bootstrapping => Self::Bootstrapping,
            RuntimePhase::Stopped => Self::Stopped,
            RuntimePhase::Preparing => Self::Preparing,
            RuntimePhase::Activating => Self::Activating,
            RuntimePhase::Verifying => Self::Verifying,
            RuntimePhase::Running => Self::Running,
            RuntimePhase::Degraded => Self::Degraded,
            RuntimePhase::Repairing => Self::Repairing,
            RuntimePhase::Stopping => Self::Stopping,
            RuntimePhase::Failed => Self::Failed,
        }
    }
}

impl From<WireRuntimePhase> for RuntimePhase {
    fn from(phase: WireRuntimePhase) -> Self {
        match phase {
            WireRuntimePhase::Unknown => Self::Unknown,
            WireRuntimePhase::Bootstrapping => Self::Bootstrapping,
            WireRuntimePhase::Stopped => Self::Stopped,
            WireRuntimePhase::Preparing => Self::Preparing,
            WireRuntimePhase::Activating => Self::Activating,
            WireRuntimePhase::Verifying => Self::Verifying,
            WireRuntimePhase::Running => Self::Running,
            WireRuntimePhase::Degraded => Self::Degraded,
            WireRuntimePhase::Repairing => Self::Repairing,
            WireRuntimePhase::Stopping => Self::Stopping,
            WireRuntimePhase::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireRuntimeCaptureState {
    #[default]
    Unknown,
    Detached,
    Published,
}

impl From<RuntimeCaptureState> for WireRuntimeCaptureState {
    fn from(capture: RuntimeCaptureState) -> Self {
        match capture {
            RuntimeCaptureState::Unknown => Self::Unknown,
            RuntimeCaptureState::Detached => Self::Detached,
            RuntimeCaptureState::Published => Self::Published,
        }
    }
}

impl From<WireRuntimeCaptureState> for RuntimeCaptureState {
    fn from(capture: WireRuntimeCaptureState) -> Self {
        match capture {
            WireRuntimeCaptureState::Unknown => Self::Unknown,
            WireRuntimeCaptureState::Detached => Self::Detached,
            WireRuntimeCaptureState::Published => Self::Published,
        }
    }
}

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireRuntimeEngineState {
    #[default]
    Unknown,
    Stopped,
    Starting,
    Ready,
    Exited,
    BackingOff,
    Stopping,
    Failed,
}

impl From<RuntimeEngineState> for WireRuntimeEngineState {
    fn from(engine: RuntimeEngineState) -> Self {
        match engine {
            RuntimeEngineState::Unknown => Self::Unknown,
            RuntimeEngineState::Stopped => Self::Stopped,
            RuntimeEngineState::Starting => Self::Starting,
            RuntimeEngineState::Ready => Self::Ready,
            RuntimeEngineState::Exited => Self::Exited,
            RuntimeEngineState::BackingOff => Self::BackingOff,
            RuntimeEngineState::Stopping => Self::Stopping,
            RuntimeEngineState::Failed => Self::Failed,
        }
    }
}

impl From<WireRuntimeEngineState> for RuntimeEngineState {
    fn from(engine: WireRuntimeEngineState) -> Self {
        match engine {
            WireRuntimeEngineState::Unknown => Self::Unknown,
            WireRuntimeEngineState::Stopped => Self::Stopped,
            WireRuntimeEngineState::Starting => Self::Starting,
            WireRuntimeEngineState::Ready => Self::Ready,
            WireRuntimeEngineState::Exited => Self::Exited,
            WireRuntimeEngineState::BackingOff => Self::BackingOff,
            WireRuntimeEngineState::Stopping => Self::Stopping,
            WireRuntimeEngineState::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireRuntimeVerificationState {
    #[default]
    StructuralOnly,
    FunctionalPending,
    FunctionalPassed,
    FunctionalFailed,
}

impl From<RuntimeVerificationState> for WireRuntimeVerificationState {
    fn from(verification: RuntimeVerificationState) -> Self {
        match verification {
            RuntimeVerificationState::StructuralOnly => Self::StructuralOnly,
            RuntimeVerificationState::FunctionalPending => Self::FunctionalPending,
            RuntimeVerificationState::FunctionalPassed => Self::FunctionalPassed,
            RuntimeVerificationState::FunctionalFailed => Self::FunctionalFailed,
        }
    }
}

impl From<WireRuntimeVerificationState> for RuntimeVerificationState {
    fn from(verification: WireRuntimeVerificationState) -> Self {
        match verification {
            WireRuntimeVerificationState::StructuralOnly => Self::StructuralOnly,
            WireRuntimeVerificationState::FunctionalPending => Self::FunctionalPending,
            WireRuntimeVerificationState::FunctionalPassed => Self::FunctionalPassed,
            WireRuntimeVerificationState::FunctionalFailed => Self::FunctionalFailed,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct WireRuntimeFailure {
    operation: String,
    message: String,
    recovery: String,
}

impl From<&RuntimeFailure> for WireRuntimeFailure {
    fn from(failure: &RuntimeFailure) -> Self {
        Self {
            operation: failure.operation.clone(),
            message: failure.message.clone(),
            recovery: failure.recovery.clone(),
        }
    }
}

impl From<WireRuntimeFailure> for RuntimeFailure {
    fn from(failure: WireRuntimeFailure) -> Self {
        Self {
            operation: failure.operation,
            message: failure.message,
            recovery: failure.recovery,
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

impl From<RuntimeIntent> for WireIntent {
    fn from(intent: RuntimeIntent) -> Self {
        let (action, reason) = match intent {
            RuntimeIntent::Running { reason } => (WireAction::Start, reason),
            RuntimeIntent::Stopped { reason } => (WireAction::Stop, reason),
            RuntimeIntent::Reload { reason } => (WireAction::Reload, reason),
            RuntimeIntent::ResyncAddresses { reason } => (WireAction::Resync, reason),
        };
        Self {
            action,
            reason: reason.into(),
        }
    }
}

impl From<WireIntent> for RuntimeIntent {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    address_resync: Option<WireAddressResyncDisposition>,
}

impl From<OperationReport> for WireOperationReport {
    fn from(report: OperationReport) -> Self {
        Self {
            intent: report.intent.into(),
            revision: report.revision,
            address_resync: report.address_resync.map(Into::into),
        }
    }
}

impl From<WireOperationReport> for OperationReport {
    fn from(report: WireOperationReport) -> Self {
        Self {
            intent: report.intent.into(),
            revision: report.revision,
            address_resync: report.address_resync.map(Into::into),
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
    intent: RuntimeIntent,
) -> Result<Vec<u8>, ControlError> {
    let (action, reason) = match intent {
        RuntimeIntent::Running { reason } => (WireAction::Start, reason),
        RuntimeIntent::Stopped { reason } => (WireAction::Stop, reason),
        RuntimeIntent::Reload { reason } => (WireAction::Reload, reason),
        RuntimeIntent::ResyncAddresses { reason } => (WireAction::Resync, reason),
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

pub(crate) fn encode_subscription_update_request(request_id: u64) -> Result<Vec<u8>, ControlError> {
    encode_request(RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        command: WireCommand::SubscriptionUpdate,
    })
}

pub(crate) fn encode_diagnose_request(request_id: u64) -> Result<Vec<u8>, ControlError> {
    encode_request(RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        command: WireCommand::Diagnose,
    })
}

pub(crate) fn encode_logs_request(
    request_id: u64,
    stream: LogStream,
    lines: u16,
) -> Result<Vec<u8>, ControlError> {
    encode_request(RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        command: WireCommand::Logs { stream, lines },
    })
}

pub(crate) fn encode_explain_request(request_id: u64) -> Result<Vec<u8>, ControlError> {
    encode_request(RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        command: WireCommand::Explain,
    })
}

pub(crate) fn decode_control_response(
    packet: &[u8],
    expected_request_id: u64,
    intent: RuntimeIntent,
) -> Result<OperationReport, ControlError> {
    let response = decode_response(packet, expected_request_id)?;
    match response.result {
        WireResult::Ok {
            body:
                ResponseBody::Operation {
                    revision,
                    address_resync,
                },
        } => validate_operation_report(OperationReport {
            intent,
            revision,
            address_resync: address_resync.map(Into::into),
        }),
        WireResult::Ok { .. } => Err(unexpected_response("control")),
        WireResult::Error { code, message } => Err(rejected_response(code, message)),
    }
}

fn validate_operation_report(report: OperationReport) -> Result<OperationReport, ControlError> {
    let valid = matches!(
        (report.intent, report.address_resync),
        (RuntimeIntent::ResyncAddresses { .. }, Some(_))
            | (
                RuntimeIntent::Running { .. }
                    | RuntimeIntent::Stopped { .. }
                    | RuntimeIntent::Reload { .. },
                None
            )
    );
    if valid {
        Ok(report)
    } else {
        Err(ControlError::protocol(
            "operation resync disposition does not match its intent",
        ))
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
            body:
                ResponseBody::Snapshot {
                    capability_profile,
                    native_admission,
                    control,
                    runtime,
                },
        } => {
            let capability_profile: CapabilityProfile = (*capability_profile).try_into()?;
            Ok(DaemonSnapshot {
                capability_profile,
                native_admission: native_admission.into(),
                control: control.try_into()?,
                runtime: runtime.into(),
            })
        }
        WireResult::Ok { .. } => Err(unexpected_response("status")),
        WireResult::Error { code, message } => Err(rejected_response(code, message)),
    }
}

pub(crate) fn decode_subscription_update_response(
    packet: &[u8],
    expected_request_id: u64,
) -> Result<SubscriptionRefreshReport, ControlError> {
    let response = decode_response(packet, expected_request_id)?;
    match response.result {
        WireResult::Ok {
            body:
                ResponseBody::SubscriptionUpdate {
                    disposition,
                    generation,
                    node_count,
                    cleanup_pending,
                },
        } => {
            decode_subscription_refresh_report(disposition, generation, node_count, cleanup_pending)
        }
        WireResult::Ok { .. } => Err(unexpected_response("subscription update")),
        WireResult::Error { code, message } => Err(rejected_response(code, message)),
    }
}

pub(crate) fn decode_diagnose_response(
    packet: &[u8],
    expected_request_id: u64,
) -> Result<DiagnosticReport, ControlError> {
    let response = decode_response(packet, expected_request_id)?;
    match response.result {
        WireResult::Ok {
            body: ResponseBody::Diagnostics { report },
        } if report.validate() => Ok(report),
        WireResult::Ok {
            body: ResponseBody::Diagnostics { .. },
        } => Err(ControlError::protocol(
            "daemon returned an invalid diagnostic report".to_owned(),
        )),
        WireResult::Ok { .. } => Err(unexpected_response("diagnose")),
        WireResult::Error { code, message } => Err(rejected_response(code, message)),
    }
}

pub(crate) fn decode_logs_response(
    packet: &[u8],
    expected_request_id: u64,
    requested_stream: LogStream,
    requested_lines: u16,
) -> Result<LogReport, ControlError> {
    let response = decode_response(packet, expected_request_id)?;
    match response.result {
        WireResult::Ok {
            body: ResponseBody::Logs { report },
        } if report.stream() == requested_stream && report.validate(requested_lines) => Ok(report),
        WireResult::Ok {
            body: ResponseBody::Logs { .. },
        } => Err(ControlError::protocol(
            "daemon returned an invalid bounded log report".to_owned(),
        )),
        WireResult::Ok { .. } => Err(unexpected_response("logs")),
        WireResult::Error { code, message } => Err(rejected_response(code, message)),
    }
}

pub(crate) fn decode_explain_response(
    packet: &[u8],
    expected_request_id: u64,
) -> Result<ExplainReport, ControlError> {
    let response = decode_response(packet, expected_request_id)?;
    match response.result {
        WireResult::Ok {
            body: ResponseBody::Explain { report },
        } if report.validate() => Ok(report),
        WireResult::Ok {
            body: ResponseBody::Explain { .. },
        } => Err(ControlError::protocol(
            "daemon returned an invalid Desired State explanation".to_owned(),
        )),
        WireResult::Ok { .. } => Err(unexpected_response("explain")),
        WireResult::Error { code, message } => Err(rejected_response(code, message)),
    }
}

fn decode_subscription_refresh_report(
    disposition: WireSubscriptionRefreshDisposition,
    generation: Option<u64>,
    node_count: Option<u32>,
    cleanup_pending: bool,
) -> Result<SubscriptionRefreshReport, ControlError> {
    let invalid = || {
        ControlError::protocol(
            "daemon returned incoherent subscription update disposition metadata".to_owned(),
        )
    };
    match disposition {
        WireSubscriptionRefreshDisposition::Updated => Ok(SubscriptionRefreshReport::updated(
            generation
                .filter(|generation| *generation != 0)
                .ok_or_else(invalid)?,
            node_count
                .filter(|node_count| *node_count != 0)
                .ok_or_else(invalid)?,
            cleanup_pending,
        )),
        WireSubscriptionRefreshDisposition::UpdatedDeferred => {
            if generation.is_some() {
                return Err(invalid());
            }
            Ok(SubscriptionRefreshReport::updated_deferred(
                node_count
                    .filter(|node_count| *node_count != 0)
                    .ok_or_else(invalid)?,
                cleanup_pending,
            ))
        }
        WireSubscriptionRefreshDisposition::Unchanged => {
            if generation.is_some() {
                return Err(invalid());
            }
            Ok(SubscriptionRefreshReport::unchanged(
                node_count
                    .filter(|node_count| *node_count != 0)
                    .ok_or_else(invalid)?,
                cleanup_pending,
            ))
        }
        WireSubscriptionRefreshDisposition::Disabled => {
            if generation.is_some() || node_count.is_some() || cleanup_pending {
                return Err(invalid());
            }
            Ok(SubscriptionRefreshReport::disabled())
        }
        WireSubscriptionRefreshDisposition::Busy => {
            if generation.is_some() || node_count.is_some() || cleanup_pending {
                return Err(invalid());
            }
            Ok(SubscriptionRefreshReport::busy())
        }
    }
}

fn encode_request(request: RequestEnvelope) -> Result<Vec<u8>, ControlError> {
    serde_json::to_vec(&request)
        .map_err(|error| ControlError::protocol(format!("encode control request: {error}")))
}

fn decode_response(
    packet: &[u8],
    expected_request_id: u64,
) -> Result<ResponseEnvelope, ControlError> {
    let response = serde_json::from_slice::<ResponseEnvelope>(packet)
        .map_err(|error| ControlError::protocol(format!("decode control response: {error}")))?;
    if response.protocol_version != PROTOCOL_VERSION {
        return Err(ControlError::protocol(format!(
            "daemon protocol version {} does not match {PROTOCOL_VERSION}",
            response.protocol_version
        )));
    }
    if response.request_id != expected_request_id {
        return Err(ControlError::protocol(format!(
            "daemon response request ID {} does not match {expected_request_id}",
            response.request_id
        )));
    }
    Ok(response)
}

fn unexpected_response(request_kind: &str) -> ControlError {
    ControlError::protocol(format!(
        "daemon returned an unexpected body for a {request_kind} request"
    ))
}

fn rejected_response(code: String, message: String) -> ControlError {
    ControlError::request_rejected(code, message)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use flux_core::{
        CapabilityProfile, CapabilityProfileRevision, ConfigurationChangeClient,
        ConfigurationChangeReport, ControlClient, ControlSnapshotSource, OperationReport,
        RuntimeIntent,
    };
    use flux_testkit::CapabilityProfileFixture;

    use super::*;
    use crate::DiagnosticState;
    use crate::inspection::ProcessInspectionSource;
    use crate::subscription::{SubscriptionRefreshError, SubscriptionRefreshErrorKind};

    #[derive(Default)]
    struct TestControl;

    impl ControlClient for TestControl {
        fn submit_and_wait(&self, intent: RuntimeIntent) -> Result<OperationReport, ControlError> {
            Ok(OperationReport {
                intent,
                revision: 1,
                address_resync: matches!(intent, RuntimeIntent::ResyncAddresses { .. })
                    .then_some(AddressResyncDisposition::AcceptedDeferred),
            })
        }
    }

    impl ControlSnapshotSource for TestControl {
        fn snapshot(&self) -> Arc<ControlSnapshot> {
            Arc::new(ControlSnapshot::default())
        }
    }

    impl ConfigurationChangeClient for TestControl {
        fn configuration_changed(
            &self,
            _reason: Reason,
        ) -> Result<ConfigurationChangeReport, ControlError> {
            Ok(ConfigurationChangeReport::Deferred { revision: 1 })
        }
    }

    #[test]
    fn read_only_inspection_round_trips_bounded_reports_without_mutation_caching() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let run = directory.path().join("run");
        fs::create_dir(&run).expect("create run directory");
        fs::write(run.join("flux.log"), "one\ntwo\nthree\n").expect("write runtime log");
        let inspection = Arc::new(ProcessInspectionSource::new(
            directory.path().join("flux.toml"),
            run.join("flux.log"),
            run.join("fluxd.log"),
            run.join("sing-box.log"),
        ));
        let handler = ProtocolHandler::with_runtime_subscription_and_inspection(
            Arc::new(CapabilityProfileFixture::supported()),
            NativeAdmissionState::Admitted,
            TestControl,
            RuntimeSnapshotSource::default(),
            None,
            Some(inspection.clone()),
        );

        let request = encode_logs_request(91, LogStream::Runtime, 2).expect("log request");
        assert_eq!(
            String::from_utf8(request.clone()).expect("UTF-8 request"),
            "{\"protocol_version\":5,\"request_id\":91,\"command\":{\"kind\":\"logs\",\"stream\":\"runtime\",\"lines\":2}}"
        );
        let first = handler.handle_for_peer(&request, RequestPeerId::new(Uid::ROOT, 72));
        let report = decode_logs_response(&first, 91, LogStream::Runtime, 2).expect("log report");
        assert_eq!(report.content(), "two\nthree\n");
        assert_eq!(report.line_count(), 2);

        fs::write(run.join("flux.log"), "changed\n").expect("replace runtime log");
        let second = handler.handle_for_peer(&request, RequestPeerId::new(Uid::ROOT, 72));
        let report =
            decode_logs_response(&second, 91, LogStream::Runtime, 2).expect("fresh log report");
        assert_eq!(report.content(), "changed\n");
        assert_ne!(
            second, first,
            "read-only requests must not use mutation deduplication"
        );

        let request = encode_diagnose_request(92).expect("diagnostic request");
        let response = handler.handle(&request);
        let diagnostics = decode_diagnose_response(&response, 92).expect("diagnostic report");
        assert_eq!(
            diagnostics.desired_state().state(),
            DiagnosticState::Missing
        );
        assert_eq!(diagnostics.runtime_log().state(), DiagnosticState::Ready);

        let request = encode_logs_request(93, LogStream::Runtime, 0).expect("invalid log request");
        let response = handler.handle(&request);
        let error = decode_logs_response(&response, 93, LogStream::Runtime, 0)
            .expect_err("zero-line request must fail");
        assert_eq!(error.rejection_code(), Some("inspection_invalid_request"));

        let template_path = directory.path().join("template.json");
        fs::write(
            &template_path,
            include_bytes!("../../../conf/template.json"),
        )
        .expect("write engine template");
        let config = include_str!("../../../conf/flux.toml").replace(
            "/data/adb/flux/conf/template.json",
            template_path.to_str().expect("UTF-8 template path"),
        );
        fs::write(directory.path().join("flux.toml"), config).expect("write Desired State");
        let request = encode_explain_request(94).expect("explain request");
        let response = handler.handle(&request);
        let explanation = decode_explain_response(&response, 94).expect("explain report");
        assert!(explanation.non_authorizing());
        assert_eq!(explanation.backend(), "xtables");

        let read_only_handler = ProtocolHandler::with_runtime_subscription_and_inspection(
            Arc::new(CapabilityProfileFixture::unsupported_kernel()),
            NativeAdmissionState::Rejected(NativeAdmissionRejection::UnsupportedKernel),
            TestControl,
            RuntimeSnapshotSource::default(),
            None,
            Some(inspection),
        );
        let request =
            encode_logs_request(95, LogStream::Runtime, 1).expect("read-only log request");
        let response = read_only_handler.handle(&request);
        let report = decode_logs_response(&response, 95, LogStream::Runtime, 1)
            .expect("inspection remains available under a read-only capability profile");
        assert_eq!(report.content(), "changed\n");
    }

    #[test]
    fn subscription_update_round_trips_one_typed_mutating_response() {
        let calls = Arc::new(AtomicUsize::new(0));
        let refresh_calls = Arc::clone(&calls);
        let subscription = SubscriptionRefreshClient::for_test(move || {
            refresh_calls.fetch_add(1, Ordering::SeqCst);
            Ok(SubscriptionRefreshReport::updated(71, 23, true))
        });
        let handler = ProtocolHandler::with_runtime_snapshot_and_subscription(
            Arc::new(CapabilityProfileFixture::supported()),
            NativeAdmissionState::Admitted,
            TestControl,
            RuntimeSnapshotSource::default(),
            Some(subscription),
        );
        let request = encode_subscription_update_request(101).expect("subscription request");

        let response = handler.handle_for_peer(&request, RequestPeerId::new(Uid::ROOT, 44));
        let report =
            decode_subscription_update_response(&response, 101).expect("subscription response");

        assert_eq!(
            String::from_utf8(response).expect("UTF-8 response"),
            concat!(
                "{\"protocol_version\":5,\"request_id\":101,",
                "\"result\":{\"status\":\"ok\",\"body\":{",
                "\"kind\":\"subscription_update\",\"disposition\":\"updated\",",
                "\"generation\":71,\"node_count\":23,\"cleanup_pending\":true}}}\n"
            )
        );
        assert_eq!(report, SubscriptionRefreshReport::updated(71, 23, true));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn subscription_update_uses_mutation_gate_and_recent_request_deduplication() {
        let gated_calls = Arc::new(AtomicUsize::new(0));
        let refresh_calls = Arc::clone(&gated_calls);
        let subscription = SubscriptionRefreshClient::for_test(move || {
            refresh_calls.fetch_add(1, Ordering::SeqCst);
            Ok(SubscriptionRefreshReport::disabled())
        });
        let gated = ProtocolHandler::with_runtime_snapshot_and_subscription(
            Arc::new(CapabilityProfileFixture::unsupported_kernel()),
            NativeAdmissionState::Rejected(NativeAdmissionRejection::UnsupportedKernel),
            TestControl,
            RuntimeSnapshotSource::default(),
            Some(subscription),
        );
        let request = encode_subscription_update_request(102).expect("subscription request");

        let response = gated.handle_for_peer(&request, RequestPeerId::new(Uid::ROOT, 45));

        assert_eq!(
            String::from_utf8(response).expect("UTF-8 response"),
            concat!(
                "{\"protocol_version\":5,\"request_id\":102,",
                "\"result\":{\"status\":\"error\",\"code\":\"unsupported_kernel\",",
                "\"message\":\"kernel 5.4.280 is below minimum 5.10.0\"}}\n"
            )
        );
        assert_eq!(gated_calls.load(Ordering::SeqCst), 0);

        let calls = Arc::new(AtomicUsize::new(0));
        let refresh_calls = Arc::clone(&calls);
        let subscription = SubscriptionRefreshClient::for_test(move || {
            refresh_calls.fetch_add(1, Ordering::SeqCst);
            Ok(SubscriptionRefreshReport::unchanged(17, false))
        });
        let handler = ProtocolHandler::with_runtime_snapshot_and_subscription(
            Arc::new(CapabilityProfileFixture::supported()),
            NativeAdmissionState::Admitted,
            TestControl,
            RuntimeSnapshotSource::default(),
            Some(subscription),
        );
        let peer = RequestPeerId::new(Uid::ROOT, 46);
        let request = encode_subscription_update_request(103).expect("subscription request");

        let first = handler.handle_for_peer(&request, peer);
        let duplicate = handler.handle_for_peer(&request, peer);

        assert_eq!(duplicate, first);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn subscription_update_errors_have_stable_codes_and_incoherent_reports_fail_closed() {
        let expected_codes = [
            (
                SubscriptionRefreshErrorKind::Configuration,
                "subscription_configuration_failed",
            ),
            (
                SubscriptionRefreshErrorKind::UnsupportedIdentity,
                "subscription_identity_unsupported",
            ),
            (
                SubscriptionRefreshErrorKind::Source,
                "subscription_source_failed",
            ),
            (
                SubscriptionRefreshErrorKind::Preparation,
                "subscription_preparation_failed",
            ),
            (
                SubscriptionRefreshErrorKind::Store,
                "subscription_store_failed",
            ),
            (
                SubscriptionRefreshErrorKind::SourceChanged,
                "subscription_source_changed",
            ),
            (
                SubscriptionRefreshErrorKind::WorkerUnavailable,
                "subscription_worker_unavailable",
            ),
            (
                SubscriptionRefreshErrorKind::Activation,
                "subscription_activation_failed",
            ),
            (
                SubscriptionRefreshErrorKind::Rollback,
                "subscription_rollback_failed",
            ),
        ];
        for (kind, expected) in expected_codes {
            assert_eq!(kind.rejection_code(), expected);
        }

        let subscription = SubscriptionRefreshClient::for_test(|| {
            Err(SubscriptionRefreshError::activation(
                "candidate activation failed",
            ))
        });
        let handler = ProtocolHandler::with_runtime_snapshot_and_subscription(
            Arc::new(CapabilityProfileFixture::supported()),
            NativeAdmissionState::Admitted,
            TestControl,
            RuntimeSnapshotSource::default(),
            Some(subscription),
        );
        let request = encode_subscription_update_request(104).expect("subscription request");
        let response = handler.handle(&request);
        let error = decode_subscription_update_response(&response, 104)
            .expect_err("activation failure must be rejected");
        assert_eq!(
            error.rejection_code(),
            Some("subscription_activation_failed")
        );

        let incoherent = encode_response(ResponseEnvelope::ok(
            105,
            ResponseBody::SubscriptionUpdate {
                disposition: WireSubscriptionRefreshDisposition::Updated,
                generation: None,
                node_count: Some(9),
                cleanup_pending: false,
            },
        ));
        let error = decode_subscription_update_response(&incoherent, 105)
            .expect_err("missing Generation must fail closed");
        assert_eq!(
            error.to_string(),
            "control protocol: daemon returned incoherent subscription update disposition metadata"
        );
    }

    #[test]
    fn status_decoder_preserves_a_nonzero_profile_revision() {
        let initial = CapabilityProfileFixture::supported();
        let revision = CapabilityProfileRevision::new(47).expect("nonzero revision");
        let profile = CapabilityProfile::new(
            revision,
            initial.boot_identity().clone(),
            initial.device_identity().clone(),
            initial.kernel().clone(),
            initial.selinux().clone(),
        );
        let response = encode_response(ResponseEnvelope::ok(
            92,
            ResponseBody::Snapshot {
                capability_profile: Box::new((&profile).into()),
                native_admission: NativeAdmissionState::Admitted.into(),
                control: (&ControlSnapshot::default()).into(),
                runtime: WireRuntimeSnapshot::default(),
            },
        ));

        let snapshot = decode_status_response(&response, 92).expect("coherent status");

        assert_eq!(snapshot.capability_profile.revision(), revision);
    }

    #[test]
    fn status_decoder_round_trips_the_exact_device_identity() {
        let profile = CapabilityProfileFixture::device_qualified();
        let response = encode_response(ResponseEnvelope::ok(
            94,
            ResponseBody::Snapshot {
                capability_profile: Box::new((&profile).into()),
                native_admission: NativeAdmissionState::Admitted.into(),
                control: (&ControlSnapshot::default()).into(),
                runtime: WireRuntimeSnapshot::default(),
            },
        ));

        let document: serde_json::Value =
            serde_json::from_slice(&response).expect("encoded status JSON");
        assert_eq!(
            document.pointer("/result/body/capability_profile/device_identity"),
            Some(&serde_json::json!({
                "status": "verified",
                "value": {
                    "android_product": "google/redfin/redfin",
                    "android_build": "google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys",
                    "vendor_build": "google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys",
                    "security_patch": "2023-08-05",
                    "verified_boot": {
                        "state": "green",
                        "device_locked": true,
                        "vbmeta_sha256": "1111111111111111111111111111111111111111111111111111111111111111"
                    },
                    "kernel_build": "5.10.198-android13-gki fixture-build",
                    "selinux_policy": {
                        "sha256": "2121212121212121212121212121212121212121212121212121212121212121",
                        "size": 4096
                    },
                    "netd": {
                        "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
                        "size": 8192
                    },
                    "connectivity": {
                        "sha256": "2323232323232323232323232323232323232323232323232323232323232323",
                        "size": 16384
                    },
                    "tools": [{
                        "id": "fluxd",
                        "artifact": {
                            "sha256": "2424242424242424242424242424242424242424242424242424242424242424",
                            "size": 32768
                        }
                    }],
                    "network_namespace": { "device": 10, "inode": 20 }
                }
            }))
        );

        let snapshot = decode_status_response(&response, 94).expect("coherent exact identity");

        assert_eq!(snapshot.capability_profile, profile);
    }

    #[test]
    fn status_decoder_rejects_an_unsupported_capability_profile_schema() {
        let profile = CapabilityProfileFixture::supported();
        let response = encode_response(ResponseEnvelope::ok(
            96,
            ResponseBody::Snapshot {
                capability_profile: Box::new((&profile).into()),
                native_admission: NativeAdmissionState::Admitted.into(),
                control: (&ControlSnapshot::default()).into(),
                runtime: WireRuntimeSnapshot::default(),
            },
        ));
        let mut document: serde_json::Value =
            serde_json::from_slice(&response).expect("encoded status JSON");
        let capability_profile = document
            .pointer_mut("/result/body/capability_profile")
            .and_then(serde_json::Value::as_object_mut)
            .expect("capability profile object");
        capability_profile.insert("schema_version".to_owned(), serde_json::json!(1));
        capability_profile.remove("device_identity");
        let response = serde_json::to_vec(&document).expect("schema-1 status JSON");

        let error = decode_status_response(&response, 96).expect_err("schema 1 is unsupported");

        assert_eq!(
            error.to_string(),
            "control protocol: invalid daemon capability profile: schema version 1 is unsupported; expected 3"
        );
    }

    #[test]
    fn status_decoder_preserves_the_observed_runtime_snapshot() {
        let profile = CapabilityProfileFixture::supported();
        let runtime = RuntimeSnapshot {
            revision: 14,
            phase: RuntimePhase::Repairing,
            capture: RuntimeCaptureState::Detached,
            engine: RuntimeEngineState::BackingOff,
            verification: RuntimeVerificationState::FunctionalFailed,
            generation: Some(48),
            last_error: Some(RuntimeFailure {
                operation: "maintain proxy engine".to_owned(),
                message: "owned child exited unexpectedly".to_owned(),
                recovery: "retry after bounded backoff".to_owned(),
            }),
        };
        let response = encode_response(ResponseEnvelope::ok(
            93,
            ResponseBody::Snapshot {
                capability_profile: Box::new((&profile).into()),
                native_admission: NativeAdmissionState::Admitted.into(),
                control: (&ControlSnapshot::default()).into(),
                runtime: (&runtime).into(),
            },
        ));

        let snapshot = decode_status_response(&response, 93).expect("coherent status");

        assert_eq!(snapshot.runtime, runtime);
    }

    #[test]
    fn status_requires_runtime_verification() {
        let profile = CapabilityProfileFixture::supported();
        let response = encode_response(ResponseEnvelope::ok(
            94,
            ResponseBody::Snapshot {
                capability_profile: Box::new((&profile).into()),
                native_admission: NativeAdmissionState::Admitted.into(),
                control: (&ControlSnapshot::default()).into(),
                runtime: WireRuntimeSnapshot::default(),
            },
        ));
        let mut document: serde_json::Value =
            serde_json::from_slice(&response).expect("encoded response document");
        document["result"]["body"]["runtime"]
            .as_object_mut()
            .expect("runtime object")
            .remove("verification");
        let response = serde_json::to_vec(&document).expect("response without verification");

        let error = decode_status_response(&response, 94)
            .expect_err("version-three runtime verification is required");

        assert!(
            error.to_string().contains("missing field `verification`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn status_decoder_preserves_every_runtime_verification_state() {
        let profile = CapabilityProfileFixture::supported();
        for verification in [
            RuntimeVerificationState::StructuralOnly,
            RuntimeVerificationState::FunctionalPending,
            RuntimeVerificationState::FunctionalPassed,
            RuntimeVerificationState::FunctionalFailed,
        ] {
            let runtime = RuntimeSnapshot {
                verification,
                ..RuntimeSnapshot::unknown()
            };
            let response = encode_response(ResponseEnvelope::ok(
                95,
                ResponseBody::Snapshot {
                    capability_profile: Box::new((&profile).into()),
                    native_admission: NativeAdmissionState::Admitted.into(),
                    control: (&ControlSnapshot::default()).into(),
                    runtime: (&runtime).into(),
                },
            ));

            let snapshot = decode_status_response(&response, 95).expect("coherent status");

            assert_eq!(snapshot.runtime.verification, verification);
        }
    }
}
