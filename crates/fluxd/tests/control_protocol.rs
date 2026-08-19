use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use flux_core::{
    AdministrativeState, CapabilityProfile, ConfigurationChangeClient, ConfigurationChangeReport,
    ControlClient, ControlError, ControlSnapshot, ControlSnapshotSource, KernelFacts, Observation,
    OperationReport, Reason, RuntimeIntent,
};
use flux_platform::Uid;
use flux_testkit::CapabilityProfileFixture;
use fluxd::{
    MAX_CONTROL_PACKET_BYTES, NativeAdmissionRejection, NativeAdmissionState, ProtocolHandler,
    RequestPeerId, RuntimeCaptureState, RuntimeEngineState, RuntimeFailure,
    RuntimeGenerationBinding, RuntimePhase, RuntimeSnapshot, RuntimeSnapshotSource,
    RuntimeVerificationState,
};

mod support;

const ADMITTED: NativeAdmissionState = NativeAdmissionState::Admitted;

fn uid(raw: u32) -> Uid {
    Uid::from_raw(raw).expect("valid test UID")
}

fn supported_profile() -> Arc<flux_core::CapabilityProfile> {
    Arc::new(CapabilityProfileFixture::supported())
}

fn unverified_kernel_profile() -> CapabilityProfile {
    let supported = CapabilityProfileFixture::supported();
    CapabilityProfile::initial(
        supported.boot_identity().clone(),
        supported.device_identity().clone(),
        KernelFacts::from_release(Observation::Unavailable),
        supported.selinux().clone(),
    )
}

#[test]
fn ping_has_a_stable_versioned_json_contract() {
    let handler = ProtocolHandler::new(supported_profile(), ADMITTED, RecordingClient::default());

    let response =
        handler.handle(br#"{"protocol_version":8,"request_id":7,"command":{"kind":"ping"}}"#);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":8,\"request_id\":7,",
            "\"result\":{\"status\":\"ok\",\"body\":{\"kind\":\"pong\"}}}\n"
        )
    );
}

#[test]
fn older_protocol_requests_are_explicitly_rejected() {
    let handler = ProtocolHandler::new(supported_profile(), ADMITTED, RecordingClient::default());

    for version in [1, 2, 3, 4, 5, 6, 7] {
        let request = format!(
            "{{\"protocol_version\":{version},\"request_id\":6,\"command\":{{\"kind\":\"ping\"}}}}"
        );
        let response = handler.handle(request.as_bytes());

        assert_eq!(
            String::from_utf8(response).expect("UTF-8 response"),
            format!(
                "{{\"protocol_version\":8,\"request_id\":6,\"result\":{{\"status\":\"error\",\"code\":\"unsupported_protocol\",\"message\":\"protocol version {version} is unsupported; expected 8\"}}}}\n"
            )
        );
    }
}

#[test]
fn status_returns_one_coherent_capability_profile_and_control_snapshot() {
    let runtime = RuntimeSnapshotSource::default();
    runtime.publish(RuntimeSnapshot {
        revision: 12,
        phase: RuntimePhase::Repairing,
        capture: RuntimeCaptureState::Detached,
        engine: RuntimeEngineState::BackingOff,
        verification: RuntimeVerificationState::FunctionalFailed,
        active_generation: Some(RuntimeGenerationBinding::new(
            flux_core::GenerationId::new(74).expect("nonzero Generation"),
            support::xtables_capture_path_selection(),
        )),
        latest_capture_path_decision: Some(support::xtables_capture_path_decision()),
        last_error: Some(RuntimeFailure {
            operation: "maintain proxy engine".to_owned(),
            message: "owned child exited unexpectedly".to_owned(),
            recovery: "retry after bounded backoff".to_owned(),
        }),
    });
    let handler = ProtocolHandler::with_runtime_snapshot_source(
        supported_profile(),
        ADMITTED,
        RecordingClient::with_snapshot(ControlSnapshot {
            revision: 73,
            administrative_state: AdministrativeState::Running,
            configuration_dirty: false,
            in_flight: None,
            last_completed: Some(OperationReport {
                intent: RuntimeIntent::Reload {
                    reason: Reason::Automation,
                },
                revision: 73,
                address_resync: None,
            }),
        }),
        runtime,
    );

    let response =
        handler.handle(br#"{"protocol_version":8,"request_id":8,"command":{"kind":"status"}}"#);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":8,\"request_id\":8,",
            "\"result\":{\"status\":\"ok\",\"body\":{\"kind\":\"snapshot\",",
            "\"capability_profile\":{\"schema_version\":3,\"revision\":1,",
            "\"boot_identity\":{\"status\":\"verified\",",
            "\"value\":\"01234567-89ab-cdef-0123-456789abcdef\"},",
            "\"device_identity\":{\"status\":\"unavailable\"},",
            "\"kernel\":{\"release\":{\"status\":\"verified\",",
            "\"value\":\"5.10.198-android12-9-gki\"},",
            "\"version\":{\"status\":\"verified\",\"value\":\"5.10.198\"},",
            "\"minimum\":\"5.10.0\",\"gate\":{\"status\":\"allowed\"}},",
            "\"selinux\":{\"status\":\"verified\",\"value\":\"enforcing\"}},",
            "\"native_admission\":{\"state\":\"admitted\"},",
            "\"control\":{\"revision\":73,\"administrative_state\":\"running\",",
            "\"configuration_dirty\":false,",
            "\"in_flight\":null,\"last_completed\":{",
            "\"intent\":{\"action\":\"reload\",\"reason\":\"automation\"},",
            "\"revision\":73}},",
            "\"runtime\":{\"revision\":1,\"phase\":\"repairing\",",
            "\"capture\":\"detached\",",
            "\"engine\":\"backing_off\",",
            "\"verification\":\"functional_failed\",\"active_generation\":{",
            "\"generation\":74,",
            "\"capture_path_selection\":{\"request\":\"auto\",",
            "\"selected\":\"xtables_tproxy\",",
            "\"reason\":\"automatic_highest_ranked_qualified\",",
            "\"candidates\":[{\"path\":\"ebpf\",",
            "\"state\":\"unimplemented\",\"qualification_state\":\"unqualified\",",
            "\"first_kernel_gap\":null},",
            "{\"path\":\"nftables_tproxy\",",
            "\"state\":\"unimplemented\",\"qualification_state\":\"unqualified\",",
            "\"first_kernel_gap\":null},",
            "{\"path\":\"xtables_tproxy\",\"state\":\"qualified\",",
            "\"qualification_state\":\"qualified\",\"first_kernel_gap\":null},",
            "{\"path\":\"managed_tun\",\"state\":\"unimplemented\",",
            "\"qualification_state\":\"unqualified\",\"first_kernel_gap\":null}],",
            "\"evidence_digest\":",
            "\"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\"}},",
            "\"latest_capture_path_decision\":{\"outcome\":\"selected\",",
            "\"selection\":{\"request\":\"auto\",",
            "\"selected\":\"xtables_tproxy\",",
            "\"reason\":\"automatic_highest_ranked_qualified\",",
            "\"candidates\":[{\"path\":\"ebpf\",",
            "\"state\":\"unimplemented\",\"qualification_state\":\"unqualified\",",
            "\"first_kernel_gap\":null},",
            "{\"path\":\"nftables_tproxy\",",
            "\"state\":\"unimplemented\",\"qualification_state\":\"unqualified\",",
            "\"first_kernel_gap\":null},",
            "{\"path\":\"xtables_tproxy\",\"state\":\"qualified\",",
            "\"qualification_state\":\"qualified\",\"first_kernel_gap\":null},",
            "{\"path\":\"managed_tun\",\"state\":\"unimplemented\",",
            "\"qualification_state\":\"unqualified\",\"first_kernel_gap\":null}],",
            "\"evidence_digest\":",
            "\"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\"}},",
            "\"last_error\":{\"operation\":\"maintain proxy engine\",",
            "\"message\":\"owned child exited unexpectedly\",",
            "\"recovery\":\"retry after bounded backoff\"}}}}}\n"
        )
    );
}

#[test]
fn retried_mutation_with_the_same_peer_and_request_id_is_applied_once() {
    let handler = ProtocolHandler::new(supported_profile(), ADMITTED, RecordingClient::default());
    let peer = RequestPeerId::new(uid(1000), 42);
    let packet = br#"{"protocol_version":8,"request_id":21,"command":{"kind":"control","action":"start","reason":"user_control"}}"#;

    let first = handler.handle_for_peer(packet, peer);
    let retry = handler.handle_for_peer(packet, peer);

    assert_eq!(retry, first);
    assert_eq!(
        handler.control().intents(),
        vec![RuntimeIntent::Running {
            reason: Reason::UserControl,
        }]
    );
}

#[test]
fn resync_disposition_round_trips_through_control_status_and_duplicate_caching() {
    let control = RecordingClient::with_snapshot(ControlSnapshot {
        revision: 80,
        administrative_state: AdministrativeState::Running,
        configuration_dirty: false,
        in_flight: None,
        last_completed: Some(OperationReport {
            intent: RuntimeIntent::ResyncAddresses {
                reason: Reason::UserControl,
            },
            revision: 80,
            address_resync: Some(flux_core::AddressResyncDisposition::CompleteNoChange),
        }),
    });
    let handler = ProtocolHandler::new(supported_profile(), ADMITTED, control);
    let peer = RequestPeerId::new(uid(1000), 142);
    let packet = br#"{"protocol_version":8,"request_id":121,"command":{"kind":"control","action":"resync","reason":"user_control"}}"#;

    let first = handler.handle_for_peer(packet, peer);
    let duplicate = handler.handle_for_peer(packet, peer);
    assert_eq!(duplicate, first);
    assert_eq!(
        String::from_utf8(first).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":8,\"request_id\":121,",
            "\"result\":{\"status\":\"ok\",\"body\":{\"kind\":\"operation\",",
            "\"revision\":73,\"address_resync\":\"accepted_deferred\"}}}\n"
        )
    );
    assert_eq!(
        handler.control().intents(),
        vec![RuntimeIntent::ResyncAddresses {
            reason: Reason::UserControl,
        }]
    );

    let status =
        handler.handle(br#"{"protocol_version":8,"request_id":122,"command":{"kind":"status"}}"#);
    let status: serde_json::Value = serde_json::from_slice(&status).expect("status JSON");
    assert_eq!(
        status.pointer("/result/body/control/last_completed/address_resync"),
        Some(&serde_json::Value::String("complete_no_change".to_owned()))
    );
}

#[test]
fn concurrent_retry_waits_for_the_original_mutation_result() {
    let handler = Arc::new(ProtocolHandler::new(
        supported_profile(),
        ADMITTED,
        BlockingClient::new(),
    ));
    let peer = RequestPeerId::new(uid(1000), 43);
    let packet = br#"{"protocol_version":8,"request_id":23,"command":{"kind":"control","action":"start","reason":"user_control"}}"#;

    let original_handler = Arc::clone(&handler);
    let original = thread::spawn(move || original_handler.handle_for_peer(packet, peer));
    handler.control().wait_for_first_call();

    let (retry_started_tx, retry_started_rx) = mpsc::sync_channel(1);
    let (retry_finished_tx, retry_finished_rx) = mpsc::sync_channel(1);
    let retry_handler = Arc::clone(&handler);
    let retry = thread::spawn(move || {
        retry_started_tx.send(()).expect("report retry start");
        let response = retry_handler.handle_for_peer(packet, peer);
        retry_finished_tx
            .send(response.clone())
            .expect("report retry completion");
        response
    });
    retry_started_rx.recv().expect("retry started");

    let retry_before_release = retry_finished_rx.recv_timeout(Duration::from_millis(250));
    let calls_before_release = handler.control().call_count();
    handler.control().release_first_call();
    let original_response = original.join().expect("original request thread");
    let retry_response = retry.join().expect("retry request thread");

    assert!(matches!(
        retry_before_release,
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert_eq!(calls_before_release, 1);
    assert_eq!(retry_response, original_response);
    assert_eq!(handler.control().call_count(), 1);
}

#[test]
fn semantically_equal_mutation_with_different_packet_bytes_conflicts() {
    let handler = ProtocolHandler::new(supported_profile(), ADMITTED, RecordingClient::default());
    let peer = RequestPeerId::new(uid(1000), 44);
    let compact = br#"{"protocol_version":8,"request_id":24,"command":{"kind":"control","action":"start","reason":"user_control"}}"#;
    let spaced = br#"{ "protocol_version": 8, "request_id": 24, "command": { "kind": "control", "action": "start", "reason": "user_control" } }"#;

    let _ = handler.handle_for_peer(compact, peer);
    let response = handler.handle_for_peer(spaced, peer);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":8,\"request_id\":24,",
            "\"result\":{\"status\":\"error\",\"code\":\"request_id_conflict\",",
            "\"message\":\"request ID was already used for a different mutation\"}}\n"
        )
    );
    assert_eq!(handler.control().intents().len(), 1);
}

#[test]
fn request_ids_are_scoped_to_the_authenticated_peer() {
    let handler = ProtocolHandler::new(supported_profile(), ADMITTED, RecordingClient::default());
    let packet = br#"{"protocol_version":8,"request_id":25,"command":{"kind":"control","action":"start","reason":"user_control"}}"#;

    let _ = handler.handle_for_peer(packet, RequestPeerId::new(uid(1000), 45));
    let _ = handler.handle_for_peer(packet, RequestPeerId::new(uid(1000), 46));

    assert_eq!(handler.control().intents().len(), 2);
}

#[test]
fn oversized_mutation_result_is_replaced_by_a_bounded_protocol_error() {
    let handler = ProtocolHandler::new(
        supported_profile(),
        ADMITTED,
        ErrorClient::new(MAX_CONTROL_PACKET_BYTES),
    );
    let peer = RequestPeerId::new(uid(1000), 47);
    let packet = br#"{"protocol_version":8,"request_id":26,"command":{"kind":"control","action":"start","reason":"user_control"}}"#;

    let response = handler.handle_for_peer(packet, peer);
    let retry = handler.handle_for_peer(packet, peer);

    assert!(response.len() <= MAX_CONTROL_PACKET_BYTES);
    assert_eq!(
        String::from_utf8(response.clone()).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":8,\"request_id\":26,",
            "\"result\":{\"status\":\"error\",\"code\":\"response_too_large\",",
            "\"message\":\"control response exceeds 1048576 bytes\"}}\n"
        )
    );
    assert_eq!(retry, response);
    assert_eq!(handler.control().call_count(), 1);
}

#[test]
fn completed_result_cache_evicts_entries_to_bound_retained_response_bytes() {
    let handler = ProtocolHandler::new(
        supported_profile(),
        ADMITTED,
        ErrorClient::new(MAX_CONTROL_PACKET_BYTES / 2 + 1024),
    );
    let peer = RequestPeerId::new(uid(1000), 48);
    let first_packet = br#"{"protocol_version":8,"request_id":27,"command":{"kind":"control","action":"start","reason":"user_control"}}"#;
    let second_packet = br#"{"protocol_version":8,"request_id":28,"command":{"kind":"control","action":"stop","reason":"user_control"}}"#;

    let first_response = handler.handle_for_peer(first_packet, peer);
    let second_response = handler.handle_for_peer(second_packet, peer);
    let retried_first_response = handler.handle_for_peer(first_packet, peer);

    assert!(first_response.len() > MAX_CONTROL_PACKET_BYTES / 2);
    assert!(second_response.len() > MAX_CONTROL_PACKET_BYTES / 2);
    assert_eq!(retried_first_response, first_response);
    assert_eq!(handler.control().call_count(), 3);
}

#[test]
fn concurrent_large_results_never_overrun_the_completed_response_budget() {
    const CONCURRENT_RESULTS: usize = 16;

    let handler = Arc::new(ProtocolHandler::new(
        supported_profile(),
        ADMITTED,
        SynchronizedErrorClient::new(CONCURRENT_RESULTS, MAX_CONTROL_PACKET_BYTES / 2 + 1024),
    ));
    let peer = RequestPeerId::new(uid(1000), 49);
    let workers = (0..CONCURRENT_RESULTS)
        .map(|index| {
            let handler = Arc::clone(&handler);
            thread::spawn(move || {
                let packet = format!(
                    "{{\"protocol_version\":8,\"request_id\":{},\"command\":{{\"kind\":\"control\",\"action\":\"start\",\"reason\":\"user_control\"}}}}",
                    100 + index
                );
                handler.handle_for_peer(packet.as_bytes(), peer)
            })
        })
        .collect::<Vec<_>>();

    let responses = workers
        .into_iter()
        .map(|worker| worker.join().expect("large response worker"))
        .collect::<Vec<_>>();

    assert!(
        responses
            .iter()
            .all(|response| response.len() > MAX_CONTROL_PACKET_BYTES / 2)
    );
    assert!(
        responses
            .iter()
            .all(|response| response.len() <= MAX_CONTROL_PACKET_BYTES)
    );

    for index in 0..CONCURRENT_RESULTS {
        let packet = format!(
            "{{\"protocol_version\":8,\"request_id\":{},\"command\":{{\"kind\":\"control\",\"action\":\"start\",\"reason\":\"user_control\"}}}}",
            100 + index
        );
        let response = handler.handle_for_peer(packet.as_bytes(), peer);
        assert!(response.len() > MAX_CONTROL_PACKET_BYTES / 2);
    }

    assert!(handler.control().call_count() >= CONCURRENT_RESULTS * 2 - 1);
}

#[test]
fn reused_request_id_with_different_payload_is_rejected() {
    let handler = ProtocolHandler::new(supported_profile(), ADMITTED, RecordingClient::default());
    let peer = RequestPeerId::new(uid(1000), 42);
    let start = br#"{"protocol_version":8,"request_id":22,"command":{"kind":"control","action":"start","reason":"user_control"}}"#;
    let stop = br#"{"protocol_version":8,"request_id":22,"command":{"kind":"control","action":"stop","reason":"user_control"}}"#;

    let _ = handler.handle_for_peer(start, peer);
    let response = handler.handle_for_peer(stop, peer);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":8,\"request_id\":22,",
            "\"result\":{\"status\":\"error\",\"code\":\"request_id_conflict\",",
            "\"message\":\"request ID was already used for a different mutation\"}}\n"
        )
    );
    assert_eq!(handler.control().intents().len(), 1);
}

#[test]
fn control_request_maps_wire_intent_and_returns_the_operation_revision() {
    let client = RecordingClient::default();
    let handler = ProtocolHandler::new(supported_profile(), ADMITTED, client);

    let response = handler.handle(
        br#"{"protocol_version":8,"request_id":9,"command":{"kind":"control","action":"reload","reason":"config_changed"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":8,\"request_id\":9,",
            "\"result\":{\"status\":\"ok\",\"body\":{",
            "\"kind\":\"operation\",\"revision\":73}}}\n"
        )
    );
    assert_eq!(
        handler.control().intents(),
        vec![RuntimeIntent::Reload {
            reason: Reason::ConfigChanged,
        }]
    );
}

#[test]
fn control_clients_cannot_claim_daemon_automation_provenance() {
    let client = RecordingClient::default();
    let handler = ProtocolHandler::new(supported_profile(), ADMITTED, client);

    let response = handler.handle(
        br#"{"protocol_version":8,"request_id":10,"command":{"kind":"control","action":"reload","reason":"automation"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":8,\"request_id\":10,",
            "\"result\":{\"status\":\"error\",\"code\":\"reserved_reason\",",
            "\"message\":\"the automation reason is reserved for daemon-originated proposals\"}}\n"
        )
    );
    assert!(handler.control().intents().is_empty());
}

#[test]
fn unsupported_kernel_rejects_mutation_without_calling_the_writer() {
    let handler = ProtocolHandler::new(
        Arc::new(CapabilityProfileFixture::unsupported_kernel()),
        NativeAdmissionState::Rejected(NativeAdmissionRejection::UnsupportedKernel),
        RecordingClient::default(),
    );

    let response = handler.handle(
        br#"{"protocol_version":8,"request_id":11,"command":{"kind":"control","action":"start","reason":"boot"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":8,\"request_id\":11,",
            "\"result\":{\"status\":\"error\",\"code\":\"unsupported_kernel\",",
            "\"message\":\"kernel 5.4.280 is below minimum 5.10.0\"}}\n"
        )
    );
    assert!(handler.control().intents().is_empty());
}

#[test]
fn unverified_kernel_or_boot_rejects_mutation_without_calling_the_writer() {
    for (profile, admission, code, message) in [
        (
            CapabilityProfileFixture::unverified_boot(),
            NativeAdmissionState::Rejected(NativeAdmissionRejection::UnverifiedBootIdentity),
            "unverified_boot_identity",
            "native admission rejected: the boot identity is unverified",
        ),
        (
            unverified_kernel_profile(),
            NativeAdmissionState::Rejected(NativeAdmissionRejection::UnverifiedKernel),
            "unverified_kernel",
            "native admission rejected: the kernel version is unverified",
        ),
    ] {
        let handler =
            ProtocolHandler::new(Arc::new(profile), admission, RecordingClient::default());

        let response = handler.handle(
            br#"{"protocol_version":8,"request_id":13,"command":{"kind":"control","action":"start","reason":"boot"}}"#,
        );

        assert_eq!(
            String::from_utf8(response).expect("UTF-8 response"),
            format!(
                "{{\"protocol_version\":8,\"request_id\":13,\"result\":{{\"status\":\"error\",\"code\":\"{code}\",\"message\":\"{message}\"}}}}\n"
            )
        );
        assert!(handler.control().intents().is_empty());
    }
}

#[test]
fn oversized_packet_is_rejected_before_json_parsing() {
    let handler = ProtocolHandler::new(supported_profile(), ADMITTED, RecordingClient::default());
    let packet = vec![b' '; MAX_CONTROL_PACKET_BYTES + 1];

    let response = handler.handle(&packet);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":8,\"request_id\":0,",
            "\"result\":{\"status\":\"error\",\"code\":\"packet_too_large\",",
            "\"message\":\"control packet exceeds 1048576 bytes\"}}\n"
        )
    );
}

#[derive(Default)]
struct RecordingClient {
    intents: Mutex<Vec<RuntimeIntent>>,
    snapshot: Mutex<ControlSnapshot>,
}

impl RecordingClient {
    fn with_snapshot(snapshot: ControlSnapshot) -> Self {
        Self {
            intents: Mutex::new(Vec::new()),
            snapshot: Mutex::new(snapshot),
        }
    }

    fn intents(&self) -> Vec<RuntimeIntent> {
        self.intents.lock().expect("intents lock").clone()
    }
}

impl ControlClient for RecordingClient {
    fn submit_and_wait(&self, intent: RuntimeIntent) -> Result<OperationReport, ControlError> {
        self.intents.lock().expect("intents lock").push(intent);
        Ok(OperationReport {
            intent,
            revision: 73,
            address_resync: matches!(intent, RuntimeIntent::ResyncAddresses { .. })
                .then_some(flux_core::AddressResyncDisposition::AcceptedDeferred),
        })
    }
}

impl ControlSnapshotSource for RecordingClient {
    fn snapshot(&self) -> Arc<ControlSnapshot> {
        Arc::new(*self.snapshot.lock().expect("snapshot lock"))
    }
}

impl ConfigurationChangeClient for RecordingClient {
    fn configuration_changed(
        &self,
        reason: Reason,
    ) -> Result<ConfigurationChangeReport, ControlError> {
        let mut snapshot = self.snapshot.lock().expect("snapshot lock");
        if snapshot.administrative_state == AdministrativeState::Running {
            drop(snapshot);
            return self
                .submit_and_wait(RuntimeIntent::Reload { reason })
                .map(ConfigurationChangeReport::Reloaded);
        }
        snapshot.revision = snapshot.revision.saturating_add(1);
        snapshot.configuration_dirty = true;
        Ok(ConfigurationChangeReport::Deferred {
            revision: snapshot.revision,
        })
    }
}

struct BlockingClient {
    calls: AtomicUsize,
    first_call_entered: Barrier,
    release_first_call: Barrier,
}

impl BlockingClient {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            first_call_entered: Barrier::new(2),
            release_first_call: Barrier::new(2),
        }
    }

    fn wait_for_first_call(&self) {
        self.first_call_entered.wait();
    }

    fn release_first_call(&self) {
        self.release_first_call.wait();
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ControlClient for BlockingClient {
    fn submit_and_wait(&self, intent: RuntimeIntent) -> Result<OperationReport, ControlError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            self.first_call_entered.wait();
            self.release_first_call.wait();
        }
        Ok(OperationReport {
            intent,
            revision: 73,
            address_resync: matches!(intent, RuntimeIntent::ResyncAddresses { .. })
                .then_some(flux_core::AddressResyncDisposition::AcceptedDeferred),
        })
    }
}

impl ControlSnapshotSource for BlockingClient {
    fn snapshot(&self) -> Arc<ControlSnapshot> {
        Arc::new(ControlSnapshot::default())
    }
}

impl ConfigurationChangeClient for BlockingClient {
    fn configuration_changed(
        &self,
        _reason: Reason,
    ) -> Result<ConfigurationChangeReport, ControlError> {
        Ok(ConfigurationChangeReport::Deferred { revision: 0 })
    }
}

struct ErrorClient {
    calls: AtomicUsize,
    message_bytes: usize,
}

impl ErrorClient {
    fn new(message_bytes: usize) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            message_bytes,
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ControlClient for ErrorClient {
    fn submit_and_wait(&self, _intent: RuntimeIntent) -> Result<OperationReport, ControlError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ControlError::dispatcher("x".repeat(self.message_bytes)))
    }
}

impl ControlSnapshotSource for ErrorClient {
    fn snapshot(&self) -> Arc<ControlSnapshot> {
        Arc::new(ControlSnapshot::default())
    }
}

impl ConfigurationChangeClient for ErrorClient {
    fn configuration_changed(
        &self,
        _reason: Reason,
    ) -> Result<ConfigurationChangeReport, ControlError> {
        Ok(ConfigurationChangeReport::Deferred { revision: 0 })
    }
}

struct SynchronizedErrorClient {
    calls: AtomicUsize,
    first_wave: Barrier,
    first_wave_size: usize,
    message_bytes: usize,
}

impl SynchronizedErrorClient {
    fn new(first_wave_size: usize, message_bytes: usize) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            first_wave: Barrier::new(first_wave_size),
            first_wave_size,
            message_bytes,
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ControlClient for SynchronizedErrorClient {
    fn submit_and_wait(&self, _intent: RuntimeIntent) -> Result<OperationReport, ControlError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call < self.first_wave_size {
            self.first_wave.wait();
        }
        Err(ControlError::dispatcher("x".repeat(self.message_bytes)))
    }
}

impl ControlSnapshotSource for SynchronizedErrorClient {
    fn snapshot(&self) -> Arc<ControlSnapshot> {
        Arc::new(ControlSnapshot::default())
    }
}

impl ConfigurationChangeClient for SynchronizedErrorClient {
    fn configuration_changed(
        &self,
        _reason: Reason,
    ) -> Result<ConfigurationChangeReport, ControlError> {
        Ok(ConfigurationChangeReport::Deferred { revision: 0 })
    }
}
