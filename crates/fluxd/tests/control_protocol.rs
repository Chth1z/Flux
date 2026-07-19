use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use flux_core::{
    AdministrativeState, CapabilityProfile, ConfigurationChangeClient, ConfigurationChangeReport,
    ControlClient, ControlError, ControlSnapshot, ControlSnapshotSource, KernelFacts, LegacyIntent,
    Observation, OperationReport, Reason,
};
use flux_platform::Uid;
use flux_testkit::CapabilityProfileFixture;
use fluxd::{
    MAX_CONTROL_PACKET_BYTES, ProtocolHandler, RequestPeerId, RuntimeCaptureState,
    RuntimeEngineState, RuntimeFailure, RuntimePhase, RuntimeSnapshot, RuntimeSnapshotSource,
    RuntimeVerificationState,
};

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
        supported.legacy_bridge().clone(),
    )
}

#[test]
fn ping_has_a_stable_versioned_json_contract() {
    let handler = ProtocolHandler::new(supported_profile(), RecordingClient::default());

    let response =
        handler.handle(br#"{"protocol_version":3,"request_id":7,"command":{"kind":"ping"}}"#);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":7,",
            "\"result\":{\"status\":\"ok\",\"body\":{\"kind\":\"pong\"}}}\n"
        )
    );
}

#[test]
fn version_two_requests_are_explicitly_rejected() {
    let handler = ProtocolHandler::new(supported_profile(), RecordingClient::default());

    let response =
        handler.handle(br#"{"protocol_version":2,"request_id":6,"command":{"kind":"ping"}}"#);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":6,",
            "\"result\":{\"status\":\"error\",\"code\":\"unsupported_protocol\",",
            "\"message\":\"protocol version 2 is unsupported; expected 3\"}}\n"
        )
    );
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
        generation: Some(74),
        last_error: Some(RuntimeFailure {
            operation: "maintain proxy engine".to_owned(),
            message: "owned child exited unexpectedly".to_owned(),
            recovery: "retry after bounded backoff".to_owned(),
        }),
    });
    let handler = ProtocolHandler::with_runtime_snapshot_source(
        supported_profile(),
        RecordingClient::with_snapshot(ControlSnapshot {
            revision: 73,
            administrative_state: AdministrativeState::Running,
            configuration_dirty: false,
            in_flight: None,
            last_completed: Some(OperationReport {
                intent: LegacyIntent::Reload {
                    reason: Reason::ConfigChanged,
                },
                revision: 73,
            }),
        }),
        runtime,
    );

    let response =
        handler.handle(br#"{"protocol_version":3,"request_id":8,"command":{"kind":"status"}}"#);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":8,",
            "\"result\":{\"status\":\"ok\",\"body\":{\"kind\":\"snapshot\",",
            "\"kernel\":{\"status\":\"supported\",\"version\":\"5.10.198\"},",
            "\"capability_profile\":{\"schema_version\":2,\"revision\":1,",
            "\"boot_identity\":{\"status\":\"verified\",",
            "\"value\":\"01234567-89ab-cdef-0123-456789abcdef\"},",
            "\"device_identity\":{\"status\":\"unavailable\"},",
            "\"kernel\":{\"release\":{\"status\":\"verified\",",
            "\"value\":\"5.10.198-android12-9-gki\"},",
            "\"version\":{\"status\":\"verified\",\"value\":\"5.10.198\"},",
            "\"minimum\":\"5.10.0\",\"gate\":{\"status\":\"allowed\"}},",
            "\"selinux\":{\"status\":\"verified\",\"value\":\"enforcing\"},",
            "\"legacy_bridge\":{\"mutation_writer\":\"dispatcher\",",
            "\"rule_backend\":\"iptables_restore\",",
            "\"address_synchronization\":\"standalone_addrsyncd_via_script\",",
            "\"shell\":{\"status\":\"verified\",\"value\":{",
            "\"resolution\":\"direct\",\"ready\":true}},",
            "\"dispatcher\":{\"status\":\"verified\",\"value\":{",
            "\"resolution\":\"direct\",\"ready\":true}},",
            "\"addrsync\":{\"status\":\"verified\",\"value\":{",
            "\"resolution\":\"direct\",\"ready\":true}}}},",
            "\"control\":{\"revision\":73,\"administrative_state\":\"running\",",
            "\"configuration_dirty\":false,",
            "\"in_flight\":null,\"last_completed\":{",
            "\"intent\":{\"action\":\"reload\",\"reason\":\"config_changed\"},",
            "\"revision\":73}},",
            "\"runtime\":{\"revision\":1,\"phase\":\"repairing\",",
            "\"capture\":\"detached\",",
            "\"engine\":\"backing_off\",",
            "\"verification\":\"functional_failed\",\"generation\":74,",
            "\"last_error\":{\"operation\":\"maintain proxy engine\",",
            "\"message\":\"owned child exited unexpectedly\",",
            "\"recovery\":\"retry after bounded backoff\"}}}}}\n"
        )
    );
}

#[test]
fn config_event_while_stopped_is_deferred_without_invoking_the_writer() {
    let handler = ProtocolHandler::new(
        supported_profile(),
        RecordingClient::with_snapshot(ControlSnapshot {
            administrative_state: AdministrativeState::Stopped,
            ..ControlSnapshot::default()
        }),
    );

    let response = handler.handle(
        br#"{"protocol_version":3,"request_id":10,"command":{"kind":"event","event_type":"y","watched_path":"/data/adb/flux/conf","event_name":"settings.ini"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":10,",
            "\"result\":{\"status\":\"ok\",\"body\":{",
            "\"kind\":\"event\",\"disposition\":\"deferred\",\"revision\":1}}}\n"
        )
    );
    assert!(handler.control().intents().is_empty());
    assert!(handler.control().snapshot().configuration_dirty);
}

#[test]
fn disable_removal_event_maps_to_a_running_intent() {
    let handler = ProtocolHandler::new(supported_profile(), RecordingClient::default());

    let response = handler.handle(
        br#"{"protocol_version":3,"request_id":12,"command":{"kind":"event","event_type":"d","watched_path":"/data/adb/modules/flux","event_name":"disable"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":12,",
            "\"result\":{\"status\":\"ok\",\"body\":{",
            "\"kind\":\"event\",\"disposition\":\"applied\",\"revision\":73}}}\n"
        )
    );
    assert_eq!(
        handler.control().intents(),
        vec![LegacyIntent::Running {
            reason: Reason::DisableRemoved,
        }]
    );
}

#[test]
fn unrelated_inotify_fact_is_acknowledged_without_mutation() {
    let handler = ProtocolHandler::new(supported_profile(), RecordingClient::default());

    let response = handler.handle(
        br#"{"protocol_version":3,"request_id":14,"command":{"kind":"event","event_type":"y","watched_path":"/data/adb/flux/conf","event_name":"notes.txt"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":14,",
            "\"result\":{\"status\":\"ok\",\"body\":{",
            "\"kind\":\"event\",\"disposition\":\"ignored\",\"revision\":0}}}\n"
        )
    );
    assert!(handler.control().intents().is_empty());
}

#[test]
fn retried_mutation_with_the_same_peer_and_request_id_is_applied_once() {
    let handler = ProtocolHandler::new(supported_profile(), RecordingClient::default());
    let peer = RequestPeerId::new(uid(1000), 42);
    let packet = br#"{"protocol_version":3,"request_id":21,"command":{"kind":"control","action":"start","reason":"fluxctl"}}"#;

    let first = handler.handle_for_peer(packet, peer);
    let retry = handler.handle_for_peer(packet, peer);

    assert_eq!(retry, first);
    assert_eq!(
        handler.control().intents(),
        vec![LegacyIntent::Running {
            reason: Reason::Fluxctl,
        }]
    );
}

#[test]
fn concurrent_retry_waits_for_the_original_mutation_result() {
    let handler = Arc::new(ProtocolHandler::new(
        supported_profile(),
        BlockingClient::new(),
    ));
    let peer = RequestPeerId::new(uid(1000), 43);
    let packet = br#"{"protocol_version":3,"request_id":23,"command":{"kind":"control","action":"start","reason":"fluxctl"}}"#;

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
    let handler = ProtocolHandler::new(supported_profile(), RecordingClient::default());
    let peer = RequestPeerId::new(uid(1000), 44);
    let compact = br#"{"protocol_version":3,"request_id":24,"command":{"kind":"control","action":"start","reason":"fluxctl"}}"#;
    let spaced = br#"{ "protocol_version": 3, "request_id": 24, "command": { "kind": "control", "action": "start", "reason": "fluxctl" } }"#;

    let _ = handler.handle_for_peer(compact, peer);
    let response = handler.handle_for_peer(spaced, peer);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":24,",
            "\"result\":{\"status\":\"error\",\"code\":\"request_id_conflict\",",
            "\"message\":\"request ID was already used for a different mutation\"}}\n"
        )
    );
    assert_eq!(handler.control().intents().len(), 1);
}

#[test]
fn request_ids_are_scoped_to_the_authenticated_peer() {
    let handler = ProtocolHandler::new(supported_profile(), RecordingClient::default());
    let packet = br#"{"protocol_version":3,"request_id":25,"command":{"kind":"control","action":"start","reason":"fluxctl"}}"#;

    let _ = handler.handle_for_peer(packet, RequestPeerId::new(uid(1000), 45));
    let _ = handler.handle_for_peer(packet, RequestPeerId::new(uid(1000), 46));

    assert_eq!(handler.control().intents().len(), 2);
}

#[test]
fn oversized_mutation_result_is_replaced_by_a_bounded_protocol_error() {
    let handler = ProtocolHandler::new(
        supported_profile(),
        ErrorClient::new(MAX_CONTROL_PACKET_BYTES),
    );
    let peer = RequestPeerId::new(uid(1000), 47);
    let packet = br#"{"protocol_version":3,"request_id":26,"command":{"kind":"control","action":"start","reason":"fluxctl"}}"#;

    let response = handler.handle_for_peer(packet, peer);
    let retry = handler.handle_for_peer(packet, peer);

    assert!(response.len() <= MAX_CONTROL_PACKET_BYTES);
    assert_eq!(
        String::from_utf8(response.clone()).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":26,",
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
        ErrorClient::new(MAX_CONTROL_PACKET_BYTES / 2 + 1024),
    );
    let peer = RequestPeerId::new(uid(1000), 48);
    let first_packet = br#"{"protocol_version":3,"request_id":27,"command":{"kind":"control","action":"start","reason":"fluxctl"}}"#;
    let second_packet = br#"{"protocol_version":3,"request_id":28,"command":{"kind":"control","action":"stop","reason":"fluxctl"}}"#;

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
        SynchronizedErrorClient::new(CONCURRENT_RESULTS, MAX_CONTROL_PACKET_BYTES / 2 + 1024),
    ));
    let peer = RequestPeerId::new(uid(1000), 49);
    let workers = (0..CONCURRENT_RESULTS)
        .map(|index| {
            let handler = Arc::clone(&handler);
            thread::spawn(move || {
                let packet = format!(
                    "{{\"protocol_version\":3,\"request_id\":{},\"command\":{{\"kind\":\"control\",\"action\":\"start\",\"reason\":\"fluxctl\"}}}}",
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
            "{{\"protocol_version\":3,\"request_id\":{},\"command\":{{\"kind\":\"control\",\"action\":\"start\",\"reason\":\"fluxctl\"}}}}",
            100 + index
        );
        let response = handler.handle_for_peer(packet.as_bytes(), peer);
        assert!(response.len() > MAX_CONTROL_PACKET_BYTES / 2);
    }

    assert!(handler.control().call_count() >= CONCURRENT_RESULTS * 2 - 1);
}

#[test]
fn reused_request_id_with_different_payload_is_rejected() {
    let handler = ProtocolHandler::new(supported_profile(), RecordingClient::default());
    let peer = RequestPeerId::new(uid(1000), 42);
    let start = br#"{"protocol_version":3,"request_id":22,"command":{"kind":"control","action":"start","reason":"fluxctl"}}"#;
    let stop = br#"{"protocol_version":3,"request_id":22,"command":{"kind":"control","action":"stop","reason":"fluxctl"}}"#;

    let _ = handler.handle_for_peer(start, peer);
    let response = handler.handle_for_peer(stop, peer);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":22,",
            "\"result\":{\"status\":\"error\",\"code\":\"request_id_conflict\",",
            "\"message\":\"request ID was already used for a different mutation\"}}\n"
        )
    );
    assert_eq!(handler.control().intents().len(), 1);
}

#[test]
fn control_request_maps_wire_intent_and_returns_the_operation_revision() {
    let client = RecordingClient::default();
    let handler = ProtocolHandler::new(supported_profile(), client);

    let response = handler.handle(
        br#"{"protocol_version":3,"request_id":9,"command":{"kind":"control","action":"reload","reason":"config_changed"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":9,",
            "\"result\":{\"status\":\"ok\",\"body\":{",
            "\"kind\":\"operation\",\"revision\":73}}}\n"
        )
    );
    assert_eq!(
        handler.control().intents(),
        vec![LegacyIntent::Reload {
            reason: Reason::ConfigChanged,
        }]
    );
}

#[test]
fn unsupported_kernel_rejects_mutation_without_calling_the_writer() {
    let handler = ProtocolHandler::new(
        Arc::new(CapabilityProfileFixture::unsupported_kernel()),
        RecordingClient::default(),
    );

    let response = handler.handle(
        br#"{"protocol_version":3,"request_id":11,"command":{"kind":"control","action":"start","reason":"boot"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":11,",
            "\"result\":{\"status\":\"error\",\"code\":\"unsupported_kernel\",",
            "\"message\":\"kernel 5.4.280 is below minimum 5.10.0\"}}\n"
        )
    );
    assert!(handler.control().intents().is_empty());
}

#[test]
fn unverified_kernel_or_boot_rejects_mutation_without_calling_the_writer() {
    for profile in [
        CapabilityProfileFixture::unverified_boot(),
        unverified_kernel_profile(),
    ] {
        let handler = ProtocolHandler::new(Arc::new(profile), RecordingClient::default());

        let response = handler.handle(
            br#"{"protocol_version":3,"request_id":13,"command":{"kind":"control","action":"start","reason":"boot"}}"#,
        );

        assert_eq!(
            String::from_utf8(response).expect("UTF-8 response"),
            concat!(
                "{\"protocol_version\":3,\"request_id\":13,",
                "\"result\":{\"status\":\"error\",\"code\":\"read_only_profile\",",
                "\"message\":\"capability profile is read-only because kernel or boot identity is unverified\"}}\n"
            )
        );
        assert!(handler.control().intents().is_empty());
    }
}

#[test]
fn read_only_profile_rejects_configuration_events_before_control_service_state_changes() {
    let handler = ProtocolHandler::new(
        Arc::new(CapabilityProfileFixture::unverified_boot()),
        RecordingClient::default(),
    );

    let response = handler.handle(
        br#"{"protocol_version":3,"request_id":15,"command":{"kind":"event","event_type":"y","watched_path":"/data/adb/flux/conf","event_name":"settings.ini"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":15,",
            "\"result\":{\"status\":\"error\",\"code\":\"read_only_profile\",",
            "\"message\":\"capability profile is read-only because kernel or boot identity is unverified\"}}\n"
        )
    );
    assert_eq!(
        handler.control().snapshot().as_ref(),
        &ControlSnapshot::default()
    );
    assert!(handler.control().intents().is_empty());
}

#[test]
fn oversized_packet_is_rejected_before_json_parsing() {
    let handler = ProtocolHandler::new(supported_profile(), RecordingClient::default());
    let packet = vec![b' '; MAX_CONTROL_PACKET_BYTES + 1];

    let response = handler.handle(&packet);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":3,\"request_id\":0,",
            "\"result\":{\"status\":\"error\",\"code\":\"packet_too_large\",",
            "\"message\":\"control packet exceeds 1048576 bytes\"}}\n"
        )
    );
}

#[derive(Default)]
struct RecordingClient {
    intents: Mutex<Vec<LegacyIntent>>,
    snapshot: Mutex<ControlSnapshot>,
}

impl RecordingClient {
    fn with_snapshot(snapshot: ControlSnapshot) -> Self {
        Self {
            intents: Mutex::new(Vec::new()),
            snapshot: Mutex::new(snapshot),
        }
    }

    fn intents(&self) -> Vec<LegacyIntent> {
        self.intents.lock().expect("intents lock").clone()
    }
}

impl ControlClient for RecordingClient {
    fn submit_and_wait(&self, intent: LegacyIntent) -> Result<OperationReport, ControlError> {
        self.intents.lock().expect("intents lock").push(intent);
        Ok(OperationReport {
            intent,
            revision: 73,
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
                .submit_and_wait(LegacyIntent::Reload { reason })
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
    fn submit_and_wait(&self, intent: LegacyIntent) -> Result<OperationReport, ControlError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            self.first_call_entered.wait();
            self.release_first_call.wait();
        }
        Ok(OperationReport {
            intent,
            revision: 73,
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
    fn submit_and_wait(&self, _intent: LegacyIntent) -> Result<OperationReport, ControlError> {
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
    fn submit_and_wait(&self, _intent: LegacyIntent) -> Result<OperationReport, ControlError> {
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
