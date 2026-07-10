use std::sync::{Arc, Mutex};

use flux_core::{
    AdministrativeState, ControlClient, ControlError, ControlSnapshot, KernelSupport, LegacyIntent,
    OperationReport, Reason,
};
use fluxd::{MAX_CONTROL_PACKET_BYTES, ProtocolHandler};

#[test]
fn ping_has_a_stable_versioned_json_contract() {
    let handler = ProtocolHandler::new(
        KernelSupport::evaluate("5.10.0").expect("kernel release"),
        RecordingClient::default(),
    );

    let response =
        handler.handle(br#"{"protocol_version":1,"request_id":7,"command":{"kind":"ping"}}"#);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":1,\"request_id\":7,",
            "\"result\":{\"status\":\"ok\",\"body\":{\"kind\":\"pong\"}}}\n"
        )
    );
}

#[test]
fn status_returns_the_daemon_control_snapshot_and_kernel_support() {
    let handler = ProtocolHandler::new(
        KernelSupport::evaluate("6.6.30-android15").expect("kernel release"),
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
    );

    let response =
        handler.handle(br#"{"protocol_version":1,"request_id":8,"command":{"kind":"status"}}"#);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":1,\"request_id\":8,",
            "\"result\":{\"status\":\"ok\",\"body\":{\"kind\":\"snapshot\",",
            "\"kernel\":{\"status\":\"supported\",\"version\":\"6.6.30\"},",
            "\"control\":{\"revision\":73,\"administrative_state\":\"running\",",
            "\"configuration_dirty\":false,",
            "\"in_flight\":null,\"last_completed\":{",
            "\"intent\":{\"action\":\"reload\",\"reason\":\"config_changed\"},",
            "\"revision\":73}}}}}\n"
        )
    );
}

#[test]
fn config_event_while_stopped_is_deferred_without_invoking_the_writer() {
    let handler = ProtocolHandler::new(
        KernelSupport::evaluate("5.10.0").expect("kernel release"),
        RecordingClient::with_snapshot(ControlSnapshot {
            administrative_state: AdministrativeState::Stopped,
            ..ControlSnapshot::default()
        }),
    );

    let response = handler.handle(
        br#"{"protocol_version":1,"request_id":10,"command":{"kind":"event","event_type":"y","watched_path":"/data/adb/flux/conf","event_name":"settings.ini"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":1,\"request_id\":10,",
            "\"result\":{\"status\":\"ok\",\"body\":{",
            "\"kind\":\"event\",\"disposition\":\"deferred\",\"revision\":1}}}\n"
        )
    );
    assert!(handler.control().intents().is_empty());
    assert!(handler.control().snapshot().configuration_dirty);
}

#[test]
fn disable_removal_event_maps_to_a_running_intent() {
    let handler = ProtocolHandler::new(
        KernelSupport::evaluate("5.10.0").expect("kernel release"),
        RecordingClient::default(),
    );

    let response = handler.handle(
        br#"{"protocol_version":1,"request_id":12,"command":{"kind":"event","event_type":"d","watched_path":"/data/adb/modules/flux","event_name":"disable"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":1,\"request_id\":12,",
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
    let handler = ProtocolHandler::new(
        KernelSupport::evaluate("5.10.0").expect("kernel release"),
        RecordingClient::default(),
    );

    let response = handler.handle(
        br#"{"protocol_version":1,"request_id":14,"command":{"kind":"event","event_type":"y","watched_path":"/data/adb/flux/conf","event_name":"notes.txt"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":1,\"request_id\":14,",
            "\"result\":{\"status\":\"ok\",\"body\":{",
            "\"kind\":\"event\",\"disposition\":\"ignored\",\"revision\":0}}}\n"
        )
    );
    assert!(handler.control().intents().is_empty());
}

#[test]
fn control_request_maps_wire_intent_and_returns_the_operation_revision() {
    let client = RecordingClient::default();
    let handler = ProtocolHandler::new(
        KernelSupport::evaluate("6.6.30-android15").expect("kernel release"),
        client,
    );

    let response = handler.handle(
        br#"{"protocol_version":1,"request_id":9,"command":{"kind":"control","action":"reload","reason":"config_changed"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":1,\"request_id\":9,",
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
        KernelSupport::evaluate("5.4.280-vendor").expect("kernel release"),
        RecordingClient::default(),
    );

    let response = handler.handle(
        br#"{"protocol_version":1,"request_id":11,"command":{"kind":"control","action":"start","reason":"boot"}}"#,
    );

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":1,\"request_id\":11,",
            "\"result\":{\"status\":\"error\",\"code\":\"unsupported_kernel\",",
            "\"message\":\"kernel 5.4.280 is below minimum 5.10.0\"}}\n"
        )
    );
    assert!(handler.control().intents().is_empty());
}

#[test]
fn oversized_packet_is_rejected_before_json_parsing() {
    let handler = ProtocolHandler::new(
        KernelSupport::evaluate("5.10.0").expect("kernel release"),
        RecordingClient::default(),
    );
    let packet = vec![b' '; MAX_CONTROL_PACKET_BYTES + 1];

    let response = handler.handle(&packet);

    assert_eq!(
        String::from_utf8(response).expect("UTF-8 response"),
        concat!(
            "{\"protocol_version\":1,\"request_id\":0,",
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

    fn snapshot(&self) -> Arc<ControlSnapshot> {
        Arc::new(*self.snapshot.lock().expect("snapshot lock"))
    }

    fn mark_configuration_dirty(&self) -> Result<u64, ControlError> {
        let mut snapshot = self.snapshot.lock().expect("snapshot lock");
        snapshot.revision = snapshot.revision.saturating_add(1);
        snapshot.configuration_dirty = true;
        Ok(snapshot.revision)
    }
}
