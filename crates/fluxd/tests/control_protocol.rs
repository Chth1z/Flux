use std::sync::Mutex;

use flux_core::{
    ControlClient, ControlError, KernelSupport, LegacyIntent, OperationReport, Reason,
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
}

impl RecordingClient {
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
