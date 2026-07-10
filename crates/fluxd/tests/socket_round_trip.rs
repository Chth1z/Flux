#![cfg(any(target_os = "linux", target_os = "android"))]

use std::sync::{Arc, Mutex};
use std::thread;

use flux_core::{
    ControlClient, ControlError, KernelSupport, LegacyControlBridge, LegacyDispatcher,
    LegacyIntent, Reason,
};
use fluxd::{ControlSocketServer, SocketControlClient};
use tempfile::tempdir;

#[test]
fn seqpacket_client_and_server_complete_a_control_operation() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let bridge = LegacyControlBridge::start(
        RecordingDispatcher {
            calls: Arc::clone(&calls),
        },
        4,
    )
    .expect("start bridge");
    let server = ControlSocketServer::bind(
        &socket_path,
        KernelSupport::evaluate("5.10.0").expect("kernel release"),
        bridge,
    )
    .expect("bind server");

    let server_thread = thread::spawn(move || server.serve_once().expect("serve request"));
    let client = SocketControlClient::new(&socket_path);
    let intent = LegacyIntent::Running {
        reason: Reason::Fluxctl,
    };

    let report = client
        .submit_and_wait(intent)
        .expect("control operation completes");

    assert_eq!(report.intent, intent);
    assert_eq!(report.revision, 2);
    server_thread.join().expect("server thread");
    assert_eq!(calls.lock().expect("calls lock").as_slice(), &[intent]);
}

struct RecordingDispatcher {
    calls: Arc<Mutex<Vec<LegacyIntent>>>,
}

impl LegacyDispatcher for RecordingDispatcher {
    fn execute(&mut self, intent: &LegacyIntent) -> Result<(), ControlError> {
        self.calls.lock().expect("calls lock").push(*intent);
        Ok(())
    }
}
