#![cfg(any(target_os = "linux", target_os = "android"))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use flux_core::{
    ControlClient, ControlError, KernelSupport, LegacyControlBridge, LegacyDispatcher,
    LegacyIntent, Reason,
};
use flux_platform::SeqpacketConnection;
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

#[test]
fn daemon_keeps_serving_after_a_client_disconnects_before_sending() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let bridge = LegacyControlBridge::start(
        RecordingDispatcher {
            calls: Arc::new(Mutex::new(Vec::new())),
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
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop);
    let server_thread = thread::spawn(move || {
        server
            .serve_until(|| Ok(server_stop.load(Ordering::Acquire)))
            .expect("serve until stopped");
    });

    let disconnected = SeqpacketConnection::connect(&socket_path).expect("connect first client");
    drop(disconnected);

    let client = SocketControlClient::new(&socket_path);
    client.ping().expect("second client receives pong");
    stop.store(true, Ordering::Release);
    server_thread.join().expect("server thread");
}

#[test]
fn ping_remains_responsive_while_a_control_operation_is_in_flight() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let bridge = LegacyControlBridge::start(
        BlockingDispatcher {
            started_tx,
            release_rx,
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
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop);
    let server_thread = thread::spawn(move || {
        server
            .serve_until(|| Ok(server_stop.load(Ordering::Acquire)))
            .expect("serve until stopped");
    });

    let control_path = socket_path.clone();
    let control = thread::spawn(move || {
        SocketControlClient::new(control_path)
            .submit_and_wait(LegacyIntent::Running {
                reason: Reason::Fluxctl,
            })
            .expect("control completes")
    });
    started_rx
        .recv()
        .expect("dispatcher operation must be in flight");

    SocketControlClient::new(&socket_path)
        .ping()
        .expect("ping remains responsive");

    release_tx.send(()).expect("release dispatcher");
    control.join().expect("control client");
    stop.store(true, Ordering::Release);
    server_thread.join().expect("server thread");
}

struct RecordingDispatcher {
    calls: Arc<Mutex<Vec<LegacyIntent>>>,
}

struct BlockingDispatcher {
    started_tx: mpsc::Sender<()>,
    release_rx: mpsc::Receiver<()>,
}

impl LegacyDispatcher for BlockingDispatcher {
    fn execute(&mut self, _intent: &LegacyIntent) -> Result<(), ControlError> {
        self.started_tx
            .send(())
            .map_err(|error| ControlError::dispatcher(error.to_string()))?;
        self.release_rx
            .recv()
            .map_err(|error| ControlError::dispatcher(error.to_string()))
    }
}

impl LegacyDispatcher for RecordingDispatcher {
    fn execute(&mut self, intent: &LegacyIntent) -> Result<(), ControlError> {
        self.calls.lock().expect("calls lock").push(*intent);
        Ok(())
    }
}
