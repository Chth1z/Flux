#![cfg(any(target_os = "linux", target_os = "android"))]

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use flux_core::{
    AddressResyncDisposition, CapabilityProfile, CapabilityProfileRevision, ControlClient,
    ControlError, DispatcherCompletion, Reason, RuntimeControl, RuntimeDispatcher, RuntimeIntent,
};
use flux_platform::{DaemonReactor, SeqpacketConnection, ShutdownSignal};
use flux_testkit::CapabilityProfileFixture;
use fluxd::{
    ControlConnectionHandler, NativeAdmissionRejection, NativeAdmissionState, RuntimeCaptureState,
    RuntimeEngineState, RuntimeFailure, RuntimePhase, RuntimeSnapshot, RuntimeSnapshotSource,
    RuntimeVerificationState, SocketControlClient,
};
use tempfile::tempdir;

#[test]
fn seqpacket_client_and_reactor_complete_a_control_operation() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let runtime = RuntimeControl::start(
        RecordingDispatcher {
            calls: Arc::clone(&calls),
        },
        4,
    )
    .expect("start runtime");
    let handler = ControlConnectionHandler::new(
        Arc::new(CapabilityProfileFixture::supported()),
        NativeAdmissionState::Admitted,
        runtime,
    );
    let (reactor, stop) = DaemonReactor::bind(&socket_path, shutdown, move |connection| {
        handler.serve(connection).expect("serve control connection");
    })
    .expect("bind reactor");

    let intent = RuntimeIntent::Running {
        reason: Reason::UserControl,
    };
    let client_path = socket_path.clone();
    let client_thread = thread::spawn(move || {
        let result = SocketControlClient::new(client_path).submit_and_wait(intent);
        stop.request_stop().expect("request reactor stop");
        result.expect("control operation completes")
    });

    reactor.run().expect("run reactor");
    let report = client_thread.join().expect("client thread");

    assert_eq!(report.intent, intent);
    assert_eq!(report.revision, 2);
    assert_eq!(calls.lock().expect("calls lock").as_slice(), &[intent]);
    assert_socket_absent(&socket_path);
}

#[test]
fn seqpacket_status_preserves_the_capability_profile_revision() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
    let initial = CapabilityProfileFixture::supported();
    let revision = CapabilityProfileRevision::new(23).expect("nonzero revision");
    let profile = CapabilityProfile::new(
        revision,
        initial.boot_identity().clone(),
        initial.device_identity().clone(),
        initial.kernel().clone(),
        initial.selinux().clone(),
    );
    let expected_profile = profile.clone();
    let runtime = RuntimeControl::start(
        RecordingDispatcher {
            calls: Arc::new(Mutex::new(Vec::new())),
        },
        4,
    )
    .expect("start runtime");
    let handler = ControlConnectionHandler::new(
        Arc::new(profile),
        NativeAdmissionState::Rejected(NativeAdmissionRejection::UnsupportedKernel),
        runtime,
    );
    let (reactor, stop) = DaemonReactor::bind(&socket_path, shutdown, move |connection| {
        handler.serve(connection).expect("serve control connection");
    })
    .expect("bind reactor");
    let client_path = socket_path.clone();
    let client_thread = thread::spawn(move || {
        let snapshot = SocketControlClient::new(client_path)
            .status()
            .expect("status snapshot");
        stop.request_stop().expect("request reactor stop");
        snapshot
    });

    reactor.run().expect("run reactor");
    let snapshot = client_thread.join().expect("client thread");

    assert_eq!(snapshot.capability_profile, expected_profile);
    assert_socket_absent(&socket_path);
}

#[test]
fn seqpacket_status_preserves_the_observed_runtime_snapshot() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
    let runtime_source = RuntimeSnapshotSource::default();
    runtime_source.publish(RuntimeSnapshot {
        revision: 33,
        phase: RuntimePhase::Verifying,
        capture: RuntimeCaptureState::Published,
        engine: RuntimeEngineState::Ready,
        verification: RuntimeVerificationState::FunctionalPending,
        generation: flux_core::GenerationId::new(91),
        last_error: Some(RuntimeFailure {
            operation: "verify published capture".to_owned(),
            message: "functional probe timed out".to_owned(),
            recovery: "detach capture before retiring the proxy engine".to_owned(),
        }),
    });
    let expected_runtime = runtime_source.snapshot().as_ref().clone();
    let runtime_control = RuntimeControl::start(
        RecordingDispatcher {
            calls: Arc::new(Mutex::new(Vec::new())),
        },
        4,
    )
    .expect("start runtime");
    let handler = ControlConnectionHandler::with_runtime_snapshot_source(
        Arc::new(CapabilityProfileFixture::supported()),
        NativeAdmissionState::Admitted,
        runtime_control,
        runtime_source,
    );
    let (reactor, stop) = DaemonReactor::bind(&socket_path, shutdown, move |connection| {
        handler.serve(connection).expect("serve control connection");
    })
    .expect("bind reactor");
    let client_path = socket_path.clone();
    let client_thread = thread::spawn(move || {
        let snapshot = SocketControlClient::new(client_path)
            .status()
            .expect("status snapshot");
        stop.request_stop().expect("request reactor stop");
        snapshot
    });

    reactor.run().expect("run reactor");
    let snapshot = client_thread.join().expect("client thread");

    assert_eq!(snapshot.runtime, expected_runtime);
    assert_socket_absent(&socket_path);
}

#[test]
fn daemon_keeps_serving_after_a_client_disconnects_before_sending() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
    let runtime = RuntimeControl::start(
        RecordingDispatcher {
            calls: Arc::new(Mutex::new(Vec::new())),
        },
        4,
    )
    .expect("start runtime");
    let handler = ControlConnectionHandler::new(
        Arc::new(CapabilityProfileFixture::supported()),
        NativeAdmissionState::Admitted,
        runtime,
    );
    let (reactor, stop) = DaemonReactor::bind(&socket_path, shutdown, move |connection| {
        if let Err(error) = handler.serve(connection) {
            eprintln!("rejected test connection: {error}");
        }
    })
    .expect("bind reactor");
    let client_path = socket_path.clone();
    let client_thread = thread::spawn(move || {
        let result = {
            let disconnected =
                SeqpacketConnection::connect(&client_path).expect("connect first client");
            drop(disconnected);

            SocketControlClient::new(&client_path).ping()
        };
        stop.request_stop().expect("request reactor stop");
        result.expect("second client receives pong");
    });

    reactor.run().expect("run reactor");
    client_thread.join().expect("client thread");
}

#[test]
fn ping_remains_responsive_while_a_control_operation_is_in_flight() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let runtime = RuntimeControl::start(
        BlockingDispatcher {
            started_tx,
            release_rx,
        },
        4,
    )
    .expect("start runtime");
    let handler = ControlConnectionHandler::new(
        Arc::new(CapabilityProfileFixture::supported()),
        NativeAdmissionState::Admitted,
        runtime,
    );
    let (reactor, stop) = DaemonReactor::bind(&socket_path, shutdown, move |connection| {
        handler.serve(connection).expect("serve control connection");
    })
    .expect("bind reactor");
    let client_path = socket_path.clone();
    let client_thread = thread::spawn(move || {
        let control_path = client_path.clone();
        let control = thread::spawn(move || {
            SocketControlClient::new(control_path).submit_and_wait(RuntimeIntent::Running {
                reason: Reason::UserControl,
            })
        });
        let result = (|| {
            started_rx.recv().map_err(|error| error.to_string())?;
            let ping_result = SocketControlClient::new(&client_path)
                .ping()
                .map_err(|error| error.to_string());
            release_tx.send(()).map_err(|error| error.to_string())?;
            let control_result = control
                .join()
                .map_err(|_| "control client panicked".to_owned())?
                .map_err(|error| error.to_string());
            ping_result?;
            control_result?;
            Ok::<(), String>(())
        })();
        stop.request_stop().expect("request reactor stop");
        result.expect("ping and control complete");
    });

    reactor.run().expect("run reactor");
    client_thread.join().expect("client coordinator");
}

#[test]
fn stop_requested_before_run_closes_the_listener_without_dispatching_queued_clients() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
    let runtime = RuntimeControl::start(
        RecordingDispatcher {
            calls: Arc::new(Mutex::new(Vec::new())),
        },
        4,
    )
    .expect("start runtime");
    let handler = ControlConnectionHandler::new(
        Arc::new(CapabilityProfileFixture::supported()),
        NativeAdmissionState::Admitted,
        runtime,
    );
    let served = Arc::new(AtomicBool::new(false));
    let handler_served = Arc::clone(&served);
    let (reactor, stop) = DaemonReactor::bind(&socket_path, shutdown, move |connection| {
        handler_served.store(true, Ordering::Release);
        handler.serve(connection).expect("serve control connection");
    })
    .expect("bind reactor");
    let queued = SeqpacketConnection::connect(&socket_path).expect("queue client");
    queued
        .send_packet(br#"{"protocol_version":5,"request_id":7,"command":{"kind":"ping"}}"#)
        .expect("send queued request");

    stop.request_stop().expect("request reactor stop");
    reactor.run().expect("run stopped reactor");

    assert!(!served.load(Ordering::Acquire));
    assert_socket_absent(&socket_path);
}

#[test]
fn stop_closes_control_admission_before_a_running_mutation_drains() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let runtime = RuntimeControl::start(
        BlockingDispatcher {
            started_tx,
            release_rx,
        },
        4,
    )
    .expect("start runtime");
    let handler = ControlConnectionHandler::new(
        Arc::new(CapabilityProfileFixture::supported()),
        NativeAdmissionState::Admitted,
        runtime,
    );
    let (reactor, stop) = DaemonReactor::bind(&socket_path, shutdown, move |connection| {
        handler.serve(connection).expect("serve control connection");
    })
    .expect("bind reactor");
    let client_path = socket_path.clone();
    let coordinator = thread::spawn(move || {
        let control_path = client_path.clone();
        let control = thread::spawn(move || {
            SocketControlClient::new(control_path).submit_and_wait(RuntimeIntent::Running {
                reason: Reason::UserControl,
            })
        });
        started_rx
            .recv()
            .expect("dispatcher operation must be in flight");

        stop.request_stop().expect("request reactor stop");
        let closed_before_drain = wait_for_socket_absence(&client_path, Duration::from_secs(1));
        let mutation_still_running = !control.is_finished();
        release_tx.send(()).expect("release dispatcher");
        control
            .join()
            .expect("control client")
            .expect("control operation completes");

        assert!(closed_before_drain, "listener must close before drain");
        assert!(mutation_still_running, "mutation must still be draining");
    });

    reactor.run().expect("run reactor");
    coordinator.join().expect("client coordinator");
}

fn wait_for_socket_absence(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
            Ok(_) | Err(_) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(2));
            }
            Ok(_) | Err(_) => return false,
        }
    }
}

fn assert_socket_absent(path: &Path) {
    let error = std::fs::symlink_metadata(path).expect_err("listener socket must be absent");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

struct RecordingDispatcher {
    calls: Arc<Mutex<Vec<RuntimeIntent>>>,
}

struct BlockingDispatcher {
    started_tx: mpsc::Sender<()>,
    release_rx: mpsc::Receiver<()>,
}

impl RuntimeDispatcher for BlockingDispatcher {
    fn execute(&mut self, intent: &RuntimeIntent) -> Result<DispatcherCompletion, ControlError> {
        self.started_tx
            .send(())
            .map_err(|error| ControlError::dispatcher(error.to_string()))?;
        self.release_rx
            .recv()
            .map_err(|error| ControlError::dispatcher(error.to_string()))?;
        Ok(completion_for(intent))
    }
}

impl RuntimeDispatcher for RecordingDispatcher {
    fn execute(&mut self, intent: &RuntimeIntent) -> Result<DispatcherCompletion, ControlError> {
        self.calls.lock().expect("calls lock").push(*intent);
        Ok(completion_for(intent))
    }
}

fn completion_for(intent: &RuntimeIntent) -> DispatcherCompletion {
    match intent {
        RuntimeIntent::ResyncAddresses { .. } => {
            DispatcherCompletion::AddressResync(AddressResyncDisposition::AcceptedDeferred)
        }
        _ => DispatcherCompletion::Completed,
    }
}
