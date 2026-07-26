use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use flux_core::{
    AdministrativeState, ConfigurationChangeReport, ControlError, ControlObservation,
    LegacyControlBridge, LegacyDispatcher, LegacyIntent, OperationReport, Reason,
};

#[test]
fn running_intent_updates_the_snapshot_after_dispatcher_success() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let dispatcher = RecordingDispatcher {
        calls: Arc::clone(&calls),
    };
    let bridge = LegacyControlBridge::start(dispatcher, 8).expect("start bridge");

    let report = bridge
        .submit(LegacyIntent::Running {
            reason: Reason::Fluxctl,
        })
        .expect("accept operation")
        .wait()
        .expect("dispatcher succeeds");

    assert_eq!(
        report,
        OperationReport {
            intent: LegacyIntent::Running {
                reason: Reason::Fluxctl,
            },
            revision: 2,
        }
    );
    assert_eq!(
        calls.lock().expect("calls lock").as_slice(),
        &[LegacyIntent::Running {
            reason: Reason::Fluxctl,
        }]
    );

    let snapshot = bridge.snapshot();
    assert_eq!(snapshot.revision, 2);
    assert_eq!(snapshot.administrative_state, AdministrativeState::Running);
    assert!(!snapshot.configuration_dirty);
    assert_eq!(snapshot.in_flight, None);
    assert_eq!(snapshot.last_completed, Some(report));
}

#[test]
fn configuration_change_while_stopped_is_deferred_without_calling_the_dispatcher() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let bridge = LegacyControlBridge::start(
        RecordingDispatcher {
            calls: Arc::clone(&calls),
        },
        8,
    )
    .expect("start bridge");
    bridge
        .submit(LegacyIntent::Stopped {
            reason: Reason::Fluxctl,
        })
        .expect("accept stop")
        .wait()
        .expect("stop succeeds");
    calls.lock().expect("calls lock").clear();

    let revision = bridge
        .mark_configuration_dirty()
        .expect("defer configuration change");

    assert_eq!(revision, 3);
    assert!(calls.lock().expect("calls lock").is_empty());
    let snapshot = bridge.snapshot();
    assert_eq!(snapshot.administrative_state, AdministrativeState::Stopped);
    assert!(snapshot.configuration_dirty);
}

#[test]
fn successful_start_consumes_a_deferred_configuration_change() {
    let bridge = LegacyControlBridge::start(
        RecordingDispatcher {
            calls: Arc::new(Mutex::new(Vec::new())),
        },
        8,
    )
    .expect("start bridge");
    bridge
        .mark_configuration_dirty()
        .expect("mark configuration dirty");

    bridge
        .submit(LegacyIntent::Running {
            reason: Reason::DisableRemoved,
        })
        .expect("accept start")
        .wait()
        .expect("start succeeds");

    assert!(!bridge.snapshot().configuration_dirty);
}

#[test]
fn configuration_change_queued_after_stop_is_deferred_in_writer_order() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let bridge = LegacyControlBridge::start(
        RecordingDispatcher {
            calls: Arc::clone(&calls),
        },
        8,
    )
    .expect("start bridge");
    let stop = bridge
        .submit(LegacyIntent::Stopped {
            reason: Reason::DisableCreated,
        })
        .expect("accept stop");

    let report = bridge
        .configuration_changed(Reason::ConfigChanged)
        .expect("handle configuration change");
    stop.wait().expect("stop succeeds");

    assert_eq!(report, ConfigurationChangeReport::Deferred { revision: 3 });
    assert_eq!(
        calls.lock().expect("calls lock").as_slice(),
        &[LegacyIntent::Stopped {
            reason: Reason::DisableCreated,
        }]
    );
    assert!(bridge.snapshot().configuration_dirty);
}

#[test]
fn accepted_administrative_intent_remains_desired_after_dispatcher_failure() {
    let bridge = LegacyControlBridge::start(FailingDispatcher, 4).expect("start bridge");

    bridge
        .submit(LegacyIntent::Running {
            reason: Reason::Boot,
        })
        .expect("accept start")
        .wait()
        .expect_err("dispatcher fails");

    let snapshot = bridge.snapshot();
    assert_eq!(snapshot.administrative_state, AdministrativeState::Running);
    assert_eq!(snapshot.in_flight, None);
    assert_eq!(snapshot.last_completed, None);
}

#[test]
fn dropping_an_operation_handle_does_not_cancel_an_accepted_intent() {
    let (completed_tx, completed_rx) = mpsc::channel();
    let dispatcher = NotifyingDispatcher { completed_tx };
    let bridge = LegacyControlBridge::start(dispatcher, 2).expect("start bridge");

    let handle = bridge
        .submit(LegacyIntent::Reload {
            reason: Reason::ConfigChanged,
        })
        .expect("accept operation");
    drop(handle);

    assert_eq!(
        completed_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("accepted intent must execute"),
        LegacyIntent::Reload {
            reason: Reason::ConfigChanged,
        }
    );
}

#[test]
fn concurrent_submissions_never_execute_more_than_one_dispatcher_call() {
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let dispatcher = ConcurrencyCheckingDispatcher {
        active: Arc::clone(&active),
        maximum: Arc::clone(&maximum),
    };
    let bridge = LegacyControlBridge::start(dispatcher, 16).expect("start bridge");

    let handles = (0..8)
        .map(|_| {
            bridge
                .submit(LegacyIntent::ResyncAddresses {
                    reason: Reason::Fluxctl,
                })
                .expect("accept operation")
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.wait().expect("dispatcher succeeds");
    }

    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(maximum.load(Ordering::SeqCst), 1);
    assert_eq!(bridge.snapshot().revision, 16);
}

#[test]
fn maintenance_and_shutdown_share_the_serialized_writer() {
    let (event_tx, event_rx) = mpsc::channel();
    let dispatcher = MaintenanceDispatcher { event_tx };
    let bridge = LegacyControlBridge::start(dispatcher, 4).expect("start bridge");

    assert_eq!(
        event_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("idle maintenance runs"),
        MaintenanceEvent::Maintained
    );

    bridge
        .submit(LegacyIntent::Running {
            reason: Reason::Fluxctl,
        })
        .expect("accept operation")
        .wait()
        .expect("dispatcher succeeds");
    loop {
        if event_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("observe execute event")
            == MaintenanceEvent::Executed
        {
            break;
        }
    }
    assert_eq!(
        event_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("maintenance follows request"),
        MaintenanceEvent::Maintained
    );

    drop(bridge);
    loop {
        if event_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("observe shutdown event")
            == MaintenanceEvent::Shutdown
        {
            break;
        }
    }
}

#[test]
fn observations_coalesce_without_blocking_or_dropping_when_the_queue_is_full() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let bridge = LegacyControlBridge::start(
        BlockingRecordingDispatcher {
            calls: Arc::clone(&calls),
            entered_tx: Some(entered_tx),
            release_rx,
        },
        1,
    )
    .expect("start bridge");
    let first = bridge
        .submit(LegacyIntent::ResyncAddresses {
            reason: Reason::Fluxctl,
        })
        .expect("accept blocking operation");
    entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("writer enters blocking operation");
    let queued = bridge
        .submit(LegacyIntent::ResyncAddresses {
            reason: Reason::Fluxctl,
        })
        .expect("fill bounded writer queue");

    let ingress = bridge.observation_ingress().expect("observation ingress");
    ingress
        .submit(ControlObservation::ConfigurationInputsChanged)
        .expect("coalesce configuration observation behind full queue");
    ingress
        .submit(ControlObservation::DisableStateChanged { disabled: true })
        .expect("coalesce initial disable observation");
    ingress
        .submit(ControlObservation::DisableStateChanged { disabled: false })
        .expect("latest disable state replaces the stale observation");

    release_tx.send(()).expect("release writer");
    first.wait().expect("first operation succeeds");
    queued.wait().expect("queued operation succeeds");

    assert_eq!(
        calls.lock().expect("calls lock").as_slice(),
        &[
            LegacyIntent::ResyncAddresses {
                reason: Reason::Fluxctl,
            },
            LegacyIntent::Running {
                reason: Reason::DisableRemoved,
            },
            LegacyIntent::ResyncAddresses {
                reason: Reason::Fluxctl,
            },
        ]
    );
    assert_eq!(
        bridge.snapshot().administrative_state,
        AdministrativeState::Running
    );
}

#[test]
fn observed_configuration_change_is_deferred_while_stopped() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let bridge = LegacyControlBridge::start(
        RecordingDispatcher {
            calls: Arc::clone(&calls),
        },
        2,
    )
    .expect("start bridge");
    bridge
        .submit(LegacyIntent::Stopped {
            reason: Reason::Fluxctl,
        })
        .expect("accept stop")
        .wait()
        .expect("stop succeeds");

    bridge
        .observation_ingress()
        .expect("observation ingress")
        .submit(ControlObservation::ConfigurationInputsChanged)
        .expect("submit asynchronous configuration observation");
    wait_until(Duration::from_secs(1), || {
        bridge.snapshot().configuration_dirty
    });

    assert_eq!(
        calls.lock().expect("calls lock").as_slice(),
        &[LegacyIntent::Stopped {
            reason: Reason::Fluxctl,
        }]
    );
}

#[test]
fn observed_configuration_consumed_by_disable_removal_notifies_the_dispatcher_once() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let consumptions = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let bridge = LegacyControlBridge::start(
        ConfigurationConsumptionDispatcher {
            calls: Arc::clone(&calls),
            consumptions: Arc::clone(&consumptions),
            entered_tx: Some(entered_tx),
            release_rx,
        },
        2,
    )
    .expect("start bridge");
    let blocking = bridge
        .submit(LegacyIntent::ResyncAddresses {
            reason: Reason::Fluxctl,
        })
        .expect("accept blocking operation");
    entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("writer enters blocking operation");

    let ingress = bridge.observation_ingress().expect("observation ingress");
    ingress
        .submit(ControlObservation::ConfigurationInputsChanged)
        .expect("record configuration observation");
    ingress
        .submit(ControlObservation::DisableStateChanged { disabled: false })
        .expect("record disable removal");
    release_tx.send(()).expect("release writer");
    blocking.wait().expect("blocking operation succeeds");
    wait_until(Duration::from_secs(1), || {
        consumptions.load(Ordering::SeqCst) == 1
    });

    assert_eq!(
        calls.lock().expect("calls lock").as_slice(),
        &[
            LegacyIntent::ResyncAddresses {
                reason: Reason::Fluxctl,
            },
            LegacyIntent::Running {
                reason: Reason::DisableRemoved,
            },
        ]
    );
    assert!(!bridge.snapshot().configuration_dirty);
    assert_eq!(consumptions.load(Ordering::SeqCst), 1);
}

struct RecordingDispatcher {
    calls: Arc<Mutex<Vec<LegacyIntent>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MaintenanceEvent {
    Executed,
    Maintained,
    Shutdown,
}

struct MaintenanceDispatcher {
    event_tx: mpsc::Sender<MaintenanceEvent>,
}

impl LegacyDispatcher for MaintenanceDispatcher {
    fn execute(&mut self, _intent: &LegacyIntent) -> Result<(), ControlError> {
        self.event_tx
            .send(MaintenanceEvent::Executed)
            .map_err(|error| ControlError::dispatcher(error.to_string()))
    }

    fn maintenance_interval(&self) -> Option<Duration> {
        Some(Duration::from_millis(5))
    }

    fn maintain(&mut self) {
        let _ = self.event_tx.send(MaintenanceEvent::Maintained);
    }

    fn shutdown(&mut self) {
        let _ = self.event_tx.send(MaintenanceEvent::Shutdown);
    }
}

impl LegacyDispatcher for RecordingDispatcher {
    fn execute(&mut self, intent: &LegacyIntent) -> Result<(), ControlError> {
        self.calls.lock().expect("calls lock").push(*intent);
        Ok(())
    }
}

struct NotifyingDispatcher {
    completed_tx: mpsc::Sender<LegacyIntent>,
}

struct BlockingRecordingDispatcher {
    calls: Arc<Mutex<Vec<LegacyIntent>>>,
    entered_tx: Option<mpsc::SyncSender<()>>,
    release_rx: mpsc::Receiver<()>,
}

struct ConfigurationConsumptionDispatcher {
    calls: Arc<Mutex<Vec<LegacyIntent>>>,
    consumptions: Arc<AtomicUsize>,
    entered_tx: Option<mpsc::SyncSender<()>>,
    release_rx: mpsc::Receiver<()>,
}

impl LegacyDispatcher for BlockingRecordingDispatcher {
    fn execute(&mut self, intent: &LegacyIntent) -> Result<(), ControlError> {
        self.calls.lock().expect("calls lock").push(*intent);
        if let Some(entered_tx) = self.entered_tx.take() {
            entered_tx
                .send(())
                .map_err(|error| ControlError::dispatcher(error.to_string()))?;
            self.release_rx
                .recv()
                .map_err(|error| ControlError::dispatcher(error.to_string()))?;
        }
        Ok(())
    }
}

impl LegacyDispatcher for ConfigurationConsumptionDispatcher {
    fn execute(&mut self, intent: &LegacyIntent) -> Result<(), ControlError> {
        self.calls.lock().expect("calls lock").push(*intent);
        if let Some(entered_tx) = self.entered_tx.take() {
            entered_tx
                .send(())
                .map_err(|error| ControlError::dispatcher(error.to_string()))?;
            self.release_rx
                .recv()
                .map_err(|error| ControlError::dispatcher(error.to_string()))?;
        }
        Ok(())
    }

    fn configuration_inputs_consumed(&mut self) {
        self.consumptions.fetch_add(1, Ordering::SeqCst);
    }
}

fn wait_until(timeout: Duration, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(Instant::now() < deadline, "condition timed out");
        thread::sleep(Duration::from_millis(2));
    }
}

impl LegacyDispatcher for NotifyingDispatcher {
    fn execute(&mut self, intent: &LegacyIntent) -> Result<(), ControlError> {
        self.completed_tx
            .send(*intent)
            .map_err(|error| ControlError::dispatcher(error.to_string()))
    }
}

struct ConcurrencyCheckingDispatcher {
    active: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
}

struct FailingDispatcher;

impl LegacyDispatcher for FailingDispatcher {
    fn execute(&mut self, _intent: &LegacyIntent) -> Result<(), ControlError> {
        Err(ControlError::dispatcher("injected failure"))
    }
}

impl LegacyDispatcher for ConcurrencyCheckingDispatcher {
    fn execute(&mut self, _intent: &LegacyIntent) -> Result<(), ControlError> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(5));
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }
}
