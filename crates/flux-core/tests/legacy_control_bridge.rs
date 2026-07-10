use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use flux_core::{
    AdministrativeState, ConfigurationChangeReport, ControlError, LegacyControlBridge,
    LegacyDispatcher, LegacyIntent, OperationReport, Reason,
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

struct RecordingDispatcher {
    calls: Arc<Mutex<Vec<LegacyIntent>>>,
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
