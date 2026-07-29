use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use flux_core::{
    AddressResyncDisposition, AdministrativeState, ConfigurationChangeReport, ControlError,
    ControlObservation, DispatcherCompletion, OperationReport, Reason, RuntimeControl,
    RuntimeDispatcher, RuntimeIntent,
};

#[test]
fn running_intent_updates_the_snapshot_after_dispatcher_success() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let dispatcher = RecordingDispatcher {
        calls: Arc::clone(&calls),
    };
    let runtime = RuntimeControl::start(dispatcher, 8).expect("start runtime");

    let report = runtime
        .submit(RuntimeIntent::Running {
            reason: Reason::UserControl,
        })
        .expect("accept operation")
        .wait()
        .expect("dispatcher succeeds");

    assert_eq!(
        report,
        OperationReport {
            intent: RuntimeIntent::Running {
                reason: Reason::UserControl,
            },
            revision: 2,
            address_resync: None,
        }
    );
    assert_eq!(
        calls.lock().expect("calls lock").as_slice(),
        &[RuntimeIntent::Running {
            reason: Reason::UserControl,
        }]
    );

    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.revision, 2);
    assert_eq!(snapshot.administrative_state, AdministrativeState::Running);
    assert!(!snapshot.configuration_dirty);
    assert_eq!(snapshot.in_flight, None);
    assert_eq!(snapshot.last_completed, Some(report));
}

#[test]
fn configuration_change_while_stopped_is_deferred_without_calling_the_dispatcher() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let runtime = RuntimeControl::start(
        RecordingDispatcher {
            calls: Arc::clone(&calls),
        },
        8,
    )
    .expect("start runtime");
    runtime
        .submit(RuntimeIntent::Stopped {
            reason: Reason::UserControl,
        })
        .expect("accept stop")
        .wait()
        .expect("stop succeeds");
    calls.lock().expect("calls lock").clear();

    let revision = runtime
        .mark_configuration_dirty()
        .expect("defer configuration change");

    assert_eq!(revision, 3);
    assert!(calls.lock().expect("calls lock").is_empty());
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.administrative_state, AdministrativeState::Stopped);
    assert!(snapshot.configuration_dirty);
}

#[test]
fn successful_start_consumes_a_deferred_configuration_change() {
    let runtime = RuntimeControl::start(
        RecordingDispatcher {
            calls: Arc::new(Mutex::new(Vec::new())),
        },
        8,
    )
    .expect("start runtime");
    runtime
        .mark_configuration_dirty()
        .expect("mark configuration dirty");

    runtime
        .submit(RuntimeIntent::Running {
            reason: Reason::DisableRemoved,
        })
        .expect("accept start")
        .wait()
        .expect("start succeeds");

    assert!(!runtime.snapshot().configuration_dirty);
}

#[test]
fn configuration_change_queued_after_stop_is_deferred_in_writer_order() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let runtime = RuntimeControl::start(
        RecordingDispatcher {
            calls: Arc::clone(&calls),
        },
        8,
    )
    .expect("start runtime");
    let stop = runtime
        .submit(RuntimeIntent::Stopped {
            reason: Reason::DisableCreated,
        })
        .expect("accept stop");

    let report = runtime
        .configuration_changed(Reason::ConfigChanged)
        .expect("handle configuration change");
    stop.wait().expect("stop succeeds");

    assert_eq!(report, ConfigurationChangeReport::Deferred { revision: 3 });
    assert_eq!(
        calls.lock().expect("calls lock").as_slice(),
        &[RuntimeIntent::Stopped {
            reason: Reason::DisableCreated,
        }]
    );
    assert!(runtime.snapshot().configuration_dirty);
}

#[test]
fn automation_maintenance_queued_after_stop_cannot_reactivate_the_runtime() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let runtime = RuntimeControl::start(
        BlockingRecordingDispatcher {
            calls: Arc::clone(&calls),
            entered_tx: Some(entered_tx),
            release_rx,
        },
        3,
    )
    .expect("start runtime");
    let running = runtime
        .submit(RuntimeIntent::Running {
            reason: Reason::Boot,
        })
        .expect("accept blocking start");
    entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("start enters the serialized dispatcher");
    let stop = runtime
        .submit(RuntimeIntent::Stopped {
            reason: Reason::UserControl,
        })
        .expect("queue stop");
    let automation_reload = runtime
        .submit(RuntimeIntent::Reload {
            reason: Reason::Automation,
        })
        .expect("queue automation reload behind stop");
    let automation_resync = runtime
        .submit(RuntimeIntent::ResyncAddresses {
            reason: Reason::Automation,
        })
        .expect("queue automation resync behind stop");

    release_tx.send(()).expect("release start");
    running.wait().expect("start succeeds");
    stop.wait().expect("stop succeeds");
    let reload_error = automation_reload
        .wait()
        .expect_err("serialized stop must reject later automation reload");
    let resync_error = automation_resync
        .wait()
        .expect_err("serialized stop must reject later automation resync");

    assert_eq!(
        reload_error.rejection_code(),
        Some("automation_runtime_not_running")
    );
    assert_eq!(
        resync_error.rejection_code(),
        Some("automation_runtime_not_running")
    );
    assert_eq!(
        calls.lock().expect("calls lock").as_slice(),
        &[
            RuntimeIntent::Running {
                reason: Reason::Boot,
            },
            RuntimeIntent::Stopped {
                reason: Reason::UserControl,
            },
        ]
    );
    assert_eq!(
        runtime.snapshot().administrative_state,
        AdministrativeState::Stopped
    );
}

#[test]
fn accepted_administrative_intent_remains_desired_after_dispatcher_failure() {
    let runtime = RuntimeControl::start(FailingDispatcher, 4).expect("start runtime");

    runtime
        .submit(RuntimeIntent::Running {
            reason: Reason::Boot,
        })
        .expect("accept start")
        .wait()
        .expect_err("dispatcher fails");

    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.administrative_state, AdministrativeState::Running);
    assert_eq!(snapshot.in_flight, None);
    assert_eq!(snapshot.last_completed, None);
}

#[test]
fn dropping_an_operation_handle_does_not_cancel_an_accepted_intent() {
    let (completed_tx, completed_rx) = mpsc::channel();
    let dispatcher = NotifyingDispatcher { completed_tx };
    let runtime = RuntimeControl::start(dispatcher, 2).expect("start runtime");

    let handle = runtime
        .submit(RuntimeIntent::Reload {
            reason: Reason::ConfigChanged,
        })
        .expect("accept operation");
    drop(handle);

    assert_eq!(
        completed_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("accepted intent must execute"),
        RuntimeIntent::Reload {
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
    let runtime = RuntimeControl::start(dispatcher, 16).expect("start runtime");

    let handles = (0..8)
        .map(|_| {
            runtime
                .submit(RuntimeIntent::ResyncAddresses {
                    reason: Reason::UserControl,
                })
                .expect("accept operation")
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.wait().expect("dispatcher succeeds");
    }

    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(maximum.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.snapshot().revision, 16);
}

#[test]
fn maintenance_and_shutdown_share_the_serialized_writer() {
    let (event_tx, event_rx) = mpsc::channel();
    let dispatcher = MaintenanceDispatcher { event_tx };
    let runtime = RuntimeControl::start(dispatcher, 4).expect("start runtime");

    assert_eq!(
        event_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("idle maintenance runs"),
        MaintenanceEvent::Maintained
    );

    runtime
        .submit(RuntimeIntent::Running {
            reason: Reason::UserControl,
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

    drop(runtime);
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
    let runtime = RuntimeControl::start(
        BlockingRecordingDispatcher {
            calls: Arc::clone(&calls),
            entered_tx: Some(entered_tx),
            release_rx,
        },
        1,
    )
    .expect("start runtime");
    let first = runtime
        .submit(RuntimeIntent::ResyncAddresses {
            reason: Reason::UserControl,
        })
        .expect("accept blocking operation");
    entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("writer enters blocking operation");
    let queued = runtime
        .submit(RuntimeIntent::ResyncAddresses {
            reason: Reason::UserControl,
        })
        .expect("fill bounded writer queue");

    let ingress = runtime.observation_ingress().expect("observation ingress");
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
            RuntimeIntent::ResyncAddresses {
                reason: Reason::UserControl,
            },
            RuntimeIntent::Running {
                reason: Reason::DisableRemoved,
            },
            RuntimeIntent::ResyncAddresses {
                reason: Reason::UserControl,
            },
        ]
    );
    assert_eq!(
        runtime.snapshot().administrative_state,
        AdministrativeState::Running
    );
}

#[test]
fn observed_configuration_change_is_deferred_while_stopped() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let runtime = RuntimeControl::start(
        RecordingDispatcher {
            calls: Arc::clone(&calls),
        },
        2,
    )
    .expect("start runtime");
    runtime
        .submit(RuntimeIntent::Stopped {
            reason: Reason::UserControl,
        })
        .expect("accept stop")
        .wait()
        .expect("stop succeeds");

    runtime
        .observation_ingress()
        .expect("observation ingress")
        .submit(ControlObservation::ConfigurationInputsChanged)
        .expect("submit asynchronous configuration observation");
    wait_until(Duration::from_secs(1), || {
        runtime.snapshot().configuration_dirty
    });

    assert_eq!(
        calls.lock().expect("calls lock").as_slice(),
        &[RuntimeIntent::Stopped {
            reason: Reason::UserControl,
        }]
    );
}

#[test]
fn observed_configuration_consumed_by_disable_removal_notifies_the_dispatcher_once() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let consumptions = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let runtime = RuntimeControl::start(
        ConfigurationConsumptionDispatcher {
            calls: Arc::clone(&calls),
            consumptions: Arc::clone(&consumptions),
            entered_tx: Some(entered_tx),
            release_rx,
        },
        2,
    )
    .expect("start runtime");
    let blocking = runtime
        .submit(RuntimeIntent::ResyncAddresses {
            reason: Reason::UserControl,
        })
        .expect("accept blocking operation");
    entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("writer enters blocking operation");

    let ingress = runtime.observation_ingress().expect("observation ingress");
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
            RuntimeIntent::ResyncAddresses {
                reason: Reason::UserControl,
            },
            RuntimeIntent::Running {
                reason: Reason::DisableRemoved,
            },
        ]
    );
    assert!(!runtime.snapshot().configuration_dirty);
    assert_eq!(consumptions.load(Ordering::SeqCst), 1);
}

struct RecordingDispatcher {
    calls: Arc<Mutex<Vec<RuntimeIntent>>>,
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

impl RuntimeDispatcher for MaintenanceDispatcher {
    fn execute(&mut self, intent: &RuntimeIntent) -> Result<DispatcherCompletion, ControlError> {
        self.event_tx
            .send(MaintenanceEvent::Executed)
            .map_err(|error| ControlError::dispatcher(error.to_string()))
            .map(|()| completion_for(intent))
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

impl RuntimeDispatcher for RecordingDispatcher {
    fn execute(&mut self, intent: &RuntimeIntent) -> Result<DispatcherCompletion, ControlError> {
        self.calls.lock().expect("calls lock").push(*intent);
        Ok(completion_for(intent))
    }
}

struct NotifyingDispatcher {
    completed_tx: mpsc::Sender<RuntimeIntent>,
}

struct BlockingRecordingDispatcher {
    calls: Arc<Mutex<Vec<RuntimeIntent>>>,
    entered_tx: Option<mpsc::SyncSender<()>>,
    release_rx: mpsc::Receiver<()>,
}

struct ConfigurationConsumptionDispatcher {
    calls: Arc<Mutex<Vec<RuntimeIntent>>>,
    consumptions: Arc<AtomicUsize>,
    entered_tx: Option<mpsc::SyncSender<()>>,
    release_rx: mpsc::Receiver<()>,
}

impl RuntimeDispatcher for BlockingRecordingDispatcher {
    fn execute(&mut self, intent: &RuntimeIntent) -> Result<DispatcherCompletion, ControlError> {
        self.calls.lock().expect("calls lock").push(*intent);
        if let Some(entered_tx) = self.entered_tx.take() {
            entered_tx
                .send(())
                .map_err(|error| ControlError::dispatcher(error.to_string()))?;
            self.release_rx
                .recv()
                .map_err(|error| ControlError::dispatcher(error.to_string()))?;
        }
        Ok(completion_for(intent))
    }
}

impl RuntimeDispatcher for ConfigurationConsumptionDispatcher {
    fn execute(&mut self, intent: &RuntimeIntent) -> Result<DispatcherCompletion, ControlError> {
        self.calls.lock().expect("calls lock").push(*intent);
        if let Some(entered_tx) = self.entered_tx.take() {
            entered_tx
                .send(())
                .map_err(|error| ControlError::dispatcher(error.to_string()))?;
            self.release_rx
                .recv()
                .map_err(|error| ControlError::dispatcher(error.to_string()))?;
        }
        Ok(completion_for(intent))
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

impl RuntimeDispatcher for NotifyingDispatcher {
    fn execute(&mut self, intent: &RuntimeIntent) -> Result<DispatcherCompletion, ControlError> {
        self.completed_tx
            .send(*intent)
            .map_err(|error| ControlError::dispatcher(error.to_string()))
            .map(|()| completion_for(intent))
    }
}

struct ConcurrencyCheckingDispatcher {
    active: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
}

struct FailingDispatcher;

impl RuntimeDispatcher for FailingDispatcher {
    fn execute(&mut self, _intent: &RuntimeIntent) -> Result<DispatcherCompletion, ControlError> {
        Err(ControlError::dispatcher("injected failure"))
    }
}

impl RuntimeDispatcher for ConcurrencyCheckingDispatcher {
    fn execute(&mut self, intent: &RuntimeIntent) -> Result<DispatcherCompletion, ControlError> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(5));
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(completion_for(intent))
    }
}

fn completion_for(intent: &RuntimeIntent) -> DispatcherCompletion {
    match intent {
        RuntimeIntent::ResyncAddresses { .. } => {
            DispatcherCompletion::AddressResync(AddressResyncDisposition::CompleteNoChange)
        }
        RuntimeIntent::Running { .. }
        | RuntimeIntent::Stopped { .. }
        | RuntimeIntent::Reload { .. } => DispatcherCompletion::Completed,
    }
}
