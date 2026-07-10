use std::error::Error;
use std::fmt;
use std::sync::{Arc, RwLock, mpsc};
use std::thread::{self, JoinHandle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    Boot,
    Fluxctl,
    ConfigChanged,
    DisableCreated,
    DisableRemoved,
    EngineExited,
    DaemonRecovery,
}

impl Reason {
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Fluxctl => "fluxctl",
            Self::ConfigChanged => "config_changed",
            Self::DisableCreated => "disable_created",
            Self::DisableRemoved => "disable_removed",
            Self::EngineExited => "engine_exited",
            Self::DaemonRecovery => "daemon_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyIntent {
    Running { reason: Reason },
    Stopped { reason: Reason },
    Reload { reason: Reason },
    ResyncAddresses { reason: Reason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdministrativeState {
    Unknown,
    Running,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationReport {
    pub intent: LegacyIntent,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlSnapshot {
    pub revision: u64,
    pub administrative_state: AdministrativeState,
    pub in_flight: Option<LegacyIntent>,
    pub last_completed: Option<OperationReport>,
}

impl Default for ControlSnapshot {
    fn default() -> Self {
        Self {
            revision: 0,
            administrative_state: AdministrativeState::Unknown,
            in_flight: None,
            last_completed: None,
        }
    }
}

pub trait LegacyDispatcher: Send + 'static {
    fn execute(&mut self, intent: &LegacyIntent) -> Result<(), ControlError>;
}

pub trait ControlClient {
    fn submit_and_wait(&self, intent: LegacyIntent) -> Result<OperationReport, ControlError>;
}

pub struct LegacyControlBridge {
    sender: Option<mpsc::SyncSender<WorkerRequest>>,
    snapshot: Arc<RwLock<Arc<ControlSnapshot>>>,
    worker: Option<JoinHandle<()>>,
}

impl LegacyControlBridge {
    pub fn start<D>(dispatcher: D, queue_capacity: usize) -> Result<Self, ControlError>
    where
        D: LegacyDispatcher,
    {
        if queue_capacity == 0 {
            return Err(ControlError::InvalidQueueCapacity);
        }

        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let snapshot = Arc::new(RwLock::new(Arc::new(ControlSnapshot::default())));
        let worker_snapshot = Arc::clone(&snapshot);
        let worker = thread::Builder::new()
            .name("flux-legacy-writer".to_owned())
            .spawn(move || worker_loop(dispatcher, receiver, &worker_snapshot))
            .map_err(|error| ControlError::WorkerStart(error.to_string()))?;

        Ok(Self {
            sender: Some(sender),
            snapshot,
            worker: Some(worker),
        })
    }

    pub fn submit(&self, intent: LegacyIntent) -> Result<OperationHandle, ControlError> {
        let sender = self.sender.as_ref().ok_or(ControlError::BridgeStopped)?;
        let (completion_tx, completion_rx) = mpsc::channel();
        sender
            .try_send(WorkerRequest {
                intent,
                completion_tx,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => ControlError::QueueFull,
                mpsc::TrySendError::Disconnected(_) => ControlError::BridgeStopped,
            })?;
        Ok(OperationHandle {
            completion_rx: Some(completion_rx),
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<ControlSnapshot> {
        match self.snapshot.read() {
            Ok(snapshot) => Arc::clone(&snapshot),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }
}

impl ControlClient for LegacyControlBridge {
    fn submit_and_wait(&self, intent: LegacyIntent) -> Result<OperationReport, ControlError> {
        self.submit(intent)?.wait()
    }
}

impl Drop for LegacyControlBridge {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub struct OperationHandle {
    completion_rx: Option<mpsc::Receiver<Result<OperationReport, ControlError>>>,
}

impl OperationHandle {
    pub fn wait(mut self) -> Result<OperationReport, ControlError> {
        let receiver = self
            .completion_rx
            .take()
            .ok_or(ControlError::OperationAlreadyConsumed)?;
        receiver.recv().map_err(|_| ControlError::BridgeStopped)?
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlError {
    InvalidQueueCapacity,
    QueueFull,
    BridgeStopped,
    OperationAlreadyConsumed,
    WorkerStart(String),
    Dispatcher(String),
}

impl ControlError {
    #[must_use]
    pub fn dispatcher(message: impl Into<String>) -> Self {
        Self::Dispatcher(message.into())
    }
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQueueCapacity => {
                formatter.write_str("legacy writer queue capacity must be greater than zero")
            }
            Self::QueueFull => formatter.write_str("legacy writer queue is full"),
            Self::BridgeStopped => formatter.write_str("legacy control bridge is stopped"),
            Self::OperationAlreadyConsumed => {
                formatter.write_str("operation result was already consumed")
            }
            Self::WorkerStart(message) => {
                write!(formatter, "cannot start legacy writer: {message}")
            }
            Self::Dispatcher(message) => write!(formatter, "legacy dispatcher failed: {message}"),
        }
    }
}

impl Error for ControlError {}

struct WorkerRequest {
    intent: LegacyIntent,
    completion_tx: mpsc::Sender<Result<OperationReport, ControlError>>,
}

fn worker_loop<D>(
    mut dispatcher: D,
    receiver: mpsc::Receiver<WorkerRequest>,
    snapshot: &RwLock<Arc<ControlSnapshot>>,
) where
    D: LegacyDispatcher,
{
    while let Ok(request) = receiver.recv() {
        let started = replace_snapshot(snapshot, |current| ControlSnapshot {
            revision: current.revision.saturating_add(1),
            administrative_state: current.administrative_state,
            in_flight: Some(request.intent),
            last_completed: current.last_completed,
        });

        let result = dispatcher.execute(&request.intent);
        let completed_revision = started.revision.saturating_add(1);
        let operation = result.map(|()| OperationReport {
            intent: request.intent,
            revision: completed_revision,
        });

        replace_snapshot(snapshot, |current| ControlSnapshot {
            revision: completed_revision,
            administrative_state: operation
                .as_ref()
                .map_or(current.administrative_state, |report| {
                    next_administrative_state(current.administrative_state, report.intent)
                }),
            in_flight: None,
            last_completed: operation.as_ref().ok().copied().or(current.last_completed),
        });

        let _ = request.completion_tx.send(operation);
    }
}

fn replace_snapshot(
    snapshot: &RwLock<Arc<ControlSnapshot>>,
    update: impl FnOnce(&ControlSnapshot) -> ControlSnapshot,
) -> Arc<ControlSnapshot> {
    let mut current = match snapshot.write() {
        Ok(current) => current,
        Err(poisoned) => poisoned.into_inner(),
    };
    let next = Arc::new(update(&current));
    *current = Arc::clone(&next);
    next
}

const fn next_administrative_state(
    current: AdministrativeState,
    intent: LegacyIntent,
) -> AdministrativeState {
    match intent {
        LegacyIntent::Running { .. } => AdministrativeState::Running,
        LegacyIntent::Stopped { .. } => AdministrativeState::Stopped,
        LegacyIntent::Reload { .. } | LegacyIntent::ResyncAddresses { .. } => current,
    }
}
