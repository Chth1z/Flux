use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    Boot,
    UserControl,
    ConfigChanged,
    DisableCreated,
    DisableRemoved,
    EngineExited,
    DaemonRecovery,
    Automation,
}

impl Reason {
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::UserControl => "user_control",
            Self::ConfigChanged => "config_changed",
            Self::DisableCreated => "disable_created",
            Self::DisableRemoved => "disable_removed",
            Self::EngineExited => "engine_exited",
            Self::DaemonRecovery => "daemon_recovery",
            Self::Automation => "automation",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeIntent {
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
    pub intent: RuntimeIntent,
    pub revision: u64,
    pub address_resync: Option<AddressResyncDisposition>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressResyncDisposition {
    CompleteNoChange,
    SuccessorConverged,
    AcceptedDeferred,
}

impl AddressResyncDisposition {
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::CompleteNoChange => "complete_no_change",
            Self::SuccessorConverged => "successor_converged",
            Self::AcceptedDeferred => "accepted_deferred",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatcherCompletion {
    Completed,
    AddressResync(AddressResyncDisposition),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationChangeReport {
    Reloaded(OperationReport),
    Deferred { revision: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlObservation {
    ConfigurationInputsChanged,
    DisableStateChanged { disabled: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlSnapshot {
    pub revision: u64,
    pub administrative_state: AdministrativeState,
    pub configuration_dirty: bool,
    pub in_flight: Option<RuntimeIntent>,
    pub last_completed: Option<OperationReport>,
}

impl Default for ControlSnapshot {
    fn default() -> Self {
        Self {
            revision: 0,
            administrative_state: AdministrativeState::Unknown,
            configuration_dirty: false,
            in_flight: None,
            last_completed: None,
        }
    }
}

pub trait RuntimeDispatcher: Send + 'static {
    fn execute(&mut self, intent: &RuntimeIntent) -> Result<DispatcherCompletion, ControlError>;

    fn observation_failed(&mut self, _observation: ControlObservation, _error: &ControlError) {}

    fn configuration_inputs_consumed(&mut self) {}

    fn maintenance_interval(&self) -> Option<Duration> {
        None
    }

    fn maintain(&mut self) {}

    fn shutdown(&mut self) {}
}

pub trait ControlClient {
    fn submit_and_wait(&self, intent: RuntimeIntent) -> Result<OperationReport, ControlError>;
}

pub trait ControlSnapshotSource {
    #[must_use]
    fn snapshot(&self) -> Arc<ControlSnapshot>;
}

pub trait ConfigurationChangeClient {
    fn configuration_changed(
        &self,
        reason: Reason,
    ) -> Result<ConfigurationChangeReport, ControlError>;
}

pub trait ControlService:
    ControlClient + ControlSnapshotSource + ConfigurationChangeClient
{
}

impl<T> ControlService for T where
    T: ControlClient + ControlSnapshotSource + ConfigurationChangeClient
{
}

pub struct RuntimeControl {
    sender: Option<mpsc::SyncSender<WorkerRequest>>,
    observations: Arc<Mutex<PendingControlObservations>>,
    snapshot: Arc<RwLock<Arc<ControlSnapshot>>>,
    worker: Option<JoinHandle<()>>,
}

impl RuntimeControl {
    pub fn start<D>(dispatcher: D, queue_capacity: usize) -> Result<Self, ControlError>
    where
        D: RuntimeDispatcher,
    {
        if queue_capacity == 0 {
            return Err(ControlError::InvalidQueueCapacity);
        }

        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let observations = Arc::new(Mutex::new(PendingControlObservations::default()));
        let worker_observations = Arc::clone(&observations);
        let snapshot = Arc::new(RwLock::new(Arc::new(ControlSnapshot::default())));
        let worker_snapshot = Arc::clone(&snapshot);
        let worker = thread::Builder::new()
            .name("flux-runtime-control".to_owned())
            .spawn(move || {
                worker_loop(dispatcher, receiver, &worker_observations, &worker_snapshot);
            })
            .map_err(|error| ControlError::WorkerStart(error.to_string()))?;

        Ok(Self {
            sender: Some(sender),
            observations,
            snapshot,
            worker: Some(worker),
        })
    }

    pub fn submit(&self, intent: RuntimeIntent) -> Result<OperationHandle, ControlError> {
        let sender = self.sender.as_ref().ok_or(ControlError::RuntimeStopped)?;
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        sender
            .try_send(WorkerRequest::Execute {
                intent,
                completion_tx,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => ControlError::QueueFull,
                mpsc::TrySendError::Disconnected(_) => ControlError::RuntimeStopped,
            })?;
        Ok(OperationHandle {
            completion_rx: Some(completion_rx),
        })
    }

    pub fn mark_configuration_dirty(&self) -> Result<u64, ControlError> {
        let sender = self.sender.as_ref().ok_or(ControlError::RuntimeStopped)?;
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        sender
            .try_send(WorkerRequest::MarkConfigurationDirty { completion_tx })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => ControlError::QueueFull,
                mpsc::TrySendError::Disconnected(_) => ControlError::RuntimeStopped,
            })?;
        completion_rx
            .recv()
            .map_err(|_| ControlError::RuntimeStopped)?
    }

    pub fn configuration_changed(
        &self,
        reason: Reason,
    ) -> Result<ConfigurationChangeReport, ControlError> {
        let sender = self.sender.as_ref().ok_or(ControlError::RuntimeStopped)?;
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        sender
            .try_send(WorkerRequest::ConfigurationChanged {
                reason,
                completion_tx,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => ControlError::QueueFull,
                mpsc::TrySendError::Disconnected(_) => ControlError::RuntimeStopped,
            })?;
        completion_rx
            .recv()
            .map_err(|_| ControlError::RuntimeStopped)?
    }

    pub fn observation_ingress(&self) -> Result<ControlObservationIngress, ControlError> {
        Ok(ControlObservationIngress {
            sender: self
                .sender
                .as_ref()
                .ok_or(ControlError::RuntimeStopped)?
                .clone(),
            pending: Arc::clone(&self.observations),
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

impl ControlClient for RuntimeControl {
    fn submit_and_wait(&self, intent: RuntimeIntent) -> Result<OperationReport, ControlError> {
        self.submit(intent)?.wait()
    }
}

impl ControlSnapshotSource for RuntimeControl {
    fn snapshot(&self) -> Arc<ControlSnapshot> {
        RuntimeControl::snapshot(self)
    }
}

impl ConfigurationChangeClient for RuntimeControl {
    fn configuration_changed(
        &self,
        reason: Reason,
    ) -> Result<ConfigurationChangeReport, ControlError> {
        RuntimeControl::configuration_changed(self, reason)
    }
}

impl Drop for RuntimeControl {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(WorkerRequest::Shutdown);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Clone)]
pub struct ControlObservationIngress {
    sender: mpsc::SyncSender<WorkerRequest>,
    pending: Arc<Mutex<PendingControlObservations>>,
}

impl ControlObservationIngress {
    pub fn submit(&self, observation: ControlObservation) -> Result<(), ControlError> {
        let should_wake = {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.record(observation);
            let should_wake = !pending.wake_owed;
            pending.wake_owed = true;
            should_wake
        };
        if !should_wake {
            return Ok(());
        }

        match self.sender.try_send(WorkerRequest::ObservationsReady) {
            Ok(()) | Err(mpsc::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(ControlError::RuntimeStopped),
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
        receiver.recv().map_err(|_| ControlError::RuntimeStopped)?
    }
}

#[derive(Clone, Debug)]
pub enum ControlError {
    InvalidQueueCapacity,
    QueueFull,
    RuntimeStopped,
    OperationAlreadyConsumed,
    WorkerStart(String),
    Persistence {
        operation: &'static str,
        source: Arc<dyn Error + Send + Sync>,
        recovery: &'static str,
    },
    Runtime {
        operation: &'static str,
        source: Arc<dyn Error + Send + Sync>,
        recovery: &'static str,
    },
    RequestRejected {
        code: String,
        message: String,
    },
    Protocol(String),
    Transport(String),
    Dispatcher(String),
}

impl ControlError {
    #[must_use]
    pub fn dispatcher(message: impl Into<String>) -> Self {
        Self::Dispatcher(message.into())
    }

    #[must_use]
    pub fn persistence<E>(operation: &'static str, source: E, recovery: &'static str) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::Persistence {
            operation,
            source: Arc::new(source),
            recovery,
        }
    }

    #[must_use]
    pub fn runtime<E>(operation: &'static str, source: E, recovery: &'static str) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::Runtime {
            operation,
            source: Arc::new(source),
            recovery,
        }
    }

    #[must_use]
    pub fn request_rejected(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::RequestRejected {
            code: code.into(),
            message: message.into(),
        }
    }

    #[must_use]
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    #[must_use]
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport(message.into())
    }

    #[must_use]
    pub fn rejection_code(&self) -> Option<&str> {
        match self {
            Self::RequestRejected { code, .. } => Some(code),
            Self::InvalidQueueCapacity
            | Self::QueueFull
            | Self::RuntimeStopped
            | Self::OperationAlreadyConsumed
            | Self::WorkerStart(_)
            | Self::Persistence { .. }
            | Self::Runtime { .. }
            | Self::Protocol(_)
            | Self::Transport(_)
            | Self::Dispatcher(_) => None,
        }
    }
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQueueCapacity => {
                formatter.write_str("runtime control queue capacity must be greater than zero")
            }
            Self::QueueFull => formatter.write_str("runtime control queue is full"),
            Self::RuntimeStopped => formatter.write_str("runtime control is stopped"),
            Self::OperationAlreadyConsumed => {
                formatter.write_str("operation result was already consumed")
            }
            Self::WorkerStart(message) => {
                write!(formatter, "cannot start runtime control worker: {message}")
            }
            Self::Persistence {
                operation,
                source,
                recovery,
            } => write!(
                formatter,
                "cannot persist control state during {operation}: {source}; recovery: {recovery}"
            ),
            Self::Runtime {
                operation,
                source,
                recovery,
            } => write!(
                formatter,
                "runtime reconciliation failed during {operation}: {source}; recovery: {recovery}"
            ),
            Self::RequestRejected { code, message } => {
                write!(formatter, "control request rejected ({code}): {message}")
            }
            Self::Protocol(message) => write!(formatter, "control protocol: {message}"),
            Self::Transport(message) => write!(formatter, "control transport: {message}"),
            Self::Dispatcher(message) => write!(formatter, "runtime dispatcher failed: {message}"),
        }
    }
}

impl Error for ControlError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Persistence { source, .. } | Self::Runtime { source, .. } => {
                Some(source.as_ref())
            }
            Self::InvalidQueueCapacity
            | Self::QueueFull
            | Self::RuntimeStopped
            | Self::OperationAlreadyConsumed
            | Self::WorkerStart(_)
            | Self::RequestRejected { .. }
            | Self::Protocol(_)
            | Self::Transport(_)
            | Self::Dispatcher(_) => None,
        }
    }
}

enum WorkerRequest {
    Execute {
        intent: RuntimeIntent,
        completion_tx: mpsc::SyncSender<Result<OperationReport, ControlError>>,
    },
    MarkConfigurationDirty {
        completion_tx: mpsc::SyncSender<Result<u64, ControlError>>,
    },
    ConfigurationChanged {
        reason: Reason,
        completion_tx: mpsc::SyncSender<Result<ConfigurationChangeReport, ControlError>>,
    },
    ObservationsReady,
    Shutdown,
}

#[derive(Default)]
struct PendingControlObservations {
    configuration_inputs_changed: bool,
    disable_state: Option<bool>,
    wake_owed: bool,
}

impl PendingControlObservations {
    fn record(&mut self, observation: ControlObservation) {
        match observation {
            ControlObservation::ConfigurationInputsChanged => {
                self.configuration_inputs_changed = true;
            }
            ControlObservation::DisableStateChanged { disabled } => {
                self.disable_state = Some(disabled);
            }
        }
    }

    fn take(&mut self) -> ControlObservationBatch {
        let batch = ControlObservationBatch {
            configuration_inputs_changed: self.configuration_inputs_changed,
            disable_state: self.disable_state.take(),
        };
        self.configuration_inputs_changed = false;
        self.wake_owed = false;
        batch
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ControlObservationBatch {
    configuration_inputs_changed: bool,
    disable_state: Option<bool>,
}

fn worker_loop<D>(
    mut dispatcher: D,
    receiver: mpsc::Receiver<WorkerRequest>,
    observations: &Mutex<PendingControlObservations>,
    snapshot: &RwLock<Arc<ControlSnapshot>>,
) where
    D: RuntimeDispatcher,
{
    let maintenance_interval = dispatcher
        .maintenance_interval()
        .filter(|interval| !interval.is_zero());
    loop {
        let request = match maintenance_interval {
            Some(interval) => match receiver.recv_timeout(interval) {
                Ok(request) => Some(request),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    drain_control_observations(&mut dispatcher, observations, snapshot);
                    dispatcher.maintain();
                    None
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    drain_control_observations(&mut dispatcher, observations, snapshot);
                    break;
                }
            },
            None => match receiver.recv() {
                Ok(request) => Some(request),
                Err(_) => {
                    drain_control_observations(&mut dispatcher, observations, snapshot);
                    break;
                }
            },
        };
        let Some(request) = request else {
            continue;
        };
        let shutdown = matches!(request, WorkerRequest::Shutdown);
        match request {
            WorkerRequest::Execute {
                intent,
                completion_tx,
            } => {
                let _ = completion_tx.send(execute_intent(&mut dispatcher, snapshot, intent));
            }
            WorkerRequest::MarkConfigurationDirty { completion_tx } => {
                let _ = completion_tx.send(Ok(mark_dirty(snapshot)));
            }
            WorkerRequest::ConfigurationChanged {
                reason,
                completion_tx,
            } => {
                let result = apply_configuration_change(&mut dispatcher, snapshot, reason);
                let _ = completion_tx.send(result);
            }
            WorkerRequest::ObservationsReady | WorkerRequest::Shutdown => {}
        }
        drain_control_observations(&mut dispatcher, observations, snapshot);
        if shutdown {
            break;
        }
        dispatcher.maintain();
    }
    dispatcher.shutdown();
}

fn drain_control_observations<D>(
    dispatcher: &mut D,
    observations: &Mutex<PendingControlObservations>,
    snapshot: &RwLock<Arc<ControlSnapshot>>,
) where
    D: RuntimeDispatcher,
{
    let pending = observations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let mut configuration_consumed = false;

    if pending.configuration_inputs_changed && pending.disable_state == Some(false) {
        mark_dirty(snapshot);
    }

    if let Some(disabled) = pending.disable_state {
        let observation = ControlObservation::DisableStateChanged { disabled };
        let intent = if disabled {
            RuntimeIntent::Stopped {
                reason: Reason::DisableCreated,
            }
        } else {
            RuntimeIntent::Running {
                reason: Reason::DisableRemoved,
            }
        };
        match execute_intent(dispatcher, snapshot, intent) {
            Ok(_) if !disabled => configuration_consumed = true,
            Ok(_) => {}
            Err(error) => dispatcher.observation_failed(observation, &error),
        }
    }

    if pending.configuration_inputs_changed && !configuration_consumed {
        let observation = ControlObservation::ConfigurationInputsChanged;
        if let Err(error) = apply_configuration_change(dispatcher, snapshot, Reason::ConfigChanged)
        {
            dispatcher.observation_failed(observation, &error);
        }
    }
}

fn apply_configuration_change<D>(
    dispatcher: &mut D,
    snapshot: &RwLock<Arc<ControlSnapshot>>,
    reason: Reason,
) -> Result<ConfigurationChangeReport, ControlError>
where
    D: RuntimeDispatcher,
{
    if read_snapshot(snapshot).administrative_state == AdministrativeState::Running {
        execute_intent(dispatcher, snapshot, RuntimeIntent::Reload { reason })
            .map(ConfigurationChangeReport::Reloaded)
    } else {
        Ok(ConfigurationChangeReport::Deferred {
            revision: mark_dirty(snapshot),
        })
    }
}

fn execute_intent<D>(
    dispatcher: &mut D,
    snapshot: &RwLock<Arc<ControlSnapshot>>,
    intent: RuntimeIntent,
) -> Result<OperationReport, ControlError>
where
    D: RuntimeDispatcher,
{
    if matches!(
        intent,
        RuntimeIntent::Reload {
            reason: Reason::Automation
        } | RuntimeIntent::ResyncAddresses {
            reason: Reason::Automation
        }
    ) && read_snapshot(snapshot).administrative_state != AdministrativeState::Running
    {
        return Err(ControlError::request_rejected(
            "automation_runtime_not_running",
            "automation maintenance requires running administrative intent",
        ));
    }
    let started = replace_snapshot(snapshot, |current| ControlSnapshot {
        revision: current.revision.saturating_add(1),
        administrative_state: next_administrative_state(current.administrative_state, intent),
        configuration_dirty: current.configuration_dirty,
        in_flight: Some(intent),
        last_completed: current.last_completed,
    });
    let configuration_was_dirty = started.configuration_dirty;

    let result = dispatcher.execute(&intent).and_then(|completion| {
        let valid = matches!(
            (intent, completion),
            (
                RuntimeIntent::ResyncAddresses { .. },
                DispatcherCompletion::AddressResync(_)
            ) | (
                RuntimeIntent::Running { .. }
                    | RuntimeIntent::Stopped { .. }
                    | RuntimeIntent::Reload { .. },
                DispatcherCompletion::Completed
            )
        );
        if valid {
            Ok(completion)
        } else {
            Err(ControlError::dispatcher(
                "dispatcher returned a completion that does not match the requested intent",
            ))
        }
    });
    if result.is_ok() && configuration_was_dirty && matches!(intent, RuntimeIntent::Running { .. })
    {
        dispatcher.configuration_inputs_consumed();
    }
    let completed_revision = started.revision.saturating_add(1);
    let operation = result.map(|completion| OperationReport {
        intent,
        revision: completed_revision,
        address_resync: match completion {
            DispatcherCompletion::Completed => None,
            DispatcherCompletion::AddressResync(disposition) => Some(disposition),
        },
    });

    replace_snapshot(snapshot, |current| ControlSnapshot {
        revision: completed_revision,
        administrative_state: current.administrative_state,
        configuration_dirty: operation
            .as_ref()
            .map_or(current.configuration_dirty, |report| match report.intent {
                RuntimeIntent::Running { .. } | RuntimeIntent::Reload { .. } => false,
                RuntimeIntent::Stopped { .. } | RuntimeIntent::ResyncAddresses { .. } => {
                    current.configuration_dirty
                }
            }),
        in_flight: None,
        last_completed: operation.as_ref().ok().copied().or(current.last_completed),
    });

    operation
}

fn mark_dirty(snapshot: &RwLock<Arc<ControlSnapshot>>) -> u64 {
    replace_snapshot(snapshot, |current| ControlSnapshot {
        revision: current.revision.saturating_add(1),
        administrative_state: current.administrative_state,
        configuration_dirty: true,
        in_flight: current.in_flight,
        last_completed: current.last_completed,
    })
    .revision
}

fn read_snapshot(snapshot: &RwLock<Arc<ControlSnapshot>>) -> Arc<ControlSnapshot> {
    match snapshot.read() {
        Ok(snapshot) => Arc::clone(&snapshot),
        Err(poisoned) => Arc::clone(&poisoned.into_inner()),
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
    intent: RuntimeIntent,
) -> AdministrativeState {
    match intent {
        RuntimeIntent::Running { .. } => AdministrativeState::Running,
        RuntimeIntent::Stopped { .. } => AdministrativeState::Stopped,
        RuntimeIntent::Reload { .. } | RuntimeIntent::ResyncAddresses { .. } => current,
    }
}
