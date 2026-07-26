use std::error::Error;
use std::fmt;

use crate::{FileObservationError, PlatformError};

#[cfg(any(target_os = "linux", target_os = "android"))]
const MAX_ACCEPTS_PER_TURN: usize = 8;
#[cfg(any(target_os = "linux", target_os = "android"))]
const MAX_WORKERS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopDisposition {
    Requested,
    AlreadyStopping,
    Exited,
}

#[derive(Debug)]
pub enum NetworkInventoryDegradation {
    Initialization(PlatformError),
    DescriptorFailure { events: u32 },
    Runtime(PlatformError),
}

impl fmt::Display for NetworkInventoryDegradation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialization(error) => {
                write!(
                    formatter,
                    "initialize network inventory observation: {error}"
                )
            }
            Self::DescriptorFailure { events } => write!(
                formatter,
                "network inventory descriptor reported epoll events 0x{events:x}"
            ),
            Self::Runtime(error) => {
                write!(formatter, "drive network inventory observation: {error}")
            }
        }
    }
}

impl Error for NetworkInventoryDegradation {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Initialization(error) | Self::Runtime(error) => Some(error),
            Self::DescriptorFailure { .. } => None,
        }
    }
}

#[derive(Debug)]
pub enum ReactorError {
    Platform(PlatformError),
    FileObservation(FileObservationError),
    FileObservationAlreadyAttached,
    WorkerSpawn {
        source: std::io::Error,
    },
    WorkerPanicked {
        worker_id: u64,
    },
    WorkerIdentifierExhausted,
    UnknownWorkerCompletion {
        worker_id: u64,
    },
    DescriptorFailure {
        descriptor: &'static str,
        events: u32,
    },
    UnknownEpollToken(u64),
}

impl fmt::Display for ReactorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => error.fmt(formatter),
            Self::FileObservation(error) => write!(formatter, "file observation: {error}"),
            Self::FileObservationAlreadyAttached => {
                formatter.write_str("file observation is already attached to the daemon reactor")
            }
            Self::WorkerSpawn { source } => {
                write!(formatter, "spawn reactor worker failed: {source}")
            }
            Self::WorkerPanicked { worker_id } => {
                write!(formatter, "reactor worker {worker_id} panicked")
            }
            Self::WorkerIdentifierExhausted => {
                formatter.write_str("reactor worker identifier space is exhausted")
            }
            Self::UnknownWorkerCompletion { worker_id } => {
                write!(
                    formatter,
                    "received completion for unknown reactor worker {worker_id}"
                )
            }
            Self::DescriptorFailure { descriptor, events } => {
                write!(
                    formatter,
                    "{descriptor} reported fatal epoll events 0x{events:x}"
                )
            }
            Self::UnknownEpollToken(token) => {
                write!(formatter, "epoll returned unknown reactor token {token}")
            }
        }
    }
}

impl Error for ReactorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            Self::FileObservation(error) => Some(error),
            Self::FileObservationAlreadyAttached => None,
            Self::WorkerSpawn { source } => Some(source),
            Self::WorkerPanicked { .. }
            | Self::WorkerIdentifierExhausted
            | Self::UnknownWorkerCompletion { .. }
            | Self::DescriptorFailure { .. }
            | Self::UnknownEpollToken(_) => None,
        }
    }
}

impl From<PlatformError> for ReactorError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl From<FileObservationError> for ReactorError {
    fn from(error: FileObservationError) -> Self {
        Self::FileObservation(error)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::collections::HashMap;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
    use std::path::Path;
    use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    use super::{
        MAX_ACCEPTS_PER_TURN, MAX_WORKERS, NetworkInventoryDegradation, ReactorError,
        StopDisposition,
    };
    use crate::address_sync::AddressEventPolicy;
    use crate::file_observer::{FileObservationDriveReport, FileObserverDriver};
    use crate::network_observer::NetworkInventorySource;
    use crate::network_observer::driver::{
        RouteNetworkInventoryDriver, RouteNetworkInventoryWorkBudget,
    };
    use crate::{
        FileObservationBatch, FileObservationError, FileObservationPaths, PlatformError,
        SeqpacketConnection, SeqpacketListener, ShutdownSignal,
    };

    const LISTENER_TOKEN: u64 = 1;
    const SHUTDOWN_TOKEN: u64 = 2;
    const WAKE_TOKEN: u64 = 3;
    const NETWORK_INVENTORY_TOKEN: u64 = 4;
    const FILE_OBSERVATION_TOKEN: u64 = 5;
    const EPOLL_EVENT_CAPACITY: usize = 5;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StopPhase {
        Running,
        Stopping,
        Exited,
    }

    struct ReactorWake {
        fd: OwnedFd,
        phase: Mutex<StopPhase>,
    }

    impl ReactorWake {
        fn create() -> Result<Self, PlatformError> {
            // SAFETY: eventfd has no pointer arguments. On success it returns
            // one new descriptor owned by the caller.
            let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            if fd < 0 {
                return Err(last_error("create reactor eventfd"));
            }
            Ok(Self {
                // SAFETY: successful eventfd returned a new owned descriptor.
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
                phase: Mutex::new(StopPhase::Running),
            })
        }

        fn readiness_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }

        fn request_stop(&self) -> Result<StopDisposition, PlatformError> {
            let mut phase = self.lock_phase();
            match *phase {
                StopPhase::Running => {
                    *phase = StopPhase::Stopping;
                    if let Err(error) = self.notify() {
                        *phase = StopPhase::Running;
                        return Err(error);
                    }
                    Ok(StopDisposition::Requested)
                }
                StopPhase::Stopping => Ok(StopDisposition::AlreadyStopping),
                StopPhase::Exited => Ok(StopDisposition::Exited),
            }
        }

        fn begin_shutdown(&self) {
            let mut phase = self.lock_phase();
            if *phase == StopPhase::Running {
                *phase = StopPhase::Stopping;
            }
        }

        fn mark_exited(&self) {
            *self.lock_phase() = StopPhase::Exited;
        }

        fn is_stopping(&self) -> bool {
            *self.lock_phase() != StopPhase::Running
        }

        fn notify(&self) -> Result<(), PlatformError> {
            let value = 1_u64.to_ne_bytes();
            loop {
                // SAFETY: `value` is readable for exactly one eventfd word and
                // the descriptor remains valid through this shared value.
                let written = unsafe {
                    libc::write(
                        self.fd.as_raw_fd(),
                        value.as_ptr().cast::<libc::c_void>(),
                        value.len(),
                    )
                };
                if usize::try_from(written).ok() == Some(value.len()) {
                    return Ok(());
                }
                if written < 0 {
                    let source = std::io::Error::last_os_error();
                    match source.raw_os_error() {
                        Some(libc::EINTR) => continue,
                        // A saturated eventfd already has a wake pending.
                        Some(libc::EAGAIN) => return Ok(()),
                        _ => return Err(system_call_error("write reactor eventfd", source)),
                    }
                }
                return Err(system_call_error(
                    "write reactor eventfd",
                    std::io::Error::from_raw_os_error(libc::EPROTO),
                ));
            }
        }

        fn drain(&self) -> Result<(), PlatformError> {
            let mut value = 0_u64;
            loop {
                // SAFETY: `value` provides writable storage for one eventfd
                // word and the descriptor remains valid for this call.
                let received = unsafe {
                    libc::read(
                        self.fd.as_raw_fd(),
                        (&raw mut value).cast::<libc::c_void>(),
                        std::mem::size_of::<u64>(),
                    )
                };
                if usize::try_from(received).ok() == Some(std::mem::size_of::<u64>()) {
                    continue;
                }
                if received < 0 {
                    let source = std::io::Error::last_os_error();
                    match source.raw_os_error() {
                        Some(libc::EINTR) => continue,
                        Some(libc::EAGAIN) => return Ok(()),
                        _ => return Err(system_call_error("read reactor eventfd", source)),
                    }
                }
                return Err(system_call_error(
                    "read reactor eventfd",
                    std::io::Error::from_raw_os_error(libc::EPROTO),
                ));
            }
        }

        fn lock_phase(&self) -> MutexGuard<'_, StopPhase> {
            self.phase
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    #[derive(Clone)]
    pub struct ReactorStopHandle {
        wake: Arc<ReactorWake>,
    }

    impl ReactorStopHandle {
        pub fn request_stop(&self) -> Result<StopDisposition, PlatformError> {
            self.wake.request_stop()
        }
    }

    struct WorkerCompletion {
        worker_id: u64,
        panicked: bool,
    }

    struct CompletionNotifier {
        worker_id: u64,
        sender: SyncSender<WorkerCompletion>,
        wake: Arc<ReactorWake>,
    }

    impl Drop for CompletionNotifier {
        fn drop(&mut self) {
            let completion = WorkerCompletion {
                worker_id: self.worker_id,
                panicked: thread::panicking(),
            };
            if self.sender.send(completion).is_ok() {
                let _ = self.wake.notify();
            }
        }
    }

    struct ReadySet {
        listener: bool,
        shutdown: bool,
        wake: bool,
        network_inventory: bool,
        network_inventory_failure: Option<u32>,
        file_observation: bool,
    }

    struct NetworkInventoryRegistration {
        driver: RouteNetworkInventoryDriver,
        on_degradation: Box<dyn FnOnce(NetworkInventoryDegradation) + Send>,
    }

    impl NetworkInventoryRegistration {
        fn next_deadline(&self) -> Option<Instant> {
            self.driver.next_deadline()
        }

        fn drive_ready(&mut self, now: Instant) -> Result<(), PlatformError> {
            self.driver
                .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
                .map(|_| ())
        }

        fn drive_due(&mut self, now: Instant) -> Result<(), PlatformError> {
            self.driver.drive_due(now).map(|_| ())
        }

        fn degrade(mut self, degradation: NetworkInventoryDegradation) {
            self.driver.disable();
            (self.on_degradation)(degradation);
        }

        fn disable(mut self) {
            self.driver.disable();
        }
    }

    struct FileObservationRegistration {
        driver: FileObserverDriver,
        on_observation: Box<dyn FnMut(FileObservationBatch) -> Option<FileObservationPaths> + Send>,
        on_issue: Box<dyn FnMut(FileObservationError) + Send>,
    }

    impl FileObservationRegistration {
        fn next_deadline(&self) -> Instant {
            self.driver.next_deadline()
        }

        fn reconcile_initial(&mut self, now: Instant) {
            self.apply_observation(FileObservationBatch::all(), now);
        }

        fn drive_ready(&mut self, now: Instant) -> Result<(), FileObservationError> {
            let report = self.driver.drive_ready(now)?;
            self.apply_report(report, now);
            Ok(())
        }

        fn drive_due(&mut self, now: Instant) {
            let report = self.driver.drive_due(now);
            self.apply_report(report, now);
        }

        fn apply_report(&mut self, report: FileObservationDriveReport, now: Instant) {
            for issue in report.issues {
                (self.on_issue)(issue);
            }
            self.apply_observation(report.observation, now);
        }

        fn apply_observation(&mut self, observation: FileObservationBatch, now: Instant) {
            if observation.is_empty() {
                return;
            }
            let Some(paths) = (self.on_observation)(observation) else {
                return;
            };
            match self.driver.replace_paths(&paths, now) {
                Ok(issues) => {
                    for issue in issues {
                        (self.on_issue)(issue);
                    }
                }
                Err(error) => (self.on_issue)(error),
            }
        }
    }

    pub struct DaemonReactor {
        epoll: OwnedFd,
        listener: Option<SeqpacketListener>,
        listener_registered: bool,
        wake: Arc<ReactorWake>,
        handler: Arc<dyn Fn(SeqpacketConnection) + Send + Sync>,
        completion_sender: SyncSender<WorkerCompletion>,
        completion_receiver: Receiver<WorkerCompletion>,
        workers: HashMap<u64, JoinHandle<()>>,
        next_worker_id: u64,
        network_inventory: Option<NetworkInventoryRegistration>,
        file_observation: Option<FileObservationRegistration>,
        // Keep this last: its field drop restores the installing thread's
        // signal mask only after every other daemon-owned value is gone.
        shutdown: ShutdownSignal,
    }

    impl DaemonReactor {
        pub fn bind<H>(
            path: impl AsRef<Path>,
            shutdown: ShutdownSignal,
            handler: H,
        ) -> Result<(Self, ReactorStopHandle), ReactorError>
        where
            H: Fn(SeqpacketConnection) + Send + Sync + 'static,
        {
            let listener = SeqpacketListener::bind_nonblocking(path)?;
            let wake = Arc::new(ReactorWake::create()?);
            let epoll = create_epoll()?;

            add_epoll_interest(epoll.as_raw_fd(), listener.readiness_fd(), LISTENER_TOKEN)?;
            add_epoll_interest(epoll.as_raw_fd(), shutdown.readiness_fd(), SHUTDOWN_TOKEN)?;
            add_epoll_interest(epoll.as_raw_fd(), wake.readiness_fd(), WAKE_TOKEN)?;

            let (completion_sender, completion_receiver) = mpsc::sync_channel(MAX_WORKERS);
            let stop = ReactorStopHandle {
                wake: Arc::clone(&wake),
            };
            Ok((
                Self {
                    epoll,
                    listener: Some(listener),
                    listener_registered: true,
                    wake,
                    handler: Arc::new(handler),
                    completion_sender,
                    completion_receiver,
                    workers: HashMap::with_capacity(MAX_WORKERS),
                    next_worker_id: 1,
                    network_inventory: None,
                    file_observation: None,
                    shutdown,
                },
                stop,
            ))
        }

        pub fn bind_with_network_inventory<H, D>(
            path: impl AsRef<Path>,
            shutdown: ShutdownSignal,
            handler: H,
            on_degradation: D,
        ) -> Result<(Self, ReactorStopHandle, Option<NetworkInventorySource>), ReactorError>
        where
            H: Fn(SeqpacketConnection) + Send + Sync + 'static,
            D: FnOnce(NetworkInventoryDegradation) + Send + 'static,
        {
            let (mut reactor, stop) = Self::bind(path, shutdown, handler)?;
            let (mut driver, source) = match RouteNetworkInventoryDriver::open(
                AddressEventPolicy::new(true),
                Instant::now(),
            ) {
                Ok(opened) => opened,
                Err(error) => {
                    on_degradation(NetworkInventoryDegradation::Initialization(error));
                    return Ok((reactor, stop, None));
                }
            };
            if let Err(error) = add_epoll_interest(
                reactor.epoll.as_raw_fd(),
                driver.readiness_fd(),
                NETWORK_INVENTORY_TOKEN,
            ) {
                driver.disable();
                on_degradation(NetworkInventoryDegradation::Initialization(error));
                return Ok((reactor, stop, None));
            }
            reactor.network_inventory = Some(NetworkInventoryRegistration {
                driver,
                on_degradation: Box::new(on_degradation),
            });
            Ok((reactor, stop, Some(source)))
        }

        pub fn attach_file_observation<O, I>(
            &mut self,
            paths: &FileObservationPaths,
            on_observation: O,
            on_issue: I,
        ) -> Result<(), ReactorError>
        where
            O: FnMut(FileObservationBatch) -> Option<FileObservationPaths> + Send + 'static,
            I: FnMut(FileObservationError) + Send + 'static,
        {
            if self.file_observation.is_some() {
                return Err(ReactorError::FileObservationAlreadyAttached);
            }
            let now = Instant::now();
            let (driver, initial_issues) = FileObserverDriver::open(paths, now)?;
            add_epoll_interest(
                self.epoll.as_raw_fd(),
                driver.readiness_fd(),
                FILE_OBSERVATION_TOKEN,
            )?;
            let mut registration = FileObservationRegistration {
                driver,
                on_observation: Box::new(on_observation),
                on_issue: Box::new(on_issue),
            };
            for issue in initial_issues {
                (registration.on_issue)(issue);
            }
            registration.reconcile_initial(Instant::now());
            self.file_observation = Some(registration);
            Ok(())
        }

        pub fn run(mut self) -> Result<(), ReactorError> {
            let terminal_error = self.drive().err();
            self.close_listener_and_drain(terminal_error)
        }

        fn drive(&mut self) -> Result<(), ReactorError> {
            loop {
                if self.wake.is_stopping() {
                    return Ok(());
                }

                let ready = self.wait_for_ready_descriptors()?;

                // Shutdown sources are always consumed before listener work,
                // regardless of the order epoll used for this batch.
                if ready.shutdown {
                    self.consume_shutdown_signals()?;
                }
                if ready.wake {
                    self.wake.drain()?;
                }
                if self.wake.is_stopping() {
                    return Ok(());
                }

                if ready.wake {
                    self.reap_completed_workers()?;
                }
                if self.wake.is_stopping() {
                    return Ok(());
                }

                if ready.listener {
                    self.dispatch_ready_connections()?;
                }
                if self.wake.is_stopping() {
                    return Ok(());
                }

                if ready.file_observation {
                    self.file_observation
                        .as_mut()
                        .expect("ready file observation remains attached")
                        .drive_ready(Instant::now())?;
                }
                if self.wake.is_stopping() {
                    return Ok(());
                }

                if let Some(events) = ready.network_inventory_failure {
                    self.degrade_network_inventory(
                        NetworkInventoryDegradation::DescriptorFailure { events },
                    );
                } else if ready.network_inventory {
                    let error = self
                        .network_inventory
                        .as_mut()
                        .and_then(|registration| registration.drive_ready(Instant::now()).err());
                    if let Some(error) = error {
                        self.degrade_network_inventory(NetworkInventoryDegradation::Runtime(error));
                    }
                }
                if self.wake.is_stopping() {
                    return Ok(());
                }

                let error = self
                    .network_inventory
                    .as_mut()
                    .and_then(|registration| registration.drive_due(Instant::now()).err());
                if let Some(error) = error {
                    self.degrade_network_inventory(NetworkInventoryDegradation::Runtime(error));
                }
                if let Some(registration) = self.file_observation.as_mut() {
                    registration.drive_due(Instant::now());
                }
            }
        }

        fn wait_for_ready_descriptors(&self) -> Result<ReadySet, ReactorError> {
            let mut events = [libc::epoll_event { events: 0, u64: 0 }; EPOLL_EVENT_CAPACITY];
            let count = loop {
                let network_deadline = self
                    .network_inventory
                    .as_ref()
                    .and_then(NetworkInventoryRegistration::next_deadline);
                let file_deadline = self
                    .file_observation
                    .as_ref()
                    .map(FileObservationRegistration::next_deadline);
                let timeout = epoll_wait_timeout(
                    Instant::now(),
                    earliest_deadline(network_deadline, file_deadline),
                );
                // SAFETY: `events` is writable for its full cardinality and the
                // epoll descriptor remains valid for this blocking call.
                let count = unsafe {
                    libc::epoll_wait(
                        self.epoll.as_raw_fd(),
                        events.as_mut_ptr(),
                        i32::try_from(events.len()).expect("event capacity fits c_int"),
                        timeout,
                    )
                };
                if count >= 0 {
                    break usize::try_from(count).expect("nonnegative epoll count fits usize");
                }
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EINTR) {
                    return Err(system_call_error("wait for reactor events", source).into());
                }
            };

            classify_ready_events(&events[..count])
        }

        fn consume_shutdown_signals(&self) -> Result<(), ReactorError> {
            let mut received_shutdown = false;
            while self.shutdown.received()? {
                received_shutdown = true;
            }
            if received_shutdown {
                self.wake.begin_shutdown();
            }
            Ok(())
        }

        fn reap_completed_workers(&mut self) -> Result<(), ReactorError> {
            loop {
                match self.completion_receiver.try_recv() {
                    Ok(completion) if completion.panicked => {
                        self.wake.begin_shutdown();
                        return Err(ReactorError::WorkerPanicked {
                            worker_id: completion.worker_id,
                        });
                    }
                    Ok(completion) => {
                        let Some(worker) = self.workers.remove(&completion.worker_id) else {
                            self.wake.begin_shutdown();
                            return Err(ReactorError::UnknownWorkerCompletion {
                                worker_id: completion.worker_id,
                            });
                        };
                        if worker.join().is_err() {
                            self.wake.begin_shutdown();
                            return Err(ReactorError::WorkerPanicked {
                                worker_id: completion.worker_id,
                            });
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        unreachable!(
                            "daemon reactor retains a completion sender for future workers"
                        );
                    }
                }
            }

            if !self.listener_registered
                && self.workers.len() < MAX_WORKERS
                && !self.wake.is_stopping()
            {
                let listener = self
                    .listener
                    .as_ref()
                    .expect("listener exists while reactor is running");
                add_epoll_interest(
                    self.epoll.as_raw_fd(),
                    listener.readiness_fd(),
                    LISTENER_TOKEN,
                )?;
                self.listener_registered = true;
            }
            Ok(())
        }

        fn dispatch_ready_connections(&mut self) -> Result<(), ReactorError> {
            for _ in 0..MAX_ACCEPTS_PER_TURN {
                if self.wake.is_stopping() {
                    break;
                }
                if self.workers.len() >= MAX_WORKERS {
                    self.disable_listener_interest()?;
                    break;
                }

                let Some(connection) = self
                    .listener
                    .as_ref()
                    .expect("listener exists while reactor is running")
                    .try_accept()?
                else {
                    break;
                };
                // A stop can race the nonblocking accept. Never dispatch that
                // accepted connection once the stop phase is visible.
                if self.wake.is_stopping() {
                    drop(connection);
                    break;
                }
                self.spawn_worker(connection)?;
                if self.workers.len() >= MAX_WORKERS {
                    self.disable_listener_interest()?;
                    break;
                }
            }
            Ok(())
        }

        fn spawn_worker(&mut self, connection: SeqpacketConnection) -> Result<(), ReactorError> {
            let worker_id = self.next_worker_id;
            self.next_worker_id = self
                .next_worker_id
                .checked_add(1)
                .ok_or(ReactorError::WorkerIdentifierExhausted)?;
            let handler = Arc::clone(&self.handler);
            let sender = self.completion_sender.clone();
            let wake = Arc::clone(&self.wake);
            let worker = thread::Builder::new()
                .name(format!("flux-reactor-{worker_id}"))
                .spawn(move || {
                    let _completion = CompletionNotifier {
                        worker_id,
                        sender,
                        wake,
                    };
                    handler(connection);
                })
                .map_err(|source| ReactorError::WorkerSpawn { source })?;
            self.workers.insert(worker_id, worker);
            Ok(())
        }

        fn disable_listener_interest(&mut self) -> Result<(), ReactorError> {
            if !self.listener_registered {
                return Ok(());
            }
            let listener = self
                .listener
                .as_ref()
                .expect("listener exists while reactor is running");
            delete_epoll_interest(self.epoll.as_raw_fd(), listener.readiness_fd())?;
            self.listener_registered = false;
            Ok(())
        }

        fn degrade_network_inventory(&mut self, degradation: NetworkInventoryDegradation) {
            if let Some(registration) = self.network_inventory.take() {
                registration.degrade(degradation);
            }
        }

        fn disable_network_inventory(&mut self) {
            if let Some(registration) = self.network_inventory.take() {
                registration.disable();
            }
        }

        fn close_listener_and_drain(
            mut self,
            mut terminal_error: Option<ReactorError>,
        ) -> Result<(), ReactorError> {
            self.wake.begin_shutdown();

            // Dropping first closes the FD and unlinks the socket pathname, so
            // no new work can arrive while existing handlers are drained.
            drop(self.listener.take());
            self.listener_registered = false;
            drop(self.file_observation.take());
            self.disable_network_inventory();

            for (worker_id, worker) in self.workers.drain() {
                if worker.join().is_err() && terminal_error.is_none() {
                    terminal_error = Some(ReactorError::WorkerPanicked { worker_id });
                }
            }
            while self.completion_receiver.try_recv().is_ok() {}

            self.wake.mark_exited();
            match terminal_error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }

    impl Drop for DaemonReactor {
        fn drop(&mut self) {
            self.wake.begin_shutdown();
            drop(self.listener.take());
            self.listener_registered = false;
            drop(self.file_observation.take());
            self.disable_network_inventory();
            for (_worker_id, worker) in self.workers.drain() {
                let _ = worker.join();
            }
            while self.completion_receiver.try_recv().is_ok() {}
            self.wake.mark_exited();
        }
    }

    fn classify_ready_events(events: &[libc::epoll_event]) -> Result<ReadySet, ReactorError> {
        let mut ready = ReadySet {
            listener: false,
            shutdown: false,
            wake: false,
            network_inventory: false,
            network_inventory_failure: None,
            file_observation: false,
        };
        for event in events {
            let token = event.u64;
            let flags = event.events;
            if token == NETWORK_INVENTORY_TOKEN {
                if flags & u32::try_from(libc::EPOLLERR | libc::EPOLLHUP).unwrap_or(u32::MAX) != 0 {
                    ready.network_inventory_failure = Some(flags);
                } else if flags & u32::try_from(libc::EPOLLIN).unwrap_or_default() != 0 {
                    ready.network_inventory = true;
                }
                continue;
            }
            let descriptor = descriptor_name(token)?;
            if flags & u32::try_from(libc::EPOLLERR | libc::EPOLLHUP).unwrap_or(u32::MAX) != 0 {
                return Err(ReactorError::DescriptorFailure {
                    descriptor,
                    events: flags,
                });
            }
            if flags & u32::try_from(libc::EPOLLIN).unwrap_or_default() == 0 {
                continue;
            }
            match token {
                LISTENER_TOKEN => ready.listener = true,
                SHUTDOWN_TOKEN => ready.shutdown = true,
                WAKE_TOKEN => ready.wake = true,
                FILE_OBSERVATION_TOKEN => ready.file_observation = true,
                _ => return Err(ReactorError::UnknownEpollToken(token)),
            }
        }
        Ok(ready)
    }

    fn epoll_wait_timeout(now: Instant, deadline: Option<Instant>) -> i32 {
        let Some(deadline) = deadline else {
            return -1;
        };
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            return 0;
        }
        let milliseconds = remaining.as_nanos().div_ceil(1_000_000);
        i32::try_from(milliseconds).unwrap_or(i32::MAX)
    }

    fn earliest_deadline(first: Option<Instant>, second: Option<Instant>) -> Option<Instant> {
        match (first, second) {
            (Some(first), Some(second)) => Some(first.min(second)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
    }

    fn create_epoll() -> Result<OwnedFd, PlatformError> {
        // SAFETY: epoll_create1 has no pointer arguments and returns one new
        // owned descriptor on success.
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(last_error("create reactor epoll"));
        }
        // SAFETY: successful epoll_create1 returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn add_epoll_interest(
        epoll: libc::c_int,
        descriptor: BorrowedFd<'_>,
        token: u64,
    ) -> Result<(), PlatformError> {
        let mut event = libc::epoll_event {
            events: u32::try_from(libc::EPOLLIN).unwrap_or_default(),
            u64: token,
        };
        epoll_control(
            epoll,
            libc::EPOLL_CTL_ADD,
            descriptor,
            &raw mut event,
            "add reactor epoll interest",
        )
    }

    fn delete_epoll_interest(
        epoll: libc::c_int,
        descriptor: BorrowedFd<'_>,
    ) -> Result<(), PlatformError> {
        epoll_control(
            epoll,
            libc::EPOLL_CTL_DEL,
            descriptor,
            std::ptr::null_mut(),
            "delete reactor epoll interest",
        )
    }

    fn epoll_control(
        epoll: libc::c_int,
        operation: libc::c_int,
        descriptor: BorrowedFd<'_>,
        event: *mut libc::epoll_event,
        operation_name: &'static str,
    ) -> Result<(), PlatformError> {
        loop {
            // SAFETY: both descriptors are live, and `event` is either null
            // for DEL or points to one initialized event for ADD.
            if unsafe { libc::epoll_ctl(epoll, operation, descriptor.as_raw_fd(), event) } == 0 {
                return Ok(());
            }
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::EINTR) {
                return Err(system_call_error(operation_name, source));
            }
        }
    }

    fn descriptor_name(token: u64) -> Result<&'static str, ReactorError> {
        match token {
            LISTENER_TOKEN => Ok("reactor listener"),
            SHUTDOWN_TOKEN => Ok("reactor signalfd"),
            WAKE_TOKEN => Ok("reactor eventfd"),
            FILE_OBSERVATION_TOKEN => Ok("reactor inotify descriptor"),
            _ => Err(ReactorError::UnknownEpollToken(token)),
        }
    }

    fn last_error(operation: &'static str) -> PlatformError {
        system_call_error(operation, std::io::Error::last_os_error())
    }

    fn system_call_error(operation: &'static str, source: std::io::Error) -> PlatformError {
        PlatformError::SystemCall { operation, source }
    }

    #[cfg(test)]
    mod tests {
        use std::time::Duration;

        use super::*;

        #[test]
        fn epoll_timeout_tracks_inventory_deadlines_without_oversleeping() {
            let now = Instant::now();

            assert_eq!(epoll_wait_timeout(now, None), -1);
            assert_eq!(epoll_wait_timeout(now, Some(now)), 0);
            assert_eq!(
                epoll_wait_timeout(now, now.checked_add(Duration::from_nanos(1))),
                1
            );
            assert_eq!(
                epoll_wait_timeout(now, now.checked_add(Duration::from_nanos(1_000_001))),
                2
            );
            assert_eq!(
                epoll_wait_timeout(
                    now,
                    now.checked_add(Duration::from_millis(i32::MAX as u64 + 1)),
                ),
                i32::MAX
            );
        }

        #[test]
        fn route_descriptor_failure_is_degraded_while_core_failures_remain_fatal() {
            let input = u32::try_from(libc::EPOLLIN).unwrap_or_default();
            let hangup = u32::try_from(libc::EPOLLHUP).unwrap_or_default();
            let ready = classify_ready_events(&[
                libc::epoll_event {
                    events: input,
                    u64: LISTENER_TOKEN,
                },
                libc::epoll_event {
                    events: hangup,
                    u64: NETWORK_INVENTORY_TOKEN,
                },
            ])
            .expect("route hangup is a degraded observation failure");

            assert!(ready.listener);
            assert_eq!(ready.network_inventory_failure, Some(hangup));
            assert!(matches!(
                classify_ready_events(&[libc::epoll_event {
                    events: hangup,
                    u64: LISTENER_TOKEN,
                }]),
                Err(ReactorError::DescriptorFailure {
                    descriptor: "reactor listener",
                    events,
                }) if events == hangup
            ));
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod implementation {
    use std::path::Path;

    use super::{NetworkInventoryDegradation, ReactorError, StopDisposition};
    use crate::{
        FileObservationBatch, FileObservationError, FileObservationPaths, NetworkInventorySource,
        PlatformError, SeqpacketConnection, ShutdownSignal,
    };

    pub struct DaemonReactor;

    impl DaemonReactor {
        pub fn bind<H>(
            _path: impl AsRef<Path>,
            _shutdown: ShutdownSignal,
            _handler: H,
        ) -> Result<(Self, ReactorStopHandle), ReactorError>
        where
            H: Fn(SeqpacketConnection) + Send + Sync + 'static,
        {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS).into())
        }

        pub fn bind_with_network_inventory<H, D>(
            _path: impl AsRef<Path>,
            _shutdown: ShutdownSignal,
            _handler: H,
            _on_degradation: D,
        ) -> Result<(Self, ReactorStopHandle, Option<NetworkInventorySource>), ReactorError>
        where
            H: Fn(SeqpacketConnection) + Send + Sync + 'static,
            D: FnOnce(NetworkInventoryDegradation) + Send + 'static,
        {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS).into())
        }

        pub fn attach_file_observation<O, I>(
            &mut self,
            _paths: &FileObservationPaths,
            _on_observation: O,
            _on_issue: I,
        ) -> Result<(), ReactorError>
        where
            O: FnMut(FileObservationBatch) -> Option<FileObservationPaths> + Send + 'static,
            I: FnMut(FileObservationError) + Send + 'static,
        {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS).into())
        }

        pub fn run(self) -> Result<(), ReactorError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS).into())
        }
    }

    #[derive(Clone)]
    pub struct ReactorStopHandle;

    impl ReactorStopHandle {
        pub fn request_stop(&self) -> Result<StopDisposition, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }
    }
}

pub use implementation::{DaemonReactor, ReactorStopHandle};
