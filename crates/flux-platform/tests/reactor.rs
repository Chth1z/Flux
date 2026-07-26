#![cfg(any(target_os = "linux", target_os = "android"))]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::{Duration, Instant};

use flux_platform::{
    DaemonReactor, FileObservationBatch, FileObservationPaths, ReactorError, ReactorStopHandle,
    SeqpacketConnection, ShutdownSignal, StopDisposition,
};
use tempfile::tempdir;

const PARTIAL_BIND_HELPER_ENV: &str = "FLUX_REACTOR_PARTIAL_BIND_HELPER";

extern "C" fn test_signal_handler(_signal: libc::c_int) {}

struct SignalHandlerGuard {
    previous: libc::sigaction,
}

impl SignalHandlerGuard {
    fn install() -> Self {
        // SAFETY: zero is a valid starting representation before these
        // sigaction fields are initialized below.
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = test_signal_handler as *const () as usize;
        action.sa_flags = 0;
        // SAFETY: `sa_mask` is writable storage within `action`.
        assert_eq!(unsafe { libc::sigemptyset(&raw mut action.sa_mask) }, 0);

        // SAFETY: zeroed storage is valid for receiving the previous action.
        let mut previous = unsafe { std::mem::zeroed::<libc::sigaction>() };
        // SAFETY: both pointers reference initialized/writable sigaction values.
        let install_result =
            unsafe { libc::sigaction(libc::SIGUSR1, &raw const action, &raw mut previous) };
        assert_eq!(install_result, 0);
        Self { previous }
    }
}

impl Drop for SignalHandlerGuard {
    fn drop(&mut self) {
        // SAFETY: `previous` was initialized by the successful sigaction call.
        let _ = unsafe {
            libc::sigaction(
                libc::SIGUSR1,
                &raw const self.previous,
                std::ptr::null_mut(),
            )
        };
    }
}

struct RunningReactor {
    stop: ReactorStopHandle,
    reactor_thread: ThreadId,
    native_thread: usize,
    thread: JoinHandle<Result<(), ReactorError>>,
}

struct BoundReactor {
    stop: ReactorStopHandle,
    start: mpsc::SyncSender<()>,
    thread: JoinHandle<Result<(), ReactorError>>,
}

#[test]
fn programmatic_stop_wakes_an_idle_reactor() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let running = spawn_reactor(socket_path, drop_connection);

    thread::sleep(Duration::from_millis(20));
    assert_eq!(
        running.stop.request_stop().expect("request reactor stop"),
        StopDisposition::Requested
    );
    wait_until(Duration::from_secs(1), || running.thread.is_finished());

    running
        .thread
        .join()
        .expect("reactor thread")
        .expect("run reactor");
}

#[test]
fn stop_disposition_distinguishes_pending_and_completed_shutdown() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let bound = bind_reactor(socket_path, drop_connection);

    assert_eq!(
        bound.stop.request_stop().expect("request reactor stop"),
        StopDisposition::Requested
    );
    assert_eq!(
        bound.stop.request_stop().expect("repeat reactor stop"),
        StopDisposition::AlreadyStopping
    );
    bound.start.send(()).expect("start reactor");
    bound
        .thread
        .join()
        .expect("reactor thread")
        .expect("run reactor");
    assert_eq!(
        bound.stop.request_stop().expect("query exited reactor"),
        StopDisposition::Exited
    );
}

#[test]
fn dropping_an_unrun_reactor_completes_cleanup_and_stop_state() {
    let sigint_was_blocked = signal_is_blocked(libc::SIGINT);
    let sigterm_was_blocked = signal_is_blocked(libc::SIGTERM);
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
    let (reactor, stop) =
        DaemonReactor::bind(&socket_path, shutdown, drop_connection).expect("bind reactor");
    assert!(socket_path.exists());

    drop(reactor);

    assert_socket_absent(&socket_path);
    assert_eq!(signal_is_blocked(libc::SIGINT), sigint_was_blocked);
    assert_eq!(signal_is_blocked(libc::SIGTERM), sigterm_was_blocked);
    assert_eq!(
        stop.request_stop().expect("query dropped reactor"),
        StopDisposition::Exited
    );
}

#[test]
fn inventory_enabled_reactor_publishes_without_displacing_control_work() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let (handled_tx, handled_rx) = mpsc::sync_channel(1);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let reactor_path = socket_path.clone();
    let thread = thread::spawn(move || {
        let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
        let (reactor, stop, source) = DaemonReactor::bind_with_network_inventory(
            reactor_path,
            shutdown,
            move |connection| {
                let packet = connection.recv_packet(64).expect("receive request");
                handled_tx.send(packet).expect("publish handled packet");
            },
            drop,
        )
        .expect("bind inventory-enabled reactor");
        ready_tx
            .send((stop, source))
            .expect("publish inventory-enabled reactor");
        reactor.run()
    });
    let (stop, source) = ready_rx.recv().expect("reactor setup result");
    let Some(source) = source else {
        assert_eq!(
            stop.request_stop().expect("request degraded reactor stop"),
            StopDisposition::Requested
        );
        thread
            .join()
            .expect("reactor thread")
            .expect("run degraded inventory-enabled reactor");
        return;
    };

    let client = SeqpacketConnection::connect(&socket_path).expect("connect reactor");
    client.send_packet(b"request").expect("send request");
    assert_eq!(
        handled_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("control request is handled"),
        b"request"
    );
    wait_until(Duration::from_secs(2), || source.snapshot().is_some());

    assert_eq!(
        stop.request_stop().expect("request reactor stop"),
        StopDisposition::Requested
    );
    thread
        .join()
        .expect("reactor thread")
        .expect("run inventory-enabled reactor");
    assert!(source.snapshot().is_none());
}

#[test]
fn partial_bind_failure_unlinks_listener_and_restores_signal_mask() {
    if let Some(socket_path) = std::env::var_os(PARTIAL_BIND_HELPER_ENV) {
        exercise_partial_bind_failure(Path::new(&socket_path));
        return;
    }

    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("partial_bind_failure_unlinks_listener_and_restores_signal_mask")
        .env(PARTIAL_BIND_HELPER_ENV, &socket_path)
        .status()
        .expect("run partial-bind helper");

    assert!(status.success(), "partial-bind helper failed: {status}");
    assert_socket_absent(&socket_path);
}

#[test]
fn ready_connection_runs_on_a_worker_and_preserves_packet_boundaries() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let (handled_tx, handled_rx) = mpsc::sync_channel(1);
    let running = spawn_reactor(socket_path.clone(), move |connection| {
        let packet = connection.recv_packet(64).expect("receive request");
        handled_tx
            .send((thread::current().id(), packet))
            .expect("publish handled request");
    });

    let client = SeqpacketConnection::connect(&socket_path).expect("connect reactor");
    client.send_packet(b"request").expect("send request");
    let (worker_thread, packet) = handled_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("worker handles request");

    assert_ne!(worker_thread, running.reactor_thread);
    assert_eq!(packet, b"request");
    stop_and_join(running);
}

#[test]
fn pending_stop_beats_an_already_ready_listener() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let handled = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&handled);
    let bound = bind_reactor(socket_path.clone(), move |_connection| {
        handler_flag.store(true, Ordering::SeqCst);
    });
    let client = SeqpacketConnection::connect(&socket_path).expect("queue client");
    client.send_packet(b"queued").expect("queue request");

    assert_eq!(
        bound.stop.request_stop().expect("request reactor stop"),
        StopDisposition::Requested
    );
    bound.start.send(()).expect("start reactor");
    bound
        .thread
        .join()
        .expect("reactor thread")
        .expect("run reactor");

    assert!(!handled.load(Ordering::SeqCst));
    assert_socket_absent(&socket_path);
}

#[test]
fn listener_is_unlinked_before_running_workers_are_drained() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let handler_release = Arc::clone(&release);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let running = spawn_reactor(socket_path.clone(), move |_connection| {
        entered_tx.send(()).expect("publish worker entry");
        let (lock, changed) = &*handler_release;
        let mut released = lock.lock().expect("worker release lock");
        while !*released {
            released = changed.wait(released).expect("wait for worker release");
        }
    });
    let _client = SeqpacketConnection::connect(&socket_path).expect("connect reactor");
    entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("worker starts");

    assert_eq!(
        running.stop.request_stop().expect("request reactor stop"),
        StopDisposition::Requested
    );
    wait_until(Duration::from_secs(1), || !socket_path.exists());
    assert!(
        !running.thread.is_finished(),
        "worker must still be draining"
    );

    let (lock, changed) = &*release;
    *lock.lock().expect("worker release lock") = true;
    changed.notify_all();
    running
        .thread
        .join()
        .expect("reactor thread")
        .expect("run reactor");
}

#[test]
fn inventory_is_invalidated_before_running_workers_are_drained() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let handler_release = Arc::clone(&release);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let reactor_path = socket_path.clone();
    let thread = thread::spawn(move || {
        let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
        let (reactor, stop, source) = DaemonReactor::bind_with_network_inventory(
            reactor_path,
            shutdown,
            move |_connection| {
                entered_tx.send(()).expect("publish worker entry");
                let (lock, changed) = &*handler_release;
                let mut released = lock.lock().expect("worker release lock");
                while !*released {
                    released = changed.wait(released).expect("wait for worker release");
                }
            },
            drop,
        )
        .expect("bind inventory-enabled reactor");
        ready_tx
            .send((stop, source))
            .expect("publish inventory-enabled reactor");
        reactor.run()
    });
    let (stop, source) = ready_rx.recv().expect("reactor setup result");
    let Some(source) = source else {
        assert_eq!(
            stop.request_stop().expect("request degraded reactor stop"),
            StopDisposition::Requested
        );
        thread
            .join()
            .expect("reactor thread")
            .expect("run degraded inventory-enabled reactor");
        return;
    };
    wait_until(Duration::from_secs(2), || source.snapshot().is_some());

    let _client = SeqpacketConnection::connect(&socket_path).expect("connect reactor");
    entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("worker starts");
    assert_eq!(
        stop.request_stop().expect("request reactor stop"),
        StopDisposition::Requested
    );
    wait_until(Duration::from_secs(1), || !socket_path.exists());
    assert!(source.snapshot().is_none());
    assert!(!thread.is_finished(), "worker must still be draining");

    let (lock, changed) = &*release;
    *lock.lock().expect("worker release lock") = true;
    changed.notify_all();
    thread
        .join()
        .expect("reactor thread")
        .expect("run inventory-enabled reactor");
}

#[test]
fn reactor_caps_workers_at_sixteen_then_readmits_a_queued_client() {
    const CLIENT_COUNT: usize = 17;
    const WORKER_LIMIT: usize = 16;

    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let permits = Arc::new((Mutex::new(0_usize), Condvar::new()));
    let handler_permits = Arc::clone(&permits);
    let (started_tx, started_rx) = mpsc::sync_channel(CLIENT_COUNT);
    let running = spawn_reactor(socket_path.clone(), move |connection| {
        let packet = connection.recv_packet(1).expect("receive client id");
        started_tx.send(packet[0]).expect("publish started worker");
        let (lock, changed) = &*handler_permits;
        let mut available = lock.lock().expect("worker permit lock");
        while *available == 0 {
            available = changed.wait(available).expect("wait for worker permit");
        }
        *available -= 1;
    });

    let mut clients = Vec::with_capacity(CLIENT_COUNT);
    for id in 0..CLIENT_COUNT {
        let client = SeqpacketConnection::connect(&socket_path).expect("connect queued client");
        client
            .send_packet(&[u8::try_from(id).expect("client id fits in one byte")])
            .expect("send client id");
        clients.push(client);
    }

    let mut started = HashSet::new();
    for _ in 0..WORKER_LIMIT {
        started.insert(
            started_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("initial worker starts"),
        );
    }
    assert_eq!(started.len(), WORKER_LIMIT);
    assert_eq!(
        started_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout),
        "the seventeenth client must remain queued at capacity"
    );

    release_workers(&permits, 1);
    let readmitted = started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("queued client is admitted after a completion");
    assert!(started.insert(readmitted));
    assert_eq!(started.len(), CLIENT_COUNT);

    assert_eq!(
        running.stop.request_stop().expect("request reactor stop"),
        StopDisposition::Requested
    );
    release_workers(&permits, WORKER_LIMIT);
    running
        .thread
        .join()
        .expect("reactor thread")
        .expect("run reactor");
    drop(clients);
}

#[test]
fn termination_signal_wakes_the_reactor_through_signalfd() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let running = spawn_reactor(socket_path, drop_connection);

    thread::sleep(Duration::from_millis(20));
    // SAFETY: `native_thread` names the live reactor thread, where SIGTERM was
    // blocked before its signalfd was registered with epoll.
    let kill_result =
        unsafe { libc::pthread_kill(running.native_thread as libc::pthread_t, libc::SIGTERM) };
    assert_eq!(kill_result, 0);
    wait_until(Duration::from_secs(1), || running.thread.is_finished());
    running
        .thread
        .join()
        .expect("reactor thread")
        .expect("run reactor");
    assert_eq!(
        running.stop.request_stop().expect("query exited reactor"),
        StopDisposition::Exited
    );
}

#[test]
fn reactor_keeps_waiting_after_epoll_is_interrupted() {
    let _signal_handler = SignalHandlerGuard::install();
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let (handled_tx, handled_rx) = mpsc::sync_channel(1);
    let running = spawn_reactor(socket_path.clone(), move |_connection| {
        handled_tx.send(()).expect("publish handled connection");
    });

    thread::sleep(Duration::from_millis(20));
    // SAFETY: `native_thread` names the live reactor thread and SIGUSR1 has a
    // process-wide non-restarting handler for the duration of this test.
    let kill_result =
        unsafe { libc::pthread_kill(running.native_thread as libc::pthread_t, libc::SIGUSR1) };
    assert_eq!(kill_result, 0);
    thread::sleep(Duration::from_millis(10));
    let _client = SeqpacketConnection::connect(&socket_path).expect("connect after signal");
    handled_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("reactor dispatches after interrupted epoll wait");

    stop_and_join(running);
}

#[test]
fn worker_panic_stops_the_reactor_after_listener_cleanup() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let running = spawn_reactor(socket_path.clone(), |_connection| {
        panic!("handler failed");
    });
    let _client = SeqpacketConnection::connect(&socket_path).expect("connect reactor");

    wait_until(Duration::from_secs(1), || running.thread.is_finished());
    let error = running
        .thread
        .join()
        .expect("reactor thread")
        .expect_err("worker panic must fail the reactor");

    assert!(error.to_string().contains("panicked"));
    assert_socket_absent(&socket_path);
    assert_eq!(
        running.stop.request_stop().expect("query exited reactor"),
        StopDisposition::Exited
    );
}

#[test]
fn file_observation_reports_atomic_replacement_and_disable_state_changes() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path();
    let configuration = root.join("conf");
    fs::create_dir(&configuration).expect("create configuration directory");
    let paths = FileObservationPaths::new(
        configuration.join("flux.toml"),
        configuration.join("template.json"),
        configuration.join("subscription-url.txt"),
        root.join("disable"),
    );
    write_observed_inputs(&paths);
    let replacement = Arc::new(Mutex::new(None));
    let (running, observations, issues) =
        spawn_file_observing_reactor(root.join("fluxd.sock"), paths.clone(), replacement);
    assert_initial_file_reconciliation(&observations);

    fs::write(configuration.join("unrelated.tmp"), "ignored").expect("write unrelated file");
    assert_eq!(
        observations.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );

    let replacement_template = configuration.join("template.next");
    fs::write(&replacement_template, "replacement").expect("write replacement template");
    fs::rename(&replacement_template, paths.engine_template())
        .expect("replace template atomically");
    recv_file_observation(&observations, Duration::from_secs(1), |observation| {
        observation.configuration_inputs_changed()
    });

    fs::write(paths.disable(), "").expect("create disable entry");
    recv_file_observation(&observations, Duration::from_secs(1), |observation| {
        observation.disable_state_changed()
    });
    assert!(issues.try_iter().collect::<Vec<_>>().is_empty());
    stop_and_join(running);
}

#[test]
fn file_observation_replaces_dynamic_targets_from_the_reconciliation_callback() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path();
    let old_configuration = root.join("old");
    let new_configuration = root.join("new");
    fs::create_dir(&old_configuration).expect("create old configuration directory");
    fs::create_dir(&new_configuration).expect("create new configuration directory");
    let initial = FileObservationPaths::new(
        old_configuration.join("flux.toml"),
        old_configuration.join("template.json"),
        old_configuration.join("subscription-url.txt"),
        root.join("disable"),
    );
    let updated = FileObservationPaths::new(
        initial.desired_state(),
        new_configuration.join("template.json"),
        new_configuration.join("subscription-url.txt"),
        initial.disable(),
    );
    write_observed_inputs(&initial);
    fs::write(updated.engine_template(), "new template").expect("write new template");
    fs::write(updated.subscription_url(), "new URL").expect("write new URL");
    let replacement = Arc::new(Mutex::new(None));
    let (running, observations, issues) = spawn_file_observing_reactor(
        root.join("fluxd.sock"),
        initial.clone(),
        Arc::clone(&replacement),
    );
    assert_initial_file_reconciliation(&observations);
    *replacement.lock().expect("replacement lock") = Some(updated.clone());

    fs::write(initial.desired_state(), "changed desired state").expect("change desired state");
    recv_file_observation(&observations, Duration::from_secs(1), |observation| {
        observation.configuration_inputs_changed()
    });
    thread::sleep(Duration::from_millis(50));
    while observations.try_recv().is_ok() {}

    fs::write(initial.engine_template(), "old target changed").expect("change old template");
    assert_eq!(
        observations.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout),
        "the replaced template target must no longer produce a fact"
    );
    fs::write(updated.engine_template(), "new target changed").expect("change new template");
    recv_file_observation(&observations, Duration::from_secs(1), |observation| {
        observation.configuration_inputs_changed()
    });

    assert!(issues.try_iter().collect::<Vec<_>>().is_empty());
    stop_and_join(running);
}

#[test]
fn file_observation_recovers_after_an_ancestor_directory_is_replaced() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path();
    let active = root.join("active");
    let configuration = active.join("conf");
    fs::create_dir_all(&configuration).expect("create active configuration directory");
    let paths = FileObservationPaths::new(
        configuration.join("flux.toml"),
        configuration.join("template.json"),
        configuration.join("subscription-url.txt"),
        root.join("disable"),
    );
    write_observed_inputs(&paths);
    let replacement = Arc::new(Mutex::new(None));
    let (running, observations, issues) =
        spawn_file_observing_reactor(root.join("fluxd.sock"), paths.clone(), replacement);
    assert_initial_file_reconciliation(&observations);

    fs::rename(&active, root.join("retired")).expect("retire observed ancestor");
    fs::create_dir_all(&configuration).expect("replace observed ancestor");
    write_observed_inputs(&paths);
    recv_file_observation(&observations, Duration::from_secs(3), |observation| {
        observation.configuration_inputs_changed()
    });
    thread::sleep(Duration::from_millis(300));
    while observations.try_recv().is_ok() {}

    fs::write(paths.engine_template(), "changed after reinstall")
        .expect("change reinstalled target");
    recv_file_observation(&observations, Duration::from_secs(1), |observation| {
        observation.configuration_inputs_changed()
    });
    assert!(
        issues
            .try_iter()
            .all(|issue| issue.contains("open observed directory")),
        "only the bounded transient replacement gap may be reported"
    );
    stop_and_join(running);
}

fn spawn_reactor<H>(path: PathBuf, handler: H) -> RunningReactor
where
    H: Fn(SeqpacketConnection) + Send + Sync + 'static,
{
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let thread = thread::spawn(move || {
        let shutdown = match ShutdownSignal::install() {
            Ok(shutdown) => shutdown,
            Err(error) => {
                ready_tx
                    .send(Err(error.to_string()))
                    .expect("publish shutdown setup failure");
                return Err(ReactorError::from(error));
            }
        };
        let (reactor, stop) = match DaemonReactor::bind(path, shutdown, handler) {
            Ok(bound) => bound,
            Err(error) => {
                ready_tx
                    .send(Err(error.to_string()))
                    .expect("publish reactor bind failure");
                return Err(error);
            }
        };
        // SAFETY: pthread_self has no pointer arguments or preconditions.
        let native_thread = unsafe { libc::pthread_self() } as usize;
        ready_tx
            .send(Ok((stop, thread::current().id(), native_thread)))
            .expect("publish running reactor");
        reactor.run()
    });
    let (stop, reactor_thread, native_thread) = ready_rx
        .recv()
        .expect("reactor setup result")
        .unwrap_or_else(|error| panic!("start reactor: {error}"));
    RunningReactor {
        stop,
        reactor_thread,
        native_thread,
        thread,
    }
}

fn spawn_file_observing_reactor(
    socket_path: PathBuf,
    paths: FileObservationPaths,
    replacement: Arc<Mutex<Option<FileObservationPaths>>>,
) -> (
    RunningReactor,
    mpsc::Receiver<FileObservationBatch>,
    mpsc::Receiver<String>,
) {
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (observation_tx, observation_rx) = mpsc::channel();
    let (issue_tx, issue_rx) = mpsc::channel();
    let thread = thread::spawn(move || {
        let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
        let (mut reactor, stop) = DaemonReactor::bind(&socket_path, shutdown, drop_connection)
            .expect("bind file-observing reactor");
        reactor
            .attach_file_observation(
                &paths,
                move |observation| {
                    observation_tx
                        .send(observation)
                        .expect("publish file observation");
                    replacement.lock().expect("replacement lock").take()
                },
                move |error| {
                    issue_tx
                        .send(error.to_string())
                        .expect("publish file observation issue");
                },
            )
            .expect("attach file observation");
        // SAFETY: pthread_self has no pointer arguments or preconditions.
        let native_thread = unsafe { libc::pthread_self() } as usize;
        ready_tx
            .send((stop, thread::current().id(), native_thread))
            .expect("publish file-observing reactor");
        reactor.run()
    });
    let (stop, reactor_thread, native_thread) = ready_rx.recv().expect("reactor setup result");
    (
        RunningReactor {
            stop,
            reactor_thread,
            native_thread,
            thread,
        },
        observation_rx,
        issue_rx,
    )
}

fn bind_reactor<H>(path: PathBuf, handler: H) -> BoundReactor
where
    H: Fn(SeqpacketConnection) + Send + Sync + 'static,
{
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (start_tx, start_rx) = mpsc::sync_channel(0);
    let thread = thread::spawn(move || {
        let shutdown = match ShutdownSignal::install() {
            Ok(shutdown) => shutdown,
            Err(error) => {
                ready_tx
                    .send(Err(error.to_string()))
                    .expect("publish shutdown setup failure");
                return Err(ReactorError::from(error));
            }
        };
        let (reactor, stop) = match DaemonReactor::bind(path, shutdown, handler) {
            Ok(bound) => bound,
            Err(error) => {
                ready_tx
                    .send(Err(error.to_string()))
                    .expect("publish reactor bind failure");
                return Err(error);
            }
        };
        ready_tx
            .send(Ok(stop))
            .expect("publish bound reactor stop handle");
        start_rx.recv().expect("wait to run reactor");
        reactor.run()
    });
    let stop = ready_rx
        .recv()
        .expect("reactor setup result")
        .unwrap_or_else(|error| panic!("bind reactor: {error}"));
    BoundReactor {
        stop,
        start: start_tx,
        thread,
    }
}

fn stop_and_join(running: RunningReactor) {
    match running.stop.request_stop().expect("request reactor stop") {
        StopDisposition::Requested | StopDisposition::AlreadyStopping => {}
        StopDisposition::Exited => panic!("reactor exited before stop was requested"),
    }
    running
        .thread
        .join()
        .expect("reactor thread")
        .expect("run reactor");
}

fn release_workers(permits: &Arc<(Mutex<usize>, Condvar)>, count: usize) {
    let (lock, changed) = &**permits;
    *lock.lock().expect("worker permit lock") += count;
    changed.notify_all();
}

fn write_observed_inputs(paths: &FileObservationPaths) {
    fs::write(paths.desired_state(), "desired state").expect("write desired state");
    fs::write(paths.engine_template(), "template").expect("write engine template");
    fs::write(paths.subscription_url(), "URL").expect("write subscription URL");
}

fn assert_initial_file_reconciliation(observations: &mpsc::Receiver<FileObservationBatch>) {
    let initial = observations
        .recv_timeout(Duration::from_secs(1))
        .expect("initial file reconciliation");
    assert!(initial.configuration_inputs_changed());
    assert!(initial.disable_state_changed());
}

fn recv_file_observation(
    observations: &mpsc::Receiver<FileObservationBatch>,
    timeout: Duration,
    predicate: impl Fn(FileObservationBatch) -> bool,
) -> FileObservationBatch {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let observation = observations
            .recv_timeout(remaining)
            .expect("receive matching file observation");
        if predicate(observation) {
            return observation;
        }
    }
}

fn drop_connection(_connection: SeqpacketConnection) {}

fn assert_socket_absent(path: &Path) {
    let error = std::fs::symlink_metadata(path).expect_err("listener socket must be absent");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

fn exercise_partial_bind_failure(socket_path: &Path) {
    let sigint_was_blocked = signal_is_blocked(libc::SIGINT);
    let sigterm_was_blocked = signal_is_blocked(libc::SIGTERM);
    let maximum_observed_fd = std::fs::read_dir("/proc/self/fd")
        .expect("read process descriptors")
        .map(|entry| {
            entry
                .expect("process descriptor entry")
                .file_name()
                .to_string_lossy()
                .parse::<libc::rlim_t>()
                .expect("numeric process descriptor")
        })
        .max()
        .expect("test process has descriptors");
    let mut original_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `original_limit` is writable storage for one rlimit value.
    let get_limit_result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut original_limit) };
    assert_eq!(get_limit_result, 0);
    let constrained_limit = libc::rlimit {
        rlim_cur: maximum_observed_fd.saturating_add(32),
        rlim_max: original_limit.rlim_max,
    };
    assert!(constrained_limit.rlim_cur <= constrained_limit.rlim_max);
    // SAFETY: `constrained_limit` is initialized and only lowers this helper
    // process's soft descriptor limit.
    let set_limit_result =
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const constrained_limit) };
    assert_eq!(set_limit_result, 0);

    let mut fillers = Vec::new();
    let saturation_error = loop {
        match std::fs::File::open("/dev/null") {
            Ok(file) => fillers.push(file),
            Err(error) => break error,
        }
    };
    assert_eq!(saturation_error.raw_os_error(), Some(libc::EMFILE));
    // Saturating first accounts for arbitrary gaps in the test harness's FD
    // table. Three released slots permit signalfd, the listener, and eventfd;
    // epoll creation then fails after the socket pathname has been bound.
    for _ in 0..3 {
        drop(fillers.pop().expect("descriptor saturation filler"));
    }

    let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
    let result = DaemonReactor::bind(socket_path, shutdown, drop_connection);

    // SAFETY: restoring the previously returned process limit is valid.
    let restore_result = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const original_limit) };
    assert_eq!(restore_result, 0, "restore descriptor limit");
    drop(fillers);
    match result {
        Ok((reactor, _stop)) => {
            drop(reactor);
            panic!("constrained descriptor limit must fail reactor bind");
        }
        Err(error) => assert!(error.to_string().contains("reactor")),
    }
    assert_socket_absent(socket_path);
    assert_eq!(signal_is_blocked(libc::SIGINT), sigint_was_blocked);
    assert_eq!(signal_is_blocked(libc::SIGTERM), sigterm_was_blocked);
}

fn signal_is_blocked(signal: libc::c_int) -> bool {
    let mut current = std::mem::MaybeUninit::<libc::sigset_t>::zeroed();
    // SAFETY: a null set pointer queries the calling thread's current mask and
    // `current` is writable storage for the result.
    let mask_result =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), current.as_mut_ptr()) };
    assert_eq!(mask_result, 0);
    // SAFETY: pthread_sigmask initialized the complete signal set above.
    let current = unsafe { current.assume_init() };
    // SAFETY: `current` is initialized and `signal` is a valid POSIX signal.
    unsafe { libc::sigismember(&raw const current, signal) == 1 }
}

fn wait_until(timeout: Duration, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(Instant::now() < deadline, "condition timed out");
        thread::sleep(Duration::from_millis(2));
    }
}
