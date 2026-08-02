#![cfg(any(target_os = "linux", target_os = "android"))]

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::process::{Command, exit};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use flux_platform::{
    PlatformError, SeqpacketConnection, SeqpacketConnectionHandoffReceive, SeqpacketListener,
    SeqpacketReceive, Uid,
};
use tempfile::tempdir;

const STALE_SOCKET_HELPER_ENV: &str = "FLUX_SEQPACKET_STALE_SOCKET_HELPER";
static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn anonymous_pair_preserves_record_truncation_empty_records_and_eof() {
    let (producer, collector) = SeqpacketConnection::pair().expect("create anonymous pair");
    let credentials = collector.peer_credentials().expect("pair credentials");
    let deadline = Instant::now() + Duration::from_secs(1);

    producer
        .send_packet(b"12345678")
        .expect("send oversized record");
    assert_eq!(
        collector
            .recv_record_until(4, deadline)
            .expect("receive oversized record"),
        Some(SeqpacketReceive::Record {
            bytes: b"1234".to_vec(),
            truncated: true,
            credentials,
        })
    );

    producer.send_packet(b"").expect("send empty record");
    assert_eq!(
        collector
            .recv_record_until(4, deadline)
            .expect("receive empty record"),
        Some(SeqpacketReceive::Record {
            bytes: Vec::new(),
            truncated: false,
            credentials,
        })
    );

    drop(producer);
    assert_eq!(
        collector
            .recv_record_until(4, deadline)
            .expect("observe producer close"),
        Some(SeqpacketReceive::Eof)
    );
}

#[test]
fn typed_connection_handoff_preserves_payload_credentials_transport_and_eof() {
    let (control_sender, control_receiver) =
        SeqpacketConnection::pair().expect("create control pair");
    let expected_credentials = control_receiver
        .peer_credentials()
        .expect("control sender credentials");
    let (producer_endpoint, collector_endpoint) =
        SeqpacketConnection::pair().expect("create report pair");

    control_sender
        .send_connection(b"attempt-7", &producer_endpoint)
        .expect("transfer producer endpoint");
    assert!(
        control_receiver
            .recv_connection_until(64, Instant::now())
            .expect("observe expired handoff deadline")
            .is_none(),
        "an expired deadline must not consume a queued handoff"
    );
    drop(producer_endpoint);
    let received = control_receiver
        .recv_connection_until(64, fresh_deadline())
        .expect("receive producer endpoint")
        .expect("handoff must arrive");
    let SeqpacketConnectionHandoffReceive::Record {
        bytes,
        credentials,
        connection,
    } = received
    else {
        panic!("queued handoff cannot be EOF");
    };
    assert_eq!(bytes, b"attempt-7");
    assert_eq!(credentials, expected_credentials);

    collector_endpoint
        .send_packet(b"challenge")
        .expect("send collector challenge");
    assert_eq!(receive_complete_record(&connection, 64), b"challenge");
    connection
        .send_packet(b"report")
        .expect("send report through transferred endpoint");
    assert_eq!(receive_complete_record(&collector_endpoint, 64), b"report");

    drop(connection);
    assert_eq!(
        collector_endpoint
            .recv_record_until(64, fresh_deadline())
            .expect("observe transferred endpoint close"),
        Some(SeqpacketReceive::Eof)
    );
    drop(control_sender);
    assert!(matches!(
        control_receiver
            .recv_connection_until(64, fresh_deadline())
            .expect("observe control sender close"),
        Some(SeqpacketConnectionHandoffReceive::Eof)
    ));
}

#[test]
fn expired_connection_handoff_sends_nothing_and_keeps_the_borrowed_endpoint_live() {
    let (control_sender, control_receiver) =
        SeqpacketConnection::pair().expect("create control pair");
    let (producer_endpoint, collector_endpoint) =
        SeqpacketConnection::pair().expect("create report pair");

    assert!(
        !control_sender
            .send_connection_until(b"expired", &producer_endpoint, Instant::now())
            .expect("reject expired handoff")
    );
    assert!(
        control_receiver
            .recv_connection_until(64, Instant::now() + Duration::from_millis(20))
            .expect("inspect control receiver")
            .is_none()
    );
    producer_endpoint
        .send_packet(b"still-owned")
        .expect("use endpoint after expired borrowed handoff");
    assert_eq!(
        receive_complete_record(&collector_endpoint, 64),
        b"still-owned"
    );
}

#[test]
fn connection_handoff_returns_at_deadline_when_the_control_queue_is_full() {
    let _serial = SIGNAL_TEST_LOCK.lock().expect("signal test lock");
    let _handler = SignalHandlerGuard::install();
    let (control_sender, control_receiver) =
        SeqpacketConnection::pair().expect("create control pair");
    let (producer_endpoint, collector_endpoint) =
        SeqpacketConnection::pair().expect("create report pair");
    let mut queued = 0_usize;
    while control_sender
        .send_connection_until(
            b"queued",
            &producer_endpoint,
            Instant::now() + Duration::from_millis(10),
        )
        .expect("fill control queue")
    {
        queued += 1;
        assert!(queued < 4096, "control queue must become full");
    }
    assert!(queued > 0, "at least one handoff must be queued");

    let started = Instant::now();
    // SAFETY: `pthread_self` has no pointer arguments or preconditions.
    let sending_thread = unsafe { libc::pthread_self() } as usize;
    let interrupter = thread::spawn(move || {
        thread::sleep(Duration::from_millis(10));
        // SAFETY: `sending_thread` names the live test thread and SIGUSR1 has a process-wide
        // non-restarting handler installed for this test.
        let result =
            unsafe { libc::pthread_kill(sending_thread as libc::pthread_t, libc::SIGUSR1) };
        assert_eq!(result, 0);
    });
    assert!(
        !control_sender
            .send_connection_until(
                b"deadline",
                &producer_endpoint,
                started + Duration::from_millis(40),
            )
            .expect("bound a full-queue handoff")
    );
    interrupter.join().expect("signal interrupter");
    assert!(started.elapsed() >= Duration::from_millis(20));
    assert!(started.elapsed() < Duration::from_secs(1));
    producer_endpoint
        .send_packet(b"still-owned")
        .expect("use endpoint after full-queue timeout");
    assert_eq!(
        receive_complete_record(&collector_endpoint, 64),
        b"still-owned"
    );

    for _ in 0..queued {
        let received = control_receiver
            .recv_connection_until(64, fresh_deadline())
            .expect("drain queued handoff")
            .expect("queued handoff must remain");
        let SeqpacketConnectionHandoffReceive::Record {
            bytes, connection, ..
        } = received
        else {
            panic!("queued handoff cannot be EOF");
        };
        assert_eq!(bytes, b"queued");
        drop(connection);
    }
    assert!(
        control_sender
            .send_connection_until(b"after-drain", &producer_endpoint, fresh_deadline())
            .expect("send after draining control queue")
    );
}

#[test]
fn truncated_connection_handoff_closes_the_transferred_endpoint() {
    let (control_sender, control_receiver) =
        SeqpacketConnection::pair().expect("create control pair");
    let (producer_endpoint, collector_endpoint) =
        SeqpacketConnection::pair().expect("create report pair");

    control_sender
        .send_connection(b"oversized", &producer_endpoint)
        .expect("transfer producer endpoint");
    drop(producer_endpoint);
    let error = control_receiver
        .recv_connection_until(4, fresh_deadline())
        .expect_err("a handoff payload must not be truncated");
    match error {
        PlatformError::PacketTooLarge { actual, limit } => {
            assert_eq!((actual, limit), (9, 4));
        }
        other => panic!("unexpected handoff truncation error: {other}"),
    }
    assert_eq!(
        collector_endpoint
            .recv_record_until(64, fresh_deadline())
            .expect("observe rejected endpoint close"),
        Some(SeqpacketReceive::Eof)
    );
}

fn fresh_deadline() -> Instant {
    Instant::now() + Duration::from_secs(1)
}

fn receive_complete_record(connection: &SeqpacketConnection, limit: usize) -> Vec<u8> {
    match connection
        .recv_record_until(limit, fresh_deadline())
        .expect("receive deadline-bound authenticated record")
        .expect("record must arrive before the deadline")
    {
        SeqpacketReceive::Record {
            bytes,
            truncated: false,
            ..
        } => bytes,
        SeqpacketReceive::Record {
            truncated: true, ..
        } => panic!("record must not be truncated"),
        SeqpacketReceive::Eof => panic!("record must precede EOF"),
    }
}

#[test]
fn record_receive_returns_none_at_the_exclusive_deadline() {
    let (_producer, collector) = SeqpacketConnection::pair().expect("create anonymous pair");
    let started = Instant::now();

    let received = collector
        .recv_record_until(64, started + Duration::from_millis(40))
        .expect("wait for absent record");

    assert_eq!(received, None);
    assert!(started.elapsed() >= Duration::from_millis(20));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn queued_empty_record_precedes_eof_after_the_producer_closes() {
    let (producer, collector) = SeqpacketConnection::pair().expect("create anonymous pair");
    let credentials = collector.peer_credentials().expect("pair credentials");
    producer.send_packet(b"").expect("send empty record");
    drop(producer);
    let deadline = Instant::now() + Duration::from_secs(1);

    assert_eq!(
        collector
            .recv_record_until(64, deadline)
            .expect("receive queued empty record"),
        Some(SeqpacketReceive::Record {
            bytes: Vec::new(),
            truncated: false,
            credentials,
        })
    );
    assert_eq!(
        collector
            .recv_record_until(64, deadline)
            .expect("receive drained EOF"),
        Some(SeqpacketReceive::Eof)
    );
}

#[test]
fn expired_deadline_does_not_consume_a_queued_record() {
    let (producer, collector) = SeqpacketConnection::pair().expect("create anonymous pair");
    let credentials = collector.peer_credentials().expect("pair credentials");
    producer.send_packet(b"queued").expect("send queued record");

    assert_eq!(
        collector
            .recv_record_until(64, Instant::now())
            .expect("observe expired deadline"),
        None
    );
    assert_eq!(
        collector
            .recv_record_until(64, Instant::now() + Duration::from_secs(1))
            .expect("receive preserved record"),
        Some(SeqpacketReceive::Record {
            bytes: b"queued".to_vec(),
            truncated: false,
            credentials,
        })
    );
}

extern "C" fn test_signal_handler(_signal: libc::c_int) {}

struct SignalHandlerGuard {
    previous: libc::sigaction,
}

impl SignalHandlerGuard {
    fn install() -> Self {
        // SAFETY: zero is a valid starting representation for sigaction before
        // its mask, handler, and flags are initialized below.
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = test_signal_handler as *const () as usize;
        action.sa_flags = 0;
        // SAFETY: `sa_mask` is valid writable storage within `action`.
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

#[test]
fn stale_socket_helper() {
    let Some(socket_path) = std::env::var_os(STALE_SOCKET_HELPER_ENV) else {
        return;
    };

    let listener = SeqpacketListener::bind(socket_path).expect("bind helper listener");
    std::mem::forget(listener);
    exit(0);
}

#[test]
fn listener_recovers_a_stale_socket_without_manual_cleanup() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");

    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("stale_socket_helper")
        .env(STALE_SOCKET_HELPER_ENV, &socket_path)
        .status()
        .expect("run stale socket helper");
    assert!(status.success(), "stale socket helper failed: {status}");
    assert!(
        fs::symlink_metadata(&socket_path)
            .expect("stale socket metadata")
            .file_type()
            .is_socket(),
        "helper must leave a socket pathname behind"
    );

    let listener = SeqpacketListener::bind(&socket_path).expect("recover stale socket path");
    let server = thread::spawn(move || {
        let connection = listener.accept().expect("accept recovered listener client");
        assert_eq!(
            connection.recv_packet(64).expect("receive request"),
            b"request"
        );
    });

    let client = SeqpacketConnection::connect(&socket_path).expect("connect recovered listener");
    client.send_packet(b"request").expect("send request");
    server.join().expect("server thread");
}

#[test]
fn binding_never_unlinks_a_live_listener() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind live listener");
    let original_inode = fs::symlink_metadata(&socket_path)
        .expect("live listener metadata")
        .ino();

    SeqpacketListener::bind(&socket_path).expect_err("second listener must be rejected");
    assert_eq!(
        fs::symlink_metadata(&socket_path)
            .expect("live listener path must remain")
            .ino(),
        original_inode
    );

    let server = thread::spawn(move || {
        loop {
            let connection = listener.accept().expect("accept queued connection");
            match connection.recv_packet(64) {
                Ok(packet) => return packet,
                Err(PlatformError::PeerClosed) => continue,
                Err(error) => panic!("receive live-listener request: {error}"),
            }
        }
    });
    let client = SeqpacketConnection::connect(&socket_path).expect("connect live listener");
    client.send_packet(b"request").expect("send request");
    assert_eq!(server.join().expect("server thread"), b"request");
}

#[test]
fn accept_timeout_returns_none_when_no_peer_arrives() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");

    let started = Instant::now();
    let accepted = listener
        .accept_timeout(Duration::from_millis(40))
        .expect("wait for client");

    assert!(accepted.is_none());
    assert!(started.elapsed() >= Duration::from_millis(20));
}

#[test]
fn accept_timeout_returns_connection_when_peer_arrives() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");
    let client_path = socket_path.clone();
    let client = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        let connection = SeqpacketConnection::connect(client_path).expect("connect client");
        connection.send_packet(b"request").expect("send request");
    });

    let connection = listener
        .accept_timeout(Duration::from_secs(1))
        .expect("wait for client")
        .expect("client must arrive before timeout");
    assert_eq!(
        connection.recv_packet(64).expect("receive request"),
        b"request"
    );
    client.join().expect("client thread");
}

#[test]
fn zero_accept_timeout_still_observes_an_already_queued_peer() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");
    let client = SeqpacketConnection::connect(&socket_path).expect("queue client");
    client.send_packet(b"request").expect("queue request");

    let connection = listener
        .accept_timeout(Duration::ZERO)
        .expect("poll queued client")
        .expect("queued client must be accepted");
    assert_eq!(
        connection.recv_packet(64).expect("receive request"),
        b"request"
    );
}

#[test]
fn accept_timeout_keeps_waiting_after_signal_interruption() {
    let _serial = SIGNAL_TEST_LOCK.lock().expect("signal test lock");
    let _handler = SignalHandlerGuard::install();
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");
    let (thread_tx, thread_rx) = mpsc::channel();

    let server = thread::spawn(move || {
        // SAFETY: pthread_self has no pointer arguments or preconditions.
        thread_tx
            .send(unsafe { libc::pthread_self() } as usize)
            .expect("publish server thread");
        let started = Instant::now();
        let accepted = listener
            .accept_timeout(Duration::from_millis(80))
            .expect("timeout wait after signal");
        (accepted.is_none(), started.elapsed())
    });

    let server_thread = thread_rx.recv().expect("server thread identity");
    thread::sleep(Duration::from_millis(20));
    // SAFETY: `server_thread` names the live server thread and SIGUSR1 has a
    // process-wide non-restarting handler installed for this test.
    let kill_result =
        unsafe { libc::pthread_kill(server_thread as libc::pthread_t, libc::SIGUSR1) };
    assert_eq!(kill_result, 0);

    let (timed_out, elapsed) = server.join().expect("server thread");
    assert!(timed_out);
    assert!(elapsed >= Duration::from_millis(60));
}

#[test]
fn record_receive_keeps_the_same_deadline_after_signal_interruption() {
    let _serial = SIGNAL_TEST_LOCK.lock().expect("signal test lock");
    let _handler = SignalHandlerGuard::install();
    let (_producer, collector) = SeqpacketConnection::pair().expect("create anonymous pair");
    let (thread_tx, thread_rx) = mpsc::channel();

    let receiver = thread::spawn(move || {
        // SAFETY: pthread_self has no pointer arguments or preconditions.
        thread_tx
            .send(unsafe { libc::pthread_self() } as usize)
            .expect("publish receiver thread");
        let started = Instant::now();
        let received = collector
            .recv_record_until(64, started + Duration::from_millis(80))
            .expect("wait after signal");
        (received, started.elapsed())
    });

    let receiver_thread = thread_rx.recv().expect("receiver thread identity");
    thread::sleep(Duration::from_millis(20));
    // SAFETY: `receiver_thread` names the live receiver thread and SIGUSR1 has
    // a process-wide non-restarting handler installed for this test.
    let kill_result =
        unsafe { libc::pthread_kill(receiver_thread as libc::pthread_t, libc::SIGUSR1) };
    assert_eq!(kill_result, 0);

    let (received, elapsed) = receiver.join().expect("receiver thread");
    assert_eq!(received, None);
    assert!(elapsed >= Duration::from_millis(60));
    assert!(elapsed < Duration::from_secs(1));
}

#[test]
fn seqpacket_transport_preserves_request_and_response_boundaries() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");

    let server = thread::spawn(move || {
        let connection = listener.accept().expect("accept client");
        assert_eq!(
            connection.recv_packet(1024).expect("receive request"),
            b"request"
        );
        connection.send_packet(b"response").expect("send response");
    });

    let connection = SeqpacketConnection::connect(&socket_path).expect("connect client");
    connection.send_packet(b"request").expect("send request");
    assert_eq!(
        connection.recv_packet(1024).expect("receive response"),
        b"response"
    );

    server.join().expect("server thread");
}

#[test]
fn accepted_connection_preserves_an_empty_record_before_eof() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");

    let server = thread::spawn(move || {
        let connection = listener.accept().expect("accept client");
        let credentials = connection.peer_credentials().expect("client credentials");
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            connection
                .recv_record_until(64, deadline)
                .expect("receive empty record"),
            Some(SeqpacketReceive::Record {
                bytes: Vec::new(),
                truncated: false,
                credentials,
            })
        );
        assert_eq!(
            connection
                .recv_record_until(64, deadline)
                .expect("receive drained EOF"),
            Some(SeqpacketReceive::Eof)
        );
    });

    let connection = SeqpacketConnection::connect(&socket_path).expect("connect client");
    connection.send_packet(b"").expect("send empty record");
    drop(connection);

    server.join().expect("server thread");
}

#[test]
fn accepted_connection_reports_kernel_peer_credentials() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");

    let server = thread::spawn(move || {
        listener
            .accept()
            .expect("accept client")
            .peer_credentials()
            .expect("read peer credentials")
    });

    let _client = SeqpacketConnection::connect(&socket_path).expect("connect client");
    let credentials = server.join().expect("server thread");

    assert_eq!(credentials.pid(), std::process::id());
    // SAFETY: these functions have no pointer arguments or preconditions.
    let effective_uid = Uid::from_raw(unsafe { libc::geteuid() }).expect("valid effective UID");
    assert_eq!(credentials.uid(), effective_uid);
    // SAFETY: these functions have no pointer arguments or preconditions.
    assert_eq!(credentials.gid(), unsafe { libc::getegid() });
}

#[test]
fn root_peer_validation_uses_kernel_credentials() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");

    let server = thread::spawn(move || {
        listener
            .accept()
            .expect("accept client")
            .require_root_peer()
    });

    let _client = SeqpacketConnection::connect(&socket_path).expect("connect client");
    let result = server.join().expect("server thread");
    // SAFETY: `geteuid` has no pointer arguments or preconditions.
    let effective_uid = Uid::from_raw(unsafe { libc::geteuid() }).expect("valid effective UID");
    if effective_uid.is_root() {
        assert!(result.expect("root peer must be accepted").is_root());
    } else {
        match result.expect_err("non-root peer must be rejected") {
            PlatformError::PeerUidMismatch {
                expected_uid, uid, ..
            } => {
                assert_eq!(expected_uid, Uid::ROOT);
                assert_eq!(uid, effective_uid);
            }
            other => panic!("unexpected validation error: {other}"),
        }
    }
}

#[test]
fn same_effective_user_validation_accepts_the_local_client() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");

    let server = thread::spawn(move || {
        listener
            .accept()
            .expect("accept client")
            .require_same_effective_user()
    });

    let _client = SeqpacketConnection::connect(&socket_path).expect("connect client");
    let credentials = server
        .join()
        .expect("server thread")
        .expect("same effective user must be accepted");
    // SAFETY: `geteuid` has no pointer arguments or preconditions.
    let effective_uid = Uid::from_raw(unsafe { libc::geteuid() }).expect("valid effective UID");
    assert_eq!(credentials.uid(), effective_uid);
}

#[test]
fn oversized_packet_is_reported_without_losing_message_boundaries() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");

    let server = thread::spawn(move || {
        let connection = listener.accept().expect("accept client");
        let error = connection.recv_packet(4).expect_err("packet is too large");
        match error {
            PlatformError::PacketTooLarge { actual, limit } => {
                assert_eq!((actual, limit), (8, 4));
            }
            error => panic!("unexpected receive error: {error}"),
        }
    });

    let connection = SeqpacketConnection::connect(&socket_path).expect("connect client");
    connection
        .send_packet(b"12345678")
        .expect("send oversized request");

    server.join().expect("server thread");
}

#[test]
fn recv_packet_retries_after_signal_interruption() {
    let _serial = SIGNAL_TEST_LOCK.lock().expect("signal test lock");
    let _handler = SignalHandlerGuard::install();
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");
    let (thread_tx, thread_rx) = mpsc::channel();

    let server = thread::spawn(move || {
        let connection = listener.accept().expect("accept client");
        // SAFETY: pthread_self has no pointer arguments or preconditions.
        thread_tx
            .send(unsafe { libc::pthread_self() } as usize)
            .expect("publish server thread");
        connection.recv_packet(64)
    });

    let client = SeqpacketConnection::connect(&socket_path).expect("connect client");
    let server_thread = thread_rx.recv().expect("server thread identity");
    thread::sleep(Duration::from_millis(20));
    // SAFETY: `server_thread` names the live server thread and SIGUSR1 has a
    // process-wide non-restarting handler installed for this test.
    let kill_result =
        unsafe { libc::pthread_kill(server_thread as libc::pthread_t, libc::SIGUSR1) };
    assert_eq!(kill_result, 0);
    thread::sleep(Duration::from_millis(10));
    client.send_packet(b"request").expect("send after signal");

    assert_eq!(
        server
            .join()
            .expect("server thread")
            .expect("receive after signal"),
        b"request"
    );
}

#[test]
fn accept_retries_after_signal_interruption() {
    let _serial = SIGNAL_TEST_LOCK.lock().expect("signal test lock");
    let _handler = SignalHandlerGuard::install();
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");
    let (thread_tx, thread_rx) = mpsc::channel();

    let server = thread::spawn(move || {
        // SAFETY: pthread_self has no pointer arguments or preconditions.
        thread_tx
            .send(unsafe { libc::pthread_self() } as usize)
            .expect("publish server thread");
        let connection = listener.accept().expect("accept after signal");
        connection.recv_packet(64)
    });

    let server_thread = thread_rx.recv().expect("server thread identity");
    thread::sleep(Duration::from_millis(20));
    // SAFETY: `server_thread` names the live server thread and SIGUSR1 has a
    // process-wide non-restarting handler installed for this test.
    let kill_result =
        unsafe { libc::pthread_kill(server_thread as libc::pthread_t, libc::SIGUSR1) };
    assert_eq!(kill_result, 0);
    thread::sleep(Duration::from_millis(10));
    let client = SeqpacketConnection::connect(&socket_path).expect("connect after signal");
    client.send_packet(b"request").expect("send request");

    assert_eq!(
        server
            .join()
            .expect("server thread")
            .expect("receive request"),
        b"request"
    );
}

#[test]
fn send_packet_retries_after_signal_interruption() {
    const PACKET_COUNT: usize = 4096;
    const PACKET_SIZE: usize = 4096;

    let _serial = SIGNAL_TEST_LOCK.lock().expect("signal test lock");
    let _handler = SignalHandlerGuard::install();
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let (drain_tx, drain_rx) = mpsc::channel();

    let server = thread::spawn(move || {
        let connection = listener.accept().expect("accept client");
        accepted_tx.send(()).expect("publish accepted connection");
        drain_rx.recv().expect("wait before draining");
        let mut received = 0;
        loop {
            match connection.recv_packet(PACKET_SIZE) {
                Ok(packet) => {
                    assert_eq!(packet.len(), PACKET_SIZE);
                    received += 1;
                }
                Err(PlatformError::PeerClosed) => return received,
                Err(error) => panic!("receive queued packet: {error}"),
            }
        }
    });

    let connection = SeqpacketConnection::connect(&socket_path).expect("connect client");
    accepted_rx.recv().expect("server accepted client");
    let (thread_tx, thread_rx) = mpsc::channel();
    let (progress_tx, progress_rx) = mpsc::channel();
    let sender = thread::spawn(move || {
        // SAFETY: pthread_self has no pointer arguments or preconditions.
        thread_tx
            .send(unsafe { libc::pthread_self() } as usize)
            .expect("publish sender thread");
        let packet = vec![0x5a; PACKET_SIZE];
        for sent in 0..PACKET_COUNT {
            connection.send_packet(&packet)?;
            progress_tx.send(sent + 1).expect("publish send progress");
        }
        Ok::<(), PlatformError>(())
    });

    let sender_thread = thread_rx.recv().expect("sender thread identity");
    let mut progress = 0;
    loop {
        match progress_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(sent) => progress = sent,
            Err(mpsc::RecvTimeoutError::Timeout) if progress > 0 => break,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("sender completed before its socket buffer filled")
            }
        }
    }
    assert!(progress < PACKET_COUNT, "sender must be blocked in send");

    // SAFETY: `sender_thread` names the live sender thread and SIGUSR1 has a
    // process-wide non-restarting handler installed for this test.
    let kill_result =
        unsafe { libc::pthread_kill(sender_thread as libc::pthread_t, libc::SIGUSR1) };
    assert_eq!(kill_result, 0);
    thread::sleep(Duration::from_millis(10));
    drain_tx.send(()).expect("allow server to drain packets");

    sender
        .join()
        .expect("sender thread")
        .expect("send packets after signal");
    assert_eq!(server.join().expect("server thread"), PACKET_COUNT);
}
