#![cfg(any(target_os = "linux", target_os = "android"))]

use std::thread;

use flux_platform::{SeqpacketConnection, SeqpacketListener};
use tempfile::tempdir;

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
fn oversized_packet_is_reported_without_losing_message_boundaries() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("fluxd.sock");
    let listener = SeqpacketListener::bind(&socket_path).expect("bind listener");

    let server = thread::spawn(move || {
        let connection = listener.accept().expect("accept client");
        let error = connection.recv_packet(4).expect_err("packet is too large");
        assert!(error.to_string().contains("exceeds 4 bytes"));
    });

    let connection = SeqpacketConnection::connect(&socket_path).expect("connect client");
    connection
        .send_packet(b"12345678")
        .expect("send oversized request");

    server.join().expect("server thread");
}
