#![cfg(any(target_os = "linux", target_os = "android"))]

use std::ffi::OsStr;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::num::{NonZeroU32, NonZeroU64};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::time::{Duration, Instant};

use super::implementation::{
    DumpDecoder, DumpSpec, RawNetlinkSocketAddress, encode_dump_request, parse_fd_name,
    parse_proc_stat, parse_socket_symlink_target, require_stable_socket_fds,
    validate_kernel_sender,
};
use super::*;

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;
const NLM_F_MULTI: u16 = 2;
const NLM_F_DUMP_INTR: u16 = 0x10;

#[test]
fn dump_requests_are_exact_and_connected_udp_is_state_filtered() {
    let tcp = DumpSpec {
        address_family: InetSocketAddressFamily::Ipv4,
        protocol: InetSocketProtocol::Tcp,
    };
    let udp = DumpSpec {
        address_family: InetSocketAddressFamily::Ipv6,
        protocol: InetSocketProtocol::Udp,
    };
    let sequence = NonZeroU32::new(9).unwrap();
    let tcp_request = encode_dump_request(tcp, sequence);
    let udp_request = encode_dump_request(udp, sequence);

    assert_eq!(u32::from_ne_bytes(tcp_request[..4].try_into().unwrap()), 72);
    assert_eq!(
        u16::from_ne_bytes(tcp_request[4..6].try_into().unwrap()),
        20
    );
    assert_eq!(
        u16::from_ne_bytes(tcp_request[6..8].try_into().unwrap()),
        0x301
    );
    assert_eq!(
        u32::from_ne_bytes(tcp_request[8..12].try_into().unwrap()),
        9
    );
    assert_eq!(tcp_request[12..16], [0; 4]);
    assert_eq!(tcp_request[16], libc::AF_INET as u8);
    assert_eq!(tcp_request[17], libc::IPPROTO_TCP as u8);
    assert_eq!(
        u32::from_ne_bytes(tcp_request[20..24].try_into().unwrap()),
        u32::MAX
    );
    assert_eq!(udp_request[16], libc::AF_INET6 as u8);
    assert_eq!(udp_request[17], libc::IPPROTO_UDP as u8);
    assert_eq!(
        u32::from_ne_bytes(udp_request[20..24].try_into().unwrap()),
        2
    );
    assert!(tcp_request[24..].iter().all(|byte| *byte == 0));
}

#[test]
fn proc_stat_parser_binds_pid_and_start_ticks_without_trusting_comm() {
    let mut fields = vec!["0"; 20];
    fields[0] = "S";
    fields[19] = "98765";
    let stat = format!("4242 (name with ) paren) {}\n", fields.join(" "));
    assert_eq!(
        parse_proc_stat(stat.as_bytes()),
        Some(SocketDiagnosticsProcessIdentity::new(
            NonZeroU32::new(4242).unwrap(),
            NonZeroU64::new(98765).unwrap()
        ))
    );

    assert!(parse_proc_stat(stat.replacen("4242", "04242", 1).as_bytes()).is_none());
    assert!(parse_proc_stat(stat.replacen("98765", "098765", 1).as_bytes()).is_none());
    assert!(parse_proc_stat(b"4242 (unterminated S 0 0").is_none());
}

#[test]
fn proc_fd_and_socket_targets_are_canonical_and_preserve_fd_zero() {
    assert_eq!(parse_fd_name(OsStr::new("0")), Some(0));
    assert_eq!(parse_fd_name(OsStr::new("2147483647")), Some(2_147_483_647));
    assert_eq!(parse_fd_name(OsStr::new("2147483648")), None);
    assert_eq!(parse_fd_name(OsStr::new("00")), None);
    assert_eq!(parse_fd_name(OsStr::new("-1")), None);
    assert_eq!(
        parse_socket_symlink_target(OsStr::new("socket:[1234]")),
        Ok(Some(NonZeroU64::new(1234).unwrap()))
    );
    assert_eq!(
        parse_socket_symlink_target(OsStr::new("/dev/null")),
        Ok(None)
    );
    for malformed in [
        "socket:1234",
        "socket:[]",
        "socket:[0]",
        "socket:[01234]",
        "socket:[1234]tail",
    ] {
        assert_eq!(parse_socket_symlink_target(OsStr::new(malformed)), Err(()));
    }
}

#[test]
fn decoder_accepts_exact_ipv4_record_with_cookie_uid_inode_and_mark() {
    let spec = ipv4_tcp();
    let mut attributes = attribute(15, &0x1234_5678_u32.to_ne_bytes());
    attributes.extend(attribute(10, &[libc::IPPROTO_TCP as u8]));
    let payload = diagnostic_payload(
        spec,
        1,
        "192.0.2.10:40000".parse().unwrap(),
        "198.51.100.20:443".parse().unwrap(),
        7,
        [11, 22],
        1000,
        4567,
        &attributes,
    );
    let mut datagram = netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 3, 44, &payload);
    datagram.extend(netlink_message(
        NLMSG_DONE,
        NLM_F_MULTI,
        3,
        44,
        &0_i32.to_ne_bytes(),
    ));
    let mut decoder = DumpDecoder::new(
        spec,
        NonZeroU32::new(3).unwrap(),
        NonZeroU32::new(44).unwrap(),
    );
    decoder.decode_datagram(&datagram).unwrap();
    let now = Instant::now();
    let records = decoder.finish(now, now).unwrap().sockets;
    assert_eq!(records.len(), 1);
    let record = records[0];
    assert_eq!(record.local_address(), "192.0.2.10:40000".parse().unwrap());
    assert_eq!(
        record.remote_address(),
        "198.51.100.20:443".parse().unwrap()
    );
    assert_eq!(record.interface_index(), 7);
    assert_eq!(record.cookie().words(), [11, 22]);
    assert_eq!(record.uid(), 1000);
    assert_eq!(record.inode(), 4567);
    assert_eq!(record.mark(), Some(0x1234_5678));
}

#[test]
fn decoder_preserves_exact_ipv6_tuple() {
    let spec = DumpSpec {
        address_family: InetSocketAddressFamily::Ipv6,
        protocol: InetSocketProtocol::Tcp,
    };
    let local = SocketAddr::new("2001:db8::1".parse().unwrap(), 12345);
    let remote = SocketAddr::new("2001:db8::2".parse().unwrap(), 443);
    let payload = diagnostic_payload(spec, 1, local, remote, 0, [1, 0], 42, 99, &[]);
    let mut decoder = decoder(spec);
    decoder
        .decode_datagram(&netlink_message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            7,
            8,
            &payload,
        ))
        .unwrap();
    decoder
        .decode_datagram(&netlink_message(NLMSG_DONE, NLM_F_MULTI, 7, 8, &[]))
        .unwrap();
    let now = Instant::now();
    let record = decoder.finish(now, now).unwrap().sockets[0];
    assert_eq!(record.local_address(), local);
    assert_eq!(record.remote_address(), remote);
    assert_eq!(record.address_family(), InetSocketAddressFamily::Ipv6);
}

#[test]
fn decoder_rejects_framing_terminal_and_transaction_ambiguity() {
    let payload = diagnostic_payload(
        ipv4_tcp(),
        1,
        "127.0.0.1:1000".parse().unwrap(),
        "127.0.0.1:2000".parse().unwrap(),
        0,
        [1, 2],
        1000,
        123,
        &[],
    );
    let cases = [
        vec![0; 15],
        netlink_message(NLMSG_OVERRUN, NLM_F_MULTI, 7, 8, &[]),
        netlink_message(NLMSG_ERROR, NLM_F_MULTI, 7, 8, &(-1_i32).to_ne_bytes()),
        netlink_message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI | NLM_F_DUMP_INTR,
            7,
            8,
            &payload,
        ),
        netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 6, 8, &payload),
        netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 7, 9, &payload),
        Vec::new(),
    ];
    for datagram in cases {
        assert_eq!(
            decoder(ipv4_tcp())
                .decode_datagram(&datagram)
                .unwrap_err()
                .kind(),
            SocketDiagnosticsErrorKind::NetlinkProtocol
        );
    }

    let mut after_done = netlink_message(NLMSG_DONE, NLM_F_MULTI, 7, 8, &[]);
    after_done.extend(netlink_message(
        SOCK_DIAG_BY_FAMILY,
        NLM_F_MULTI,
        7,
        8,
        &payload,
    ));
    assert!(decoder(ipv4_tcp()).decode_datagram(&after_done).is_err());
    let now = Instant::now();
    assert!(decoder(ipv4_tcp()).finish(now, now).is_err());
}

#[test]
fn decoder_rejects_unconnected_udp_missing_cookie_and_malformed_attributes() {
    let udp = DumpSpec {
        address_family: InetSocketAddressFamily::Ipv4,
        protocol: InetSocketProtocol::Udp,
    };
    let tuple = (
        "127.0.0.1:1000".parse().unwrap(),
        "127.0.0.1:2000".parse().unwrap(),
    );
    let unconnected = diagnostic_payload(udp, 7, tuple.0, tuple.1, 0, [1, 2], 1, 2, &[]);
    assert!(
        decoder(udp)
            .decode_datagram(&netlink_message(
                SOCK_DIAG_BY_FAMILY,
                NLM_F_MULTI,
                7,
                8,
                &unconnected,
            ))
            .is_err()
    );

    let no_cookie =
        diagnostic_payload(ipv4_tcp(), 1, tuple.0, tuple.1, 0, [u32::MAX; 2], 1, 2, &[]);
    assert!(
        decoder(ipv4_tcp())
            .decode_datagram(&netlink_message(
                SOCK_DIAG_BY_FAMILY,
                NLM_F_MULTI,
                7,
                8,
                &no_cookie,
            ))
            .is_err()
    );

    let mut malformed_mark = diagnostic_payload(
        ipv4_tcp(),
        1,
        tuple.0,
        tuple.1,
        0,
        [1, 2],
        1,
        2,
        &attribute(15, &[1]),
    );
    malformed_mark.extend_from_slice(&[]);
    assert!(
        decoder(ipv4_tcp())
            .decode_datagram(&netlink_message(
                SOCK_DIAG_BY_FAMILY,
                NLM_F_MULTI,
                7,
                8,
                &malformed_mark,
            ))
            .is_err()
    );
}

#[test]
fn sender_validation_rejects_every_non_kernel_field() {
    let kernel = RawNetlinkSocketAddress {
        family: libc::AF_NETLINK as u16,
        ..RawNetlinkSocketAddress::default()
    };
    validate_kernel_sender(kernel, 12).unwrap();
    for sender in [
        RawNetlinkSocketAddress {
            port_id: 9,
            ..kernel
        },
        RawNetlinkSocketAddress {
            groups: 1,
            ..kernel
        },
        RawNetlinkSocketAddress {
            padding: 1,
            ..kernel
        },
        RawNetlinkSocketAddress {
            family: libc::AF_INET as u16,
            ..kernel
        },
    ] {
        assert!(validate_kernel_sender(sender, 12).is_err());
    }
    assert!(validate_kernel_sender(kernel, 8).is_err());
}

#[test]
fn correlation_requires_one_exact_fd_inode_protocol_and_directional_tuple() {
    let local: SocketAddr = "127.0.0.1:1000".parse().unwrap();
    let remote: SocketAddr = "127.0.0.1:2000".parse().unwrap();
    let diagnostic = InetSocketDiagnostic {
        dump_sequence: NonZeroU32::new(1).unwrap(),
        address_family: InetSocketAddressFamily::Ipv4,
        protocol: InetSocketProtocol::Tcp,
        state: 1,
        local_address: local,
        remote_address: remote,
        interface_index: 0,
        uid: 1000,
        inode: 55,
        cookie: InetDiagCookie { words: [1, 2] },
        mark: None,
    };
    let snapshot = snapshot_with(vec![diagnostic]);
    assert_eq!(
        snapshot
            .correlate(0, InetSocketProtocol::Tcp, local, remote)
            .unwrap()
            .diagnostic(),
        diagnostic
    );
    assert_eq!(
        snapshot
            .correlate(1, InetSocketProtocol::Tcp, local, remote)
            .unwrap_err(),
        SocketCorrelationError::MissingProcessSocketFd { fd: 1 }
    );
    assert!(
        snapshot
            .correlate(0, InetSocketProtocol::Udp, local, remote)
            .is_err()
    );
    assert_eq!(
        snapshot_with(vec![diagnostic, diagnostic])
            .correlate(0, InetSocketProtocol::Tcp, local, remote)
            .unwrap_err(),
        SocketCorrelationError::AmbiguousDiagnostic { fd: 0 }
    );
}

#[test]
fn changed_socket_fd_mapping_cannot_be_returned_as_complete() {
    let process = SocketDiagnosticsProcessIdentity::new(
        NonZeroU32::new(42).unwrap(),
        NonZeroU64::new(99).unwrap(),
    );
    let initial = [ProcessSocketFd {
        fd: 0,
        inode: NonZeroU64::new(10).unwrap(),
    }];
    assert!(require_stable_socket_fds(process, &initial, &initial).is_ok());
    let reused = [ProcessSocketFd {
        fd: 0,
        inode: NonZeroU64::new(11).unwrap(),
    }];
    assert_eq!(
        require_stable_socket_fds(process, &initial, &reused)
            .unwrap_err()
            .kind(),
        SocketDiagnosticsErrorKind::ProcessSocketFdsChanged
    );
}

#[test]
fn collection_deadline_is_exclusive_and_checked_before_procfs_access() {
    let identity = SocketDiagnosticsProcessIdentity::new(
        NonZeroU32::new(u32::MAX).unwrap(),
        NonZeroU64::new(1).unwrap(),
    );
    let deadline = Instant::now();
    let error = SystemSocketDiagnosticsSource
        .collect_until(identity, deadline)
        .unwrap_err();
    assert_eq!(error.kind(), SocketDiagnosticsErrorKind::DeadlineExpired);
}

#[test]
fn live_same_process_tcp_and_connected_udp_are_exactly_correlated() {
    const CHILD_MODE: &str = "FLUX_SOCKET_DIAGNOSTICS_LIVE_CHILD";
    const CHILD_TOKEN: &str = "socket-diag-live-v1";
    const CHILD_PARENT: &str = "FLUX_SOCKET_DIAGNOSTICS_LIVE_PARENT";
    // SAFETY: `getppid` has no pointer arguments or preconditions.
    let parent_pid = unsafe { libc::getppid() };
    let is_isolated_child = std::env::var_os(CHILD_MODE).as_deref()
        == Some(OsStr::new(CHILD_TOKEN))
        && std::env::var(CHILD_PARENT)
            .ok()
            .and_then(|value| value.parse::<libc::pid_t>().ok())
            == Some(parent_pid);
    if !is_isolated_child {
        // SAFETY: `getpid` has no pointer arguments or preconditions.
        let process_id = unsafe { libc::getpid() };
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                "socket_diagnostics::tests::live_same_process_tcp_and_connected_udp_are_exactly_correlated",
            )
            .arg("--test-threads=1")
            .env_clear()
            .env(CHILD_MODE, CHILD_TOKEN)
            .env(CHILD_PARENT, process_id.to_string())
            .status()
            .unwrap();
        assert!(status.success(), "isolated socket-diagnostic smoke failed");
        return;
    }

    let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let tcp_client = TcpStream::connect(tcp_listener.local_addr().unwrap()).unwrap();
    let (tcp_server, _) = tcp_listener.accept().unwrap();
    let udp_left = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let udp_right = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    udp_left.connect(udp_right.local_addr().unwrap()).unwrap();
    udp_right.connect(udp_left.local_addr().unwrap()).unwrap();

    let identity = parse_proc_stat(&fs::read("/proc/self/stat").unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let snapshot = SystemSocketDiagnosticsSource
        .collect_until(identity, deadline)
        .unwrap();
    // SAFETY: `geteuid` has no pointer arguments or preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    assert_eq!(snapshot.process(), identity);
    assert!(snapshot.fd_scan_complete());
    assert!(snapshot.diag_dumps_complete());
    assert_eq!(snapshot.dumps().len(), 4);
    assert!(snapshot.started_at() <= snapshot.completed_at());
    assert!(snapshot.completed_at() < deadline);
    assert!(snapshot.dumps().iter().all(|dump| {
        snapshot.started_at() <= dump.started_at()
            && dump.started_at() <= dump.completed_at()
            && dump.completed_at() <= snapshot.completed_at()
    }));

    let tcp = snapshot
        .correlate(
            u32::try_from(tcp_client.as_raw_fd()).unwrap(),
            InetSocketProtocol::Tcp,
            tcp_client.local_addr().unwrap(),
            tcp_client.peer_addr().unwrap(),
        )
        .unwrap();
    assert_eq!(tcp.diagnostic().uid(), effective_uid);
    assert_ne!(tcp.diagnostic().cookie().words(), [u32::MAX; 2]);

    let udp = snapshot
        .correlate(
            u32::try_from(udp_left.as_raw_fd()).unwrap(),
            InetSocketProtocol::Udp,
            udp_left.local_addr().unwrap(),
            udp_left.peer_addr().unwrap(),
        )
        .unwrap();
    assert_eq!(udp.diagnostic().state(), 1);
    assert_eq!(udp.diagnostic().uid(), effective_uid);

    drop((tcp_server, tcp_client, tcp_listener, udp_left, udp_right));
}

fn decoder(spec: DumpSpec) -> DumpDecoder {
    DumpDecoder::new(
        spec,
        NonZeroU32::new(7).unwrap(),
        NonZeroU32::new(8).unwrap(),
    )
}

fn ipv4_tcp() -> DumpSpec {
    DumpSpec {
        address_family: InetSocketAddressFamily::Ipv4,
        protocol: InetSocketProtocol::Tcp,
    }
}

#[allow(clippy::too_many_arguments)]
fn diagnostic_payload(
    spec: DumpSpec,
    state: u8,
    local: SocketAddr,
    remote: SocketAddr,
    interface_index: u32,
    cookie: [u32; 2],
    uid: u32,
    inode: u32,
    attributes: &[u8],
) -> Vec<u8> {
    let mut payload = vec![0_u8; 72];
    payload[0] = match spec.address_family {
        InetSocketAddressFamily::Ipv4 => libc::AF_INET as u8,
        InetSocketAddressFamily::Ipv6 => libc::AF_INET6 as u8,
    };
    payload[1] = state;
    payload[4..6].copy_from_slice(&local.port().to_be_bytes());
    payload[6..8].copy_from_slice(&remote.port().to_be_bytes());
    encode_ip(local.ip(), &mut payload[8..24]);
    encode_ip(remote.ip(), &mut payload[24..40]);
    payload[40..44].copy_from_slice(&interface_index.to_ne_bytes());
    payload[44..48].copy_from_slice(&cookie[0].to_ne_bytes());
    payload[48..52].copy_from_slice(&cookie[1].to_ne_bytes());
    payload[64..68].copy_from_slice(&uid.to_ne_bytes());
    payload[68..72].copy_from_slice(&inode.to_ne_bytes());
    payload.extend_from_slice(attributes);
    payload
}

fn encode_ip(ip: IpAddr, target: &mut [u8]) {
    target.fill(0);
    match ip {
        IpAddr::V4(address) => target[..4].copy_from_slice(&address.octets()),
        IpAddr::V6(address) => target.copy_from_slice(&address.octets()),
    }
}

fn attribute(attribute_type: u16, value: &[u8]) -> Vec<u8> {
    let length = 4 + value.len();
    let aligned = (length + 3) & !3;
    let mut attribute = vec![0_u8; aligned];
    attribute[..2].copy_from_slice(&(length as u16).to_ne_bytes());
    attribute[2..4].copy_from_slice(&attribute_type.to_ne_bytes());
    attribute[4..length].copy_from_slice(value);
    attribute
}

fn netlink_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    port_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let length = 16 + payload.len();
    let aligned = (length + 3) & !3;
    let mut message = vec![0_u8; aligned];
    message[..4].copy_from_slice(&(length as u32).to_ne_bytes());
    message[4..6].copy_from_slice(&message_type.to_ne_bytes());
    message[6..8].copy_from_slice(&flags.to_ne_bytes());
    message[8..12].copy_from_slice(&sequence.to_ne_bytes());
    message[12..16].copy_from_slice(&port_id.to_ne_bytes());
    message[16..length].copy_from_slice(payload);
    message
}

fn snapshot_with(sockets: Vec<InetSocketDiagnostic>) -> ProcessSocketDiagnostics {
    ProcessSocketDiagnostics {
        process: SocketDiagnosticsProcessIdentity::new(
            NonZeroU32::new(1).unwrap(),
            NonZeroU64::new(1).unwrap(),
        ),
        netlink_port_id: NonZeroU32::new(1).unwrap(),
        started_at: Instant::now(),
        completed_at: Instant::now(),
        socket_fds: vec![ProcessSocketFd {
            fd: 0,
            inode: NonZeroU64::new(55).unwrap(),
        }]
        .into_boxed_slice(),
        dumps: Box::default(),
        sockets: sockets.into_boxed_slice(),
    }
}
