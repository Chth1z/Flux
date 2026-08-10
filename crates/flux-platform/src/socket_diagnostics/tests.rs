#![cfg(any(target_os = "linux", target_os = "android"))]

use std::ffi::OsStr;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::time::{Duration, Instant};

use super::implementation::{
    DumpDecoder, DumpSequenceState, DumpSpec, ListenerDumpSpec, RawNetlinkSocketAddress,
    bounded_session_deadline, encode_dump_request, encode_listener_dump_request, parse_fd_name,
    parse_proc_stat, parse_socket_symlink_target, require_stable_socket_fds,
    validate_kernel_sender, validate_listener_conflict_targets,
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
fn listener_dump_requests_filter_tcp_listen_and_udp_close_by_big_endian_source_port() {
    let udp = ListenerDumpSpec {
        address_family: InetSocketAddressFamily::Ipv6,
        protocol: InetSocketProtocol::Udp,
        source_port: NonZeroU16::new(15_361).unwrap(),
    };
    let tcp = ListenerDumpSpec {
        address_family: InetSocketAddressFamily::Ipv4,
        protocol: InetSocketProtocol::Tcp,
        source_port: NonZeroU16::new(0x1234).unwrap(),
    };
    let sequence = NonZeroU32::new(19).unwrap();
    let udp_request = encode_listener_dump_request(udp, sequence);
    let tcp_request = encode_listener_dump_request(tcp, sequence);

    assert_eq!(udp_request[16], libc::AF_INET6 as u8);
    assert_eq!(udp_request[17], libc::IPPROTO_UDP as u8);
    assert_eq!(
        u32::from_ne_bytes(udp_request[20..24].try_into().unwrap()),
        1_u32 << 7
    );
    assert_eq!(
        u16::from_be_bytes(udp_request[24..26].try_into().unwrap()),
        15_361
    );
    assert!(udp_request[26..].iter().all(|byte| *byte == 0));
    assert_eq!(tcp_request[16], libc::AF_INET as u8);
    assert_eq!(tcp_request[17], libc::IPPROTO_TCP as u8);
    assert_eq!(
        u32::from_ne_bytes(tcp_request[20..24].try_into().unwrap()),
        1_u32 << 10
    );
    assert_eq!(&tcp_request[24..26], &[0x12, 0x34]);
}

#[test]
fn listener_decoder_exposes_transparency_and_ipv6_only_state() {
    let spec = ListenerDumpSpec {
        address_family: InetSocketAddressFamily::Ipv6,
        protocol: InetSocketProtocol::Udp,
        source_port: NonZeroU16::new(15_361).unwrap(),
    };
    let mut attributes = attribute(11, &[1]);
    attributes.extend(attribute(22, &[0x20, 0]));
    let payload = diagnostic_payload(
        DumpSpec {
            address_family: spec.address_family,
            protocol: InetSocketProtocol::Udp,
        },
        7,
        "[::]:15361".parse().unwrap(),
        "[::]:0".parse().unwrap(),
        0,
        [11, 22],
        1000,
        4567,
        &attributes,
    );
    let mut decoder = DumpDecoder::new_listener(
        spec,
        NonZeroU32::new(3).unwrap(),
        NonZeroU32::new(44).unwrap(),
    );
    decoder
        .decode_datagram(&netlink_message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            3,
            44,
            &payload,
        ))
        .unwrap();
    decoder
        .decode_datagram(&netlink_message(NLMSG_DONE, NLM_F_MULTI, 3, 44, &[]))
        .unwrap();
    let now = Instant::now();
    let record = decoder.finish(now, now).unwrap().sockets[0];
    assert_eq!(record.state(), 7);
    assert_eq!(record.transparent(), Some(true));
    assert_eq!(record.ipv6_only(), Some(true));
}

#[test]
fn listener_conflict_decoder_accepts_zero_row_done_and_synthetic_ipv6() {
    let spec = ListenerDumpSpec {
        address_family: InetSocketAddressFamily::Ipv6,
        protocol: InetSocketProtocol::Tcp,
        source_port: NonZeroU16::new(15_361).unwrap(),
    };
    let sequence = NonZeroU32::new(3).unwrap();
    let port_id = NonZeroU32::new(44).unwrap();
    let now = Instant::now();
    let mut empty = DumpDecoder::new_listener(spec, sequence, port_id);
    empty
        .decode_datagram(&netlink_message(NLMSG_DONE, NLM_F_MULTI, 3, 44, &[]))
        .unwrap();
    assert!(empty.finish(now, now).unwrap().sockets.is_empty());

    let dump_spec = DumpSpec {
        address_family: InetSocketAddressFamily::Ipv6,
        protocol: InetSocketProtocol::Tcp,
    };
    let payload = diagnostic_payload(
        dump_spec,
        10,
        "[2001:db8::1]:15361".parse().unwrap(),
        "[::]:0".parse().unwrap(),
        0,
        [4, 5],
        1000,
        77,
        &attribute(10, &[libc::IPPROTO_TCP as u8]),
    );
    let mut decoder = DumpDecoder::new_listener(spec, sequence, port_id);
    decoder
        .decode_datagram(&netlink_message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            3,
            44,
            &payload,
        ))
        .unwrap();
    decoder
        .decode_datagram(&netlink_message(NLMSG_DONE, NLM_F_MULTI, 3, 44, &[]))
        .unwrap();
    let record = decoder.finish(now, now).unwrap().sockets[0];
    assert_eq!(record.address_family(), InetSocketAddressFamily::Ipv6);
    assert_eq!(record.protocol(), InetSocketProtocol::Tcp);
    assert_eq!(record.state(), 10);
    assert_eq!(
        record.local_address(),
        "[2001:db8::1]:15361".parse().unwrap()
    );
}

#[test]
fn listener_conflict_decoder_rejects_substituted_transaction_and_row_fields() {
    let spec = ListenerDumpSpec {
        address_family: InetSocketAddressFamily::Ipv6,
        protocol: InetSocketProtocol::Tcp,
        source_port: NonZeroU16::new(15_361).unwrap(),
    };
    let expected = DumpSpec {
        address_family: InetSocketAddressFamily::Ipv6,
        protocol: InetSocketProtocol::Tcp,
    };
    let payload = |dump_spec, state, local: SocketAddr, attributes: &[u8]| {
        diagnostic_payload(
            dump_spec,
            state,
            local,
            "[::]:0".parse().unwrap(),
            0,
            [7, 8],
            1000,
            88,
            attributes,
        )
    };
    let wrong_family = payload(
        DumpSpec {
            address_family: InetSocketAddressFamily::Ipv4,
            protocol: InetSocketProtocol::Tcp,
        },
        10,
        "127.0.0.1:15361".parse().unwrap(),
        &[],
    );
    let wrong_state = payload(expected, 1, "[::1]:15361".parse().unwrap(), &[]);
    let wrong_port = payload(expected, 10, "[::1]:15362".parse().unwrap(), &[]);
    let wrong_protocol = payload(
        expected,
        10,
        "[::1]:15361".parse().unwrap(),
        &attribute(10, &[libc::IPPROTO_UDP as u8]),
    );
    for datagram in [
        netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 3, 44, &wrong_family),
        netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 3, 44, &wrong_state),
        netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 3, 44, &wrong_port),
        netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 3, 44, &wrong_protocol),
        netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 4, 44, &wrong_state),
        netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 3, 45, &wrong_state),
    ] {
        assert_eq!(
            DumpDecoder::new_listener(
                spec,
                NonZeroU32::new(3).unwrap(),
                NonZeroU32::new(44).unwrap(),
            )
            .decode_datagram(&datagram)
            .unwrap_err()
            .kind(),
            SocketDiagnosticsErrorKind::NetlinkProtocol
        );
    }

    let now = Instant::now();
    assert!(
        DumpDecoder::new_listener(
            spec,
            NonZeroU32::new(3).unwrap(),
            NonZeroU32::new(44).unwrap(),
        )
        .finish(now, now)
        .is_err()
    );
    let mut after_done = DumpDecoder::new_listener(
        spec,
        NonZeroU32::new(3).unwrap(),
        NonZeroU32::new(44).unwrap(),
    );
    after_done
        .decode_datagram(&netlink_message(NLMSG_DONE, NLM_F_MULTI, 3, 44, &[]))
        .unwrap();
    assert!(
        after_done
            .decode_datagram(&netlink_message(
                SOCK_DIAG_BY_FAMILY,
                NLM_F_MULTI,
                3,
                44,
                &payload(expected, 10, "[::1]:15361".parse().unwrap(), &[]),
            ))
            .is_err()
    );
}

#[test]
fn transparent_listener_correlation_requires_one_row_and_one_fd_inode_join() {
    let local: SocketAddr = "0.0.0.0:15361".parse().unwrap();
    let remote: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let diagnostic = InetSocketDiagnostic {
        dump_sequence: NonZeroU32::new(1).unwrap(),
        address_family: InetSocketAddressFamily::Ipv4,
        protocol: InetSocketProtocol::Tcp,
        state: 10,
        local_address: local,
        remote_address: remote,
        interface_index: 0,
        uid: 1000,
        inode: 55,
        cookie: InetDiagCookie { words: [1, 2] },
        mark: None,
        transparent: Some(true),
        ipv6_only: None,
    };
    let snapshot = snapshot_with(vec![diagnostic]);
    let correlated = snapshot
        .correlate_transparent_listener(
            InetSocketAddressFamily::Ipv4,
            InetSocketProtocol::Tcp,
            NonZeroU16::new(15361).unwrap(),
        )
        .unwrap();
    assert_eq!(correlated.process_fd().fd(), 0);
    assert_eq!(correlated.diagnostic(), diagnostic);

    let ambiguous_fd = ProcessSocketDiagnostics {
        socket_fds: vec![
            ProcessSocketFd {
                fd: 0,
                inode: NonZeroU64::new(55).unwrap(),
            },
            ProcessSocketFd {
                fd: 1,
                inode: NonZeroU64::new(55).unwrap(),
            },
        ]
        .into_boxed_slice(),
        ..snapshot_with(vec![diagnostic])
    };
    assert!(
        ambiguous_fd
            .correlate_transparent_listener(
                InetSocketAddressFamily::Ipv4,
                InetSocketProtocol::Tcp,
                NonZeroU16::new(15361).unwrap(),
            )
            .is_err()
    );
}

#[test]
fn transparent_listener_correlation_rejects_wrong_role_state_tuple_and_attributes() {
    let base = InetSocketDiagnostic {
        dump_sequence: NonZeroU32::new(1).unwrap(),
        address_family: InetSocketAddressFamily::Ipv4,
        protocol: InetSocketProtocol::Tcp,
        state: 10,
        local_address: "0.0.0.0:15361".parse().unwrap(),
        remote_address: "0.0.0.0:0".parse().unwrap(),
        interface_index: 0,
        uid: 1000,
        inode: 55,
        cookie: InetDiagCookie { words: [1, 2] },
        mark: None,
        transparent: Some(true),
        ipv6_only: None,
    };
    let port = NonZeroU16::new(15361).unwrap();
    let assert_missing = |diagnostic: InetSocketDiagnostic| {
        assert_eq!(
            snapshot_with(vec![diagnostic])
                .correlate_transparent_listener(
                    InetSocketAddressFamily::Ipv4,
                    InetSocketProtocol::Tcp,
                    port,
                )
                .unwrap_err(),
            ListenerSocketCorrelationError::MissingDiagnostic {
                address_family: InetSocketAddressFamily::Ipv4,
                protocol: InetSocketProtocol::Tcp,
                port,
            }
        );
    };
    assert_missing(InetSocketDiagnostic { state: 7, ..base });
    assert_missing(InetSocketDiagnostic {
        local_address: "127.0.0.1:15361".parse().unwrap(),
        ..base
    });
    assert_missing(InetSocketDiagnostic {
        remote_address: "0.0.0.0:9".parse().unwrap(),
        ..base
    });
    assert_missing(InetSocketDiagnostic {
        transparent: Some(false),
        ..base
    });
    assert_missing(InetSocketDiagnostic {
        ipv6_only: Some(false),
        ..base
    });

    let ipv6 = InetSocketDiagnostic {
        dump_sequence: NonZeroU32::new(3).unwrap(),
        address_family: InetSocketAddressFamily::Ipv6,
        protocol: InetSocketProtocol::Tcp,
        state: 10,
        local_address: "[::]:15361".parse().unwrap(),
        remote_address: "[::]:0".parse().unwrap(),
        interface_index: 0,
        uid: 1000,
        inode: 56,
        cookie: InetDiagCookie { words: [2, 3] },
        mark: None,
        transparent: Some(true),
        ipv6_only: Some(true),
    };
    assert!(
        snapshot_with(vec![ipv6])
            .correlate_transparent_listener(
                InetSocketAddressFamily::Ipv6,
                InetSocketProtocol::Tcp,
                port,
            )
            .is_err()
    );
}

#[test]
fn complete_four_role_listener_snapshot_correlates_distinct_socket_identities() {
    let observed_at = Instant::now();
    let port = NonZeroU16::new(15_361).unwrap();
    let roles = [
        (
            InetSocketAddressFamily::Ipv4,
            InetSocketProtocol::Tcp,
            10,
            "0.0.0.0:15361".parse().unwrap(),
            "0.0.0.0:0".parse().unwrap(),
            None,
            1,
        ),
        (
            InetSocketAddressFamily::Ipv4,
            InetSocketProtocol::Udp,
            7,
            "0.0.0.0:15361".parse().unwrap(),
            "0.0.0.0:0".parse().unwrap(),
            None,
            5,
        ),
        (
            InetSocketAddressFamily::Ipv6,
            InetSocketProtocol::Tcp,
            10,
            "[::]:15361".parse().unwrap(),
            "[::]:0".parse().unwrap(),
            Some(true),
            3,
        ),
        (
            InetSocketAddressFamily::Ipv6,
            InetSocketProtocol::Udp,
            7,
            "[::]:15361".parse().unwrap(),
            "[::]:0".parse().unwrap(),
            Some(true),
            6,
        ),
    ];
    let sockets = roles
        .into_iter()
        .enumerate()
        .map(
            |(index, (address_family, protocol, state, local, remote, ipv6_only, sequence))| {
                InetSocketDiagnostic {
                    dump_sequence: NonZeroU32::new(sequence).unwrap(),
                    address_family,
                    protocol,
                    state,
                    local_address: local,
                    remote_address: remote,
                    interface_index: 0,
                    uid: 1000,
                    inode: 55 + u64::try_from(index).unwrap(),
                    cookie: InetDiagCookie {
                        words: [1 + u32::try_from(index).unwrap(), 11],
                    },
                    mark: None,
                    transparent: Some(true),
                    ipv6_only,
                }
            },
        )
        .collect::<Vec<_>>();
    let socket_fds = sockets
        .iter()
        .enumerate()
        .map(|(index, diagnostic)| ProcessSocketFd {
            fd: 10 + u32::try_from(index).unwrap(),
            inode: NonZeroU64::new(diagnostic.inode()).unwrap(),
        })
        .collect::<Vec<_>>();
    let snapshot = ProcessSocketDiagnostics {
        process: SocketDiagnosticsProcessIdentity::new(
            NonZeroU32::new(1).unwrap(),
            NonZeroU64::new(1).unwrap(),
        ),
        netlink_port_id: NonZeroU32::new(1).unwrap(),
        started_at: observed_at,
        completed_at: observed_at,
        socket_fds: socket_fds.into_boxed_slice(),
        dumps: broad_dumps(observed_at),
        listener_port: Some(port),
        listener_dumps: [
            InetSocketDump {
                sequence: NonZeroU32::new(5).unwrap(),
                address_family: InetSocketAddressFamily::Ipv4,
                protocol: InetSocketProtocol::Udp,
                started_at: observed_at,
                completed_at: observed_at,
            },
            InetSocketDump {
                sequence: NonZeroU32::new(6).unwrap(),
                address_family: InetSocketAddressFamily::Ipv6,
                protocol: InetSocketProtocol::Udp,
                started_at: observed_at,
                completed_at: observed_at,
            },
        ]
        .into(),
        sockets: sockets.into_boxed_slice(),
    };

    assert!(snapshot.diag_dumps_complete());
    assert!(snapshot.listener_diag_dumps_complete());
    assert_eq!(
        roles.map(|(family, protocol, ..)| snapshot.listener_role_sequence(family, protocol)),
        [1, 5, 3, 6].map(NonZeroU32::new)
    );
    let correlated = roles.map(|(family, protocol, ..)| {
        snapshot
            .correlate_transparent_listener(family, protocol, port)
            .unwrap()
    });
    assert_eq!(
        correlated.map(|socket| socket.process_fd().fd()),
        [10, 11, 12, 13]
    );
    assert_eq!(
        correlated.map(|socket| socket.diagnostic().inode()),
        [55, 56, 57, 58]
    );
    assert_eq!(
        correlated.map(|socket| socket.diagnostic().cookie().words()),
        [[1, 11], [2, 11], [3, 11], [4, 11]]
    );

    let mut gapped = snapshot.clone();
    gapped.listener_dumps[0].sequence = NonZeroU32::new(7).unwrap();
    gapped.listener_dumps[1].sequence = NonZeroU32::new(8).unwrap();
    assert!(!gapped.listener_diag_dumps_complete());
    assert_eq!(
        gapped.listener_role_sequence(InetSocketAddressFamily::Ipv4, InetSocketProtocol::Tcp,),
        None
    );
    assert!(
        gapped
            .correlate_transparent_listener(
                InetSocketAddressFamily::Ipv4,
                InetSocketProtocol::Udp,
                port,
            )
            .is_err()
    );
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
fn deterministic_arbitrary_datagrams_never_panic() {
    const CASES: usize = 4_096;
    const MAX_LENGTH: usize = 768;

    let mut state = 0x5e8d_2a41_7c93_b06f_u64;
    for case in 0..CASES {
        let length = (next_random(&mut state) as usize) % (MAX_LENGTH + 1);
        let mut datagram = vec![0_u8; length];
        for byte in &mut datagram {
            *byte = next_random(&mut state) as u8;
        }

        for spec in DumpSpec::all() {
            let outcome = std::panic::catch_unwind(|| decoder(spec).decode_datagram(&datagram));
            assert!(
                outcome.is_ok(),
                "socket-diagnostics decoder panicked for deterministic case {case} ({spec:?})"
            );
        }
    }
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

    for attributes in [
        attribute(22, &[0x20]),
        {
            let mut duplicate = attribute(22, &[0x20, 0]);
            duplicate.extend(attribute(22, &[0, 0]));
            duplicate
        },
        attribute(11, &[2]),
    ] {
        let payload = diagnostic_payload(
            ipv4_tcp(),
            10,
            "0.0.0.0:15361".parse().unwrap(),
            "0.0.0.0:0".parse().unwrap(),
            0,
            [1, 2],
            1,
            2,
            &attributes,
        );
        assert!(
            decoder(ipv4_tcp())
                .decode_datagram(&netlink_message(
                    SOCK_DIAG_BY_FAMILY,
                    NLM_F_MULTI,
                    7,
                    8,
                    &payload,
                ))
                .is_err()
        );
    }
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
        transparent: None,
        ipv6_only: None,
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
    let session = SystemSocketDiagnosticsSource
        .open_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
    let error = match session.collect_process_until(identity, Instant::now()) {
        Ok(_) => panic!("an expired deadline cannot collect a diagnostic snapshot"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), SocketDiagnosticsErrorKind::DeadlineExpired);
}

#[test]
fn session_open_deadline_is_exclusive() {
    let error = match SystemSocketDiagnosticsSource.open_until(Instant::now()) {
        Ok(_) => panic!("an expired deadline cannot open a diagnostic session"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), SocketDiagnosticsErrorKind::DeadlineExpired);
}

#[test]
fn session_sequences_are_monotonic_nonzero_and_never_wrap() {
    let mut ordinary = DumpSequenceState::starting_at(NonZeroU32::new(1).unwrap());
    assert_eq!(
        ordinary.reserve_snapshot().unwrap().map(NonZeroU32::get),
        [1, 2, 3, 4]
    );
    assert_eq!(
        ordinary.reserve_snapshot().unwrap().map(NonZeroU32::get),
        [5, 6, 7, 8]
    );

    let mut final_complete = DumpSequenceState::starting_at(NonZeroU32::new(u32::MAX - 3).unwrap());
    assert_eq!(
        final_complete
            .reserve_snapshot()
            .unwrap()
            .map(NonZeroU32::get),
        [u32::MAX - 3, u32::MAX - 2, u32::MAX - 1, u32::MAX]
    );
    assert_eq!(
        final_complete.reserve_snapshot().unwrap_err().kind(),
        SocketDiagnosticsErrorKind::CollectionLimitExceeded
    );

    let mut insufficient = DumpSequenceState::starting_at(NonZeroU32::new(u32::MAX - 2).unwrap());
    assert_eq!(
        insufficient.reserve_snapshot().unwrap_err().kind(),
        SocketDiagnosticsErrorKind::CollectionLimitExceeded
    );
    assert_eq!(
        insufficient.reserve_snapshot().unwrap_err().kind(),
        SocketDiagnosticsErrorKind::CollectionLimitExceeded
    );
}

#[test]
fn listener_conflict_targets_are_bounded_ordered_and_unique() {
    let target = ListenerConflictTarget::new(
        InetSocketAddressFamily::Ipv4,
        InetSocketProtocol::Tcp,
        NonZeroU16::new(15_361).unwrap(),
    );
    assert_eq!(
        validate_listener_conflict_targets(&[]).unwrap_err().kind(),
        SocketDiagnosticsErrorKind::InvalidRequest
    );
    assert_eq!(
        validate_listener_conflict_targets(&[target, target])
            .unwrap_err()
            .kind(),
        SocketDiagnosticsErrorKind::InvalidRequest
    );

    let too_many = (0..=MAX_LISTENER_CONFLICT_TARGETS)
        .map(|offset| {
            ListenerConflictTarget::new(
                InetSocketAddressFamily::Ipv4,
                InetSocketProtocol::Udp,
                NonZeroU16::new(20_000 + u16::try_from(offset).unwrap()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        validate_listener_conflict_targets(&too_many)
            .unwrap_err()
            .kind(),
        SocketDiagnosticsErrorKind::CollectionLimitExceeded
    );

    let ordered = [
        target,
        ListenerConflictTarget::new(
            InetSocketAddressFamily::Ipv4,
            InetSocketProtocol::Udp,
            target.source_port(),
        ),
        ListenerConflictTarget::new(
            InetSocketAddressFamily::Ipv6,
            InetSocketProtocol::Tcp,
            target.source_port(),
        ),
    ];
    validate_listener_conflict_targets(&ordered).unwrap();
    assert_eq!(
        ordered.map(ListenerConflictTarget::protocol),
        [
            InetSocketProtocol::Tcp,
            InetSocketProtocol::Udp,
            InetSocketProtocol::Tcp,
        ]
    );
}

#[test]
fn listener_conflict_sequence_reservation_is_dynamic_contiguous_and_exhausting() {
    let mut ordinary = DumpSequenceState::starting_at(NonZeroU32::new(1).unwrap());
    assert_eq!(
        ordinary.reserve_listener_conflicts(0).unwrap_err().kind(),
        SocketDiagnosticsErrorKind::InvalidRequest
    );
    assert_eq!(
        ordinary
            .reserve_listener_conflicts(MAX_LISTENER_CONFLICT_TARGETS + 1)
            .unwrap_err()
            .kind(),
        SocketDiagnosticsErrorKind::CollectionLimitExceeded
    );
    assert_eq!(
        ordinary
            .reserve_listener_conflicts(3)
            .unwrap()
            .into_iter()
            .map(NonZeroU32::get)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(
        ordinary.reserve_snapshot().unwrap().map(NonZeroU32::get),
        [4, 5, 6, 7]
    );

    let mut final_complete = DumpSequenceState::starting_at(NonZeroU32::new(u32::MAX - 2).unwrap());
    assert_eq!(
        final_complete
            .reserve_listener_conflicts(3)
            .unwrap()
            .into_iter()
            .map(NonZeroU32::get)
            .collect::<Vec<_>>(),
        [u32::MAX - 2, u32::MAX - 1, u32::MAX]
    );
    assert_eq!(
        final_complete
            .reserve_listener_conflicts(1)
            .unwrap_err()
            .kind(),
        SocketDiagnosticsErrorKind::CollectionLimitExceeded
    );

    let mut insufficient = DumpSequenceState::starting_at(NonZeroU32::new(u32::MAX - 1).unwrap());
    assert_eq!(
        insufficient
            .reserve_listener_conflicts(3)
            .unwrap_err()
            .kind(),
        SocketDiagnosticsErrorKind::CollectionLimitExceeded
    );
    assert_eq!(
        insufficient
            .reserve_listener_conflicts(1)
            .unwrap_err()
            .kind(),
        SocketDiagnosticsErrorKind::CollectionLimitExceeded
    );
}

#[test]
fn later_collection_deadline_cannot_extend_the_session_ceiling() {
    let opened = Instant::now();
    let hard = opened + Duration::from_secs(3);
    assert_eq!(
        bounded_session_deadline(hard, opened + Duration::from_secs(2)),
        opened + Duration::from_secs(2)
    );
    assert_eq!(
        bounded_session_deadline(hard, opened + Duration::from_secs(4)),
        hard
    );
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
    let fd_count_before_expiring_session = proc_fd_count();
    let mut expiring_session = SystemSocketDiagnosticsSource
        .open_until(Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert_eq!(proc_fd_count(), fd_count_before_expiring_session + 1);
    expiring_session.set_deadline_for_test(Instant::now());
    let error = match expiring_session
        .collect_process_until(identity, Instant::now() + Duration::from_secs(5))
    {
        Ok(_) => panic!("a later collection deadline extended the expired session ceiling"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), SocketDiagnosticsErrorKind::DeadlineExpired);
    assert_eq!(proc_fd_count(), fd_count_before_expiring_session);

    let deadline = Instant::now() + Duration::from_secs(8);
    let fd_count_before_session = proc_fd_count();
    let session = SystemSocketDiagnosticsSource.open_until(deadline).unwrap();
    assert_eq!(proc_fd_count(), fd_count_before_session + 1);
    let after_open_lower_bound = Instant::now();
    let prebound_port_id = session.netlink_port_id();
    let other_session = SystemSocketDiagnosticsSource.open_until(deadline).unwrap();
    assert_eq!(proc_fd_count(), fd_count_before_session + 2);
    assert_ne!(other_session.netlink_port_id(), prebound_port_id);
    drop(other_session);
    assert_eq!(proc_fd_count(), fd_count_before_session + 1);
    let (session, snapshot) = session.collect_process_until(identity, deadline).unwrap();
    // SAFETY: `geteuid` has no pointer arguments or preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    assert_eq!(snapshot.process(), identity);
    assert_eq!(snapshot.netlink_port_id(), prebound_port_id);
    assert!(snapshot.started_at() >= after_open_lower_bound);
    assert!(snapshot.fd_scan_complete());
    assert!(snapshot.diag_dumps_complete());
    assert!(!snapshot.listener_diag_dumps_complete());
    assert_eq!(snapshot.listener_port(), None);
    assert_eq!(snapshot.dumps().len(), 4);
    assert!(snapshot.started_at() <= snapshot.completed_at());
    assert!(snapshot.completed_at() < deadline);
    assert!(snapshot.dumps().iter().all(|dump| {
        snapshot.started_at() <= dump.started_at()
            && dump.started_at() <= dump.completed_at()
            && dump.completed_at() <= snapshot.completed_at()
    }));
    assert_eq!(
        snapshot
            .dumps()
            .iter()
            .map(|dump| dump.sequence().get())
            .collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    assert_eq!(
        snapshot
            .dumps()
            .iter()
            .map(|dump| (dump.address_family(), dump.protocol()))
            .collect::<Vec<_>>(),
        [
            (InetSocketAddressFamily::Ipv4, InetSocketProtocol::Tcp),
            (InetSocketAddressFamily::Ipv4, InetSocketProtocol::Udp),
            (InetSocketAddressFamily::Ipv6, InetSocketProtocol::Tcp),
            (InetSocketAddressFamily::Ipv6, InetSocketProtocol::Udp),
        ]
    );

    // A second transaction through the retained session proves that the
    // targeted listener path observes unconnected UDP without widening the
    // ordinary four-dump contract.
    let udp_listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listener_port = NonZeroU16::new(udp_listener.local_addr().unwrap().port()).unwrap();
    let (session, listener_snapshot) = session
        .collect_process_and_listeners_until(identity, listener_port, deadline)
        .unwrap();
    assert_eq!(listener_snapshot.dumps().len(), 4);
    assert_eq!(listener_snapshot.listener_dumps().len(), 2);
    assert!(listener_snapshot.listener_diag_dumps_complete());
    assert_eq!(listener_snapshot.listener_port(), Some(listener_port));
    assert_eq!(
        listener_snapshot
            .listener_dumps()
            .iter()
            .map(|dump| dump.sequence().get())
            .collect::<Vec<_>>(),
        [9, 10]
    );
    assert!(listener_snapshot.sockets().iter().any(|diagnostic| {
        diagnostic.address_family() == InetSocketAddressFamily::Ipv4
            && diagnostic.protocol() == InetSocketProtocol::Udp
            && diagnostic.state() == 7
            && diagnostic.local_address().port() == listener_port.get()
            && diagnostic.transparent() == Some(false)
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

    let (session, second) = session.collect_process_until(identity, deadline).unwrap();
    assert_eq!(second.netlink_port_id(), prebound_port_id);
    assert_eq!(
        second
            .dumps()
            .iter()
            .map(|dump| dump.sequence().get())
            .collect::<Vec<_>>(),
        [11, 12, 13, 14]
    );

    let temporary_session = SystemSocketDiagnosticsSource.open_until(deadline).unwrap();
    let (temporary_session, temporary) = temporary_session
        .collect_process_until(identity, deadline)
        .unwrap();
    assert_ne!(temporary.netlink_port_id(), prebound_port_id);
    assert_eq!(
        temporary
            .dumps()
            .iter()
            .map(|dump| dump.sequence().get())
            .collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    assert_eq!(proc_fd_count(), fd_count_before_session + 3);
    drop(temporary_session);
    drop(session);
    drop(udp_listener);
    assert_eq!(proc_fd_count(), fd_count_before_session);

    drop((tcp_server, tcp_client, tcp_listener, udp_left, udp_right));
}

#[test]
fn live_listener_conflicts_reobserve_empty_through_retained_session() {
    const CHILD_MODE: &str = "FLUX_LISTENER_CONFLICT_LIVE_CHILD";
    const CHILD_TOKEN: &str = "listener-conflict-live-v1";
    const CHILD_PARENT: &str = "FLUX_LISTENER_CONFLICT_LIVE_PARENT";
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
                "socket_diagnostics::tests::live_listener_conflicts_reobserve_empty_through_retained_session",
            )
            .arg("--test-threads=1")
            .env_clear()
            .env(CHILD_MODE, CHILD_TOKEN)
            .env(CHILD_PARENT, process_id.to_string())
            .status()
            .unwrap();
        assert!(status.success(), "isolated listener-conflict smoke failed");
        return;
    }

    let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = NonZeroU16::new(tcp_listener.local_addr().unwrap().port()).unwrap();
    let udp_listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, port.get())).unwrap();
    let unrelated = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let unrelated_port = unrelated.local_addr().unwrap().port();
    assert_ne!(unrelated_port, port.get());

    let targets = [
        ListenerConflictTarget::new(InetSocketAddressFamily::Ipv4, InetSocketProtocol::Tcp, port),
        ListenerConflictTarget::new(InetSocketAddressFamily::Ipv4, InetSocketProtocol::Udp, port),
    ];
    let deadline = Instant::now() + Duration::from_secs(8);
    let session = SystemSocketDiagnosticsSource.open_until(deadline).unwrap();
    let port_id = session.netlink_port_id();
    let (session, conflicts) = session
        .collect_listener_conflicts_until(&targets, deadline)
        .unwrap();
    assert_eq!(conflicts.netlink_port_id(), port_id);
    assert!(conflicts.dumps_complete());
    assert_eq!(
        conflicts
            .dumps()
            .iter()
            .map(|dump| (dump.sequence().get(), dump.target()))
            .collect::<Vec<_>>(),
        vec![(1, targets[0]), (2, targets[1])]
    );
    assert_eq!(conflicts.conflicts().len(), targets.len());
    assert!(conflicts.conflicts().iter().all(|diagnostic| {
        diagnostic.local_address().port() == port.get()
            && diagnostic.local_address().port() != unrelated_port
    }));
    for (target, state) in targets.into_iter().zip([10, 7]) {
        let matches = conflicts
            .conflicts()
            .iter()
            .filter(|diagnostic| {
                diagnostic.address_family() == target.address_family()
                    && diagnostic.protocol() == target.protocol()
                    && diagnostic.state() == state
                    && diagnostic.local_address().port() == target.source_port().get()
            })
            .count();
        assert_eq!(matches, 1);
    }

    drop((tcp_listener, udp_listener));
    let (session, empty) = session
        .collect_listener_conflicts_until(&targets, deadline)
        .unwrap();
    assert_eq!(empty.netlink_port_id(), port_id);
    assert!(empty.dumps_complete());
    assert_eq!(
        empty
            .dumps()
            .iter()
            .map(|dump| dump.sequence().get())
            .collect::<Vec<_>>(),
        [3, 4]
    );
    assert!(empty.conflicts().is_empty());
    drop((session, unrelated));
}

fn proc_fd_count() -> usize {
    fs::read_dir("/proc/self/fd").unwrap().count()
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

fn next_random(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn snapshot_with(sockets: Vec<InetSocketDiagnostic>) -> ProcessSocketDiagnostics {
    let observed_at = Instant::now();
    ProcessSocketDiagnostics {
        process: SocketDiagnosticsProcessIdentity::new(
            NonZeroU32::new(1).unwrap(),
            NonZeroU64::new(1).unwrap(),
        ),
        netlink_port_id: NonZeroU32::new(1).unwrap(),
        started_at: observed_at,
        completed_at: observed_at,
        socket_fds: vec![ProcessSocketFd {
            fd: 0,
            inode: NonZeroU64::new(55).unwrap(),
        }]
        .into_boxed_slice(),
        dumps: broad_dumps(observed_at),
        listener_port: None,
        listener_dumps: Box::default(),
        sockets: sockets.into_boxed_slice(),
    }
}

fn broad_dumps(observed_at: Instant) -> Box<[InetSocketDump]> {
    [
        (InetSocketAddressFamily::Ipv4, InetSocketProtocol::Tcp),
        (InetSocketAddressFamily::Ipv4, InetSocketProtocol::Udp),
        (InetSocketAddressFamily::Ipv6, InetSocketProtocol::Tcp),
        (InetSocketAddressFamily::Ipv6, InetSocketProtocol::Udp),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (address_family, protocol))| InetSocketDump {
        sequence: NonZeroU32::new(u32::try_from(index + 1).unwrap()).unwrap(),
        address_family,
        protocol,
        started_at: observed_at,
        completed_at: observed_at,
    })
    .collect::<Vec<_>>()
    .into_boxed_slice()
}
