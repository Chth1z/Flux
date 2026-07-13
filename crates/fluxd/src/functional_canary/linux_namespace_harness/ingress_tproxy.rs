//! Privileged ingress-only TPROXY checkpoint.
//!
//! This test proves that traffic arriving from a dedicated probe namespace traverses an exact
//! mangle/PREROUTING TPROXY selectors, reaches transparent dual-stack TCP/UDP listeners with the
//! original destination intact, and leaves through sockets carrying a test-owned bypass mark.
//! It deliberately does not classify local OUTPUT marking as TPROXY traversal and does not
//! construct production `UnqualifiedCanaryGateEvidence`.

use super::*;
use serde_json::Value;

mod transparent_tcp;
mod transparent_udp;

use transparent_tcp::{
    TransparentTcpListener, connect_marked as connect_marked_tcp, socket_mark as tcp_socket_mark,
};
use transparent_udp::{
    TransparentUdpListener, connect_marked as connect_marked_udp,
    connect_transparent_marked as connect_transparent_marked_udp, socket_mark as udp_socket_mark,
};

const TEST_NAME: &str = "functional_canary::linux_namespace_harness::privileged_ingress_tproxy_checkpoint_exercises_real_capture_counters_and_cleanup";
const MODE_PREFLIGHT: &str = "tproxy-preflight";
const MODE_ISOLATED: &str = "tproxy-isolated";
const MODE_PEER_HOLDER: &str = "tproxy-peer-holder";
const MODE_PROBE_HOLDER: &str = "tproxy-probe-holder";
const MODE_PEER: &str = "tproxy-peer";
const MODE_RELAY: &str = "tproxy-relay";
const MODE_CLIENT: &str = "tproxy-client";

const PROXY_MASK: u32 = 0x0000_000f;
const PROXY_MARK: u32 = 0x0000_0001;
const RELAY_ORIGIN_BIT: u32 = 0x0000_0080;
const RELAY_BYPASS_MARK: u32 = RELAY_ORIGIN_BIT | 0x0000_0002;
const ROUTE_PROTOCOL: u32 = 99;
const TCP_CAPTURE_MAXIMUM: u64 = 64;
const UDP_ECHO_PACKET_COUNT: u64 = 1;

pub(super) fn run() {
    let result = match env::var(MODE_ENV).as_deref() {
        Err(env::VarError::NotPresent) => run_outer(),
        Ok(MODE_PREFLIGHT) => run_preflight(),
        Ok(MODE_ISOLATED) => run_isolated(),
        Ok(MODE_PEER_HOLDER) => run_holder(HolderRole::Peer),
        Ok(MODE_PROBE_HOLDER) => run_holder(HolderRole::Probe),
        Ok(MODE_PEER) => run_peer(),
        Ok(MODE_RELAY) => run_relay(),
        Ok(MODE_CLIENT) => run_client(),
        Ok(other) => Err(format!("unsupported {MODE_ENV} value {other:?}")),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{MODE_ENV} must contain valid UTF-8")),
    };
    if let Err(error) = result {
        panic!("Linux ingress TPROXY checkpoint failed: {error}");
    }
}

fn run_outer() -> Result<(), String> {
    let required = required_mode()?;
    for (program, arguments) in [
        ("unshare", &["--version"][..]),
        ("nsenter", &["--version"][..]),
        ("ip", &["-Version"][..]),
        ("iptables", &["--version"][..]),
        ("ip6tables", &["--version"][..]),
        ("iptables-save", &["--version"][..]),
        ("ip6tables-save", &["--version"][..]),
    ] {
        let mut command = Command::new(program);
        command.args(arguments);
        if let Err(reason) = checked_command(command, COMMAND_TIMEOUT) {
            return skip_or_fail(
                required,
                format!("required ingress TPROXY helper `{program}` is unavailable: {reason}"),
            );
        }
    }

    if let Err(reason) = run_outer_reentry(MODE_PREFLIGHT, COMMAND_TIMEOUT) {
        return skip_or_fail(
            required,
            format!("disposable ingress TPROXY preflight is unavailable: {reason}"),
        );
    }
    run_outer_reentry(MODE_ISOLATED, PROCESS_TIMEOUT)
}

fn run_outer_reentry(mode: &str, timeout: Duration) -> Result<(), String> {
    let executable =
        env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    let reentry_token = random_nonce()?;
    let outer_netns = network_namespace_identity()?;
    let outer_userns = user_namespace_identity()?;
    let mut command = Command::new("unshare");
    command
        .args(["--user", "--map-root-user", "--mount", "--net", "--"])
        .arg(executable)
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, mode)
        .env(REENTRY_TOKEN_ENV, reentry_token)
        .env(OUTER_NETNS_ENV, outer_netns)
        .env(OUTER_USERNS_ENV, outer_userns);
    checked_command(command, timeout).map(|_| ())
}

fn run_preflight() -> Result<(), String> {
    ensure_isolated_authority_with_boundary(
        "disposable ingress-TPROXY capability preflight only; no production or local-OUTPUT qualification",
    )?;
    require_preexisting_xtables_support()?;
    command("ip", &["link", "set", "dev", "lo", "up"])?;

    let ipv4_tcp = TransparentTcpListener::bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 41_090)?;
    let ipv6_tcp = TransparentTcpListener::bind(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 41_090)?;
    let ipv4_udp =
        TransparentUdpListener::bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 41_090, IO_TIMEOUT)?;
    let ipv6_udp =
        TransparentUdpListener::bind(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 41_090, IO_TIMEOUT)?;
    if ipv4_tcp.transparent_readback() != 1
        || ipv6_tcp.transparent_readback() != 1
        || ipv6_tcp.ipv6_only_readback() != Some(1)
        || ipv4_udp.transparent_readback() != 1
        || ipv6_udp.transparent_readback() != 1
        || ipv4_udp.receive_original_destination_readback() != 1
        || ipv6_udp.receive_original_destination_readback() != 1
        || ipv6_udp.ipv6_only_readback() != Some(1)
    {
        return Err("transparent listener preflight readback mismatch".to_owned());
    }

    preflight_marked_connect(IpAddr::V4(Ipv4Addr::LOCALHOST))?;
    preflight_marked_connect(IpAddr::V6(Ipv6Addr::LOCALHOST))?;
    preflight_marked_udp_connect(IpAddr::V4(Ipv4Addr::LOCALHOST))?;
    preflight_marked_udp_connect(IpAddr::V6(Ipv6Addr::LOCALHOST))?;

    for (program, chain, on_ip, source, destination) in [
        (
            "iptables",
            "FXPREF4",
            "0.0.0.0",
            "192.0.2.1/32",
            "198.51.100.1/32",
        ),
        (
            "ip6tables",
            "FXPREF6",
            "::",
            "2001:db8:1::1/128",
            "2001:db8:2::1/128",
        ),
    ] {
        command(program, &["-t", "mangle", "-N", chain])?;
        for protocol in ["tcp", "udp"] {
            command(
                program,
                &[
                    "-t",
                    "mangle",
                    "-A",
                    chain,
                    "-p",
                    protocol,
                    "-m",
                    "comment",
                    "--comment",
                    "flux-tproxy-preflight",
                    "-j",
                    "TPROXY",
                    "--on-ip",
                    on_ip,
                    "--on-port",
                    "41090",
                    "--tproxy-mark",
                    "0x1/0xf",
                ],
            )?;
            let hook = [
                "-t",
                "mangle",
                "-I",
                "PREROUTING",
                "1",
                "-i",
                "lo",
                "-s",
                source,
                "-d",
                destination,
                "-p",
                protocol,
                "--dport",
                "9",
                "-j",
                chain,
            ];
            command(program, &hook)?;
            command(
                program,
                &[
                    "-t",
                    "mangle",
                    "-D",
                    "PREROUTING",
                    "-i",
                    "lo",
                    "-s",
                    source,
                    "-d",
                    destination,
                    "-p",
                    protocol,
                    "--dport",
                    "9",
                    "-j",
                    chain,
                ],
            )?;
        }
        command(program, &["-t", "mangle", "-F", chain])?;
        command(program, &["-t", "mangle", "-X", chain])?;
    }

    command(
        "ip",
        &[
            "route",
            "add",
            "table",
            "24991",
            "local",
            "0.0.0.0/0",
            "dev",
            "lo",
            "scope",
            "host",
            "proto",
            "99",
        ],
    )?;
    command(
        "ip",
        &[
            "rule", "add", "pref", "14991", "fwmark", "0x1/0xf", "lookup", "24991", "protocol",
            "99",
        ],
    )?;
    command(
        "ip",
        &[
            "-6", "route", "add", "table", "24992", "local", "::/0", "dev", "lo", "scope", "host",
            "proto", "99",
        ],
    )?;
    command(
        "ip",
        &[
            "-6", "rule", "add", "pref", "14992", "fwmark", "0x1/0xf", "lookup", "24992",
            "protocol", "99",
        ],
    )?;
    require_local_route_lookup(false, "198.51.100.7", 24_991)?;
    require_local_route_lookup(true, "2001:db8::7", 24_992)?;
    command(
        "ip",
        &[
            "-6", "rule", "delete", "pref", "14992", "fwmark", "0x1/0xf", "lookup", "24992",
            "protocol", "99",
        ],
    )?;
    command(
        "ip",
        &[
            "-6", "route", "delete", "table", "24992", "local", "::/0", "dev", "lo", "scope",
            "host", "proto", "99",
        ],
    )?;
    command(
        "ip",
        &[
            "rule", "delete", "pref", "14991", "fwmark", "0x1/0xf", "lookup", "24991", "protocol",
            "99",
        ],
    )?;
    command(
        "ip",
        &[
            "route",
            "delete",
            "table",
            "24991",
            "local",
            "0.0.0.0/0",
            "dev",
            "lo",
            "scope",
            "host",
            "proto",
            "99",
        ],
    )?;
    Ok(())
}

fn require_preexisting_xtables_support() -> Result<(), String> {
    let ipv4_version = command_output("iptables", &["--version"])?;
    let ipv6_version = command_output("ip6tables", &["--version"])?;
    let ipv4_version = String::from_utf8(ipv4_version)
        .map_err(|error| format!("iptables version is not UTF-8: {error}"))?;
    let ipv6_version = String::from_utf8(ipv6_version)
        .map_err(|error| format!("ip6tables version is not UTF-8: {error}"))?;
    let nft_frontend = ipv4_version.contains("(nf_tables)") && ipv6_version.contains("(nf_tables)");
    let legacy_frontend =
        !ipv4_version.contains("(nf_tables)") && !ipv6_version.contains("(nf_tables)");
    if !nft_frontend && !legacy_frontend {
        return Err(format!(
            "iptables frontends are incoherent: ipv4={:?} ipv6={:?}",
            ipv4_version.trim(),
            ipv6_version.trim()
        ));
    }
    let mut modules = vec![
        "xt_TPROXY",
        "nf_tproxy_ipv4",
        "nf_tproxy_ipv6",
        "xt_mark",
        "xt_comment",
    ];
    if nft_frontend {
        modules.extend(["nft_compat", "nft_tproxy"]);
    } else {
        modules.extend([
            "ip_tables",
            "ip6_tables",
            "iptable_mangle",
            "ip6table_mangle",
        ]);
    }
    for module in modules {
        let path = PathBuf::from("/sys/module").join(module);
        let metadata = fs::metadata(&path).map_err(|error| {
            format!(
                "ingress TPROXY preflight refuses implicit kernel-module autoload; required support {module} was not already active at {}: {error}",
                path.display()
            )
        })?;
        if !metadata.is_dir() {
            return Err(format!(
                "ingress TPROXY preflight support path {} is not a directory",
                path.display()
            ));
        }
    }
    Ok(())
}

fn preflight_marked_connect(ip: IpAddr) -> Result<(), String> {
    let listener = TcpListener::bind(SocketAddr::new(ip, 0))
        .map_err(|error| format!("bind marked-connect preflight listener on {ip}: {error}"))?;
    let destination = listener
        .local_addr()
        .map_err(|error| format!("read marked-connect preflight listener tuple: {error}"))?;
    let acceptor = thread::spawn(move || listener.accept().map(|_| ()));
    let source = SocketAddr::new(ip, 0);
    let (stream, mark) = connect_marked_tcp(source, destination, RELAY_BYPASS_MARK, IO_TIMEOUT)?;
    if mark != RELAY_BYPASS_MARK || tcp_socket_mark(&stream)? != RELAY_BYPASS_MARK {
        return Err("SO_MARK preflight readback mismatch".to_owned());
    }
    drop(stream);
    acceptor
        .join()
        .map_err(|_| "marked-connect preflight acceptor panicked".to_owned())?
        .map_err(|error| format!("accept marked-connect preflight: {error}"))
}

fn preflight_marked_udp_connect(ip: IpAddr) -> Result<(), String> {
    let peer = UdpSocket::bind(SocketAddr::new(ip, 0))
        .map_err(|error| format!("bind marked UDP preflight peer on {ip}: {error}"))?;
    peer.set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set marked UDP preflight peer timeout: {error}"))?;
    let destination = peer
        .local_addr()
        .map_err(|error| format!("read marked UDP preflight peer tuple: {error}"))?;
    let (socket, mark) = connect_marked_udp(
        SocketAddr::new(ip, 0),
        destination,
        RELAY_BYPASS_MARK,
        IO_TIMEOUT,
    )?;
    if mark != RELAY_BYPASS_MARK || udp_socket_mark(&socket)? != RELAY_BYPASS_MARK {
        return Err("UDP SO_MARK preflight readback mismatch".to_owned());
    }
    let request = b"flux-tproxy-udp-preflight";
    if socket
        .send(request)
        .map_err(|error| format!("send marked UDP preflight datagram: {error}"))?
        != request.len()
    {
        return Err("marked UDP preflight sent a partial datagram".to_owned());
    }
    let mut buffer = [0_u8; 64];
    let (length, remote) = peer
        .recv_from(&mut buffer)
        .map_err(|error| format!("receive marked UDP preflight datagram: {error}"))?;
    if &buffer[..length] != request
        || remote
            != socket
                .local_addr()
                .map_err(|error| format!("read marked UDP preflight source: {error}"))?
    {
        return Err("marked UDP preflight tuple or payload mismatch".to_owned());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TproxyHarnessConfig {
    base: HarnessConfig,
    relay_probe_interface: String,
    probe_interface: String,
    relay_probe_ipv4: Ipv4Addr,
    probe_ipv4: Ipv4Addr,
    relay_probe_ipv6: Ipv6Addr,
    probe_ipv6: Ipv6Addr,
    tproxy_port: u16,
    ipv4_rule_priority: u32,
    ipv6_rule_priority: u32,
    ipv4_route_table: u32,
    ipv6_route_table: u32,
    chains: ChainNames,
    comments: CounterComments,
    probe_holder_ready_path: PathBuf,
    relay_ready_path: PathBuf,
    relay_report_path: PathBuf,
    relay_stop_path: PathBuf,
    peer_server_stop_path: PathBuf,
    probe_stop_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainNames {
    ipv4_ingress: String,
    ipv4_output: String,
    ipv6_ingress: String,
    ipv6_output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CounterComments {
    ipv4_capture_tcp: String,
    ipv4_capture_udp: String,
    ipv4_unexpected_ingress: String,
    ipv4_bypass_tcp: String,
    ipv4_bypass_udp: String,
    ipv4_recapture: String,
    ipv4_unexpected_output: String,
    ipv6_capture_tcp: String,
    ipv6_capture_udp: String,
    ipv6_unexpected_ingress: String,
    ipv6_bypass_tcp: String,
    ipv6_bypass_udp: String,
    ipv6_recapture: String,
    ipv6_unexpected_output: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RelayReadyReport {
    role: String,
    nonce: String,
    network_namespace: String,
    process_identity: ProcessIdentity,
    ipv4_tcp_listener: SocketAddr,
    ipv6_tcp_listener: SocketAddr,
    ipv4_tcp_transparent: i32,
    ipv6_tcp_transparent: i32,
    ipv6_tcp_only: i32,
    ipv4_udp_listener: SocketAddr,
    ipv6_udp_listener: SocketAddr,
    ipv4_udp_transparent: i32,
    ipv6_udp_transparent: i32,
    ipv4_udp_receive_original_destination: i32,
    ipv6_udp_receive_original_destination: i32,
    ipv6_udp_only: i32,
    relay_mark: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayFlowReport {
    id: String,
    family: String,
    transport: String,
    semantic: String,
    inbound_remote: SocketAddr,
    original_destination: SocketAddr,
    outbound_local: SocketAddr,
    outbound_remote: SocketAddr,
    observed_socket_mark: u32,
    response_local: Option<SocketAddr>,
    response_remote: Option<SocketAddr>,
    observed_response_socket_mark: Option<u32>,
    request_hex: String,
    response_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RelayReport {
    role: String,
    nonce: String,
    network_namespace: String,
    flows: Vec<RelayFlowReport>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct FamilyCounterSnapshot {
    capture_tcp: u64,
    capture_udp: u64,
    bypass_tcp: u64,
    bypass_udp: u64,
    recapture_attempt: u64,
    unexpected_ingress: u64,
    unexpected_output: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CounterSnapshot {
    ipv4: FamilyCounterSnapshot,
    ipv6: FamilyCounterSnapshot,
}

struct TproxyResources {
    journal: Journal,
    config: TproxyHarnessConfig,
    peer_holder: Option<Child>,
    peer_holder_identity: Option<ProcessIdentity>,
    probe_holder: Option<Child>,
    probe_holder_identity: Option<ProcessIdentity>,
    peer_server: Option<Child>,
    peer_server_identity: Option<ProcessIdentity>,
    relay: Option<Child>,
    relay_identity: Option<ProcessIdentity>,
    peer_link_may_exist: bool,
    probe_link_may_exist: bool,
    pending_mutations: Vec<PlannedMutation>,
    baseline_ipv4_mangle: Option<Vec<u8>>,
    baseline_ipv6_mangle: Option<Vec<u8>>,
    baseline_ipv4_rules: Option<Vec<u8>>,
    baseline_ipv6_rules: Option<Vec<u8>>,
    baseline_ipv4_table: Option<Vec<u8>>,
    baseline_ipv6_table: Option<Vec<u8>>,
    peer_holder_log: PathBuf,
    probe_holder_log: PathBuf,
    peer_server_log: PathBuf,
    relay_log: PathBuf,
}

fn run_isolated() -> Result<(), String> {
    ensure_isolated_authority_with_boundary(
        "ingress PREROUTING TPROXY and test-local relay evidence only; local OUTPUT, distinct UID, INET_DIAG, Android, and model validation remain pending",
    )?;
    let directory = tempfile::tempdir()
        .map_err(|error| format!("create ingress TPROXY harness directory: {error}"))?;
    let nonce = random_nonce()?;
    let suffix = &nonce[..8];
    let seed = u32::from_str_radix(&nonce[..4], 16)
        .map_err(|error| format!("parse ingress TPROXY nonce seed: {error}"))?;
    let ipv4_route_table = 20_000 + seed % 4_000;
    let ipv6_route_table = ipv4_route_table + 4_000;
    let ipv4_rule_priority = 10_000 + seed % 2_000;
    let ipv6_rule_priority = ipv4_rule_priority + 2_000;
    let base = HarnessConfig {
        nonce: nonce.clone(),
        daemon_network_namespace: network_namespace_identity()?,
        daemon_interface: format!("fx{suffix}r"),
        peer_interface: format!("fx{suffix}e"),
        daemon_ipv4: Ipv4Addr::new(11, 23, 42, 1),
        peer_ipv4: Ipv4Addr::new(11, 23, 42, 2),
        daemon_ipv6: "2606:4700:fffe:ffff::1"
            .parse()
            .map_err(|error| format!("parse relay-peer IPv6 address: {error}"))?,
        peer_ipv6: "2606:4700:fffe:ffff::2"
            .parse()
            .map_err(|error| format!("parse peer IPv6 address: {error}"))?,
        tcp_port: 41_001,
        udp_port: 41_002,
        dns_port: 41_053,
        journal_path: directory.path().join("mutations.jsonl"),
        holder_ready_path: directory.path().join("peer-holder-ready.json"),
        ready_path: directory.path().join("peer-ready.json"),
        peer_report_path: directory.path().join("peer-report.json"),
        client_report_path: directory.path().join("client-report.json"),
        stop_path: directory.path().join("peer-holder-stop"),
    };
    let config = TproxyHarnessConfig {
        base,
        relay_probe_interface: format!("fx{suffix}d"),
        probe_interface: format!("fx{suffix}c"),
        relay_probe_ipv4: Ipv4Addr::new(11, 23, 43, 1),
        probe_ipv4: Ipv4Addr::new(11, 23, 43, 2),
        relay_probe_ipv6: "2606:4700:fffe:fffd::1"
            .parse()
            .map_err(|error| format!("parse relay-probe IPv6 address: {error}"))?,
        probe_ipv6: "2606:4700:fffe:fffd::2"
            .parse()
            .map_err(|error| format!("parse probe IPv6 address: {error}"))?,
        tproxy_port: 41_090,
        ipv4_rule_priority,
        ipv6_rule_priority,
        ipv4_route_table,
        ipv6_route_table,
        chains: ChainNames {
            ipv4_ingress: format!("FX4{suffix}I"),
            ipv4_output: format!("FX4{suffix}O"),
            ipv6_ingress: format!("FX6{suffix}I"),
            ipv6_output: format!("FX6{suffix}O"),
        },
        comments: CounterComments {
            ipv4_capture_tcp: format!("f4{suffix}ct"),
            ipv4_capture_udp: format!("f4{suffix}cu"),
            ipv4_unexpected_ingress: format!("f4{suffix}uin"),
            ipv4_bypass_tcp: format!("f4{suffix}bt"),
            ipv4_bypass_udp: format!("f4{suffix}bu"),
            ipv4_recapture: format!("f4{suffix}rec"),
            ipv4_unexpected_output: format!("f4{suffix}uout"),
            ipv6_capture_tcp: format!("f6{suffix}ct"),
            ipv6_capture_udp: format!("f6{suffix}cu"),
            ipv6_unexpected_ingress: format!("f6{suffix}uin"),
            ipv6_bypass_tcp: format!("f6{suffix}bt"),
            ipv6_bypass_udp: format!("f6{suffix}bu"),
            ipv6_recapture: format!("f6{suffix}rec"),
            ipv6_unexpected_output: format!("f6{suffix}uout"),
        },
        probe_holder_ready_path: directory.path().join("probe-holder-ready.json"),
        relay_ready_path: directory.path().join("relay-ready.json"),
        relay_report_path: directory.path().join("relay-report.json"),
        relay_stop_path: directory.path().join("relay-stop"),
        peer_server_stop_path: directory.path().join("peer-server-stop"),
        probe_stop_path: directory.path().join("probe-holder-stop"),
    };
    let config_path = directory.path().join("config.json");
    write_json_synced(&config_path, &config)?;
    let journal = Journal::create(config.base.journal_path.clone(), nonce)?;
    let mut resources = TproxyResources {
        journal,
        config,
        peer_holder: None,
        peer_holder_identity: None,
        probe_holder: None,
        probe_holder_identity: None,
        peer_server: None,
        peer_server_identity: None,
        relay: None,
        relay_identity: None,
        peer_link_may_exist: false,
        probe_link_may_exist: false,
        pending_mutations: Vec::new(),
        baseline_ipv4_mangle: None,
        baseline_ipv6_mangle: None,
        baseline_ipv4_rules: None,
        baseline_ipv6_rules: None,
        baseline_ipv4_table: None,
        baseline_ipv6_table: None,
        peer_holder_log: directory.path().join("peer-holder.log"),
        probe_holder_log: directory.path().join("probe-holder.log"),
        peer_server_log: directory.path().join("peer-server.log"),
        relay_log: directory.path().join("relay.log"),
    };

    let execution = panic::catch_unwind(AssertUnwindSafe(|| {
        execute_isolated(&mut resources, &config_path)
    }))
    .unwrap_or_else(|payload| {
        Err(format!(
            "ingress TPROXY isolated execution panicked: {}",
            panic_message(payload)
        ))
    });
    let cleanup = cleanup_isolated(&mut resources);
    match (execution, cleanup) {
        (Ok(()), Ok(())) => validate_tproxy_journal(&resources),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(format!("cleanup failed: {cleanup_error}")),
        (Err(error), Err(cleanup_error)) => {
            Err(format!("{error}; cleanup also failed: {cleanup_error}"))
        }
    }
}

fn validate_tproxy_journal(resources: &TproxyResources) -> Result<(), String> {
    validate_journal(
        &resources.config.base.journal_path,
        &resources.config.base.nonce,
        &[
            "before-peer-holder-spawn",
            "before-probe-holder-spawn",
            "before-peer-veth-create",
            "before-probe-veth-create",
            "before-peer-server-spawn",
            "before-relay-spawn",
            "before-ipv4-rpdb-route",
            "before-ipv4-rpdb-rule",
            "before-ipv6-rpdb-route",
            "before-ipv6-rpdb-rule",
            "before-ipv4-ingress-chain-create",
            "before-ipv4-tcp-output-hook",
            "before-ipv4-udp-output-hook",
            "before-ipv4-tcp-prerouting-hook",
            "before-ipv4-udp-prerouting-hook",
            "before-ipv6-ingress-chain-create",
            "before-ipv6-tcp-output-hook",
            "before-ipv6-udp-output-hook",
            "before-ipv6-tcp-prerouting-hook",
            "before-ipv6-udp-prerouting-hook",
            "before-client-spawn",
            "before-capture-cleanup",
            "before-relay-cleanup",
            "before-peer-server-cleanup",
        ],
    )?;
    let mut expected = Vec::new();
    expected.extend(rpdb_mutations(
        false,
        resources.config.ipv4_route_table,
        resources.config.ipv4_rule_priority,
    ));
    expected.extend(rpdb_mutations(
        true,
        resources.config.ipv6_route_table,
        resources.config.ipv6_rule_priority,
    ));
    expected.extend(capture_mutations(
        &rule_plan(&resources.config, false),
        false,
    ));
    expected.extend(capture_mutations(&rule_plan(&resources.config, true), true));
    let records = read_journal(&resources.config.base.journal_path)?;
    for mutation in expected {
        let matches = records
            .iter()
            .filter(|record| record.stage == mutation.stage)
            .collect::<Vec<_>>();
        let [record] = matches.as_slice() else {
            return Err(format!(
                "journal stage {} appears {} times instead of exactly once",
                mutation.stage,
                matches.len()
            ));
        };
        let expected_action = prefixed_words(&mutation.program, &mutation.action);
        let expected_inverse = prefixed_words(&mutation.program, &mutation.inverse);
        if record.action != expected_action
            || record.inverse != expected_inverse
            || record.target_process.is_some()
        {
            return Err(format!(
                "journal stage {} does not preserve its exact command and inverse: record={record:?}",
                mutation.stage
            ));
        }
    }
    let stage_index = |stage: &str| {
        records
            .iter()
            .position(|record| record.stage == stage)
            .ok_or_else(|| format!("journal omitted ordered stage {stage}"))
    };
    for family in ["ipv4", "ipv6"] {
        for protocol in ["tcp", "udp"] {
            let output = stage_index(&format!("before-{family}-{protocol}-output-hook"))?;
            let prerouting = stage_index(&format!("before-{family}-{protocol}-prerouting-hook"))?;
            if output >= prerouting {
                return Err(format!(
                    "journal installed {family} {protocol} PREROUTING before its OUTPUT guard"
                ));
            }
        }
    }
    let capture_cleanup = stage_index("before-capture-cleanup")?;
    for child_cleanup in ["before-relay-cleanup", "before-peer-server-cleanup"] {
        if capture_cleanup >= stage_index(child_cleanup)? {
            return Err(format!(
                "journal reaped {child_cleanup} before capture cleanup began"
            ));
        }
    }
    Ok(())
}

fn execute_isolated(resources: &mut TproxyResources, config_path: &Path) -> Result<(), String> {
    spawn_holder(resources, config_path, HolderRole::Peer)?;
    spawn_holder(resources, config_path, HolderRole::Probe)?;
    create_topology(resources)?;
    require_forwarding_disabled()?;
    spawn_peer_server(resources, config_path)?;
    spawn_relay(resources, config_path)?;
    capture_baselines(resources)?;
    install_rpdb(resources)?;
    install_capture_program(resources)?;

    let before = read_counters(&resources.config)?;
    if before != CounterSnapshot::default() {
        return Err(format!(
            "ingress TPROXY counters were nonzero before traffic: {before:?}"
        ));
    }
    validate_route_controls(&resources.config)?;
    run_client_reentry(resources, config_path)?;

    wait_for_path_and_child(
        &resources.config.relay_report_path,
        resources
            .relay
            .as_mut()
            .ok_or_else(|| "relay child was not stored".to_owned())?,
        IO_TIMEOUT,
        &resources.relay_log,
    )?;
    wait_for_path_and_child(
        &resources.config.base.peer_report_path,
        resources
            .peer_server
            .as_mut()
            .ok_or_else(|| "peer-server child was not stored".to_owned())?,
        IO_TIMEOUT,
        &resources.peer_server_log,
    )?;
    let after = read_counters(&resources.config)?;
    validate_counter_bounds(after)?;
    let client: ProcessReport = read_json(&resources.config.base.client_report_path)?;
    let peer: ProcessReport = read_json(&resources.config.base.peer_report_path)?;
    let relay: RelayReport = read_json(&resources.config.relay_report_path)?;
    let relay_ready: RelayReadyReport = read_json(&resources.config.relay_ready_path)?;
    let peer_ready: ReadyReport = read_json(&resources.config.base.ready_path)?;
    let peer_holder: HolderReadyReport = read_json(&resources.config.base.holder_ready_path)?;
    let probe_holder: HolderReadyReport = read_json(&resources.config.probe_holder_ready_path)?;
    validate_reports(
        &resources.config,
        ObservedReports {
            client: &client,
            peer: &peer,
            relay: &relay,
            relay_ready: &relay_ready,
            peer_ready: &peer_ready,
            peer_holder: &peer_holder,
            probe_holder: &probe_holder,
        },
    )
}

#[derive(Clone, Copy)]
enum HolderRole {
    Peer,
    Probe,
}

impl HolderRole {
    const fn mode(self) -> &'static str {
        match self {
            Self::Peer => MODE_PEER_HOLDER,
            Self::Probe => MODE_PROBE_HOLDER,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Peer => "peer-holder",
            Self::Probe => "probe-holder",
        }
    }
}

fn spawn_holder(
    resources: &mut TproxyResources,
    config_path: &Path,
    role: HolderRole,
) -> Result<(), String> {
    let executable =
        env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    let stage = match role {
        HolderRole::Peer => "before-peer-holder-spawn",
        HolderRole::Probe => "before-probe-holder-spawn",
    };
    let action = command_words(
        "unshare",
        [
            OsString::from("--net"),
            OsString::from("--"),
            executable.as_os_str().to_owned(),
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from(TEST_NAME),
            OsString::from("--nocapture"),
            OsString::from("--test-threads=1"),
        ],
    );
    resources.journal.record(
        stage,
        &action,
        &[format!("terminate-and-reap-{}", role.label())],
    )?;
    let log_path = match role {
        HolderRole::Peer => &resources.peer_holder_log,
        HolderRole::Probe => &resources.probe_holder_log,
    };
    let (stdout, stderr) = log_files(log_path)?;
    let mut command = Command::new("unshare");
    command
        .args(["--net", "--"])
        .arg(executable)
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, role.mode())
        .env(CONFIG_ENV, config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .process_group(0);
    arm_parent_death_signal(&mut command)?;
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn {}: {error}", role.label()))?;
    let identity = capture_spawned_identity(&mut child, role.label())?;
    match role {
        HolderRole::Peer => {
            resources.peer_holder_identity = Some(identity);
            resources.peer_holder = Some(child);
        }
        HolderRole::Probe => {
            resources.probe_holder_identity = Some(identity);
            resources.probe_holder = Some(child);
        }
    }
    let ready_path = match role {
        HolderRole::Peer => &resources.config.base.holder_ready_path,
        HolderRole::Probe => &resources.config.probe_holder_ready_path,
    };
    let stored_child = match role {
        HolderRole::Peer => resources
            .peer_holder
            .as_mut()
            .ok_or_else(|| "peer holder child was not stored".to_owned())?,
        HolderRole::Probe => resources
            .probe_holder
            .as_mut()
            .ok_or_else(|| "probe holder child was not stored".to_owned())?,
    };
    wait_for_path_and_child(ready_path, stored_child, IO_TIMEOUT, log_path)?;
    let ready: HolderReadyReport = read_json(ready_path)?;
    if ready.role != role.label()
        || ready.nonce != resources.config.base.nonce
        || ready.process_identity != identity
        || ready.network_namespace == resources.config.base.daemon_network_namespace
    {
        return Err(format!("{} readiness mismatch: {ready:?}", role.label()));
    }
    Ok(())
}

fn create_topology(resources: &mut TproxyResources) -> Result<(), String> {
    let peer_holder = resources
        .peer_holder_identity
        .ok_or_else(|| "peer holder identity is missing".to_owned())?;
    let probe_holder = resources
        .probe_holder_identity
        .ok_or_else(|| "probe holder identity is missing".to_owned())?;
    create_veth(
        &resources.journal,
        "before-peer-veth-create",
        &resources.config.base.daemon_interface,
        &resources.config.base.peer_interface,
        peer_holder,
        &mut resources.peer_link_may_exist,
    )?;
    create_veth(
        &resources.journal,
        "before-probe-veth-create",
        &resources.config.relay_probe_interface,
        &resources.config.probe_interface,
        probe_holder,
        &mut resources.probe_link_may_exist,
    )?;

    journaled_ip(
        &resources.journal,
        "before-relay-loopback-up",
        &["link", "set", "dev", "lo", "up"].map(str::to_owned),
        &["link", "set", "dev", "lo", "down"].map(str::to_owned),
    )?;
    configure_link(
        &resources.journal,
        "relay-peer",
        None,
        &resources.config.base.daemon_interface,
        resources.config.base.daemon_ipv4,
        resources.config.base.daemon_ipv6,
    )?;
    configure_link(
        &resources.journal,
        "peer",
        Some(peer_holder),
        &resources.config.base.peer_interface,
        resources.config.base.peer_ipv4,
        resources.config.base.peer_ipv6,
    )?;
    configure_link(
        &resources.journal,
        "relay-probe",
        None,
        &resources.config.relay_probe_interface,
        resources.config.relay_probe_ipv4,
        resources.config.relay_probe_ipv6,
    )?;
    configure_link(
        &resources.journal,
        "probe",
        Some(probe_holder),
        &resources.config.probe_interface,
        resources.config.probe_ipv4,
        resources.config.probe_ipv6,
    )?;
    let route4 = vec![
        "route".to_owned(),
        "add".to_owned(),
        format!("{}/32", resources.config.base.peer_ipv4),
        "via".to_owned(),
        resources.config.relay_probe_ipv4.to_string(),
        "dev".to_owned(),
        resources.config.probe_interface.clone(),
        "proto".to_owned(),
        ROUTE_PROTOCOL.to_string(),
    ];
    let mut delete4 = route4.clone();
    delete4[1] = "delete".to_owned();
    journaled_nsenter_ip(
        &resources.journal,
        "before-probe-ipv4-route",
        &route4,
        &delete4,
        probe_holder,
    )?;
    let route6 = vec![
        "-6".to_owned(),
        "route".to_owned(),
        "add".to_owned(),
        format!("{}/128", resources.config.base.peer_ipv6),
        "via".to_owned(),
        resources.config.relay_probe_ipv6.to_string(),
        "dev".to_owned(),
        resources.config.probe_interface.clone(),
        "proto".to_owned(),
        ROUTE_PROTOCOL.to_string(),
    ];
    let mut delete6 = route6.clone();
    delete6[2] = "delete".to_owned();
    journaled_nsenter_ip(
        &resources.journal,
        "before-probe-ipv6-route",
        &route6,
        &delete6,
        probe_holder,
    )?;
    Ok(())
}

fn create_veth(
    journal: &Journal,
    stage: &str,
    local: &str,
    remote: &str,
    holder: ProcessIdentity,
    may_exist: &mut bool,
) -> Result<(), String> {
    let add = vec![
        "link".to_owned(),
        "add".to_owned(),
        local.to_owned(),
        "type".to_owned(),
        "veth".to_owned(),
        "peer".to_owned(),
        "name".to_owned(),
        remote.to_owned(),
    ];
    let delete = vec![
        "link".to_owned(),
        "delete".to_owned(),
        "dev".to_owned(),
        local.to_owned(),
    ];
    journal.record(
        stage,
        &prefixed_words("ip", &add),
        &prefixed_words("ip", &delete),
    )?;
    *may_exist = true;
    let mut add_command = Command::new("ip");
    add_command.args(&add);
    checked_command(add_command, COMMAND_TIMEOUT)?;

    let move_remote = vec![
        "link".to_owned(),
        "set".to_owned(),
        remote.to_owned(),
        "netns".to_owned(),
        holder.pid.to_string(),
    ];
    journal.record_for_process(
        &format!("{stage}-move"),
        &prefixed_words("ip", &move_remote),
        &["delete-owned-local-veth".to_owned(), local.to_owned()],
        holder,
    )?;
    verify_process_identity(holder)?;
    let mut move_command = Command::new("ip");
    move_command.args(&move_remote);
    checked_command(move_command, COMMAND_TIMEOUT).map(|_| ())
}

fn configure_link(
    journal: &Journal,
    label: &str,
    holder: Option<ProcessIdentity>,
    interface: &str,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
) -> Result<(), String> {
    if let Some(holder) = holder {
        journaled_nsenter_ip(
            journal,
            &format!("before-{label}-loopback-up"),
            &["link", "set", "dev", "lo", "up"].map(str::to_owned),
            &["link", "set", "dev", "lo", "down"].map(str::to_owned),
            holder,
        )?;
    }
    let ipv4_add = vec![
        "address".to_owned(),
        "add".to_owned(),
        format!("{ipv4}/30"),
        "dev".to_owned(),
        interface.to_owned(),
    ];
    let mut ipv4_delete = ipv4_add.clone();
    ipv4_delete[1] = "delete".to_owned();
    run_journaled_ip(
        journal,
        &format!("before-{label}-ipv4"),
        &ipv4_add,
        &ipv4_delete,
        holder,
    )?;
    let ipv6_add = vec![
        "-6".to_owned(),
        "address".to_owned(),
        "add".to_owned(),
        format!("{ipv6}/126"),
        "dev".to_owned(),
        interface.to_owned(),
        "nodad".to_owned(),
    ];
    let mut ipv6_delete = ipv6_add.clone();
    ipv6_delete[2] = "delete".to_owned();
    ipv6_delete.pop();
    run_journaled_ip(
        journal,
        &format!("before-{label}-ipv6"),
        &ipv6_add,
        &ipv6_delete,
        holder,
    )?;
    let up = vec![
        "link".to_owned(),
        "set".to_owned(),
        "dev".to_owned(),
        interface.to_owned(),
        "up".to_owned(),
    ];
    let mut down = up.clone();
    down[4] = "down".to_owned();
    run_journaled_ip(
        journal,
        &format!("before-{label}-link-up"),
        &up,
        &down,
        holder,
    )
}

fn run_journaled_ip(
    journal: &Journal,
    stage: &str,
    arguments: &[String],
    inverse: &[String],
    holder: Option<ProcessIdentity>,
) -> Result<(), String> {
    match holder {
        Some(holder) => {
            journaled_nsenter_ip(journal, stage, arguments, inverse, holder).map(|_| ())
        }
        None => journaled_ip(journal, stage, arguments, inverse).map(|_| ()),
    }
}

fn spawn_peer_server(resources: &mut TproxyResources, config_path: &Path) -> Result<(), String> {
    let holder = resources
        .peer_holder_identity
        .ok_or_else(|| "peer holder identity is missing".to_owned())?;
    let executable =
        env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    resources.journal.record_for_process(
        "before-peer-server-spawn",
        &command_words(
            "nsenter",
            [
                OsString::from("-t"),
                OsString::from(holder.pid.to_string()),
                OsString::from("-n"),
                OsString::from("--"),
                executable.as_os_str().to_owned(),
                OsString::from("--ignored"),
                OsString::from("--exact"),
                OsString::from(TEST_NAME),
                OsString::from("--nocapture"),
                OsString::from("--test-threads=1"),
            ],
        ),
        &["terminate-and-reap-peer-server".to_owned()],
        holder,
    )?;
    let (stdout, stderr) = log_files(&resources.peer_server_log)?;
    let mut command = Command::new("nsenter");
    command
        .args(["-t", &holder.pid.to_string(), "-n", "--"])
        .arg(executable)
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, MODE_PEER)
        .env(CONFIG_ENV, config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .process_group(0);
    arm_parent_death_signal(&mut command)?;
    verify_process_identity(holder)?;
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn ingress TPROXY peer server: {error}"))?;
    let identity = capture_spawned_identity(&mut child, "ingress TPROXY peer server")?;
    resources.peer_server_identity = Some(identity);
    resources.peer_server = Some(child);
    wait_for_path_and_child(
        &resources.config.base.ready_path,
        resources
            .peer_server
            .as_mut()
            .ok_or_else(|| "peer-server child was not stored".to_owned())?,
        IO_TIMEOUT,
        &resources.peer_server_log,
    )
}

fn spawn_relay(resources: &mut TproxyResources, config_path: &Path) -> Result<(), String> {
    let executable =
        env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    resources.journal.record(
        "before-relay-spawn",
        &command_words(
            executable.as_os_str(),
            [
                OsString::from("--ignored"),
                OsString::from("--exact"),
                OsString::from(TEST_NAME),
                OsString::from("--nocapture"),
                OsString::from("--test-threads=1"),
            ],
        ),
        &["terminate-and-reap-relay".to_owned()],
    )?;
    let (stdout, stderr) = log_files(&resources.relay_log)?;
    let mut command = Command::new(executable);
    command
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, MODE_RELAY)
        .env(CONFIG_ENV, config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .process_group(0);
    arm_parent_death_signal(&mut command)?;
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn ingress TPROXY relay: {error}"))?;
    let identity = capture_spawned_identity(&mut child, "ingress TPROXY relay")?;
    resources.relay_identity = Some(identity);
    resources.relay = Some(child);
    wait_for_path_and_child(
        &resources.config.relay_ready_path,
        resources
            .relay
            .as_mut()
            .ok_or_else(|| "relay child was not stored".to_owned())?,
        IO_TIMEOUT,
        &resources.relay_log,
    )?;
    let ready: RelayReadyReport = read_json(&resources.config.relay_ready_path)?;
    if ready.process_identity != identity {
        return Err(format!(
            "relay readiness process identity mismatch: expected={identity:?} observed={ready:?}"
        ));
    }
    Ok(())
}

fn capture_baselines(resources: &mut TproxyResources) -> Result<(), String> {
    resources.baseline_ipv4_mangle = Some(mangle_dump("iptables-save")?);
    resources.baseline_ipv6_mangle = Some(mangle_dump("ip6tables-save")?);
    require_chain_names_absent(
        resources
            .baseline_ipv4_mangle
            .as_deref()
            .ok_or_else(|| "IPv4 mangle baseline was not retained".to_owned())?,
        &[
            &resources.config.chains.ipv4_ingress,
            &resources.config.chains.ipv4_output,
        ],
    )?;
    require_chain_names_absent(
        resources
            .baseline_ipv6_mangle
            .as_deref()
            .ok_or_else(|| "IPv6 mangle baseline was not retained".to_owned())?,
        &[
            &resources.config.chains.ipv6_ingress,
            &resources.config.chains.ipv6_output,
        ],
    )?;
    resources.baseline_ipv4_rules = Some(command_output("ip", &["-j", "rule", "show"])?);
    resources.baseline_ipv6_rules = Some(command_output("ip", &["-6", "-j", "rule", "show"])?);
    require_rule_priority_absent(
        resources
            .baseline_ipv4_rules
            .as_deref()
            .ok_or_else(|| "IPv4 RPDB baseline was not retained".to_owned())?,
        resources.config.ipv4_rule_priority,
    )?;
    require_rule_table_unreferenced(
        resources
            .baseline_ipv4_rules
            .as_deref()
            .ok_or_else(|| "IPv4 RPDB baseline was not retained".to_owned())?,
        resources.config.ipv4_route_table,
    )?;
    require_rule_priority_absent(
        resources
            .baseline_ipv6_rules
            .as_deref()
            .ok_or_else(|| "IPv6 RPDB baseline was not retained".to_owned())?,
        resources.config.ipv6_rule_priority,
    )?;
    require_rule_table_unreferenced(
        resources
            .baseline_ipv6_rules
            .as_deref()
            .ok_or_else(|| "IPv6 RPDB baseline was not retained".to_owned())?,
        resources.config.ipv6_route_table,
    )?;
    resources.baseline_ipv4_table =
        Some(route_table_dump(false, resources.config.ipv4_route_table)?);
    resources.baseline_ipv6_table =
        Some(route_table_dump(true, resources.config.ipv6_route_table)?);
    if resources
        .baseline_ipv4_table
        .as_deref()
        .is_some_and(|dump| dump != b"[]\n" && dump != b"[]")
        || resources
            .baseline_ipv6_table
            .as_deref()
            .is_some_and(|dump| dump != b"[]\n" && dump != b"[]")
    {
        return Err("nonce-derived ingress TPROXY route table is not empty".to_owned());
    }
    Ok(())
}

fn install_rpdb(resources: &mut TproxyResources) -> Result<(), String> {
    let ipv4 = rpdb_mutations(
        false,
        resources.config.ipv4_route_table,
        resources.config.ipv4_rule_priority,
    );
    install_mutations(&resources.journal, &ipv4, &mut resources.pending_mutations)?;
    let ipv6 = rpdb_mutations(
        true,
        resources.config.ipv6_route_table,
        resources.config.ipv6_rule_priority,
    );
    install_mutations(&resources.journal, &ipv6, &mut resources.pending_mutations)
}

fn require_forwarding_disabled() -> Result<(), String> {
    for path in [
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv6/conf/all/forwarding",
    ] {
        let value = fs::read_to_string(path)
            .map_err(|error| format!("read forwarding control {path}: {error}"))?;
        if value.trim() != "0" {
            return Err(format!(
                "ingress TPROXY checkpoint requires forwarding disabled, but {path}={:?}",
                value.trim()
            ));
        }
    }
    Ok(())
}

fn require_rule_priority_absent(dump: &[u8], priority: u32) -> Result<(), String> {
    let rules: Value = serde_json::from_slice(dump)
        .map_err(|error| format!("decode RPDB baseline JSON: {error}"))?;
    let rules = rules
        .as_array()
        .ok_or_else(|| format!("RPDB baseline is not a JSON array: {rules}"))?;
    if rules.iter().any(|rule| {
        rule.get("priority")
            .and_then(value_as_u32)
            .is_some_and(|observed| observed == priority)
    }) {
        return Err(format!(
            "nonce-derived ingress TPROXY rule priority {priority} is already occupied"
        ));
    }
    Ok(())
}

fn require_rule_table_unreferenced(dump: &[u8], table: u32) -> Result<(), String> {
    let rules: Value = serde_json::from_slice(dump)
        .map_err(|error| format!("decode RPDB baseline JSON: {error}"))?;
    let rules = rules
        .as_array()
        .ok_or_else(|| format!("RPDB baseline is not a JSON array: {rules}"))?;
    if rules.iter().any(|rule| {
        rule.get("table")
            .and_then(value_as_u32)
            .is_some_and(|observed| observed == table)
    }) {
        return Err(format!(
            "nonce-derived ingress TPROXY route table {table} is already referenced by an RPDB rule"
        ));
    }
    Ok(())
}

fn require_chain_names_absent(dump: &[u8], chains: &[&String]) -> Result<(), String> {
    let text = std::str::from_utf8(dump)
        .map_err(|error| format!("decode mangle baseline as UTF-8: {error}"))?;
    for chain in chains {
        let declaration = format!(":{chain} ");
        let rule_prefix = format!("-A {chain} ");
        if text
            .lines()
            .any(|line| line.starts_with(&declaration) || line.starts_with(&rule_prefix))
        {
            return Err(format!(
                "nonce-derived ingress TPROXY chain {chain} already exists"
            ));
        }
    }
    Ok(())
}

fn rpdb_mutations(ipv6: bool, table: u32, priority: u32) -> Vec<PlannedMutation> {
    let family = if ipv6 { "ipv6" } else { "ipv4" };
    let family_flag = ipv6.then_some("-6");
    let mut route = vec!["route", "add", "table"];
    if let Some(family_flag) = family_flag {
        route.insert(0, family_flag);
    }
    let target = if ipv6 { "::/0" } else { "0.0.0.0/0" };
    let mut owned = route.into_iter().map(str::to_owned).collect::<Vec<_>>();
    owned.extend([
        table.to_string(),
        "local".to_owned(),
        target.to_owned(),
        "dev".to_owned(),
        "lo".to_owned(),
        "scope".to_owned(),
        "host".to_owned(),
        "proto".to_owned(),
        ROUTE_PROTOCOL.to_string(),
    ]);
    let mut delete_route = owned.clone();
    let route_operation = usize::from(ipv6) + 1;
    delete_route[route_operation] = "delete".to_owned();
    let mut rule = Vec::new();
    if ipv6 {
        rule.push("-6".to_owned());
    }
    rule.extend([
        "rule".to_owned(),
        "add".to_owned(),
        "pref".to_owned(),
        priority.to_string(),
        "fwmark".to_owned(),
        format!("{PROXY_MARK:#x}/{PROXY_MASK:#x}"),
        "lookup".to_owned(),
        table.to_string(),
        "protocol".to_owned(),
        ROUTE_PROTOCOL.to_string(),
    ]);
    let mut delete_rule = rule.clone();
    let rule_operation = usize::from(ipv6) + 1;
    delete_rule[rule_operation] = "delete".to_owned();
    vec![
        PlannedMutation {
            stage: format!("before-{family}-rpdb-route"),
            program: "ip".to_owned(),
            action: owned,
            inverse: delete_route,
        },
        PlannedMutation {
            stage: format!("before-{family}-rpdb-rule"),
            program: "ip".to_owned(),
            action: rule,
            inverse: delete_rule,
        },
    ]
}

fn install_capture_program(resources: &mut TproxyResources) -> Result<(), String> {
    install_family_capture(
        &resources.journal,
        &resources.config,
        false,
        &mut resources.pending_mutations,
    )?;
    install_family_capture(
        &resources.journal,
        &resources.config,
        true,
        &mut resources.pending_mutations,
    )
}

fn install_family_capture(
    journal: &Journal,
    config: &TproxyHarnessConfig,
    ipv6: bool,
    pending: &mut Vec<PlannedMutation>,
) -> Result<(), String> {
    let plan = rule_plan(config, ipv6);
    plan.validate_capture_boundary()?;
    let mutations = capture_mutations(&plan, ipv6);
    install_mutations(journal, &mutations, pending)?;
    validate_rule_plan_installed(&plan)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedMutation {
    stage: String,
    program: String,
    action: Vec<String>,
    inverse: Vec<String>,
}

fn capture_mutations(plan: &RulePlan, ipv6: bool) -> Vec<PlannedMutation> {
    let family = if ipv6 { "ipv6" } else { "ipv4" };
    let mut mutations = vec![
        PlannedMutation {
            stage: format!("before-{family}-ingress-chain-create"),
            program: plan.program.clone(),
            action: strings(&["-t", "mangle", "-N", &plan.ingress_chain]),
            inverse: strings(&["-t", "mangle", "-X", &plan.ingress_chain]),
        },
        PlannedMutation {
            stage: format!("before-{family}-output-chain-create"),
            program: plan.program.clone(),
            action: strings(&["-t", "mangle", "-N", &plan.output_chain]),
            inverse: strings(&["-t", "mangle", "-X", &plan.output_chain]),
        },
    ];
    for (index, rule) in plan.ingress_rules.iter().enumerate() {
        mutations.push(PlannedMutation {
            stage: format!("before-{family}-ingress-rule-{index}"),
            program: plan.program.clone(),
            action: rule.clone(),
            inverse: delete_rule(rule),
        });
    }
    for (index, rule) in plan.output_rules.iter().enumerate() {
        mutations.push(PlannedMutation {
            stage: format!("before-{family}-output-rule-{index}"),
            program: plan.program.clone(),
            action: rule.clone(),
            inverse: delete_rule(rule),
        });
    }
    for hook in &plan.output_hooks {
        let protocol = rule_value_after(hook, &["-p", "--protocol"])
            .expect("validated OUTPUT hook has an exact protocol");
        mutations.push(PlannedMutation {
            stage: format!("before-{family}-{protocol}-output-hook"),
            program: plan.program.clone(),
            action: hook.clone(),
            inverse: delete_rule(hook),
        });
    }
    for hook in &plan.prerouting_hooks {
        let protocol = rule_value_after(hook, &["-p", "--protocol"])
            .expect("validated PREROUTING hook has an exact protocol");
        mutations.push(PlannedMutation {
            stage: format!("before-{family}-{protocol}-prerouting-hook"),
            program: plan.program.clone(),
            action: hook.clone(),
            inverse: delete_rule(hook),
        });
    }
    mutations
}

fn delete_rule(rule: &[String]) -> Vec<String> {
    let mut inverse = rule.to_vec();
    let operation = inverse
        .iter()
        .position(|argument| argument == "-A" || argument == "-I")
        .expect("generated rule has an append or insert operation");
    inverse[operation] = "-D".to_owned();
    if inverse
        .get(operation + 2)
        .is_some_and(|argument| argument == "1")
    {
        inverse.remove(operation + 2);
    }
    inverse
}

fn install_mutations(
    journal: &Journal,
    mutations: &[PlannedMutation],
    pending: &mut Vec<PlannedMutation>,
) -> Result<(), String> {
    for mutation in mutations {
        journal.record(
            &mutation.stage,
            &prefixed_words(&mutation.program, &mutation.action),
            &prefixed_words(&mutation.program, &mutation.inverse),
        )?;
        pending.push(mutation.clone());
        command_owned(&mutation.program, &mutation.action)?;
    }
    Ok(())
}

struct RulePlan {
    program: String,
    ingress_chain: String,
    output_chain: String,
    ingress_rules: Vec<Vec<String>>,
    output_rules: Vec<Vec<String>>,
    prerouting_hooks: Vec<Vec<String>>,
    output_hooks: Vec<Vec<String>>,
}

impl RulePlan {
    fn validate_capture_boundary(&self) -> Result<(), String> {
        if self.ingress_chain == self.output_chain {
            return Err("ingress and OUTPUT rule-plan chains must be distinct".to_owned());
        }
        validate_private_rules(
            "ingress",
            &self.ingress_rules,
            &self.ingress_chain,
            &["TPROXY", "DROP"],
        )?;
        validate_private_rules(
            "OUTPUT",
            &self.output_rules,
            &self.output_chain,
            &["ACCEPT", "DROP"],
        )?;
        for hook in &self.prerouting_hooks {
            validate_hook("PREROUTING", hook, "PREROUTING", &self.ingress_chain)?;
        }
        for hook in &self.output_hooks {
            validate_hook("OUTPUT", hook, "OUTPUT", &self.output_chain)?;
        }
        validate_protocol_coverage(
            "ingress TPROXY rules",
            self.ingress_rules
                .iter()
                .filter(|rule| rule_action(rule) == Some("TPROXY")),
        )?;
        validate_protocol_coverage("PREROUTING hooks", self.prerouting_hooks.iter())?;
        validate_protocol_coverage(
            "OUTPUT bypass rules",
            self.output_rules
                .iter()
                .filter(|rule| rule_action(rule) == Some("ACCEPT")),
        )?;
        validate_protocol_coverage("OUTPUT hooks", self.output_hooks.iter())?;
        if self
            .output_rules
            .iter()
            .chain(&self.output_hooks)
            .flatten()
            .any(|argument| argument == "TPROXY" || argument == &self.ingress_chain)
        {
            return Err("OUTPUT-reachable rule plan references ingress TPROXY state".to_owned());
        }
        Ok(())
    }
}

fn validate_protocol_coverage<'a>(
    scope: &str,
    rules: impl Iterator<Item = &'a Vec<String>>,
) -> Result<(), String> {
    let mut protocols = BTreeSet::new();
    let mut count = 0;
    for rule in rules {
        count += 1;
        let protocol = rule_value_after(rule, &["-p", "--protocol"])
            .ok_or_else(|| format!("{scope} rule has no exact protocol: {rule:?}"))?;
        if !protocols.insert(protocol.to_owned()) {
            return Err(format!("{scope} repeats protocol {protocol}: {rule:?}"));
        }
    }
    let expected = BTreeSet::from(["tcp".to_owned(), "udp".to_owned()]);
    if count != expected.len() || protocols != expected {
        return Err(format!(
            "{scope} must cover TCP and UDP exactly once, observed {protocols:?}"
        ));
    }
    Ok(())
}

fn validate_private_rules(
    scope: &str,
    rules: &[Vec<String>],
    expected_chain: &str,
    allowed_actions: &[&str],
) -> Result<(), String> {
    for rule in rules {
        let chain = rule_value_after(rule, &["-A", "--append"])
            .ok_or_else(|| format!("{scope} private rule has no append target: {rule:?}"))?;
        if chain != expected_chain {
            return Err(format!(
                "{scope} private rule appends to {chain}, expected {expected_chain}: {rule:?}"
            ));
        }
        let action = rule_action(rule)
            .ok_or_else(|| format!("{scope} private rule has no action: {rule:?}"))?;
        if !allowed_actions.contains(&action) {
            return Err(format!(
                "{scope} private rule uses forbidden action {action}: {rule:?}"
            ));
        }
    }
    Ok(())
}

fn validate_hook(
    scope: &str,
    rule: &[String],
    expected_chain: &str,
    expected_target: &str,
) -> Result<(), String> {
    let chain = rule_value_after(rule, &["-I", "--insert"])
        .ok_or_else(|| format!("{scope} hook has no insert target: {rule:?}"))?;
    if chain != expected_chain {
        return Err(format!(
            "{scope} hook inserts into {chain}, expected {expected_chain}: {rule:?}"
        ));
    }
    let target = rule_action(rule)
        .ok_or_else(|| format!("{scope} hook has no jump or goto target: {rule:?}"))?;
    if target != expected_target {
        return Err(format!(
            "{scope} hook targets {target}, expected {expected_target}: {rule:?}"
        ));
    }
    Ok(())
}

fn rule_action(rule: &[String]) -> Option<&str> {
    rule_value_after(rule, &["-j", "--jump", "-g", "--goto"])
}

fn rule_value_after<'a>(rule: &'a [String], options: &[&str]) -> Option<&'a str> {
    rule.windows(2).find_map(|window| {
        options
            .contains(&window[0].as_str())
            .then_some(window[1].as_str())
    })
}

fn rule_plan(config: &TproxyHarnessConfig, ipv6: bool) -> RulePlan {
    let (
        program,
        ingress_chain,
        output_chain,
        probe_source,
        peer_destination,
        relay_source,
        relay_probe_interface,
        relay_peer_interface,
        on_ip,
        capture_tcp_comment,
        capture_udp_comment,
        unexpected_ingress_comment,
        bypass_tcp_comment,
        bypass_udp_comment,
        recapture_comment,
        unexpected_output_comment,
    ) = if ipv6 {
        (
            "ip6tables",
            &config.chains.ipv6_ingress,
            &config.chains.ipv6_output,
            format!("{}/128", config.probe_ipv6),
            format!("{}/128", config.base.peer_ipv6),
            format!("{}/128", config.base.daemon_ipv6),
            &config.relay_probe_interface,
            &config.base.daemon_interface,
            "::",
            &config.comments.ipv6_capture_tcp,
            &config.comments.ipv6_capture_udp,
            &config.comments.ipv6_unexpected_ingress,
            &config.comments.ipv6_bypass_tcp,
            &config.comments.ipv6_bypass_udp,
            &config.comments.ipv6_recapture,
            &config.comments.ipv6_unexpected_output,
        )
    } else {
        (
            "iptables",
            &config.chains.ipv4_ingress,
            &config.chains.ipv4_output,
            format!("{}/32", config.probe_ipv4),
            format!("{}/32", config.base.peer_ipv4),
            format!("{}/32", config.base.daemon_ipv4),
            &config.relay_probe_interface,
            &config.base.daemon_interface,
            "0.0.0.0",
            &config.comments.ipv4_capture_tcp,
            &config.comments.ipv4_capture_udp,
            &config.comments.ipv4_unexpected_ingress,
            &config.comments.ipv4_bypass_tcp,
            &config.comments.ipv4_bypass_udp,
            &config.comments.ipv4_recapture,
            &config.comments.ipv4_unexpected_output,
        )
    };
    let tproxy_rule = |protocol: &str, port: u16, comment: &str| {
        strings(&[
            "-t",
            "mangle",
            "-A",
            ingress_chain,
            "-p",
            protocol,
            "--dport",
            &port.to_string(),
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "TPROXY",
            "--on-ip",
            on_ip,
            "--on-port",
            &config.tproxy_port.to_string(),
            "--tproxy-mark",
            &format!("{PROXY_MARK:#x}/{PROXY_MASK:#x}"),
        ])
    };
    let ingress_rules = vec![
        tproxy_rule("tcp", config.base.tcp_port, capture_tcp_comment),
        tproxy_rule("udp", config.base.udp_port, capture_udp_comment),
        strings(&[
            "-t",
            "mangle",
            "-A",
            ingress_chain,
            "-m",
            "comment",
            "--comment",
            unexpected_ingress_comment,
            "-j",
            "DROP",
        ]),
    ];
    let bypass_rule = |protocol: &str, port: u16, comment: &str| {
        strings(&[
            "-t",
            "mangle",
            "-A",
            output_chain,
            "-p",
            protocol,
            "--dport",
            &port.to_string(),
            "-m",
            "mark",
            "--mark",
            &format!("{RELAY_BYPASS_MARK:#x}/0xffffffff"),
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "ACCEPT",
        ])
    };
    let output_rules = vec![
        bypass_rule("tcp", config.base.tcp_port, bypass_tcp_comment),
        bypass_rule("udp", config.base.udp_port, bypass_udp_comment),
        strings(&[
            "-t",
            "mangle",
            "-A",
            output_chain,
            "-m",
            "mark",
            "--mark",
            &format!("{RELAY_ORIGIN_BIT:#x}/{RELAY_ORIGIN_BIT:#x}"),
            "-m",
            "comment",
            "--comment",
            recapture_comment,
            "-j",
            "DROP",
        ]),
        strings(&[
            "-t",
            "mangle",
            "-A",
            output_chain,
            "-m",
            "comment",
            "--comment",
            unexpected_output_comment,
            "-j",
            "DROP",
        ]),
    ];
    let prerouting_hook = |protocol: &str, port: u16| {
        strings(&[
            "-t",
            "mangle",
            "-I",
            "PREROUTING",
            "1",
            "-i",
            relay_probe_interface,
            "-s",
            &probe_source,
            "-d",
            &peer_destination,
            "-p",
            protocol,
            "--dport",
            &port.to_string(),
            "-j",
            ingress_chain,
        ])
    };
    let output_hook = |protocol: &str, port: u16| {
        strings(&[
            "-t",
            "mangle",
            "-I",
            "OUTPUT",
            "1",
            "-o",
            relay_peer_interface,
            "-s",
            &relay_source,
            "-d",
            &peer_destination,
            "-p",
            protocol,
            "--dport",
            &port.to_string(),
            "-j",
            output_chain,
        ])
    };
    let prerouting_hooks = vec![
        prerouting_hook("tcp", config.base.tcp_port),
        prerouting_hook("udp", config.base.udp_port),
    ];
    let output_hooks = vec![
        output_hook("tcp", config.base.tcp_port),
        output_hook("udp", config.base.udp_port),
    ];
    RulePlan {
        program: program.to_owned(),
        ingress_chain: ingress_chain.clone(),
        output_chain: output_chain.clone(),
        ingress_rules,
        output_rules,
        prerouting_hooks,
        output_hooks,
    }
}

fn validate_rule_plan_installed(plan: &RulePlan) -> Result<(), String> {
    for rule in plan
        .ingress_rules
        .iter()
        .chain(&plan.output_rules)
        .chain(&plan.output_hooks)
        .chain(&plan.prerouting_hooks)
    {
        let mut check = rule.clone();
        let operation = check
            .iter()
            .position(|argument| argument == "-A" || argument == "-I")
            .ok_or_else(|| format!("rule plan has no append/insert operation: {rule:?}"))?;
        check[operation] = "-C".to_owned();
        if check
            .get(operation + 1)
            .is_some_and(|chain| chain == "PREROUTING" || chain == "OUTPUT")
            && check.get(operation + 2).is_some_and(|value| value == "1")
        {
            check.remove(operation + 2);
        }
        command_owned(&plan.program, &check)?;
    }
    Ok(())
}

fn run_client_reentry(resources: &TproxyResources, config_path: &Path) -> Result<(), String> {
    let holder = resources
        .probe_holder_identity
        .ok_or_else(|| "probe holder identity is missing".to_owned())?;
    let executable =
        env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    resources.journal.record_for_process(
        "before-client-spawn",
        &command_words(
            "nsenter",
            [
                OsString::from("-t"),
                OsString::from(holder.pid.to_string()),
                OsString::from("-n"),
                OsString::from("--"),
                executable.as_os_str().to_owned(),
                OsString::from("--ignored"),
                OsString::from("--exact"),
                OsString::from(TEST_NAME),
                OsString::from("--nocapture"),
                OsString::from("--test-threads=1"),
            ],
        ),
        &["terminate-and-reap-client".to_owned()],
        holder,
    )?;
    verify_process_identity(holder)?;
    let mut command = Command::new("nsenter");
    command
        .args(["-t", &holder.pid.to_string(), "-n", "--"])
        .arg(executable)
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, MODE_CLIENT)
        .env(CONFIG_ENV, config_path);
    checked_command(command, PROCESS_TIMEOUT).map(|_| ())
}

fn run_holder(role: HolderRole) -> Result<(), String> {
    let config = config_from_environment()?;
    let (ready_path, stop_path) = match role {
        HolderRole::Peer => (&config.base.holder_ready_path, &config.base.stop_path),
        HolderRole::Probe => (&config.probe_holder_ready_path, &config.probe_stop_path),
    };
    let ready = HolderReadyReport {
        role: role.label().to_owned(),
        nonce: config.base.nonce.clone(),
        network_namespace: network_namespace_identity()?,
        process_identity: capture_process_identity(std::process::id())?,
    };
    if ready.network_namespace == config.base.daemon_network_namespace {
        return Err(format!(
            "{} did not enter a distinct network namespace",
            role.label()
        ));
    }
    write_json_synced(ready_path, &ready)?;
    wait_for_stop(stop_path, PROCESS_TIMEOUT)
}

fn run_peer() -> Result<(), String> {
    let config = config_from_environment()?;
    let mut servers = echo_specs(&config.base)
        .into_iter()
        .map(|spec| match spec.transport {
            FlowTransport::Tcp => {
                let listener = TcpListener::bind(spec.peer).map_err(|error| {
                    format!("bind ingress TPROXY peer TCP flow {}: {error}", spec.id)
                })?;
                listener.set_nonblocking(true).map_err(|error| {
                    format!(
                        "make ingress TPROXY peer TCP flow {} nonblocking: {error}",
                        spec.id
                    )
                })?;
                Ok(BoundPeerServer::Tcp { spec, listener })
            }
            FlowTransport::Udp => {
                let socket = UdpSocket::bind(spec.peer).map_err(|error| {
                    format!("bind ingress TPROXY peer UDP flow {}: {error}", spec.id)
                })?;
                socket.set_read_timeout(Some(IO_TIMEOUT)).map_err(|error| {
                    format!(
                        "set ingress TPROXY peer UDP timeout for {}: {error}",
                        spec.id
                    )
                })?;
                Ok(BoundPeerServer::Udp { spec, socket })
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let ready = ReadyReport {
        role: "peer".to_owned(),
        nonce: config.base.nonce.clone(),
        network_namespace: network_namespace_identity()?,
        interface: config.base.peer_interface.clone(),
        ifindex: interface_index(&config.base.peer_interface)?,
        ipv4: config.base.peer_ipv4,
        ipv6: config.base.peer_ipv6,
    };
    write_json_synced(&config.base.ready_path, &ready)?;
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let mut flows = Vec::with_capacity(servers.len());
    for server in &mut servers {
        flows.push(server.serve(&config.base, deadline)?);
    }
    write_json_synced(
        &config.base.peer_report_path,
        &ProcessReport {
            role: "peer".to_owned(),
            nonce: config.base.nonce.clone(),
            network_namespace: network_namespace_identity()?,
            flows,
        },
    )?;
    wait_for_stop(&config.peer_server_stop_path, PROCESS_TIMEOUT)
}

fn run_client() -> Result<(), String> {
    let config = config_from_environment()?;
    let mut flows = Vec::new();
    for spec in echo_specs(&config.base) {
        flows.push(match spec.transport {
            FlowTransport::Tcp => run_client_tcp(&config.base, &spec)?,
            FlowTransport::Udp => run_probe_client_udp(&config, &spec)?,
        });
    }
    write_json_synced(
        &config.base.client_report_path,
        &ProcessReport {
            role: "client".to_owned(),
            nonce: config.base.nonce.clone(),
            network_namespace: network_namespace_identity()?,
            flows,
        },
    )
}

fn run_probe_client_udp(
    config: &TproxyHarnessConfig,
    spec: &FlowSpec,
) -> Result<FlowReport, String> {
    let source_ip = match spec.family {
        AddressFamily::Ipv4 => IpAddr::V4(config.probe_ipv4),
        AddressFamily::Ipv6 => IpAddr::V6(config.probe_ipv6),
    };
    let socket = UdpSocket::bind(SocketAddr::new(source_ip, 0))
        .map_err(|error| format!("bind ingress TPROXY client UDP flow {}: {error}", spec.id))?;
    socket.connect(spec.peer).map_err(|error| {
        format!(
            "connect ingress TPROXY client UDP flow {} to {}: {error}",
            spec.id, spec.peer
        )
    })?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| socket.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|error| {
            format!(
                "set ingress TPROXY client UDP timeouts for {}: {error}",
                spec.id
            )
        })?;
    let request = spec.request(&config.base)?;
    let sent = socket
        .send(&request)
        .map_err(|error| format!("send ingress TPROXY client UDP flow {}: {error}", spec.id))?;
    if sent != request.len() {
        return Err(format!(
            "ingress TPROXY client UDP flow {} sent {sent} of {} request bytes",
            spec.id,
            request.len()
        ));
    }
    let mut buffer = [0_u8; 4096];
    let length = socket.recv(&mut buffer).map_err(|error| {
        format!(
            "receive ingress TPROXY client UDP flow {}: {error}",
            spec.id
        )
    })?;
    let response = buffer[..length].to_vec();
    validate_response(spec, &config.base, &request, &response)?;
    let local = socket
        .local_addr()
        .map_err(|error| format!("read ingress TPROXY client UDP local tuple: {error}"))?;
    let remote = socket
        .peer_addr()
        .map_err(|error| format!("read ingress TPROXY client UDP peer tuple: {error}"))?;
    flow_report(spec, &config.base, local, remote, request, response)
}

fn run_relay() -> Result<(), String> {
    let config = config_from_environment()?;
    let ipv4_tcp =
        TransparentTcpListener::bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.tproxy_port)?;
    let ipv6_tcp =
        TransparentTcpListener::bind(IpAddr::V6(Ipv6Addr::UNSPECIFIED), config.tproxy_port)?;
    let ipv4_udp = TransparentUdpListener::bind(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        config.tproxy_port,
        IO_TIMEOUT,
    )?;
    let ipv6_udp = TransparentUdpListener::bind(
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        config.tproxy_port,
        IO_TIMEOUT,
    )?;
    let ready = RelayReadyReport {
        role: "relay".to_owned(),
        nonce: config.base.nonce.clone(),
        network_namespace: network_namespace_identity()?,
        process_identity: capture_process_identity(std::process::id())?,
        ipv4_tcp_listener: ipv4_tcp.local_addr()?,
        ipv6_tcp_listener: ipv6_tcp.local_addr()?,
        ipv4_tcp_transparent: ipv4_tcp.transparent_readback(),
        ipv6_tcp_transparent: ipv6_tcp.transparent_readback(),
        ipv6_tcp_only: ipv6_tcp.ipv6_only_readback().ok_or_else(|| {
            "IPv6 transparent TCP listener omitted IPV6_V6ONLY readback".to_owned()
        })?,
        ipv4_udp_listener: ipv4_udp.local_addr()?,
        ipv6_udp_listener: ipv6_udp.local_addr()?,
        ipv4_udp_transparent: ipv4_udp.transparent_readback(),
        ipv6_udp_transparent: ipv6_udp.transparent_readback(),
        ipv4_udp_receive_original_destination: ipv4_udp.receive_original_destination_readback(),
        ipv6_udp_receive_original_destination: ipv6_udp.receive_original_destination_readback(),
        ipv6_udp_only: ipv6_udp.ipv6_only_readback().ok_or_else(|| {
            "IPv6 transparent UDP listener omitted IPV6_V6ONLY readback".to_owned()
        })?,
        relay_mark: RELAY_BYPASS_MARK,
    };
    write_json_synced(&config.relay_ready_path, &ready)?;

    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let mut flows = Vec::new();
    for spec in echo_specs(&config.base) {
        flows.push(match spec.transport {
            FlowTransport::Tcp => {
                let listener = match spec.family {
                    AddressFamily::Ipv4 => ipv4_tcp.listener(),
                    AddressFamily::Ipv6 => ipv6_tcp.listener(),
                };
                relay_tcp_echo(&config, &spec, listener, deadline)?
            }
            FlowTransport::Udp => {
                let listener = match spec.family {
                    AddressFamily::Ipv4 => &ipv4_udp,
                    AddressFamily::Ipv6 => &ipv6_udp,
                };
                relay_udp_echo(&config, &spec, listener)?
            }
        });
    }
    write_json_synced(
        &config.relay_report_path,
        &RelayReport {
            role: "relay".to_owned(),
            nonce: config.base.nonce.clone(),
            network_namespace: network_namespace_identity()?,
            flows,
        },
    )?;
    wait_for_stop(&config.relay_stop_path, PROCESS_TIMEOUT)
}

fn relay_tcp_echo(
    config: &TproxyHarnessConfig,
    spec: &FlowSpec,
    listener: &TcpListener,
    deadline: Instant,
) -> Result<RelayFlowReport, String> {
    let (mut inbound, inbound_remote) = accept_until(listener, deadline, &spec.id)?;
    inbound
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| inbound.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|error| format!("set relay inbound timeouts for {}: {error}", spec.id))?;
    let original_destination = inbound
        .local_addr()
        .map_err(|error| format!("read relay original destination for {}: {error}", spec.id))?;
    if original_destination != spec.peer {
        return Err(format!(
            "relay flow {} recovered original destination {original_destination}, expected {}",
            spec.id, spec.peer
        ));
    }
    let request = read_u32_frame(&mut inbound)?;
    require_expected_request(config, spec, &request)?;
    let relay_ip = relay_peer_ip(config, spec.family);
    let (mut outbound, observed_socket_mark) = connect_marked_tcp(
        SocketAddr::new(relay_ip, 0),
        original_destination,
        RELAY_BYPASS_MARK,
        IO_TIMEOUT,
    )?;
    let outbound_local = outbound
        .local_addr()
        .map_err(|error| format!("read relay outbound local tuple for {}: {error}", spec.id))?;
    let outbound_remote = outbound
        .peer_addr()
        .map_err(|error| format!("read relay outbound peer tuple for {}: {error}", spec.id))?;
    write_u32_frame(&mut outbound, &request)?;
    let response = read_u32_frame(&mut outbound)?;
    require_expected_response(config, spec, &request, &response)?;
    if tcp_socket_mark(&outbound)? != RELAY_BYPASS_MARK {
        return Err(format!(
            "relay TCP flow {} lost its SO_MARK before response",
            spec.id
        ));
    }
    write_u32_frame(&mut inbound, &response)?;
    Ok(RelayFlowReport {
        id: spec.id.clone(),
        family: spec.family.label().to_owned(),
        transport: spec.transport.label().to_owned(),
        semantic: spec.semantic.label().to_owned(),
        inbound_remote,
        original_destination,
        outbound_local,
        outbound_remote,
        observed_socket_mark,
        response_local: None,
        response_remote: None,
        observed_response_socket_mark: None,
        request_hex: hex_encode(&request),
        response_hex: hex_encode(&response),
    })
}

fn relay_udp_echo(
    config: &TproxyHarnessConfig,
    spec: &FlowSpec,
    listener: &TransparentUdpListener,
) -> Result<RelayFlowReport, String> {
    let mut inbound_buffer = [0_u8; 4096];
    let inbound = listener.receive(&mut inbound_buffer)?;
    if inbound.original_destination != spec.peer {
        return Err(format!(
            "relay UDP flow {} recovered original destination {}, expected {}",
            spec.id, inbound.original_destination, spec.peer
        ));
    }
    require_expected_request(config, spec, &inbound.payload)?;

    let relay_ip = relay_peer_ip(config, spec.family);
    let (outbound, observed_socket_mark) = connect_marked_udp(
        SocketAddr::new(relay_ip, 0),
        inbound.original_destination,
        RELAY_BYPASS_MARK,
        IO_TIMEOUT,
    )?;
    let outbound_local = outbound.local_addr().map_err(|error| {
        format!(
            "read relay UDP outbound local tuple for {}: {error}",
            spec.id
        )
    })?;
    let outbound_remote = outbound.peer_addr().map_err(|error| {
        format!(
            "read relay UDP outbound peer tuple for {}: {error}",
            spec.id
        )
    })?;
    let sent = outbound
        .send(&inbound.payload)
        .map_err(|error| format!("send relay UDP upstream flow {}: {error}", spec.id))?;
    if sent != inbound.payload.len() {
        return Err(format!(
            "relay UDP flow {} sent {sent} of {} upstream bytes",
            spec.id,
            inbound.payload.len()
        ));
    }
    let mut response_buffer = [0_u8; 4096];
    let response_length = outbound
        .recv(&mut response_buffer)
        .map_err(|error| format!("receive relay UDP upstream flow {}: {error}", spec.id))?;
    let response = response_buffer[..response_length].to_vec();
    require_expected_response(config, spec, &inbound.payload, &response)?;
    if udp_socket_mark(&outbound)? != RELAY_BYPASS_MARK {
        return Err(format!(
            "relay UDP flow {} lost its upstream SO_MARK before response",
            spec.id
        ));
    }

    let (response_socket, observed_response_socket_mark, transparent) =
        connect_transparent_marked_udp(
            inbound.original_destination,
            inbound.remote,
            RELAY_BYPASS_MARK,
            IO_TIMEOUT,
        )?;
    if transparent != 1 || udp_socket_mark(&response_socket)? != RELAY_BYPASS_MARK {
        return Err(format!(
            "relay UDP flow {} response socket lost transparency or SO_MARK",
            spec.id
        ));
    }
    let response_local = response_socket.local_addr().map_err(|error| {
        format!(
            "read relay UDP response local tuple for {}: {error}",
            spec.id
        )
    })?;
    let response_remote = response_socket.peer_addr().map_err(|error| {
        format!(
            "read relay UDP response peer tuple for {}: {error}",
            spec.id
        )
    })?;
    let sent = response_socket
        .send(&response)
        .map_err(|error| format!("send relay UDP client response for {}: {error}", spec.id))?;
    if sent != response.len() {
        return Err(format!(
            "relay UDP flow {} sent {sent} of {} client-response bytes",
            spec.id,
            response.len()
        ));
    }

    Ok(RelayFlowReport {
        id: spec.id.clone(),
        family: spec.family.label().to_owned(),
        transport: spec.transport.label().to_owned(),
        semantic: spec.semantic.label().to_owned(),
        inbound_remote: inbound.remote,
        original_destination: inbound.original_destination,
        outbound_local,
        outbound_remote,
        observed_socket_mark,
        response_local: Some(response_local),
        response_remote: Some(response_remote),
        observed_response_socket_mark: Some(observed_response_socket_mark),
        request_hex: hex_encode(&inbound.payload),
        response_hex: hex_encode(&response),
    })
}

fn relay_peer_ip(config: &TproxyHarnessConfig, family: AddressFamily) -> IpAddr {
    match family {
        AddressFamily::Ipv4 => IpAddr::V4(config.base.daemon_ipv4),
        AddressFamily::Ipv6 => IpAddr::V6(config.base.daemon_ipv6),
    }
}

fn require_expected_request(
    config: &TproxyHarnessConfig,
    spec: &FlowSpec,
    request: &[u8],
) -> Result<(), String> {
    let expected = spec.request(&config.base)?;
    if request != expected {
        return Err(format!(
            "relay flow {} received unexpected request: expected={} actual={}",
            spec.id,
            hex_encode(&expected),
            hex_encode(request)
        ));
    }
    Ok(())
}

fn require_expected_response(
    config: &TproxyHarnessConfig,
    spec: &FlowSpec,
    request: &[u8],
    response: &[u8],
) -> Result<(), String> {
    let expected = spec.response(&config.base, request)?;
    if response != expected {
        return Err(format!(
            "relay flow {} received unexpected upstream response: expected={} actual={}",
            spec.id,
            hex_encode(&expected),
            hex_encode(response)
        ));
    }
    Ok(())
}

fn accept_until(
    listener: &TcpListener,
    deadline: Instant,
    flow: &str,
) -> Result<(TcpStream, SocketAddr), String> {
    loop {
        match listener.accept() {
            Ok(accepted) => return Ok(accepted),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "relay flow {flow} timed out waiting for TPROXY accept"
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(format!("accept relay flow {flow}: {error}")),
        }
    }
}

fn echo_specs(config: &HarnessConfig) -> Vec<FlowSpec> {
    flow_specs(config)
        .into_iter()
        .filter(|spec| spec.semantic == FlowSemantic::Echo)
        .collect()
}

struct ObservedReports<'a> {
    client: &'a ProcessReport,
    peer: &'a ProcessReport,
    relay: &'a RelayReport,
    relay_ready: &'a RelayReadyReport,
    peer_ready: &'a ReadyReport,
    peer_holder: &'a HolderReadyReport,
    probe_holder: &'a HolderReadyReport,
}

fn validate_reports(
    config: &TproxyHarnessConfig,
    reports: ObservedReports<'_>,
) -> Result<(), String> {
    let ObservedReports {
        client,
        peer,
        relay,
        relay_ready,
        peer_ready,
        peer_holder,
        probe_holder,
    } = reports;
    if peer_holder.role != HolderRole::Peer.label()
        || probe_holder.role != HolderRole::Probe.label()
        || peer_holder.nonce != config.base.nonce
        || probe_holder.nonce != config.base.nonce
        || peer_holder.network_namespace == probe_holder.network_namespace
        || peer_holder.network_namespace == config.base.daemon_network_namespace
        || probe_holder.network_namespace == config.base.daemon_network_namespace
    {
        return Err(format!(
            "ingress TPROXY holder identity mismatch: peer={peer_holder:?} probe={probe_holder:?}"
        ));
    }
    if client.role != "client"
        || peer.role != "peer"
        || relay.role != "relay"
        || client.nonce != config.base.nonce
        || peer.nonce != config.base.nonce
        || relay.nonce != config.base.nonce
        || relay.network_namespace != config.base.daemon_network_namespace
        || client.network_namespace != probe_holder.network_namespace
        || peer.network_namespace != peer_holder.network_namespace
        || peer_ready.network_namespace != peer_holder.network_namespace
    {
        return Err(format!(
            "ingress TPROXY report identity mismatch: client={client:?} peer={peer:?} relay={relay:?} relay_ready={relay_ready:?} peer_ready={peer_ready:?}"
        ));
    }
    if peer_ready.role != "peer"
        || peer_ready.nonce != config.base.nonce
        || peer_ready.interface != config.base.peer_interface
        || peer_ready.ifindex == 0
        || peer_ready.ipv4 != config.base.peer_ipv4
        || peer_ready.ipv6 != config.base.peer_ipv6
    {
        return Err(format!("peer readiness mismatch: {peer_ready:?}"));
    }
    if relay_ready.role != "relay"
        || relay_ready.nonce != config.base.nonce
        || relay_ready.network_namespace != config.base.daemon_network_namespace
        || relay_ready.ipv4_tcp_listener
            != SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.tproxy_port)
        || relay_ready.ipv6_tcp_listener
            != SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), config.tproxy_port)
        || relay_ready.ipv4_tcp_transparent != 1
        || relay_ready.ipv6_tcp_transparent != 1
        || relay_ready.ipv6_tcp_only != 1
        || relay_ready.ipv4_udp_listener
            != SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.tproxy_port)
        || relay_ready.ipv6_udp_listener
            != SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), config.tproxy_port)
        || relay_ready.ipv4_udp_transparent != 1
        || relay_ready.ipv6_udp_transparent != 1
        || relay_ready.ipv4_udp_receive_original_destination != 1
        || relay_ready.ipv6_udp_receive_original_destination != 1
        || relay_ready.ipv6_udp_only != 1
        || relay_ready.relay_mark != RELAY_BYPASS_MARK
    {
        return Err(format!("relay readiness mismatch: {relay_ready:?}"));
    }
    let client_flows = indexed_flows("client", &client.flows)?;
    let peer_flows = indexed_flows("peer", &peer.flows)?;
    let relay_flows = indexed_relay_flows(&relay.flows)?;
    let specs = echo_specs(&config.base);
    if client_flows.len() != specs.len()
        || peer_flows.len() != specs.len()
        || relay_flows.len() != specs.len()
    {
        return Err(format!(
            "expected {} ingress TPROXY flows, found client={} relay={} peer={}",
            specs.len(),
            client_flows.len(),
            relay_flows.len(),
            peer_flows.len()
        ));
    }
    for spec in specs {
        let client_flow = client_flows
            .get(&spec.id)
            .ok_or_else(|| format!("client omitted flow {}", spec.id))?;
        let relay_flow = relay_flows
            .get(&spec.id)
            .ok_or_else(|| format!("relay omitted flow {}", spec.id))?;
        let peer_flow = peer_flows
            .get(&spec.id)
            .ok_or_else(|| format!("peer omitted flow {}", spec.id))?;
        for (role, flow) in [("client", client_flow), ("peer", peer_flow)] {
            if flow.family != spec.family.label()
                || flow.transport != spec.transport.label()
                || flow.semantic != FlowSemantic::Echo.label()
                || flow.nonce != config.base.nonce
            {
                return Err(format!(
                    "{role} flow {} metadata mismatch: {flow:?}",
                    spec.id
                ));
            }
        }
        let expected_probe_ip = match spec.family {
            AddressFamily::Ipv4 => IpAddr::V4(config.probe_ipv4),
            AddressFamily::Ipv6 => IpAddr::V6(config.probe_ipv6),
        };
        let expected_relay_ip = match spec.family {
            AddressFamily::Ipv4 => IpAddr::V4(config.base.daemon_ipv4),
            AddressFamily::Ipv6 => IpAddr::V6(config.base.daemon_ipv6),
        };
        let response_tuple_valid = match spec.transport {
            FlowTransport::Tcp => {
                relay_flow.response_local.is_none()
                    && relay_flow.response_remote.is_none()
                    && relay_flow.observed_response_socket_mark.is_none()
            }
            FlowTransport::Udp => {
                relay_flow.response_local == Some(client_flow.remote)
                    && relay_flow.response_remote == Some(client_flow.local)
                    && relay_flow.observed_response_socket_mark == Some(RELAY_BYPASS_MARK)
            }
        };
        if client_flow.local.ip() != expected_probe_ip
            || client_flow.remote != spec.peer
            || relay_flow.family != spec.family.label()
            || relay_flow.transport != spec.transport.label()
            || relay_flow.semantic != spec.semantic.label()
            || relay_flow.inbound_remote != client_flow.local
            || relay_flow.original_destination != client_flow.remote
            || relay_flow.outbound_local.ip() != expected_relay_ip
            || relay_flow.outbound_remote != peer_flow.local
            || relay_flow.outbound_local != peer_flow.remote
            || peer_flow.local != spec.peer
            || relay_flow.observed_socket_mark != RELAY_BYPASS_MARK
            || !response_tuple_valid
        {
            return Err(format!(
                "flow {} tuple/mark cross-check failed: client={client_flow:?} relay={relay_flow:?} peer={peer_flow:?}",
                spec.id
            ));
        }
        let request = spec.request(&config.base)?;
        let response = spec.response(&config.base, &request)?;
        let expected_request = hex_encode(&request);
        let expected_response = hex_encode(&response);
        if client_flow.request_hex != expected_request
            || relay_flow.request_hex != expected_request
            || peer_flow.request_hex != expected_request
            || client_flow.response_hex != expected_response
            || relay_flow.response_hex != expected_response
            || peer_flow.response_hex != expected_response
            || client_flow.dns.is_some()
            || peer_flow.dns.is_some()
        {
            return Err(format!("flow {} payload cross-check failed", spec.id));
        }
    }
    Ok(())
}

fn indexed_relay_flows(
    flows: &[RelayFlowReport],
) -> Result<BTreeMap<String, &RelayFlowReport>, String> {
    let mut indexed = BTreeMap::new();
    for flow in flows {
        if indexed.insert(flow.id.clone(), flow).is_some() {
            return Err(format!("relay reported flow {} more than once", flow.id));
        }
    }
    Ok(indexed)
}

fn read_counters(config: &TproxyHarnessConfig) -> Result<CounterSnapshot, String> {
    let ipv4 = command_output("iptables-save", &["-c", "-t", "mangle"])?;
    let ipv6 = command_output("ip6tables-save", &["-c", "-t", "mangle"])?;
    Ok(CounterSnapshot {
        ipv4: FamilyCounterSnapshot {
            capture_tcp: packet_count_for_comment(&ipv4, &config.comments.ipv4_capture_tcp)?,
            capture_udp: packet_count_for_comment(&ipv4, &config.comments.ipv4_capture_udp)?,
            bypass_tcp: packet_count_for_comment(&ipv4, &config.comments.ipv4_bypass_tcp)?,
            bypass_udp: packet_count_for_comment(&ipv4, &config.comments.ipv4_bypass_udp)?,
            recapture_attempt: packet_count_for_comment(&ipv4, &config.comments.ipv4_recapture)?,
            unexpected_ingress: packet_count_for_comment(
                &ipv4,
                &config.comments.ipv4_unexpected_ingress,
            )?,
            unexpected_output: packet_count_for_comment(
                &ipv4,
                &config.comments.ipv4_unexpected_output,
            )?,
        },
        ipv6: FamilyCounterSnapshot {
            capture_tcp: packet_count_for_comment(&ipv6, &config.comments.ipv6_capture_tcp)?,
            capture_udp: packet_count_for_comment(&ipv6, &config.comments.ipv6_capture_udp)?,
            bypass_tcp: packet_count_for_comment(&ipv6, &config.comments.ipv6_bypass_tcp)?,
            bypass_udp: packet_count_for_comment(&ipv6, &config.comments.ipv6_bypass_udp)?,
            recapture_attempt: packet_count_for_comment(&ipv6, &config.comments.ipv6_recapture)?,
            unexpected_ingress: packet_count_for_comment(
                &ipv6,
                &config.comments.ipv6_unexpected_ingress,
            )?,
            unexpected_output: packet_count_for_comment(
                &ipv6,
                &config.comments.ipv6_unexpected_output,
            )?,
        },
    })
}

fn packet_count_for_comment(dump: &[u8], comment: &str) -> Result<u64, String> {
    let text = std::str::from_utf8(dump)
        .map_err(|error| format!("iptables-save counter dump is not UTF-8: {error}"))?;
    let matches = text
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .any(|word| word.trim_matches('"') == comment)
        })
        .collect::<Vec<_>>();
    let [line] = matches.as_slice() else {
        return Err(format!(
            "counter comment {comment:?} matched {} rules: {matches:?}",
            matches.len()
        ));
    };
    let counter = line
        .strip_prefix('[')
        .and_then(|line| line.split_once(']'))
        .map(|(counter, _)| counter)
        .ok_or_else(|| format!("counter rule lacks [packets:bytes] prefix: {line}"))?;
    let packets = counter
        .split_once(':')
        .map(|(packets, _)| packets)
        .ok_or_else(|| format!("counter rule has malformed prefix: {line}"))?;
    packets
        .parse()
        .map_err(|error| format!("parse packet counter {packets:?}: {error}"))
}

fn validate_counter_bounds(snapshot: CounterSnapshot) -> Result<(), String> {
    for (family, counters) in [("IPv4", snapshot.ipv4), ("IPv6", snapshot.ipv6)] {
        if !(1..=TCP_CAPTURE_MAXIMUM).contains(&counters.capture_tcp)
            || !(1..=TCP_CAPTURE_MAXIMUM).contains(&counters.bypass_tcp)
            || counters.capture_udp != UDP_ECHO_PACKET_COUNT
            || counters.bypass_udp != UDP_ECHO_PACKET_COUNT
            || counters.recapture_attempt != 0
            || counters.unexpected_ingress != 0
            || counters.unexpected_output != 0
        {
            return Err(format!(
                "{family} ingress TPROXY counters are outside the TCP/UDP echo checkpoint bounds: {counters:?}"
            ));
        }
    }
    Ok(())
}

fn validate_route_controls(config: &TproxyHarnessConfig) -> Result<(), String> {
    require_local_route_lookup(
        false,
        &config.base.peer_ipv4.to_string(),
        config.ipv4_route_table,
    )?;
    require_local_route_lookup(
        true,
        &config.base.peer_ipv6.to_string(),
        config.ipv6_route_table,
    )?;
    require_bypass_route_lookup(
        false,
        &config.base.peer_ipv4.to_string(),
        &config.base.daemon_interface,
        &config.base.daemon_ipv4.to_string(),
    )?;
    require_bypass_route_lookup(
        true,
        &config.base.peer_ipv6.to_string(),
        &config.base.daemon_interface,
        &config.base.daemon_ipv6.to_string(),
    )
}

fn require_local_route_lookup(ipv6: bool, destination: &str, table: u32) -> Result<(), String> {
    let mut args = Vec::new();
    if ipv6 {
        args.push("-6".to_owned());
    }
    args.extend([
        "-j".to_owned(),
        "route".to_owned(),
        "get".to_owned(),
        destination.to_owned(),
        "mark".to_owned(),
        format!("{PROXY_MARK:#x}"),
        "uid".to_owned(),
        "0".to_owned(),
    ]);
    let output = command_output_owned("ip", &args)?;
    let route = first_route(&output)?;
    let observed_table = route
        .get("table")
        .and_then(value_as_u32)
        .ok_or_else(|| format!("local route lookup omitted numeric table: {route:?}"))?;
    if route.get("type").and_then(Value::as_str) != Some("local")
        || route.get("dev").and_then(Value::as_str) != Some("lo")
        || observed_table != table
    {
        return Err(format!(
            "proxy-mark route lookup selected the wrong path: expected local table {table}, observed {route:?}"
        ));
    }
    Ok(())
}

fn require_bypass_route_lookup(
    ipv6: bool,
    destination: &str,
    interface: &str,
    source: &str,
) -> Result<(), String> {
    let mut args = Vec::new();
    if ipv6 {
        args.push("-6".to_owned());
    }
    args.extend([
        "-j".to_owned(),
        "route".to_owned(),
        "get".to_owned(),
        destination.to_owned(),
        "mark".to_owned(),
        format!("{RELAY_BYPASS_MARK:#x}"),
        "uid".to_owned(),
        "0".to_owned(),
    ]);
    let output = command_output_owned("ip", &args)?;
    let route = first_route(&output)?;
    let observed_source = route
        .get("prefsrc")
        .or_else(|| route.get("src"))
        .and_then(Value::as_str);
    if route.get("type").and_then(Value::as_str) == Some("local")
        || route.get("dev").and_then(Value::as_str) != Some(interface)
        || observed_source != Some(source)
    {
        return Err(format!(
            "relay-bypass route lookup selected the wrong path: expected dev={interface} source={source}, observed {route:?}"
        ));
    }
    Ok(())
}

fn first_route(output: &[u8]) -> Result<serde_json::Map<String, Value>, String> {
    let value: Value =
        serde_json::from_slice(output).map_err(|error| format!("decode ip route JSON: {error}"))?;
    let routes = value
        .as_array()
        .ok_or_else(|| format!("ip route JSON is not an array: {value}"))?;
    let [route] = routes.as_slice() else {
        return Err(format!(
            "ip route JSON contains {} entries: {value}",
            routes.len()
        ));
    };
    route
        .as_object()
        .cloned()
        .ok_or_else(|| format!("ip route JSON entry is not an object: {route}"))
}

fn value_as_u32(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn cleanup_isolated(resources: &mut TproxyResources) -> Result<(), String> {
    let mut failures = Vec::new();
    let mut inverse_diagnostics = Vec::new();
    if !resources.pending_mutations.is_empty()
        && let Err(error) = resources.journal.record(
            "before-capture-cleanup",
            &["replay exact ingress TPROXY mutation inverses".to_owned()],
            &["terminal cleanup has no inverse".to_owned()],
        )
    {
        failures.push(error);
    }

    for mutation in resources
        .pending_mutations
        .iter()
        .rev()
        .filter(|mutation| mutation.stage.ends_with("-prerouting-hook"))
    {
        attempt_inverse(mutation, &mut inverse_diagnostics);
    }
    let ingress_detached =
        prerouting_hooks_absent(&resources.pending_mutations, &mut inverse_diagnostics);
    if !ingress_detached {
        failures.push(
            "PREROUTING capture hooks remain or could not be proven absent before relay reap"
                .to_owned(),
        );
        cut_probe_link(resources, &mut failures);
    }

    stop_reporting_child(
        &resources.journal,
        "before-relay-cleanup",
        &resources.config.relay_report_path,
        &resources.config.relay_stop_path,
        &mut resources.relay,
        resources.relay_identity,
        &resources.relay_log,
        &mut failures,
        "relay",
    );
    stop_reporting_child(
        &resources.journal,
        "before-peer-server-cleanup",
        &resources.config.base.peer_report_path,
        &resources.config.peer_server_stop_path,
        &mut resources.peer_server,
        resources.peer_server_identity,
        &resources.peer_server_log,
        &mut failures,
        "peer server",
    );

    for mutation in resources
        .pending_mutations
        .iter()
        .rev()
        .filter(|mutation| !mutation.stage.ends_with("-prerouting-hook"))
    {
        attempt_inverse(mutation, &mut inverse_diagnostics);
    }
    if !validate_baselines(resources, &mut failures) {
        failures.extend(inverse_diagnostics);
    }

    for (may_exist, interface, label) in [
        (
            &mut resources.probe_link_may_exist,
            resources.config.relay_probe_interface.as_str(),
            "probe veth",
        ),
        (
            &mut resources.peer_link_may_exist,
            resources.config.base.daemon_interface.as_str(),
            "peer veth",
        ),
    ] {
        if *may_exist {
            if let Err(error) = delete_interface_if_present(interface) {
                failures.push(format!("delete {label}: {error}"));
            }
            *may_exist = false;
        }
        if let Err(error) = assert_interface_absent(None, interface) {
            failures.push(error);
        }
    }
    if let Some(holder) = resources.peer_holder_identity
        && let Err(error) =
            assert_interface_absent(Some(holder), &resources.config.base.peer_interface)
    {
        failures.push(error);
    }
    if let Some(holder) = resources.probe_holder_identity
        && let Err(error) = assert_interface_absent(Some(holder), &resources.config.probe_interface)
    {
        failures.push(error);
    }

    stop_holder(
        &resources.journal,
        "before-probe-holder-stop",
        &resources.config.probe_stop_path,
        &mut resources.probe_holder,
        resources.probe_holder_identity,
        &resources.probe_holder_log,
        &mut failures,
        "probe holder",
    );
    stop_holder(
        &resources.journal,
        "before-peer-holder-stop",
        &resources.config.base.stop_path,
        &mut resources.peer_holder,
        resources.peer_holder_identity,
        &resources.peer_holder_log,
        &mut failures,
        "peer holder",
    );
    if let Err(error) = validate_journal_integrity(
        &resources.config.base.journal_path,
        &resources.config.base.nonce,
    ) {
        failures.push(error);
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn cut_probe_link(resources: &mut TproxyResources, failures: &mut Vec<String>) {
    if resources.probe_link_may_exist {
        if let Err(error) = resources.journal.record(
            "before-probe-veth-safety-cut",
            &prefixed_words(
                "ip",
                &strings(&[
                    "link",
                    "delete",
                    "dev",
                    &resources.config.relay_probe_interface,
                ]),
            ),
            &["terminal safety cut has no inverse".to_owned()],
        ) {
            failures.push(error);
        }
        if let Err(error) = delete_interface_if_present(&resources.config.relay_probe_interface) {
            failures.push(format!("cut probe veth before relay reap: {error}"));
        }
        resources.probe_link_may_exist = false;
    }
    if let Err(error) = assert_interface_absent(None, &resources.config.relay_probe_interface) {
        failures.push(error);
    }
}

fn attempt_inverse(mutation: &PlannedMutation, diagnostics: &mut Vec<String>) {
    let mut command = Command::new(&mutation.program);
    command.args(&mutation.inverse);
    match run_command(&mut command, COMMAND_TIMEOUT) {
        Ok(output) if output.status.success() => {}
        Ok(output) => diagnostics.push(format!(
            "inverse {} {} exited with {}: stdout={} stderr={}",
            mutation.program,
            mutation.inverse.join(" "),
            output.status,
            bounded_diagnostic(&output.stdout),
            bounded_diagnostic(&output.stderr)
        )),
        Err(error) => diagnostics.push(format!(
            "execute inverse {} {}: {error}",
            mutation.program,
            mutation.inverse.join(" ")
        )),
    }
}

fn prerouting_hooks_absent(pending: &[PlannedMutation], diagnostics: &mut Vec<String>) -> bool {
    let mut all_absent = true;
    for mutation in pending
        .iter()
        .filter(|mutation| mutation.stage.ends_with("-prerouting-hook"))
    {
        let mut check = mutation.action.clone();
        let Some(operation) = check.iter().position(|argument| argument == "-I") else {
            diagnostics.push(format!(
                "PREROUTING mutation lacks insert operation: {mutation:?}"
            ));
            all_absent = false;
            continue;
        };
        check[operation] = "-C".to_owned();
        if check
            .get(operation + 2)
            .is_some_and(|argument| argument == "1")
        {
            check.remove(operation + 2);
        }
        let mut command = Command::new(&mutation.program);
        command.args(&check);
        match run_command(&mut command, COMMAND_TIMEOUT) {
            Ok(output) if output.status.success() => {
                diagnostics.push(format!(
                    "PREROUTING hook remains after inverse: {} {}",
                    mutation.program,
                    check.join(" ")
                ));
                all_absent = false;
            }
            Ok(output) if output.status.code() == Some(1) => {}
            Ok(output) => {
                diagnostics.push(format!(
                    "verify PREROUTING hook absence with {} {} exited with {}: stdout={} stderr={}",
                    mutation.program,
                    check.join(" "),
                    output.status,
                    bounded_diagnostic(&output.stdout),
                    bounded_diagnostic(&output.stderr)
                ));
                all_absent = false;
            }
            Err(error) => {
                diagnostics.push(format!(
                    "verify PREROUTING hook absence with {} {}: {error}",
                    mutation.program,
                    check.join(" ")
                ));
                all_absent = false;
            }
        }
    }
    all_absent
}

fn validate_baselines(resources: &TproxyResources, failures: &mut Vec<String>) -> bool {
    let failures_before = failures.len();
    for (label, expected, observed) in [
        (
            "IPv4 mangle",
            resources.baseline_ipv4_mangle.as_deref(),
            mangle_dump("iptables-save"),
        ),
        (
            "IPv6 mangle",
            resources.baseline_ipv6_mangle.as_deref(),
            mangle_dump("ip6tables-save"),
        ),
        (
            "IPv4 RPDB",
            resources.baseline_ipv4_rules.as_deref(),
            command_output("ip", &["-j", "rule", "show"]),
        ),
        (
            "IPv6 RPDB",
            resources.baseline_ipv6_rules.as_deref(),
            command_output("ip", &["-6", "-j", "rule", "show"]),
        ),
        (
            "IPv4 private table",
            resources.baseline_ipv4_table.as_deref(),
            route_table_dump(false, resources.config.ipv4_route_table),
        ),
        (
            "IPv6 private table",
            resources.baseline_ipv6_table.as_deref(),
            route_table_dump(true, resources.config.ipv6_route_table),
        ),
    ] {
        if let Some(expected) = expected {
            match observed {
                Ok(observed) if observed == expected => {}
                Ok(observed) => failures.push(format!(
                    "{label} baseline was not restored: expected={} observed={}",
                    bounded_diagnostic(expected),
                    bounded_diagnostic(&observed)
                )),
                Err(error) => failures.push(format!("read {label} cleanup baseline: {error}")),
            }
        }
    }
    failures.len() == failures_before
}

#[allow(clippy::too_many_arguments)]
fn stop_reporting_child(
    journal: &Journal,
    stage: &str,
    report_path: &Path,
    stop_path: &Path,
    child: &mut Option<Child>,
    identity: Option<ProcessIdentity>,
    log: &Path,
    failures: &mut Vec<String>,
    label: &str,
) {
    let Some(mut child) = child.take() else {
        return;
    };
    let Some(identity) = identity else {
        failures.push(format!("{label} child existed without a captured identity"));
        if let Err(error) = kill_live_child_group(&mut child) {
            failures.push(format!("kill unidentified {label}: {error}"));
        }
        if let Err(error) = wait_child(&mut child, IO_TIMEOUT) {
            failures.push(format!("reap unidentified {label}: {error}"));
        }
        return;
    };
    if !report_path.exists() {
        if let Err(error) = journal.record_for_process(
            stage,
            &[
                format!("terminate-and-reap-incomplete-{label}"),
                identity.pid.to_string(),
            ],
            &["no-inverse-owned-process-cleanup".to_owned()],
            identity,
        ) {
            failures.push(error);
        }
        if let Err(error) = terminate_and_reap_owned(&mut child, identity, IO_TIMEOUT) {
            failures.push(format!("clean up incomplete {label}: {error}"));
        }
        return;
    }
    if let Err(error) = journal.record_for_process(
        stage,
        &[
            "create-stop-token".to_owned(),
            stop_path.display().to_string(),
        ],
        &["remove-stop-token".to_owned()],
        identity,
    ) {
        failures.push(error);
    }
    if let Err(error) = write_synced(stop_path, b"stop\n") {
        failures.push(error);
    }
    match wait_child(&mut child, IO_TIMEOUT) {
        Ok(status) if status.success() => {}
        Ok(status) => failures.push(format!(
            "{label} exited with {status}: {}",
            read_diagnostic(log)
        )),
        Err(error) => {
            failures.push(format!(
                "{label} did not stop after capture detach: {error}"
            ));
            if let Err(cleanup_error) = terminate_and_reap_owned(&mut child, identity, IO_TIMEOUT) {
                failures.push(format!("force clean up {label}: {cleanup_error}"));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn stop_holder(
    journal: &Journal,
    stage: &str,
    stop_path: &Path,
    child: &mut Option<Child>,
    identity: Option<ProcessIdentity>,
    log: &Path,
    failures: &mut Vec<String>,
    label: &str,
) {
    let Some(mut child) = child.take() else {
        return;
    };
    let Some(identity) = identity else {
        failures.push(format!("{label} existed without a captured identity"));
        let _ = kill_live_child_group(&mut child);
        let _ = wait_child(&mut child, IO_TIMEOUT);
        return;
    };
    if let Err(error) = journal.record_for_process(
        stage,
        &[
            "create-stop-token".to_owned(),
            stop_path.display().to_string(),
        ],
        &["remove-stop-token".to_owned()],
        identity,
    ) {
        failures.push(error);
    }
    if let Err(error) = write_synced(stop_path, b"stop\n") {
        failures.push(error);
    }
    match wait_child(&mut child, IO_TIMEOUT) {
        Ok(status) if status.success() => {}
        Ok(status) => failures.push(format!(
            "{label} exited with {status}: {}",
            read_diagnostic(log)
        )),
        Err(error) => {
            let kill_error = kill_owned_process_group(identity).err();
            let reap_error = wait_child(&mut child, IO_TIMEOUT).err();
            failures.push(format!(
                "reap {label}: {error}; kill_error={kill_error:?}; reap_error={reap_error:?}"
            ));
        }
    }
}

fn route_table_dump(ipv6: bool, table: u32) -> Result<Vec<u8>, String> {
    let mut arguments = Vec::new();
    if ipv6 {
        arguments.push("-6".to_owned());
    }
    arguments.extend([
        "-j".to_owned(),
        "route".to_owned(),
        "show".to_owned(),
        "table".to_owned(),
        table.to_string(),
    ]);
    let mut command = Command::new("ip");
    command.args(&arguments);
    let output = run_command(&mut command, COMMAND_TIMEOUT)?;
    if output.status.success() || output.stdout == b"[]\n" || output.stdout == b"[]" {
        Ok(output.stdout)
    } else {
        Err(format!(
            "ip {} exited with {}: stdout={} stderr={}",
            arguments.join(" "),
            output.status,
            bounded_diagnostic(&output.stdout),
            bounded_diagnostic(&output.stderr)
        ))
    }
}

fn mangle_dump(program: &str) -> Result<Vec<u8>, String> {
    let dump = command_output(program, &["-t", "mangle"])?;
    let text = std::str::from_utf8(&dump)
        .map_err(|error| format!("{program} output is not UTF-8: {error}"))?;
    let mut canonical = Vec::new();
    for line in text
        .lines()
        .filter(|line| !line.starts_with("# Generated by ") && !line.starts_with("# Completed on "))
    {
        if line.starts_with(':') {
            let prefix = line
                .split_once('[')
                .map(|(prefix, _)| prefix)
                .ok_or_else(|| format!("{program} chain declaration lacks counters: {line}"))?;
            canonical.extend_from_slice(prefix.as_bytes());
            canonical.extend_from_slice(b"[0:0]\n");
        } else {
            canonical.extend_from_slice(line.as_bytes());
            canonical.push(b'\n');
        }
    }
    Ok(canonical)
}

fn config_from_environment() -> Result<TproxyHarnessConfig, String> {
    let path = env::var_os(CONFIG_ENV).ok_or_else(|| format!("{CONFIG_ENV} is required"))?;
    read_json(Path::new(&path))
}

fn log_files(path: &Path) -> Result<(File, File), String> {
    let stdout = File::create(path)
        .map_err(|error| format!("create child log {}: {error}", path.display()))?;
    let stderr = stdout
        .try_clone()
        .map_err(|error| format!("clone child log {}: {error}", path.display()))?;
    Ok((stdout, stderr))
}

fn command(program: &str, arguments: &[&str]) -> Result<(), String> {
    let mut command = Command::new(program);
    command.args(arguments);
    checked_command(command, COMMAND_TIMEOUT).map(|_| ())
}

fn command_owned(program: &str, arguments: &[String]) -> Result<(), String> {
    let mut command = Command::new(program);
    command.args(arguments);
    checked_command(command, COMMAND_TIMEOUT).map(|_| ())
}

fn command_output(program: &str, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let mut command = Command::new(program);
    command.args(arguments);
    checked_command(command, COMMAND_TIMEOUT).map(|output| output.stdout)
}

fn command_output_owned(program: &str, arguments: &[String]) -> Result<Vec<u8>, String> {
    let mut command = Command::new(program);
    command.args(arguments);
    checked_command(command, COMMAND_TIMEOUT).map(|output| output.stdout)
}

fn strings(arguments: &[&str]) -> Vec<String> {
    arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_protocol_rule<'a>(
        rules: &'a [Vec<String>],
        action: &str,
        protocol: &str,
    ) -> &'a [String] {
        let matches = rules
            .iter()
            .filter(|rule| {
                rule_action(rule) == Some(action)
                    && rule_value_after(rule, &["-p", "--protocol"]) == Some(protocol)
            })
            .collect::<Vec<_>>();
        let [rule] = matches.as_slice() else {
            panic!(
                "expected exactly one {protocol} {action} rule, found {}",
                matches.len()
            );
        };
        rule
    }

    #[test]
    fn ingress_rule_plan_never_places_tproxy_in_output() {
        let directory = PathBuf::from("/tmp/flux-ingress-rule-plan-test");
        let config = TproxyHarnessConfig {
            base: HarnessConfig {
                nonce: "0123456789abcdef0123456789abcdef".to_owned(),
                daemon_network_namespace: "net:[1]".to_owned(),
                daemon_interface: "fxrelay".to_owned(),
                peer_interface: "fxpeer".to_owned(),
                daemon_ipv4: Ipv4Addr::new(11, 23, 42, 1),
                peer_ipv4: Ipv4Addr::new(11, 23, 42, 2),
                daemon_ipv6: "2001:db8:1::1".parse().expect("test IPv6"),
                peer_ipv6: "2001:db8:1::2".parse().expect("test IPv6"),
                tcp_port: 41_001,
                udp_port: 41_002,
                dns_port: 41_053,
                journal_path: directory.join("journal"),
                holder_ready_path: directory.join("holder"),
                ready_path: directory.join("ready"),
                peer_report_path: directory.join("peer"),
                client_report_path: directory.join("client"),
                stop_path: directory.join("stop"),
            },
            relay_probe_interface: "fxdaemon".to_owned(),
            probe_interface: "fxprobe".to_owned(),
            relay_probe_ipv4: Ipv4Addr::new(11, 23, 43, 1),
            probe_ipv4: Ipv4Addr::new(11, 23, 43, 2),
            relay_probe_ipv6: "2001:db8:2::1".parse().expect("test IPv6"),
            probe_ipv6: "2001:db8:2::2".parse().expect("test IPv6"),
            tproxy_port: 41_090,
            ipv4_rule_priority: 10_001,
            ipv6_rule_priority: 12_001,
            ipv4_route_table: 20_001,
            ipv6_route_table: 24_001,
            chains: ChainNames {
                ipv4_ingress: "FX4TESTI".to_owned(),
                ipv4_output: "FX4TESTO".to_owned(),
                ipv6_ingress: "FX6TESTI".to_owned(),
                ipv6_output: "FX6TESTO".to_owned(),
            },
            comments: CounterComments {
                ipv4_capture_tcp: "f4ct".to_owned(),
                ipv4_capture_udp: "f4cu".to_owned(),
                ipv4_unexpected_ingress: "f4uin".to_owned(),
                ipv4_bypass_tcp: "f4bt".to_owned(),
                ipv4_bypass_udp: "f4bu".to_owned(),
                ipv4_recapture: "f4rec".to_owned(),
                ipv4_unexpected_output: "f4uout".to_owned(),
                ipv6_capture_tcp: "f6ct".to_owned(),
                ipv6_capture_udp: "f6cu".to_owned(),
                ipv6_unexpected_ingress: "f6uin".to_owned(),
                ipv6_bypass_tcp: "f6bt".to_owned(),
                ipv6_bypass_udp: "f6bu".to_owned(),
                ipv6_recapture: "f6rec".to_owned(),
                ipv6_unexpected_output: "f6uout".to_owned(),
            },
            probe_holder_ready_path: directory.join("probe-holder"),
            relay_ready_path: directory.join("relay-ready"),
            relay_report_path: directory.join("relay-report"),
            relay_stop_path: directory.join("relay-stop"),
            peer_server_stop_path: directory.join("peer-server-stop"),
            probe_stop_path: directory.join("probe-stop"),
        };
        assert_eq!(
            echo_specs(&config.base)
                .into_iter()
                .map(|spec| spec.id)
                .collect::<Vec<_>>(),
            [
                "ipv4-tcp".to_owned(),
                "ipv4-udp".to_owned(),
                "ipv6-tcp".to_owned(),
                "ipv6-udp".to_owned(),
            ]
        );
        for (ipv6, plan) in [
            (false, rule_plan(&config, false)),
            (true, rule_plan(&config, true)),
        ] {
            plan.validate_capture_boundary()
                .expect("real ingress rule plan preserves its capture boundary");
            assert!(
                plan.ingress_rules
                    .iter()
                    .flatten()
                    .any(|argument| argument == "TPROXY")
            );
            assert!(
                !plan
                    .output_rules
                    .iter()
                    .flatten()
                    .any(|argument| argument == "TPROXY")
            );
            assert_eq!(plan.prerouting_hooks.len(), 2);
            assert_eq!(plan.output_hooks.len(), 2);
            let (
                program,
                probe_source,
                peer_destination,
                relay_source,
                on_ip,
                capture_tcp_comment,
                capture_udp_comment,
                bypass_tcp_comment,
                bypass_udp_comment,
            ) = if ipv6 {
                (
                    "ip6tables",
                    "2001:db8:2::2/128".to_owned(),
                    "2001:db8:1::2/128".to_owned(),
                    "2001:db8:1::1/128".to_owned(),
                    "::",
                    "f6ct",
                    "f6cu",
                    "f6bt",
                    "f6bu",
                )
            } else {
                (
                    "iptables",
                    "11.23.43.2/32".to_owned(),
                    "11.23.42.2/32".to_owned(),
                    "11.23.42.1/32".to_owned(),
                    "0.0.0.0",
                    "f4ct",
                    "f4cu",
                    "f4bt",
                    "f4bu",
                )
            };
            assert_eq!(plan.program, program);
            for (protocol, port, capture_comment, bypass_comment) in [
                ("tcp", "41001", capture_tcp_comment, bypass_tcp_comment),
                ("udp", "41002", capture_udp_comment, bypass_udp_comment),
            ] {
                let capture = exact_protocol_rule(&plan.ingress_rules, "TPROXY", protocol);
                assert_eq!(rule_value_after(capture, &["--dport"]), Some(port));
                assert_eq!(
                    rule_value_after(capture, &["--comment"]),
                    Some(capture_comment)
                );
                assert_eq!(rule_value_after(capture, &["--on-ip"]), Some(on_ip));
                assert_eq!(rule_value_after(capture, &["--on-port"]), Some("41090"));
                assert_eq!(
                    rule_value_after(capture, &["--tproxy-mark"]),
                    Some("0x1/0xf")
                );

                let prerouting = exact_protocol_rule(
                    &plan.prerouting_hooks,
                    plan.ingress_chain.as_str(),
                    protocol,
                );
                assert_eq!(
                    rule_value_after(prerouting, &["-I", "--insert"]),
                    Some("PREROUTING")
                );
                assert_eq!(rule_value_after(prerouting, &["-i"]), Some("fxdaemon"));
                assert_eq!(
                    rule_value_after(prerouting, &["-s"]),
                    Some(probe_source.as_str())
                );
                assert_eq!(
                    rule_value_after(prerouting, &["-d"]),
                    Some(peer_destination.as_str())
                );
                assert_eq!(rule_value_after(prerouting, &["--dport"]), Some(port));

                let bypass = exact_protocol_rule(&plan.output_rules, "ACCEPT", protocol);
                assert_eq!(rule_value_after(bypass, &["--dport"]), Some(port));
                assert_eq!(
                    rule_value_after(bypass, &["--mark"]),
                    Some("0x82/0xffffffff")
                );
                assert_eq!(
                    rule_value_after(bypass, &["--comment"]),
                    Some(bypass_comment)
                );

                let output =
                    exact_protocol_rule(&plan.output_hooks, plan.output_chain.as_str(), protocol);
                assert_eq!(
                    rule_value_after(output, &["-I", "--insert"]),
                    Some("OUTPUT")
                );
                assert_eq!(rule_value_after(output, &["-o"]), Some("fxrelay"));
                assert_eq!(
                    rule_value_after(output, &["-s"]),
                    Some(relay_source.as_str())
                );
                assert_eq!(
                    rule_value_after(output, &["-d"]),
                    Some(peer_destination.as_str())
                );
                assert_eq!(rule_value_after(output, &["--dport"]), Some(port));
            }

            let mutations = capture_mutations(&plan, ipv6);
            let last_output = mutations
                .iter()
                .rposition(|mutation| mutation.stage.ends_with("-output-hook"))
                .expect("output hook mutation");
            let first_prerouting = mutations
                .iter()
                .position(|mutation| mutation.stage.ends_with("-prerouting-hook"))
                .expect("PREROUTING hook mutation");
            assert!(last_output < first_prerouting);
            assert!(
                mutations[first_prerouting..]
                    .iter()
                    .all(|mutation| mutation.stage.ends_with("-prerouting-hook"))
            );
        }

        let mut plan = rule_plan(&config, false);
        let target = plan.output_hooks[0]
            .iter()
            .position(|argument| argument == "-j")
            .expect("OUTPUT hook jump")
            + 1;
        plan.output_hooks[0][target] = plan.ingress_chain.clone();
        let error = plan
            .validate_capture_boundary()
            .expect_err("OUTPUT must not jump to the ingress TPROXY chain");
        assert!(error.contains("OUTPUT hook targets FX4TESTI, expected FX4TESTO"));
    }

    #[test]
    fn tcp_activity_cannot_mask_missing_udp_counters() {
        let tcp_only = FamilyCounterSnapshot {
            capture_tcp: 1,
            capture_udp: 0,
            bypass_tcp: 1,
            bypass_udp: 0,
            recapture_attempt: 0,
            unexpected_ingress: 0,
            unexpected_output: 0,
        };
        let error = validate_counter_bounds(CounterSnapshot {
            ipv4: tcp_only,
            ipv6: tcp_only,
        })
        .expect_err("TCP-only counters must not qualify the UDP checkpoint");
        assert!(error.contains("TCP/UDP echo checkpoint bounds"));
    }
}
