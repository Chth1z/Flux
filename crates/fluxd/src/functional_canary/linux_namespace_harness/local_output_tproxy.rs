//! Disposable local-OUTPUT-to-loopback TPROXY checkpoint.
//!
//! This ignored Linux test proves one conventional mechanism only: exact local OUTPUT selectors
//! set a masked mark, the RPDB selects a test-owned local route through loopback, and loopback
//! PREROUTING applies TPROXY to exact transparent TCP and UDP listeners without rewriting the
//! original destination. It is test evidence, not production composition, Android qualification,
//! or Capture Program activation authority.

use super::transparent_tcp::{
    TransparentTcpListener, connect_marked as connect_marked_tcp,
    set_socket_mark as set_tcp_socket_mark, socket_mark as tcp_socket_mark,
};
use super::transparent_udp::{
    TransparentUdpListener, connect_marked as connect_marked_udp,
    connect_transparent_marked as connect_transparent_marked_udp, socket_mark as udp_socket_mark,
};
use super::*;

use serde_json::Value;
use std::sync::mpsc::{self, Receiver, Sender};

const TEST_NAME: &str = "functional_canary::linux_namespace_harness::privileged_local_output_tproxy_checkpoint_exercises_loopback_reinjection_and_cleanup";
const MODE_PREFLIGHT: &str = "local-output-tproxy-preflight";
const MODE_ISOLATED: &str = "local-output-tproxy-isolated";

const PROXY_MASK: u32 = 0x0000_000f;
const PROXY_MARK: u32 = 0x0000_0001;
const BYPASS_MARK: u32 = 0x0000_0082;
const ROUTE_PROTOCOL: u32 = 99;
const TCP_PORT: u16 = 41_201;
const UDP_PORT: u16 = 41_202;
const TPROXY_PORT: u16 = 41_290;
const NEGATIVE_PORT: u16 = 41_299;
const TCP_COUNTER_MAXIMUM: u64 = 64;
const NEGATIVE_TIMEOUT: Duration = Duration::from_millis(250);

pub(super) fn run() {
    let result = match env::var(MODE_ENV).as_deref() {
        Err(env::VarError::NotPresent) => run_outer(),
        Ok(MODE_PREFLIGHT) => run_preflight(),
        Ok(MODE_ISOLATED) => run_isolated(),
        Ok(other) => Err(format!("unsupported {MODE_ENV} value {other:?}")),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{MODE_ENV} must contain valid UTF-8")),
    };
    if let Err(error) = result {
        panic!("Linux local-OUTPUT TPROXY checkpoint failed: {error}");
    }
}

fn run_outer() -> Result<(), String> {
    let required = required_mode()?;
    for (program, arguments) in [
        ("unshare", &["--version"][..]),
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
                format!("required local-OUTPUT TPROXY helper `{program}` is unavailable: {reason}"),
            );
        }
    }

    if let Err(reason) = run_outer_reentry(MODE_PREFLIGHT, COMMAND_TIMEOUT) {
        return skip_or_fail(
            required,
            format!("disposable local-OUTPUT TPROXY preflight is unavailable: {reason}"),
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
        "disposable conventional local-OUTPUT TPROXY capability preflight only; no production or Android qualification",
    )?;
    let modules = ModuleInventory::capture()?;
    command("ip", &["link", "set", "dev", "lo", "up"])?;

    let ipv4_tcp = TransparentTcpListener::bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED), TPROXY_PORT)?;
    let ipv6_tcp = TransparentTcpListener::bind(IpAddr::V6(Ipv6Addr::UNSPECIFIED), TPROXY_PORT)?;
    let ipv4_udp =
        TransparentUdpListener::bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED), TPROXY_PORT, IO_TIMEOUT)?;
    let ipv6_udp =
        TransparentUdpListener::bind(IpAddr::V6(Ipv6Addr::UNSPECIFIED), TPROXY_PORT, IO_TIMEOUT)?;
    if ipv4_tcp.transparent_readback() != 1
        || ipv6_tcp.transparent_readback() != 1
        || ipv6_tcp.ipv6_only_readback() != Some(1)
        || ipv4_udp.transparent_readback() != 1
        || ipv6_udp.transparent_readback() != 1
        || ipv4_udp.receive_original_destination_readback() != 1
        || ipv6_udp.receive_original_destination_readback() != 1
        || ipv6_udp.ipv6_only_readback() != Some(1)
        || ipv4_tcp.set_mark(BYPASS_MARK)? != BYPASS_MARK
        || ipv6_tcp.set_mark(BYPASS_MARK)? != BYPASS_MARK
    {
        return Err("transparent listener preflight readback mismatch".to_owned());
    }

    preflight_marked_tcp(IpAddr::V4(Ipv4Addr::LOCALHOST))?;
    preflight_marked_tcp(IpAddr::V6(Ipv6Addr::LOCALHOST))?;
    preflight_marked_udp(IpAddr::V4(Ipv4Addr::LOCALHOST))?;
    preflight_marked_udp(IpAddr::V6(Ipv6Addr::LOCALHOST))?;

    for (program, output_chain, prerouting_chain, source, destination, on_ip) in [
        (
            "iptables",
            "FXLOP4O",
            "FXLOP4P",
            "192.0.2.1/32",
            "198.51.100.1/32",
            "0.0.0.0",
        ),
        (
            "ip6tables",
            "FXLOP6O",
            "FXLOP6P",
            "2001:db8:1::1/128",
            "2001:db8:2::1/128",
            "::",
        ),
    ] {
        command(program, &["-t", "mangle", "-N", output_chain])?;
        command(program, &["-t", "mangle", "-N", prerouting_chain])?;
        let mark_rule = [
            "-t",
            "mangle",
            "-A",
            output_chain,
            "-s",
            source,
            "-d",
            destination,
            "-p",
            "udp",
            "--dport",
            "9",
            "-j",
            "MARK",
            "--set-xmark",
            "0x1/0xf",
        ];
        command(program, &mark_rule)?;
        let output_hook = [
            "-t",
            "mangle",
            "-I",
            "OUTPUT",
            "1",
            "-s",
            source,
            "-d",
            destination,
            "-p",
            "udp",
            "--dport",
            "9",
            "-j",
            output_chain,
        ];
        let tproxy_rule = [
            "-t",
            "mangle",
            "-A",
            prerouting_chain,
            "-p",
            "tcp",
            "--dport",
            "9",
            "-j",
            "TPROXY",
            "--on-ip",
            on_ip,
            "--on-port",
            "41290",
            "--tproxy-mark",
            "0x1/0xf",
        ];
        command(program, &tproxy_rule)?;
        let prerouting_hook = [
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
            "tcp",
            "--dport",
            "9",
            "-j",
            prerouting_chain,
        ];
        command(program, &prerouting_hook)?;
        command(program, &output_hook)?;

        command(
            program,
            &[
                "-t",
                "mangle",
                "-D",
                "OUTPUT",
                "-s",
                source,
                "-d",
                destination,
                "-p",
                "udp",
                "--dport",
                "9",
                "-j",
                output_chain,
            ],
        )?;
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
                "tcp",
                "--dport",
                "9",
                "-j",
                prerouting_chain,
            ],
        )?;
        let mut delete_mark = mark_rule;
        delete_mark[2] = "-D";
        command(program, &delete_mark)?;
        let mut delete_tproxy = tproxy_rule;
        delete_tproxy[2] = "-D";
        command(program, &delete_tproxy)?;
        command(program, &["-t", "mangle", "-X", output_chain])?;
        command(program, &["-t", "mangle", "-X", prerouting_chain])?;
    }

    preflight_rpdb(false, 29_991, 14_991, "198.51.100.1")?;
    preflight_rpdb(true, 29_992, 14_992, "2001:db8:2::1")?;

    command(
        "ip",
        &[
            "link",
            "add",
            "fxloppre0",
            "type",
            "veth",
            "peer",
            "name",
            "fxloppre1",
        ],
    )?;
    command("ip", &["link", "delete", "dev", "fxloppre0"])?;
    modules.verify()
}

fn preflight_rpdb(ipv6: bool, table: u32, priority: u32, destination: &str) -> Result<(), String> {
    let mut route = Vec::new();
    if ipv6 {
        route.push("-6".to_owned());
    }
    route.extend([
        "route".to_owned(),
        "add".to_owned(),
        "table".to_owned(),
        table.to_string(),
        "local".to_owned(),
        if ipv6 {
            "::/0".to_owned()
        } else {
            "0.0.0.0/0".to_owned()
        },
        "dev".to_owned(),
        "lo".to_owned(),
        "scope".to_owned(),
        "host".to_owned(),
        "proto".to_owned(),
        ROUTE_PROTOCOL.to_string(),
    ]);
    command_owned("ip", &route)?;
    let route_operation = usize::from(ipv6) + 1;
    let mut delete_route = route.clone();
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
    command_owned("ip", &rule)?;
    let observed_route = route_lookup(
        if ipv6 {
            AddressFamily::Ipv6
        } else {
            AddressFamily::Ipv4
        },
        destination,
        if ipv6 { "::1" } else { "127.0.0.1" },
        PROXY_MARK,
    )?;
    if observed_route.get("type").and_then(Value::as_str) != Some("local")
        || observed_route.get("dev").and_then(Value::as_str) != Some("lo")
        || observed_route.get("table").and_then(value_as_u32) != Some(table)
    {
        return Err(format!(
            "preflight RPDB lookup did not select local table {table}: {observed_route:?}"
        ));
    }
    let rule_operation = usize::from(ipv6) + 1;
    rule[rule_operation] = "delete".to_owned();
    command_owned("ip", &rule)?;
    command_owned("ip", &delete_route)
}

fn preflight_marked_tcp(ip: IpAddr) -> Result<(), String> {
    let listener = TcpListener::bind(SocketAddr::new(ip, 0))
        .map_err(|error| format!("bind local-OUTPUT marked TCP preflight listener: {error}"))?;
    let destination = listener
        .local_addr()
        .map_err(|error| format!("read local-OUTPUT marked TCP preflight address: {error}"))?;
    let acceptor = thread::spawn(move || listener.accept().map(|_| ()));
    let (stream, mark) =
        connect_marked_tcp(SocketAddr::new(ip, 0), destination, BYPASS_MARK, IO_TIMEOUT)?;
    if mark != BYPASS_MARK || tcp_socket_mark(&stream)? != BYPASS_MARK {
        return Err("marked TCP preflight SO_MARK readback mismatch".to_owned());
    }
    drop(stream);
    acceptor
        .join()
        .map_err(|_| "marked TCP preflight acceptor panicked".to_owned())?
        .map_err(|error| format!("accept marked TCP preflight: {error}"))
}

fn preflight_marked_udp(ip: IpAddr) -> Result<(), String> {
    let peer = UdpSocket::bind(SocketAddr::new(ip, 0))
        .map_err(|error| format!("bind local-OUTPUT marked UDP preflight peer: {error}"))?;
    peer.set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set local-OUTPUT marked UDP preflight timeout: {error}"))?;
    let destination = peer
        .local_addr()
        .map_err(|error| format!("read local-OUTPUT marked UDP preflight address: {error}"))?;
    let (socket, mark) =
        connect_marked_udp(SocketAddr::new(ip, 0), destination, BYPASS_MARK, IO_TIMEOUT)?;
    if mark != BYPASS_MARK || udp_socket_mark(&socket)? != BYPASS_MARK {
        return Err("marked UDP preflight SO_MARK readback mismatch".to_owned());
    }
    socket
        .send(b"flux-local-output-preflight")
        .map_err(|error| format!("send marked UDP preflight: {error}"))?;
    let mut buffer = [0_u8; 64];
    let received = peer
        .recv(&mut buffer)
        .map_err(|error| format!("receive marked UDP preflight: {error}"))?;
    if &buffer[..received] != b"flux-local-output-preflight" {
        return Err("marked UDP preflight payload mismatch".to_owned());
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ModuleInventory {
    module_presence: BTreeMap<String, bool>,
    registrations: BTreeMap<PathBuf, Option<Vec<u8>>>,
}

impl ModuleInventory {
    fn capture() -> Result<Self, String> {
        let ipv4 = String::from_utf8(command_output("iptables", &["--version"])?)
            .map_err(|error| format!("iptables version is not UTF-8: {error}"))?;
        let ipv6 = String::from_utf8(command_output("ip6tables", &["--version"])?)
            .map_err(|error| format!("ip6tables version is not UTF-8: {error}"))?;
        let nft_frontend = ipv4.contains("(nf_tables)") && ipv6.contains("(nf_tables)");
        let legacy_frontend = !ipv4.contains("(nf_tables)") && !ipv6.contains("(nf_tables)");
        if !nft_frontend && !legacy_frontend {
            return Err(format!(
                "iptables frontends are incoherent: ipv4={:?} ipv6={:?}",
                ipv4.trim(),
                ipv6.trim()
            ));
        }
        let mut names = vec![
            "veth",
            "xt_TPROXY",
            "nf_tproxy_ipv4",
            "nf_tproxy_ipv6",
            "xt_mark",
            "xt_comment",
            "xt_tcpudp",
            "x_tables",
        ];
        if nft_frontend {
            names.extend(["nf_tables", "nft_compat", "nft_tproxy", "nft_counter"]);
        } else {
            names.extend([
                "ip_tables",
                "ip6_tables",
                "iptable_mangle",
                "ip6table_mangle",
            ]);
        }
        let module_presence = names
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    PathBuf::from("/sys/module").join(name).is_dir(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let registrations = [
            "/proc/net/ip_tables_targets",
            "/proc/net/ip6_tables_targets",
            "/proc/net/ip_tables_matches",
            "/proc/net/ip6_tables_matches",
            "/proc/net/ip_tables_names",
            "/proc/net/ip6_tables_names",
        ]
        .into_iter()
        .map(|path| {
            let path = PathBuf::from(path);
            let contents = match fs::read(&path) {
                Ok(contents) => Some(contents),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    None
                }
                Err(error) => {
                    return Err(format!(
                        "read xtables registration inventory {}: {error}",
                        path.display()
                    ));
                }
            };
            Ok((path, contents))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
        let inventory = Self {
            module_presence,
            registrations,
        };
        inventory.require_support(nft_frontend)?;
        Ok(inventory)
    }

    fn verify(&self) -> Result<(), String> {
        for (module, expected) in &self.module_presence {
            let observed = PathBuf::from("/sys/module").join(module).is_dir();
            if observed != *expected {
                return Err(format!(
                    "kernel-module inventory changed during local-OUTPUT TPROXY checkpoint: {module} expected_present={expected} observed_present={observed}"
                ));
            }
        }
        for (path, expected) in &self.registrations {
            let observed = match fs::read(path) {
                Ok(contents) => Some(contents),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    None
                }
                Err(error) => {
                    return Err(format!(
                        "reread xtables registration inventory {}: {error}",
                        path.display()
                    ));
                }
            };
            if observed != *expected {
                return Err(format!(
                    "xtables registration inventory changed during local-OUTPUT TPROXY checkpoint: {}",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    fn require_support(&self, nft_frontend: bool) -> Result<(), String> {
        self.require_component("veth link type", &[&["veth"]], &[])?;
        if nft_frontend {
            self.require_component(
                "nftables selector and counter expressions",
                &[&["nf_tables", "nft_compat", "nft_counter"]],
                &[],
            )?;
        }
        self.require_component(
            "IPv4 mangle table",
            if nft_frontend {
                &[&["nf_tables", "nft_compat"]]
            } else {
                &[&["ip_tables", "iptable_mangle"]]
            },
            &[("/proc/net/ip_tables_names", "mangle")],
        )?;
        self.require_component(
            "IPv6 mangle table",
            if nft_frontend {
                &[&["nf_tables", "nft_compat"]]
            } else {
                &[&["ip6_tables", "ip6table_mangle"]]
            },
            &[("/proc/net/ip6_tables_names", "mangle")],
        )?;
        self.require_component(
            "IPv4 TPROXY target",
            if nft_frontend {
                &[&["nf_tables", "nft_compat", "nft_tproxy", "nf_tproxy_ipv4"]]
            } else {
                &[&["xt_TPROXY", "nf_tproxy_ipv4"]]
            },
            &[("/proc/net/ip_tables_targets", "TPROXY")],
        )?;
        self.require_component(
            "IPv6 TPROXY target",
            if nft_frontend {
                &[&["nf_tables", "nft_compat", "nft_tproxy", "nf_tproxy_ipv6"]]
            } else {
                &[&["xt_TPROXY", "nf_tproxy_ipv6"]]
            },
            &[("/proc/net/ip6_tables_targets", "TPROXY")],
        )?;
        self.require_component(
            "IPv4 MARK target",
            if nft_frontend {
                &[&["nf_tables", "nft_compat"], &["xt_mark"]]
            } else {
                &[&["xt_mark"]]
            },
            &[("/proc/net/ip_tables_targets", "MARK")],
        )?;
        self.require_component(
            "IPv6 MARK target",
            if nft_frontend {
                &[&["nf_tables", "nft_compat"], &["xt_mark"]]
            } else {
                &[&["xt_mark"]]
            },
            &[("/proc/net/ip6_tables_targets", "MARK")],
        )?;
        self.require_component(
            "IPv4 comment match",
            if nft_frontend {
                &[&["nf_tables", "nft_compat"], &["xt_comment"]]
            } else {
                &[&["xt_comment"]]
            },
            &[("/proc/net/ip_tables_matches", "comment")],
        )?;
        self.require_component(
            "IPv6 comment match",
            if nft_frontend {
                &[&["nf_tables", "nft_compat"], &["xt_comment"]]
            } else {
                &[&["xt_comment"]]
            },
            &[("/proc/net/ip6_tables_matches", "comment")],
        )?;
        for (family, path) in [
            ("IPv4", "/proc/net/ip_tables_matches"),
            ("IPv6", "/proc/net/ip6_tables_matches"),
        ] {
            self.require_component(
                &format!("{family} TCP match"),
                if nft_frontend {
                    &[&["nf_tables", "nft_compat"]]
                } else {
                    &[&["xt_tcpudp"]]
                },
                &[(path, "tcp")],
            )?;
            self.require_component(
                &format!("{family} UDP match"),
                if nft_frontend {
                    &[&["nf_tables", "nft_compat"]]
                } else {
                    &[&["xt_tcpudp"]]
                },
                &[(path, "udp")],
            )?;
        }
        Ok(())
    }

    fn require_component(
        &self,
        label: &str,
        module_sets: &[&[&str]],
        registrations: &[(&str, &str)],
    ) -> Result<(), String> {
        let module_proof = module_sets.iter().any(|set| {
            set.iter()
                .all(|module| self.module_presence.get(*module).copied().unwrap_or(false))
        });
        let registration_proof = registrations.iter().any(|(path, token)| {
            self.registrations
                .get(Path::new(path))
                .and_then(Option::as_deref)
                .is_some_and(|contents| registration_has_token(contents, token))
        });
        if module_proof || registration_proof {
            Ok(())
        } else {
            Err(format!(
                "local-OUTPUT TPROXY checkpoint refuses mutation because {label} is neither already active in /sys/module nor already registered in procfs; implicit module autoload is forbidden"
            ))
        }
    }
}

fn registration_has_token(contents: &[u8], token: &str) -> bool {
    String::from_utf8_lossy(contents)
        .lines()
        .any(|line| line.trim() == token)
}

#[derive(Debug, Clone)]
struct LocalOutputConfig {
    nonce: String,
    egress_interface: String,
    sink_interface: String,
    ipv4_source: Ipv4Addr,
    ipv6_source: Ipv6Addr,
    ipv4_destination: Ipv4Addr,
    ipv6_destination: Ipv6Addr,
    ipv4_rule_priority: u32,
    ipv6_rule_priority: u32,
    ipv4_route_table: u32,
    ipv6_route_table: u32,
    chains: ChainNames,
    comments: CounterComments,
}

impl LocalOutputConfig {
    fn new(nonce: String) -> Result<Self, String> {
        let suffix = nonce[..8].to_owned();
        let seed = u32::from_str_radix(&nonce[..4], 16)
            .map_err(|error| format!("parse local-OUTPUT nonce seed: {error}"))?;
        let ipv4_route_table = 28_000 + seed % 1_000;
        let ipv6_route_table = ipv4_route_table + 1_000;
        let ipv4_rule_priority = 14_000 + seed % 500;
        let ipv6_rule_priority = ipv4_rule_priority + 500;
        Ok(Self {
            nonce,
            egress_interface: format!("fl{suffix}e"),
            sink_interface: format!("fl{suffix}s"),
            ipv4_source: Ipv4Addr::new(192, 0, 2, 1),
            ipv6_source: "2001:db8:100::1"
                .parse()
                .map_err(|error| format!("parse local-OUTPUT source IPv6: {error}"))?,
            ipv4_destination: Ipv4Addr::new(198, 51, 100, 10),
            ipv6_destination: "2001:db8:ffff::10"
                .parse()
                .map_err(|error| format!("parse local-OUTPUT destination IPv6: {error}"))?,
            ipv4_rule_priority,
            ipv6_rule_priority,
            ipv4_route_table,
            ipv6_route_table,
            chains: ChainNames {
                ipv4_output: format!("FL4{suffix}O"),
                ipv4_prerouting: format!("FL4{suffix}P"),
                ipv6_output: format!("FL6{suffix}O"),
                ipv6_prerouting: format!("FL6{suffix}P"),
            },
            comments: CounterComments::new(&suffix),
        })
    }

    const fn source(&self, family: AddressFamily) -> IpAddr {
        match family {
            AddressFamily::Ipv4 => IpAddr::V4(self.ipv4_source),
            AddressFamily::Ipv6 => IpAddr::V6(self.ipv6_source),
        }
    }

    const fn destination(&self, family: AddressFamily) -> IpAddr {
        match family {
            AddressFamily::Ipv4 => IpAddr::V4(self.ipv4_destination),
            AddressFamily::Ipv6 => IpAddr::V6(self.ipv6_destination),
        }
    }
}

#[derive(Debug, Clone)]
struct ChainNames {
    ipv4_output: String,
    ipv4_prerouting: String,
    ipv6_output: String,
    ipv6_prerouting: String,
}

#[derive(Debug, Clone)]
struct CounterComments {
    ipv4: FamilyComments,
    ipv6: FamilyComments,
}

impl CounterComments {
    fn new(suffix: &str) -> Self {
        Self {
            ipv4: FamilyComments::new("4", suffix),
            ipv6: FamilyComments::new("6", suffix),
        }
    }

    fn family(&self, family: AddressFamily) -> &FamilyComments {
        match family {
            AddressFamily::Ipv4 => &self.ipv4,
            AddressFamily::Ipv6 => &self.ipv6,
        }
    }
}

#[derive(Debug, Clone)]
struct FamilyComments {
    mark_tcp: String,
    mark_udp: String,
    output_tcp: String,
    output_udp: String,
    tproxy_tcp: String,
    tproxy_udp: String,
    bypass_tcp: String,
    bypass_udp: String,
    leak_tcp: String,
    leak_udp: String,
    negative: String,
    forward_bypass: String,
    unexpected_output: String,
    unexpected_prerouting: String,
}

impl FamilyComments {
    fn new(family: &str, suffix: &str) -> Self {
        let prefix = format!("lo{family}{suffix}");
        Self {
            mark_tcp: format!("{prefix}mt"),
            mark_udp: format!("{prefix}mu"),
            output_tcp: format!("{prefix}ot"),
            output_udp: format!("{prefix}ou"),
            tproxy_tcp: format!("{prefix}tt"),
            tproxy_udp: format!("{prefix}tu"),
            bypass_tcp: format!("{prefix}bt"),
            bypass_udp: format!("{prefix}bu"),
            leak_tcp: format!("{prefix}lt"),
            leak_udp: format!("{prefix}lu"),
            negative: format!("{prefix}neg"),
            forward_bypass: format!("{prefix}fb"),
            unexpected_output: format!("{prefix}xo"),
            unexpected_prerouting: format!("{prefix}xp"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedMutation {
    stage: String,
    program: String,
    action: Vec<String>,
    inverse: Vec<String>,
    activation: bool,
}

#[derive(Debug)]
struct Baselines {
    ipv4_mangle: Vec<u8>,
    ipv6_mangle: Vec<u8>,
    ipv4_rules: Vec<u8>,
    ipv6_rules: Vec<u8>,
    ipv4_private_table: Vec<u8>,
    ipv6_private_table: Vec<u8>,
    links: Vec<u8>,
    addresses: Vec<u8>,
    ipv4_routes: Vec<u8>,
    ipv6_routes: Vec<u8>,
}

impl Baselines {
    fn capture(config: &LocalOutputConfig) -> Result<Self, String> {
        let baseline = Self {
            ipv4_mangle: mangle_dump("iptables-save")?,
            ipv6_mangle: mangle_dump("ip6tables-save")?,
            ipv4_rules: command_output("ip", &["-j", "rule", "show"])?,
            ipv6_rules: command_output("ip", &["-6", "-j", "rule", "show"])?,
            ipv4_private_table: route_table_dump(false, config.ipv4_route_table)?,
            ipv6_private_table: route_table_dump(true, config.ipv6_route_table)?,
            links: command_output("ip", &["-j", "link", "show"])?,
            addresses: command_output("ip", &["-j", "address", "show"])?,
            ipv4_routes: command_output("ip", &["-j", "route", "show", "table", "all"])?,
            ipv6_routes: command_output("ip", &["-6", "-j", "route", "show", "table", "all"])?,
        };
        require_names_absent(&baseline, config)?;
        Ok(baseline)
    }
}

struct LocalOutputResources {
    journal: Journal,
    config: LocalOutputConfig,
    modules: ModuleInventory,
    baselines: Baselines,
    pending: Vec<PlannedMutation>,
    listeners: Option<ListenerWorkers>,
}

fn run_isolated() -> Result<(), String> {
    ensure_isolated_authority_with_boundary(
        "conventional local OUTPUT mark, RPDB local route, loopback PREROUTING TPROXY, and exact cleanup evidence only; no Android or production qualification",
    )?;
    let modules = ModuleInventory::capture()?;
    let directory = tempfile::tempdir()
        .map_err(|error| format!("create local-OUTPUT TPROXY harness directory: {error}"))?;
    let config = LocalOutputConfig::new(random_nonce()?)?;
    let journal_path = directory.path().join("mutations.jsonl");
    let journal = Journal::create(journal_path, config.nonce.clone())?;
    let baselines = Baselines::capture(&config)?;
    modules.verify()?;
    let mut resources = LocalOutputResources {
        journal,
        config,
        modules,
        baselines,
        pending: Vec::new(),
        listeners: None,
    };

    let execution = panic::catch_unwind(AssertUnwindSafe(|| execute_isolated(&mut resources)))
        .unwrap_or_else(|payload| {
            Err(format!(
                "local-OUTPUT TPROXY isolated execution panicked: {}",
                panic_message(payload)
            ))
        });
    let cleanup = cleanup_isolated(&mut resources);
    match (execution, cleanup) {
        (Ok(()), Ok(())) => validate_journal(&resources),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(format!("cleanup failed: {cleanup_error}")),
        (Err(error), Err(cleanup_error)) => {
            Err(format!("{error}; cleanup also failed: {cleanup_error}"))
        }
    }
}

fn require_names_absent(baseline: &Baselines, config: &LocalOutputConfig) -> Result<(), String> {
    for (label, dump, chains) in [
        (
            "IPv4 mangle",
            baseline.ipv4_mangle.as_slice(),
            [
                config.chains.ipv4_output.as_str(),
                config.chains.ipv4_prerouting.as_str(),
            ],
        ),
        (
            "IPv6 mangle",
            baseline.ipv6_mangle.as_slice(),
            [
                config.chains.ipv6_output.as_str(),
                config.chains.ipv6_prerouting.as_str(),
            ],
        ),
    ] {
        let text = std::str::from_utf8(dump)
            .map_err(|error| format!("decode {label} baseline as UTF-8: {error}"))?;
        require_clean_mangle_baseline(label, text)?;
        for chain in chains {
            if text.lines().any(|line| {
                line.starts_with(&format!(":{chain} ")) || line.starts_with(&format!("-A {chain} "))
            }) {
                return Err(format!("nonce-derived chain {chain} already exists"));
            }
        }
    }
    for (label, dump, priority, table) in [
        (
            "IPv4 RPDB",
            baseline.ipv4_rules.as_slice(),
            config.ipv4_rule_priority,
            config.ipv4_route_table,
        ),
        (
            "IPv6 RPDB",
            baseline.ipv6_rules.as_slice(),
            config.ipv6_rule_priority,
            config.ipv6_route_table,
        ),
    ] {
        let rules = json_array(dump, label)?;
        for rule in &rules {
            if let Some((value, mask)) = rpdb_fwmark_selector(rule)?
                && mask & PROXY_MASK != 0
            {
                return Err(format!(
                    "foreign {label} fwmark selector overlaps the local-OUTPUT test mask: value={value:#x} mask={mask:#x} rule={rule}"
                ));
            }
        }
        if rules.iter().any(|rule| {
            rule.get("priority")
                .and_then(value_as_u32)
                .is_some_and(|value| value == priority)
                || rule
                    .get("table")
                    .and_then(value_as_u32)
                    .is_some_and(|value| value == table)
        }) {
            return Err(format!(
                "nonce-derived local-OUTPUT priority {priority} or table {table} is already referenced in {label}"
            ));
        }
    }
    for (label, dump) in [
        ("IPv4 private route table", &baseline.ipv4_private_table),
        ("IPv6 private route table", &baseline.ipv6_private_table),
    ] {
        if !json_array(dump, label)?.is_empty() {
            return Err(format!("nonce-derived {label} is not empty"));
        }
    }
    let links = json_array(&baseline.links, "link baseline")?;
    for interface in [&config.egress_interface, &config.sink_interface] {
        if links.iter().any(|link| {
            link.get("ifname")
                .and_then(Value::as_str)
                .is_some_and(|name| name == interface)
        }) {
            return Err(format!(
                "nonce-derived local-OUTPUT interface {interface} already exists"
            ));
        }
    }
    Ok(())
}

fn require_clean_mangle_baseline(label: &str, text: &str) -> Result<(), String> {
    const BUILT_INS: [&str; 5] = ["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"];
    for line in text.lines() {
        if let Some(declaration) = line.strip_prefix(':') {
            let fields = declaration.split_whitespace().collect::<Vec<_>>();
            let chain = fields
                .first()
                .copied()
                .ok_or_else(|| format!("{label} has a malformed chain declaration: {line}"))?;
            if !BUILT_INS.contains(&chain) {
                return Err(format!(
                    "{label} contains foreign private chain {chain}; disposable checkpoint refuses meaningful capture state"
                ));
            }
            if fields.get(1).copied() != Some("ACCEPT") {
                return Err(format!(
                    "{label} built-in chain {chain} has a non-ACCEPT policy: {line}"
                ));
            }
        } else if line.starts_with("-A ") {
            return Err(format!(
                "{label} contains a foreign active rule; disposable checkpoint requires empty built-in chains: {line}"
            ));
        }
    }
    Ok(())
}

fn rpdb_fwmark_selector(rule: &Value) -> Result<Option<(u32, u32)>, String> {
    let Some(mark) = rule.get("fwmark") else {
        return Ok(None);
    };
    if let Some(encoded) = mark.as_str()
        && let Some((value, mask)) = encoded.split_once('/')
    {
        return Ok(Some((
            parse_u32_token(value).ok_or_else(|| {
                format!("RPDB fwmark value is not a bounded integer: {encoded:?}")
            })?,
            parse_u32_token(mask)
                .ok_or_else(|| format!("RPDB fwmark mask is not a bounded integer: {encoded:?}"))?,
        )));
    }
    let value = value_as_u32(mark)
        .or_else(|| mark.as_str().and_then(parse_u32_token))
        .ok_or_else(|| format!("RPDB fwmark is not a bounded integer: {mark}"))?;
    let mask = match rule.get("fwmask") {
        Some(mask) => value_as_u32(mask)
            .or_else(|| mask.as_str().and_then(parse_u32_token))
            .ok_or_else(|| format!("RPDB fwmask is not a bounded integer: {mask}"))?,
        None => u32::MAX,
    };
    Ok(Some((value, mask)))
}

fn parse_u32_token(token: &str) -> Option<u32> {
    token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
        .and_then(|token| u32::from_str_radix(token, 16).ok())
        .or_else(|| token.parse().ok())
}

fn execute_isolated(resources: &mut LocalOutputResources) -> Result<(), String> {
    let network = network_mutations(&resources.config);
    install_mutations(resources, &network)?;
    let listeners = PreparedListeners::bind(&resources.config)?;
    let rpdb = rpdb_mutations(&resources.config);
    install_mutations(resources, &rpdb)?;

    let mut plans = Vec::new();
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        let plan = rule_plan(&resources.config, family);
        plan.validate()?;
        let (prepared, activation) = capture_mutations(&plan, family);
        install_mutations(resources, &prepared)?;
        validate_prepared_plan(&plan)?;
        plans.push((plan, activation));
    }
    resources.listeners = Some(listeners.spawn(&resources.config));
    for (plan, activation) in &plans {
        install_mutations(resources, activation)?;
        validate_active_plan(plan)?;
    }

    let before = read_counters(&resources.config)?;
    if before != CounterSnapshot::default() {
        return Err(format!(
            "local-OUTPUT TPROXY counters were nonzero before traffic: {before:?}"
        ));
    }
    validate_route_controls(&resources.config)?;
    resources.modules.verify()?;

    resources
        .listeners
        .as_mut()
        .ok_or_else(|| "transparent listener workers were not retained".to_owned())?
        .start()?;
    let client_result = run_positive_clients(&resources.config);
    let listener_result = resources
        .listeners
        .as_mut()
        .ok_or_else(|| "transparent listener workers were not retained".to_owned())?
        .receive_observations();
    let (clients, listeners) = match (client_result, listener_result) {
        (Ok(clients), Ok(listeners)) => (clients, listeners),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => return Err(error),
        (Err(client_error), Err(listener_error)) => {
            return Err(format!(
                "{client_error}; transparent listeners also failed: {listener_error}"
            ));
        }
    };
    validate_flow_observations(&resources.config, &clients, &listeners)?;

    let after_positive = read_counters(&resources.config)?;
    validate_positive_counters(after_positive)?;
    run_negative_controls(&resources.config)?;
    let after_negative = read_counters(&resources.config)?;
    validate_negative_control(after_positive, after_negative)?;
    resources.modules.verify()
}

fn network_mutations(config: &LocalOutputConfig) -> Vec<PlannedMutation> {
    vec![
        mutation(
            "before-loopback-up",
            "ip",
            strings(&["link", "set", "dev", "lo", "up"]),
            strings(&["link", "set", "dev", "lo", "down"]),
        ),
        mutation(
            "before-egress-veth-create",
            "ip",
            strings(&[
                "link",
                "add",
                &config.egress_interface,
                "type",
                "veth",
                "peer",
                "name",
                &config.sink_interface,
            ]),
            strings(&["link", "delete", "dev", &config.egress_interface]),
        ),
        mutation(
            "before-egress-link-up",
            "ip",
            strings(&["link", "set", "dev", &config.egress_interface, "up"]),
            strings(&["link", "set", "dev", &config.egress_interface, "down"]),
        ),
        mutation(
            "before-egress-ipv4-address",
            "ip",
            strings(&[
                "address",
                "add",
                &format!("{}/32", config.ipv4_source),
                "dev",
                &config.egress_interface,
            ]),
            strings(&[
                "address",
                "delete",
                &format!("{}/32", config.ipv4_source),
                "dev",
                &config.egress_interface,
            ]),
        ),
        mutation(
            "before-egress-ipv6-address",
            "ip",
            strings(&[
                "-6",
                "address",
                "add",
                &format!("{}/128", config.ipv6_source),
                "dev",
                &config.egress_interface,
                "nodad",
            ]),
            strings(&[
                "-6",
                "address",
                "delete",
                &format!("{}/128", config.ipv6_source),
                "dev",
                &config.egress_interface,
            ]),
        ),
        mutation(
            "before-egress-ipv4-route",
            "ip",
            strings(&[
                "route",
                "add",
                &format!("{}/32", config.ipv4_destination),
                "dev",
                &config.egress_interface,
                "scope",
                "link",
                "src",
                &config.ipv4_source.to_string(),
                "proto",
                &ROUTE_PROTOCOL.to_string(),
            ]),
            strings(&[
                "route",
                "delete",
                &format!("{}/32", config.ipv4_destination),
                "dev",
                &config.egress_interface,
                "scope",
                "link",
                "src",
                &config.ipv4_source.to_string(),
                "proto",
                &ROUTE_PROTOCOL.to_string(),
            ]),
        ),
        mutation(
            "before-egress-ipv6-route",
            "ip",
            strings(&[
                "-6",
                "route",
                "add",
                &format!("{}/128", config.ipv6_destination),
                "dev",
                &config.egress_interface,
                "src",
                &config.ipv6_source.to_string(),
                "proto",
                &ROUTE_PROTOCOL.to_string(),
            ]),
            strings(&[
                "-6",
                "route",
                "delete",
                &format!("{}/128", config.ipv6_destination),
                "dev",
                &config.egress_interface,
                "src",
                &config.ipv6_source.to_string(),
                "proto",
                &ROUTE_PROTOCOL.to_string(),
            ]),
        ),
    ]
}

fn rpdb_mutations(config: &LocalOutputConfig) -> Vec<PlannedMutation> {
    let mut mutations = Vec::new();
    for (family, table, priority) in [
        (
            AddressFamily::Ipv4,
            config.ipv4_route_table,
            config.ipv4_rule_priority,
        ),
        (
            AddressFamily::Ipv6,
            config.ipv6_route_table,
            config.ipv6_rule_priority,
        ),
    ] {
        let family_label = family.label();
        let mut route = Vec::new();
        if family == AddressFamily::Ipv6 {
            route.push("-6".to_owned());
        }
        route.extend([
            "route".to_owned(),
            "add".to_owned(),
            "table".to_owned(),
            table.to_string(),
            "local".to_owned(),
            if family == AddressFamily::Ipv6 {
                "::/0".to_owned()
            } else {
                "0.0.0.0/0".to_owned()
            },
            "dev".to_owned(),
            "lo".to_owned(),
            "scope".to_owned(),
            "host".to_owned(),
            "proto".to_owned(),
            ROUTE_PROTOCOL.to_string(),
        ]);
        let mut delete_route = route.clone();
        delete_route[usize::from(family == AddressFamily::Ipv6) + 1] = "delete".to_owned();

        let mut rule = Vec::new();
        if family == AddressFamily::Ipv6 {
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
        delete_rule[usize::from(family == AddressFamily::Ipv6) + 1] = "delete".to_owned();
        mutations.push(mutation(
            &format!("before-{family_label}-rpdb-route"),
            "ip",
            route,
            delete_route,
        ));
        mutations.push(mutation(
            &format!("before-{family_label}-rpdb-rule"),
            "ip",
            rule,
            delete_rule,
        ));
    }
    mutations
}

fn mutation(
    stage: &str,
    program: &str,
    action: Vec<String>,
    inverse: Vec<String>,
) -> PlannedMutation {
    PlannedMutation {
        stage: stage.to_owned(),
        program: program.to_owned(),
        action,
        inverse,
        activation: false,
    }
}

#[derive(Debug, Clone)]
struct RulePlan {
    family: AddressFamily,
    program: String,
    output_chain: String,
    prerouting_chain: String,
    output_rules: Vec<Vec<String>>,
    prerouting_rules: Vec<Vec<String>>,
    postrouting_guards: Vec<Vec<String>>,
    prerouting_hooks: Vec<Vec<String>>,
    response_output_hooks: Vec<Vec<String>>,
    activation_hooks: Vec<Vec<String>>,
}

impl RulePlan {
    fn validate(&self) -> Result<(), String> {
        if self.output_chain == self.prerouting_chain {
            return Err(
                "local-OUTPUT rule plan reuses one private chain for both hooks".to_owned(),
            );
        }
        for rule in &self.output_rules {
            validate_private_rule(rule, &self.output_chain, &["MARK", "ACCEPT", "DROP"])?;
            if rule.iter().any(|argument| argument == "TPROXY") {
                return Err(format!("OUTPUT-reachable rule contains TPROXY: {rule:?}"));
            }
        }
        for rule in &self.prerouting_rules {
            validate_private_rule(rule, &self.prerouting_chain, &["TPROXY", "DROP"])?;
        }
        for hook in &self.prerouting_hooks {
            validate_hook(hook, "PREROUTING", &self.prerouting_chain)?;
            if rule_value_after(hook, &["-i"]) != Some("lo") {
                return Err(format!(
                    "local-OUTPUT PREROUTING hook is not loopback-scoped: {hook:?}"
                ));
            }
        }
        for hook in self
            .response_output_hooks
            .iter()
            .chain(&self.activation_hooks)
        {
            validate_hook(hook, "OUTPUT", &self.output_chain)?;
        }
        for guard in &self.postrouting_guards {
            let action = rule_action(guard);
            if rule_value_after(guard, &["-I", "--insert"]) != Some("POSTROUTING")
                || rule_value_after(guard, &["-o"]) == Some("lo")
                || action != Some("DROP")
            {
                return Err(format!("invalid positive/negative egress guard: {guard:?}"));
            }
        }

        let expected = BTreeSet::from([("tcp".to_owned(), TCP_PORT), ("udp".to_owned(), UDP_PORT)]);
        let mark_selectors = selector_set(
            self.output_rules
                .iter()
                .filter(|rule| rule_action(rule) == Some("MARK")),
        )?;
        let tproxy_selectors = selector_set(
            self.prerouting_rules
                .iter()
                .filter(|rule| rule_action(rule) == Some("TPROXY")),
        )?;
        let prerouting_selectors = selector_set(self.prerouting_hooks.iter())?;
        let activation_selectors = selector_set(self.activation_hooks.iter())?;
        if mark_selectors != expected
            || tproxy_selectors != expected
            || prerouting_selectors != expected
            || activation_selectors != expected
        {
            return Err(format!(
                "local-OUTPUT selector coverage differs: expected={expected:?} mark={mark_selectors:?} tproxy={tproxy_selectors:?} prerouting={prerouting_selectors:?} activation={activation_selectors:?}"
            ));
        }
        let terminal_drop = self
            .output_rules
            .iter()
            .rposition(|rule| rule_action(rule) == Some("DROP"))
            .ok_or_else(|| "local-OUTPUT chain has no terminal unexpected DROP".to_owned())?;
        for (protocol, port) in [("tcp", TCP_PORT), ("udp", UDP_PORT)] {
            let matching = |action: &str| {
                self.output_rules
                    .iter()
                    .enumerate()
                    .filter(|(_, rule)| {
                        rule_action(rule) == Some(action)
                            && rule_value_after(rule, &["-p", "--protocol"]) == Some(protocol)
                            && rule_value_after(rule, &["--dport"])
                                == Some(port.to_string().as_str())
                    })
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>()
            };
            let marks = matching("MARK");
            let accepts = matching("ACCEPT");
            let ([mark], [accept]) = (marks.as_slice(), accepts.as_slice()) else {
                return Err(format!(
                    "{} {protocol}/{port} requires exactly one MARK and one proxy-mark ACCEPT: marks={marks:?} accepts={accepts:?}",
                    self.family.label()
                ));
            };
            if !(mark < accept && *accept < terminal_drop) {
                return Err(format!(
                    "{} {protocol}/{port} MARK is not terminated by ACCEPT before unexpected DROP: mark={mark} accept={accept} drop={terminal_drop}",
                    self.family.label()
                ));
            }
        }
        for hook in &self.activation_hooks {
            if rule_value_after(hook, &["-o"]).is_none()
                || rule_value_after(hook, &["-o"]) == Some("lo")
                || rule_value_after(hook, &["--mark"])
                    != Some(format!("0x0/{PROXY_MASK:#x}").as_str())
            {
                return Err(format!(
                    "{} OUTPUT activation is not an unmarked test-egress selector: {hook:?}",
                    self.family.label()
                ));
            }
        }
        for hook in &self.response_output_hooks {
            if rule_value_after(hook, &["--mark"])
                != Some(format!("{BYPASS_MARK:#x}/0xffffffff").as_str())
            {
                return Err(format!(
                    "{} response hook omits the exact bypass mark: {hook:?}",
                    self.family.label()
                ));
            }
        }
        for rule in self
            .prerouting_rules
            .iter()
            .filter(|rule| rule_action(rule) == Some("TPROXY"))
        {
            if rule_value_after(rule, &["--on-port"]) != Some(&TPROXY_PORT.to_string())
                || rule_value_after(rule, &["--tproxy-mark"])
                    != Some(&format!("{PROXY_MARK:#x}/{PROXY_MASK:#x}"))
            {
                return Err(format!(
                    "TPROXY rule has the wrong listener or mark: {rule:?}"
                ));
            }
        }
        Ok(())
    }
}

fn rule_plan(config: &LocalOutputConfig, family: AddressFamily) -> RulePlan {
    let (program, output_chain, prerouting_chain, source, destination, comments, on_ip) =
        match family {
            AddressFamily::Ipv4 => (
                "iptables",
                &config.chains.ipv4_output,
                &config.chains.ipv4_prerouting,
                format!("{}/32", config.ipv4_source),
                format!("{}/32", config.ipv4_destination),
                &config.comments.ipv4,
                "0.0.0.0",
            ),
            AddressFamily::Ipv6 => (
                "ip6tables",
                &config.chains.ipv6_output,
                &config.chains.ipv6_prerouting,
                format!("{}/128", config.ipv6_source),
                format!("{}/128", config.ipv6_destination),
                &config.comments.ipv6,
                "::",
            ),
        };
    let bypass_rule = |protocol: &str, port: u16, comment: &str| {
        strings(&[
            "-t",
            "mangle",
            "-A",
            output_chain,
            "-s",
            &destination,
            "-d",
            &source,
            "-p",
            protocol,
            "--sport",
            &port.to_string(),
            "-m",
            "mark",
            "--mark",
            &format!("{BYPASS_MARK:#x}/0xffffffff"),
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "ACCEPT",
        ])
    };
    let mark_rule = |protocol: &str, port: u16, comment: &str| {
        strings(&[
            "-t",
            "mangle",
            "-A",
            output_chain,
            "-s",
            &source,
            "-d",
            &destination,
            "-p",
            protocol,
            "--dport",
            &port.to_string(),
            "-m",
            "mark",
            "--mark",
            &format!("0x0/{PROXY_MASK:#x}"),
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "MARK",
            "--set-xmark",
            &format!("{PROXY_MARK:#x}/{PROXY_MASK:#x}"),
        ])
    };
    let output_accept_rule = |protocol: &str, port: u16, comment: &str| {
        strings(&[
            "-t",
            "mangle",
            "-A",
            output_chain,
            "-s",
            &source,
            "-d",
            &destination,
            "-p",
            protocol,
            "--dport",
            &port.to_string(),
            "-m",
            "mark",
            "--mark",
            &format!("{PROXY_MARK:#x}/{PROXY_MASK:#x}"),
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "ACCEPT",
        ])
    };
    let output_rules = vec![
        bypass_rule("tcp", TCP_PORT, &comments.bypass_tcp),
        bypass_rule("udp", UDP_PORT, &comments.bypass_udp),
        mark_rule("tcp", TCP_PORT, &comments.mark_tcp),
        output_accept_rule("tcp", TCP_PORT, &comments.output_tcp),
        mark_rule("udp", UDP_PORT, &comments.mark_udp),
        output_accept_rule("udp", UDP_PORT, &comments.output_udp),
        strings(&[
            "-t",
            "mangle",
            "-A",
            output_chain,
            "-m",
            "comment",
            "--comment",
            &comments.unexpected_output,
            "-j",
            "DROP",
        ]),
    ];

    let tproxy_rule = |protocol: &str, port: u16, comment: &str| {
        strings(&[
            "-t",
            "mangle",
            "-A",
            prerouting_chain,
            "-s",
            &source,
            "-d",
            &destination,
            "-p",
            protocol,
            "--dport",
            &port.to_string(),
            "-m",
            "mark",
            "--mark",
            &format!("{PROXY_MARK:#x}/{PROXY_MASK:#x}"),
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "TPROXY",
            "--on-ip",
            on_ip,
            "--on-port",
            &TPROXY_PORT.to_string(),
            "--tproxy-mark",
            &format!("{PROXY_MARK:#x}/{PROXY_MASK:#x}"),
        ])
    };
    let prerouting_rules = vec![
        tproxy_rule("tcp", TCP_PORT, &comments.tproxy_tcp),
        tproxy_rule("udp", UDP_PORT, &comments.tproxy_udp),
        strings(&[
            "-t",
            "mangle",
            "-A",
            prerouting_chain,
            "-m",
            "comment",
            "--comment",
            &comments.unexpected_prerouting,
            "-j",
            "DROP",
        ]),
    ];

    let egress_guard = |protocol: &str, port: u16, comment: &str| {
        strings(&[
            "-t",
            "mangle",
            "-I",
            "POSTROUTING",
            "1",
            "-o",
            &config.egress_interface,
            "-s",
            &source,
            "-d",
            &destination,
            "-p",
            protocol,
            "--dport",
            &port.to_string(),
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "DROP",
        ])
    };
    let postrouting_guards = vec![
        egress_guard("tcp", TCP_PORT, &comments.leak_tcp),
        egress_guard("udp", UDP_PORT, &comments.leak_udp),
        egress_guard("udp", NEGATIVE_PORT, &comments.negative),
        strings(&[
            "-t",
            "mangle",
            "-I",
            "POSTROUTING",
            "1",
            "-o",
            &config.egress_interface,
            "-s",
            &source,
            "-d",
            &destination,
            "-p",
            "udp",
            "--dport",
            &UDP_PORT.to_string(),
            "-m",
            "mark",
            "--mark",
            &format!("{BYPASS_MARK:#x}/0xffffffff"),
            "-m",
            "comment",
            "--comment",
            &comments.forward_bypass,
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
            "lo",
            "-s",
            &source,
            "-d",
            &destination,
            "-p",
            protocol,
            "--dport",
            &port.to_string(),
            "-j",
            prerouting_chain,
        ])
    };
    let prerouting_hooks = vec![
        prerouting_hook("tcp", TCP_PORT),
        prerouting_hook("udp", UDP_PORT),
    ];

    let response_hook = |protocol: &str, port: u16| {
        strings(&[
            "-t",
            "mangle",
            "-I",
            "OUTPUT",
            "1",
            "-s",
            &destination,
            "-d",
            &source,
            "-p",
            protocol,
            "--sport",
            &port.to_string(),
            "-m",
            "mark",
            "--mark",
            &format!("{BYPASS_MARK:#x}/0xffffffff"),
            "-j",
            output_chain,
        ])
    };
    let activation_hook = |protocol: &str, port: u16| {
        strings(&[
            "-t",
            "mangle",
            "-I",
            "OUTPUT",
            "1",
            "-o",
            &config.egress_interface,
            "-s",
            &source,
            "-d",
            &destination,
            "-p",
            protocol,
            "--dport",
            &port.to_string(),
            "-m",
            "mark",
            "--mark",
            &format!("0x0/{PROXY_MASK:#x}"),
            "-j",
            output_chain,
        ])
    };
    RulePlan {
        family,
        program: program.to_owned(),
        output_chain: output_chain.clone(),
        prerouting_chain: prerouting_chain.clone(),
        output_rules,
        prerouting_rules,
        postrouting_guards,
        prerouting_hooks,
        response_output_hooks: vec![
            response_hook("tcp", TCP_PORT),
            response_hook("udp", UDP_PORT),
        ],
        activation_hooks: vec![
            activation_hook("tcp", TCP_PORT),
            activation_hook("udp", UDP_PORT),
        ],
    }
}

fn capture_mutations(
    plan: &RulePlan,
    family: AddressFamily,
) -> (Vec<PlannedMutation>, Vec<PlannedMutation>) {
    let label = family.label();
    let mut prepared = vec![
        mutation(
            &format!("before-{label}-output-chain-create"),
            &plan.program,
            strings(&["-t", "mangle", "-N", &plan.output_chain]),
            strings(&["-t", "mangle", "-X", &plan.output_chain]),
        ),
        mutation(
            &format!("before-{label}-prerouting-chain-create"),
            &plan.program,
            strings(&["-t", "mangle", "-N", &plan.prerouting_chain]),
            strings(&["-t", "mangle", "-X", &plan.prerouting_chain]),
        ),
    ];
    for (index, rule) in plan.output_rules.iter().enumerate() {
        prepared.push(mutation(
            &format!("before-{label}-output-rule-{index}"),
            &plan.program,
            rule.clone(),
            delete_rule(rule),
        ));
    }
    for (index, rule) in plan.prerouting_rules.iter().enumerate() {
        prepared.push(mutation(
            &format!("before-{label}-prerouting-rule-{index}"),
            &plan.program,
            rule.clone(),
            delete_rule(rule),
        ));
    }
    for (index, rule) in plan.postrouting_guards.iter().enumerate() {
        prepared.push(mutation(
            &format!("before-{label}-postrouting-guard-{index}"),
            &plan.program,
            rule.clone(),
            delete_rule(rule),
        ));
    }
    for (index, hook) in plan.prerouting_hooks.iter().enumerate() {
        prepared.push(mutation(
            &format!("before-{label}-loopback-prerouting-hook-{index}"),
            &plan.program,
            hook.clone(),
            delete_rule(hook),
        ));
    }
    for (index, hook) in plan.response_output_hooks.iter().enumerate() {
        prepared.push(mutation(
            &format!("before-{label}-response-bypass-hook-{index}"),
            &plan.program,
            hook.clone(),
            delete_rule(hook),
        ));
    }
    let activation = plan
        .activation_hooks
        .iter()
        .enumerate()
        .map(|(index, hook)| PlannedMutation {
            stage: format!("before-{label}-output-activation-hook-{index}"),
            program: plan.program.clone(),
            action: hook.clone(),
            inverse: delete_rule(hook),
            activation: true,
        })
        .collect();
    (prepared, activation)
}

fn install_mutations(
    resources: &mut LocalOutputResources,
    mutations: &[PlannedMutation],
) -> Result<(), String> {
    for mutation in mutations {
        resources.journal.record(
            &mutation.stage,
            &prefixed_words(&mutation.program, &mutation.action),
            &prefixed_words(&mutation.program, &mutation.inverse),
        )?;
        resources.pending.push(mutation.clone());
        command_owned(&mutation.program, &mutation.action)?;
    }
    Ok(())
}

fn validate_prepared_plan(plan: &RulePlan) -> Result<(), String> {
    for rule in plan
        .output_rules
        .iter()
        .chain(&plan.prerouting_rules)
        .chain(&plan.postrouting_guards)
        .chain(&plan.prerouting_hooks)
        .chain(&plan.response_output_hooks)
    {
        check_rule_present(&plan.program, rule)?;
    }
    for hook in &plan.activation_hooks {
        check_rule_absent(&plan.program, hook)?;
    }
    Ok(())
}

fn validate_active_plan(plan: &RulePlan) -> Result<(), String> {
    for hook in &plan.activation_hooks {
        check_rule_present(&plan.program, hook)?;
    }
    Ok(())
}

fn check_rule_present(program: &str, rule: &[String]) -> Result<(), String> {
    let check = check_rule(rule)?;
    command_owned(program, &check)
}

fn check_rule_absent(program: &str, rule: &[String]) -> Result<(), String> {
    let check = check_rule(rule)?;
    let mut command = Command::new(program);
    command.args(&check);
    let output = run_command(&mut command, COMMAND_TIMEOUT)?;
    if output.status.code() == Some(1) {
        Ok(())
    } else if output.status.success() {
        Err(format!(
            "rule unexpectedly exists before activation: {program} {}",
            check.join(" ")
        ))
    } else {
        Err(format!(
            "check absent rule with {program} {} exited with {}: stdout={} stderr={}",
            check.join(" "),
            output.status,
            bounded_diagnostic(&output.stdout),
            bounded_diagnostic(&output.stderr)
        ))
    }
}

fn check_rule(rule: &[String]) -> Result<Vec<String>, String> {
    let mut check = rule.to_vec();
    let operation = check
        .iter()
        .position(|argument| argument == "-A" || argument == "-I")
        .ok_or_else(|| format!("rule has no append or insert operation: {rule:?}"))?;
    check[operation] = "-C".to_owned();
    if check
        .get(operation + 2)
        .is_some_and(|argument| argument == "1")
    {
        check.remove(operation + 2);
    }
    Ok(check)
}

fn delete_rule(rule: &[String]) -> Vec<String> {
    let mut inverse = rule.to_vec();
    let operation = inverse
        .iter()
        .position(|argument| argument == "-A" || argument == "-I")
        .expect("generated local-OUTPUT rule has an append or insert operation");
    inverse[operation] = "-D".to_owned();
    if inverse
        .get(operation + 2)
        .is_some_and(|argument| argument == "1")
    {
        inverse.remove(operation + 2);
    }
    inverse
}

fn validate_private_rule(rule: &[String], chain: &str, actions: &[&str]) -> Result<(), String> {
    if rule_value_after(rule, &["-A", "--append"]) != Some(chain) {
        return Err(format!("private rule targets the wrong chain: {rule:?}"));
    }
    let action = rule_action(rule).ok_or_else(|| format!("rule has no jump action: {rule:?}"))?;
    if !actions.contains(&action) {
        return Err(format!(
            "private rule has forbidden action {action}: {rule:?}"
        ));
    }
    Ok(())
}

fn validate_hook(rule: &[String], hook: &str, target: &str) -> Result<(), String> {
    if rule_value_after(rule, &["-I", "--insert"]) != Some(hook)
        || rule_action(rule) != Some(target)
    {
        return Err(format!(
            "hook rule does not insert into {hook} and jump to {target}: {rule:?}"
        ));
    }
    Ok(())
}

fn selector_set<'a>(
    rules: impl Iterator<Item = &'a Vec<String>>,
) -> Result<BTreeSet<(String, u16)>, String> {
    let mut selectors = BTreeSet::new();
    for rule in rules {
        let protocol = rule_value_after(rule, &["-p", "--protocol"])
            .ok_or_else(|| format!("selector rule has no protocol: {rule:?}"))?;
        let port = rule_value_after(rule, &["--dport"])
            .ok_or_else(|| format!("selector rule has no destination port: {rule:?}"))?
            .parse()
            .map_err(|error| format!("parse selector port in {rule:?}: {error}"))?;
        if !selectors.insert((protocol.to_owned(), port)) {
            return Err(format!("duplicate selector {protocol}/{port}"));
        }
    }
    Ok(selectors)
}

fn rule_action(rule: &[String]) -> Option<&str> {
    rule_value_after(rule, &["-j", "--jump"])
}

fn rule_value_after<'a>(rule: &'a [String], options: &[&str]) -> Option<&'a str> {
    rule.windows(2)
        .find(|pair| options.contains(&pair[0].as_str()))
        .map(|pair| pair[1].as_str())
}

struct PreparedListeners {
    ipv4_tcp: TransparentTcpListener,
    ipv6_tcp: TransparentTcpListener,
    ipv4_udp: TransparentUdpListener,
    ipv6_udp: TransparentUdpListener,
}

impl PreparedListeners {
    fn bind(_config: &LocalOutputConfig) -> Result<Self, String> {
        let ipv4_tcp =
            TransparentTcpListener::bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED), TPROXY_PORT)?;
        let ipv6_tcp =
            TransparentTcpListener::bind(IpAddr::V6(Ipv6Addr::UNSPECIFIED), TPROXY_PORT)?;
        let ipv4_udp = TransparentUdpListener::bind(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            TPROXY_PORT,
            IO_TIMEOUT,
        )?;
        let ipv6_udp = TransparentUdpListener::bind(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            TPROXY_PORT,
            IO_TIMEOUT,
        )?;
        if ipv4_tcp.local_addr()? != SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), TPROXY_PORT)
            || ipv6_tcp.local_addr()?
                != SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), TPROXY_PORT)
            || ipv4_udp.local_addr()?
                != SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), TPROXY_PORT)
            || ipv6_udp.local_addr()?
                != SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), TPROXY_PORT)
            || ipv4_tcp.transparent_readback() != 1
            || ipv6_tcp.transparent_readback() != 1
            || ipv6_tcp.ipv6_only_readback() != Some(1)
            || ipv4_udp.transparent_readback() != 1
            || ipv6_udp.transparent_readback() != 1
            || ipv4_udp.receive_original_destination_readback() != 1
            || ipv6_udp.receive_original_destination_readback() != 1
            || ipv6_udp.ipv6_only_readback() != Some(1)
            || ipv4_tcp.set_mark(BYPASS_MARK)? != BYPASS_MARK
            || ipv6_tcp.set_mark(BYPASS_MARK)? != BYPASS_MARK
        {
            return Err("prepared transparent listener readback mismatch".to_owned());
        }
        Ok(Self {
            ipv4_tcp,
            ipv6_tcp,
            ipv4_udp,
            ipv6_udp,
        })
    }

    fn spawn(self, config: &LocalOutputConfig) -> ListenerWorkers {
        ListenerWorkers {
            workers: vec![
                spawn_tcp_worker(
                    "IPv4 TCP",
                    self.ipv4_tcp,
                    config.clone(),
                    AddressFamily::Ipv4,
                ),
                spawn_tcp_worker(
                    "IPv6 TCP",
                    self.ipv6_tcp,
                    config.clone(),
                    AddressFamily::Ipv6,
                ),
                spawn_udp_worker(
                    "IPv4 UDP",
                    self.ipv4_udp,
                    config.clone(),
                    AddressFamily::Ipv4,
                ),
                spawn_udp_worker(
                    "IPv6 UDP",
                    self.ipv6_udp,
                    config.clone(),
                    AddressFamily::Ipv6,
                ),
            ],
            started: false,
        }
    }
}

struct ListenerWorkers {
    workers: Vec<ListenerWorker>,
    started: bool,
}

impl ListenerWorkers {
    fn start(&mut self) -> Result<(), String> {
        if self.started {
            return Err("transparent listener workers were started more than once".to_owned());
        }
        for worker in &self.workers {
            worker.control.send(ListenerControl::Start).map_err(|_| {
                format!(
                    "{} transparent listener dropped its control channel",
                    worker.label
                )
            })?;
        }
        self.started = true;
        Ok(())
    }

    fn receive_observations(&mut self) -> Result<Vec<ListenerObservation>, String> {
        let mut observations = Vec::with_capacity(self.workers.len());
        for worker in &mut self.workers {
            let result = worker
                .result
                .recv_timeout(IO_TIMEOUT + Duration::from_secs(1))
                .map_err(|error| {
                    format!(
                        "{} transparent listener did not report before timeout: {error}",
                        worker.label
                    )
                })?;
            observations.push(result?);
        }
        Ok(observations)
    }

    fn release_and_join(self, failures: &mut Vec<String>) {
        for worker in &self.workers {
            if worker.control.send(ListenerControl::Release).is_err() {
                failures.push(format!(
                    "{} transparent listener dropped its control receiver",
                    worker.label
                ));
            }
        }
        for worker in self.workers {
            if worker.handle.join().is_err() {
                failures.push(format!(
                    "{} transparent listener panicked before guarded teardown",
                    worker.label
                ));
            }
        }
    }
}

struct ListenerWorker {
    label: &'static str,
    result: Receiver<Result<ListenerObservation, String>>,
    control: Sender<ListenerControl>,
    handle: thread::JoinHandle<()>,
}

#[derive(Clone, Copy)]
enum ListenerControl {
    Start,
    Release,
}

fn spawn_tcp_worker(
    label: &'static str,
    listener: TransparentTcpListener,
    config: LocalOutputConfig,
    family: AddressFamily,
) -> ListenerWorker {
    let (result_tx, result_rx) = mpsc::channel();
    let (control_tx, control_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        if !matches!(control_rx.recv(), Ok(ListenerControl::Start)) {
            return;
        }
        let result = serve_tcp(&listener, &config, family);
        let _ = result_tx.send(result);
        while !matches!(control_rx.recv(), Ok(ListenerControl::Release) | Err(_)) {}
    });
    ListenerWorker {
        label,
        result: result_rx,
        control: control_tx,
        handle,
    }
}

fn spawn_udp_worker(
    label: &'static str,
    listener: TransparentUdpListener,
    config: LocalOutputConfig,
    family: AddressFamily,
) -> ListenerWorker {
    let (result_tx, result_rx) = mpsc::channel();
    let (control_tx, control_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        if !matches!(control_rx.recv(), Ok(ListenerControl::Start)) {
            return;
        }
        let result = serve_udp(&listener, &config, family);
        let _ = result_tx.send(result);
        while !matches!(control_rx.recv(), Ok(ListenerControl::Release) | Err(_)) {}
    });
    ListenerWorker {
        label,
        result: result_rx,
        control: control_tx,
        handle,
    }
}

#[derive(Debug, Clone)]
struct ListenerObservation {
    family: AddressFamily,
    transport: FlowTransport,
    listener: SocketAddr,
    remote: SocketAddr,
    original_destination: SocketAddr,
    response_local: SocketAddr,
    response_remote: SocketAddr,
    response_mark: u32,
    request: Vec<u8>,
    response: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ClientObservation {
    family: AddressFamily,
    transport: FlowTransport,
    local: SocketAddr,
    remote: SocketAddr,
    socket_mark: u32,
    request: Vec<u8>,
    response: Vec<u8>,
}

fn serve_tcp(
    listener: &TransparentTcpListener,
    config: &LocalOutputConfig,
    family: AddressFamily,
) -> Result<ListenerObservation, String> {
    let listener_address = listener.local_addr()?;
    let (mut stream, remote) = accept_until(listener.listener(), IO_TIMEOUT)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|error| format!("configure transparent TCP stream: {error}"))?;
    let original_destination = stream
        .local_addr()
        .map_err(|error| format!("read transparent TCP original destination: {error}"))?;
    let response_mark = set_tcp_socket_mark(&stream, BYPASS_MARK)?;
    let request = read_u32_frame(&mut stream)?;
    let response = response_payload(&request);
    write_u32_frame(&mut stream, &response)?;
    let response_local = stream
        .local_addr()
        .map_err(|error| format!("read transparent TCP response local tuple: {error}"))?;
    let response_remote = stream
        .peer_addr()
        .map_err(|error| format!("read transparent TCP response remote tuple: {error}"))?;
    if tcp_socket_mark(&stream)? != BYPASS_MARK {
        return Err("transparent TCP response socket lost its bypass mark".to_owned());
    }
    let expected = SocketAddr::new(config.destination(family), TCP_PORT);
    if original_destination != expected || response_local != expected {
        return Err(format!(
            "transparent TCP listener observed {original_destination} / response {response_local}, expected {expected}"
        ));
    }
    Ok(ListenerObservation {
        family,
        transport: FlowTransport::Tcp,
        listener: listener_address,
        remote,
        original_destination,
        response_local,
        response_remote,
        response_mark,
        request,
        response,
    })
}

fn serve_udp(
    listener: &TransparentUdpListener,
    config: &LocalOutputConfig,
    family: AddressFamily,
) -> Result<ListenerObservation, String> {
    let listener_address = listener.local_addr()?;
    let mut buffer = [0_u8; 512];
    let datagram = listener.receive(&mut buffer)?;
    let expected = SocketAddr::new(config.destination(family), UDP_PORT);
    if datagram.original_destination != expected {
        return Err(format!(
            "transparent UDP listener observed original destination {}, expected {expected}",
            datagram.original_destination
        ));
    }
    let response = response_payload(&datagram.payload);
    let (response_socket, response_mark, transparent) = connect_transparent_marked_udp(
        datagram.original_destination,
        datagram.remote,
        BYPASS_MARK,
        IO_TIMEOUT,
    )?;
    if response_mark != BYPASS_MARK
        || transparent != 1
        || udp_socket_mark(&response_socket)? != BYPASS_MARK
    {
        return Err("transparent UDP response socket readback mismatch".to_owned());
    }
    let sent = response_socket
        .send(&response)
        .map_err(|error| format!("send transparent UDP response: {error}"))?;
    if sent != response.len() {
        return Err(format!(
            "transparent UDP response was partial: sent={sent} expected={}",
            response.len()
        ));
    }
    let response_local = response_socket
        .local_addr()
        .map_err(|error| format!("read transparent UDP response local tuple: {error}"))?;
    let response_remote = response_socket
        .peer_addr()
        .map_err(|error| format!("read transparent UDP response remote tuple: {error}"))?;
    Ok(ListenerObservation {
        family,
        transport: FlowTransport::Udp,
        listener: listener_address,
        remote: datagram.remote,
        original_destination: datagram.original_destination,
        response_local,
        response_remote,
        response_mark,
        request: datagram.payload,
        response,
    })
}

fn accept_until(
    listener: &TcpListener,
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok(accepted) => return Ok(accepted),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "transparent TCP listener timed out after {timeout:?}"
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("accept transparent TCP stream: {error}")),
        }
    }
}

fn response_payload(request: &[u8]) -> Vec<u8> {
    let mut response = b"flux-local-output-reply:".to_vec();
    response.extend_from_slice(request);
    response
}

fn request_payload(
    config: &LocalOutputConfig,
    family: AddressFamily,
    transport: FlowTransport,
) -> Vec<u8> {
    format!(
        "flux-local-output:{}:{}:{}",
        config.nonce,
        family.label(),
        transport.label()
    )
    .into_bytes()
}

fn run_positive_clients(config: &LocalOutputConfig) -> Result<Vec<ClientObservation>, String> {
    let mut observations = Vec::with_capacity(4);
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        observations.push(run_tcp_client(config, family)?);
        observations.push(run_udp_client(config, family)?);
    }
    Ok(observations)
}

fn run_tcp_client(
    config: &LocalOutputConfig,
    family: AddressFamily,
) -> Result<ClientObservation, String> {
    let source = SocketAddr::new(config.source(family), 0);
    let destination = SocketAddr::new(config.destination(family), TCP_PORT);
    let (mut stream, observed_mark) = connect_marked_tcp(source, destination, 0, IO_TIMEOUT)?;
    if observed_mark != 0 || tcp_socket_mark(&stream)? != 0 {
        return Err("positive TCP client was not initially unmarked".to_owned());
    }
    let request = request_payload(config, family, FlowTransport::Tcp);
    write_u32_frame(&mut stream, &request)?;
    let response = read_u32_frame(&mut stream)?;
    let local = stream
        .local_addr()
        .map_err(|error| format!("read positive TCP client local tuple: {error}"))?;
    let remote = stream
        .peer_addr()
        .map_err(|error| format!("read positive TCP client remote tuple: {error}"))?;
    if response != response_payload(&request) {
        return Err("positive TCP client response payload mismatch".to_owned());
    }
    Ok(ClientObservation {
        family,
        transport: FlowTransport::Tcp,
        local,
        remote,
        socket_mark: observed_mark,
        request,
        response,
    })
}

fn run_udp_client(
    config: &LocalOutputConfig,
    family: AddressFamily,
) -> Result<ClientObservation, String> {
    let source = SocketAddr::new(config.source(family), 0);
    let destination = SocketAddr::new(config.destination(family), UDP_PORT);
    let (socket, observed_mark) = connect_marked_udp(source, destination, 0, IO_TIMEOUT)?;
    if observed_mark != 0 || udp_socket_mark(&socket)? != 0 {
        return Err("positive UDP client was not initially unmarked".to_owned());
    }
    let request = request_payload(config, family, FlowTransport::Udp);
    let sent = socket
        .send(&request)
        .map_err(|error| format!("send positive UDP client request: {error}"))?;
    if sent != request.len() {
        return Err(format!(
            "positive UDP client request was partial: sent={sent} expected={}",
            request.len()
        ));
    }
    let mut buffer = [0_u8; 512];
    let received = socket
        .recv(&mut buffer)
        .map_err(|error| format!("receive positive UDP client response: {error}"))?;
    let response = buffer[..received].to_vec();
    let local = socket
        .local_addr()
        .map_err(|error| format!("read positive UDP client local tuple: {error}"))?;
    let remote = socket
        .peer_addr()
        .map_err(|error| format!("read positive UDP client remote tuple: {error}"))?;
    if response != response_payload(&request) {
        return Err("positive UDP client response payload mismatch".to_owned());
    }
    Ok(ClientObservation {
        family,
        transport: FlowTransport::Udp,
        local,
        remote,
        socket_mark: observed_mark,
        request,
        response,
    })
}

fn validate_flow_observations(
    config: &LocalOutputConfig,
    clients: &[ClientObservation],
    listeners: &[ListenerObservation],
) -> Result<(), String> {
    if clients.len() != 4 || listeners.len() != 4 {
        return Err(format!(
            "expected four client and listener observations, found client={} listener={}",
            clients.len(),
            listeners.len()
        ));
    }
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        for transport in [FlowTransport::Tcp, FlowTransport::Udp] {
            let clients = clients
                .iter()
                .filter(|flow| flow.family == family && flow.transport == transport)
                .collect::<Vec<_>>();
            let listeners = listeners
                .iter()
                .filter(|flow| flow.family == family && flow.transport == transport)
                .collect::<Vec<_>>();
            let [client] = clients.as_slice() else {
                return Err(format!(
                    "expected one {} {} client observation, found {}",
                    family.label(),
                    transport.label(),
                    clients.len()
                ));
            };
            let [listener] = listeners.as_slice() else {
                return Err(format!(
                    "expected one {} {} listener observation, found {}",
                    family.label(),
                    transport.label(),
                    listeners.len()
                ));
            };
            let port = match transport {
                FlowTransport::Tcp => TCP_PORT,
                FlowTransport::Udp => UDP_PORT,
            };
            let destination = SocketAddr::new(config.destination(family), port);
            let wildcard = SocketAddr::new(
                match family {
                    AddressFamily::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    AddressFamily::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                },
                TPROXY_PORT,
            );
            if client.socket_mark != 0
                || client.local.ip() != config.source(family)
                || client.remote != destination
                || listener.listener != wildcard
                || listener.remote != client.local
                || listener.original_destination != destination
                || listener.response_local != destination
                || listener.response_remote != client.local
                || listener.response_mark != BYPASS_MARK
                || listener.request != client.request
                || listener.response != client.response
                || client.response != response_payload(&client.request)
            {
                return Err(format!(
                    "{} {} local-OUTPUT TPROXY observation mismatch: client={client:?} listener={listener:?}",
                    family.label(),
                    transport.label()
                ));
            }
        }
    }
    Ok(())
}

fn run_negative_controls(config: &LocalOutputConfig) -> Result<(), String> {
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        let source = SocketAddr::new(config.source(family), 0);
        let destination = SocketAddr::new(config.destination(family), NEGATIVE_PORT);
        let (socket, observed_mark) = connect_marked_udp(source, destination, 0, NEGATIVE_TIMEOUT)?;
        if observed_mark != 0 || udp_socket_mark(&socket)? != 0 {
            return Err(format!(
                "{} unmatched negative-control socket was not unmarked",
                family.label()
            ));
        }
        let request = format!("flux-local-output-negative:{}", config.nonce).into_bytes();
        let sent = socket.send(&request).map_err(|error| {
            format!(
                "send {} unmatched negative-control datagram: {error}",
                family.label()
            )
        })?;
        if sent != request.len() {
            return Err(format!(
                "{} unmatched negative-control datagram was partial",
                family.label()
            ));
        }
        let mut buffer = [0_u8; 64];
        match socket.recv(&mut buffer) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                return Err(format!(
                    "{} unmatched negative-control receive failed unexpectedly: {error}",
                    family.label()
                ));
            }
            Ok(length) => {
                return Err(format!(
                    "{} unmatched negative control received {length} bytes",
                    family.label()
                ));
            }
        }

        let bypass_destination = SocketAddr::new(config.destination(family), UDP_PORT);
        let (bypass_socket, bypass_mark) = connect_marked_udp(
            SocketAddr::new(config.source(family), 0),
            bypass_destination,
            BYPASS_MARK,
            NEGATIVE_TIMEOUT,
        )?;
        if bypass_mark != BYPASS_MARK || udp_socket_mark(&bypass_socket)? != BYPASS_MARK {
            return Err(format!(
                "{} forward-tuple bypass negative-control socket lost its mark",
                family.label()
            ));
        }
        let bypass_request =
            format!("flux-local-output-forward-bypass:{}", config.nonce).into_bytes();
        let sent = bypass_socket.send(&bypass_request).map_err(|error| {
            format!(
                "send {} forward-tuple bypass negative control: {error}",
                family.label()
            )
        })?;
        if sent != bypass_request.len() {
            return Err(format!(
                "{} forward-tuple bypass negative control was partial",
                family.label()
            ));
        }
        match bypass_socket.recv(&mut buffer) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                return Err(format!(
                    "{} forward-tuple bypass negative-control receive failed unexpectedly: {error}",
                    family.label()
                ));
            }
            Ok(length) => {
                return Err(format!(
                    "{} forward-tuple bypass negative control received {length} bytes",
                    family.label()
                ));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct FamilyCounterSnapshot {
    mark_tcp: u64,
    mark_udp: u64,
    output_tcp: u64,
    output_udp: u64,
    tproxy_tcp: u64,
    tproxy_udp: u64,
    bypass_tcp: u64,
    bypass_udp: u64,
    leak_tcp: u64,
    leak_udp: u64,
    negative: u64,
    forward_bypass: u64,
    unexpected_output: u64,
    unexpected_prerouting: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CounterSnapshot {
    ipv4: FamilyCounterSnapshot,
    ipv6: FamilyCounterSnapshot,
}

fn read_counters(config: &LocalOutputConfig) -> Result<CounterSnapshot, String> {
    let ipv4 = command_output("iptables-save", &["-c", "-t", "mangle"])?;
    let ipv6 = command_output("ip6tables-save", &["-c", "-t", "mangle"])?;
    Ok(CounterSnapshot {
        ipv4: read_family_counters(&ipv4, &config.comments.ipv4)?,
        ipv6: read_family_counters(&ipv6, &config.comments.ipv6)?,
    })
}

fn read_family_counters(
    dump: &[u8],
    comments: &FamilyComments,
) -> Result<FamilyCounterSnapshot, String> {
    Ok(FamilyCounterSnapshot {
        mark_tcp: packet_count_for_comment(dump, &comments.mark_tcp)?,
        mark_udp: packet_count_for_comment(dump, &comments.mark_udp)?,
        output_tcp: packet_count_for_comment(dump, &comments.output_tcp)?,
        output_udp: packet_count_for_comment(dump, &comments.output_udp)?,
        tproxy_tcp: packet_count_for_comment(dump, &comments.tproxy_tcp)?,
        tproxy_udp: packet_count_for_comment(dump, &comments.tproxy_udp)?,
        bypass_tcp: packet_count_for_comment(dump, &comments.bypass_tcp)?,
        bypass_udp: packet_count_for_comment(dump, &comments.bypass_udp)?,
        leak_tcp: packet_count_for_comment(dump, &comments.leak_tcp)?,
        leak_udp: packet_count_for_comment(dump, &comments.leak_udp)?,
        negative: packet_count_for_comment(dump, &comments.negative)?,
        forward_bypass: packet_count_for_comment(dump, &comments.forward_bypass)?,
        unexpected_output: packet_count_for_comment(dump, &comments.unexpected_output)?,
        unexpected_prerouting: packet_count_for_comment(dump, &comments.unexpected_prerouting)?,
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
    let counters = line
        .strip_prefix('[')
        .and_then(|line| line.split_once(']'))
        .map(|(counters, _)| counters)
        .ok_or_else(|| format!("counter rule lacks [packets:bytes] prefix: {line}"))?;
    let packets = counters
        .split_once(':')
        .map(|(packets, _)| packets)
        .ok_or_else(|| format!("counter rule has malformed prefix: {line}"))?;
    packets
        .parse()
        .map_err(|error| format!("parse packet counter {packets:?}: {error}"))
}

fn validate_positive_counters(snapshot: CounterSnapshot) -> Result<(), String> {
    for (family, counters) in [("IPv4", snapshot.ipv4), ("IPv6", snapshot.ipv6)] {
        if !(1..=TCP_COUNTER_MAXIMUM).contains(&counters.mark_tcp)
            || !(1..=TCP_COUNTER_MAXIMUM).contains(&counters.output_tcp)
            || !(1..=TCP_COUNTER_MAXIMUM).contains(&counters.tproxy_tcp)
            || !(1..=TCP_COUNTER_MAXIMUM).contains(&counters.bypass_tcp)
            || counters.mark_udp != 1
            || counters.output_udp != 1
            || counters.tproxy_udp != 1
            || counters.bypass_udp != 1
            || counters.leak_tcp != 0
            || counters.leak_udp != 0
            || counters.negative != 0
            || counters.forward_bypass != 0
            || counters.unexpected_output != 0
            || counters.unexpected_prerouting != 0
        {
            return Err(format!(
                "{family} local-OUTPUT TPROXY positive counters are outside bounds: {counters:?}"
            ));
        }
    }
    Ok(())
}

fn validate_negative_control(
    positive: CounterSnapshot,
    negative: CounterSnapshot,
) -> Result<(), String> {
    for (family, before, after) in [
        ("IPv4", positive.ipv4, negative.ipv4),
        ("IPv6", positive.ipv6, negative.ipv6),
    ] {
        let expected = FamilyCounterSnapshot {
            negative: 1,
            forward_bypass: 1,
            ..before
        };
        if after != expected {
            return Err(format!(
                "{family} unmatched negative control changed capture state or missed the safe egress drop: before={before:?} after={after:?} expected={expected:?}"
            ));
        }
    }
    Ok(())
}

fn validate_route_controls(config: &LocalOutputConfig) -> Result<(), String> {
    for (family, table) in [
        (AddressFamily::Ipv4, config.ipv4_route_table),
        (AddressFamily::Ipv6, config.ipv6_route_table),
    ] {
        let destination = config.destination(family).to_string();
        let source = config.source(family).to_string();
        let local = route_lookup(family, &destination, &source, PROXY_MARK)?;
        if local.get("type").and_then(Value::as_str) != Some("local")
            || local.get("dev").and_then(Value::as_str) != Some("lo")
            || local.get("table").and_then(value_as_u32) != Some(table)
        {
            return Err(format!(
                "{} proxy-mark route lookup did not select local table {table} through lo: {local:?}",
                family.label()
            ));
        }

        let direct = route_lookup(family, &destination, &source, 0)?;
        if direct.get("type").and_then(Value::as_str) == Some("local")
            || direct.get("dev").and_then(Value::as_str) != Some(config.egress_interface.as_str())
        {
            return Err(format!(
                "{} unmarked route lookup did not select test egress {}: {direct:?}",
                family.label(),
                config.egress_interface
            ));
        }

        let bypass = route_lookup(family, &destination, &source, BYPASS_MARK)?;
        if bypass.get("type").and_then(Value::as_str) == Some("local")
            || bypass.get("dev").and_then(Value::as_str) != Some(config.egress_interface.as_str())
        {
            return Err(format!(
                "{} bypass mark accidentally selects the proxy local route: {bypass:?}",
                family.label()
            ));
        }
    }
    Ok(())
}

fn route_lookup(
    family: AddressFamily,
    destination: &str,
    source: &str,
    mark: u32,
) -> Result<serde_json::Map<String, Value>, String> {
    let mut arguments = Vec::new();
    if family == AddressFamily::Ipv6 {
        arguments.push("-6".to_owned());
    }
    arguments.extend([
        "-j".to_owned(),
        "route".to_owned(),
        "get".to_owned(),
        destination.to_owned(),
        "from".to_owned(),
        source.to_owned(),
        "mark".to_owned(),
        format!("{mark:#x}"),
        "uid".to_owned(),
        "0".to_owned(),
    ]);
    first_json_object(&command_output_owned("ip", &arguments)?, "ip route get")
}

fn first_json_object(output: &[u8], label: &str) -> Result<serde_json::Map<String, Value>, String> {
    let values = json_array(output, label)?;
    let [value] = values.as_slice() else {
        return Err(format!(
            "{label} JSON contains {} entries: {values:?}",
            values.len()
        ));
    };
    value
        .as_object()
        .cloned()
        .ok_or_else(|| format!("{label} JSON entry is not an object: {value}"))
}

fn json_array(output: &[u8], label: &str) -> Result<Vec<Value>, String> {
    let value: Value =
        serde_json::from_slice(output).map_err(|error| format!("decode {label} JSON: {error}"))?;
    value
        .as_array()
        .cloned()
        .ok_or_else(|| format!("{label} JSON is not an array: {value}"))
}

fn value_as_u32(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn cleanup_isolated(resources: &mut LocalOutputResources) -> Result<(), String> {
    let mut failures = Vec::new();
    if !resources.pending.is_empty()
        && let Err(error) = resources.journal.record(
            "before-local-output-cleanup",
            &[
                "detach OUTPUT activation before listener teardown and replay exact inverses"
                    .to_owned(),
            ],
            &["terminal cleanup has no inverse".to_owned()],
        )
    {
        failures.push(error);
    }

    let mut activation_detached = true;
    for mutation in resources
        .pending
        .iter()
        .rev()
        .filter(|mutation| mutation.activation)
    {
        activation_detached &= attempt_inverse(mutation, &mut failures);
    }
    for mutation in resources
        .pending
        .iter()
        .filter(|mutation| mutation.activation)
    {
        if let Err(error) = prove_rule_absent(&mutation.program, &mutation.action) {
            activation_detached = false;
            failures.push(format!(
                "OUTPUT activation hook remains after first cleanup phase: {error}"
            ));
        }
    }

    if !activation_detached
        && let Err(error) = delete_interface_if_present(&resources.config.egress_interface)
    {
        failures.push(format!(
            "cut test egress after OUTPUT-detach failure: {error}"
        ));
    }
    if let Some(listeners) = resources.listeners.take() {
        listeners.release_and_join(&mut failures);
    }

    for mutation in resources
        .pending
        .iter()
        .rev()
        .filter(|mutation| !mutation.activation)
    {
        attempt_inverse(mutation, &mut failures);
    }

    validate_baselines(resources, &mut failures);
    if let Err(error) = resources.modules.verify() {
        failures.push(error);
    }
    if let Err(error) = validate_journal_integrity(&resources.journal.path, &resources.config.nonce)
    {
        failures.push(error);
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn attempt_inverse(mutation: &PlannedMutation, failures: &mut Vec<String>) -> bool {
    let mut command = Command::new(&mutation.program);
    command.args(&mutation.inverse);
    match run_command(&mut command, COMMAND_TIMEOUT) {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            failures.push(format!(
                "inverse {} {} exited with {}: stdout={} stderr={}",
                mutation.program,
                mutation.inverse.join(" "),
                output.status,
                bounded_diagnostic(&output.stdout),
                bounded_diagnostic(&output.stderr)
            ));
            false
        }
        Err(error) => {
            failures.push(format!(
                "execute inverse {} {}: {error}",
                mutation.program,
                mutation.inverse.join(" ")
            ));
            false
        }
    }
}

fn prove_rule_absent(program: &str, rule: &[String]) -> Result<(), String> {
    let check = check_rule(rule)?;
    let mut command = Command::new(program);
    command.args(&check);
    let output = run_command(&mut command, COMMAND_TIMEOUT)?;
    if output.status.code() == Some(1) {
        Ok(())
    } else if output.status.success() {
        Err(format!("{program} {} still succeeds", check.join(" ")))
    } else {
        Err(format!(
            "{program} {} exited with {}: stdout={} stderr={}",
            check.join(" "),
            output.status,
            bounded_diagnostic(&output.stdout),
            bounded_diagnostic(&output.stderr)
        ))
    }
}

fn validate_baselines(resources: &LocalOutputResources, failures: &mut Vec<String>) {
    let observed = [
        (
            "IPv4 mangle",
            resources.baselines.ipv4_mangle.as_slice(),
            mangle_dump("iptables-save"),
        ),
        (
            "IPv6 mangle",
            resources.baselines.ipv6_mangle.as_slice(),
            mangle_dump("ip6tables-save"),
        ),
        (
            "IPv4 RPDB",
            resources.baselines.ipv4_rules.as_slice(),
            command_output("ip", &["-j", "rule", "show"]),
        ),
        (
            "IPv6 RPDB",
            resources.baselines.ipv6_rules.as_slice(),
            command_output("ip", &["-6", "-j", "rule", "show"]),
        ),
        (
            "IPv4 private route table",
            resources.baselines.ipv4_private_table.as_slice(),
            route_table_dump(false, resources.config.ipv4_route_table),
        ),
        (
            "IPv6 private route table",
            resources.baselines.ipv6_private_table.as_slice(),
            route_table_dump(true, resources.config.ipv6_route_table),
        ),
        (
            "link inventory",
            resources.baselines.links.as_slice(),
            command_output("ip", &["-j", "link", "show"]),
        ),
        (
            "address inventory",
            resources.baselines.addresses.as_slice(),
            command_output("ip", &["-j", "address", "show"]),
        ),
        (
            "IPv4 route inventory",
            resources.baselines.ipv4_routes.as_slice(),
            command_output("ip", &["-j", "route", "show", "table", "all"]),
        ),
        (
            "IPv6 route inventory",
            resources.baselines.ipv6_routes.as_slice(),
            command_output("ip", &["-6", "-j", "route", "show", "table", "all"]),
        ),
    ];
    for (label, expected, result) in observed {
        match result {
            Ok(actual) if actual == expected => {}
            Ok(actual) => failures.push(format!(
                "{label} baseline was not restored: expected={} observed={}",
                bounded_diagnostic(expected),
                bounded_diagnostic(&actual)
            )),
            Err(error) => failures.push(format!("read {label} cleanup baseline: {error}")),
        }
    }
}

fn validate_journal(resources: &LocalOutputResources) -> Result<(), String> {
    validate_journal_integrity(&resources.journal.path, &resources.config.nonce)?;
    let records = read_journal(&resources.journal.path)?;
    for mutation in &resources.pending {
        let matching = records
            .iter()
            .filter(|record| record.stage == mutation.stage)
            .collect::<Vec<_>>();
        let [record] = matching.as_slice() else {
            return Err(format!(
                "journal stage {} appears {} times instead of once",
                mutation.stage,
                matching.len()
            ));
        };
        if record.action != prefixed_words(&mutation.program, &mutation.action)
            || record.inverse != prefixed_words(&mutation.program, &mutation.inverse)
            || record.target_process.is_some()
        {
            return Err(format!(
                "journal stage {} does not retain the exact action and inverse: {record:?}",
                mutation.stage
            ));
        }
    }
    let cleanup = records
        .iter()
        .position(|record| record.stage == "before-local-output-cleanup")
        .ok_or_else(|| "journal omitted local-OUTPUT cleanup boundary".to_owned())?;
    let last_activation = records
        .iter()
        .rposition(|record| record.stage.contains("output-activation-hook"))
        .ok_or_else(|| "journal omitted OUTPUT activation".to_owned())?;
    if last_activation >= cleanup {
        return Err("journal cleanup boundary precedes OUTPUT activation".to_owned());
    }
    Ok(())
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

    fn test_config() -> LocalOutputConfig {
        LocalOutputConfig::new("0123456789abcdef0123456789abcdef".to_owned()).expect("test config")
    }

    #[test]
    fn local_output_plan_prepares_loopback_tproxy_before_output_activation() {
        let config = test_config();
        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            let plan = rule_plan(&config, family);
            plan.validate().expect("valid local-OUTPUT plan");
            assert!(
                plan.output_rules
                    .iter()
                    .flatten()
                    .all(|argument| argument != "TPROXY")
            );
            assert_eq!(plan.prerouting_hooks.len(), 2);
            assert!(plan.prerouting_hooks.iter().all(|hook| {
                rule_value_after(hook, &["-i"]) == Some("lo")
                    && rule_action(hook) == Some(plan.prerouting_chain.as_str())
            }));
            let (prepared, activation) = capture_mutations(&plan, family);
            assert!(prepared.iter().all(|mutation| !mutation.activation));
            assert!(activation.iter().all(|mutation| mutation.activation));
            assert!(
                prepared
                    .iter()
                    .any(|mutation| mutation.stage.contains("loopback-prerouting-hook"))
            );
            assert!(
                activation
                    .iter()
                    .all(|mutation| mutation.stage.contains("output-activation-hook"))
            );
            for mutation in prepared.iter().chain(&activation) {
                let Some(operation) = mutation
                    .action
                    .iter()
                    .position(|argument| argument == "-A" || argument == "-I")
                else {
                    continue;
                };
                let mut expected = mutation.action.clone();
                expected[operation] = "-D".to_owned();
                if expected
                    .get(operation + 2)
                    .is_some_and(|argument| argument == "1")
                {
                    expected.remove(operation + 2);
                }
                assert_eq!(mutation.inverse, expected);
            }
        }
    }

    #[test]
    fn counter_parser_requires_one_exact_comment() {
        let dump = b"[3:144] -A FL4TEST -m comment --comment lo4testmt -j MARK\n";
        assert_eq!(packet_count_for_comment(dump, "lo4testmt"), Ok(3));
        assert!(packet_count_for_comment(dump, "missing").is_err());
        let duplicate = [dump.as_slice(), dump.as_slice()].concat();
        assert!(packet_count_for_comment(&duplicate, "lo4testmt").is_err());
    }

    #[test]
    fn route_parser_requires_one_object() {
        let route = first_json_object(br#"[{"type":"local","dev":"lo","table":28001}]"#, "route")
            .expect("one route");
        assert_eq!(route.get("dev").and_then(Value::as_str), Some("lo"));
        assert!(first_json_object(b"[]", "route").is_err());
        assert!(first_json_object(b"[{},{}]", "route").is_err());
    }

    #[test]
    fn foreign_mangle_and_overlapping_fwmark_state_are_rejected() {
        require_clean_mangle_baseline(
            "mangle",
            "*mangle\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n",
        )
        .expect("empty built-in chains are admissible");
        assert!(
            require_clean_mangle_baseline(
                "mangle",
                "*mangle\n:FOREIGN - [0:0]\n-A OUTPUT -j FOREIGN\nCOMMIT\n",
            )
            .is_err()
        );
        let overlapping: Value =
            serde_json::from_str(r#"{"fwmark":"0x1/0xf"}"#).expect("test rule");
        let disjoint: Value =
            serde_json::from_str(r#"{"fwmark":128,"fwmask":128}"#).expect("test rule");
        let (_, overlap_mask) = rpdb_fwmark_selector(&overlapping)
            .expect("parse overlapping rule")
            .expect("fwmark selector");
        let (_, disjoint_mask) = rpdb_fwmark_selector(&disjoint)
            .expect("parse disjoint rule")
            .expect("fwmark selector");
        assert_ne!(overlap_mask & PROXY_MASK, 0);
        assert_eq!(disjoint_mask & PROXY_MASK, 0);
    }
}
