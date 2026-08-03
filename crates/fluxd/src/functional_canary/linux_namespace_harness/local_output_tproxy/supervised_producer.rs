use super::*;

use std::io::{Read, Write};
use std::net::Shutdown;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::thread::JoinHandle;

use flux_core::GenerationId;
use flux_platform::internal::{PinnedSingBoxLaunch, SingBoxChild, SingBoxProcessAdapter};
use flux_platform::{SeqpacketReceive, SingBoxLaunchSpec, SingBoxPrivilege, SingBoxReadiness};

use crate::functional_canary::supervised_delivery_report::collector;
use crate::functional_canary::tests::request_with_engine_profile_revision_and_duration;
use crate::functional_canary::{
    CanaryAddressFamilies, CanaryAttemptRequest, CanaryFlow, CanaryFlowKind, CanaryFlowProtocol,
    CanaryFlowTuple, CanaryNonce, FUNCTIONAL_CANARY_FLOW_SLOTS, FUNCTIONAL_CANARY_NONCE_BYTES,
    MAX_FUNCTIONAL_CANARY_DURATION,
};
use crate::generation_engine_config::{
    EngineCapabilityProfile, TproxyEngineConfigRequest, bind_engine_config_to_spec,
    collect_tproxy_engine_capability_profile, compile_tproxy_engine_config,
    declare_supervised_delivery_report_profile_fixture,
};
use crate::{EngineSpec, RestartPolicy};

const PRODUCER_BINARY_ENV: &str = "FLUX_TEST_SING_BOX_PRODUCER_BINARY";
const DNS_PORT: u16 = 41_003;
const EXPECTED_TCP_SINK_FLOWS: usize = 4;
const EXPECTED_UDP_SINK_FLOWS: usize = 4;
const SINK_TIMEOUT: Duration = Duration::from_secs(10);
const PRODUCER_STOP_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_SELECTOR_PACKETS: u64 = 64;

pub(super) fn config(nonce: String) -> Result<LocalOutputConfig, String> {
    let mut config = LocalOutputConfig::new(nonce)?;
    config.ipv4_source = Ipv4Addr::new(11, 0, 0, 10);
    config.ipv4_destination = Ipv4Addr::new(11, 0, 0, 2);
    config.ipv6_source = "2001:4860::10"
        .parse()
        .map_err(|error| format!("parse supervised-producer source IPv6: {error}"))?;
    config.ipv6_destination = "2001:4860::2"
        .parse()
        .map_err(|error| format!("parse supervised-producer destination IPv6: {error}"))?;
    Ok(config)
}

pub(super) fn execute(resources: &mut LocalOutputResources) -> Result<(), String> {
    let prepared = PreparedProducer::new()?;
    let comments = SupervisedCounterComments::new(&resources.config.nonce[..8]);

    install_mutations(resources, &network_mutations(&resources.config))?;
    install_mutations(resources, &rpdb_mutations(&resources.config))?;

    let mut plans = Vec::new();
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        let plan = supervised_rule_plan(&resources.config, family, comments.family(family));
        plan.validate()?;
        let (prepared_rules, activation) = capture_mutations(&plan, family);
        install_mutations(resources, &prepared_rules)?;
        validate_prepared_plan(&plan)?;
        plans.push((plan, activation));
    }
    for (plan, activation) in &plans {
        install_mutations(resources, activation)?;
        validate_active_plan(plan)?;
    }

    validate_supervised_counters(&comments, CounterExpectation::Zero)?;
    validate_route_controls(&resources.config)?;
    resources.modules.verify()?;

    let sinks = prepared.start_sinks()?;
    let mut producer = prepared.spawn()?;
    producer.wait_ready()?;
    exercise_attempt_lifecycle(&resources.config, &producer.fixture, producer.child())?;

    validate_supervised_counters(&comments, CounterExpectation::Positive)?;
    sinks.join()?;
    producer.ensure_running()?;
    producer.terminate()?;
    resources.modules.verify()
}

struct PreparedProducer {
    _directory: tempfile::TempDir,
    fixture: ProducerFixture,
    sinks: PreparedSinks,
}

impl PreparedProducer {
    fn new() -> Result<Self, String> {
        let binary = producer_binary()?;
        let sinks = PreparedSinks::bind()?;
        let template = serde_json::to_vec(&serde_json::json!({
            "log": { "disabled": true },
            "inbounds": [],
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": {
                "rules": [{
                    "action": "route",
                    "outbound": "direct",
                    "override_address": "127.0.0.1",
                    "override_port": sinks.port.get(),
                }],
            },
        }))
        .map_err(|error| format!("encode supervised-producer config template: {error}"))?;
        let listener_port = NonZeroU16::new(TPROXY_PORT).expect("TPROXY port is nonzero");
        let artifact =
            compile_tproxy_engine_config(TproxyEngineConfigRequest::new(&template, listener_port))
                .map_err(|error| format!("compile supervised-producer config: {error}"))?;
        let directory = tempfile::tempdir()
            .map_err(|error| format!("create supervised-producer fixture directory: {error}"))?;
        let config = directory.path().join("config.json");
        fs::write(&config, artifact.bytes())
            .map_err(|error| format!("write supervised-producer config: {error}"))?;
        let spec = EngineSpec::new(
            SingBoxLaunchSpec {
                binary: binary.clone(),
                config: config.clone(),
                working_directory: directory.path().to_path_buf(),
                log: directory.path().join("engine.log"),
                privilege: SingBoxPrivilege::Inherit,
                readiness: SingBoxReadiness::Listener {
                    port: listener_port,
                },
                startup_timeout: Duration::from_secs(3),
                stop_timeout: PRODUCER_STOP_TIMEOUT,
            },
            RestartPolicy::new(
                1,
                Duration::from_secs(1),
                Duration::from_millis(10),
                Duration::from_millis(10),
                Duration::from_secs(1),
            )
            .map_err(|error| format!("construct supervised-producer restart policy: {error}"))?,
        )
        .map_err(|error| format!("inspect supervised-producer artifacts: {error}"))?;
        let binding = bind_engine_config_to_spec(artifact, &spec)
            .map_err(|error| format!("bind supervised-producer config: {error}"))?;
        let profile = declare_supervised_delivery_report_profile_fixture(
            collect_tproxy_engine_capability_profile(&binding, &spec)
                .map_err(|error| format!("profile supervised producer: {error}"))?,
        );
        let pinned = PinnedSingBoxLaunch::new(
            File::open(&binary).map_err(|error| format!("open supervised producer: {error}"))?,
            File::open(&config)
                .map_err(|error| format!("open supervised-producer config: {error}"))?,
        )
        .map_err(|error| format!("pin supervised-producer artifacts: {error}"))?;
        Ok(Self {
            _directory: directory,
            fixture: ProducerFixture {
                spec,
                profile,
                pinned,
                adapter: SingBoxProcessAdapter,
            },
            sinks,
        })
    }

    fn start_sinks(&self) -> Result<SinkWorkers, String> {
        self.sinks.spawn()
    }

    fn spawn(&self) -> Result<ProducerGuard<'_>, String> {
        let child = self
            .fixture
            .adapter
            .spawn_pinned(&self.fixture.pinned, self.fixture.spec.process())
            .map_err(|error| format!("spawn supervised producer: {error}"))?;
        Ok(ProducerGuard {
            fixture: &self.fixture,
            child: Some(child),
        })
    }
}

fn producer_binary() -> Result<PathBuf, String> {
    let path = env::var_os(PRODUCER_BINARY_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{PRODUCER_BINARY_ENV} is required"))?;
    if !path.is_absolute() {
        return Err(format!("{PRODUCER_BINARY_ENV} must be absolute"));
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("inspect supervised producer: {error}"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("supervised producer must be a regular non-symlink file".to_owned());
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err("supervised producer must be executable".to_owned());
    }
    let canonical = fs::canonicalize(&path)
        .map_err(|error| format!("canonicalize supervised producer: {error}"))?;
    if canonical != path {
        return Err(format!(
            "{PRODUCER_BINARY_ENV} must already be canonical: supplied={path:?} canonical={canonical:?}"
        ));
    }
    Ok(canonical)
}

struct ProducerFixture {
    spec: EngineSpec,
    profile: EngineCapabilityProfile,
    pinned: PinnedSingBoxLaunch,
    adapter: SingBoxProcessAdapter,
}

struct ProducerGuard<'a> {
    fixture: &'a ProducerFixture,
    child: Option<SingBoxChild>,
}

impl ProducerGuard<'_> {
    fn child(&self) -> &SingBoxChild {
        self.child
            .as_ref()
            .expect("live producer guard retains its child")
    }

    fn child_mut(&mut self) -> &mut SingBoxChild {
        self.child
            .as_mut()
            .expect("live producer guard retains its child")
    }

    fn wait_ready(&mut self) -> Result<(), String> {
        let process = self.fixture.spec.process().clone();
        self.fixture
            .adapter
            .wait_ready(self.child_mut(), &process)
            .map(|_| ())
            .map_err(|error| format!("wait for supervised producer readiness: {error}"))
    }

    fn ensure_running(&mut self) -> Result<(), String> {
        match self
            .fixture
            .adapter
            .try_wait(self.child_mut())
            .map_err(|error| format!("poll supervised producer: {error}"))?
        {
            None => Ok(()),
            Some(exit) => Err(format!(
                "supervised producer exited before explicit termination: {exit:?}"
            )),
        }
    }

    fn terminate(&mut self) -> Result<(), String> {
        let adapter = self.fixture.adapter;
        adapter
            .terminate(self.child_mut(), PRODUCER_STOP_TIMEOUT)
            .map_err(|error| format!("terminate and reap supervised producer: {error}"))?;
        self.child.take();
        Ok(())
    }
}

impl Drop for ProducerGuard<'_> {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.terminate();
        }
    }
}

fn exercise_attempt_lifecycle(
    config: &LocalOutputConfig,
    fixture: &ProducerFixture,
    child: &SingBoxChild,
) -> Result<(), String> {
    let first_request = request_for_child(fixture, child, [0xa1; FUNCTIONAL_CANARY_NONCE_BYTES]);
    let first_authority = collector::SupervisedDeliveryReportPrebindAuthority::fixture(
        &fixture.profile,
        &first_request,
    );
    let (first_producer, first_collector) = collector::prebind(first_authority, Instant::now)
        .map_err(|error| format!("prebind first supervised report: {error}"))?;
    let first_installed = first_producer
        .into_engine_handoff()
        .install_into(child)
        .map_err(|error| format!("install first supervised report: {error}"))?;
    if first_installed.child() != first_request.pre_binding().engine().engine() {
        return Err("first report handoff changed child identity".to_owned());
    }

    let overlap_request = request_for_child(fixture, child, [0xa2; FUNCTIONAL_CANARY_NONCE_BYTES]);
    let overlap_authority = collector::SupervisedDeliveryReportPrebindAuthority::fixture(
        &fixture.profile,
        &overlap_request,
    );
    let (overlap_producer, overlap_collector) = collector::prebind(overlap_authority, Instant::now)
        .map_err(|error| format!("prebind overlapping supervised report: {error}"))?;
    let _overlap_installed = overlap_producer
        .into_engine_handoff()
        .install_into(child)
        .map_err(|error| format!("transfer overlapping supervised report: {error}"))?;
    if !matches!(
        overlap_collector
            .recv_fixture_record_until(1, Instant::now() + Duration::from_secs(1))
            .map_err(|error| format!("observe overlapping report rejection: {error}"))?,
        Some(SeqpacketReceive::Eof)
    ) {
        return Err("overlapping supervised report was not rejected by exact EOF".to_owned());
    }
    if first_collector
        .recv_fixture_record_until(1, Instant::now() + Duration::from_millis(100))
        .map_err(|error| format!("inspect admitted first report: {error}"))?
        .is_some()
    {
        return Err("first supervised report stopped while overlap was rejected".to_owned());
    }
    drop(first_collector);

    let successor_request =
        request_for_child(fixture, child, [0xa3; FUNCTIONAL_CANARY_NONCE_BYTES]);
    let expected_report_object = successor_request
        .pre_binding()
        .environment()
        .attempt_objects()
        .listener_delivery_report();
    let successor_authority = collector::SupervisedDeliveryReportPrebindAuthority::fixture(
        &fixture.profile,
        &successor_request,
    );
    let (successor_producer, mut successor_collector) =
        collector::prebind(successor_authority, Instant::now)
            .map_err(|error| format!("prebind successor supervised report: {error}"))?;
    let _successor_installed = successor_producer
        .into_engine_handoff()
        .install_into(child)
        .map_err(|error| format!("install successor supervised report: {error}"))?;

    let mut client_tuples = [None; FUNCTIONAL_CANARY_FLOW_SLOTS];
    for flow in CanaryFlow::ALL {
        let payload = flow_payload(&successor_request, flow)?;
        let destination = SocketAddr::new(
            successor_request.peer_address(flow),
            successor_request.responder_port(flow).get(),
        );
        let source = SocketAddr::new(config.source(flow_family(flow)), 0);
        let tuple = match flow.protocol() {
            CanaryFlowProtocol::Tcp => {
                let (stream, tuple) = send_tcp_flow(source, destination, &payload)?;
                successor_collector
                    .ingest_fixture_record_until(successor_request.deadline().expires_at())
                    .map_err(|error| format!("collect {flow:?} supervised report: {error}"))?;
                drop(stream);
                tuple
            }
            CanaryFlowProtocol::Udp => {
                let (socket, tuple) = send_udp_flow(source, destination, &payload)?;
                successor_collector
                    .ingest_fixture_record_until(successor_request.deadline().expires_at())
                    .map_err(|error| format!("collect {flow:?} supervised report: {error}"))?;
                drop(socket);
                tuple
            }
        };
        client_tuples[flow.index()] = Some(tuple);
    }

    let drained = successor_collector
        .drain()
        .map_err(|failed| format!("drain successor supervised report: {failed}"))?;
    if drained.report_object() != expected_report_object
        || drained.profile_revision() != fixture.profile.revision()
        || drained.terminal_observed_at() > drained.eof_observed_at()
    {
        return Err("completed supervised report changed its binding or chronology".to_owned());
    }
    for flow in CanaryFlow::ALL {
        let expected = client_tuples[flow.index()]
            .ok_or_else(|| format!("missing actual client tuple for {flow:?}"))?;
        if drained.delivery_tuple(flow) != Some(expected) {
            return Err(format!(
                "{flow:?} report tuple differs from the actual client tuple: expected={expected:?} observed={:?}",
                drained.delivery_tuple(flow)
            ));
        }
    }
    Ok(())
}

fn request_for_child(
    fixture: &ProducerFixture,
    child: &SingBoxChild,
    nonce: [u8; FUNCTIONAL_CANARY_NONCE_BYTES],
) -> CanaryAttemptRequest {
    let identity = child.identity();
    request_with_engine_profile_revision_and_duration(
        &fixture.spec,
        CanaryAddressFamilies::Ipv4AndIpv6,
        Instant::now(),
        CanaryNonce::from_bytes(nonce),
        GenerationId::new(29).expect("supervised-producer generation is nonzero"),
        NonZeroU32::new(identity.pid()).expect("supervised-producer PID is nonzero"),
        NonZeroU64::new(identity.start_time_ticks())
            .expect("supervised-producer start ticks are nonzero"),
        NonZeroU64::new(31).expect("supervised-producer snapshot revision is nonzero"),
        fixture.profile.revision(),
        MAX_FUNCTIONAL_CANARY_DURATION,
    )
}

fn flow_family(flow: CanaryFlow) -> AddressFamily {
    if flow.is_ipv4() {
        AddressFamily::Ipv4
    } else {
        AddressFamily::Ipv6
    }
}

fn flow_payload(request: &CanaryAttemptRequest, flow: CanaryFlow) -> Result<Vec<u8>, String> {
    match flow.kind() {
        CanaryFlowKind::TcpEcho | CanaryFlowKind::UdpEcho => {
            Ok(request.nonce().as_bytes().to_vec())
        }
        CanaryFlowKind::DnsUdp | CanaryFlowKind::DnsTcp => {
            let expected = request
                .expected_dns(flow)
                .ok_or_else(|| format!("missing DNS expectation for {flow:?}"))?;
            let question = expected.question();
            let mut query = Vec::with_capacity(99);
            query.extend_from_slice(&expected.transaction_id().to_be_bytes());
            query.extend_from_slice(&0x0100_u16.to_be_bytes());
            query.extend_from_slice(&1_u16.to_be_bytes());
            query.extend_from_slice(&[0; 6]);
            query.extend_from_slice(question.wire_name());
            query.extend_from_slice(&question.record_type().to_be_bytes());
            query.extend_from_slice(&1_u16.to_be_bytes());
            if flow.kind() == CanaryFlowKind::DnsTcp {
                let length = u16::try_from(query.len())
                    .map_err(|_| "DNS query length does not fit u16".to_owned())?;
                let mut framed = Vec::with_capacity(query.len() + 2);
                framed.extend_from_slice(&length.to_be_bytes());
                framed.extend_from_slice(&query);
                Ok(framed)
            } else {
                Ok(query)
            }
        }
    }
}

fn send_tcp_flow(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
) -> Result<(TcpStream, CanaryFlowTuple), String> {
    let (mut stream, initial_mark) = connect_marked_tcp(source, destination, 0, IO_TIMEOUT)?;
    let connected_mark = tcp_socket_mark(&stream)?;
    if initial_mark != 0 || mark_role(connected_mark) != 0 {
        return Err(format!(
            "supervised TCP client entered the owned mark field: initial={initial_mark:#x} connected={connected_mark:#x}"
        ));
    }
    stream
        .write_all(payload)
        .map_err(|error| format!("write supervised TCP payload: {error}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|error| format!("half-close supervised TCP payload: {error}"))?;
    let local = stream
        .local_addr()
        .map_err(|error| format!("read supervised TCP client source: {error}"))?;
    let remote = stream
        .peer_addr()
        .map_err(|error| format!("read supervised TCP client destination: {error}"))?;
    if local.ip() != source.ip() || remote != destination {
        return Err(format!(
            "supervised TCP client tuple changed: source={local} destination={remote}"
        ));
    }
    Ok((stream, CanaryFlowTuple::new(local, remote)))
}

fn send_udp_flow(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
) -> Result<(UdpSocket, CanaryFlowTuple), String> {
    let (socket, initial_mark) = connect_marked_udp(source, destination, 0, IO_TIMEOUT)?;
    let connected_mark = udp_socket_mark(&socket)?;
    if initial_mark != 0 || mark_role(connected_mark) != 0 {
        return Err(format!(
            "supervised UDP client entered the owned mark field: initial={initial_mark:#x} connected={connected_mark:#x}"
        ));
    }
    let sent = socket
        .send(payload)
        .map_err(|error| format!("send supervised UDP payload: {error}"))?;
    if sent != payload.len() {
        return Err(format!(
            "supervised UDP payload was partial: sent={sent} expected={}",
            payload.len()
        ));
    }
    let local = socket
        .local_addr()
        .map_err(|error| format!("read supervised UDP client source: {error}"))?;
    let remote = socket
        .peer_addr()
        .map_err(|error| format!("read supervised UDP client destination: {error}"))?;
    if local.ip() != source.ip() || remote != destination {
        return Err(format!(
            "supervised UDP client tuple changed: source={local} destination={remote}"
        ));
    }
    Ok((socket, CanaryFlowTuple::new(local, remote)))
}

struct PreparedSinks {
    port: NonZeroU16,
    tcp: TcpListener,
    udp: UdpSocket,
}

impl PreparedSinks {
    fn bind() -> Result<Self, String> {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| format!("bind supervised TCP sink: {error}"))?;
        tcp.set_nonblocking(true)
            .map_err(|error| format!("make supervised TCP sink nonblocking: {error}"))?;
        let port = NonZeroU16::new(
            tcp.local_addr()
                .map_err(|error| format!("inspect supervised TCP sink: {error}"))?
                .port(),
        )
        .ok_or_else(|| "supervised TCP sink received port zero".to_owned())?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, port.get()))
            .map_err(|error| format!("bind supervised UDP sink: {error}"))?;
        udp.set_read_timeout(Some(SINK_TIMEOUT))
            .map_err(|error| format!("bound supervised UDP sink timeout: {error}"))?;
        Ok(Self { port, tcp, udp })
    }

    fn spawn(&self) -> Result<SinkWorkers, String> {
        let tcp = self
            .tcp
            .try_clone()
            .map_err(|error| format!("clone supervised TCP sink: {error}"))?;
        let udp = self
            .udp
            .try_clone()
            .map_err(|error| format!("clone supervised UDP sink: {error}"))?;
        let tcp = thread::spawn(move || run_tcp_sink(tcp));
        let udp = thread::spawn(move || run_udp_sink(udp));
        Ok(SinkWorkers { tcp, udp })
    }
}

struct SinkWorkers {
    tcp: JoinHandle<Result<(), String>>,
    udp: JoinHandle<Result<(), String>>,
}

impl SinkWorkers {
    fn join(self) -> Result<(), String> {
        let tcp = self
            .tcp
            .join()
            .map_err(|_| "supervised TCP sink panicked".to_owned())?;
        let udp = self
            .udp
            .join()
            .map_err(|_| "supervised UDP sink panicked".to_owned())?;
        match (tcp, udp) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(tcp_error), Err(udp_error)) => {
                Err(format!("{tcp_error}; UDP sink also failed: {udp_error}"))
            }
        }
    }
}

fn run_tcp_sink(listener: TcpListener) -> Result<(), String> {
    let deadline = Instant::now() + SINK_TIMEOUT;
    for index in 0..EXPECTED_TCP_SINK_FLOWS {
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(format!("supervised TCP sink timed out before flow {index}"));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(format!("accept supervised TCP sink: {error}")),
            }
        };
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| format!("bound supervised TCP sink read: {error}"))?;
        let mut payload = Vec::new();
        stream
            .read_to_end(&mut payload)
            .map_err(|error| format!("read supervised TCP sink flow {index}: {error}"))?;
        if payload.is_empty() {
            return Err(format!("supervised TCP sink flow {index} was empty"));
        }
    }
    Ok(())
}

fn run_udp_sink(socket: UdpSocket) -> Result<(), String> {
    let mut payload = [0_u8; 512];
    for index in 0..EXPECTED_UDP_SINK_FLOWS {
        let (length, _) = socket
            .recv_from(&mut payload)
            .map_err(|error| format!("receive supervised UDP sink flow {index}: {error}"))?;
        if length == 0 {
            return Err(format!("supervised UDP sink flow {index} was empty"));
        }
    }
    Ok(())
}

#[derive(Clone)]
struct SelectorCounterComments {
    protocol: &'static str,
    port: u16,
    mark: String,
    output: String,
    tproxy: String,
    leak: String,
}

#[derive(Clone)]
struct SupervisedFamilyComments {
    selectors: Vec<SelectorCounterComments>,
    unexpected_output: String,
    unexpected_prerouting: String,
}

impl SupervisedFamilyComments {
    fn new(family: &str, suffix: &str) -> Self {
        let prefix = format!("sp{family}{suffix}");
        let selectors = [
            ("tcp", TCP_PORT, "te"),
            ("udp", UDP_PORT, "ue"),
            ("udp", DNS_PORT, "du"),
            ("tcp", DNS_PORT, "dt"),
        ]
        .into_iter()
        .map(|(protocol, port, tag)| SelectorCounterComments {
            protocol,
            port,
            mark: format!("{prefix}{tag}m"),
            output: format!("{prefix}{tag}o"),
            tproxy: format!("{prefix}{tag}t"),
            leak: format!("{prefix}{tag}l"),
        })
        .collect();
        Self {
            selectors,
            unexpected_output: format!("{prefix}xo"),
            unexpected_prerouting: format!("{prefix}xp"),
        }
    }
}

struct SupervisedCounterComments {
    ipv4: SupervisedFamilyComments,
    ipv6: SupervisedFamilyComments,
}

impl SupervisedCounterComments {
    fn new(suffix: &str) -> Self {
        Self {
            ipv4: SupervisedFamilyComments::new("4", suffix),
            ipv6: SupervisedFamilyComments::new("6", suffix),
        }
    }

    fn family(&self, family: AddressFamily) -> &SupervisedFamilyComments {
        match family {
            AddressFamily::Ipv4 => &self.ipv4,
            AddressFamily::Ipv6 => &self.ipv6,
        }
    }
}

fn supervised_rule_plan(
    config: &LocalOutputConfig,
    family: AddressFamily,
    comments: &SupervisedFamilyComments,
) -> RulePlan {
    let (program, output_chain, prerouting_chain, source, destination, on_ip) = match family {
        AddressFamily::Ipv4 => (
            "iptables",
            &config.chains.ipv4_output,
            &config.chains.ipv4_prerouting,
            format!("{}/32", config.ipv4_source),
            format!("{}/32", config.ipv4_destination),
            "0.0.0.0",
        ),
        AddressFamily::Ipv6 => (
            "ip6tables",
            &config.chains.ipv6_output,
            &config.chains.ipv6_prerouting,
            format!("{}/128", config.ipv6_source),
            format!("{}/128", config.ipv6_destination),
            "::",
        ),
    };
    let mut output_rules = Vec::new();
    let mut prerouting_rules = Vec::new();
    let mut postrouting_guards = Vec::new();
    let mut prerouting_hooks = Vec::new();
    let mut activation_hooks = Vec::new();
    for selector in &comments.selectors {
        let port = selector.port.to_string();
        output_rules.push(strings(&[
            "-t",
            "mangle",
            "-A",
            output_chain,
            "-s",
            &source,
            "-d",
            &destination,
            "-p",
            selector.protocol,
            "--dport",
            &port,
            "-m",
            "mark",
            "--mark",
            &format!("0x0/{PROXY_MASK:#x}"),
            "-m",
            "comment",
            "--comment",
            &selector.mark,
            "-j",
            "MARK",
            "--set-xmark",
            &format!("{PROXY_MARK:#x}/{PROXY_MASK:#x}"),
        ]));
        output_rules.push(strings(&[
            "-t",
            "mangle",
            "-A",
            output_chain,
            "-s",
            &source,
            "-d",
            &destination,
            "-p",
            selector.protocol,
            "--dport",
            &port,
            "-m",
            "mark",
            "--mark",
            &format!("{PROXY_MARK:#x}/{PROXY_MASK:#x}"),
            "-m",
            "comment",
            "--comment",
            &selector.output,
            "-j",
            "ACCEPT",
        ]));
        prerouting_rules.push(strings(&[
            "-t",
            "mangle",
            "-A",
            prerouting_chain,
            "-s",
            &source,
            "-d",
            &destination,
            "-p",
            selector.protocol,
            "--dport",
            &port,
            "-m",
            "mark",
            "--mark",
            &format!("{PROXY_MARK:#x}/{PROXY_MASK:#x}"),
            "-m",
            "comment",
            "--comment",
            &selector.tproxy,
            "-j",
            "TPROXY",
            "--on-ip",
            on_ip,
            "--on-port",
            &TPROXY_PORT.to_string(),
            "--tproxy-mark",
            &format!("{PROXY_MARK:#x}/{PROXY_MASK:#x}"),
        ]));
        postrouting_guards.push(strings(&[
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
            selector.protocol,
            "--dport",
            &port,
            "-m",
            "comment",
            "--comment",
            &selector.leak,
            "-j",
            "DROP",
        ]));
        prerouting_hooks.push(strings(&[
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
            selector.protocol,
            "--dport",
            &port,
            "-j",
            prerouting_chain,
        ]));
        activation_hooks.push(strings(&[
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
            selector.protocol,
            "--dport",
            &port,
            "-m",
            "mark",
            "--mark",
            &format!("0x0/{PROXY_MASK:#x}"),
            "-j",
            output_chain,
        ]));
    }
    output_rules.push(strings(&[
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
    ]));
    prerouting_rules.push(strings(&[
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
    ]));
    RulePlan {
        family,
        expected_selectors: comments
            .selectors
            .iter()
            .map(|selector| (selector.protocol.to_owned(), selector.port))
            .collect(),
        program: program.to_owned(),
        output_chain: output_chain.clone(),
        prerouting_chain: prerouting_chain.clone(),
        output_rules,
        prerouting_rules,
        postrouting_guards,
        prerouting_hooks,
        response_output_hooks: Vec::new(),
        activation_hooks,
    }
}

#[derive(Clone, Copy)]
enum CounterExpectation {
    Zero,
    Positive,
}

fn validate_supervised_counters(
    comments: &SupervisedCounterComments,
    expectation: CounterExpectation,
) -> Result<(), String> {
    for (family, program) in [
        (AddressFamily::Ipv4, "iptables-save"),
        (AddressFamily::Ipv6, "ip6tables-save"),
    ] {
        let dump = command_output(program, &["-c", "-t", "mangle"])?;
        let comments = comments.family(family);
        for selector in &comments.selectors {
            let counters = [
                ("mark", packet_count_for_comment(&dump, &selector.mark)?),
                ("output", packet_count_for_comment(&dump, &selector.output)?),
                ("TPROXY", packet_count_for_comment(&dump, &selector.tproxy)?),
            ];
            let leak = packet_count_for_comment(&dump, &selector.leak)?;
            match expectation {
                CounterExpectation::Zero
                    if counters.iter().any(|(_, count)| *count != 0) || leak != 0 =>
                {
                    return Err(format!(
                        "{} {}/{} supervised counters were nonzero before traffic: counters={counters:?} leak={leak}",
                        family.label(),
                        selector.protocol,
                        selector.port
                    ));
                }
                CounterExpectation::Positive
                    if counters
                        .iter()
                        .any(|(_, count)| !(1..=MAX_SELECTOR_PACKETS).contains(count))
                        || leak != 0 =>
                {
                    return Err(format!(
                        "{} {}/{} supervised counters are outside bounds: counters={counters:?} leak={leak}",
                        family.label(),
                        selector.protocol,
                        selector.port
                    ));
                }
                CounterExpectation::Zero | CounterExpectation::Positive => {}
            }
        }
        let unexpected_output = packet_count_for_comment(&dump, &comments.unexpected_output)?;
        let unexpected_prerouting =
            packet_count_for_comment(&dump, &comments.unexpected_prerouting)?;
        if unexpected_output != 0 || unexpected_prerouting != 0 {
            return Err(format!(
                "{} supervised unexpected counters are nonzero: output={unexpected_output} prerouting={unexpected_prerouting}",
                family.label()
            ));
        }
    }
    Ok(())
}
