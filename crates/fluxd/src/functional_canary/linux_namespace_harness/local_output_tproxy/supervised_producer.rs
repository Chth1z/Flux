use super::*;

use std::io::{Read, Write};
use std::net::Shutdown;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread::JoinHandle;

use flux_core::GenerationId;
use flux_platform::internal::{
    PinnedSingBoxLaunch, SingBoxChild, SingBoxProcessAdapter, TerminationOutcome,
};
use flux_platform::{SeqpacketReceive, SingBoxLaunchSpec, SingBoxPrivilege, SingBoxReadiness};

use crate::functional_canary::supervised_delivery_report::collector;
use crate::functional_canary::tests::{
    fixture_responder_ports, request_with_engine_profile_revision_and_duration,
};
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
const EXPECTED_TCP_SINK_FLOWS: usize = 4;
const EXPECTED_UDP_SINK_FLOWS: usize = 4;
const SINK_TIMEOUT: Duration = Duration::from_secs(10);
const SINK_POLL_INTERVAL: Duration = Duration::from_millis(50);
const SINK_PORT: u16 = 41_390;
const PRODUCER_STOP_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_SELECTOR_PACKETS: u64 = 64;
const TCP_ECHO_PAYLOAD_BYTES: usize = FUNCTIONAL_CANARY_NONCE_BYTES;
const EXPECTED_SUPERVISED_CONFIG_SHA256: [u8; 32] = [
    0xea, 0x16, 0xae, 0xf2, 0x57, 0x78, 0xcc, 0x74, 0xae, 0x44, 0xba, 0xa3, 0x04, 0x63, 0xca, 0xb5,
    0xb2, 0xef, 0xb9, 0x8c, 0xbc, 0x2c, 0x6c, 0x7c, 0x90, 0x5a, 0xa7, 0x01, 0x32, 0x18, 0xf2, 0x83,
];

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

    let before_request_nonce = [0xb1; FUNCTIONAL_CANARY_NONCE_BYTES];
    let before_collector = run_with_producer(&prepared, |producer| {
        producer.wait_ready()?;
        let request = request_for_child(prepared.fixture(), producer.child(), before_request_nonce);
        let authority = collector::SupervisedDeliveryReportPrebindAuthority::fixture(
            &prepared.fixture().profile,
            &request,
        );
        let (report_producer, report_collector) = collector::prebind(authority, Instant::now)
            .map_err(|error| format!("prebind pre-emission termination report: {error}"))?;
        let _installed = report_producer
            .into_engine_handoff()
            .install_into(producer.child())
            .map_err(|error| format!("install pre-emission termination report: {error}"))?;
        if report_collector
            .recv_fixture_record_until(1, Instant::now() + Duration::from_millis(100))
            .map_err(|error| format!("inspect pre-emission termination report: {error}"))?
            .is_some()
        {
            return Err("pre-emission attempt produced a report before traffic".to_owned());
        }
        Ok(report_collector)
    })?;
    if !matches!(
        before_collector
            .recv_fixture_record_until(1, Instant::now() + PRODUCER_STOP_TIMEOUT)
            .map_err(|error| format!("observe pre-emission producer termination: {error}"))?,
        Some(SeqpacketReceive::Eof)
    ) {
        return Err(
            "pre-emission producer termination did not close the report endpoint".to_owned(),
        );
    }

    let mut sinks = None;
    let execution = panic::catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let during_collector = run_with_producer(&prepared, |producer| {
            producer.wait_ready()?;
            let request = request_for_child(
                prepared.fixture(),
                producer.child(),
                [0xb2; FUNCTIONAL_CANARY_NONCE_BYTES],
            );
            let authority = collector::SupervisedDeliveryReportPrebindAuthority::fixture(
                &prepared.fixture().profile,
                &request,
            );
            let (report_producer, mut report_collector) =
                collector::prebind(authority, Instant::now)
                    .map_err(|error| format!("prebind mid-emission termination report: {error}"))?;
            let _installed = report_producer
                .into_engine_handoff()
                .install_into(producer.child())
                .map_err(|error| format!("install mid-emission termination report: {error}"))?;
            let flow = CanaryFlow::Ipv4TcpEcho;
            let payload = flow_payload(&request, flow)?;
            sinks = Some(prepared.start_sinks(SinkExpectations::one_tcp(payload.clone()))?);
            let destination = SocketAddr::new(
                request.peer_address(flow),
                request.responder_port(flow).get(),
            );
            let source = SocketAddr::new(resources.config.source(AddressFamily::Ipv4), 0);
            let (stream, _) = send_tcp_flow(source, destination, &payload)?;
            report_collector
                .ingest_fixture_record_until(request.deadline().expires_at())
                .map_err(|error| format!("collect mid-emission supervised report: {error}"))?;
            drop(stream);
            sinks
                .take()
                .ok_or_else(|| "mid-emission sink workers are missing".to_owned())?
                .join()?;
            Ok(report_collector)
        })?;
        if !matches!(
            during_collector
                .recv_fixture_record_until(1, Instant::now() + PRODUCER_STOP_TIMEOUT)
                .map_err(|error| format!("observe mid-emission producer termination: {error}"))?,
            Some(SeqpacketReceive::Eof)
        ) {
            return Err(
                "mid-emission producer termination did not close the incomplete report endpoint"
                    .to_owned(),
            );
        }

        run_with_producer(&prepared, |producer| {
            producer.wait_ready()?;
            exercise_attempt_lifecycle(&resources.config, &prepared, producer.child(), &mut sinks)?;
            validate_supervised_counters(&comments, CounterExpectation::Positive)?;
            sinks
                .take()
                .ok_or_else(|| "supervised sink workers are missing".to_owned())?
                .join()?;
            producer.ensure_running()
        })
    }))
    .unwrap_or_else(|payload| {
        Err(format!(
            "supervised producer execution panicked: {}",
            panic_message(payload)
        ))
    });
    let sink_cleanup = match sinks.take() {
        Some(sinks) => sinks.cancel_and_join(),
        None => Ok(()),
    };
    combine_results([
        ("supervised execution", execution),
        ("sink cleanup", sink_cleanup),
        ("module verification", resources.modules.verify()),
    ])
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
        let template = supervised_config_template(sinks.port)?;
        let listener_port = NonZeroU16::new(TPROXY_PORT).expect("TPROXY port is nonzero");
        let artifact =
            compile_tproxy_engine_config(TproxyEngineConfigRequest::new(&template, listener_port))
                .map_err(|error| format!("compile supervised-producer config: {error}"))?;
        if artifact.content_sha256() != &EXPECTED_SUPERVISED_CONFIG_SHA256 {
            return Err("supervised-producer canonical config digest drifted".to_owned());
        }
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

    fn start_sinks(&self, expectations: SinkExpectations) -> Result<SinkWorkers, String> {
        self.sinks.spawn(expectations)
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

    const fn fixture(&self) -> &ProducerFixture {
        &self.fixture
    }
}

fn supervised_config_template(sink_port: NonZeroU16) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&serde_json::json!({
        "log": { "disabled": true },
        "inbounds": [],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": {
            "rules": [{
                "action": "route",
                "outbound": "direct",
                "override_address": "127.0.0.1",
                "override_port": sink_port.get(),
            }],
        },
    }))
    .map_err(|error| format!("encode supervised-producer config template: {error}"))
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
        let mut child = self
            .child
            .take()
            .expect("live producer guard retains its child");
        let outcome = match adapter.terminate(&mut child, PRODUCER_STOP_TIMEOUT) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.child = Some(child);
                return Err(format!("terminate and reap supervised producer: {error}"));
            }
        };
        require_explicit_termination(outcome)?;
        if !matches!(
            child
                .launch_control()
                .recv_record_until(1, Instant::now() + PRODUCER_STOP_TIMEOUT)
                .map_err(|error| format!("observe supervised producer control EOF: {error}"))?,
            Some(SeqpacketReceive::Eof)
        ) {
            return Err(
                "terminated supervised producer retained its launch-control endpoint".to_owned(),
            );
        }
        Ok(())
    }
}

fn require_explicit_termination(outcome: TerminationOutcome) -> Result<(), String> {
    match outcome {
        TerminationOutcome::AlreadyExited { exit } => Err(format!(
            "supervised producer exited before explicit termination: {exit}"
        )),
        TerminationOutcome::Terminated { .. } | TerminationOutcome::Killed { .. } => Ok(()),
    }
}

impl Drop for ProducerGuard<'_> {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.terminate();
        }
    }
}

fn run_with_producer<T>(
    prepared: &PreparedProducer,
    operation: impl FnOnce(&mut ProducerGuard<'_>) -> Result<T, String>,
) -> Result<T, String> {
    let mut producer = prepared.spawn()?;
    let operation = panic::catch_unwind(AssertUnwindSafe(|| operation(&mut producer)))
        .unwrap_or_else(|payload| {
            Err(format!(
                "supervised producer phase panicked: {}",
                panic_message(payload)
            ))
        });
    finish_with_required_cleanup(operation, || producer.terminate())
}

fn finish_with_required_cleanup<T>(
    operation: Result<T, String>,
    cleanup: impl FnOnce() -> Result<(), String>,
) -> Result<T, String> {
    let cleanup = panic::catch_unwind(AssertUnwindSafe(cleanup)).unwrap_or_else(|payload| {
        Err(format!(
            "producer cleanup panicked: {}",
            panic_message(payload)
        ))
    });
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(format!("producer cleanup failed: {cleanup_error}")),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; producer cleanup also failed: {cleanup_error}"
        )),
    }
}

fn combine_results<const N: usize>(
    results: [(&'static str, Result<(), String>); N],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for (label, result) in results {
        if let Err(error) = result {
            errors.push(format!("{label} failed: {error}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn exercise_attempt_lifecycle(
    config: &LocalOutputConfig,
    prepared: &PreparedProducer,
    child: &SingBoxChild,
    sinks: &mut Option<SinkWorkers>,
) -> Result<(), String> {
    let fixture = prepared.fixture();
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
    *sinks = Some(prepared.start_sinks(SinkExpectations::for_request(&successor_request)?)?);

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
                let (socket, tuple) =
                    send_udp_flow(udp_send_mode(flow)?, source, destination, &payload)?;
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
    mode: UdpSendMode,
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
) -> Result<(UdpSocket, CanaryFlowTuple), String> {
    let (socket, initial_mark) = match mode {
        UdpSendMode::Connected => connect_marked_udp(source, destination, 0, IO_TIMEOUT)?,
        UdpSendMode::Unconnected => bind_marked_udp(source, 0, IO_TIMEOUT)?,
    };
    let observed_mark = udp_socket_mark(&socket)?;
    if initial_mark != 0 || mark_role(observed_mark) != 0 {
        return Err(format!(
            "supervised UDP client entered the owned mark field: initial={initial_mark:#x} observed={observed_mark:#x}"
        ));
    }
    let sent = match mode {
        UdpSendMode::Connected => socket.send(payload),
        UdpSendMode::Unconnected => socket.send_to(payload, destination),
    }
    .map_err(|error| format!("send supervised {mode:?} UDP payload: {error}"))?;
    if sent != payload.len() {
        return Err(format!(
            "supervised UDP payload was partial: sent={sent} expected={}",
            payload.len()
        ));
    }
    let local = socket
        .local_addr()
        .map_err(|error| format!("read supervised UDP client source: {error}"))?;
    let remote = match mode {
        UdpSendMode::Connected => socket
            .peer_addr()
            .map_err(|error| format!("read supervised UDP client destination: {error}"))?,
        UdpSendMode::Unconnected => match socket.peer_addr() {
            Err(error) if error.kind() == std::io::ErrorKind::NotConnected => destination,
            Err(error) => {
                return Err(format!(
                    "inspect unconnected supervised UDP client peer: {error}"
                ));
            }
            Ok(peer) => {
                return Err(format!(
                    "unconnected supervised UDP client acquired peer {peer}"
                ));
            }
        },
    };
    if local.ip() != source.ip() || remote != destination {
        return Err(format!(
            "supervised UDP client tuple changed: source={local} destination={remote}"
        ));
    }
    Ok((socket, CanaryFlowTuple::new(local, remote)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpSendMode {
    Connected,
    Unconnected,
}

fn udp_send_mode(flow: CanaryFlow) -> Result<UdpSendMode, String> {
    match flow.kind() {
        CanaryFlowKind::UdpEcho => Ok(UdpSendMode::Connected),
        CanaryFlowKind::DnsUdp => Ok(UdpSendMode::Unconnected),
        CanaryFlowKind::TcpEcho | CanaryFlowKind::DnsTcp => {
            Err(format!("non-UDP flow {flow:?} requested a UDP send mode"))
        }
    }
}

struct SinkExpectations {
    tcp: Vec<Vec<u8>>,
    udp: Vec<Vec<u8>>,
}

impl SinkExpectations {
    fn one_tcp(payload: Vec<u8>) -> Self {
        Self {
            tcp: vec![payload],
            udp: Vec::new(),
        }
    }

    fn for_request(request: &CanaryAttemptRequest) -> Result<Self, String> {
        let mut tcp = Vec::with_capacity(EXPECTED_TCP_SINK_FLOWS);
        let mut udp = Vec::with_capacity(EXPECTED_UDP_SINK_FLOWS);
        for flow in CanaryFlow::ALL {
            let payload = flow_payload(request, flow)?;
            match flow.protocol() {
                CanaryFlowProtocol::Tcp => tcp.push(payload),
                CanaryFlowProtocol::Udp => udp.push(payload),
            }
        }
        if tcp.len() != EXPECTED_TCP_SINK_FLOWS || udp.len() != EXPECTED_UDP_SINK_FLOWS {
            return Err(format!(
                "supervised sink expectation count drifted: tcp={} udp={}",
                tcp.len(),
                udp.len()
            ));
        }
        Ok(Self { tcp, udp })
    }
}

struct PreparedSinks {
    port: NonZeroU16,
    tcp: TcpListener,
    udp: UdpSocket,
}

impl PreparedSinks {
    fn bind() -> Result<Self, String> {
        let port = NonZeroU16::new(SINK_PORT).expect("supervised sink port is nonzero");
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port.get()))
            .map_err(|error| format!("bind supervised TCP sink: {error}"))?;
        tcp.set_nonblocking(true)
            .map_err(|error| format!("make supervised TCP sink nonblocking: {error}"))?;
        if tcp
            .local_addr()
            .map_err(|error| format!("inspect supervised TCP sink: {error}"))?
            .port()
            != port.get()
        {
            return Err("supervised TCP sink changed its fixed port".to_owned());
        }
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, port.get()))
            .map_err(|error| format!("bind supervised UDP sink: {error}"))?;
        udp.set_read_timeout(Some(SINK_POLL_INTERVAL))
            .map_err(|error| format!("bound supervised UDP sink timeout: {error}"))?;
        Ok(Self { port, tcp, udp })
    }

    fn spawn(&self, expectations: SinkExpectations) -> Result<SinkWorkers, String> {
        let tcp = self
            .tcp
            .try_clone()
            .map_err(|error| format!("clone supervised TCP sink: {error}"))?;
        let udp = self
            .udp
            .try_clone()
            .map_err(|error| format!("clone supervised UDP sink: {error}"))?;
        let SinkExpectations {
            tcp: tcp_expectations,
            udp: udp_expectations,
        } = expectations;
        let cancel = Arc::new(AtomicBool::new(false));
        let tcp_cancel = Arc::clone(&cancel);
        let tcp = thread::Builder::new()
            .name("flux-supervised-tcp-sink".to_owned())
            .spawn(move || run_tcp_sink(tcp, tcp_expectations, &tcp_cancel))
            .map_err(|error| format!("spawn supervised TCP sink: {error}"))?;
        let mut workers = SinkWorkers {
            cancel,
            tcp: Some(tcp),
            udp: None,
        };
        let udp_cancel = Arc::clone(&workers.cancel);
        match thread::Builder::new()
            .name("flux-supervised-udp-sink".to_owned())
            .spawn(move || run_udp_sink(udp, udp_expectations, &udp_cancel))
        {
            Ok(udp) => {
                workers.udp = Some(udp);
                Ok(workers)
            }
            Err(error) => {
                let cleanup = workers.cancel_and_join();
                match cleanup {
                    Ok(()) => Err(format!("spawn supervised UDP sink: {error}")),
                    Err(cleanup_error) => Err(format!(
                        "spawn supervised UDP sink: {error}; partial sink cleanup also failed: {cleanup_error}"
                    )),
                }
            }
        }
    }
}

struct SinkWorkers {
    cancel: Arc<AtomicBool>,
    tcp: Option<JoinHandle<Result<(), String>>>,
    udp: Option<JoinHandle<Result<(), String>>>,
}

impl SinkWorkers {
    fn join(mut self) -> Result<(), String> {
        self.join_all()
    }

    fn cancel_and_join(mut self) -> Result<(), String> {
        self.cancel.store(true, Ordering::Release);
        self.join_all()
    }

    fn join_all(&mut self) -> Result<(), String> {
        let tcp = join_sink_worker(self.tcp.take(), "TCP");
        let udp = join_sink_worker(self.udp.take(), "UDP");
        match (tcp, udp) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(tcp_error), Err(udp_error)) => {
                Err(format!("{tcp_error}; UDP sink also failed: {udp_error}"))
            }
        }
    }
}

impl Drop for SinkWorkers {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        let _ = self.join_all();
    }
}

fn join_sink_worker(
    worker: Option<JoinHandle<Result<(), String>>>,
    label: &str,
) -> Result<(), String> {
    let Some(worker) = worker else {
        return Ok(());
    };
    worker
        .join()
        .map_err(|_| format!("supervised {label} sink panicked"))?
}

fn run_tcp_sink(
    listener: TcpListener,
    mut expectations: Vec<Vec<u8>>,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let deadline = Instant::now() + SINK_TIMEOUT;
    let expected_flows = expectations.len();
    for index in 0..expected_flows {
        let mut stream = loop {
            if cancel.load(Ordering::Acquire) {
                return Ok(());
            }
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
        let maximum_length = expectations
            .iter()
            .map(Vec::len)
            .max()
            .ok_or_else(|| "supervised TCP sink exhausted its expectations early".to_owned())?;
        let Some(payload) =
            read_bounded_tcp_payload_to_eof(&mut stream, maximum_length, deadline, cancel, index)?
        else {
            return Ok(());
        };
        take_matching_sink_expectation(&mut expectations, &payload, "TCP", index)?;
    }
    Ok(())
}

fn read_bounded_tcp_payload_to_eof(
    stream: &mut TcpStream,
    maximum_length: usize,
    deadline: Instant,
    cancel: &AtomicBool,
    index: usize,
) -> Result<Option<Vec<u8>>, String> {
    let mut payload = Vec::with_capacity(maximum_length);
    let mut buffer = [0_u8; 512];
    while payload.len() < maximum_length {
        let remaining = maximum_length - payload.len();
        let buffer_length = remaining.min(buffer.len());
        let Some(read) =
            read_tcp_with_deadline(stream, &mut buffer[..buffer_length], deadline, cancel)?
        else {
            return Ok(None);
        };
        if read == 0 {
            return Ok(Some(payload));
        }
        payload.extend_from_slice(&buffer[..read]);
    }
    let mut suffix = [0_u8; 1];
    match read_tcp_with_deadline(stream, &mut suffix, deadline, cancel)? {
        None => Ok(None),
        Some(0) => Ok(Some(payload)),
        Some(_) => Err(format!(
            "supervised TCP sink flow {index} exceeded the bounded {maximum_length}-byte payload cap"
        )),
    }
}

fn read_tcp_with_deadline(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Option<usize>, String> {
    loop {
        if cancel.load(Ordering::Acquire) {
            return Ok(None);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("supervised TCP sink reached its absolute deadline".to_owned());
        }
        stream
            .set_read_timeout(Some(remaining.min(SINK_POLL_INTERVAL)))
            .map_err(|error| format!("bound supervised TCP sink read: {error}"))?;
        match stream.read(buffer) {
            Ok(read) => return Ok(Some(read)),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(format!("read supervised TCP sink: {error}")),
        }
    }
}

fn run_udp_sink(
    socket: UdpSocket,
    mut expectations: Vec<Vec<u8>>,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let deadline = Instant::now() + SINK_TIMEOUT;
    let expected_flows = expectations.len();
    for index in 0..expected_flows {
        let maximum_length = expectations
            .iter()
            .map(Vec::len)
            .max()
            .ok_or_else(|| "supervised UDP sink exhausted its expectations early".to_owned())?;
        let mut payload = vec![0_u8; maximum_length + 1];
        loop {
            if cancel.load(Ordering::Acquire) {
                return Ok(());
            }
            match socket.recv_from(&mut payload) {
                Ok((length, _)) => {
                    take_matching_sink_expectation(
                        &mut expectations,
                        &payload[..length],
                        "UDP",
                        index,
                    )?;
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    if Instant::now() >= deadline {
                        return Err(format!("supervised UDP sink timed out before flow {index}"));
                    }
                }
                Err(error) => {
                    return Err(format!("receive supervised UDP sink flow {index}: {error}"));
                }
            }
        }
    }
    Ok(())
}

fn take_matching_sink_expectation(
    expectations: &mut Vec<Vec<u8>>,
    payload: &[u8],
    protocol: &str,
    index: usize,
) -> Result<(), String> {
    if let Some(position) = expectations
        .iter()
        .position(|expected| expected.as_slice() == payload)
    {
        expectations.swap_remove(position);
        return Ok(());
    }
    let remaining_lengths = expectations.iter().map(Vec::len).collect::<Vec<_>>();
    let detail = if remaining_lengths.contains(&payload.len()) {
        "payload differed from every remaining canonical value"
    } else {
        "payload length differed from every remaining canonical value"
    };
    Err(format!(
        "supervised {protocol} sink flow {index} {detail}: observed={} remaining={remaining_lengths:?}",
        payload.len()
    ))
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
        let ports = fixture_responder_ports();
        let selectors = [
            ("tcp", ports.tcp_echo().get(), "te"),
            ("udp", ports.udp_echo().get(), "ue"),
            ("udp", ports.dns().get(), "du"),
            ("tcp", ports.dns().get(), "dt"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    use flux_platform::SingBoxExit;

    #[test]
    fn explicit_termination_rejects_an_already_exited_producer() {
        assert_eq!(
            require_explicit_termination(TerminationOutcome::AlreadyExited {
                exit: SingBoxExit::Code(7),
            }),
            Err("supervised producer exited before explicit termination: exit code 7".to_owned())
        );
        for outcome in [
            TerminationOutcome::Terminated {
                exit: SingBoxExit::Signal(libc::SIGTERM),
            },
            TerminationOutcome::Killed {
                exit: SingBoxExit::Signal(libc::SIGKILL),
            },
        ] {
            assert!(require_explicit_termination(outcome).is_ok());
        }
    }

    #[test]
    fn supervised_selectors_match_fixture_responder_ports() {
        let ports = fixture_responder_ports();
        let comments = SupervisedFamilyComments::new("4", "12345678");
        let observed = comments
            .selectors
            .iter()
            .map(|selector| (selector.protocol, selector.port))
            .collect::<Vec<_>>();
        assert_eq!(
            observed,
            vec![
                ("tcp", ports.tcp_echo().get()),
                ("udp", ports.udp_echo().get()),
                ("udp", ports.dns().get()),
                ("tcp", ports.dns().get()),
            ]
        );
    }

    #[test]
    fn supervised_udp_flows_cover_connected_and_unconnected_clients() {
        assert_eq!(
            udp_send_mode(CanaryFlow::Ipv4UdpEcho),
            Ok(UdpSendMode::Connected)
        );
        assert_eq!(
            udp_send_mode(CanaryFlow::Ipv6UdpEcho),
            Ok(UdpSendMode::Connected)
        );
        assert_eq!(
            udp_send_mode(CanaryFlow::Ipv4DnsUdp),
            Ok(UdpSendMode::Unconnected)
        );
        assert_eq!(
            udp_send_mode(CanaryFlow::Ipv6DnsUdp),
            Ok(UdpSendMode::Unconnected)
        );
        assert!(udp_send_mode(CanaryFlow::Ipv4TcpEcho).is_err());
    }

    #[test]
    fn required_cleanup_runs_and_preserves_primary_and_cleanup_failures() {
        let called = Cell::new(false);
        let result = finish_with_required_cleanup(Err::<(), _>("primary".to_owned()), || {
            called.set(true);
            Err("cleanup".to_owned())
        });
        assert!(called.get());
        assert_eq!(
            result,
            Err("primary; producer cleanup also failed: cleanup".to_owned())
        );
    }

    #[test]
    fn sink_join_observes_both_workers_after_one_panics() {
        let udp_joined = Arc::new(AtomicBool::new(false));
        let udp_joined_by_worker = Arc::clone(&udp_joined);
        let workers = SinkWorkers {
            cancel: Arc::new(AtomicBool::new(false)),
            tcp: Some(thread::spawn(|| -> Result<(), String> {
                panic!("TCP sink fixture panic")
            })),
            udp: Some(thread::spawn(move || {
                udp_joined_by_worker.store(true, Ordering::Release);
                Ok(())
            })),
        };

        assert_eq!(
            workers.join(),
            Err("supervised TCP sink panicked".to_owned())
        );
        assert!(udp_joined.load(Ordering::Acquire));
    }

    #[test]
    fn tcp_sink_read_requires_exact_bytes_and_eof() {
        assert!(run_tcp_sink_read_case(vec![0x41; TCP_ECHO_PAYLOAD_BYTES]).is_ok());
        let error = run_tcp_sink_read_case(vec![0x42; TCP_ECHO_PAYLOAD_BYTES])
            .expect_err("same-length mismatch must fail exact payload identity");
        assert!(error.contains("payload differed from every remaining canonical value"));
        let error = run_tcp_sink_read_case(vec![0x41; TCP_ECHO_PAYLOAD_BYTES + 1])
            .expect_err("suffix must exceed the exact payload boundary");
        assert!(error.contains("exceeded the bounded 32-byte payload cap"));
    }

    fn run_tcp_sink_read_case(payload: Vec<u8>) -> Result<(), String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind TCP sink fixture");
        let address = listener.local_addr().expect("inspect TCP sink fixture");
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("connect TCP sink fixture");
            stream.write_all(&payload).expect("write TCP sink fixture");
            stream
                .shutdown(Shutdown::Write)
                .expect("half-close TCP sink fixture");
        });
        let (mut stream, _) = listener.accept().expect("accept TCP sink fixture");
        let cancel = AtomicBool::new(false);
        let result = read_bounded_tcp_payload_to_eof(
            &mut stream,
            TCP_ECHO_PAYLOAD_BYTES,
            Instant::now() + Duration::from_secs(1),
            &cancel,
            0,
        );
        client.join().expect("join TCP sink fixture client");
        let payload =
            result?.ok_or_else(|| "TCP sink fixture was unexpectedly cancelled".to_owned())?;
        let mut expectations = vec![vec![0x41; TCP_ECHO_PAYLOAD_BYTES]];
        take_matching_sink_expectation(&mut expectations, &payload, "TCP", 0)
    }

    #[test]
    fn udp_sink_rejects_a_same_length_payload_mismatch() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP sink fixture");
        let address = socket.local_addr().expect("inspect UDP sink fixture");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP client fixture");
        client
            .send_to(&[0x42; TCP_ECHO_PAYLOAD_BYTES], address)
            .expect("send UDP sink fixture payload");
        let cancel = AtomicBool::new(false);
        let error = run_udp_sink(socket, vec![vec![0x41; TCP_ECHO_PAYLOAD_BYTES]], &cancel)
            .expect_err("same-length UDP mismatch must fail exact payload identity");
        assert!(error.contains("payload differed from every remaining canonical value"));
    }

    #[test]
    fn sink_expectation_matching_allows_reordering_and_preserves_duplicate_counts() {
        let echo = vec![0x41; TCP_ECHO_PAYLOAD_BYTES];
        let dns = vec![0x42; TCP_ECHO_PAYLOAD_BYTES + 1];
        let mut expectations = vec![echo.clone(), echo.clone(), dns.clone()];

        assert!(take_matching_sink_expectation(&mut expectations, &dns, "UDP", 0).is_ok());
        assert_eq!(expectations, vec![echo.clone(), echo.clone()]);
        assert!(take_matching_sink_expectation(&mut expectations, &echo, "UDP", 1).is_ok());
        assert_eq!(expectations, vec![echo.clone()]);
        assert!(take_matching_sink_expectation(&mut expectations, &echo, "UDP", 2).is_ok());
        assert!(expectations.is_empty());
        assert!(take_matching_sink_expectation(&mut expectations, &echo, "UDP", 3).is_err());
    }

    #[test]
    fn supervised_config_is_fixed_port_and_content_digest_bound() {
        let sink_port = NonZeroU16::new(SINK_PORT).expect("fixed sink port is nonzero");
        let template = supervised_config_template(sink_port).expect("encode config template");
        let listener_port = NonZeroU16::new(TPROXY_PORT).expect("TPROXY port is nonzero");
        let artifact =
            compile_tproxy_engine_config(TproxyEngineConfigRequest::new(&template, listener_port))
                .expect("compile canonical supervised config");
        assert_eq!(
            artifact.content_sha256(),
            &EXPECTED_SUPERVISED_CONFIG_SHA256
        );
        assert!(
            std::str::from_utf8(artifact.bytes())
                .expect("canonical config is UTF-8")
                .contains("\"override_port\":41390")
        );
    }
}
