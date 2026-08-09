//! Fixed child traffic transaction for the packaged local-OUTPUT canary.
//!
//! This module owns only the authenticated parent/child wire protocol and the
//! direct echo/DNS socket exchange. It deliberately does not observe engine
//! sockets, counters, selectors, reports, or networking state.

use std::io::{Read, Write};
use std::mem::{size_of, zeroed};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use flux_platform::internal::RestrictedChildCredentials;
use flux_platform::{PeerCredentials, SeqpacketConnection, SeqpacketReceive};

use super::super::{
    CANARY_DNS_WIRE_NAME_BYTES, CanaryAttemptRequest, CanaryDnsExpectation, CanaryFlow,
    CanaryFlowKind, CanaryFlowTuple, FUNCTIONAL_CANARY_NONCE_BYTES,
};
use super::driver_child::{BoundChildResources, PackagedDriverChildError, PackagedDriverChildRole};

const TRAFFIC_MAGIC: [u8; 4] = *b"FCT1";
const TRAFFIC_HEADER_BYTES: usize = 12;
pub(super) const MAX_TRAFFIC_FRAME_BYTES: usize = 512;
const ENCODED_SOCKET_ADDRESS_BYTES: usize = 19;
const ENCODED_TUPLE_BYTES: usize = ENCODED_SOCKET_ADDRESS_BYTES * 2;
const MAX_WIRE_PAYLOAD_BYTES: usize = 256;
const DNS_HEADER_BYTES: usize = 12;
const DNS_QUESTION_FOOTER_BYTES: usize = 4;
const DNS_QUERY_BYTES: usize =
    DNS_HEADER_BYTES + CANARY_DNS_WIRE_NAME_BYTES + DNS_QUESTION_FOOTER_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum TrafficMessage {
    ArmFlow = 1,
    Armed = 2,
    RunFlow = 3,
    ClientHolding = 4,
    PeerObserved = 5,
    ReleaseResponse = 6,
    ClientResult = 7,
    PeerResult = 8,
}

impl TrafficMessage {
    fn parse(value: u8) -> Result<Self, PackagedDriverChildError> {
        match value {
            1 => Ok(Self::ArmFlow),
            2 => Ok(Self::Armed),
            3 => Ok(Self::RunFlow),
            4 => Ok(Self::ClientHolding),
            5 => Ok(Self::PeerObserved),
            6 => Ok(Self::ReleaseResponse),
            7 => Ok(Self::ClientResult),
            8 => Ok(Self::PeerResult),
            _ => Err(PackagedDriverChildError::Protocol(
                "driver traffic frame has an unknown message kind",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WireFlowPlan {
    flow: CanaryFlow,
    source: SocketAddr,
    destination: SocketAddr,
    request: Vec<u8>,
    response: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TrafficFlowPlan {
    wire: WireFlowPlan,
    dns: Option<CanaryDnsExpectation>,
}

impl TrafficFlowPlan {
    pub(super) fn for_request(
        request: &CanaryAttemptRequest,
        flow: CanaryFlow,
    ) -> Result<Self, PackagedDriverChildError> {
        if !request.requires_flow(flow) {
            return Err(PackagedDriverChildError::Protocol(
                "driver traffic requested a flow absent from the immutable request",
            ));
        }
        let source = SocketAddr::new(request.daemon_address(flow), 0);
        let destination = SocketAddr::new(
            request.peer_address(flow),
            request.responder_port(flow).get(),
        );
        let (request_payload, response_payload, dns) = match flow.kind() {
            CanaryFlowKind::TcpEcho | CanaryFlowKind::UdpEcho => {
                let payload = request.nonce().as_bytes().to_vec();
                (payload.clone(), payload, None)
            }
            CanaryFlowKind::DnsUdp | CanaryFlowKind::DnsTcp => {
                let expected =
                    request
                        .expected_dns(flow)
                        .ok_or(PackagedDriverChildError::Protocol(
                            "driver traffic DNS flow lacks its immutable expectation",
                        ))?;
                let query = canonical_dns_query(expected);
                let response = canonical_dns_response(&query, expected)?;
                if flow.kind() == CanaryFlowKind::DnsTcp {
                    (
                        frame_dns_tcp(&query)?,
                        frame_dns_tcp(&response)?,
                        Some(expected),
                    )
                } else {
                    (query, response, Some(expected))
                }
            }
        };
        let plan = Self {
            wire: WireFlowPlan {
                flow,
                source,
                destination,
                request: request_payload,
                response: response_payload,
            },
            dns,
        };
        validate_wire_plan(&plan.wire)?;
        Ok(plan)
    }

    #[must_use]
    pub(super) const fn flow(&self) -> CanaryFlow {
        self.wire.flow
    }

    #[must_use]
    pub(super) const fn source(&self) -> SocketAddr {
        self.wire.source
    }

    #[must_use]
    pub(super) const fn destination(&self) -> SocketAddr {
        self.wire.destination
    }

    #[must_use]
    pub(super) fn request_payload(&self) -> &[u8] {
        &self.wire.request
    }

    #[must_use]
    pub(super) fn response_payload(&self) -> &[u8] {
        &self.wire.response
    }

    #[must_use]
    pub(super) const fn dns(&self) -> Option<CanaryDnsExpectation> {
        self.dns
    }

    #[cfg(test)]
    pub(super) fn with_test_endpoints(
        mut self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Result<Self, PackagedDriverChildError> {
        self.wire.source = source;
        self.wire.destination = destination;
        validate_wire_plan(&self.wire)?;
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TrafficFlowResult {
    plan: TrafficFlowPlan,
    client_tuple: CanaryFlowTuple,
    peer_tuple: CanaryFlowTuple,
}

impl TrafficFlowResult {
    pub(super) fn new(
        plan: TrafficFlowPlan,
        client_tuple: CanaryFlowTuple,
        peer_tuple: CanaryFlowTuple,
    ) -> Result<Self, PackagedDriverChildError> {
        validate_client_tuple(&plan, client_tuple)?;
        validate_peer_tuple(&plan, peer_tuple)?;
        Ok(Self {
            plan,
            client_tuple,
            peer_tuple,
        })
    }

    #[must_use]
    pub(super) const fn flow(&self) -> CanaryFlow {
        self.plan.flow()
    }

    #[must_use]
    pub(super) const fn client_tuple(&self) -> CanaryFlowTuple {
        self.client_tuple
    }

    #[must_use]
    pub(super) const fn peer_tuple(&self) -> CanaryFlowTuple {
        self.peer_tuple
    }

    #[must_use]
    pub(super) fn request_payload(&self) -> &[u8] {
        self.plan.request_payload()
    }

    #[must_use]
    pub(super) fn response_payload(&self) -> &[u8] {
        self.plan.response_payload()
    }

    #[must_use]
    pub(super) const fn dns(&self) -> Option<CanaryDnsExpectation> {
        self.plan.dns()
    }
}

struct TrafficFrame {
    role: PackagedDriverChildRole,
    message: TrafficMessage,
    flow: CanaryFlow,
    payload: Vec<u8>,
}

impl TrafficFrame {
    fn new(
        role: PackagedDriverChildRole,
        message: TrafficMessage,
        flow: CanaryFlow,
        payload: Vec<u8>,
    ) -> Result<Self, PackagedDriverChildError> {
        if TRAFFIC_HEADER_BYTES + payload.len() > MAX_TRAFFIC_FRAME_BYTES {
            return Err(PackagedDriverChildError::Protocol(
                "driver traffic frame exceeds its fixed bound",
            ));
        }
        Ok(Self {
            role,
            message,
            flow,
            payload,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, PackagedDriverChildError> {
        let payload_length = u16::try_from(self.payload.len()).map_err(|_| {
            PackagedDriverChildError::Protocol(
                "driver traffic payload length cannot be represented",
            )
        })?;
        let mut bytes = Vec::with_capacity(TRAFFIC_HEADER_BYTES + self.payload.len());
        bytes.extend_from_slice(&TRAFFIC_MAGIC);
        bytes.push(self.role as u8);
        bytes.push(self.message as u8);
        bytes.push(self.flow as u8);
        bytes.push(0);
        bytes.extend_from_slice(&payload_length.to_be_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    fn parse(bytes: &[u8]) -> Result<Self, PackagedDriverChildError> {
        if bytes.len() < TRAFFIC_HEADER_BYTES
            || bytes[..4] != TRAFFIC_MAGIC
            || bytes[7] != 0
            || bytes[10] != 0
            || bytes[11] != 0
        {
            return Err(PackagedDriverChildError::Protocol(
                "driver traffic frame header is malformed or substituted",
            ));
        }
        let role = PackagedDriverChildRole::from_tag(bytes[4]).ok_or(
            PackagedDriverChildError::Protocol("driver traffic frame has an unknown role"),
        )?;
        let message = TrafficMessage::parse(bytes[5])?;
        let flow = parse_flow(bytes[6])?;
        let payload_length = usize::from(u16::from_be_bytes([bytes[8], bytes[9]]));
        if TRAFFIC_HEADER_BYTES + payload_length != bytes.len()
            || bytes.len() > MAX_TRAFFIC_FRAME_BYTES
        {
            return Err(PackagedDriverChildError::Protocol(
                "driver traffic frame length is truncated or carries trailing bytes",
            ));
        }
        Ok(Self {
            role,
            message,
            flow,
            payload: bytes[TRAFFIC_HEADER_BYTES..].to_vec(),
        })
    }

    fn require(
        self,
        role: PackagedDriverChildRole,
        message: TrafficMessage,
        flow: CanaryFlow,
    ) -> Result<Vec<u8>, PackagedDriverChildError> {
        if self.role != role || self.message != message || self.flow != flow {
            return Err(PackagedDriverChildError::Protocol(
                "driver traffic frame has a substituted role, flow, or sequence",
            ));
        }
        Ok(self.payload)
    }
}

pub(super) fn parent_send_plan(
    control: &SeqpacketConnection,
    role: PackagedDriverChildRole,
    message: TrafficMessage,
    plan: &TrafficFlowPlan,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    let payload = encode_wire_plan(&plan.wire)?;
    send_frame(
        control,
        TrafficFrame::new(role, message, plan.flow(), payload)?,
        exclusive_deadline,
    )
}

pub(super) fn parent_send_signal(
    control: &SeqpacketConnection,
    role: PackagedDriverChildRole,
    message: TrafficMessage,
    flow: CanaryFlow,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    send_frame(
        control,
        TrafficFrame::new(role, message, flow, Vec::new())?,
        exclusive_deadline,
    )
}

pub(super) fn parent_receive_signal(
    control: &SeqpacketConnection,
    expected_pid: u32,
    expected_credentials: RestrictedChildCredentials,
    role: PackagedDriverChildRole,
    message: TrafficMessage,
    flow: CanaryFlow,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    let frame = receive_child_frame(
        control,
        expected_pid,
        expected_credentials,
        exclusive_deadline,
    )?;
    if !frame.require(role, message, flow)?.is_empty() {
        return Err(PackagedDriverChildError::Protocol(
            "driver traffic signal carries an unexpected payload",
        ));
    }
    Ok(())
}

pub(super) fn parent_receive_tuple(
    control: &SeqpacketConnection,
    expected_pid: u32,
    expected_credentials: RestrictedChildCredentials,
    role: PackagedDriverChildRole,
    message: TrafficMessage,
    flow: CanaryFlow,
    exclusive_deadline: Instant,
) -> Result<CanaryFlowTuple, PackagedDriverChildError> {
    let payload = receive_child_frame(
        control,
        expected_pid,
        expected_credentials,
        exclusive_deadline,
    )?
    .require(role, message, flow)?;
    decode_tuple(&payload)
}

fn send_frame(
    control: &SeqpacketConnection,
    frame: TrafficFrame,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    let bytes = frame.encode()?;
    let sent = control
        .send_packet_until(&bytes, exclusive_deadline)
        .map_err(|source| PackagedDriverChildError::Platform {
            operation: "send driver traffic frame",
            source,
        })?;
    if sent {
        Ok(())
    } else {
        Err(PackagedDriverChildError::DeadlineExpired(
            "send driver traffic frame",
        ))
    }
}

fn receive_child_frame(
    control: &SeqpacketConnection,
    expected_pid: u32,
    expected_credentials: RestrictedChildCredentials,
    exclusive_deadline: Instant,
) -> Result<TrafficFrame, PackagedDriverChildError> {
    let received = control
        .recv_record_until(MAX_TRAFFIC_FRAME_BYTES, exclusive_deadline)
        .map_err(|source| PackagedDriverChildError::Platform {
            operation: "receive driver traffic frame",
            source,
        })?
        .ok_or(PackagedDriverChildError::DeadlineExpired(
            "receive driver traffic frame",
        ))?;
    let SeqpacketReceive::Record {
        bytes,
        truncated,
        credentials,
    } = received
    else {
        return Err(PackagedDriverChildError::Protocol(
            "driver child closed during the traffic transaction",
        ));
    };
    if truncated {
        return Err(PackagedDriverChildError::Protocol(
            "driver child sent a truncated traffic frame",
        ));
    }
    validate_child_credentials(expected_pid, expected_credentials, credentials)?;
    TrafficFrame::parse(&bytes)
}

fn validate_child_credentials(
    expected_pid: u32,
    expected: RestrictedChildCredentials,
    observed: PeerCredentials,
) -> Result<(), PackagedDriverChildError> {
    if observed.pid() != expected_pid
        || observed.uid().as_raw() != expected.uid().get()
        || observed.gid() != expected.gid().get()
    {
        return Err(PackagedDriverChildError::Protocol(
            "driver traffic credentials do not match the retained child authority",
        ));
    }
    Ok(())
}

pub(super) fn run_child_session(
    control: &SeqpacketConnection,
    role: PackagedDriverChildRole,
    resources: &mut BoundChildResources,
    quiesce_frame: [u8; 8],
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    // SAFETY: getppid has no arguments, pointers, or failure mode.
    let parent_pid = u32::try_from(unsafe { libc::getppid() }).map_err(|_| {
        PackagedDriverChildError::Protocol("driver child observed an invalid parent PID")
    })?;
    let mut previous_flow = None;
    loop {
        let bytes = receive_parent_packet(control, parent_pid, exclusive_deadline)?;
        if bytes == quiesce_frame {
            return Ok(());
        }
        let frame = TrafficFrame::parse(&bytes)?;
        validate_child_sequence(role, previous_flow, frame.flow)?;
        match role {
            PackagedDriverChildRole::Client => {
                let flow = frame.flow;
                let wire =
                    decode_wire_plan(flow, &frame.require(role, TrafficMessage::RunFlow, flow)?)?;
                if wire.flow != flow {
                    return Err(PackagedDriverChildError::Protocol(
                        "client traffic payload substituted its frame flow",
                    ));
                }
                let pending = start_client_flow(&wire, exclusive_deadline)?;
                send_tuple(
                    control,
                    role,
                    TrafficMessage::ClientHolding,
                    flow,
                    pending.tuple(),
                    exclusive_deadline,
                )?;
                let tuple = pending.finish(&wire, exclusive_deadline)?;
                send_tuple(
                    control,
                    role,
                    TrafficMessage::ClientResult,
                    flow,
                    tuple,
                    exclusive_deadline,
                )?;
                previous_flow = Some(flow);
            }
            peer_role => {
                let flow = frame.flow;
                let wire = decode_wire_plan(
                    flow,
                    &frame.require(peer_role, TrafficMessage::ArmFlow, flow)?,
                )?;
                if wire.flow != flow {
                    return Err(PackagedDriverChildError::Protocol(
                        "peer traffic payload substituted its frame flow",
                    ));
                }
                validate_peer_resources(peer_role, resources, &wire)?;
                send_frame(
                    control,
                    TrafficFrame::new(peer_role, TrafficMessage::Armed, flow, Vec::new())?,
                    exclusive_deadline,
                )?;
                let pending = observe_peer_flow(resources, &wire, exclusive_deadline)?;
                let observed_tuple = pending.tuple();
                send_tuple(
                    control,
                    peer_role,
                    TrafficMessage::PeerObserved,
                    flow,
                    observed_tuple,
                    exclusive_deadline,
                )?;
                let release = receive_parent_packet(control, parent_pid, exclusive_deadline)?;
                if !TrafficFrame::parse(&release)?
                    .require(peer_role, TrafficMessage::ReleaseResponse, flow)?
                    .is_empty()
                {
                    return Err(PackagedDriverChildError::Protocol(
                        "peer response release carries an unexpected payload",
                    ));
                }
                let tuple = pending.finish(&wire, exclusive_deadline)?;
                send_tuple(
                    control,
                    peer_role,
                    TrafficMessage::PeerResult,
                    flow,
                    tuple,
                    exclusive_deadline,
                )?;
                previous_flow = Some(flow);
            }
        }
    }
}

fn receive_parent_packet(
    control: &SeqpacketConnection,
    expected_parent_pid: u32,
    exclusive_deadline: Instant,
) -> Result<Vec<u8>, PackagedDriverChildError> {
    let received = control
        .recv_record_until(MAX_TRAFFIC_FRAME_BYTES, exclusive_deadline)
        .map_err(|source| PackagedDriverChildError::Platform {
            operation: "receive parent driver traffic frame",
            source,
        })?
        .ok_or(PackagedDriverChildError::DeadlineExpired(
            "receive parent driver traffic frame",
        ))?;
    let SeqpacketReceive::Record {
        bytes,
        truncated,
        credentials,
    } = received
    else {
        return Err(PackagedDriverChildError::Protocol(
            "driver-child parent closed during the traffic transaction",
        ));
    };
    if truncated || credentials.pid() != expected_parent_pid {
        return Err(PackagedDriverChildError::Protocol(
            "driver child received a truncated frame or substituted parent identity",
        ));
    }
    Ok(bytes)
}

fn validate_child_sequence(
    role: PackagedDriverChildRole,
    previous: Option<CanaryFlow>,
    next: CanaryFlow,
) -> Result<(), PackagedDriverChildError> {
    let ordered = match role {
        PackagedDriverChildRole::Client => &CanaryFlow::ALL[..],
        PackagedDriverChildRole::TcpEcho => &[CanaryFlow::Ipv4TcpEcho, CanaryFlow::Ipv6TcpEcho][..],
        PackagedDriverChildRole::UdpEcho => &[CanaryFlow::Ipv4UdpEcho, CanaryFlow::Ipv6UdpEcho][..],
        PackagedDriverChildRole::Dns => &[
            CanaryFlow::Ipv4DnsUdp,
            CanaryFlow::Ipv4DnsTcp,
            CanaryFlow::Ipv6DnsUdp,
            CanaryFlow::Ipv6DnsTcp,
        ][..],
    };
    let expected_index = previous.map_or(0, |flow| {
        ordered
            .iter()
            .position(|candidate| *candidate == flow)
            .map_or(ordered.len(), |index| index + 1)
    });
    if ordered.get(expected_index).copied() != Some(next) {
        return Err(PackagedDriverChildError::Protocol(
            "driver child rejected a reordered or duplicate canary flow",
        ));
    }
    Ok(())
}

fn send_tuple(
    control: &SeqpacketConnection,
    role: PackagedDriverChildRole,
    message: TrafficMessage,
    flow: CanaryFlow,
    tuple: CanaryFlowTuple,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    send_frame(
        control,
        TrafficFrame::new(role, message, flow, encode_tuple(tuple))?,
        exclusive_deadline,
    )
}

fn encode_wire_plan(plan: &WireFlowPlan) -> Result<Vec<u8>, PackagedDriverChildError> {
    validate_wire_plan(plan)?;
    let request_length = u16::try_from(plan.request.len()).map_err(|_| {
        PackagedDriverChildError::Protocol("driver traffic request length cannot be represented")
    })?;
    let response_length = u16::try_from(plan.response.len()).map_err(|_| {
        PackagedDriverChildError::Protocol("driver traffic response length cannot be represented")
    })?;
    let mut bytes = Vec::with_capacity(
        ENCODED_SOCKET_ADDRESS_BYTES * 2 + 4 + plan.request.len() + plan.response.len(),
    );
    encode_socket_address(plan.source, &mut bytes);
    encode_socket_address(plan.destination, &mut bytes);
    bytes.extend_from_slice(&request_length.to_be_bytes());
    bytes.extend_from_slice(&plan.request);
    bytes.extend_from_slice(&response_length.to_be_bytes());
    bytes.extend_from_slice(&plan.response);
    Ok(bytes)
}

fn decode_wire_plan(
    flow: CanaryFlow,
    payload: &[u8],
) -> Result<WireFlowPlan, PackagedDriverChildError> {
    let mut cursor = 0;
    let source = decode_socket_address(payload, &mut cursor)?;
    let destination = decode_socket_address(payload, &mut cursor)?;
    let request_length = usize::from(read_be_u16(payload, &mut cursor)?);
    let request_end =
        cursor
            .checked_add(request_length)
            .ok_or(PackagedDriverChildError::Protocol(
                "driver traffic request length overflowed",
            ))?;
    let request = payload
        .get(cursor..request_end)
        .ok_or(PackagedDriverChildError::Protocol(
            "driver traffic request payload is truncated",
        ))?
        .to_vec();
    cursor = request_end;
    let response_length = usize::from(read_be_u16(payload, &mut cursor)?);
    let response_end =
        cursor
            .checked_add(response_length)
            .ok_or(PackagedDriverChildError::Protocol(
                "driver traffic response length overflowed",
            ))?;
    let response = payload
        .get(cursor..response_end)
        .ok_or(PackagedDriverChildError::Protocol(
            "driver traffic response payload is truncated",
        ))?
        .to_vec();
    if response_end != payload.len() {
        return Err(PackagedDriverChildError::Protocol(
            "driver traffic plan carries trailing bytes",
        ));
    }
    let plan = WireFlowPlan {
        flow,
        source,
        destination,
        request,
        response,
    };
    validate_wire_plan(&plan)?;
    Ok(plan)
}

fn validate_wire_plan(plan: &WireFlowPlan) -> Result<(), PackagedDriverChildError> {
    if plan.source.port() != 0
        || plan.destination.port() == 0
        || plan.source.is_ipv4() != plan.flow.is_ipv4()
        || plan.destination.is_ipv4() != plan.flow.is_ipv4()
        || plan.request.is_empty()
        || plan.response.is_empty()
        || plan.request.len() > MAX_WIRE_PAYLOAD_BYTES
        || plan.response.len() > MAX_WIRE_PAYLOAD_BYTES
    {
        return Err(PackagedDriverChildError::Protocol(
            "driver traffic plan violates its bounded address or payload contract",
        ));
    }
    match plan.flow.kind() {
        CanaryFlowKind::TcpEcho | CanaryFlowKind::UdpEcho => {
            if plan.request.len() != FUNCTIONAL_CANARY_NONCE_BYTES || plan.response != plan.request
            {
                return Err(PackagedDriverChildError::Protocol(
                    "driver echo plan does not carry the exact fixed nonce",
                ));
            }
        }
        CanaryFlowKind::DnsUdp => {
            validate_dns_wire(&plan.request, &plan.response, plan.flow.is_ipv4(), false)?
        }
        CanaryFlowKind::DnsTcp => {
            validate_dns_wire(&plan.request, &plan.response, plan.flow.is_ipv4(), true)?
        }
    }
    Ok(())
}

fn encode_tuple(tuple: CanaryFlowTuple) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ENCODED_TUPLE_BYTES);
    encode_socket_address(tuple.source(), &mut bytes);
    encode_socket_address(tuple.destination(), &mut bytes);
    bytes
}

fn decode_tuple(payload: &[u8]) -> Result<CanaryFlowTuple, PackagedDriverChildError> {
    if payload.len() != ENCODED_TUPLE_BYTES {
        return Err(PackagedDriverChildError::Protocol(
            "driver traffic tuple has the wrong fixed length",
        ));
    }
    let mut cursor = 0;
    let source = decode_socket_address(payload, &mut cursor)?;
    let destination = decode_socket_address(payload, &mut cursor)?;
    if cursor != payload.len() || source.is_ipv4() != destination.is_ipv4() {
        return Err(PackagedDriverChildError::Protocol(
            "driver traffic tuple is malformed or crosses address families",
        ));
    }
    Ok(CanaryFlowTuple::new(source, destination))
}

fn encode_socket_address(address: SocketAddr, bytes: &mut Vec<u8>) {
    match address.ip() {
        IpAddr::V4(ip) => {
            bytes.push(4);
            bytes.extend_from_slice(&address.port().to_be_bytes());
            bytes.extend_from_slice(&ip.octets());
            bytes.extend_from_slice(&[0; 12]);
        }
        IpAddr::V6(ip) => {
            bytes.push(6);
            bytes.extend_from_slice(&address.port().to_be_bytes());
            bytes.extend_from_slice(&ip.octets());
        }
    }
}

fn decode_socket_address(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<SocketAddr, PackagedDriverChildError> {
    let end = cursor.checked_add(ENCODED_SOCKET_ADDRESS_BYTES).ok_or(
        PackagedDriverChildError::Protocol("driver traffic address length overflowed"),
    )?;
    let encoded = bytes
        .get(*cursor..end)
        .ok_or(PackagedDriverChildError::Protocol(
            "driver traffic socket address is truncated",
        ))?;
    *cursor = end;
    let port = u16::from_be_bytes([encoded[1], encoded[2]]);
    match encoded[0] {
        4 if encoded[7..].iter().all(|byte| *byte == 0) => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                encoded[3], encoded[4], encoded[5], encoded[6],
            )),
            port,
        )),
        6 => {
            let octets: [u8; 16] = encoded[3..]
                .try_into()
                .map_err(|_| PackagedDriverChildError::Protocol("copy IPv6 driver address"))?;
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(PackagedDriverChildError::Protocol(
            "driver traffic socket address has an invalid family or padding",
        )),
    }
}

fn read_be_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, PackagedDriverChildError> {
    let end = cursor
        .checked_add(2)
        .ok_or(PackagedDriverChildError::Protocol(
            "driver traffic integer offset overflowed",
        ))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(PackagedDriverChildError::Protocol(
            "driver traffic integer is truncated",
        ))?;
    *cursor = end;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn parse_flow(value: u8) -> Result<CanaryFlow, PackagedDriverChildError> {
    CanaryFlow::ALL
        .get(usize::from(value))
        .copied()
        .ok_or(PackagedDriverChildError::Protocol(
            "driver traffic frame has an unknown flow",
        ))
}

fn canonical_dns_query(expected: CanaryDnsExpectation) -> Vec<u8> {
    let question = expected.question();
    let mut query = Vec::with_capacity(DNS_QUERY_BYTES);
    query.extend_from_slice(&expected.transaction_id().to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[0; 6]);
    query.extend_from_slice(question.wire_name());
    query.extend_from_slice(&question.record_type().to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query
}

fn canonical_dns_response(
    query: &[u8],
    expected: CanaryDnsExpectation,
) -> Result<Vec<u8>, PackagedDriverChildError> {
    if query.len() != DNS_QUERY_BYTES || query != canonical_dns_query(expected) {
        return Err(PackagedDriverChildError::Protocol(
            "driver DNS query differs from its immutable expectation",
        ));
    }
    let question = expected.question();
    let mut response = Vec::with_capacity(DNS_QUERY_BYTES + 28);
    response.extend_from_slice(&expected.transaction_id().to_be_bytes());
    response.extend_from_slice(&0x8500_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[0; 4]);
    response.extend_from_slice(&query[DNS_HEADER_BYTES..]);
    response.extend_from_slice(&0xc00c_u16.to_be_bytes());
    response.extend_from_slice(&question.record_type().to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&5_u32.to_be_bytes());
    match expected.answer() {
        IpAddr::V4(address) => {
            response.extend_from_slice(&4_u16.to_be_bytes());
            response.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            response.extend_from_slice(&16_u16.to_be_bytes());
            response.extend_from_slice(&address.octets());
        }
    }
    Ok(response)
}

fn frame_dns_tcp(message: &[u8]) -> Result<Vec<u8>, PackagedDriverChildError> {
    let length = u16::try_from(message.len()).map_err(|_| {
        PackagedDriverChildError::Protocol("driver DNS/TCP message length cannot be represented")
    })?;
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(message);
    Ok(framed)
}

fn validate_dns_wire(
    request: &[u8],
    response: &[u8],
    ipv4: bool,
    tcp: bool,
) -> Result<(), PackagedDriverChildError> {
    let (request, response) = if tcp {
        (
            strip_dns_tcp_frame(request)?,
            strip_dns_tcp_frame(response)?,
        )
    } else {
        (request, response)
    };
    let answer_bytes = if ipv4 { 4 } else { 16 };
    if request.len() != DNS_QUERY_BYTES
        || response.len() != DNS_QUERY_BYTES + 12 + answer_bytes
        || request[2..12] != [0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        || response[..2] != request[..2]
        || response[2..12] != [0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0]
        || response[12..DNS_QUERY_BYTES] != request[12..]
    {
        return Err(PackagedDriverChildError::Protocol(
            "driver DNS request or authoritative response header is invalid",
        ));
    }
    let question = &request[DNS_HEADER_BYTES..];
    let record_type_offset = DNS_HEADER_BYTES + CANARY_DNS_WIRE_NAME_BYTES;
    let expected_type = if ipv4 { 1_u16 } else { 28_u16 };
    if question[CANARY_DNS_WIRE_NAME_BYTES - 1] != 0
        || u16::from_be_bytes([request[record_type_offset], request[record_type_offset + 1]])
            != expected_type
        || request[record_type_offset + 2..] != [0, 1]
    {
        return Err(PackagedDriverChildError::Protocol(
            "driver DNS question name, type, or class is invalid",
        ));
    }
    let answer = &response[DNS_QUERY_BYTES..];
    if answer[..2] != 0xc00c_u16.to_be_bytes()
        || answer[2..4] != expected_type.to_be_bytes()
        || answer[4..6] != 1_u16.to_be_bytes()
        || answer[6..10] != 5_u32.to_be_bytes()
        || usize::from(u16::from_be_bytes([answer[10], answer[11]])) != answer_bytes
    {
        return Err(PackagedDriverChildError::Protocol(
            "driver DNS authoritative answer metadata is invalid",
        ));
    }
    Ok(())
}

fn strip_dns_tcp_frame(message: &[u8]) -> Result<&[u8], PackagedDriverChildError> {
    let prefix = message.get(..2).ok_or(PackagedDriverChildError::Protocol(
        "driver DNS/TCP length prefix is truncated",
    ))?;
    let declared = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    if declared + 2 != message.len() {
        return Err(PackagedDriverChildError::Protocol(
            "driver DNS/TCP length prefix does not match its frame",
        ));
    }
    Ok(&message[2..])
}

fn validate_client_tuple(
    plan: &TrafficFlowPlan,
    tuple: CanaryFlowTuple,
) -> Result<(), PackagedDriverChildError> {
    if tuple.source().ip() != plan.source().ip()
        || tuple.source().port() == 0
        || tuple.destination() != plan.destination()
    {
        return Err(PackagedDriverChildError::Protocol(
            "driver client tuple differs from its exact flow plan",
        ));
    }
    Ok(())
}

fn validate_peer_tuple(
    plan: &TrafficFlowPlan,
    tuple: CanaryFlowTuple,
) -> Result<(), PackagedDriverChildError> {
    if tuple.source().port() == 0
        || tuple.source().is_ipv4() != plan.flow().is_ipv4()
        || tuple.destination() != plan.destination()
    {
        return Err(PackagedDriverChildError::Protocol(
            "driver peer tuple differs from its exact flow plan",
        ));
    }
    Ok(())
}

fn validate_peer_resources(
    role: PackagedDriverChildRole,
    resources: &BoundChildResources,
    plan: &WireFlowPlan,
) -> Result<(), PackagedDriverChildError> {
    let addresses = match (role, resources, plan.flow.kind()) {
        (
            PackagedDriverChildRole::TcpEcho,
            BoundChildResources::Tcp(listeners),
            CanaryFlowKind::TcpEcho,
        ) => listeners
            .iter()
            .map(TcpListener::local_addr)
            .collect::<Result<Vec<_>, _>>(),
        (
            PackagedDriverChildRole::UdpEcho,
            BoundChildResources::Udp(sockets),
            CanaryFlowKind::UdpEcho,
        ) => sockets
            .iter()
            .map(UdpSocket::local_addr)
            .collect::<Result<Vec<_>, _>>(),
        (
            PackagedDriverChildRole::Dns,
            BoundChildResources::Dns { tcp, .. },
            CanaryFlowKind::DnsTcp,
        ) => tcp
            .iter()
            .map(TcpListener::local_addr)
            .collect::<Result<Vec<_>, _>>(),
        (
            PackagedDriverChildRole::Dns,
            BoundChildResources::Dns { udp, .. },
            CanaryFlowKind::DnsUdp,
        ) => udp
            .iter()
            .map(UdpSocket::local_addr)
            .collect::<Result<Vec<_>, _>>(),
        _ => {
            return Err(PackagedDriverChildError::Protocol(
                "driver traffic flow does not match the armed peer role",
            ));
        }
    }
    .map_err(|source| PackagedDriverChildError::Io {
        operation: "inspect bound driver peer socket",
        source,
    })?;
    if !addresses.contains(&plan.destination) {
        return Err(PackagedDriverChildError::Protocol(
            "driver traffic destination does not match a bound peer socket",
        ));
    }
    Ok(())
}

enum PendingClient {
    Tcp {
        stream: TcpStream,
        tuple: CanaryFlowTuple,
    },
    UdpConnected {
        socket: UdpSocket,
        tuple: CanaryFlowTuple,
    },
    UdpUnconnected {
        socket: UdpSocket,
        tuple: CanaryFlowTuple,
    },
}

impl PendingClient {
    const fn tuple(&self) -> CanaryFlowTuple {
        match self {
            Self::Tcp { tuple, .. }
            | Self::UdpConnected { tuple, .. }
            | Self::UdpUnconnected { tuple, .. } => *tuple,
        }
    }

    fn finish(
        self,
        plan: &WireFlowPlan,
        exclusive_deadline: Instant,
    ) -> Result<CanaryFlowTuple, PackagedDriverChildError> {
        let tuple = self.tuple();
        match self {
            Self::Tcp { mut stream, .. } => {
                let response = read_to_eof_until(
                    &mut stream,
                    plan.response.len() + 1,
                    "read driver TCP response",
                    exclusive_deadline,
                )?;
                if response != plan.response {
                    return Err(PackagedDriverChildError::Protocol(
                        "driver TCP response differs from the exact expected bytes",
                    ));
                }
            }
            Self::UdpConnected { socket, .. } => {
                let mut response = [0_u8; MAX_WIRE_PAYLOAD_BYTES + 1];
                set_udp_read_deadline(
                    &socket,
                    "set driver UDP response deadline",
                    exclusive_deadline,
                )?;
                let received = socket.recv(&mut response).map_err(|source| {
                    network_io_error("read driver UDP response", source, exclusive_deadline)
                })?;
                require_before_deadline("read driver UDP response", exclusive_deadline)?;
                if response[..received] != plan.response {
                    return Err(PackagedDriverChildError::Protocol(
                        "driver UDP response differs from the exact expected datagram",
                    ));
                }
            }
            Self::UdpUnconnected { socket, .. } => {
                let mut response = [0_u8; MAX_WIRE_PAYLOAD_BYTES + 1];
                set_udp_read_deadline(
                    &socket,
                    "set driver DNS/UDP response deadline",
                    exclusive_deadline,
                )?;
                let (received, source) = socket.recv_from(&mut response).map_err(|source| {
                    network_io_error("read driver DNS/UDP response", source, exclusive_deadline)
                })?;
                require_before_deadline("read driver DNS/UDP response", exclusive_deadline)?;
                if source != plan.destination || response[..received] != plan.response {
                    return Err(PackagedDriverChildError::Protocol(
                        "driver DNS/UDP response source or bytes were substituted",
                    ));
                }
            }
        }
        Ok(tuple)
    }
}

fn start_client_flow(
    plan: &WireFlowPlan,
    exclusive_deadline: Instant,
) -> Result<PendingClient, PackagedDriverChildError> {
    match plan.flow.kind() {
        CanaryFlowKind::TcpEcho | CanaryFlowKind::DnsTcp => {
            let mut stream =
                connect_bound_tcp_until(plan.source, plan.destination, exclusive_deadline)?;
            write_all_until(
                &mut stream,
                &plan.request,
                "write driver TCP request",
                exclusive_deadline,
            )?;
            require_before_deadline("half-close driver TCP request", exclusive_deadline)?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|source| PackagedDriverChildError::Io {
                    operation: "half-close driver TCP request",
                    source,
                })?;
            require_before_deadline("half-close driver TCP request", exclusive_deadline)?;
            let tuple = stream_tuple(&stream, plan)?;
            Ok(PendingClient::Tcp { stream, tuple })
        }
        CanaryFlowKind::UdpEcho => {
            let socket =
                UdpSocket::bind(plan.source).map_err(|source| PackagedDriverChildError::Io {
                    operation: "bind driver UDP client",
                    source,
                })?;
            socket
                .connect(plan.destination)
                .map_err(|source| PackagedDriverChildError::Io {
                    operation: "connect driver UDP client",
                    source,
                })?;
            send_udp_until(
                &socket,
                &plan.request,
                None,
                "send driver UDP request",
                exclusive_deadline,
            )?;
            let tuple = udp_tuple(&socket, plan)?;
            Ok(PendingClient::UdpConnected { socket, tuple })
        }
        CanaryFlowKind::DnsUdp => {
            let socket =
                UdpSocket::bind(plan.source).map_err(|source| PackagedDriverChildError::Io {
                    operation: "bind driver DNS/UDP client",
                    source,
                })?;
            send_udp_until(
                &socket,
                &plan.request,
                Some(plan.destination),
                "send driver DNS/UDP request",
                exclusive_deadline,
            )?;
            let source = socket
                .local_addr()
                .map_err(|source| PackagedDriverChildError::Io {
                    operation: "inspect driver DNS/UDP source",
                    source,
                })?;
            if source.ip() != plan.source.ip() || source.port() == 0 {
                return Err(PackagedDriverChildError::Protocol(
                    "driver DNS/UDP client changed its exact source address",
                ));
            }
            let tuple = CanaryFlowTuple::new(source, plan.destination);
            Ok(PendingClient::UdpUnconnected { socket, tuple })
        }
    }
}

enum PendingPeer<'a> {
    Tcp {
        stream: TcpStream,
        tuple: CanaryFlowTuple,
    },
    Udp {
        socket: &'a UdpSocket,
        remote: SocketAddr,
        tuple: CanaryFlowTuple,
    },
}

impl PendingPeer<'_> {
    const fn tuple(&self) -> CanaryFlowTuple {
        match self {
            Self::Tcp { tuple, .. } | Self::Udp { tuple, .. } => *tuple,
        }
    }

    fn finish(
        self,
        plan: &WireFlowPlan,
        exclusive_deadline: Instant,
    ) -> Result<CanaryFlowTuple, PackagedDriverChildError> {
        let tuple = self.tuple();
        match self {
            Self::Tcp { mut stream, .. } => {
                write_all_until(
                    &mut stream,
                    &plan.response,
                    "write driver TCP peer response",
                    exclusive_deadline,
                )?;
                require_before_deadline("half-close driver TCP peer response", exclusive_deadline)?;
                stream.shutdown(Shutdown::Write).map_err(|source| {
                    PackagedDriverChildError::Io {
                        operation: "half-close driver TCP peer response",
                        source,
                    }
                })?;
                require_before_deadline("half-close driver TCP peer response", exclusive_deadline)?;
            }
            Self::Udp { socket, remote, .. } => send_udp_until(
                socket,
                &plan.response,
                Some(remote),
                "send driver UDP peer response",
                exclusive_deadline,
            )?,
        }
        Ok(tuple)
    }
}

fn observe_peer_flow<'a>(
    resources: &'a BoundChildResources,
    plan: &WireFlowPlan,
    exclusive_deadline: Instant,
) -> Result<PendingPeer<'a>, PackagedDriverChildError> {
    match plan.flow.kind() {
        CanaryFlowKind::TcpEcho => {
            let BoundChildResources::Tcp(listeners) = resources else {
                return Err(PackagedDriverChildError::Protocol(
                    "TCP echo flow lacks its bound peer listener",
                ));
            };
            observe_peer_tcp(
                select_tcp_listener(listeners, plan.destination)?,
                plan,
                exclusive_deadline,
            )
        }
        CanaryFlowKind::DnsTcp => {
            let BoundChildResources::Dns { tcp, .. } = resources else {
                return Err(PackagedDriverChildError::Protocol(
                    "DNS/TCP flow lacks its bound peer listener",
                ));
            };
            observe_peer_tcp(
                select_tcp_listener(tcp, plan.destination)?,
                plan,
                exclusive_deadline,
            )
        }
        CanaryFlowKind::UdpEcho => {
            let BoundChildResources::Udp(sockets) = resources else {
                return Err(PackagedDriverChildError::Protocol(
                    "UDP echo flow lacks its bound peer socket",
                ));
            };
            observe_peer_udp(
                select_udp_socket(sockets, plan.destination)?,
                plan,
                exclusive_deadline,
            )
        }
        CanaryFlowKind::DnsUdp => {
            let BoundChildResources::Dns { udp, .. } = resources else {
                return Err(PackagedDriverChildError::Protocol(
                    "DNS/UDP flow lacks its bound peer socket",
                ));
            };
            observe_peer_udp(
                select_udp_socket(udp, plan.destination)?,
                plan,
                exclusive_deadline,
            )
        }
    }
}

fn observe_peer_tcp(
    listener: &TcpListener,
    plan: &WireFlowPlan,
    exclusive_deadline: Instant,
) -> Result<PendingPeer<'static>, PackagedDriverChildError> {
    let (mut stream, remote) = accept_until(listener, exclusive_deadline)?;
    let request = read_to_eof_until(
        &mut stream,
        plan.request.len() + 1,
        "read driver TCP peer request",
        exclusive_deadline,
    )?;
    if request != plan.request {
        return Err(PackagedDriverChildError::Protocol(
            "driver TCP peer observed substituted request bytes",
        ));
    }
    let local = stream
        .local_addr()
        .map_err(|source| PackagedDriverChildError::Io {
            operation: "inspect driver TCP peer destination",
            source,
        })?;
    if local != plan.destination || remote.port() == 0 {
        return Err(PackagedDriverChildError::Protocol(
            "driver TCP peer observed a substituted tuple",
        ));
    }
    Ok(PendingPeer::Tcp {
        stream,
        tuple: CanaryFlowTuple::new(remote, local),
    })
}

fn observe_peer_udp<'a>(
    socket: &'a UdpSocket,
    plan: &WireFlowPlan,
    exclusive_deadline: Instant,
) -> Result<PendingPeer<'a>, PackagedDriverChildError> {
    let mut request = [0_u8; MAX_WIRE_PAYLOAD_BYTES + 1];
    set_udp_read_deadline(socket, "set driver UDP peer deadline", exclusive_deadline)?;
    let (received, remote) = socket.recv_from(&mut request).map_err(|source| {
        network_io_error("read driver UDP peer request", source, exclusive_deadline)
    })?;
    require_before_deadline("read driver UDP peer request", exclusive_deadline)?;
    if request[..received] != plan.request {
        return Err(PackagedDriverChildError::Protocol(
            "driver UDP peer observed substituted request bytes",
        ));
    }
    let local = socket
        .local_addr()
        .map_err(|source| PackagedDriverChildError::Io {
            operation: "inspect driver UDP peer destination",
            source,
        })?;
    if local != plan.destination || remote.port() == 0 {
        return Err(PackagedDriverChildError::Protocol(
            "driver UDP peer observed a substituted tuple",
        ));
    }
    Ok(PendingPeer::Udp {
        socket,
        remote,
        tuple: CanaryFlowTuple::new(remote, local),
    })
}

fn select_tcp_listener(
    listeners: &[TcpListener],
    destination: SocketAddr,
) -> Result<&TcpListener, PackagedDriverChildError> {
    for listener in listeners {
        let local = listener
            .local_addr()
            .map_err(|source| PackagedDriverChildError::Io {
                operation: "inspect driver TCP peer listener",
                source,
            })?;
        if local == destination {
            return Ok(listener);
        }
    }
    Err(PackagedDriverChildError::Protocol(
        "driver TCP peer has no listener for the armed destination",
    ))
}

fn select_udp_socket(
    sockets: &[UdpSocket],
    destination: SocketAddr,
) -> Result<&UdpSocket, PackagedDriverChildError> {
    for socket in sockets {
        let local = socket
            .local_addr()
            .map_err(|source| PackagedDriverChildError::Io {
                operation: "inspect driver UDP peer socket",
                source,
            })?;
        if local == destination {
            return Ok(socket);
        }
    }
    Err(PackagedDriverChildError::Protocol(
        "driver UDP peer has no socket for the armed destination",
    ))
}

fn accept_until(
    listener: &TcpListener,
    exclusive_deadline: Instant,
) -> Result<(TcpStream, SocketAddr), PackagedDriverChildError> {
    listener
        .set_nonblocking(true)
        .map_err(|source| PackagedDriverChildError::Io {
            operation: "make driver TCP peer listener nonblocking",
            source,
        })?;
    loop {
        match listener.accept() {
            Ok((stream, remote)) => {
                require_before_deadline("accept driver TCP peer request", exclusive_deadline)?;
                stream
                    .set_nonblocking(false)
                    .map_err(|source| PackagedDriverChildError::Io {
                        operation: "make accepted driver TCP peer stream blocking",
                        source,
                    })?;
                return Ok((stream, remote));
            }
            Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => {
                poll_fd_until(
                    listener.as_raw_fd(),
                    libc::POLLIN,
                    "poll driver TCP peer listener",
                    exclusive_deadline,
                )?;
            }
            Err(source) => {
                return Err(PackagedDriverChildError::Io {
                    operation: "accept driver TCP peer request",
                    source,
                });
            }
        }
    }
}

fn read_to_eof_until(
    stream: &mut TcpStream,
    limit: usize,
    operation: &'static str,
    exclusive_deadline: Instant,
) -> Result<Vec<u8>, PackagedDriverChildError> {
    let mut bytes = Vec::with_capacity(limit.min(MAX_WIRE_PAYLOAD_BYTES + 1));
    let mut buffer = [0_u8; 128];
    loop {
        let remaining = remaining_until(operation, exclusive_deadline)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|source| PackagedDriverChildError::Io { operation, source })?;
        let read = stream
            .read(&mut buffer)
            .map_err(|source| network_io_error(operation, source, exclusive_deadline))?;
        require_before_deadline(operation, exclusive_deadline)?;
        if read == 0 {
            return Ok(bytes);
        }
        if bytes.len().saturating_add(read) > limit {
            return Err(PackagedDriverChildError::Protocol(
                "driver TCP payload exceeds the exact bounded length",
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

fn write_all_until(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    operation: &'static str,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    while !bytes.is_empty() {
        let remaining = remaining_until(operation, exclusive_deadline)?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|source| PackagedDriverChildError::Io { operation, source })?;
        let written = stream
            .write(bytes)
            .map_err(|source| network_io_error(operation, source, exclusive_deadline))?;
        require_before_deadline(operation, exclusive_deadline)?;
        if written == 0 {
            return Err(PackagedDriverChildError::Protocol(
                "driver TCP socket made no progress while writing",
            ));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

fn send_udp_until(
    socket: &UdpSocket,
    bytes: &[u8],
    destination: Option<SocketAddr>,
    operation: &'static str,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    let remaining = remaining_until(operation, exclusive_deadline)?;
    socket
        .set_write_timeout(Some(remaining))
        .map_err(|source| PackagedDriverChildError::Io { operation, source })?;
    let sent = destination
        .map_or_else(
            || socket.send(bytes),
            |destination| socket.send_to(bytes, destination),
        )
        .map_err(|source| network_io_error(operation, source, exclusive_deadline))?;
    require_before_deadline(operation, exclusive_deadline)?;
    if sent != bytes.len() {
        return Err(PackagedDriverChildError::Protocol(
            "driver UDP socket sent a partial datagram",
        ));
    }
    Ok(())
}

fn set_udp_read_deadline(
    socket: &UdpSocket,
    operation: &'static str,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    let remaining = remaining_until(operation, exclusive_deadline)?;
    socket
        .set_read_timeout(Some(remaining))
        .map_err(|source| PackagedDriverChildError::Io { operation, source })
}

fn stream_tuple(
    stream: &TcpStream,
    plan: &WireFlowPlan,
) -> Result<CanaryFlowTuple, PackagedDriverChildError> {
    let source = stream
        .local_addr()
        .map_err(|source| PackagedDriverChildError::Io {
            operation: "inspect driver TCP client source",
            source,
        })?;
    let destination = stream
        .peer_addr()
        .map_err(|source| PackagedDriverChildError::Io {
            operation: "inspect driver TCP client destination",
            source,
        })?;
    if source.ip() != plan.source.ip() || source.port() == 0 || destination != plan.destination {
        return Err(PackagedDriverChildError::Protocol(
            "driver TCP client changed its exact planned tuple",
        ));
    }
    Ok(CanaryFlowTuple::new(source, destination))
}

fn udp_tuple(
    socket: &UdpSocket,
    plan: &WireFlowPlan,
) -> Result<CanaryFlowTuple, PackagedDriverChildError> {
    let source = socket
        .local_addr()
        .map_err(|source| PackagedDriverChildError::Io {
            operation: "inspect driver UDP client source",
            source,
        })?;
    let destination = socket
        .peer_addr()
        .map_err(|source| PackagedDriverChildError::Io {
            operation: "inspect driver UDP client destination",
            source,
        })?;
    if source.ip() != plan.source.ip() || source.port() == 0 || destination != plan.destination {
        return Err(PackagedDriverChildError::Protocol(
            "driver UDP client changed its exact planned tuple",
        ));
    }
    Ok(CanaryFlowTuple::new(source, destination))
}

fn connect_bound_tcp_until(
    source: SocketAddr,
    destination: SocketAddr,
    exclusive_deadline: Instant,
) -> Result<TcpStream, PackagedDriverChildError> {
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(PackagedDriverChildError::Protocol(
            "driver TCP source and destination families differ",
        ));
    }
    let domain = if source.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: socket receives only integer constants and creates a new descriptor.
    let raw_fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::IPPROTO_TCP,
        )
    };
    if raw_fd < 0 {
        return Err(PackagedDriverChildError::Io {
            operation: "create bound driver TCP client",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: raw_fd is a newly returned owned descriptor and is converted once.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    if domain == libc::AF_INET6 {
        set_i32_socket_option(
            fd.as_raw_fd(),
            libc::SOL_IPV6,
            libc::IPV6_V6ONLY,
            1,
            "set driver TCP IPv6-only mode",
        )?;
    }
    bind_socket(fd.as_raw_fd(), source)?;
    connect_socket_until(fd.as_raw_fd(), destination, exclusive_deadline)?;
    // SAFETY: fd remains owned for the complete fcntl call.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(PackagedDriverChildError::Io {
            operation: "inspect bound driver TCP client flags",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: fd remains owned and F_SETFL consumes only the scalar flags value.
    let blocking_result =
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    if blocking_result < 0 {
        return Err(PackagedDriverChildError::Io {
            operation: "make bound driver TCP client blocking",
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(TcpStream::from(fd))
}

fn bind_socket(fd: RawFd, address: SocketAddr) -> Result<(), PackagedDriverChildError> {
    let result = match address {
        SocketAddr::V4(address) => {
            let raw = sockaddr_in(address.ip(), address.port());
            let length =
                libc::socklen_t::try_from(size_of::<libc::sockaddr_in>()).map_err(|_| {
                    PackagedDriverChildError::Protocol(
                        "driver IPv4 socket address length cannot be represented",
                    )
                })?;
            // SAFETY: raw is initialized and bind does not retain its pointer.
            unsafe { libc::bind(fd, (&raw as *const libc::sockaddr_in).cast(), length) }
        }
        SocketAddr::V6(address) => {
            let raw = sockaddr_in6(
                address.ip(),
                address.port(),
                address.flowinfo(),
                address.scope_id(),
            );
            let length =
                libc::socklen_t::try_from(size_of::<libc::sockaddr_in6>()).map_err(|_| {
                    PackagedDriverChildError::Protocol(
                        "driver IPv6 socket address length cannot be represented",
                    )
                })?;
            // SAFETY: raw is initialized and bind does not retain its pointer.
            unsafe { libc::bind(fd, (&raw as *const libc::sockaddr_in6).cast(), length) }
        }
    };
    if result == 0 {
        Ok(())
    } else {
        Err(PackagedDriverChildError::Io {
            operation: "bind driver TCP client source",
            source: std::io::Error::last_os_error(),
        })
    }
}

fn connect_socket_until(
    fd: RawFd,
    destination: SocketAddr,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    require_before_deadline("connect driver TCP client", exclusive_deadline)?;
    let result = match destination {
        SocketAddr::V4(address) => {
            let raw = sockaddr_in(address.ip(), address.port());
            let length =
                libc::socklen_t::try_from(size_of::<libc::sockaddr_in>()).map_err(|_| {
                    PackagedDriverChildError::Protocol(
                        "driver IPv4 destination length cannot be represented",
                    )
                })?;
            // SAFETY: raw is initialized and connect does not retain its pointer.
            unsafe { libc::connect(fd, (&raw as *const libc::sockaddr_in).cast(), length) }
        }
        SocketAddr::V6(address) => {
            let raw = sockaddr_in6(
                address.ip(),
                address.port(),
                address.flowinfo(),
                address.scope_id(),
            );
            let length =
                libc::socklen_t::try_from(size_of::<libc::sockaddr_in6>()).map_err(|_| {
                    PackagedDriverChildError::Protocol(
                        "driver IPv6 destination length cannot be represented",
                    )
                })?;
            // SAFETY: raw is initialized and connect does not retain its pointer.
            unsafe { libc::connect(fd, (&raw as *const libc::sockaddr_in6).cast(), length) }
        }
    };
    if result == 0 {
        return require_before_deadline("connect driver TCP client", exclusive_deadline);
    }
    let source = std::io::Error::last_os_error();
    if source.raw_os_error() != Some(libc::EINPROGRESS) {
        return Err(PackagedDriverChildError::Io {
            operation: "connect driver TCP client",
            source,
        });
    }
    poll_fd_until(
        fd,
        libc::POLLOUT,
        "poll driver TCP client connect",
        exclusive_deadline,
    )?;
    require_before_deadline("connect driver TCP client", exclusive_deadline)?;
    let socket_error = get_i32_socket_option(fd, libc::SOL_SOCKET, libc::SO_ERROR)?;
    if socket_error == 0 {
        Ok(())
    } else {
        Err(PackagedDriverChildError::Io {
            operation: "complete driver TCP client connect",
            source: std::io::Error::from_raw_os_error(socket_error),
        })
    }
}

fn set_i32_socket_option(
    fd: RawFd,
    level: i32,
    name: i32,
    value: i32,
    operation: &'static str,
) -> Result<(), PackagedDriverChildError> {
    let length = libc::socklen_t::try_from(size_of::<i32>()).map_err(|_| {
        PackagedDriverChildError::Protocol("driver socket option length cannot be represented")
    })?;
    // SAFETY: value is initialized, length matches it, and setsockopt does not retain it.
    let result =
        unsafe { libc::setsockopt(fd, level, name, (&value as *const i32).cast(), length) };
    if result == 0 {
        Ok(())
    } else {
        Err(PackagedDriverChildError::Io {
            operation,
            source: std::io::Error::last_os_error(),
        })
    }
}

fn get_i32_socket_option(
    fd: RawFd,
    level: i32,
    name: i32,
) -> Result<i32, PackagedDriverChildError> {
    let mut value = 0_i32;
    let mut length = libc::socklen_t::try_from(size_of::<i32>()).map_err(|_| {
        PackagedDriverChildError::Protocol("driver socket option length cannot be represented")
    })?;
    // SAFETY: value and length are writable and describe the output buffer.
    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&mut value as *mut i32).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(PackagedDriverChildError::Io {
            operation: "read driver TCP socket error",
            source: std::io::Error::last_os_error(),
        });
    }
    if usize::try_from(length).ok() != Some(size_of::<i32>()) {
        return Err(PackagedDriverChildError::Protocol(
            "driver TCP socket error option has the wrong length",
        ));
    }
    Ok(value)
}

fn sockaddr_in(address: &Ipv4Addr, port: u16) -> libc::sockaddr_in {
    // SAFETY: zero is valid for every sockaddr_in padding field.
    let mut raw = unsafe { zeroed::<libc::sockaddr_in>() };
    raw.sin_family = libc::AF_INET as libc::sa_family_t;
    raw.sin_port = port.to_be();
    raw.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(address.octets()),
    };
    raw
}

fn sockaddr_in6(address: &Ipv6Addr, port: u16, flowinfo: u32, scope_id: u32) -> libc::sockaddr_in6 {
    // SAFETY: zero is valid for every sockaddr_in6 padding field.
    let mut raw = unsafe { zeroed::<libc::sockaddr_in6>() };
    raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    raw.sin6_port = port.to_be();
    raw.sin6_flowinfo = flowinfo;
    raw.sin6_addr = libc::in6_addr {
        s6_addr: address.octets(),
    };
    raw.sin6_scope_id = scope_id;
    raw
}

fn poll_fd_until(
    fd: RawFd,
    events: i16,
    operation: &'static str,
    exclusive_deadline: Instant,
) -> Result<i16, PackagedDriverChildError> {
    loop {
        let remaining = remaining_until(operation, exclusive_deadline)?;
        let milliseconds =
            i32::try_from(remaining.as_millis().min(i32::MAX as u128)).unwrap_or(i32::MAX);
        let mut poll_fd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: poll_fd is a valid one-element array for the call.
        let polled = unsafe { libc::poll(&mut poll_fd, 1, milliseconds) };
        if polled > 0 {
            if poll_fd.revents & libc::POLLNVAL != 0 {
                return Err(PackagedDriverChildError::Protocol(
                    "driver network poll observed an invalid descriptor",
                ));
            }
            return Ok(poll_fd.revents);
        }
        if polled < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(PackagedDriverChildError::Io {
                operation,
                source: std::io::Error::last_os_error(),
            });
        }
    }
}

fn remaining_until(
    operation: &'static str,
    exclusive_deadline: Instant,
) -> Result<Duration, PackagedDriverChildError> {
    let remaining = exclusive_deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(PackagedDriverChildError::DeadlineExpired(operation))
    } else {
        Ok(remaining)
    }
}

fn require_before_deadline(
    operation: &'static str,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    if Instant::now() < exclusive_deadline {
        Ok(())
    } else {
        Err(PackagedDriverChildError::DeadlineExpired(operation))
    }
}

fn network_io_error(
    operation: &'static str,
    source: std::io::Error,
    exclusive_deadline: Instant,
) -> PackagedDriverChildError {
    if matches!(
        source.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) && Instant::now() >= exclusive_deadline
    {
        PackagedDriverChildError::DeadlineExpired(operation)
    } else {
        PackagedDriverChildError::Io { operation, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_plan(flow: CanaryFlow) -> WireFlowPlan {
        let ipv4 = flow.is_ipv4();
        let source = if ipv4 {
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
        } else {
            SocketAddr::from((Ipv6Addr::LOCALHOST, 0))
        };
        let destination = if ipv4 {
            SocketAddr::from((Ipv4Addr::LOCALHOST, 41_001))
        } else {
            SocketAddr::from((Ipv6Addr::LOCALHOST, 41_001))
        };
        WireFlowPlan {
            flow,
            source,
            destination,
            request: vec![7; FUNCTIONAL_CANARY_NONCE_BYTES],
            response: vec![7; FUNCTIONAL_CANARY_NONCE_BYTES],
        }
    }

    #[test]
    fn fixed_frames_reject_truncation_trailing_bytes_and_substitution() {
        let plan = echo_plan(CanaryFlow::Ipv4TcpEcho);
        let frame = TrafficFrame::new(
            PackagedDriverChildRole::Client,
            TrafficMessage::RunFlow,
            plan.flow,
            encode_wire_plan(&plan).expect("encode bounded flow plan"),
        )
        .expect("construct bounded frame")
        .encode()
        .expect("encode fixed frame");
        assert_eq!(
            TrafficFrame::parse(&frame)
                .expect("parse exact frame")
                .require(
                    PackagedDriverChildRole::Client,
                    TrafficMessage::RunFlow,
                    plan.flow,
                )
                .expect("match exact typed frame"),
            encode_wire_plan(&plan).expect("re-encode bounded flow plan")
        );

        for malformed in [
            frame[..TRAFFIC_HEADER_BYTES - 1].to_vec(),
            {
                let mut bytes = frame.clone();
                bytes.push(0);
                bytes
            },
            {
                let mut bytes = frame.clone();
                bytes[0] ^= 0xff;
                bytes
            },
            {
                let mut bytes = frame.clone();
                bytes[7] = 1;
                bytes
            },
        ] {
            assert!(matches!(
                TrafficFrame::parse(&malformed),
                Err(PackagedDriverChildError::Protocol(_))
            ));
        }
    }

    #[test]
    fn child_sequence_rejects_wrong_role_order_duplicates_and_skips() {
        assert!(
            validate_child_sequence(
                PackagedDriverChildRole::Client,
                None,
                CanaryFlow::Ipv4TcpEcho,
            )
            .is_ok()
        );
        for (role, previous, next) in [
            (
                PackagedDriverChildRole::Client,
                None,
                CanaryFlow::Ipv4UdpEcho,
            ),
            (
                PackagedDriverChildRole::Client,
                Some(CanaryFlow::Ipv4TcpEcho),
                CanaryFlow::Ipv4TcpEcho,
            ),
            (
                PackagedDriverChildRole::TcpEcho,
                Some(CanaryFlow::Ipv4TcpEcho),
                CanaryFlow::Ipv6UdpEcho,
            ),
            (
                PackagedDriverChildRole::Dns,
                Some(CanaryFlow::Ipv4DnsUdp),
                CanaryFlow::Ipv6DnsUdp,
            ),
        ] {
            assert!(matches!(
                validate_child_sequence(role, previous, next),
                Err(PackagedDriverChildError::Protocol(_))
            ));
        }
    }
}
