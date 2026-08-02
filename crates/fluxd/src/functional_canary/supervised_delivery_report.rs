use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU64};
use std::time::Instant;

use super::{
    CanaryAttemptObjectIdentity, CanaryAttemptRequest, CanaryFlow, CanaryFlowAddressFamily,
    CanaryFlowKind, CanaryFlowProtocol, CanaryInboundDeliveryAuthority, CanaryInboundDeliveryEvent,
    CanaryInboundPayloadDigest, CanaryInboundPayloadIdentity, CanaryInetDiagCookie,
    CanaryOriginalDestinationCmsg, CanaryProcFd, CanaryTproxyAcceptedSocketDelivery,
    CanaryTproxyUdpRecvmsgDelivery, FUNCTIONAL_CANARY_FLOW_SLOTS,
};
#[cfg(test)]
use super::{CanaryTproxyListenerSocketIdentity, UnqualifiedCanaryInboundListenerDeliveryEvidence};
use crate::OwnedEngineIdentity;
#[cfg(test)]
use crate::generation_engine_config::ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FRAME_BYTES;
use crate::generation_engine_config::{
    ENGINE_SUPERVISED_DELIVERY_REPORT_ATTEMPT_NONCE_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_HIGH_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_LOW_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_CUMULATIVE_LOSS_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_PID_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_START_TICKS_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_FLAGS_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_FRAME_LENGTH_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_GENERATION_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_BYTES,
    ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_LENGTH_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_RESERVED_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_KIND_FIELD, ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC,
    ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC_FIELD, ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_EVENTS,
    ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_FRAME_BYTES,
    ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_KIND_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_QUESTION_DIGEST_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_RESERVED_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TCP_LENGTH_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TRANSACTION_ID_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_DIGEST_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_LENGTH_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_PROFILE_REVISION_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_REPORT_OBJECT_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION,
    ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_SEQUENCE_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_FAMILY_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_IPV4_ADDRESS_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_PORT_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_RESERVED_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_COOKIE_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_FD_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_INODE_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_RESERVED_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_RESERVED_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LISTENER_COOKIE_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LOCAL_ADDRESS_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PAYLOAD_IDENTITY_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PEER_ADDRESS_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_EVENT_COUNT_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_RESERVED_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CLIENT_ADDRESS_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_COUNT_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_FAMILY_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_LENGTH_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CONTROL_TRUNCATED_FLAG,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_FLOW_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_LISTENER_COOKIE_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_ORIGINAL_DESTINATION_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_IDENTITY_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_TRUNCATED_FLAG,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_RESERVED_FIELD,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_TRUNCATION_FLAGS,
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_TRUNCATION_FLAGS_FIELD, EngineCapabilityProfile,
    EngineCapabilityProfileRevision,
    EngineSupervisedDeliveryReportAddressFamilyCode as AddressFamilyCode,
    EngineSupervisedDeliveryReportFlowCode as FlowCode,
    EngineSupervisedDeliveryReportFrameKind as FrameKind,
    EngineSupervisedDeliveryReportPayloadKind as PayloadKind,
    EngineSupervisedDeliveryReportWireCodec as WireCodec,
    EngineSupervisedDeliveryReportWireField as WireField,
};

mod collector;
pub(super) use collector::CanaryListenerDeliveryReportCleanupDisposition;
pub(crate) use collector::CanaryListenerDeliveryReportCleanupEvidence;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SupervisedDeliveryReportBindError {
    CapabilityUnavailable,
    NonCanonicalContract,
    ArtifactSetMismatch,
    ProfileRevisionMismatch,
}

impl fmt::Display for SupervisedDeliveryReportBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cannot bind supervised delivery-report parser: {self:?}"
        )
    }
}

impl Error for SupervisedDeliveryReportBindError {}

/// Sealed authority for opening one parser against an immutable request and engine profile.
///
/// There is deliberately no production constructor in checkpoint 13d. The future collector will
/// own the real attempt seqpacket and become the only production source of this authority.
#[derive(Debug)]
pub(super) struct SupervisedDeliveryReportParserAuthority {
    _sealed: (),
}

impl SupervisedDeliveryReportParserAuthority {
    const fn collector() -> Self {
        Self { _sealed: () }
    }

    #[cfg(test)]
    const fn fixture() -> Self {
        Self { _sealed: () }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SupervisedDeliveryReportIdentityField {
    Generation,
    EngineProcess,
    ReportObject,
    EngineProfileRevision,
    AttemptNonce,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SupervisedDeliveryReportError {
    Poisoned,
    TransportTruncated,
    FrameTooLarge,
    FrameTruncated,
    TrailingBytes,
    InvalidMagic,
    UnsupportedSchema,
    UnknownFrameKind,
    NonzeroHeaderFlags,
    NonCanonicalHeaderLength,
    NonCanonicalFrameLength,
    NonzeroReservedField,
    IdentityMismatch(SupervisedDeliveryReportIdentityField),
    SequenceMismatch,
    DeliveryLossObserved,
    UnknownFlow,
    FlowOrderMismatch,
    FlowTransportMismatch,
    TooManyDeliveryEvents,
    InvalidSocketIdentity,
    UnknownAddressFamily,
    AddressFamilyMismatch,
    NonCanonicalSocketAddress,
    UnknownPayloadKind,
    PayloadKindMismatch,
    NonCanonicalPayloadIdentity,
    UnknownDatagramFlags,
    TerminalBeforeAllDeliveries,
    TerminalEventCountMismatch,
    PostTerminalFrame,
    PrematureEof,
    ObservationTimeInvalid,
}

impl fmt::Display for SupervisedDeliveryReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid supervised delivery-report stream: {self:?}"
        )
    }
}

impl Error for SupervisedDeliveryReportError {}

#[derive(Clone, Copy)]
pub(super) struct SupervisedDeliveryReportDatagram<'a> {
    bytes: &'a [u8],
    transport_truncated: bool,
    observed_at: Instant,
}

impl<'a> SupervisedDeliveryReportDatagram<'a> {
    #[must_use]
    pub(super) const fn new(
        bytes: &'a [u8],
        transport_truncated: bool,
        observed_at: Instant,
    ) -> Self {
        Self {
            bytes,
            transport_truncated,
            observed_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ParsedSupervisedDeliveryTransport {
    Tcp(CanaryTproxyAcceptedSocketDelivery),
    Udp(CanaryTproxyUdpRecvmsgDelivery),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ParsedSupervisedDeliveryEvent {
    flow: CanaryFlow,
    transport: ParsedSupervisedDeliveryTransport,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) struct SupervisedDeliveryReportSchemaV2FixtureAuthority {
    _sealed: (),
}

#[cfg(test)]
impl SupervisedDeliveryReportSchemaV2FixtureAuthority {
    const fn fixture() -> Self {
        Self { _sealed: () }
    }
}

#[cfg(test)]
impl ParsedSupervisedDeliveryEvent {
    fn into_schema_v2_fixture(
        self,
        _authority: SupervisedDeliveryReportSchemaV2FixtureAuthority,
        listener: CanaryTproxyListenerSocketIdentity,
    ) -> Result<UnqualifiedCanaryInboundListenerDeliveryEvidence, SupervisedDeliveryReportError>
    {
        if listener.protocol != self.flow.protocol()
            || listener.address_family != self.flow.address_family()
        {
            return Err(SupervisedDeliveryReportError::FlowTransportMismatch);
        }
        Ok(match self.transport {
            ParsedSupervisedDeliveryTransport::Tcp(accepted) => {
                UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyTcp { listener, accepted }
            }
            ParsedSupervisedDeliveryTransport::Udp(datagram) => {
                UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyUdp { listener, datagram }
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParserState {
    Active,
    Terminal { observed_at: Instant },
    Failed,
}

#[derive(Clone, Copy, Debug)]
struct ParserBinding {
    generation: u32,
    engine: OwnedEngineIdentity,
    profile_revision: EngineCapabilityProfileRevision,
    report_object: CanaryAttemptObjectIdentity,
    nonce: super::CanaryNonce,
    deadline: super::CanaryDeadline,
    required_flows: [Option<CanaryFlow>; FUNCTIONAL_CANARY_FLOW_SLOTS],
    required_flow_count: usize,
}

#[derive(Debug)]
pub(super) struct SupervisedDeliveryReportParser {
    binding: ParserBinding,
    state: ParserState,
    events: [Option<ParsedSupervisedDeliveryEvent>; FUNCTIONAL_CANARY_FLOW_SLOTS],
    next_flow: usize,
    next_sequence: u64,
    last_observed_at: Option<Instant>,
}

impl SupervisedDeliveryReportParser {
    pub(super) fn bind(
        _authority: SupervisedDeliveryReportParserAuthority,
        profile: &EngineCapabilityProfile,
        request: &CanaryAttemptRequest,
    ) -> Result<Self, SupervisedDeliveryReportBindError> {
        let contract = profile
            .supervised_delivery_report()
            .ok_or(SupervisedDeliveryReportBindError::CapabilityUnavailable)?;
        if contract.schema_version().get() != ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION
            || !contract.is_canonical_schema_v1()
            || usize::from(ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_EVENTS)
                != FUNCTIONAL_CANARY_FLOW_SLOTS
        {
            return Err(SupervisedDeliveryReportBindError::NonCanonicalContract);
        }
        let engine = request.pre_binding().engine();
        if profile.artifacts() != engine.artifacts() {
            return Err(SupervisedDeliveryReportBindError::ArtifactSetMismatch);
        }
        if profile.revision() != engine.engine_profile_revision() {
            return Err(SupervisedDeliveryReportBindError::ProfileRevisionMismatch);
        }

        let mut required_flows = [None; FUNCTIONAL_CANARY_FLOW_SLOTS];
        let mut required_flow_count = 0;
        for flow in CanaryFlow::ALL {
            if request.requires_flow(flow) {
                required_flows[required_flow_count] = Some(flow);
                required_flow_count += 1;
            }
        }
        Ok(Self {
            binding: ParserBinding {
                generation: engine.generation().get(),
                engine: engine.engine(),
                profile_revision: profile.revision(),
                report_object: request
                    .pre_binding()
                    .environment()
                    .attempt_objects()
                    .listener_delivery_report(),
                nonce: request.nonce(),
                deadline: request.deadline(),
                required_flows,
                required_flow_count,
            },
            state: ParserState::Active,
            events: std::array::from_fn(|_| None),
            next_flow: 0,
            next_sequence: 1,
            last_observed_at: None,
        })
    }

    pub(super) fn ingest(
        &mut self,
        datagram: SupervisedDeliveryReportDatagram<'_>,
    ) -> Result<(), SupervisedDeliveryReportError> {
        if self.state == ParserState::Failed {
            return Err(SupervisedDeliveryReportError::Poisoned);
        }
        if matches!(self.state, ParserState::Terminal { .. }) {
            self.state = ParserState::Failed;
            return Err(SupervisedDeliveryReportError::PostTerminalFrame);
        }
        let result = self.ingest_active(datagram);
        if result.is_err() {
            self.state = ParserState::Failed;
        }
        result
    }

    fn ingest_active(
        &mut self,
        datagram: SupervisedDeliveryReportDatagram<'_>,
    ) -> Result<(), SupervisedDeliveryReportError> {
        self.validate_observation_time(datagram.observed_at)?;
        let (header, mut cursor) = self.parse_header(datagram)?;
        if header.sequence != self.next_sequence {
            return Err(SupervisedDeliveryReportError::SequenceMismatch);
        }
        if header.cumulative_loss != 0 {
            return Err(SupervisedDeliveryReportError::DeliveryLossObserved);
        }

        if header.kind == FrameKind::Terminal {
            if self.next_flow != self.binding.required_flow_count {
                return Err(SupervisedDeliveryReportError::TerminalBeforeAllDeliveries);
            }
            let event_count = usize::from(
                cursor.read_u8(ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_EVENT_COUNT_FIELD)?,
            );
            cursor.require_zeroes(ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_RESERVED_FIELD)?;
            cursor.finish()?;
            if event_count != self.binding.required_flow_count {
                return Err(SupervisedDeliveryReportError::TerminalEventCountMismatch);
            }
            self.last_observed_at = Some(datagram.observed_at);
            self.state = ParserState::Terminal {
                observed_at: datagram.observed_at,
            };
            return Ok(());
        }

        if self.next_flow >= self.binding.required_flow_count {
            return Err(SupervisedDeliveryReportError::TooManyDeliveryEvents);
        }
        let expected_flow = self.binding.required_flows[self.next_flow]
            .expect("required flow count indexes initialized slots");
        let parsed = match header.kind {
            FrameKind::TcpDelivery => {
                self.parse_tcp_delivery(&mut cursor, expected_flow, header)?
            }
            FrameKind::UdpDelivery => {
                self.parse_udp_delivery(&mut cursor, expected_flow, header)?
            }
            FrameKind::Terminal => unreachable!("terminal handled above"),
        };
        cursor.finish()?;
        if self.events[parsed.flow.index()].replace(parsed).is_some() {
            return Err(SupervisedDeliveryReportError::FlowOrderMismatch);
        }
        self.next_flow += 1;
        self.next_sequence += 1;
        self.last_observed_at = Some(datagram.observed_at);
        Ok(())
    }

    pub(super) fn observe_drained_eof(
        self,
        observed_at: Instant,
    ) -> Result<CompletedSupervisedDeliveryReport, SupervisedDeliveryReportError> {
        let ParserState::Terminal {
            observed_at: terminal_observed_at,
        } = self.state
        else {
            return Err(SupervisedDeliveryReportError::PrematureEof);
        };
        if observed_at < terminal_observed_at
            || observed_at < self.binding.deadline.started_at()
            || observed_at >= self.binding.deadline.expires_at()
        {
            return Err(SupervisedDeliveryReportError::ObservationTimeInvalid);
        }
        Ok(CompletedSupervisedDeliveryReport {
            binding: self.binding,
            events: self.events,
            terminal_observed_at,
            eof_observed_at: observed_at,
        })
    }

    fn validate_observation_time(
        &self,
        observed_at: Instant,
    ) -> Result<(), SupervisedDeliveryReportError> {
        if observed_at < self.binding.deadline.started_at()
            || observed_at >= self.binding.deadline.expires_at()
            || self
                .last_observed_at
                .is_some_and(|previous| observed_at < previous)
        {
            return Err(SupervisedDeliveryReportError::ObservationTimeInvalid);
        }
        Ok(())
    }

    fn parse_header<'a>(
        &self,
        datagram: SupervisedDeliveryReportDatagram<'a>,
    ) -> Result<(ParsedHeader, FrameCursor<'a>), SupervisedDeliveryReportError> {
        if datagram.transport_truncated {
            return Err(SupervisedDeliveryReportError::TransportTruncated);
        }
        if datagram.bytes.len() > usize::from(ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_FRAME_BYTES) {
            return Err(SupervisedDeliveryReportError::FrameTooLarge);
        }
        if datagram.bytes.len() < usize::from(ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_BYTES) {
            return Err(SupervisedDeliveryReportError::FrameTruncated);
        }
        let mut cursor = FrameCursor::new(datagram.bytes);
        if cursor.take::<8>(ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC_FIELD)?
            != &ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC
        {
            return Err(SupervisedDeliveryReportError::InvalidMagic);
        }
        if cursor.read_u16(ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION_FIELD)?
            != ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION
        {
            return Err(SupervisedDeliveryReportError::UnsupportedSchema);
        }
        let kind = FrameKind::from_wire_value(
            cursor.read_u8(ENGINE_SUPERVISED_DELIVERY_REPORT_KIND_FIELD)?,
        )
        .ok_or(SupervisedDeliveryReportError::UnknownFrameKind)?;
        if cursor.read_u8(ENGINE_SUPERVISED_DELIVERY_REPORT_FLAGS_FIELD)? != 0 {
            return Err(SupervisedDeliveryReportError::NonzeroHeaderFlags);
        }
        let declared_length =
            usize::from(cursor.read_u16(ENGINE_SUPERVISED_DELIVERY_REPORT_FRAME_LENGTH_FIELD)?);
        if declared_length > datagram.bytes.len() {
            return Err(SupervisedDeliveryReportError::FrameTruncated);
        }
        if declared_length < datagram.bytes.len() {
            return Err(SupervisedDeliveryReportError::TrailingBytes);
        }
        if cursor.read_u16(ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_LENGTH_FIELD)?
            != ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_BYTES
        {
            return Err(SupervisedDeliveryReportError::NonCanonicalHeaderLength);
        }
        if declared_length != usize::from(kind.frame_bytes()) {
            return Err(SupervisedDeliveryReportError::NonCanonicalFrameLength);
        }
        let sequence = cursor.read_u64(ENGINE_SUPERVISED_DELIVERY_REPORT_SEQUENCE_FIELD)?;
        let cumulative_loss =
            cursor.read_u64(ENGINE_SUPERVISED_DELIVERY_REPORT_CUMULATIVE_LOSS_FIELD)?;
        if cursor.read_u32(ENGINE_SUPERVISED_DELIVERY_REPORT_GENERATION_FIELD)?
            != self.binding.generation
        {
            return Err(SupervisedDeliveryReportError::IdentityMismatch(
                SupervisedDeliveryReportIdentityField::Generation,
            ));
        }
        if cursor.read_u32(ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_PID_FIELD)?
            != self.binding.engine.pid()
            || cursor.read_u64(ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_START_TICKS_FIELD)?
                != self.binding.engine.start_time_ticks()
        {
            return Err(SupervisedDeliveryReportError::IdentityMismatch(
                SupervisedDeliveryReportIdentityField::EngineProcess,
            ));
        }
        if cursor.take::<32>(ENGINE_SUPERVISED_DELIVERY_REPORT_REPORT_OBJECT_FIELD)?
            != &self.binding.report_object.0
        {
            return Err(SupervisedDeliveryReportError::IdentityMismatch(
                SupervisedDeliveryReportIdentityField::ReportObject,
            ));
        }
        if cursor.take::<32>(ENGINE_SUPERVISED_DELIVERY_REPORT_PROFILE_REVISION_FIELD)?
            != self.binding.profile_revision.as_bytes()
        {
            return Err(SupervisedDeliveryReportError::IdentityMismatch(
                SupervisedDeliveryReportIdentityField::EngineProfileRevision,
            ));
        }
        if cursor.take::<32>(ENGINE_SUPERVISED_DELIVERY_REPORT_ATTEMPT_NONCE_FIELD)?
            != self.binding.nonce.as_bytes()
        {
            return Err(SupervisedDeliveryReportError::IdentityMismatch(
                SupervisedDeliveryReportIdentityField::AttemptNonce,
            ));
        }
        cursor.require_zeroes(ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_RESERVED_FIELD)?;
        let payload_cursor = cursor.into_remaining();
        Ok((
            ParsedHeader {
                kind,
                sequence,
                cumulative_loss,
                observed_at: datagram.observed_at,
            },
            payload_cursor,
        ))
    }

    fn parse_tcp_delivery(
        &self,
        cursor: &mut FrameCursor<'_>,
        expected_flow: CanaryFlow,
        header: ParsedHeader,
    ) -> Result<ParsedSupervisedDeliveryEvent, SupervisedDeliveryReportError> {
        let flow = parse_flow(cursor.read_u8(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_FIELD)?)?;
        cursor.require_zeroes(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_RESERVED_FIELD)?;
        validate_flow(flow, expected_flow, CanaryFlowProtocol::Tcp)?;
        let listener_cookie = parse_cookie(
            cursor.scope(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LISTENER_COOKIE_FIELD)?,
        )?;
        let accepted_fd = CanaryProcFd::new(
            cursor.read_u32(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_FD_FIELD)?,
        )
        .ok_or(SupervisedDeliveryReportError::InvalidSocketIdentity)?;
        cursor.require_zeroes(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_RESERVED_FIELD)?;
        let accepted_inode = NonZeroU64::new(
            cursor.read_u64(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_INODE_FIELD)?,
        )
        .ok_or(SupervisedDeliveryReportError::InvalidSocketIdentity)?;
        let accepted_cookie = parse_cookie(
            cursor.scope(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_COOKIE_FIELD)?,
        )?;
        let local = parse_socket_address(
            cursor.scope(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LOCAL_ADDRESS_FIELD)?,
            flow.address_family(),
        )?;
        let peer = parse_socket_address(
            cursor.scope(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PEER_ADDRESS_FIELD)?,
            flow.address_family(),
        )?;
        let payload = parse_payload_identity(
            cursor.scope(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PAYLOAD_IDENTITY_FIELD)?,
            flow,
            self.binding.nonce,
        )?;
        let event = self.delivery_event(header);
        Ok(ParsedSupervisedDeliveryEvent {
            flow,
            transport: ParsedSupervisedDeliveryTransport::Tcp(CanaryTproxyAcceptedSocketDelivery {
                flow,
                engine: self.binding.engine,
                listener_cookie,
                accepted_fd,
                accepted_inode,
                accepted_cookie,
                local,
                peer,
                event,
                payload,
            }),
        })
    }

    fn parse_udp_delivery(
        &self,
        cursor: &mut FrameCursor<'_>,
        expected_flow: CanaryFlow,
        header: ParsedHeader,
    ) -> Result<ParsedSupervisedDeliveryEvent, SupervisedDeliveryReportError> {
        let flow = parse_flow(cursor.read_u8(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_FLOW_FIELD)?)?;
        let original_destination_cmsg_count =
            cursor.read_u8(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_COUNT_FIELD)?;
        let cmsg_family = parse_address_family(
            cursor.read_u8(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_FAMILY_FIELD)?,
        )?;
        let truncation_flags =
            cursor.read_u8(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_TRUNCATION_FLAGS_FIELD)?;
        if truncation_flags & !ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_TRUNCATION_FLAGS != 0 {
            return Err(SupervisedDeliveryReportError::UnknownDatagramFlags);
        }
        let cmsg_payload_length =
            cursor.read_u16(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_LENGTH_FIELD)?;
        cursor.require_zeroes(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_RESERVED_FIELD)?;
        validate_flow(flow, expected_flow, CanaryFlowProtocol::Udp)?;
        if cmsg_family != flow.address_family() {
            return Err(SupervisedDeliveryReportError::AddressFamilyMismatch);
        }
        let listener_cookie = parse_cookie(
            cursor.scope(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_LISTENER_COOKIE_FIELD)?,
        )?;
        let client_source = parse_socket_address(
            cursor.scope(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CLIENT_ADDRESS_FIELD)?,
            flow.address_family(),
        )?;
        let original_destination = parse_socket_address(
            cursor.scope(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_ORIGINAL_DESTINATION_FIELD)?,
            flow.address_family(),
        )?;
        let payload = parse_payload_identity(
            cursor.scope(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_IDENTITY_FIELD)?,
            flow,
            self.binding.nonce,
        )?;
        let original_destination_cmsg = match cmsg_family {
            CanaryFlowAddressFamily::Ipv4 => CanaryOriginalDestinationCmsg::Ipv4 {
                payload_length: cmsg_payload_length,
            },
            CanaryFlowAddressFamily::Ipv6 => CanaryOriginalDestinationCmsg::Ipv6 {
                payload_length: cmsg_payload_length,
            },
        };
        let event = self.delivery_event(header);
        Ok(ParsedSupervisedDeliveryEvent {
            flow,
            transport: ParsedSupervisedDeliveryTransport::Udp(CanaryTproxyUdpRecvmsgDelivery {
                flow,
                listener_cookie,
                client_source,
                original_destination,
                payload_truncated: truncation_flags
                    & ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_TRUNCATED_FLAG
                    != 0,
                control_truncated: truncation_flags
                    & ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CONTROL_TRUNCATED_FLAG
                    != 0,
                original_destination_cmsg_count,
                original_destination_cmsg,
                event,
                payload,
            }),
        })
    }

    fn delivery_event(&self, header: ParsedHeader) -> CanaryInboundDeliveryEvent {
        CanaryInboundDeliveryEvent {
            authority: CanaryInboundDeliveryAuthority::SupervisedEngineReport {
                engine: self.binding.engine,
                engine_profile_revision: self.binding.profile_revision,
                report_object: self.binding.report_object,
                schema_version: NonZeroU16::new(ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION)
                    .expect("supervised delivery-report schema is nonzero"),
            },
            sequence: NonZeroU64::new(header.sequence)
                .expect("validated delivery sequence is nonzero"),
            lost_events_before: header.cumulative_loss,
            lost_events_after: header.cumulative_loss,
            observed_at: header.observed_at,
        }
    }
}

#[derive(Debug)]
pub(super) struct CompletedSupervisedDeliveryReport {
    binding: ParserBinding,
    events: [Option<ParsedSupervisedDeliveryEvent>; FUNCTIONAL_CANARY_FLOW_SLOTS],
    terminal_observed_at: Instant,
    eof_observed_at: Instant,
}

impl CompletedSupervisedDeliveryReport {
    #[must_use]
    pub(super) const fn report_object(&self) -> CanaryAttemptObjectIdentity {
        self.binding.report_object
    }

    #[must_use]
    pub(super) const fn profile_revision(&self) -> EngineCapabilityProfileRevision {
        self.binding.profile_revision
    }

    #[must_use]
    pub(super) const fn terminal_observed_at(&self) -> Instant {
        self.terminal_observed_at
    }

    #[must_use]
    pub(super) const fn eof_observed_at(&self) -> Instant {
        self.eof_observed_at
    }

    #[cfg(test)]
    fn take_event(&mut self, flow: CanaryFlow) -> Option<ParsedSupervisedDeliveryEvent> {
        self.events[flow.index()].take()
    }
}

#[derive(Clone, Copy)]
struct ParsedHeader {
    kind: FrameKind,
    sequence: u64,
    cumulative_loss: u64,
    observed_at: Instant,
}

struct FrameCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> FrameCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn field(&mut self, field: WireField) -> Result<&'a [u8], SupervisedDeliveryReportError> {
        assert_eq!(
            self.offset,
            field.offset(),
            "supervised delivery-report fields must be consumed in contract order"
        );
        let bytes = self
            .bytes
            .get(field.offset()..field.end())
            .ok_or(SupervisedDeliveryReportError::FrameTruncated)?;
        self.offset = field.end();
        Ok(bytes)
    }

    fn take<const N: usize>(
        &mut self,
        field: WireField,
    ) -> Result<&'a [u8; N], SupervisedDeliveryReportError> {
        assert_eq!(
            field.bytes(),
            N,
            "supervised delivery-report field width must match its contract"
        );
        self.field(field)?
            .try_into()
            .map_err(|_| SupervisedDeliveryReportError::FrameTruncated)
    }

    fn view<const N: usize>(
        &self,
        field: WireField,
    ) -> Result<&'a [u8; N], SupervisedDeliveryReportError> {
        assert_eq!(
            field.bytes(),
            N,
            "supervised delivery-report field width must match its contract"
        );
        self.bytes
            .get(field.offset()..field.end())
            .ok_or(SupervisedDeliveryReportError::FrameTruncated)?
            .try_into()
            .map_err(|_| SupervisedDeliveryReportError::FrameTruncated)
    }

    fn read_u8(&mut self, field: WireField) -> Result<u8, SupervisedDeliveryReportError> {
        Ok(self.take::<1>(field)?[0])
    }

    fn read_u16(&mut self, field: WireField) -> Result<u16, SupervisedDeliveryReportError> {
        Ok(WireCodec::decode_u16(*self.take::<2>(field)?))
    }

    fn read_u32(&mut self, field: WireField) -> Result<u32, SupervisedDeliveryReportError> {
        Ok(WireCodec::decode_u32(*self.take::<4>(field)?))
    }

    fn read_u64(&mut self, field: WireField) -> Result<u64, SupervisedDeliveryReportError> {
        Ok(WireCodec::decode_u64(*self.take::<8>(field)?))
    }

    fn require_zeroes(&mut self, field: WireField) -> Result<(), SupervisedDeliveryReportError> {
        let bytes = self.field(field)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Err(SupervisedDeliveryReportError::NonzeroReservedField);
        }
        Ok(())
    }

    fn scope(&mut self, field: WireField) -> Result<Self, SupervisedDeliveryReportError> {
        Ok(Self::new(self.field(field)?))
    }

    fn into_remaining(self) -> Self {
        Self::new(
            self.bytes
                .get(self.offset..)
                .expect("a validated cursor offset remains within its frame"),
        )
    }

    fn finish(self) -> Result<(), SupervisedDeliveryReportError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SupervisedDeliveryReportError::TrailingBytes)
        }
    }
}

fn parse_flow(raw: u8) -> Result<CanaryFlow, SupervisedDeliveryReportError> {
    Ok(
        match FlowCode::from_wire_value(raw).ok_or(SupervisedDeliveryReportError::UnknownFlow)? {
            FlowCode::Ipv4TcpEcho => CanaryFlow::Ipv4TcpEcho,
            FlowCode::Ipv4UdpEcho => CanaryFlow::Ipv4UdpEcho,
            FlowCode::Ipv4DnsUdp => CanaryFlow::Ipv4DnsUdp,
            FlowCode::Ipv4DnsTcp => CanaryFlow::Ipv4DnsTcp,
            FlowCode::Ipv6TcpEcho => CanaryFlow::Ipv6TcpEcho,
            FlowCode::Ipv6UdpEcho => CanaryFlow::Ipv6UdpEcho,
            FlowCode::Ipv6DnsUdp => CanaryFlow::Ipv6DnsUdp,
            FlowCode::Ipv6DnsTcp => CanaryFlow::Ipv6DnsTcp,
        },
    )
}

fn validate_flow(
    flow: CanaryFlow,
    expected: CanaryFlow,
    protocol: CanaryFlowProtocol,
) -> Result<(), SupervisedDeliveryReportError> {
    if flow != expected {
        return Err(SupervisedDeliveryReportError::FlowOrderMismatch);
    }
    if flow.protocol() != protocol {
        return Err(SupervisedDeliveryReportError::FlowTransportMismatch);
    }
    Ok(())
}

fn parse_cookie(
    mut cursor: FrameCursor<'_>,
) -> Result<CanaryInetDiagCookie, SupervisedDeliveryReportError> {
    let cookie = CanaryInetDiagCookie::new(
        cursor.read_u32(ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_HIGH_FIELD)?,
        cursor.read_u32(ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_LOW_FIELD)?,
    )
    .ok_or(SupervisedDeliveryReportError::InvalidSocketIdentity)?;
    cursor.finish()?;
    Ok(cookie)
}

fn parse_address_family(raw: u8) -> Result<CanaryFlowAddressFamily, SupervisedDeliveryReportError> {
    Ok(
        match AddressFamilyCode::from_wire_value(raw)
            .ok_or(SupervisedDeliveryReportError::UnknownAddressFamily)?
        {
            AddressFamilyCode::Ipv4 => CanaryFlowAddressFamily::Ipv4,
            AddressFamilyCode::Ipv6 => CanaryFlowAddressFamily::Ipv6,
        },
    )
}

fn parse_socket_address(
    mut cursor: FrameCursor<'_>,
    expected_family: CanaryFlowAddressFamily,
) -> Result<SocketAddr, SupervisedDeliveryReportError> {
    let family = parse_address_family(
        cursor.read_u8(ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_FAMILY_FIELD)?,
    )?;
    if cursor.read_u8(ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_RESERVED_FIELD)? != 0 {
        return Err(SupervisedDeliveryReportError::NonzeroReservedField);
    }
    if family != expected_family {
        return Err(SupervisedDeliveryReportError::AddressFamilyMismatch);
    }
    let port = cursor.read_u16(ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_PORT_FIELD)?;
    if port == 0 {
        return Err(SupervisedDeliveryReportError::NonCanonicalSocketAddress);
    }
    let address = cursor.take::<16>(ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_FIELD)?;
    let ip = match family {
        CanaryFlowAddressFamily::Ipv4 => {
            let ipv4_offset = ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_IPV4_ADDRESS_FIELD.offset()
                - ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_FIELD.offset();
            if address[..ipv4_offset].iter().any(|byte| *byte != 0) {
                return Err(SupervisedDeliveryReportError::NonCanonicalSocketAddress);
            }
            IpAddr::V4(Ipv4Addr::from(*cursor.view::<4>(
                ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_IPV4_ADDRESS_FIELD,
            )?))
        }
        CanaryFlowAddressFamily::Ipv6 => IpAddr::V6(Ipv6Addr::from(*address)),
    };
    cursor.finish()?;
    if ip.is_unspecified() {
        return Err(SupervisedDeliveryReportError::NonCanonicalSocketAddress);
    }
    Ok(SocketAddr::new(ip, port))
}

fn parse_payload_identity(
    mut cursor: FrameCursor<'_>,
    flow: CanaryFlow,
    nonce: super::CanaryNonce,
) -> Result<CanaryInboundPayloadIdentity, SupervisedDeliveryReportError> {
    let kind = PayloadKind::from_wire_value(
        cursor.read_u8(ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_KIND_FIELD)?,
    )
    .ok_or(SupervisedDeliveryReportError::UnknownPayloadKind)?;
    if cursor.read_u8(ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_RESERVED_FIELD)? != 0 {
        return Err(SupervisedDeliveryReportError::NonzeroReservedField);
    }
    let wire_length = NonZeroU16::new(
        cursor.read_u16(ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_LENGTH_FIELD)?,
    )
    .ok_or(SupervisedDeliveryReportError::NonCanonicalPayloadIdentity)?;
    let wire_digest = CanaryInboundPayloadDigest::from_bytes(
        *cursor.take::<32>(ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_DIGEST_FIELD)?,
    );
    let transaction_id =
        cursor.read_u16(ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TRANSACTION_ID_FIELD)?;
    let tcp_length_prefix =
        cursor.read_u16(ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TCP_LENGTH_FIELD)?;
    let question_bytes =
        *cursor.take::<32>(ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_QUESTION_DIGEST_FIELD)?;
    cursor.finish()?;
    match kind {
        PayloadKind::Echo => {
            if matches!(flow.kind(), CanaryFlowKind::DnsUdp | CanaryFlowKind::DnsTcp) {
                return Err(SupervisedDeliveryReportError::PayloadKindMismatch);
            }
            if transaction_id != 0
                || tcp_length_prefix != 0
                || question_bytes.iter().any(|byte| *byte != 0)
            {
                return Err(SupervisedDeliveryReportError::NonCanonicalPayloadIdentity);
            }
            Ok(CanaryInboundPayloadIdentity::Echo {
                nonce,
                wire_length,
                wire_digest,
            })
        }
        PayloadKind::Dns => {
            if !matches!(flow.kind(), CanaryFlowKind::DnsUdp | CanaryFlowKind::DnsTcp) {
                return Err(SupervisedDeliveryReportError::PayloadKindMismatch);
            }
            if question_bytes.iter().all(|byte| *byte == 0) {
                return Err(SupervisedDeliveryReportError::NonCanonicalPayloadIdentity);
            }
            let tcp_length_prefix = match flow.protocol() {
                CanaryFlowProtocol::Tcp if tcp_length_prefix == wire_length.get() => {
                    Some(tcp_length_prefix)
                }
                CanaryFlowProtocol::Udp if tcp_length_prefix == 0 => None,
                _ => return Err(SupervisedDeliveryReportError::NonCanonicalPayloadIdentity),
            };
            Ok(CanaryInboundPayloadIdentity::Dns {
                nonce,
                transaction_id,
                question: super::CanaryDnsQuestionDigest::from_bytes(question_bytes),
                wire_length,
                wire_digest,
                tcp_length_prefix,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    use std::fs::File;
    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    use std::net::TcpListener;
    use std::num::{NonZeroU32, NonZeroU64};
    use std::os::unix::fs::PermissionsExt;
    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use flux_core::GenerationId;
    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    use flux_platform::SeqpacketReceive;
    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    use flux_platform::internal::{PinnedSingBoxLaunch, SingBoxChild, SingBoxProcessAdapter};
    use flux_platform::{SingBoxLaunchSpec, SingBoxPrivilege, SingBoxReadiness};

    use super::*;
    use crate::functional_canary::tests::{Fixture, request_with_engine_profile_revision};
    use crate::functional_canary::{
        CanaryAddressFamilies, CanaryAttemptCredentialBinding,
        CanaryAttemptObjectRetirementEvidence, CanaryListenerDeliveryReportCleanupEvidence,
        CanaryNonce, CanaryProcessCredentialIdentity, FUNCTIONAL_CANARY_NONCE_BYTES,
    };
    use crate::generation_engine_config as report_contract;
    use crate::generation_engine_config::{
        TproxyEngineConfigRequest, bind_engine_config_to_spec,
        collect_tproxy_engine_capability_profile, compile_tproxy_engine_config,
        declare_supervised_delivery_report_profile_fixture,
    };
    use crate::{EngineSpec, RestartPolicy};

    const PROFILE_SCRIPT: &[u8] = br#"#!/bin/sh
case "$1" in
    version)
        printf '%s\n' 'sing-box version 1.13.14'
        ;;
    check)
        exit 0
        ;;
    *)
        exit 64
        ;;
esac
"#;

    struct Context {
        baseline_profile: EngineCapabilityProfile,
        profile: EngineCapabilityProfile,
        request: CanaryAttemptRequest,
        fixture: Fixture,
        _directory: tempfile::TempDir,
    }

    impl Context {
        fn new(families: CanaryAddressFamilies) -> Self {
            Self::with_script(families, PROFILE_SCRIPT)
        }

        fn with_script(families: CanaryAddressFamilies, script: &[u8]) -> Self {
            let artifact = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
                br#"{"inbounds":[]}"#,
                NonZeroU16::new(1536).expect("listener port"),
            ))
            .expect("compile parser engine config");
            let directory = tempfile::tempdir().expect("parser engine fixture");
            let binary = directory.path().join("sing-box");
            let config = directory.path().join("config.json");
            fs::write(&binary, script).expect("write parser engine");
            fs::write(&config, artifact.bytes()).expect("write parser engine config");
            let mut permissions = fs::metadata(&binary)
                .expect("parser engine mode")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&binary, permissions).expect("make parser engine executable");
            let spec = EngineSpec::new(
                SingBoxLaunchSpec {
                    binary,
                    config,
                    working_directory: directory.path().to_path_buf(),
                    log: directory.path().join("sing-box.log"),
                    privilege: SingBoxPrivilege::Inherit,
                    readiness: SingBoxReadiness::Listener {
                        port: NonZeroU16::new(1536).expect("listener port"),
                    },
                    startup_timeout: Duration::from_secs(1),
                    stop_timeout: Duration::from_secs(1),
                },
                RestartPolicy::new(
                    3,
                    Duration::from_secs(60),
                    Duration::from_secs(1),
                    Duration::from_secs(8),
                    Duration::from_secs(10),
                )
                .expect("parser restart policy"),
            )
            .expect("parser EngineSpec");
            let binding = bind_engine_config_to_spec(artifact, &spec).expect("parser binding");
            let baseline_profile = collect_tproxy_engine_capability_profile(&binding, &spec)
                .expect("parser baseline profile");
            let profile =
                declare_supervised_delivery_report_profile_fixture(baseline_profile.clone());
            let started_at = Instant::now();
            let producer_pid = NonZeroU32::new(std::process::id()).expect("test process PID");
            let mut request = request_with_engine_profile_revision(
                &spec,
                families,
                started_at,
                CanaryNonce::from_bytes([0x71; FUNCTIONAL_CANARY_NONCE_BYTES]),
                GenerationId::new(17).expect("generation"),
                producer_pid,
                NonZeroU64::new(98_765).expect("engine start ticks"),
                NonZeroU64::new(23).expect("snapshot revision"),
                profile.revision(),
            );
            if let Some((producer_uid, producer_gid)) = non_root_process_credentials() {
                bind_request_engine_credentials(&mut request, producer_uid, producer_gid);
            }
            let fixture = Fixture::from_request(request.clone());
            Self {
                baseline_profile,
                profile,
                request,
                fixture,
                _directory: directory,
            }
        }

        fn parser(&self) -> SupervisedDeliveryReportParser {
            SupervisedDeliveryReportParser::bind(
                SupervisedDeliveryReportParserAuthority::fixture(),
                &self.profile,
                &self.request,
            )
            .expect("bind parser fixture")
        }

        fn evidence(&self) -> super::super::UnqualifiedCanaryGateEvidence {
            self.fixture.successful_evidence()
        }
    }

    fn distinct_test_identity(identity: NonZeroU32) -> NonZeroU32 {
        NonZeroU32::new(if identity.get() == u32::MAX - 1 {
            identity.get() - 1
        } else {
            identity.get() + 1
        })
        .expect("distinct test identity remains nonzero")
    }

    fn non_root_process_credentials() -> Option<(NonZeroU32, NonZeroU32)> {
        // SAFETY: these identity getters have no pointer arguments or preconditions.
        let uid = NonZeroU32::new(unsafe { libc::geteuid() })?;
        // SAFETY: see the effective-UID call above.
        let gid = NonZeroU32::new(unsafe { libc::getegid() })?;
        Some((uid, gid))
    }

    fn bind_request_engine_credentials(
        request: &mut CanaryAttemptRequest,
        engine_uid: NonZeroU32,
        engine_gid: NonZeroU32,
    ) {
        let environment = &mut request.pre_binding.environment;
        environment.credentials = CanaryAttemptCredentialBinding::new(
            CanaryProcessCredentialIdentity::new(
                distinct_test_identity(engine_uid),
                distinct_test_identity(engine_gid),
            ),
            CanaryProcessCredentialIdentity::new(engine_uid, engine_gid),
            environment.credentials.domain,
        )
        .expect("distinct test transport credentials");
        environment.rpdb.engine_uid = engine_uid;
    }

    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    struct NativeLaunchControlFixture {
        _directory: tempfile::TempDir,
        evidence: PathBuf,
        spec: EngineSpec,
        profile: EngineCapabilityProfile,
        pinned: PinnedSingBoxLaunch,
        adapter: SingBoxProcessAdapter,
    }

    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    impl NativeLaunchControlFixture {
        fn new() -> Self {
            let binary = native_composition_engine_binary();
            let directory = tempfile::tempdir().expect("launch-control fixture directory");
            let evidence = directory.path().join("control-evidence");
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("reserve launch-control listener port");
            let port = NonZeroU16::new(
                listener
                    .local_addr()
                    .expect("reserved launch-control listener address")
                    .port(),
            )
            .expect("reserved launch-control listener port is nonzero");
            drop(listener);
            let template = serde_json::to_vec(&serde_json::json!({
                "flux_test_launch_control_evidence": evidence
                    .to_str()
                    .expect("launch-control evidence path is UTF-8"),
                "inbounds": [],
            }))
            .expect("encode launch-control template");
            let artifact =
                compile_tproxy_engine_config(TproxyEngineConfigRequest::new(&template, port))
                    .expect("compile launch-control engine config");
            let config = directory.path().join("config.json");
            fs::write(&config, artifact.bytes()).expect("write launch-control engine config");
            let spec = EngineSpec::new(
                SingBoxLaunchSpec {
                    binary: binary.clone(),
                    config: config.clone(),
                    working_directory: directory.path().to_path_buf(),
                    log: directory.path().join("engine.log"),
                    privilege: SingBoxPrivilege::Inherit,
                    readiness: SingBoxReadiness::Listener { port },
                    startup_timeout: Duration::from_secs(2),
                    stop_timeout: Duration::from_secs(1),
                },
                RestartPolicy::new(
                    1,
                    Duration::from_secs(1),
                    Duration::from_millis(10),
                    Duration::from_millis(10),
                    Duration::from_secs(1),
                )
                .expect("launch-control restart policy"),
            )
            .expect("inspect launch-control EngineSpec");
            let binding =
                bind_engine_config_to_spec(artifact, &spec).expect("bind launch-control config");
            let profile = declare_supervised_delivery_report_profile_fixture(
                collect_tproxy_engine_capability_profile(&binding, &spec)
                    .expect("collect launch-control fixture profile"),
            );
            let pinned = PinnedSingBoxLaunch::new(
                File::open(&binary).expect("open launch-control fixture binary"),
                File::open(&config).expect("open launch-control fixture config"),
            )
            .expect("pin launch-control fixture artifacts");
            Self {
                _directory: directory,
                evidence,
                spec,
                profile,
                pinned,
                adapter: SingBoxProcessAdapter,
            }
        }

        fn spawn(&self) -> SingBoxChild {
            self.adapter
                .spawn_pinned(&self.pinned, self.spec.process())
                .expect("spawn exact launch-control child")
        }

        fn request_for_child(
            &self,
            child: &SingBoxChild,
            engine_uid: NonZeroU32,
            engine_gid: NonZeroU32,
        ) -> CanaryAttemptRequest {
            let identity = child.identity();
            let mut request = request_with_engine_profile_revision(
                &self.spec,
                CanaryAddressFamilies::Ipv4AndIpv6,
                Instant::now(),
                CanaryNonce::from_bytes([0x91; FUNCTIONAL_CANARY_NONCE_BYTES]),
                GenerationId::new(29).expect("launch-control generation"),
                NonZeroU32::new(identity.pid()).expect("launch-control child PID"),
                NonZeroU64::new(identity.start_time_ticks())
                    .expect("launch-control child start ticks"),
                NonZeroU64::new(31).expect("launch-control engine snapshot revision"),
                self.profile.revision(),
            );
            bind_request_engine_credentials(&mut request, engine_uid, engine_gid);
            request
        }

        fn prebind<C>(
            &self,
            request: &CanaryAttemptRequest,
            clock: C,
        ) -> (
            collector::SupervisedDeliveryReportEngineHandoff,
            collector::SupervisedDeliveryReportCollector<C>,
        )
        where
            C: FnMut() -> Instant,
        {
            let authority = collector::SupervisedDeliveryReportPrebindAuthority::fixture(
                &self.profile,
                request,
            );
            let (producer, collector) =
                collector::prebind(authority, clock).expect("prebind launch-control report");
            (producer.into_engine_handoff(), collector)
        }
    }

    #[test]
    fn profile_capability_and_runtime_revision_are_both_required() {
        let context = Context::new(CanaryAddressFamilies::Ipv4Only);
        assert_eq!(
            SupervisedDeliveryReportParser::bind(
                SupervisedDeliveryReportParserAuthority::fixture(),
                &context.baseline_profile,
                &context.request,
            )
            .expect_err("ordinary collected profile has no report producer"),
            SupervisedDeliveryReportBindError::CapabilityUnavailable
        );

        let mut revision_drift = context.request.clone();
        revision_drift.pre_binding.engine.engine_profile_revision =
            EngineCapabilityProfileRevision::from_fixture_bytes([9; 32]);
        assert_eq!(
            SupervisedDeliveryReportParser::bind(
                SupervisedDeliveryReportParserAuthority::fixture(),
                &context.profile,
                &revision_drift,
            )
            .expect_err("request cannot drift from the immutable profile"),
            SupervisedDeliveryReportBindError::ProfileRevisionMismatch
        );

        let alternate = Context::with_script(
            CanaryAddressFamilies::Ipv4Only,
            b"#!/bin/sh\n# distinct artifact\ncase \"$1\" in version) printf '%s\\n' 'sing-box version 1.13.14';; check) exit 0;; *) exit 64;; esac\n",
        );
        assert_eq!(
            SupervisedDeliveryReportParser::bind(
                SupervisedDeliveryReportParserAuthority::fixture(),
                &alternate.profile,
                &context.request,
            )
            .expect_err("another artifact cannot supply the report"),
            SupervisedDeliveryReportBindError::ArtifactSetMismatch
        );
    }

    #[test]
    fn engine_handoff_frame_is_the_exact_canonical_dual_stack_attempt() {
        let context = Context::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let (handoff, _collector) = prebind_report_collector(&context, Instant::now);

        let frame = handoff.encoded_frame().expect("encode engine handoff");
        let engine = context.request.pre_binding().engine();
        let engine_identity = engine.engine();

        assert_eq!(
            frame.len(),
            usize::from(report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FRAME_BYTES)
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_MAGIC_FIELD,
            ),
            report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_MAGIC
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_SCHEMA_VERSION_FIELD,
            ),
            report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_SCHEMA_VERSION.to_be_bytes()
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_KIND_FIELD,
            ),
            [report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ATTEMPT_KIND]
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FLAGS_FIELD,
            ),
            [0]
        );
        for field in [
            report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FRAME_LENGTH_FIELD,
            report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_HEADER_LENGTH_FIELD,
        ] {
            assert_eq!(
                handoff_field(&frame, field),
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FRAME_BYTES
                    .to_be_bytes()
            );
        }
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REQUEST_SCHEMA_FIELD,
            ),
            context.request.schema_version().to_be_bytes()
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REPORT_SCHEMA_FIELD,
            ),
            report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION.to_be_bytes()
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FAMILIES_FIELD,
            ),
            [
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_IPV4_FLAG
                    | report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_IPV6_FLAG
            ]
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REQUIRED_FLOWS_FIELD,
            ),
            [report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_DUAL_STACK_FLOW_MASK]
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_BACKEND_FIELD,
            ),
            [report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_TPROXY_BACKEND]
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_PREFIX_RESERVED_FIELD,
            ),
            [0]
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_GENERATION_FIELD,
            ),
            engine.generation().get().to_be_bytes()
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ENGINE_PID_FIELD,
            ),
            engine_identity.pid().to_be_bytes()
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ENGINE_START_TICKS_FIELD,
            ),
            engine_identity.start_time_ticks().to_be_bytes()
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ENGINE_SNAPSHOT_REVISION_FIELD,
            ),
            engine.engine_snapshot_revision().get().to_be_bytes()
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REPORT_OBJECT_FIELD,
            ),
            [15; 32]
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_PROFILE_REVISION_FIELD,
            ),
            context.profile.revision().as_bytes()
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ATTEMPT_NONCE_FIELD,
            ),
            context.request.nonce().as_bytes()
        );
        assert_eq!(
            handoff_field(
                &frame,
                report_contract::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_RESERVED_FIELD,
            ),
            [0; 16]
        );
    }

    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    #[test]
    fn exact_pinned_exec_receives_the_canonical_handoff_and_sole_producer() {
        let Some((engine_uid, engine_gid)) = non_root_process_credentials() else {
            return;
        };
        let fixture = NativeLaunchControlFixture::new();
        let mut child = fixture.spawn();
        fixture
            .adapter
            .wait_ready(&mut child, fixture.spec.process())
            .expect("launch-control child becomes ready");
        let request = fixture.request_for_child(&child, engine_uid, engine_gid);
        let (handoff, collector) = fixture.prebind(&request, Instant::now);
        let expected_frame = handoff.encoded_frame().expect("canonical handoff frame");
        let expected_child = request.pre_binding().engine().engine();
        let expected_report_object = request
            .pre_binding()
            .environment()
            .attempt_objects()
            .listener_delivery_report();

        let installed = handoff
            .install_into(&child)
            .expect("install producer into exact pinned child");

        assert_eq!(installed.child(), expected_child);
        assert_eq!(installed.report_object(), expected_report_object);
        assert_eq!(installed.profile_revision(), fixture.profile.revision());
        let deadline = Instant::now() + Duration::from_secs(5);
        match collector
            .recv_fixture_record_until(64, deadline)
            .expect("receive transferred producer proof")
        {
            Some(SeqpacketReceive::Record {
                bytes,
                truncated,
                credentials,
            }) => {
                assert_eq!(bytes, b"flux-native-control-producer");
                assert!(!truncated);
                assert_eq!(credentials.pid(), child.identity().pid());
                assert_eq!(credentials.uid().as_raw(), engine_uid.get());
                assert_eq!(credentials.gid(), engine_gid.get());
            }
            Some(SeqpacketReceive::Eof) => {
                panic!("transferred producer closed before sending its proof")
            }
            None => panic!("transferred producer proof deadline expired"),
        }
        assert!(matches!(
            collector
                .recv_fixture_record_until(1, deadline)
                .expect("observe sole producer closure"),
            Some(SeqpacketReceive::Eof)
        ));
        assert!(matches!(
            child
                .launch_control()
                .recv_record_until(1, deadline)
                .expect("observe child launch-control closure"),
            Some(SeqpacketReceive::Eof)
        ));
        wait_for_fixture_path(&fixture.evidence.join("complete"));
        assert_eq!(
            fs::read(fixture.evidence.join("frame.bin")).expect("read child handoff frame"),
            expected_frame
        );
        assert_eq!(
            fs::read_to_string(fixture.evidence.join("sender.txt"))
                .expect("read handoff sender credentials"),
            format!("{}\t{}\t{}\n", std::process::id(), engine_uid, engine_gid)
        );
        assert_eq!(
            fixture
                .adapter
                .try_wait(&mut child)
                .expect("poll launch-control child"),
            None,
            "fixture child must remain alive after closing both producer endpoints"
        );
        fixture
            .adapter
            .terminate(&mut child, Duration::from_secs(1))
            .expect("terminate and reap launch-control child");
    }

    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    #[test]
    fn wrong_child_handoff_sends_nothing_and_closes_the_producer() {
        let Some((engine_uid, engine_gid)) = non_root_process_credentials() else {
            return;
        };
        let fixture = NativeLaunchControlFixture::new();
        let mut child = fixture.spawn();
        fixture
            .adapter
            .wait_ready(&mut child, fixture.spec.process())
            .expect("launch-control child becomes ready");
        let mut request = fixture.request_for_child(&child, engine_uid, engine_gid);
        let actual = request.pre_binding().engine().engine();
        let wrong_pid = distinct_test_identity(
            NonZeroU32::new(actual.pid()).expect("actual launch-control child PID"),
        );
        request.pre_binding.engine.engine = OwnedEngineIdentity::new(
            wrong_pid,
            NonZeroU64::new(actual.start_time_ticks()).expect("actual child start ticks"),
        );
        let expected = request.pre_binding().engine().engine();
        let (handoff, collector) = fixture.prebind(&request, Instant::now);

        let error = match handoff.install_into(&child) {
            Err(error) => error,
            Ok(_) => panic!("another child identity must not receive the producer"),
        };

        assert!(matches!(
            error,
            collector::SupervisedDeliveryReportHandoffError::ChildIdentityMismatch {
                expected: observed_expected,
                observed_pid,
                observed_start_time_ticks,
            } if observed_expected == expected
                && observed_pid == child.identity().pid()
                && observed_start_time_ticks == child.identity().start_time_ticks()
        ));
        assert!(matches!(
            collector
                .recv_fixture_record_until(1, Instant::now() + Duration::from_secs(1))
                .expect("observe failed-handoff producer closure"),
            Some(SeqpacketReceive::Eof)
        ));
        assert_eq!(
            child
                .launch_control()
                .recv_record_until(1, Instant::now() + Duration::from_millis(100))
                .expect("inspect wrong-child launch control"),
            None,
            "identity mismatch must occur before any launch-control record"
        );
        assert!(!fixture.evidence.exists());
        assert_eq!(
            fixture
                .adapter
                .try_wait(&mut child)
                .expect("poll wrong-child fixture"),
            None
        );
        fixture
            .adapter
            .terminate(&mut child, Duration::from_secs(1))
            .expect("terminate and reap wrong-child fixture");
    }

    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    #[test]
    fn expired_exact_child_handoff_sends_nothing_and_closes_the_producer() {
        let Some((engine_uid, engine_gid)) = non_root_process_credentials() else {
            return;
        };
        let fixture = NativeLaunchControlFixture::new();
        let mut child = fixture.spawn();
        fixture
            .adapter
            .wait_ready(&mut child, fixture.spec.process())
            .expect("launch-control child becomes ready");
        let mut request = fixture.request_for_child(&child, engine_uid, engine_gid);
        request.deadline.expires_at = Instant::now();
        let (handoff, collector) = fixture.prebind(&request, Instant::now);

        assert!(matches!(
            handoff.install_into(&child),
            Err(collector::SupervisedDeliveryReportHandoffError::DeadlineExpired)
        ));
        assert!(matches!(
            collector
                .recv_fixture_record_until(1, Instant::now() + Duration::from_secs(1))
                .expect("observe expired-handoff producer closure"),
            Some(SeqpacketReceive::Eof)
        ));
        assert_eq!(
            child
                .launch_control()
                .recv_record_until(1, Instant::now() + Duration::from_millis(100))
                .expect("inspect expired child launch control"),
            None,
            "deadline expiry must occur before any launch-control record"
        );
        assert!(!fixture.evidence.exists());
        fixture
            .adapter
            .terminate(&mut child, Duration::from_secs(1))
            .expect("terminate and reap expired-handoff fixture");
    }

    #[test]
    fn canonical_dual_stack_report_completes_only_after_terminal_and_eof() {
        let context = Context::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let evidence = context.evidence();
        let frames = encode_report_frames(&context.request, &evidence);
        let mut report = parse_complete_report(&context, &frames);

        assert_eq!(
            report.report_object(),
            context
                .request
                .pre_binding()
                .environment()
                .attempt_objects()
                .listener_delivery_report()
        );
        assert_eq!(report.profile_revision(), context.profile.revision());
        assert!(report.terminal_observed_at() < report.eof_observed_at());
        for flow in CanaryFlow::ALL {
            assert_eq!(
                report.take_event(flow).expect("all dual-stack events").flow,
                flow
            );
        }
    }

    #[test]
    fn prebound_collector_drains_actual_seqpacket_records_through_real_eof() {
        let context = Context::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let frames = encode_report_frames(&context.request, &context.evidence());
        let started_at = context.request.deadline().started_at();
        let mut observation = 0_u64;
        let (producer, collector) = prebind_report_collector(&context, move || {
            observation += 1;
            started_at + Duration::from_millis(observation * 10)
        });

        for frame in frames {
            producer.send_frame(&frame).expect("send report frame");
        }
        drop(producer);

        let drained = collector.drain().expect("drain report collector");
        assert_eq!(
            drained.report_object(),
            context
                .request
                .pre_binding()
                .environment()
                .attempt_objects()
                .listener_delivery_report()
        );
        assert_eq!(drained.profile_revision(), context.profile.revision());
        assert!(drained.terminal_observed_at() < drained.eof_observed_at());
    }

    #[test]
    fn drained_collector_owns_receiver_retirement_after_exact_client_reap() {
        let context = Context::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let evidence = context.evidence();
        let started_at = context.request.deadline().started_at();
        let drained = drain_report_collector(
            &context,
            &evidence,
            started_at + Duration::from_millis(120),
            started_at + Duration::from_millis(123),
        );
        let authority = client_retirement_authority(drained.binding(), evidence.cleanup.client);
        let retired = drained
            .retire_after_client(authority)
            .expect("retire receiver after client reap");

        assert_eq!(retired.client_retirement(), evidence.cleanup.client);
        assert_eq!(
            retired.report_cleanup(),
            CanaryListenerDeliveryReportCleanupEvidence::retired(
                CanaryAttemptObjectRetirementEvidence::new(
                    context
                        .request
                        .pre_binding()
                        .environment()
                        .attempt_objects()
                        .listener_delivery_report(),
                    started_at + Duration::from_millis(120),
                    started_at + Duration::from_millis(123),
                ),
            )
        );
    }

    #[test]
    fn whole_retired_report_reaches_schema_v2_only_through_test_factory() {
        let context = Context::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let evidence = context.evidence();
        let started_at = context.request.deadline().started_at();
        let drained = drain_report_collector(
            &context,
            &evidence,
            started_at + Duration::from_millis(120),
            started_at + Duration::from_millis(123),
        );
        let authority = client_retirement_authority(drained.binding(), evidence.cleanup.client);
        let retired = drained
            .retire_after_client(authority)
            .expect("retire receiver after client reap");

        collector::validate_schema_v2_fixture(retired, evidence, context.fixture.observed_at())
            .expect("whole retired report satisfies the existing schema-v2 model");
    }

    #[test]
    fn whole_report_factory_rejects_request_and_client_retirement_drift() {
        let context = Context::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let evidence = context.evidence();
        let started_at = context.request.deadline().started_at();
        let drained = drain_report_collector(
            &context,
            &evidence,
            started_at + Duration::from_millis(120),
            started_at + Duration::from_millis(123),
        );
        let authority = client_retirement_authority(drained.binding(), evidence.cleanup.client);
        let retired = drained
            .retire_after_client(authority)
            .expect("retire receiver after client reap");
        let alternate = Context::new(CanaryAddressFamilies::Ipv4AndIpv6);
        assert_eq!(
            collector::validate_schema_v2_fixture(
                retired,
                alternate.evidence(),
                alternate.fixture.observed_at(),
            )
            .expect_err("another request cannot consume the retired report"),
            collector::SupervisedDeliveryReportFixtureError::RequestMismatch
        );

        let evidence = context.evidence();
        let drained = drain_report_collector(
            &context,
            &evidence,
            started_at + Duration::from_millis(120),
            started_at + Duration::from_millis(123),
        );
        let authority = client_retirement_authority(drained.binding(), evidence.cleanup.client);
        let retired = drained
            .retire_after_client(authority)
            .expect("retire receiver after client reap");
        let mut client_drift = context.evidence();
        client_drift.cleanup.client.reaped_at += Duration::from_nanos(1);
        assert_eq!(
            collector::validate_schema_v2_fixture(
                retired,
                client_drift,
                context.fixture.observed_at(),
            )
            .expect_err("copied client identity cannot replace exact retirement"),
            collector::SupervisedDeliveryReportFixtureError::ClientRetirementMismatch
        );
    }

    #[test]
    fn receiver_retirement_rejects_invalid_client_and_clock_chronology() {
        let context = Context::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let started_at = context.request.deadline().started_at();

        let exact = context.evidence();
        let alternate = Context::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let drained = drain_report_collector(
            &context,
            &exact,
            started_at + Duration::from_millis(120),
            started_at + Duration::from_millis(123),
        );
        let alternate_evidence = alternate.evidence();
        let alternate_started_at = alternate.request.deadline().started_at();
        let alternate_drained = drain_report_collector(
            &alternate,
            &alternate_evidence,
            alternate_started_at + Duration::from_millis(120),
            alternate_started_at + Duration::from_millis(123),
        );
        assert_ne!(context.request, alternate.request);
        assert_eq!(drained.report_object(), alternate_drained.report_object());
        assert_eq!(
            drained.profile_revision(),
            alternate_drained.profile_revision()
        );
        let wrong_authority = client_retirement_authority(
            alternate_drained.binding(),
            alternate_evidence.cleanup.client,
        );
        let failure = match drained.retire_after_client(wrong_authority) {
            Ok(_) => panic!("another request cannot authorize receiver retirement"),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.error(),
            collector::SupervisedDeliveryReportCollectorError::ClientRetirementAuthorityMismatch
        ));
        let (drained, alternate_authority) = retained_retirement(failure);
        alternate_drained
            .retire_after_client(alternate_authority)
            .expect("rejected authority still retires its exact alternate receiver");
        let exact_authority = client_retirement_authority(drained.binding(), exact.cleanup.client);
        drained
            .retire_after_client(exact_authority)
            .expect("exact request authority retires the preserved receiver");

        let mut unordered = context.evidence();
        unordered.cleanup.client.quiesced_at =
            unordered.cleanup.client.terminated_at + Duration::from_nanos(1);
        let drained = drain_report_collector(
            &context,
            &unordered,
            started_at + Duration::from_millis(120),
            started_at + Duration::from_millis(123),
        );
        let unordered_authority =
            client_retirement_authority(drained.binding(), unordered.cleanup.client);
        let failure = match drained.retire_after_client(unordered_authority) {
            Ok(_) => panic!("unordered client retirement cannot retire the receiver"),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.error(),
            collector::SupervisedDeliveryReportCollectorError::InvalidClientRetirement
        ));
        let (drained, _invalid_authority) = retained_retirement(failure);
        let valid = context.evidence();
        let valid_authority = client_retirement_authority(drained.binding(), valid.cleanup.client);
        drained
            .retire_after_client(valid_authority)
            .expect("retained receiver can retire with exact client authority");

        let mut client_not_reaped = context.evidence();
        client_not_reaped.cleanup.client.reaped_at = started_at + Duration::from_millis(121);
        let drained = drain_report_collector(
            &context,
            &client_not_reaped,
            started_at + Duration::from_millis(120),
            started_at + Duration::from_millis(123),
        );
        let premature_authority =
            client_retirement_authority(drained.binding(), client_not_reaped.cleanup.client);
        let failure = match drained.retire_after_client(premature_authority) {
            Ok(_) => panic!("receiver cannot retire before exact client reap"),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.error(),
            collector::SupervisedDeliveryReportCollectorError::InvalidReceiverRetirement
        ));
        let (drained, _premature_authority) = retained_retirement(failure);
        let valid = context.evidence();
        let valid_authority = client_retirement_authority(drained.binding(), valid.cleanup.client);
        drained
            .retire_after_client(valid_authority)
            .expect("preserved receiver can retire on a later valid clock sample");

        let absence_before_drop = context.evidence();
        let drained = drain_report_collector(
            &context,
            &absence_before_drop,
            started_at + Duration::from_millis(120),
            started_at + Duration::from_millis(119),
        );
        let absence_authority =
            client_retirement_authority(drained.binding(), absence_before_drop.cleanup.client);
        let failure = match drained.retire_after_client(absence_authority) {
            Ok(_) => panic!("absence cannot precede receiver destruction"),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.error(),
            collector::SupervisedDeliveryReportCollectorError::InvalidReceiverRetirement
        ));
        let unverified = match failure.into_disposition() {
            collector::SupervisedDeliveryReportRetirementFailureDisposition::ReceiverRetained {
                ..
            } => panic!("post-drop clock failure cannot retain a destroyed receiver"),
            collector::SupervisedDeliveryReportRetirementFailureDisposition::ReceiverRetiredWithoutCleanupEvidence(
                retirement,
            ) => retirement,
        };
        assert!(matches!(
            unverified.error(),
            collector::SupervisedDeliveryReportCollectorError::InvalidReceiverRetirement
        ));
        assert_eq!(
            unverified.report_object(),
            context
                .request
                .pre_binding()
                .environment()
                .attempt_objects()
                .listener_delivery_report()
        );
        assert_eq!(unverified.profile_revision(), context.profile.revision());
        assert_eq!(
            unverified.client_retirement(),
            absence_before_drop.cleanup.client
        );
        assert_eq!(
            unverified.retired_at(),
            started_at + Duration::from_millis(120)
        );
        assert_eq!(
            unverified.absent_observed_at(),
            started_at + Duration::from_millis(119)
        );
        assert_eq!(
            unverified
                .completed_report()
                .expect("completed report remains available for diagnostics")
                .report_object(),
            unverified.report_object()
        );
        assert!(unverified.collection_error().is_none());
    }

    #[test]
    fn collector_authenticates_kernel_sender_before_parsing_frame_bytes() {
        let mut context = Context::new(CanaryAddressFamilies::Ipv4Only);
        let observed_pid = std::process::id();
        let expected_pid = NonZeroU32::new(
            observed_pid
                .checked_add(1)
                .unwrap_or_else(|| observed_pid - 1),
        )
        .expect("different expected producer PID");
        let start_ticks = NonZeroU64::new(
            context
                .request
                .pre_binding()
                .engine()
                .engine()
                .start_time_ticks(),
        )
        .expect("engine start ticks");
        context.request.pre_binding.engine.engine =
            OwnedEngineIdentity::new(expected_pid, start_ticks);
        let (producer, collector) = prebind_report_collector(&context, || {
            panic!("credential rejection must precede frame timestamping")
        });
        producer
            .send_frame(b"not a report frame")
            .expect("send unauthenticated record");
        drop(producer);

        let failed = match collector.drain() {
            Ok(_) => panic!("another process identity cannot produce the report"),
            Err(failed) => failed,
        };
        match failed.collection_error() {
            collector::SupervisedDeliveryReportCollectorError::ProducerCredentialsMismatch {
                expected_pid: rejected_pid,
                observed,
                ..
            } => {
                assert_eq!(*rejected_pid, expected_pid.get());
                assert_eq!(observed.pid(), observed_pid);
            }
            other => panic!("unexpected collector error: {other}"),
        }
        drop(failed);
    }

    #[test]
    fn collector_rejects_transport_truncation_from_a_real_oversized_record() {
        let context = Context::new(CanaryAddressFamilies::Ipv4Only);
        let evidence = context.evidence();
        let started_at = context.request.deadline().started_at();
        let clock = scripted_collector_clock(
            &context,
            1,
            10,
            started_at + Duration::from_millis(120),
            started_at + Duration::from_millis(123),
        );
        let (producer, collector) = prebind_report_collector(&context, clock);
        producer
            .send_frame(&vec![
                0;
                usize::from(
                    ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_FRAME_BYTES
                ) + 1
            ])
            .expect("send oversized record");
        drop(producer);

        let failed = match collector.drain() {
            Ok(_) => panic!("transport truncation must fail"),
            Err(failed) => *failed,
        };
        assert!(matches!(
            failed.collection_error(),
            collector::SupervisedDeliveryReportCollectorError::InvalidReport(
                SupervisedDeliveryReportError::TransportTruncated
            )
        ));
        let authority = client_retirement_authority(failed.binding(), evidence.cleanup.client);
        let retired = failed
            .retire_after_client(authority)
            .expect("failed collector retires only after exact client reap");
        assert!(matches!(
            retired.collection_error(),
            collector::SupervisedDeliveryReportCollectorError::InvalidReport(
                SupervisedDeliveryReportError::TransportTruncated
            )
        ));
        assert_eq!(retired.client_retirement(), evidence.cleanup.client);
    }

    #[test]
    fn failed_collection_retains_diagnostics_without_minting_cleanup_after_bad_post_drop_clock() {
        let context = Context::new(CanaryAddressFamilies::Ipv4Only);
        let evidence = context.evidence();
        let started_at = context.request.deadline().started_at();
        let clock = scripted_collector_clock(
            &context,
            1,
            10,
            started_at + Duration::from_millis(120),
            started_at + Duration::from_millis(119),
        );
        let (producer, collector) = prebind_report_collector(&context, clock);
        producer
            .send_frame(&vec![
                0;
                usize::from(
                    ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_FRAME_BYTES
                ) + 1
            ])
            .expect("send oversized record");
        drop(producer);

        let failed = match collector.drain() {
            Ok(_) => panic!("transport truncation must fail"),
            Err(failed) => *failed,
        };
        let authority = client_retirement_authority(failed.binding(), evidence.cleanup.client);
        let retirement_failure = match failed.retire_after_client(authority) {
            Ok(_) => panic!("invalid post-drop chronology cannot mint cleanup evidence"),
            Err(failure) => failure,
        };
        let unverified = match retirement_failure.into_disposition() {
            collector::SupervisedDeliveryReportRetirementFailureDisposition::ReceiverRetained {
                ..
            } => panic!("post-drop clock failure cannot retain a destroyed receiver"),
            collector::SupervisedDeliveryReportRetirementFailureDisposition::ReceiverRetiredWithoutCleanupEvidence(
                retirement,
            ) => retirement,
        };
        assert!(unverified.completed_report().is_none());
        assert!(matches!(
            unverified
                .collection_error()
                .expect("collection failure remains available for diagnostics"),
            collector::SupervisedDeliveryReportCollectorError::InvalidReport(
                SupervisedDeliveryReportError::TransportTruncated
            )
        ));
        assert_eq!(unverified.client_retirement(), evidence.cleanup.client);
        assert_eq!(
            unverified.absent_observed_at(),
            started_at + Duration::from_millis(119)
        );
    }

    #[test]
    fn collector_rejects_an_empty_record_after_terminal_instead_of_completing() {
        let context = Context::new(CanaryAddressFamilies::Ipv4Only);
        let evidence = context.evidence();
        let frames = encode_report_frames(&context.request, &evidence);
        let record_count = frames.len() + 1;
        let started_at = context.request.deadline().started_at();
        let clock = scripted_collector_clock(
            &context,
            record_count,
            10,
            started_at + Duration::from_millis(120),
            started_at + Duration::from_millis(123),
        );
        let (producer, collector) = prebind_report_collector(&context, clock);
        for frame in frames {
            producer.send_frame(&frame).expect("send report frame");
        }
        producer
            .send_frame(b"")
            .expect("send empty trailing record");
        drop(producer);

        let failed = match collector.drain() {
            Ok(_) => panic!("an empty post-terminal record cannot complete the report"),
            Err(failed) => *failed,
        };
        assert!(matches!(
            failed.collection_error(),
            collector::SupervisedDeliveryReportCollectorError::InvalidReport(
                SupervisedDeliveryReportError::PostTerminalFrame
            )
        ));
        let authority = client_retirement_authority(failed.binding(), evidence.cleanup.client);
        failed
            .retire_after_client(authority)
            .expect("post-terminal failure retains cleanup ownership");
    }

    #[test]
    fn collector_times_out_while_the_post_terminal_producer_is_retained() {
        let mut context = Context::new(CanaryAddressFamilies::Ipv4Only);
        let started_at = context.request.deadline().started_at();
        let short_duration =
            Instant::now().saturating_duration_since(started_at) + Duration::from_millis(40);
        context.request.deadline = super::super::CanaryDeadline::new(started_at, short_duration)
            .expect("short collector deadline");
        let evidence = context.evidence();
        let frames = encode_report_frames(&context.request, &evidence);
        let record_count = frames.len();
        let clock = scripted_collector_clock(
            &context,
            record_count,
            1,
            started_at + Duration::from_millis(120),
            started_at + Duration::from_millis(123),
        );
        let (producer, collector) = prebind_report_collector(&context, clock);
        for frame in frames {
            producer.send_frame(&frame).expect("send report frame");
        }

        let wait_started_at = Instant::now();
        let failed = match collector.drain() {
            Ok(_) => panic!("retained producer cannot synthesize drained EOF"),
            Err(failed) => *failed,
        };
        assert!(matches!(
            failed.collection_error(),
            collector::SupervisedDeliveryReportCollectorError::DeadlineExpired
        ));
        assert!(wait_started_at.elapsed() >= Duration::from_millis(20));
        assert!(wait_started_at.elapsed() < Duration::from_secs(1));
        drop(producer);
        let authority = client_retirement_authority(failed.binding(), evidence.cleanup.client);
        let retired = failed
            .retire_after_client(authority)
            .expect("timeout retains receiver ownership until exact client reap");
        assert!(matches!(
            retired.collection_error(),
            collector::SupervisedDeliveryReportCollectorError::DeadlineExpired
        ));
        assert_eq!(
            retired.report_cleanup(),
            CanaryListenerDeliveryReportCleanupEvidence::retired(
                CanaryAttemptObjectRetirementEvidence::new(
                    context
                        .request
                        .pre_binding()
                        .environment()
                        .attempt_objects()
                        .listener_delivery_report(),
                    started_at + Duration::from_millis(120),
                    started_at + Duration::from_millis(123),
                ),
            )
        );
    }

    #[test]
    fn header_framing_and_identity_mutations_fail_closed_and_poison_parser() {
        let context = Context::new(CanaryAddressFamilies::Ipv4Only);
        let evidence = context.evidence();
        let frames = encode_report_frames(&context.request, &evidence);
        let first = &frames[0];
        let observed_at = context.request.deadline().started_at() + Duration::from_millis(10);

        assert_first_error(
            &context,
            first.clone(),
            true,
            observed_at,
            SupervisedDeliveryReportError::TransportTruncated,
        );
        assert_first_error(
            &context,
            vec![0; usize::from(ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_FRAME_BYTES) + 1],
            false,
            observed_at,
            SupervisedDeliveryReportError::FrameTooLarge,
        );

        let mut mutations: Vec<(Vec<u8>, SupervisedDeliveryReportError)> = Vec::new();
        let mut truncated = first.clone();
        truncated.pop();
        mutations.push((truncated, SupervisedDeliveryReportError::FrameTruncated));
        mutations.push((
            mutate_u8(first, ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC_FIELD, b'X'),
            SupervisedDeliveryReportError::InvalidMagic,
        ));
        mutations.push((
            mutate_u16(
                first,
                ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION_FIELD,
                2,
            ),
            SupervisedDeliveryReportError::UnsupportedSchema,
        ));
        mutations.push((
            mutate_u8(first, ENGINE_SUPERVISED_DELIVERY_REPORT_KIND_FIELD, 0xff),
            SupervisedDeliveryReportError::UnknownFrameKind,
        ));
        mutations.push((
            mutate_u8(first, ENGINE_SUPERVISED_DELIVERY_REPORT_FLAGS_FIELD, 1),
            SupervisedDeliveryReportError::NonzeroHeaderFlags,
        ));
        mutations.push((
            mutate_u16(
                first,
                ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_LENGTH_FIELD,
                151,
            ),
            SupervisedDeliveryReportError::NonCanonicalHeaderLength,
        ));
        mutations.push((
            mutate_u16(
                first,
                ENGINE_SUPERVISED_DELIVERY_REPORT_FRAME_LENGTH_FIELD,
                ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FRAME_BYTES - 1,
            ),
            SupervisedDeliveryReportError::TrailingBytes,
        ));
        let mut noncanonical_length =
            first[..usize::from(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FRAME_BYTES - 1)].to_vec();
        write_u16(
            &mut noncanonical_length,
            ENGINE_SUPERVISED_DELIVERY_REPORT_FRAME_LENGTH_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FRAME_BYTES - 1,
        );
        mutations.push((
            noncanonical_length,
            SupervisedDeliveryReportError::NonCanonicalFrameLength,
        ));
        mutations.push((
            mutate_u8(
                first,
                ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_RESERVED_FIELD,
                1,
            ),
            SupervisedDeliveryReportError::NonzeroReservedField,
        ));
        mutations.push((
            mutate_u64(first, ENGINE_SUPERVISED_DELIVERY_REPORT_SEQUENCE_FIELD, 2),
            SupervisedDeliveryReportError::SequenceMismatch,
        ));
        mutations.push((
            mutate_u64(
                first,
                ENGINE_SUPERVISED_DELIVERY_REPORT_CUMULATIVE_LOSS_FIELD,
                1,
            ),
            SupervisedDeliveryReportError::DeliveryLossObserved,
        ));
        for (wire_field, identity_field) in [
            (
                ENGINE_SUPERVISED_DELIVERY_REPORT_GENERATION_FIELD,
                SupervisedDeliveryReportIdentityField::Generation,
            ),
            (
                ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_PID_FIELD,
                SupervisedDeliveryReportIdentityField::EngineProcess,
            ),
            (
                ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_START_TICKS_FIELD,
                SupervisedDeliveryReportIdentityField::EngineProcess,
            ),
            (
                ENGINE_SUPERVISED_DELIVERY_REPORT_REPORT_OBJECT_FIELD,
                SupervisedDeliveryReportIdentityField::ReportObject,
            ),
            (
                ENGINE_SUPERVISED_DELIVERY_REPORT_PROFILE_REVISION_FIELD,
                SupervisedDeliveryReportIdentityField::EngineProfileRevision,
            ),
            (
                ENGINE_SUPERVISED_DELIVERY_REPORT_ATTEMPT_NONCE_FIELD,
                SupervisedDeliveryReportIdentityField::AttemptNonce,
            ),
        ] {
            let mut drift = first.clone();
            drift[wire_field.offset()] ^= 1;
            mutations.push((
                drift,
                SupervisedDeliveryReportError::IdentityMismatch(identity_field),
            ));
        }
        for (frame, expected) in mutations {
            assert_first_error(&context, frame, false, observed_at, expected);
        }
    }

    #[test]
    fn flow_socket_payload_and_datagram_mutations_are_rejected() {
        let context = Context::new(CanaryAddressFamilies::Ipv4Only);
        let evidence = context.evidence();
        let frames = encode_report_frames(&context.request, &evidence);
        let observed_at = context.request.deadline().started_at() + Duration::from_millis(10);
        let first = &frames[0];

        for (frame, expected) in [
            (
                mutate_u8(
                    first,
                    report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_FIELD),
                    0xff,
                ),
                SupervisedDeliveryReportError::UnknownFlow,
            ),
            (
                mutate_u8(
                    first,
                    report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_FIELD),
                    flow_code(CanaryFlow::Ipv4DnsTcp).wire_value(),
                ),
                SupervisedDeliveryReportError::FlowOrderMismatch,
            ),
            (
                mutate_u64(
                    first,
                    report_payload_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_INODE_FIELD,
                    ),
                    0,
                ),
                SupervisedDeliveryReportError::InvalidSocketIdentity,
            ),
            (
                mutate_u8(
                    first,
                    report_payload_field(nested_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LOCAL_ADDRESS_FIELD,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_FAMILY_FIELD,
                    )),
                    AddressFamilyCode::Ipv6.wire_value(),
                ),
                SupervisedDeliveryReportError::AddressFamilyMismatch,
            ),
            (
                mutate_u8(
                    first,
                    report_payload_field(nested_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LOCAL_ADDRESS_FIELD,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_FAMILY_FIELD,
                    )),
                    5,
                ),
                SupervisedDeliveryReportError::UnknownAddressFamily,
            ),
            (
                mutate_u8(
                    first,
                    report_payload_field(nested_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LOCAL_ADDRESS_FIELD,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_RESERVED_FIELD,
                    )),
                    1,
                ),
                SupervisedDeliveryReportError::NonzeroReservedField,
            ),
            (
                mutate_u16(
                    first,
                    report_payload_field(nested_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LOCAL_ADDRESS_FIELD,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_PORT_FIELD,
                    )),
                    0,
                ),
                SupervisedDeliveryReportError::NonCanonicalSocketAddress,
            ),
            (
                mutate_u8(
                    first,
                    report_payload_field(nested_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LOCAL_ADDRESS_FIELD,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_FIELD,
                    )),
                    1,
                ),
                SupervisedDeliveryReportError::NonCanonicalSocketAddress,
            ),
            (
                mutate_u8(
                    first,
                    report_payload_field(nested_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PAYLOAD_IDENTITY_FIELD,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_KIND_FIELD,
                    )),
                    0xff,
                ),
                SupervisedDeliveryReportError::UnknownPayloadKind,
            ),
            (
                mutate_u8(
                    first,
                    report_payload_field(nested_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PAYLOAD_IDENTITY_FIELD,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_KIND_FIELD,
                    )),
                    PayloadKind::Dns.wire_value(),
                ),
                SupervisedDeliveryReportError::PayloadKindMismatch,
            ),
            (
                mutate_u8(
                    first,
                    report_payload_field(nested_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PAYLOAD_IDENTITY_FIELD,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_RESERVED_FIELD,
                    )),
                    1,
                ),
                SupervisedDeliveryReportError::NonzeroReservedField,
            ),
            (
                mutate_u16(
                    first,
                    report_payload_field(nested_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PAYLOAD_IDENTITY_FIELD,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TRANSACTION_ID_FIELD,
                    )),
                    1,
                ),
                SupervisedDeliveryReportError::NonCanonicalPayloadIdentity,
            ),
        ] {
            assert_first_error(&context, frame, false, observed_at, expected);
        }

        let mut parser = context.parser();
        parser
            .ingest(datagram(
                &frames[0],
                context.request.deadline().started_at() + Duration::from_millis(10),
            ))
            .expect("first TCP event");
        let mut udp_unknown_flags = frames[1].clone();
        write_u8(
            &mut udp_unknown_flags,
            report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_TRUNCATION_FLAGS_FIELD),
            0x80,
        );
        assert_eq!(
            parser
                .ingest(datagram(
                    &udp_unknown_flags,
                    context.request.deadline().started_at() + Duration::from_millis(11),
                ))
                .expect_err("unknown UDP flags"),
            SupervisedDeliveryReportError::UnknownDatagramFlags
        );
    }

    #[test]
    fn ordering_terminal_eof_and_local_time_are_strict() {
        let context = Context::new(CanaryAddressFamilies::Ipv4Only);
        let evidence = context.evidence();
        let frames = encode_report_frames(&context.request, &evidence);
        let start = context.request.deadline().started_at();

        let premature = context.parser();
        assert_eq!(
            premature
                .observe_drained_eof(start + Duration::from_millis(1))
                .expect_err("EOF before terminal"),
            SupervisedDeliveryReportError::PrematureEof
        );

        let mut early_terminal = context.parser();
        let terminal = frames.last().expect("terminal frame");
        let mut early = terminal.clone();
        write_u64(
            &mut early,
            ENGINE_SUPERVISED_DELIVERY_REPORT_SEQUENCE_FIELD,
            1,
        );
        write_u8(
            &mut early,
            report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_EVENT_COUNT_FIELD),
            0,
        );
        assert_eq!(
            early_terminal
                .ingest(datagram(&early, start + Duration::from_millis(1)))
                .expect_err("terminal before deliveries"),
            SupervisedDeliveryReportError::TerminalBeforeAllDeliveries
        );

        let mut gap = context.parser();
        gap.ingest(datagram(&frames[0], start + Duration::from_millis(10)))
            .expect("first frame");
        let second_gap = mutate_u64(
            &frames[1],
            ENGINE_SUPERVISED_DELIVERY_REPORT_SEQUENCE_FIELD,
            3,
        );
        assert_eq!(
            gap.ingest(datagram(&second_gap, start + Duration::from_millis(11)))
                .expect_err("sequence gap"),
            SupervisedDeliveryReportError::SequenceMismatch
        );

        let mut reorder = context.parser();
        reorder
            .ingest(datagram(&frames[0], start + Duration::from_millis(10)))
            .expect("first frame");
        let duplicate = mutate_u64(
            &frames[0],
            ENGINE_SUPERVISED_DELIVERY_REPORT_SEQUENCE_FIELD,
            2,
        );
        assert_eq!(
            reorder
                .ingest(datagram(&duplicate, start + Duration::from_millis(11)))
                .expect_err("duplicate/reordered flow"),
            SupervisedDeliveryReportError::FlowOrderMismatch
        );

        let mut bad_count = context.parser();
        for (index, frame) in frames[..4].iter().enumerate() {
            bad_count
                .ingest(datagram(
                    frame,
                    start + Duration::from_millis(10 + u64::try_from(index).unwrap()),
                ))
                .expect("delivery frame");
        }
        let mut count_drift = terminal.clone();
        write_u8(
            &mut count_drift,
            report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_EVENT_COUNT_FIELD),
            3,
        );
        assert_eq!(
            bad_count
                .ingest(datagram(&count_drift, start + Duration::from_millis(14)))
                .expect_err("terminal count drift"),
            SupervisedDeliveryReportError::TerminalEventCountMismatch
        );

        let mut overflow = context.parser();
        for (index, frame) in frames[..4].iter().enumerate() {
            overflow
                .ingest(datagram(
                    frame,
                    start + Duration::from_millis(10 + u64::try_from(index).unwrap()),
                ))
                .expect("delivery frame");
        }
        let extra = mutate_u64(
            &frames[0],
            ENGINE_SUPERVISED_DELIVERY_REPORT_SEQUENCE_FIELD,
            5,
        );
        assert_eq!(
            overflow
                .ingest(datagram(&extra, start + Duration::from_millis(20)))
                .expect_err("delivery beyond the request flow set"),
            SupervisedDeliveryReportError::TooManyDeliveryEvents
        );

        let mut post_terminal = context.parser();
        for (index, frame) in frames.iter().enumerate() {
            post_terminal
                .ingest(datagram(
                    frame,
                    start + Duration::from_millis(10 + u64::try_from(index).unwrap()),
                ))
                .expect("complete through terminal");
        }
        assert_eq!(
            post_terminal
                .ingest(datagram(&frames[0], start + Duration::from_millis(20)))
                .expect_err("frame after terminal"),
            SupervisedDeliveryReportError::PostTerminalFrame
        );

        assert_first_error(
            &context,
            frames[0].clone(),
            false,
            start.checked_sub(Duration::from_nanos(1)).unwrap(),
            SupervisedDeliveryReportError::ObservationTimeInvalid,
        );
        assert_first_error(
            &context,
            frames[0].clone(),
            false,
            context.request.deadline().expires_at(),
            SupervisedDeliveryReportError::ObservationTimeInvalid,
        );

        let mut decreasing = context.parser();
        decreasing
            .ingest(datagram(&frames[0], start + Duration::from_millis(20)))
            .expect("first timestamp");
        assert_eq!(
            decreasing
                .ingest(datagram(&frames[1], start + Duration::from_millis(19)))
                .expect_err("daemon observations cannot move backward"),
            SupervisedDeliveryReportError::ObservationTimeInvalid
        );
    }

    fn parse_complete_report(
        context: &Context,
        frames: &[Vec<u8>],
    ) -> CompletedSupervisedDeliveryReport {
        let start = context.request.deadline().started_at();
        let mut parser = context.parser();
        let delivery_count = frames.len() - 1;
        for (index, frame) in frames.iter().enumerate() {
            let observed_at = if index < delivery_count {
                start
                    + Duration::from_millis(
                        10 * u64::try_from(index + 1).expect("flow index fits u64") + 1,
                    )
            } else {
                start
                    + Duration::from_millis(
                        10 * u64::try_from(delivery_count).expect("flow count fits u64") + 2,
                    )
            };
            parser
                .ingest(datagram(frame, observed_at))
                .expect("canonical report frame");
        }
        parser
            .observe_drained_eof(
                start
                    + Duration::from_millis(
                        10 * u64::try_from(delivery_count).expect("flow count fits u64") + 3,
                    ),
            )
            .expect("terminal followed by drained EOF")
    }

    fn prebind_report_collector<C>(
        context: &Context,
        clock: C,
    ) -> (
        collector::SupervisedDeliveryReportEngineHandoff,
        collector::SupervisedDeliveryReportCollector<C>,
    )
    where
        C: FnMut() -> Instant,
    {
        let authority = collector::SupervisedDeliveryReportPrebindAuthority::fixture(
            &context.profile,
            &context.request,
        );
        let (producer, collector) =
            collector::prebind(authority, clock).expect("prebind report collector");
        let handoff = producer.into_engine_handoff();
        assert_eq!(
            handoff.report_object(),
            context
                .request
                .pre_binding()
                .environment()
                .attempt_objects()
                .listener_delivery_report()
        );
        assert_eq!(handoff.profile_revision(), context.profile.revision());
        assert_eq!(handoff.request(), &context.request);
        (handoff, collector)
    }

    fn handoff_field(frame: &[u8], field: WireField) -> &[u8] {
        &frame[field.offset()..field.end()]
    }

    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    fn native_composition_engine_binary() -> PathBuf {
        let test = std::env::current_exe().expect("resolve current fluxd test executable");
        let debug_root = test
            .parent()
            .and_then(Path::parent)
            .expect("derive target directory from fluxd test executable");
        let binary = debug_root.join(format!(
            "flux-native-composition-engine{}",
            std::env::consts::EXE_SUFFIX
        ));
        assert!(
            fs::metadata(&binary)
                .expect("feature-gated native composition engine is built")
                .is_file(),
            "native composition engine fixture must be a regular file"
        );
        fs::canonicalize(binary).expect("canonicalize native composition engine fixture")
    }

    #[cfg(all(feature = "native-composition-test", target_os = "linux"))]
    fn wait_for_fixture_path(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if path.is_file() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("fixture evidence {} was not published", path.display());
    }

    fn client_retirement_authority(
        binding: Arc<collector::SupervisedDeliveryReportTransportBinding>,
        retirement: super::super::CanaryProcessRetirementEvidence,
    ) -> collector::SupervisedDeliveryReportClientRetirementAuthority {
        collector::SupervisedDeliveryReportClientRetirementAuthority::fixture(binding, retirement)
    }

    fn retained_retirement<T>(
        failure: collector::SupervisedDeliveryReportRetirementFailure<T>,
    ) -> (
        T,
        collector::SupervisedDeliveryReportClientRetirementAuthority,
    ) {
        match failure.into_disposition() {
            collector::SupervisedDeliveryReportRetirementFailureDisposition::ReceiverRetained {
                owner,
                authority,
            } => (*owner, authority),
            collector::SupervisedDeliveryReportRetirementFailureDisposition::ReceiverRetiredWithoutCleanupEvidence(
                ..
            ) => panic!("pre-drop failure must preserve receiver ownership"),
        }
    }

    fn scripted_collector_clock(
        context: &Context,
        record_observations: usize,
        record_step_millis: u64,
        retired_at: Instant,
        absent_observed_at: Instant,
    ) -> Box<dyn FnMut() -> Instant> {
        let started_at = context.request.deadline().started_at();
        let mut observations = (1..=record_observations)
            .map(|index| {
                started_at
                    + Duration::from_millis(
                        record_step_millis * u64::try_from(index).expect("record index fits u64"),
                    )
            })
            .chain([retired_at, absent_observed_at])
            .collect::<Vec<_>>()
            .into_iter();
        Box::new(move || observations.next().expect("scripted collector timestamp"))
    }

    fn drain_report_collector(
        context: &Context,
        evidence: &super::super::UnqualifiedCanaryGateEvidence,
        retired_at: Instant,
        absent_observed_at: Instant,
    ) -> collector::DrainedSupervisedDeliveryReportCollector<Box<dyn FnMut() -> Instant>> {
        let frames = encode_report_frames(&context.request, evidence);
        let start = context.request.deadline().started_at();
        let delivery_count = frames.len() - 1;
        let mut observations = frames
            .iter()
            .enumerate()
            .map(|(index, _)| {
                if index < delivery_count {
                    start
                        + Duration::from_millis(
                            10 * u64::try_from(index + 1).expect("flow index fits u64") + 1,
                        )
                } else {
                    start
                        + Duration::from_millis(
                            10 * u64::try_from(delivery_count).expect("flow count fits u64") + 2,
                        )
                }
            })
            .chain([
                start
                    + Duration::from_millis(
                        10 * u64::try_from(delivery_count).expect("flow count fits u64") + 3,
                    ),
                retired_at,
                absent_observed_at,
                absent_observed_at + Duration::from_nanos(1),
            ])
            .collect::<Vec<_>>()
            .into_iter();
        let clock: Box<dyn FnMut() -> Instant> =
            Box::new(move || observations.next().expect("scripted collector timestamp"));
        let (producer, collector) = prebind_report_collector(context, clock);
        for frame in frames {
            producer.send_frame(&frame).expect("send report frame");
        }
        drop(producer);
        collector.drain().expect("drain report collector")
    }

    fn assert_first_error(
        context: &Context,
        frame: Vec<u8>,
        truncated: bool,
        observed_at: Instant,
        expected: SupervisedDeliveryReportError,
    ) {
        let mut parser = context.parser();
        assert_eq!(
            parser
                .ingest(SupervisedDeliveryReportDatagram::new(
                    &frame,
                    truncated,
                    observed_at,
                ))
                .expect_err("mutated frame must fail"),
            expected
        );
        assert_eq!(
            parser
                .ingest(SupervisedDeliveryReportDatagram::new(
                    &frame,
                    false,
                    observed_at,
                ))
                .expect_err("a failed parser stays poisoned"),
            SupervisedDeliveryReportError::Poisoned
        );
    }

    fn datagram(bytes: &[u8], observed_at: Instant) -> SupervisedDeliveryReportDatagram<'_> {
        SupervisedDeliveryReportDatagram::new(bytes, false, observed_at)
    }

    fn encode_report_frames(
        request: &CanaryAttemptRequest,
        evidence: &super::super::UnqualifiedCanaryGateEvidence,
    ) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut sequence = 1_u64;
        for flow in CanaryFlow::ALL {
            if !request.requires_flow(flow) {
                continue;
            }
            let delivery = evidence.flows.slots[flow.index()]
                .as_ref()
                .expect("required flow")
                .inbound_listener_delivery
                .as_ref()
                .expect("delivery evidence");
            frames.push(encode_delivery_frame(request, delivery, sequence));
            sequence += 1;
        }
        frames.push(encode_terminal_frame(request, sequence, frames.len()));
        frames
    }

    fn encode_delivery_frame(
        request: &CanaryAttemptRequest,
        delivery: &UnqualifiedCanaryInboundListenerDeliveryEvidence,
        sequence: u64,
    ) -> Vec<u8> {
        match delivery {
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyTcp { accepted, .. } => {
                let mut frame = common_frame(request, FrameKind::TcpDelivery, sequence);
                write_u8(
                    &mut frame,
                    report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_FIELD),
                    flow_code(accepted.flow).wire_value(),
                );
                write_cookie(
                    &mut frame,
                    report_payload_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LISTENER_COOKIE_FIELD,
                    ),
                    accepted.listener_cookie,
                );
                write_u32(
                    &mut frame,
                    report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_FD_FIELD),
                    accepted.accepted_fd.get(),
                );
                write_u64(
                    &mut frame,
                    report_payload_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_INODE_FIELD,
                    ),
                    accepted.accepted_inode.get(),
                );
                write_cookie(
                    &mut frame,
                    report_payload_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_COOKIE_FIELD,
                    ),
                    accepted.accepted_cookie,
                );
                write_socket_address(
                    &mut frame,
                    report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LOCAL_ADDRESS_FIELD),
                    accepted.local,
                );
                write_socket_address(
                    &mut frame,
                    report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PEER_ADDRESS_FIELD),
                    accepted.peer,
                );
                write_payload_identity(
                    &mut frame,
                    report_payload_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PAYLOAD_IDENTITY_FIELD,
                    ),
                    accepted.payload,
                );
                frame
            }
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyUdp { datagram, .. } => {
                let mut frame = common_frame(request, FrameKind::UdpDelivery, sequence);
                write_u8(
                    &mut frame,
                    report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_FLOW_FIELD),
                    flow_code(datagram.flow).wire_value(),
                );
                write_u8(
                    &mut frame,
                    report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_COUNT_FIELD),
                    datagram.original_destination_cmsg_count,
                );
                let (family, payload_length) = match datagram.original_destination_cmsg {
                    CanaryOriginalDestinationCmsg::Ipv4 { payload_length } => {
                        (AddressFamilyCode::Ipv4, payload_length)
                    }
                    CanaryOriginalDestinationCmsg::Ipv6 { payload_length } => {
                        (AddressFamilyCode::Ipv6, payload_length)
                    }
                };
                write_u8(
                    &mut frame,
                    report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_FAMILY_FIELD),
                    family.wire_value(),
                );
                write_u8(
                    &mut frame,
                    report_payload_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_TRUNCATION_FLAGS_FIELD,
                    ),
                    (u8::from(datagram.payload_truncated)
                        * ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_TRUNCATED_FLAG)
                        | (u8::from(datagram.control_truncated)
                            * ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CONTROL_TRUNCATED_FLAG),
                );
                write_u16(
                    &mut frame,
                    report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_LENGTH_FIELD),
                    payload_length,
                );
                write_cookie(
                    &mut frame,
                    report_payload_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_LISTENER_COOKIE_FIELD,
                    ),
                    datagram.listener_cookie,
                );
                write_socket_address(
                    &mut frame,
                    report_payload_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CLIENT_ADDRESS_FIELD,
                    ),
                    datagram.client_source,
                );
                write_socket_address(
                    &mut frame,
                    report_payload_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_ORIGINAL_DESTINATION_FIELD,
                    ),
                    datagram.original_destination,
                );
                write_payload_identity(
                    &mut frame,
                    report_payload_field(
                        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_IDENTITY_FIELD,
                    ),
                    datagram.payload,
                );
                frame
            }
            UnqualifiedCanaryInboundListenerDeliveryEvidence::Redirect
            | UnqualifiedCanaryInboundListenerDeliveryEvidence::Dnat => {
                panic!("schema-v1 report fixtures require TPROXY delivery")
            }
        }
    }

    fn encode_terminal_frame(
        request: &CanaryAttemptRequest,
        sequence: u64,
        event_count: usize,
    ) -> Vec<u8> {
        let mut frame = common_frame(request, FrameKind::Terminal, sequence);
        write_u8(
            &mut frame,
            report_payload_field(ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_EVENT_COUNT_FIELD),
            u8::try_from(event_count).expect("event count fits u8"),
        );
        frame
    }

    fn common_frame(request: &CanaryAttemptRequest, kind: FrameKind, sequence: u64) -> Vec<u8> {
        let length = kind.frame_bytes();
        let mut frame = vec![0; usize::from(length)];
        write_bytes(
            &mut frame,
            ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC_FIELD,
            &ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC,
        );
        write_u16(
            &mut frame,
            ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION,
        );
        write_u8(
            &mut frame,
            ENGINE_SUPERVISED_DELIVERY_REPORT_KIND_FIELD,
            kind.wire_value(),
        );
        write_u16(
            &mut frame,
            ENGINE_SUPERVISED_DELIVERY_REPORT_FRAME_LENGTH_FIELD,
            length,
        );
        write_u16(
            &mut frame,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_LENGTH_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_BYTES,
        );
        write_u64(
            &mut frame,
            ENGINE_SUPERVISED_DELIVERY_REPORT_SEQUENCE_FIELD,
            sequence,
        );
        let engine = request.pre_binding().engine();
        write_u32(
            &mut frame,
            ENGINE_SUPERVISED_DELIVERY_REPORT_GENERATION_FIELD,
            engine.generation().get(),
        );
        write_u32(
            &mut frame,
            ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_PID_FIELD,
            engine.engine().pid(),
        );
        write_u64(
            &mut frame,
            ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_START_TICKS_FIELD,
            engine.engine().start_time_ticks(),
        );
        write_bytes(
            &mut frame,
            ENGINE_SUPERVISED_DELIVERY_REPORT_REPORT_OBJECT_FIELD,
            &request
                .pre_binding()
                .environment()
                .attempt_objects()
                .listener_delivery_report()
                .0,
        );
        write_bytes(
            &mut frame,
            ENGINE_SUPERVISED_DELIVERY_REPORT_PROFILE_REVISION_FIELD,
            engine.engine_profile_revision().as_bytes(),
        );
        write_bytes(
            &mut frame,
            ENGINE_SUPERVISED_DELIVERY_REPORT_ATTEMPT_NONCE_FIELD,
            request.nonce().as_bytes(),
        );
        frame
    }

    fn flow_code(flow: CanaryFlow) -> FlowCode {
        match flow {
            CanaryFlow::Ipv4TcpEcho => FlowCode::Ipv4TcpEcho,
            CanaryFlow::Ipv4UdpEcho => FlowCode::Ipv4UdpEcho,
            CanaryFlow::Ipv4DnsUdp => FlowCode::Ipv4DnsUdp,
            CanaryFlow::Ipv4DnsTcp => FlowCode::Ipv4DnsTcp,
            CanaryFlow::Ipv6TcpEcho => FlowCode::Ipv6TcpEcho,
            CanaryFlow::Ipv6UdpEcho => FlowCode::Ipv6UdpEcho,
            CanaryFlow::Ipv6DnsUdp => FlowCode::Ipv6DnsUdp,
            CanaryFlow::Ipv6DnsTcp => FlowCode::Ipv6DnsTcp,
        }
    }

    fn report_payload_field(field: WireField) -> WireField {
        field.at(ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_RESERVED_FIELD.end())
    }

    fn nested_field(container: WireField, field: WireField) -> WireField {
        assert!(field.end() <= container.bytes());
        field.at(container.offset())
    }

    fn write_cookie(frame: &mut [u8], field: WireField, cookie: CanaryInetDiagCookie) {
        assert_eq!(
            field.bytes(),
            ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_LOW_FIELD.end()
        );
        write_u32(
            frame,
            nested_field(field, ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_HIGH_FIELD),
            cookie.high,
        );
        write_u32(
            frame,
            nested_field(field, ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_LOW_FIELD),
            cookie.low,
        );
    }

    fn write_socket_address(frame: &mut [u8], field: WireField, address: SocketAddr) {
        let family = if address.is_ipv4() {
            AddressFamilyCode::Ipv4
        } else {
            AddressFamilyCode::Ipv6
        };
        write_u8(
            frame,
            nested_field(field, ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_FAMILY_FIELD),
            family.wire_value(),
        );
        write_u16(
            frame,
            nested_field(field, ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_PORT_FIELD),
            address.port(),
        );
        match address.ip() {
            IpAddr::V4(address) => write_bytes(
                frame,
                nested_field(
                    field,
                    ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_IPV4_ADDRESS_FIELD,
                ),
                &address.octets(),
            ),
            IpAddr::V6(address) => write_bytes(
                frame,
                nested_field(
                    field,
                    ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_FIELD,
                ),
                &address.octets(),
            ),
        }
    }

    fn write_payload_identity(
        frame: &mut [u8],
        field: WireField,
        payload: CanaryInboundPayloadIdentity,
    ) {
        match payload {
            CanaryInboundPayloadIdentity::Echo {
                wire_length,
                wire_digest,
                ..
            } => {
                write_u8(
                    frame,
                    nested_field(field, ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_KIND_FIELD),
                    PayloadKind::Echo.wire_value(),
                );
                write_u16(
                    frame,
                    nested_field(
                        field,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_LENGTH_FIELD,
                    ),
                    wire_length.get(),
                );
                write_bytes(
                    frame,
                    nested_field(
                        field,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_DIGEST_FIELD,
                    ),
                    &wire_digest.0,
                );
            }
            CanaryInboundPayloadIdentity::Dns {
                transaction_id,
                question,
                wire_length,
                wire_digest,
                tcp_length_prefix,
                ..
            } => {
                write_u8(
                    frame,
                    nested_field(field, ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_KIND_FIELD),
                    PayloadKind::Dns.wire_value(),
                );
                write_u16(
                    frame,
                    nested_field(
                        field,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_LENGTH_FIELD,
                    ),
                    wire_length.get(),
                );
                write_bytes(
                    frame,
                    nested_field(
                        field,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_DIGEST_FIELD,
                    ),
                    &wire_digest.0,
                );
                write_u16(
                    frame,
                    nested_field(
                        field,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TRANSACTION_ID_FIELD,
                    ),
                    transaction_id,
                );
                write_u16(
                    frame,
                    nested_field(
                        field,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TCP_LENGTH_FIELD,
                    ),
                    tcp_length_prefix.unwrap_or(0),
                );
                write_bytes(
                    frame,
                    nested_field(
                        field,
                        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_QUESTION_DIGEST_FIELD,
                    ),
                    &question.0,
                );
            }
        }
    }

    fn mutate_u8(frame: &[u8], field: WireField, value: u8) -> Vec<u8> {
        let mut mutated = frame.to_vec();
        mutated[field.offset()] = value;
        mutated
    }

    fn mutate_u16(frame: &[u8], field: WireField, value: u16) -> Vec<u8> {
        let mut mutated = frame.to_vec();
        write_u16(&mut mutated, field, value);
        mutated
    }

    fn mutate_u64(frame: &[u8], field: WireField, value: u64) -> Vec<u8> {
        let mut mutated = frame.to_vec();
        write_u64(&mut mutated, field, value);
        mutated
    }

    fn write_bytes(frame: &mut [u8], field: WireField, value: &[u8]) {
        assert_eq!(field.bytes(), value.len());
        frame[field.offset()..field.end()].copy_from_slice(value);
    }

    fn write_u8(frame: &mut [u8], field: WireField, value: u8) {
        assert_eq!(field.bytes(), 1);
        frame[field.offset()] = value;
    }

    fn write_u16(frame: &mut [u8], field: WireField, value: u16) {
        write_bytes(frame, field, &WireCodec::encode_u16(value));
    }

    fn write_u32(frame: &mut [u8], field: WireField, value: u32) {
        write_bytes(frame, field, &WireCodec::encode_u32(value));
    }

    fn write_u64(frame: &mut [u8], field: WireField, value: u64) {
        write_bytes(frame, field, &WireCodec::encode_u64(value));
    }
}
