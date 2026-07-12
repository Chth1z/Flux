use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use flux_core::{
    InterfaceName, MAX_OPAQUE_RULE_ATTRIBUTE_DETAILS, NetworkAddressFamily, NetworkRuleRecord,
    NetworkRuleRecordErrorKind, OpaqueRuleAttribute, RuleAction, RuleAttributeOpacity, RuleFlags,
    RuleFlowId, RuleFwMark, RuleIpProtocol, RuleOpaqueAttributeFingerprint, RulePortRange,
    RulePrefix, RulePriority, RuleProperties, RuleProtocol, RuleSuppressInterfaceGroup,
    RuleSuppressPrefixLength, RuleTableId, RuleTunnelId, RuleUidRange,
};
use sha2::{Digest, Sha256};

use super::{
    NETLINK_HEADER_LENGTH, NLM_F_DUMP_INTR, NLMSG_DONE, NLMSG_ERROR, NLMSG_OVERRUN,
    NetlinkAttribute, NetlinkAttributeError, NetlinkAttributeErrorKind, NetlinkAttributeIter,
    NetlinkDoneError, NetlinkDoneErrorKind, NetlinkFrameError, NetlinkFrameErrorKind,
    NetlinkMessageHeader, NetlinkMessageIter, validate_done_payload,
};

const RULE_MESSAGE_LENGTH: usize = 12;
const UID_RANGE_LENGTH: usize = 8;
const PORT_RANGE_LENGTH: usize = 4;
const OPAQUE_ATTRIBUTE_FINGERPRINT_DOMAIN: &[u8] = b"flux-rule-opaque-attributes-v1\0";

const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const RT_TABLE_COMPAT: u8 = 252;

const FRA_DST: u16 = 1;
const FRA_SRC: u16 = 2;
const FRA_IIFNAME: u16 = 3;
const FRA_GOTO: u16 = 4;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_FLOW: u16 = 11;
const FRA_TUN_ID: u16 = 12;
const FRA_SUPPRESS_IFGROUP: u16 = 13;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_OIFNAME: u16 = 17;
const FRA_PAD: u16 = 18;
const FRA_L3MDEV: u16 = 19;
const FRA_UID_RANGE: u16 = 20;
const FRA_PROTOCOL: u16 = 21;
const FRA_IP_PROTO: u16 = 22;
const FRA_SPORT_RANGE: u16 = 23;
const FRA_DPORT_RANGE: u16 = 24;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NetworkRuleEvent {
    Upsert(NetworkRuleRecord),
    Remove(NetworkRuleRecord),
}

impl NetworkRuleEvent {
    #[must_use]
    pub(crate) const fn record(&self) -> &NetworkRuleRecord {
        match self {
            Self::Upsert(record) | Self::Remove(record) => record,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuleEventDecodeErrorKind {
    TruncatedHeader,
    InvalidMessageLength,
    MissingMessagePadding,
    TruncatedRuleMessage,
    NonzeroReservedField,
    InvalidAttributeLength,
    MissingAttributePadding,
    InvalidAttributeFlags,
    DuplicateSemanticAttribute,
    MissingDestination,
    InvalidDestinationLength,
    InvalidDestinationPrefixLength,
    MissingSource,
    InvalidSourceLength,
    InvalidSourcePrefixLength,
    MissingTable,
    InvalidTableLength,
    InconsistentTable,
    InvalidInputInterfaceName,
    InvalidOutputInterfaceName,
    InvalidGotoLength,
    InvalidGotoTarget,
    MissingGotoTarget,
    UnexpectedGotoTarget,
    BackwardGoto,
    InvalidPriorityLength,
    InvalidFwmarkLength,
    MissingFwmask,
    InvalidFwmaskLength,
    InvalidFlowLength,
    InvalidFlowId,
    FlowUnsupported,
    InvalidTunnelIdLength,
    InvalidTunnelId,
    InvalidSuppressInterfaceGroupLength,
    MissingSuppressPrefixLength,
    InvalidSuppressPrefixLengthLength,
    InvalidL3mdevLength,
    InvalidL3mdev,
    InvalidUidRangeLength,
    InvalidUidRange,
    MissingProtocol,
    InvalidProtocolLength,
    InvalidIpProtocolLength,
    InvalidIpProtocol,
    InvalidSourcePortRangeLength,
    InvalidDestinationPortRangeLength,
    InvalidPortRange,
    InvalidPaddingLength,
    InvalidIpv4Tos,
    L3mdevTableConflict,
    InvalidRuleRecord,
    NetlinkOverrun,
    NetlinkError,
    InterruptedDump,
    MixedSequence,
    DuplicateDone,
    MessageAfterDone,
    InvalidDonePayload,
    DoneErrorStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuleEventDecodeError {
    kind: RuleEventDecodeErrorKind,
    offset: usize,
}

impl RuleEventDecodeError {
    const fn new(kind: RuleEventDecodeErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    #[must_use]
    pub(crate) const fn kind(self) -> RuleEventDecodeErrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }
}

impl From<NetlinkFrameError> for RuleEventDecodeError {
    fn from(error: NetlinkFrameError) -> Self {
        Self::new(
            match error.kind() {
                NetlinkFrameErrorKind::TruncatedHeader => RuleEventDecodeErrorKind::TruncatedHeader,
                NetlinkFrameErrorKind::InvalidMessageLength => {
                    RuleEventDecodeErrorKind::InvalidMessageLength
                }
                NetlinkFrameErrorKind::MissingMessagePadding => {
                    RuleEventDecodeErrorKind::MissingMessagePadding
                }
            },
            error.offset(),
        )
    }
}

impl From<NetlinkAttributeError> for RuleEventDecodeError {
    fn from(error: NetlinkAttributeError) -> Self {
        Self::new(
            match error.kind() {
                NetlinkAttributeErrorKind::InvalidAttributeLength => {
                    RuleEventDecodeErrorKind::InvalidAttributeLength
                }
                NetlinkAttributeErrorKind::MissingAttributePadding => {
                    RuleEventDecodeErrorKind::MissingAttributePadding
                }
                NetlinkAttributeErrorKind::InvalidAttributeFlags => {
                    RuleEventDecodeErrorKind::InvalidAttributeFlags
                }
            },
            error.offset(),
        )
    }
}

impl From<NetlinkDoneError> for RuleEventDecodeError {
    fn from(error: NetlinkDoneError) -> Self {
        Self::new(
            match error.kind() {
                NetlinkDoneErrorKind::InvalidPayload => {
                    RuleEventDecodeErrorKind::InvalidDonePayload
                }
                NetlinkDoneErrorKind::ErrorStatus => RuleEventDecodeErrorKind::DoneErrorStatus,
            },
            error.offset(),
        )
    }
}

impl fmt::Display for RuleEventDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid rtnetlink rule datagram at byte {}: {}",
            self.offset,
            match self.kind {
                RuleEventDecodeErrorKind::TruncatedHeader => "truncated netlink header",
                RuleEventDecodeErrorKind::InvalidMessageLength => "invalid netlink message length",
                RuleEventDecodeErrorKind::MissingMessagePadding => {
                    "missing aligned netlink message padding"
                }
                RuleEventDecodeErrorKind::TruncatedRuleMessage => "truncated fib_rule_hdr",
                RuleEventDecodeErrorKind::NonzeroReservedField => {
                    "fib_rule_hdr reserved field is nonzero"
                }
                RuleEventDecodeErrorKind::InvalidAttributeLength => {
                    "invalid netlink attribute length"
                }
                RuleEventDecodeErrorKind::MissingAttributePadding => {
                    "missing aligned netlink attribute padding"
                }
                RuleEventDecodeErrorKind::InvalidAttributeFlags => {
                    "recognized rule attribute carries incompatible flags"
                }
                RuleEventDecodeErrorKind::DuplicateSemanticAttribute => {
                    "duplicate semantic rule attribute"
                }
                RuleEventDecodeErrorKind::MissingDestination => {
                    "destination-specific rule has no destination attribute"
                }
                RuleEventDecodeErrorKind::InvalidDestinationLength => {
                    "destination has the wrong length for its address family"
                }
                RuleEventDecodeErrorKind::InvalidDestinationPrefixLength => {
                    "destination prefix length is invalid"
                }
                RuleEventDecodeErrorKind::MissingSource => {
                    "source-specific rule has no source attribute"
                }
                RuleEventDecodeErrorKind::InvalidSourceLength => {
                    "source has the wrong length for its address family"
                }
                RuleEventDecodeErrorKind::InvalidSourcePrefixLength => {
                    "source prefix length is invalid"
                }
                RuleEventDecodeErrorKind::MissingTable => {
                    "kernel rule output is missing mandatory FRA_TABLE"
                }
                RuleEventDecodeErrorKind::InvalidTableLength => {
                    "FRA_TABLE must contain exactly one u32"
                }
                RuleEventDecodeErrorKind::InconsistentTable => {
                    "rule header and FRA_TABLE disagree"
                }
                RuleEventDecodeErrorKind::InvalidInputInterfaceName => {
                    "FRA_IIFNAME is not one canonical kernel interface name"
                }
                RuleEventDecodeErrorKind::InvalidOutputInterfaceName => {
                    "FRA_OIFNAME is not one canonical kernel interface name"
                }
                RuleEventDecodeErrorKind::InvalidGotoLength => {
                    "FRA_GOTO must contain exactly one u32"
                }
                RuleEventDecodeErrorKind::InvalidGotoTarget => "FRA_GOTO target is zero",
                RuleEventDecodeErrorKind::MissingGotoTarget => {
                    "goto action is missing FRA_GOTO"
                }
                RuleEventDecodeErrorKind::UnexpectedGotoTarget => {
                    "non-goto action carries FRA_GOTO"
                }
                RuleEventDecodeErrorKind::BackwardGoto => {
                    "FRA_GOTO does not target a later priority"
                }
                RuleEventDecodeErrorKind::InvalidPriorityLength => {
                    "FRA_PRIORITY must contain exactly one u32"
                }
                RuleEventDecodeErrorKind::InvalidFwmarkLength => {
                    "FRA_FWMARK must contain exactly one u32"
                }
                RuleEventDecodeErrorKind::MissingFwmask => {
                    "nonzero FRA_FWMARK is missing canonical FRA_FWMASK"
                }
                RuleEventDecodeErrorKind::InvalidFwmaskLength => {
                    "FRA_FWMASK must contain exactly one u32"
                }
                RuleEventDecodeErrorKind::InvalidFlowLength => {
                    "FRA_FLOW must contain exactly one u32"
                }
                RuleEventDecodeErrorKind::InvalidFlowId => "FRA_FLOW is zero",
                RuleEventDecodeErrorKind::FlowUnsupported => {
                    "FRA_FLOW is unsupported for IPv6 rules"
                }
                RuleEventDecodeErrorKind::InvalidTunnelIdLength => {
                    "FRA_TUN_ID must contain exactly one big-endian u64"
                }
                RuleEventDecodeErrorKind::InvalidTunnelId => "FRA_TUN_ID is zero",
                RuleEventDecodeErrorKind::InvalidSuppressInterfaceGroupLength => {
                    "FRA_SUPPRESS_IFGROUP must contain exactly one u32"
                }
                RuleEventDecodeErrorKind::MissingSuppressPrefixLength => {
                    "kernel rule output is missing mandatory FRA_SUPPRESS_PREFIXLEN"
                }
                RuleEventDecodeErrorKind::InvalidSuppressPrefixLengthLength => {
                    "FRA_SUPPRESS_PREFIXLEN must contain exactly one u32"
                }
                RuleEventDecodeErrorKind::InvalidL3mdevLength => {
                    "FRA_L3MDEV must contain exactly one u8"
                }
                RuleEventDecodeErrorKind::InvalidL3mdev => "FRA_L3MDEV must equal one",
                RuleEventDecodeErrorKind::InvalidUidRangeLength => {
                    "FRA_UID_RANGE must contain exactly one fib_rule_uid_range"
                }
                RuleEventDecodeErrorKind::InvalidUidRange => "FRA_UID_RANGE is invalid",
                RuleEventDecodeErrorKind::MissingProtocol => {
                    "kernel rule output is missing mandatory FRA_PROTOCOL"
                }
                RuleEventDecodeErrorKind::InvalidProtocolLength => {
                    "FRA_PROTOCOL must contain exactly one u8"
                }
                RuleEventDecodeErrorKind::InvalidIpProtocolLength => {
                    "FRA_IP_PROTO must contain exactly one u8"
                }
                RuleEventDecodeErrorKind::InvalidIpProtocol => "FRA_IP_PROTO is zero",
                RuleEventDecodeErrorKind::InvalidSourcePortRangeLength => {
                    "FRA_SPORT_RANGE must contain exactly one fib_rule_port_range"
                }
                RuleEventDecodeErrorKind::InvalidDestinationPortRangeLength => {
                    "FRA_DPORT_RANGE must contain exactly one fib_rule_port_range"
                }
                RuleEventDecodeErrorKind::InvalidPortRange => "policy-rule port range is invalid",
                RuleEventDecodeErrorKind::InvalidPaddingLength => {
                    "FRA_PAD must have an empty payload"
                }
                RuleEventDecodeErrorKind::InvalidIpv4Tos => {
                    "IPv4 rule TOS contains bits outside IPTOS_TOS_MASK"
                }
                RuleEventDecodeErrorKind::L3mdevTableConflict => {
                    "l3mdev rule also names a routing table"
                }
                RuleEventDecodeErrorKind::InvalidRuleRecord => {
                    "rule fields cannot form a canonical record"
                }
                RuleEventDecodeErrorKind::NetlinkOverrun => "netlink reported message overrun",
                RuleEventDecodeErrorKind::NetlinkError => "netlink returned NLMSG_ERROR",
                RuleEventDecodeErrorKind::InterruptedDump => {
                    "netlink message reports an interrupted dump"
                }
                RuleEventDecodeErrorKind::MixedSequence => {
                    "netlink datagram contains mixed sequence numbers"
                }
                RuleEventDecodeErrorKind::DuplicateDone => {
                    "netlink datagram contains more than one NLMSG_DONE"
                }
                RuleEventDecodeErrorKind::MessageAfterDone => {
                    "netlink datagram contains a message after NLMSG_DONE"
                }
                RuleEventDecodeErrorKind::InvalidDonePayload => {
                    "NLMSG_DONE payload or extended-ack attributes are malformed"
                }
                RuleEventDecodeErrorKind::DoneErrorStatus => {
                    "NLMSG_DONE reports a nonzero error status"
                }
            }
        )
    }
}

impl Error for RuleEventDecodeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuleDatagram {
    sequence: Option<u32>,
    events: Vec<NetworkRuleEvent>,
    completion: Option<NetlinkMessageHeader>,
}

impl RuleDatagram {
    #[must_use]
    pub(crate) const fn sequence(&self) -> Option<u32> {
        self.sequence
    }

    #[must_use]
    pub(crate) fn events(&self) -> &[NetworkRuleEvent] {
        &self.events
    }

    #[must_use]
    pub(crate) const fn completion(&self) -> Option<NetlinkMessageHeader> {
        self.completion
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RtnetlinkRuleEventDecoder {
    include_ipv6: bool,
}

impl RtnetlinkRuleEventDecoder {
    #[must_use]
    pub(crate) const fn new(include_ipv6: bool) -> Self {
        Self { include_ipv6 }
    }

    pub(crate) fn decode_datagram(
        &self,
        datagram: &[u8],
    ) -> Result<RuleDatagram, RuleEventDecodeError> {
        let mut sequence = None;
        let mut events = Vec::new();
        let mut completion = None;

        for message in NetlinkMessageIter::new(datagram) {
            let message = message.map_err(RuleEventDecodeError::from)?;
            let header = message.header();
            if sequence.is_some_and(|expected| expected != header.sequence()) {
                return Err(RuleEventDecodeError::new(
                    RuleEventDecodeErrorKind::MixedSequence,
                    message.offset(),
                ));
            }
            sequence.get_or_insert(header.sequence());

            if completion.is_some() {
                return Err(RuleEventDecodeError::new(
                    if header.message_type() == NLMSG_DONE {
                        RuleEventDecodeErrorKind::DuplicateDone
                    } else {
                        RuleEventDecodeErrorKind::MessageAfterDone
                    },
                    message.offset(),
                ));
            }

            if header.flags() & NLM_F_DUMP_INTR != 0 {
                return Err(RuleEventDecodeError::new(
                    RuleEventDecodeErrorKind::InterruptedDump,
                    message.offset(),
                ));
            }

            match header.message_type() {
                NLMSG_OVERRUN => {
                    return Err(RuleEventDecodeError::new(
                        RuleEventDecodeErrorKind::NetlinkOverrun,
                        message.offset(),
                    ));
                }
                NLMSG_ERROR => {
                    return Err(RuleEventDecodeError::new(
                        RuleEventDecodeErrorKind::NetlinkError,
                        message.offset(),
                    ));
                }
                NLMSG_DONE => {
                    validate_done_payload(
                        message.payload(),
                        header.flags(),
                        message.offset() + NETLINK_HEADER_LENGTH,
                    )
                    .map_err(RuleEventDecodeError::from)?;
                    completion = Some(header);
                }
                RTM_NEWRULE | RTM_DELRULE => {
                    if let Some(event) = self.decode_rule_message(
                        header.message_type(),
                        message.payload(),
                        message.offset() + NETLINK_HEADER_LENGTH,
                    )? {
                        events.push(event);
                    }
                }
                _ => {}
            }
        }

        Ok(RuleDatagram {
            sequence,
            events,
            completion,
        })
    }

    fn decode_rule_message(
        &self,
        message_type: u16,
        body: &[u8],
        body_offset: usize,
    ) -> Result<Option<NetworkRuleEvent>, RuleEventDecodeError> {
        if body.len() < RULE_MESSAGE_LENGTH {
            return Err(RuleEventDecodeError::new(
                RuleEventDecodeErrorKind::TruncatedRuleMessage,
                body_offset,
            ));
        }

        let attributes = &body[RULE_MESSAGE_LENGTH..];
        let attributes_offset = body_offset + RULE_MESSAGE_LENGTH;
        let Some(family) = decode_family(u16::from(body[0])) else {
            validate_attribute_framing(attributes, attributes_offset)?;
            return Ok(None);
        };

        if body[5] != 0 {
            return Err(RuleEventDecodeError::new(
                RuleEventDecodeErrorKind::NonzeroReservedField,
                body_offset + 5,
            ));
        }
        if body[6] != 0 {
            return Err(RuleEventDecodeError::new(
                RuleEventDecodeErrorKind::NonzeroReservedField,
                body_offset + 6,
            ));
        }

        let decoded = decode_rule_attributes(family, attributes, attributes_offset)?;
        let destination = decode_prefix(
            family,
            body[1],
            decoded.destination,
            PrefixRole::Destination,
            body_offset + 1,
            attributes_offset,
        )?;
        let source = decode_prefix(
            family,
            body[2],
            decoded.source,
            PrefixRole::Source,
            body_offset + 2,
            attributes_offset,
        )?;
        let table_attribute = decoded.table.ok_or_else(|| {
            RuleEventDecodeError::new(RuleEventDecodeErrorKind::MissingTable, attributes_offset)
        })?;
        let suppress_prefix_length = decoded.suppress_prefix_length.ok_or_else(|| {
            RuleEventDecodeError::new(
                RuleEventDecodeErrorKind::MissingSuppressPrefixLength,
                attributes_offset,
            )
        })?;
        let protocol = decoded.protocol.ok_or_else(|| {
            RuleEventDecodeError::new(RuleEventDecodeErrorKind::MissingProtocol, attributes_offset)
        })?;
        if decoded.fwmark.is_some_and(|mark| mark.value != 0) && decoded.fwmask.is_none() {
            return Err(RuleEventDecodeError::new(
                RuleEventDecodeErrorKind::MissingFwmask,
                decoded.fwmark.expect("nonzero mark checked above").offset,
            ));
        }
        let table = reconcile_table(body[4], table_attribute)?;
        let priority = RulePriority::from_raw(decoded.priority.unwrap_or(0));
        let properties = RuleProperties::new(
            body[3],
            RuleTableId::from_raw(table),
            RuleAction::from_raw(body[7]),
            RuleProtocol::from_raw(protocol),
            RuleFlags::from_raw(read_u32(&body[8..])),
        );
        let mut record = NetworkRuleRecord::new(
            destination,
            source,
            properties,
            priority,
            decoded.goto_target.map(|target| target.value),
        )
        .map_err(|error| record_error(error.kind(), body_offset, decoded.goto_target))?;

        let fwmark_value = decoded.fwmark.map_or(0, |mark| mark.value);
        let fwmark_mask = decoded
            .fwmask
            .unwrap_or(if fwmark_value == 0 { 0 } else { u32::MAX });
        if let Some(fwmark) = RuleFwMark::new(fwmark_value, fwmark_mask) {
            record = record.with_fwmark(fwmark);
        }
        if let Some(input_interface) = decoded.input_interface {
            record = record.with_input_interface(input_interface);
        }
        if let Some(output_interface) = decoded.output_interface {
            record = record.with_output_interface(output_interface);
        }
        if let Some(tunnel_id) = decoded.tunnel_id {
            record = record.with_tunnel_id(tunnel_id);
        }
        if let Some(group) = decoded.suppress_interface_group {
            record = record.with_suppress_interface_group(group);
        }
        if let Some(prefix_length) = suppress_prefix_length {
            record = record.with_suppress_prefix_length(prefix_length);
        }
        if decoded.l3mdev {
            record = record
                .with_l3mdev()
                .map_err(|error| record_error(error.kind(), body_offset, decoded.goto_target))?;
        }
        if let Some(uid_range) = decoded.uid_range {
            record = record.with_uid_range(uid_range);
        }
        if let Some(ip_protocol) = decoded.ip_protocol {
            record = record.with_ip_protocol(ip_protocol);
        }
        if let Some(range) = decoded.source_port_range {
            record = record.with_source_port_range(range);
        }
        if let Some(range) = decoded.destination_port_range {
            record = record.with_destination_port_range(range);
        }
        if let Some(flow) = decoded.flow {
            record = record
                .with_flow(flow)
                .map_err(|error| record_error(error.kind(), body_offset, decoded.goto_target))?;
        }
        if let Some(opacity) = decoded.opaque_attributes.finish() {
            record = record.with_attribute_opacity(opacity);
        }

        if family == NetworkAddressFamily::Ipv6 && !self.include_ipv6 {
            return Ok(None);
        }

        Ok(Some(if message_type == RTM_DELRULE {
            NetworkRuleEvent::Remove(record)
        } else {
            NetworkRuleEvent::Upsert(record)
        }))
    }
}

#[derive(Clone, Copy)]
struct Located<T> {
    value: T,
    offset: usize,
}

#[derive(Default)]
struct DecodedRuleAttributes {
    destination: Option<Located<IpAddr>>,
    source: Option<Located<IpAddr>>,
    input_interface: Option<InterfaceName>,
    output_interface: Option<InterfaceName>,
    goto_target: Option<Located<RulePriority>>,
    priority: Option<u32>,
    fwmark: Option<Located<u32>>,
    fwmask: Option<u32>,
    flow: Option<RuleFlowId>,
    tunnel_id: Option<RuleTunnelId>,
    suppress_interface_group: Option<RuleSuppressInterfaceGroup>,
    suppress_prefix_length: Option<Option<RuleSuppressPrefixLength>>,
    table: Option<Located<u32>>,
    l3mdev: bool,
    uid_range: Option<RuleUidRange>,
    protocol: Option<u8>,
    ip_protocol: Option<RuleIpProtocol>,
    source_port_range: Option<RulePortRange>,
    destination_port_range: Option<RulePortRange>,
    opaque_attributes: OpaqueRuleAttributeAccumulator,
}

struct OpaqueRuleAttributeAccumulator {
    retained_details: Vec<OpaqueRuleAttribute>,
    omitted_details: u32,
    total_attributes: u32,
    hasher: Sha256,
}

impl Default for OpaqueRuleAttributeAccumulator {
    fn default() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(OPAQUE_ATTRIBUTE_FINGERPRINT_DOMAIN);
        Self {
            retained_details: Vec::with_capacity(MAX_OPAQUE_RULE_ATTRIBUTE_DETAILS),
            omitted_details: 0,
            total_attributes: 0,
            hasher,
        }
    }
}

impl OpaqueRuleAttributeAccumulator {
    fn record(&mut self, attribute: NetlinkAttribute<'_>) {
        let payload_length = u16::try_from(attribute.value().len())
            .expect("a netlink attribute payload is bounded by its u16 length field");
        let detail = OpaqueRuleAttribute::new(
            attribute.attribute_type(),
            attribute.flags(),
            payload_length,
        );
        if self.retained_details.len() < MAX_OPAQUE_RULE_ATTRIBUTE_DETAILS {
            self.retained_details.push(detail);
        } else {
            self.omitted_details = self
                .omitted_details
                .checked_add(1)
                .expect("one netlink message cannot contain u32::MAX attributes");
        }
        self.total_attributes = self
            .total_attributes
            .checked_add(1)
            .expect("one netlink message cannot contain u32::MAX attributes");

        let raw_type = attribute.attribute_type() | attribute.flags();
        self.hasher.update(raw_type.to_le_bytes());
        self.hasher.update(payload_length.to_le_bytes());
        self.hasher.update(attribute.value());
    }

    fn finish(mut self) -> Option<RuleAttributeOpacity> {
        if self.total_attributes == 0 {
            return None;
        }
        self.hasher.update(self.total_attributes.to_le_bytes());
        let fingerprint = RuleOpaqueAttributeFingerprint::from_bytes(self.hasher.finalize().into());
        Some(
            RuleAttributeOpacity::new(self.retained_details, self.omitted_details, fingerprint)
                .expect("opaque attribute accumulator maintains the core evidence bounds"),
        )
    }
}

fn decode_rule_attributes(
    family: NetworkAddressFamily,
    attributes: &[u8],
    attributes_offset: usize,
) -> Result<DecodedRuleAttributes, RuleEventDecodeError> {
    let mut decoded = DecodedRuleAttributes::default();
    let mut seen = [false; (FRA_DPORT_RANGE + 1) as usize];

    for attribute in NetlinkAttributeIter::new(attributes, attributes_offset) {
        let attribute = attribute.map_err(RuleEventDecodeError::from)?;
        let attribute_type = attribute.attribute_type();
        match attribute_type {
            FRA_DST => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.destination = Some(decode_family_address(
                    family,
                    attribute,
                    RuleEventDecodeErrorKind::InvalidDestinationLength,
                )?);
            }
            FRA_SRC => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.source = Some(decode_family_address(
                    family,
                    attribute,
                    RuleEventDecodeErrorKind::InvalidSourceLength,
                )?);
            }
            FRA_IIFNAME => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.input_interface = Some(decode_interface_name(
                    attribute,
                    RuleEventDecodeErrorKind::InvalidInputInterfaceName,
                )?);
            }
            FRA_GOTO => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u32>(),
                    RuleEventDecodeErrorKind::InvalidGotoLength,
                    attribute.value_offset(),
                )?;
                let value = read_u32(attribute.value());
                if value == 0 {
                    return Err(RuleEventDecodeError::new(
                        RuleEventDecodeErrorKind::InvalidGotoTarget,
                        attribute.value_offset(),
                    ));
                }
                decoded.goto_target = Some(Located {
                    value: RulePriority::from_raw(value),
                    offset: attribute.value_offset(),
                });
            }
            FRA_PRIORITY => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.priority = Some(decode_u32(
                    attribute,
                    RuleEventDecodeErrorKind::InvalidPriorityLength,
                )?);
            }
            FRA_FWMARK => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.fwmark = Some(Located {
                    value: decode_u32(attribute, RuleEventDecodeErrorKind::InvalidFwmarkLength)?,
                    offset: attribute.offset(),
                });
            }
            FRA_FLOW => {
                if family == NetworkAddressFamily::Ipv6 {
                    // The IPv6 5.10 rule policy leaves FRA_FLOW unspecified,
                    // accepts arbitrary payload, ignores it, and never emits it.
                    // Preserve that family-specific forward-compatibility contract.
                    continue;
                }
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                let value = decode_u32(attribute, RuleEventDecodeErrorKind::InvalidFlowLength)?;
                decoded.flow = Some(RuleFlowId::new(value).ok_or_else(|| {
                    RuleEventDecodeError::new(
                        RuleEventDecodeErrorKind::InvalidFlowId,
                        attribute.value_offset(),
                    )
                })?);
            }
            FRA_TUN_ID => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u64>(),
                    RuleEventDecodeErrorKind::InvalidTunnelIdLength,
                    attribute.value_offset(),
                )?;
                decoded.tunnel_id = Some(
                    RuleTunnelId::new(read_be_u64(attribute.value())).ok_or_else(|| {
                        RuleEventDecodeError::new(
                            RuleEventDecodeErrorKind::InvalidTunnelId,
                            attribute.value_offset(),
                        )
                    })?,
                );
            }
            FRA_SUPPRESS_IFGROUP => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.suppress_interface_group =
                    RuleSuppressInterfaceGroup::from_raw(decode_u32(
                        attribute,
                        RuleEventDecodeErrorKind::InvalidSuppressInterfaceGroupLength,
                    )?);
            }
            FRA_SUPPRESS_PREFIXLEN => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.suppress_prefix_length =
                    Some(RuleSuppressPrefixLength::from_raw(decode_u32(
                        attribute,
                        RuleEventDecodeErrorKind::InvalidSuppressPrefixLengthLength,
                    )?));
            }
            FRA_TABLE => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u32>(),
                    RuleEventDecodeErrorKind::InvalidTableLength,
                    attribute.value_offset(),
                )?;
                decoded.table = Some(Located {
                    value: read_u32(attribute.value()),
                    offset: attribute.value_offset(),
                });
            }
            FRA_FWMASK => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.fwmask = Some(decode_u32(
                    attribute,
                    RuleEventDecodeErrorKind::InvalidFwmaskLength,
                )?);
            }
            FRA_OIFNAME => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.output_interface = Some(decode_interface_name(
                    attribute,
                    RuleEventDecodeErrorKind::InvalidOutputInterfaceName,
                )?);
            }
            FRA_PAD => {
                require_plain_attribute(attribute)?;
                require_length(
                    attribute.value(),
                    0,
                    RuleEventDecodeErrorKind::InvalidPaddingLength,
                    attribute.value_offset(),
                )?;
            }
            FRA_L3MDEV => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u8>(),
                    RuleEventDecodeErrorKind::InvalidL3mdevLength,
                    attribute.value_offset(),
                )?;
                if attribute.value()[0] != 1 {
                    return Err(RuleEventDecodeError::new(
                        RuleEventDecodeErrorKind::InvalidL3mdev,
                        attribute.value_offset(),
                    ));
                }
                decoded.l3mdev = true;
            }
            FRA_UID_RANGE => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    UID_RANGE_LENGTH,
                    RuleEventDecodeErrorKind::InvalidUidRangeLength,
                    attribute.value_offset(),
                )?;
                decoded.uid_range = Some(
                    RuleUidRange::new(
                        read_u32(attribute.value()),
                        read_u32(&attribute.value()[size_of::<u32>()..]),
                    )
                    .map_err(|_| {
                        RuleEventDecodeError::new(
                            RuleEventDecodeErrorKind::InvalidUidRange,
                            attribute.value_offset(),
                        )
                    })?,
                );
            }
            FRA_PROTOCOL => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u8>(),
                    RuleEventDecodeErrorKind::InvalidProtocolLength,
                    attribute.value_offset(),
                )?;
                decoded.protocol = Some(attribute.value()[0]);
            }
            FRA_IP_PROTO => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u8>(),
                    RuleEventDecodeErrorKind::InvalidIpProtocolLength,
                    attribute.value_offset(),
                )?;
                decoded.ip_protocol =
                    Some(RuleIpProtocol::new(attribute.value()[0]).ok_or_else(|| {
                        RuleEventDecodeError::new(
                            RuleEventDecodeErrorKind::InvalidIpProtocol,
                            attribute.value_offset(),
                        )
                    })?);
            }
            FRA_SPORT_RANGE => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.source_port_range = Some(decode_port_range(
                    attribute,
                    RuleEventDecodeErrorKind::InvalidSourcePortRangeLength,
                )?);
            }
            FRA_DPORT_RANGE => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.destination_port_range = Some(decode_port_range(
                    attribute,
                    RuleEventDecodeErrorKind::InvalidDestinationPortRangeLength,
                )?);
            }
            _ => decoded.opaque_attributes.record(attribute),
        }
    }

    Ok(decoded)
}

#[derive(Clone, Copy)]
enum PrefixRole {
    Destination,
    Source,
}

fn decode_prefix(
    family: NetworkAddressFamily,
    prefix_length: u8,
    address: Option<Located<IpAddr>>,
    role: PrefixRole,
    prefix_offset: usize,
    missing_offset: usize,
) -> Result<RulePrefix, RuleEventDecodeError> {
    if prefix_length > maximum_prefix_length(family) {
        return Err(RuleEventDecodeError::new(
            prefix_length_error(role),
            prefix_offset,
        ));
    }
    let Some(address) = address else {
        if prefix_length == 0 {
            return Ok(RulePrefix::unspecified(family));
        }
        return Err(RuleEventDecodeError::new(
            match role {
                PrefixRole::Destination => RuleEventDecodeErrorKind::MissingDestination,
                PrefixRole::Source => RuleEventDecodeErrorKind::MissingSource,
            },
            missing_offset,
        ));
    };

    RulePrefix::new(address.value, prefix_length)
        .map_err(|_| RuleEventDecodeError::new(prefix_length_error(role), address.offset))
}

const fn prefix_length_error(role: PrefixRole) -> RuleEventDecodeErrorKind {
    match role {
        PrefixRole::Destination => RuleEventDecodeErrorKind::InvalidDestinationPrefixLength,
        PrefixRole::Source => RuleEventDecodeErrorKind::InvalidSourcePrefixLength,
    }
}

fn reconcile_table(
    header_table: u8,
    attribute_table: Located<u32>,
) -> Result<u32, RuleEventDecodeError> {
    let consistent = if let Ok(compact) = u8::try_from(attribute_table.value) {
        compact == header_table
    } else {
        header_table == RT_TABLE_COMPAT
    };
    if consistent {
        Ok(attribute_table.value)
    } else {
        Err(RuleEventDecodeError::new(
            RuleEventDecodeErrorKind::InconsistentTable,
            attribute_table.offset,
        ))
    }
}

fn decode_interface_name(
    attribute: NetlinkAttribute<'_>,
    error_kind: RuleEventDecodeErrorKind,
) -> Result<InterfaceName, RuleEventDecodeError> {
    let value = decode_string(attribute.value())
        .ok_or_else(|| RuleEventDecodeError::new(error_kind, attribute.value_offset()))?;
    InterfaceName::new(value)
        .ok_or_else(|| RuleEventDecodeError::new(error_kind, attribute.value_offset()))
}

fn decode_port_range(
    attribute: NetlinkAttribute<'_>,
    length_error: RuleEventDecodeErrorKind,
) -> Result<RulePortRange, RuleEventDecodeError> {
    require_length(
        attribute.value(),
        PORT_RANGE_LENGTH,
        length_error,
        attribute.value_offset(),
    )?;
    RulePortRange::new(
        read_u16(attribute.value()),
        read_u16(&attribute.value()[size_of::<u16>()..]),
    )
    .map_err(|_| {
        RuleEventDecodeError::new(
            RuleEventDecodeErrorKind::InvalidPortRange,
            attribute.value_offset(),
        )
    })
}

fn decode_u32(
    attribute: NetlinkAttribute<'_>,
    length_error: RuleEventDecodeErrorKind,
) -> Result<u32, RuleEventDecodeError> {
    require_length(
        attribute.value(),
        size_of::<u32>(),
        length_error,
        attribute.value_offset(),
    )?;
    Ok(read_u32(attribute.value()))
}

fn decode_family_address(
    family: NetworkAddressFamily,
    attribute: NetlinkAttribute<'_>,
    length_error: RuleEventDecodeErrorKind,
) -> Result<Located<IpAddr>, RuleEventDecodeError> {
    require_length(
        attribute.value(),
        address_length(family),
        length_error,
        attribute.value_offset(),
    )?;
    Ok(Located {
        value: decode_address(family, attribute.value()),
        offset: attribute.value_offset(),
    })
}

fn record_error(
    kind: NetworkRuleRecordErrorKind,
    body_offset: usize,
    goto_target: Option<Located<RulePriority>>,
) -> RuleEventDecodeError {
    RuleEventDecodeError::new(
        match kind {
            NetworkRuleRecordErrorKind::InvalidIpv4Tos => RuleEventDecodeErrorKind::InvalidIpv4Tos,
            NetworkRuleRecordErrorKind::MissingGotoTarget => {
                RuleEventDecodeErrorKind::MissingGotoTarget
            }
            NetworkRuleRecordErrorKind::UnexpectedGotoTarget => {
                RuleEventDecodeErrorKind::UnexpectedGotoTarget
            }
            NetworkRuleRecordErrorKind::BackwardGoto => RuleEventDecodeErrorKind::BackwardGoto,
            NetworkRuleRecordErrorKind::L3mdevTableConflict => {
                RuleEventDecodeErrorKind::L3mdevTableConflict
            }
            NetworkRuleRecordErrorKind::FlowUnsupported => {
                RuleEventDecodeErrorKind::FlowUnsupported
            }
            NetworkRuleRecordErrorKind::AddressFamilyMismatch => {
                RuleEventDecodeErrorKind::InvalidRuleRecord
            }
        },
        goto_target.map_or(body_offset, |target| target.offset),
    )
}

fn decode_family(raw: u16) -> Option<NetworkAddressFamily> {
    match raw {
        AF_INET => Some(NetworkAddressFamily::Ipv4),
        AF_INET6 => Some(NetworkAddressFamily::Ipv6),
        _ => None,
    }
}

const fn address_length(family: NetworkAddressFamily) -> usize {
    match family {
        NetworkAddressFamily::Ipv4 => 4,
        NetworkAddressFamily::Ipv6 => 16,
    }
}

const fn maximum_prefix_length(family: NetworkAddressFamily) -> u8 {
    match family {
        NetworkAddressFamily::Ipv4 => 32,
        NetworkAddressFamily::Ipv6 => 128,
    }
}

fn decode_address(family: NetworkAddressFamily, value: &[u8]) -> IpAddr {
    match family {
        NetworkAddressFamily::Ipv4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(value).expect("validated IPv4 address width"),
        )),
        NetworkAddressFamily::Ipv6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(value).expect("validated IPv6 address width"),
        )),
    }
}

fn validate_attribute_framing(
    attributes: &[u8],
    attributes_offset: usize,
) -> Result<(), RuleEventDecodeError> {
    for attribute in NetlinkAttributeIter::new(attributes, attributes_offset) {
        let _ = attribute.map_err(RuleEventDecodeError::from)?;
    }
    Ok(())
}

fn mark_seen(
    seen: &mut [bool],
    attribute_type: u16,
    offset: usize,
) -> Result<(), RuleEventDecodeError> {
    let slot = &mut seen[usize::from(attribute_type)];
    if std::mem::replace(slot, true) {
        Err(RuleEventDecodeError::new(
            RuleEventDecodeErrorKind::DuplicateSemanticAttribute,
            offset,
        ))
    } else {
        Ok(())
    }
}

fn require_plain_attribute(attribute: NetlinkAttribute<'_>) -> Result<(), RuleEventDecodeError> {
    if attribute.flags() == 0 {
        Ok(())
    } else {
        Err(RuleEventDecodeError::new(
            RuleEventDecodeErrorKind::InvalidAttributeFlags,
            attribute.offset(),
        ))
    }
}

fn require_length(
    value: &[u8],
    expected: usize,
    kind: RuleEventDecodeErrorKind,
    offset: usize,
) -> Result<(), RuleEventDecodeError> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(RuleEventDecodeError::new(kind, offset))
    }
}

fn decode_string(value: &[u8]) -> Option<&[u8]> {
    let (&0, bytes) = value.split_last()? else {
        return None;
    };
    if bytes.contains(&0) {
        None
    } else {
        Some(bytes)
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes[..2].try_into().expect("validated two-byte field"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes[..4].try_into().expect("validated four-byte field"))
}

fn read_be_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes[..8].try_into().expect("validated eight-byte field"))
}

#[cfg(test)]
#[path = "rule_tests.rs"]
mod tests;
