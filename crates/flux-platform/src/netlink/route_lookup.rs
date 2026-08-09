use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::num::{NonZeroI32, NonZeroU16, NonZeroU32};

use flux_core::RouteTableId;

use super::policy_routing::PolicyRoutingAckSender;
use super::{
    NETLINK_ATTRIBUTE_HEADER_LENGTH, NETLINK_HEADER_LENGTH, NLM_F_ACK_TLVS,
    NetlinkAttributeErrorKind, NetlinkAttributeIter, NetlinkFrameErrorKind, NetlinkMessageIter,
    align4,
};

pub(crate) const MAX_ROUTE_LOOKUP_RESPONSE_BYTES: usize = 64 * 1024;

const ROUTE_MESSAGE_LENGTH: usize = 12;
const IPV4_ROUTE_LOOKUP_REQUEST_BYTES: usize = 68;
const IPV6_ROUTE_LOOKUP_REQUEST_BYTES: usize = 80;
const NLMSGERR_HEADER_LENGTH: usize = 20;
const MAX_LINUX_ERRNO: i32 = 4_095;

const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_CAPPED: u16 = 0x0100;
const RTM_F_LOOKUP_TABLE: u32 = 0x1000;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const RT_TABLE_COMPAT: u8 = 252;

const RTA_DST: u16 = 1;
const RTA_TABLE: u16 = 15;
const RTA_MARK: u16 = 16;
const RTA_UID: u16 = 25;
const RTA_IP_PROTO: u16 = 27;
const RTA_DPORT: u16 = 29;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryRouteLookupRequest {
    destination: IpAddr,
    responder_port: NonZeroU16,
    uid: NonZeroU32,
    mark: u32,
}

impl CanaryRouteLookupRequest {
    #[must_use]
    pub(crate) const fn new(
        destination: IpAddr,
        responder_port: NonZeroU16,
        uid: NonZeroU32,
        mark: u32,
    ) -> Self {
        Self {
            destination,
            responder_port,
            uid,
            mark,
        }
    }

    #[must_use]
    pub(crate) const fn destination(self) -> IpAddr {
        self.destination
    }

    #[must_use]
    pub(crate) const fn responder_port(self) -> NonZeroU16 {
        self.responder_port
    }

    #[must_use]
    pub(crate) const fn uid(self) -> NonZeroU32 {
        self.uid
    }

    #[must_use]
    pub(crate) const fn mark(self) -> u32 {
        self.mark
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EncodedCanaryRouteLookupRequest {
    bytes: Box<[u8]>,
    sequence: NonZeroU32,
    lookup: CanaryRouteLookupRequest,
}

impl EncodedCanaryRouteLookupRequest {
    #[must_use]
    pub(crate) const fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub(crate) const fn sequence(&self) -> NonZeroU32 {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn lookup(&self) -> CanaryRouteLookupRequest {
        self.lookup
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryRouteLookupResult {
    table: RouteTableId,
}

impl CanaryRouteLookupResult {
    #[must_use]
    pub(crate) const fn table(self) -> RouteTableId {
        self.table
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryRouteLookupRejection {
    errno: NonZeroI32,
}

impl CanaryRouteLookupRejection {
    #[must_use]
    pub(crate) const fn errno(self) -> NonZeroI32 {
        self.errno
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryRouteLookupOutcome {
    Resolved(CanaryRouteLookupResult),
    Rejected(CanaryRouteLookupRejection),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteLookupDecodeErrorKind {
    DatagramTooLarge,
    UnexpectedSender,
    MissingMessage,
    InvalidFrame(NetlinkFrameErrorKind),
    MultipleMessages,
    MultipartResponse,
    UnexpectedSequence,
    UnexpectedPortId,
    UnexpectedControlMessage { message_type: u16 },
    UnexpectedMessageType { message_type: u16 },
    TruncatedRouteMessage,
    UnexpectedFamily,
    UnexpectedDestinationPrefixLength,
    InvalidAttribute(NetlinkAttributeErrorKind),
    InvalidAttributeFlags { attribute_type: u16 },
    DuplicateAttribute { attribute_type: u16 },
    MissingDestination,
    InvalidDestinationLength,
    UnexpectedDestination,
    MissingTable,
    InvalidTableLength,
    InconsistentTable,
    InvalidTable,
    InvalidUidLength,
    UnexpectedUid,
    InvalidMarkLength,
    UnexpectedMark,
    InvalidErrorFlags,
    TruncatedError,
    EmbeddedRequestMismatch,
    InvalidErrno,
    UnexpectedErrorPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RouteLookupDecodeError {
    kind: RouteLookupDecodeErrorKind,
    offset: usize,
}

impl RouteLookupDecodeError {
    const fn new(kind: RouteLookupDecodeErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    #[must_use]
    pub(crate) const fn kind(self) -> RouteLookupDecodeErrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }
}

impl fmt::Display for RouteLookupDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid canary route lookup response at byte {}: {:?}",
            self.offset, self.kind
        )
    }
}

impl Error for RouteLookupDecodeError {}

#[must_use]
pub(crate) fn encode_canary_route_lookup(
    lookup: CanaryRouteLookupRequest,
    sequence: NonZeroU32,
) -> EncodedCanaryRouteLookupRequest {
    let (family, prefix_length, destination, route_flags, expected_length) =
        match lookup.destination() {
            IpAddr::V4(destination) => (
                AF_INET,
                32,
                destination.octets().to_vec(),
                RTM_F_LOOKUP_TABLE,
                IPV4_ROUTE_LOOKUP_REQUEST_BYTES,
            ),
            IpAddr::V6(destination) => (
                AF_INET6,
                128,
                destination.octets().to_vec(),
                0,
                IPV6_ROUTE_LOOKUP_REQUEST_BYTES,
            ),
        };

    let mut bytes = Vec::with_capacity(expected_length);
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(&RTM_GETROUTE.to_ne_bytes());
    bytes.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    bytes.extend_from_slice(&sequence.get().to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());

    let mut route = [0_u8; ROUTE_MESSAGE_LENGTH];
    route[0] = family;
    route[1] = prefix_length;
    route[8..12].copy_from_slice(&route_flags.to_ne_bytes());
    bytes.extend_from_slice(&route);

    append_attribute(&mut bytes, RTA_DST, &destination);
    append_attribute(&mut bytes, RTA_IP_PROTO, &[IPPROTO_TCP]);
    append_attribute(
        &mut bytes,
        RTA_DPORT,
        &lookup.responder_port().get().to_be_bytes(),
    );
    append_attribute(&mut bytes, RTA_UID, &lookup.uid().get().to_ne_bytes());
    append_attribute(&mut bytes, RTA_MARK, &lookup.mark().to_ne_bytes());

    assert_eq!(
        bytes.len(),
        expected_length,
        "fixed route lookup request length"
    );
    bytes[..4].copy_from_slice(&(expected_length as u32).to_ne_bytes());
    EncodedCanaryRouteLookupRequest {
        bytes: bytes.into_boxed_slice(),
        sequence,
        lookup,
    }
}

pub(crate) fn decode_canary_route_lookup(
    datagram: &[u8],
    sender: PolicyRoutingAckSender,
    local_port_id: NonZeroU32,
    request: &EncodedCanaryRouteLookupRequest,
) -> Result<CanaryRouteLookupOutcome, RouteLookupDecodeError> {
    if datagram.len() > MAX_ROUTE_LOOKUP_RESPONSE_BYTES {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::DatagramTooLarge,
            0,
        ));
    }
    if !sender.is_kernel_unicast() {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::UnexpectedSender,
            0,
        ));
    }

    let mut messages = NetlinkMessageIter::new(datagram);
    let message = messages
        .next()
        .ok_or_else(|| RouteLookupDecodeError::new(RouteLookupDecodeErrorKind::MissingMessage, 0))?
        .map_err(|error| {
            RouteLookupDecodeError::new(
                RouteLookupDecodeErrorKind::InvalidFrame(error.kind()),
                error.offset(),
            )
        })?;
    if let Some(extra) = messages.next() {
        let extra = extra.map_err(|error| {
            RouteLookupDecodeError::new(
                RouteLookupDecodeErrorKind::InvalidFrame(error.kind()),
                error.offset(),
            )
        })?;
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::MultipleMessages,
            extra.offset(),
        ));
    }

    let header = message.header();
    if header.flags() & NLM_F_MULTI != 0 {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::MultipartResponse,
            message.offset() + 6,
        ));
    }
    if header.sequence() != request.sequence().get() {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::UnexpectedSequence,
            message.offset() + 8,
        ));
    }
    if header.port_id() != local_port_id.get() {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::UnexpectedPortId,
            message.offset() + 12,
        ));
    }

    match header.message_type() {
        RTM_NEWROUTE => decode_route(message.payload(), message.offset(), request),
        super::NLMSG_ERROR => {
            decode_rejection(message.payload(), header.flags(), message.offset(), request)
        }
        super::NLMSG_DONE | super::NLMSG_OVERRUN => Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::UnexpectedControlMessage {
                message_type: header.message_type(),
            },
            message.offset() + 4,
        )),
        message_type => Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::UnexpectedMessageType { message_type },
            message.offset() + 4,
        )),
    }
}

fn decode_route(
    payload: &[u8],
    message_offset: usize,
    request: &EncodedCanaryRouteLookupRequest,
) -> Result<CanaryRouteLookupOutcome, RouteLookupDecodeError> {
    let payload_offset = message_offset + NETLINK_HEADER_LENGTH;
    if payload.len() < ROUTE_MESSAGE_LENGTH {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::TruncatedRouteMessage,
            payload_offset,
        ));
    }

    let lookup = request.lookup();
    if payload[0] != family_byte(lookup.destination()) {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::UnexpectedFamily,
            payload_offset,
        ));
    }
    if payload[1] != maximum_prefix_length(lookup.destination()) {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::UnexpectedDestinationPrefixLength,
            payload_offset + 1,
        ));
    }

    let attributes_offset = payload_offset + ROUTE_MESSAGE_LENGTH;
    let mut destination = None;
    let mut table = None;
    let mut uid = None;
    let mut mark = None;
    for attribute in NetlinkAttributeIter::new(&payload[ROUTE_MESSAGE_LENGTH..], attributes_offset)
    {
        let attribute = attribute.map_err(|error| {
            RouteLookupDecodeError::new(
                RouteLookupDecodeErrorKind::InvalidAttribute(error.kind()),
                error.offset(),
            )
        })?;
        let attribute_type = attribute.attribute_type();
        if matches!(attribute_type, RTA_DST | RTA_TABLE | RTA_UID | RTA_MARK)
            && attribute.flags() != 0
        {
            return Err(RouteLookupDecodeError::new(
                RouteLookupDecodeErrorKind::InvalidAttributeFlags { attribute_type },
                attribute.offset() + 2,
            ));
        }
        match attribute_type {
            RTA_DST => {
                require_unseen(destination.is_none(), attribute_type, attribute.offset())?;
                let expected = destination_bytes(lookup.destination());
                if attribute.value().len() != expected.len() {
                    return Err(RouteLookupDecodeError::new(
                        RouteLookupDecodeErrorKind::InvalidDestinationLength,
                        attribute.value_offset(),
                    ));
                }
                if attribute.value() != expected.as_slice() {
                    return Err(RouteLookupDecodeError::new(
                        RouteLookupDecodeErrorKind::UnexpectedDestination,
                        attribute.value_offset(),
                    ));
                }
                destination = Some(attribute.offset());
            }
            RTA_TABLE => {
                require_unseen(table.is_none(), attribute_type, attribute.offset())?;
                if attribute.value().len() != size_of::<u32>() {
                    return Err(RouteLookupDecodeError::new(
                        RouteLookupDecodeErrorKind::InvalidTableLength,
                        attribute.value_offset(),
                    ));
                }
                table = Some((read_u32(attribute.value()), attribute.value_offset()));
            }
            RTA_UID => {
                require_unseen(uid.is_none(), attribute_type, attribute.offset())?;
                if attribute.value().len() != size_of::<u32>() {
                    return Err(RouteLookupDecodeError::new(
                        RouteLookupDecodeErrorKind::InvalidUidLength,
                        attribute.value_offset(),
                    ));
                }
                let echoed = read_u32(attribute.value());
                if echoed != lookup.uid().get() {
                    return Err(RouteLookupDecodeError::new(
                        RouteLookupDecodeErrorKind::UnexpectedUid,
                        attribute.value_offset(),
                    ));
                }
                uid = Some(attribute.offset());
            }
            RTA_MARK => {
                require_unseen(mark.is_none(), attribute_type, attribute.offset())?;
                if attribute.value().len() != size_of::<u32>() {
                    return Err(RouteLookupDecodeError::new(
                        RouteLookupDecodeErrorKind::InvalidMarkLength,
                        attribute.value_offset(),
                    ));
                }
                let echoed = read_u32(attribute.value());
                if echoed != lookup.mark() {
                    return Err(RouteLookupDecodeError::new(
                        RouteLookupDecodeErrorKind::UnexpectedMark,
                        attribute.value_offset(),
                    ));
                }
                mark = Some(attribute.offset());
            }
            _ => {}
        }
    }

    if destination.is_none() {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::MissingDestination,
            attributes_offset,
        ));
    }
    let table = reconcile_table(payload[4], table, payload_offset + 4)?;
    if table == 0 {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::InvalidTable,
            payload_offset + 4,
        ));
    }

    Ok(CanaryRouteLookupOutcome::Resolved(
        CanaryRouteLookupResult {
            table: RouteTableId::from_raw(table),
        },
    ))
}

fn decode_rejection(
    payload: &[u8],
    flags: u16,
    message_offset: usize,
    request: &EncodedCanaryRouteLookupRequest,
) -> Result<CanaryRouteLookupOutcome, RouteLookupDecodeError> {
    let payload_offset = message_offset + NETLINK_HEADER_LENGTH;
    if flags & !(NLM_F_CAPPED | NLM_F_ACK_TLVS) != 0 {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::InvalidErrorFlags,
            message_offset + 6,
        ));
    }
    if payload.len() < NLMSGERR_HEADER_LENGTH {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::TruncatedError,
            payload_offset,
        ));
    }
    if payload[4..NLMSGERR_HEADER_LENGTH] != request.bytes()[..NETLINK_HEADER_LENGTH] {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::EmbeddedRequestMismatch,
            payload_offset + 4,
        ));
    }

    let raw_error = read_i32(payload);
    let Some(errno) = raw_error.checked_neg().and_then(NonZeroI32::new) else {
        return Err(RouteLookupDecodeError::new(
            if raw_error == 0 {
                RouteLookupDecodeErrorKind::UnexpectedControlMessage {
                    message_type: super::NLMSG_ERROR,
                }
            } else {
                RouteLookupDecodeErrorKind::InvalidErrno
            },
            payload_offset,
        ));
    };
    if raw_error >= 0 || errno.get() > MAX_LINUX_ERRNO {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::InvalidErrno,
            payload_offset,
        ));
    }

    let attributes_start = if flags & NLM_F_CAPPED != 0 {
        NLMSGERR_HEADER_LENGTH
    } else {
        let embedded_length = read_u32(&payload[4..]) as usize;
        if embedded_length != request.bytes().len() {
            return Err(RouteLookupDecodeError::new(
                RouteLookupDecodeErrorKind::EmbeddedRequestMismatch,
                payload_offset + 4,
            ));
        }
        let echoed_end = 4_usize
            .checked_add(align4(embedded_length))
            .ok_or_else(|| {
                RouteLookupDecodeError::new(
                    RouteLookupDecodeErrorKind::EmbeddedRequestMismatch,
                    payload_offset + 4,
                )
            })?;
        if payload.len() < echoed_end || payload[4..4 + embedded_length] != request.bytes()[..] {
            return Err(RouteLookupDecodeError::new(
                RouteLookupDecodeErrorKind::EmbeddedRequestMismatch,
                payload_offset + 4,
            ));
        }
        echoed_end
    };

    let attributes = &payload[attributes_start..];
    if !attributes.is_empty() && flags & NLM_F_ACK_TLVS == 0 {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::UnexpectedErrorPayload,
            payload_offset + attributes_start,
        ));
    }
    for attribute in NetlinkAttributeIter::new(attributes, payload_offset + attributes_start) {
        attribute.map_err(|error| {
            RouteLookupDecodeError::new(
                RouteLookupDecodeErrorKind::InvalidAttribute(error.kind()),
                error.offset(),
            )
        })?;
    }

    Ok(CanaryRouteLookupOutcome::Rejected(
        CanaryRouteLookupRejection { errno },
    ))
}

fn reconcile_table(
    compact: u8,
    extended: Option<(u32, usize)>,
    compact_offset: usize,
) -> Result<u32, RouteLookupDecodeError> {
    let Some((extended, offset)) = extended else {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::MissingTable,
            compact_offset,
        ));
    };
    let agrees =
        u8::try_from(extended).map_or(compact == RT_TABLE_COMPAT, |value| value == compact);
    if !agrees {
        return Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::InconsistentTable,
            offset,
        ));
    }
    Ok(extended)
}

fn require_unseen(
    unseen: bool,
    attribute_type: u16,
    offset: usize,
) -> Result<(), RouteLookupDecodeError> {
    if unseen {
        Ok(())
    } else {
        Err(RouteLookupDecodeError::new(
            RouteLookupDecodeErrorKind::DuplicateAttribute { attribute_type },
            offset,
        ))
    }
}

fn append_attribute(bytes: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
    let length = NETLINK_ATTRIBUTE_HEADER_LENGTH + value.len();
    bytes.extend_from_slice(&(length as u16).to_ne_bytes());
    bytes.extend_from_slice(&attribute_type.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(align4(bytes.len()), 0);
}

fn destination_bytes(destination: IpAddr) -> Vec<u8> {
    match destination {
        IpAddr::V4(destination) => destination.octets().to_vec(),
        IpAddr::V6(destination) => destination.octets().to_vec(),
    }
}

const fn family_byte(destination: IpAddr) -> u8 {
    match destination {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    }
}

const fn maximum_prefix_length(destination: IpAddr) -> u8 {
    match destination {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes[..4].try_into().expect("validated u32 field"))
}

fn read_i32(bytes: &[u8]) -> i32 {
    i32::from_ne_bytes(bytes[..4].try_into().expect("validated i32 field"))
}

#[cfg(test)]
#[path = "route_lookup_tests.rs"]
mod tests;
