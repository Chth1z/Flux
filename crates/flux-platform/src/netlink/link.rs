use std::error::Error;
use std::fmt;

use flux_core::{
    InterfaceHardwareType, InterfaceIndex, InterfaceLinkFlags, InterfaceLinkKind,
    InterfaceLinkRecord, InterfaceName, InterfaceOperationalState,
};

use super::{
    NETLINK_HEADER_LENGTH, NLA_F_NESTED, NLA_F_NET_BYTEORDER, NLM_F_DUMP_INTR, NLMSG_DONE,
    NLMSG_ERROR, NLMSG_OVERRUN, NetlinkAttributeError, NetlinkAttributeErrorKind,
    NetlinkAttributeIter, NetlinkDoneError, NetlinkDoneErrorKind, NetlinkFrameError,
    NetlinkFrameErrorKind, NetlinkMessageHeader, NetlinkMessageIter, validate_done_payload,
};

const INTERFACE_INFORMATION_MESSAGE_LENGTH: usize = 16;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const AF_UNSPEC: u8 = 0;

const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKINFO: u16 = 18;
const IFLA_CARRIER: u16 = 33;

const IFLA_INFO_KIND: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InterfaceLinkEvent {
    Upsert(InterfaceLinkRecord),
    Remove(InterfaceIndex),
}

impl InterfaceLinkEvent {
    #[must_use]
    pub(crate) const fn interface_index(&self) -> InterfaceIndex {
        match self {
            Self::Upsert(record) => record.interface_index(),
            Self::Remove(interface_index) => *interface_index,
        }
    }

    #[must_use]
    pub(crate) const fn record(&self) -> Option<&InterfaceLinkRecord> {
        match self {
            Self::Upsert(record) => Some(record),
            Self::Remove(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinkEventDecodeErrorKind {
    TruncatedHeader,
    InvalidMessageLength,
    MissingMessagePadding,
    TruncatedLinkMessage,
    InvalidAttributeLength,
    MissingAttributePadding,
    InvalidAttributeFlags,
    InvalidInterfaceIndex,
    MissingInterfaceName,
    InvalidInterfaceName,
    InvalidLinkKind,
    InvalidMtuLength,
    InvalidOperationalStateLength,
    InvalidCarrierLength,
    InvalidCarrierValue,
    DuplicateSemanticAttribute,
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
pub(crate) struct LinkEventDecodeError {
    kind: LinkEventDecodeErrorKind,
    offset: usize,
}

impl LinkEventDecodeError {
    const fn new(kind: LinkEventDecodeErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    #[must_use]
    pub(crate) const fn kind(self) -> LinkEventDecodeErrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }
}

impl From<NetlinkFrameError> for LinkEventDecodeError {
    fn from(error: NetlinkFrameError) -> Self {
        Self::new(
            match error.kind() {
                NetlinkFrameErrorKind::TruncatedHeader => LinkEventDecodeErrorKind::TruncatedHeader,
                NetlinkFrameErrorKind::InvalidMessageLength => {
                    LinkEventDecodeErrorKind::InvalidMessageLength
                }
                NetlinkFrameErrorKind::MissingMessagePadding => {
                    LinkEventDecodeErrorKind::MissingMessagePadding
                }
            },
            error.offset(),
        )
    }
}

impl From<NetlinkAttributeError> for LinkEventDecodeError {
    fn from(error: NetlinkAttributeError) -> Self {
        Self::new(
            match error.kind() {
                NetlinkAttributeErrorKind::InvalidAttributeLength => {
                    LinkEventDecodeErrorKind::InvalidAttributeLength
                }
                NetlinkAttributeErrorKind::MissingAttributePadding => {
                    LinkEventDecodeErrorKind::MissingAttributePadding
                }
                NetlinkAttributeErrorKind::InvalidAttributeFlags => {
                    LinkEventDecodeErrorKind::InvalidAttributeFlags
                }
            },
            error.offset(),
        )
    }
}

impl From<NetlinkDoneError> for LinkEventDecodeError {
    fn from(error: NetlinkDoneError) -> Self {
        Self::new(
            match error.kind() {
                NetlinkDoneErrorKind::InvalidPayload => {
                    LinkEventDecodeErrorKind::InvalidDonePayload
                }
                NetlinkDoneErrorKind::ErrorStatus => LinkEventDecodeErrorKind::DoneErrorStatus,
            },
            error.offset(),
        )
    }
}

impl fmt::Display for LinkEventDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid rtnetlink link datagram at byte {}: {}",
            self.offset,
            match self.kind {
                LinkEventDecodeErrorKind::TruncatedHeader => "truncated netlink header",
                LinkEventDecodeErrorKind::InvalidMessageLength => "invalid netlink message length",
                LinkEventDecodeErrorKind::MissingMessagePadding => {
                    "missing aligned netlink message padding"
                }
                LinkEventDecodeErrorKind::TruncatedLinkMessage => {
                    "truncated interface-information message"
                }
                LinkEventDecodeErrorKind::InvalidAttributeLength => {
                    "invalid netlink attribute length"
                }
                LinkEventDecodeErrorKind::MissingAttributePadding => {
                    "missing aligned netlink attribute padding"
                }
                LinkEventDecodeErrorKind::InvalidAttributeFlags => {
                    "recognized link attribute carries incompatible flags"
                }
                LinkEventDecodeErrorKind::InvalidInterfaceIndex => {
                    "interface-information message has an invalid interface index"
                }
                LinkEventDecodeErrorKind::MissingInterfaceName => {
                    "link update has no primary interface name"
                }
                LinkEventDecodeErrorKind::InvalidInterfaceName => {
                    "link interface name is invalid"
                }
                LinkEventDecodeErrorKind::InvalidLinkKind => "link kind is invalid",
                LinkEventDecodeErrorKind::InvalidMtuLength => {
                    "IFLA_MTU must contain exactly one u32"
                }
                LinkEventDecodeErrorKind::InvalidOperationalStateLength => {
                    "IFLA_OPERSTATE must contain exactly one u8"
                }
                LinkEventDecodeErrorKind::InvalidCarrierLength => {
                    "IFLA_CARRIER must contain exactly one u8"
                }
                LinkEventDecodeErrorKind::InvalidCarrierValue => {
                    "IFLA_CARRIER must be zero or one"
                }
                LinkEventDecodeErrorKind::DuplicateSemanticAttribute => {
                    "duplicate semantic link attribute"
                }
                LinkEventDecodeErrorKind::NetlinkOverrun => "netlink reported message overrun",
                LinkEventDecodeErrorKind::NetlinkError => "netlink returned NLMSG_ERROR",
                LinkEventDecodeErrorKind::InterruptedDump => {
                    "netlink message reports an interrupted dump"
                }
                LinkEventDecodeErrorKind::MixedSequence => {
                    "netlink datagram contains mixed sequence numbers"
                }
                LinkEventDecodeErrorKind::DuplicateDone => {
                    "netlink datagram contains more than one NLMSG_DONE"
                }
                LinkEventDecodeErrorKind::MessageAfterDone => {
                    "netlink datagram contains a message after NLMSG_DONE"
                }
                LinkEventDecodeErrorKind::InvalidDonePayload => {
                    "NLMSG_DONE payload or extended-ack attributes are malformed"
                }
                LinkEventDecodeErrorKind::DoneErrorStatus => {
                    "NLMSG_DONE reports a nonzero error status"
                }
            }
        )
    }
}

impl Error for LinkEventDecodeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinkDatagram {
    sequence: Option<u32>,
    events: Vec<InterfaceLinkEvent>,
    completion: Option<NetlinkMessageHeader>,
}

impl LinkDatagram {
    #[must_use]
    pub(crate) const fn sequence(&self) -> Option<u32> {
        self.sequence
    }

    #[must_use]
    pub(crate) fn events(&self) -> &[InterfaceLinkEvent] {
        &self.events
    }

    #[must_use]
    pub(crate) const fn completion(&self) -> Option<NetlinkMessageHeader> {
        self.completion
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RtnetlinkLinkEventDecoder;

impl RtnetlinkLinkEventDecoder {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }

    pub(crate) fn decode_datagram(
        &self,
        datagram: &[u8],
    ) -> Result<LinkDatagram, LinkEventDecodeError> {
        let mut sequence = None;
        let mut events = Vec::new();
        let mut completion = None;

        for message in NetlinkMessageIter::new(datagram) {
            let message = message.map_err(LinkEventDecodeError::from)?;
            let header = message.header();
            if sequence.is_some_and(|expected| expected != header.sequence()) {
                return Err(LinkEventDecodeError::new(
                    LinkEventDecodeErrorKind::MixedSequence,
                    message.offset(),
                ));
            }
            sequence.get_or_insert(header.sequence());

            if completion.is_some() {
                return Err(LinkEventDecodeError::new(
                    if header.message_type() == NLMSG_DONE {
                        LinkEventDecodeErrorKind::DuplicateDone
                    } else {
                        LinkEventDecodeErrorKind::MessageAfterDone
                    },
                    message.offset(),
                ));
            }

            if header.flags() & NLM_F_DUMP_INTR != 0 {
                return Err(LinkEventDecodeError::new(
                    LinkEventDecodeErrorKind::InterruptedDump,
                    message.offset(),
                ));
            }

            match header.message_type() {
                NLMSG_OVERRUN => {
                    return Err(LinkEventDecodeError::new(
                        LinkEventDecodeErrorKind::NetlinkOverrun,
                        message.offset(),
                    ));
                }
                NLMSG_ERROR => {
                    return Err(LinkEventDecodeError::new(
                        LinkEventDecodeErrorKind::NetlinkError,
                        message.offset(),
                    ));
                }
                NLMSG_DONE => {
                    validate_done_payload(
                        message.payload(),
                        header.flags(),
                        message.offset() + NETLINK_HEADER_LENGTH,
                    )
                    .map_err(LinkEventDecodeError::from)?;
                    completion = Some(header);
                }
                RTM_NEWLINK | RTM_DELLINK => {
                    if let Some(event) = self.decode_link_message(
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

        Ok(LinkDatagram {
            sequence,
            events,
            completion,
        })
    }

    fn decode_link_message(
        &self,
        message_type: u16,
        body: &[u8],
        body_offset: usize,
    ) -> Result<Option<InterfaceLinkEvent>, LinkEventDecodeError> {
        if body.len() < INTERFACE_INFORMATION_MESSAGE_LENGTH {
            return Err(LinkEventDecodeError::new(
                LinkEventDecodeErrorKind::TruncatedLinkMessage,
                body_offset,
            ));
        }

        let attributes = &body[INTERFACE_INFORMATION_MESSAGE_LENGTH..];
        let attributes_offset = body_offset + INTERFACE_INFORMATION_MESSAGE_LENGTH;
        if body[0] != AF_UNSPEC {
            validate_attribute_framing(attributes, attributes_offset)?;
            return Ok(None);
        }

        let raw_interface_index = read_i32(&body[4..]);
        let interface_index = positive_interface_index(raw_interface_index).ok_or_else(|| {
            LinkEventDecodeError::new(
                LinkEventDecodeErrorKind::InvalidInterfaceIndex,
                body_offset + 4,
            )
        })?;
        let decoded = decode_link_attributes(attributes, attributes_offset)?;
        if message_type == RTM_DELLINK {
            return Ok(Some(InterfaceLinkEvent::Remove(interface_index)));
        }

        let name = decoded.name.ok_or_else(|| {
            LinkEventDecodeError::new(
                LinkEventDecodeErrorKind::MissingInterfaceName,
                attributes_offset,
            )
        })?;
        let mut record = InterfaceLinkRecord::new(
            interface_index,
            name,
            InterfaceHardwareType::from_raw(read_u16(&body[2..])),
            InterfaceLinkFlags::from_bits(read_u32(&body[8..])),
        );
        if let Some(mtu) = decoded.mtu {
            record = record.with_mtu(mtu);
        }
        if let Some(state) = decoded.operational_state {
            record = record.with_operational_state(state);
        }
        if let Some(carrier) = decoded.carrier {
            record = record.with_carrier(carrier);
        }
        if let Some(kind) = decoded.kind {
            record = record.with_kind(kind);
        }

        Ok(Some(InterfaceLinkEvent::Upsert(record)))
    }
}

#[derive(Default)]
struct DecodedLinkAttributes {
    name: Option<InterfaceName>,
    mtu: Option<u32>,
    operational_state: Option<InterfaceOperationalState>,
    carrier: Option<bool>,
    kind: Option<InterfaceLinkKind>,
    saw_link_info: bool,
}

fn decode_link_attributes(
    attributes: &[u8],
    attributes_offset: usize,
) -> Result<DecodedLinkAttributes, LinkEventDecodeError> {
    let mut decoded = DecodedLinkAttributes::default();
    for attribute in NetlinkAttributeIter::new(attributes, attributes_offset) {
        let attribute = attribute.map_err(LinkEventDecodeError::from)?;
        match attribute.attribute_type() {
            IFLA_IFNAME => {
                require_plain_attribute(attribute.flags(), attribute.offset())?;
                if decoded.name.is_some() {
                    return Err(duplicate_attribute(attribute.offset()));
                }
                let value = decode_string(attribute.value()).ok_or_else(|| {
                    LinkEventDecodeError::new(
                        LinkEventDecodeErrorKind::InvalidInterfaceName,
                        attribute.value_offset(),
                    )
                })?;
                decoded.name = Some(InterfaceName::new(value).ok_or_else(|| {
                    LinkEventDecodeError::new(
                        LinkEventDecodeErrorKind::InvalidInterfaceName,
                        attribute.value_offset(),
                    )
                })?);
            }
            IFLA_MTU => {
                require_plain_attribute(attribute.flags(), attribute.offset())?;
                if decoded.mtu.is_some() {
                    return Err(duplicate_attribute(attribute.offset()));
                }
                require_length(
                    attribute.value(),
                    std::mem::size_of::<u32>(),
                    LinkEventDecodeErrorKind::InvalidMtuLength,
                    attribute.value_offset(),
                )?;
                decoded.mtu = Some(read_u32(attribute.value()));
            }
            IFLA_OPERSTATE => {
                require_plain_attribute(attribute.flags(), attribute.offset())?;
                if decoded.operational_state.is_some() {
                    return Err(duplicate_attribute(attribute.offset()));
                }
                require_length(
                    attribute.value(),
                    1,
                    LinkEventDecodeErrorKind::InvalidOperationalStateLength,
                    attribute.value_offset(),
                )?;
                decoded.operational_state =
                    Some(InterfaceOperationalState::from_raw(attribute.value()[0]));
            }
            IFLA_LINKINFO => {
                require_nested_attribute(attribute.flags(), attribute.offset())?;
                if decoded.saw_link_info {
                    return Err(duplicate_attribute(attribute.offset()));
                }
                decoded.saw_link_info = true;
                decoded.kind = decode_link_kind(attribute.value(), attribute.value_offset())?;
            }
            IFLA_CARRIER => {
                require_plain_attribute(attribute.flags(), attribute.offset())?;
                if decoded.carrier.is_some() {
                    return Err(duplicate_attribute(attribute.offset()));
                }
                require_length(
                    attribute.value(),
                    1,
                    LinkEventDecodeErrorKind::InvalidCarrierLength,
                    attribute.value_offset(),
                )?;
                decoded.carrier = Some(match attribute.value()[0] {
                    0 => false,
                    1 => true,
                    _ => {
                        return Err(LinkEventDecodeError::new(
                            LinkEventDecodeErrorKind::InvalidCarrierValue,
                            attribute.value_offset(),
                        ));
                    }
                });
            }
            _ => {}
        }
    }
    Ok(decoded)
}

fn decode_link_kind(
    attributes: &[u8],
    attributes_offset: usize,
) -> Result<Option<InterfaceLinkKind>, LinkEventDecodeError> {
    let mut kind = None;
    for attribute in NetlinkAttributeIter::new(attributes, attributes_offset) {
        let attribute = attribute.map_err(LinkEventDecodeError::from)?;
        if attribute.attribute_type() != IFLA_INFO_KIND {
            continue;
        }
        require_plain_attribute(attribute.flags(), attribute.offset())?;
        if kind.is_some() {
            return Err(duplicate_attribute(attribute.offset()));
        }
        let value = decode_string(attribute.value()).ok_or_else(|| {
            LinkEventDecodeError::new(
                LinkEventDecodeErrorKind::InvalidLinkKind,
                attribute.value_offset(),
            )
        })?;
        kind = Some(InterfaceLinkKind::new(value).ok_or_else(|| {
            LinkEventDecodeError::new(
                LinkEventDecodeErrorKind::InvalidLinkKind,
                attribute.value_offset(),
            )
        })?);
    }
    Ok(kind)
}

fn validate_attribute_framing(
    attributes: &[u8],
    attributes_offset: usize,
) -> Result<(), LinkEventDecodeError> {
    for attribute in NetlinkAttributeIter::new(attributes, attributes_offset) {
        let _ = attribute.map_err(LinkEventDecodeError::from)?;
    }
    Ok(())
}

fn require_plain_attribute(flags: u16, offset: usize) -> Result<(), LinkEventDecodeError> {
    if flags == 0 {
        Ok(())
    } else {
        Err(LinkEventDecodeError::new(
            LinkEventDecodeErrorKind::InvalidAttributeFlags,
            offset,
        ))
    }
}

fn require_nested_attribute(flags: u16, offset: usize) -> Result<(), LinkEventDecodeError> {
    if flags & NLA_F_NET_BYTEORDER == 0 && flags & !NLA_F_NESTED == 0 {
        Ok(())
    } else {
        Err(LinkEventDecodeError::new(
            LinkEventDecodeErrorKind::InvalidAttributeFlags,
            offset,
        ))
    }
}

fn require_length(
    value: &[u8],
    expected: usize,
    kind: LinkEventDecodeErrorKind,
    offset: usize,
) -> Result<(), LinkEventDecodeError> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(LinkEventDecodeError::new(kind, offset))
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

fn duplicate_attribute(offset: usize) -> LinkEventDecodeError {
    LinkEventDecodeError::new(LinkEventDecodeErrorKind::DuplicateSemanticAttribute, offset)
}

fn positive_interface_index(value: i32) -> Option<InterfaceIndex> {
    u32::try_from(value).ok().and_then(InterfaceIndex::new)
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes[..2].try_into().expect("validated two-byte field"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes[..4].try_into().expect("validated four-byte field"))
}

fn read_i32(bytes: &[u8]) -> i32 {
    i32::from_ne_bytes(bytes[..4].try_into().expect("validated four-byte field"))
}

#[cfg(test)]
#[path = "link_tests.rs"]
mod tests;
