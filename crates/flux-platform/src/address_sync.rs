use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use flux_core::{InterfaceAddressFlags, InterfaceAddressRecord, InterfaceIndex};

use crate::netlink::{
    NETLINK_HEADER_LENGTH, NLM_F_DUMP_INTR, NLMSG_DONE, NLMSG_ERROR, NLMSG_OVERRUN,
    NetlinkDoneError, NetlinkDoneErrorKind, NetlinkFrameError, NetlinkFrameErrorKind,
    NetlinkMessageHeader, NetlinkMessageIter, align4, validate_done_payload,
};

const INTERFACE_ADDRESS_MESSAGE_LENGTH: usize = 8;
const NETLINK_ATTRIBUTE_HEADER_LENGTH: usize = 4;

const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;

const IFA_F_TEMPORARY: u32 = 0x01;
const IFA_F_OPTIMISTIC: u32 = 0x04;
const IFA_F_DAD_FAILED: u32 = 0x08;
const IFA_F_DEPRECATED: u32 = 0x20;
const IFA_F_TENTATIVE: u32 = 0x40;
const IFA_F_MANAGE_TEMPORARY_ADDRESSES: u32 = 0x100;
const IFA_F_STABLE_PRIVACY: u32 = 0x800;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressEventKind {
    Add,
    Remove,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InterfaceAddressEvent {
    kind: AddressEventKind,
    record: InterfaceAddressRecord,
}

impl InterfaceAddressEvent {
    #[must_use]
    pub(crate) const fn kind(self) -> AddressEventKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn record(self) -> InterfaceAddressRecord {
        self.record
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AddressEventPolicy {
    ipv6_enabled: bool,
    ignored_flags: InterfaceAddressFlags,
    ignored_addresses: BTreeSet<IpAddr>,
    ignored_prefixes: Vec<IpPrefix>,
}

impl AddressEventPolicy {
    #[must_use]
    pub(crate) const fn new(ipv6_enabled: bool) -> Self {
        Self {
            ipv6_enabled,
            ignored_flags: InterfaceAddressFlags::from_bits(0),
            ignored_addresses: BTreeSet::new(),
            ignored_prefixes: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) fn with_ignored_flags(mut self, flags: InterfaceAddressFlags) -> Self {
        self.ignored_flags = flags;
        self
    }

    #[must_use]
    pub(crate) fn with_ignored_addresses(
        mut self,
        addresses: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        self.ignored_addresses
            .extend(addresses.into_iter().map(normalize_exact_address));
        self
    }

    pub(crate) fn with_ignored_prefixes(
        mut self,
        prefixes: impl IntoIterator<Item = (IpAddr, u8)>,
    ) -> Result<Self, AddressEventPolicyError> {
        for (address, prefix_length) in prefixes {
            self.ignored_prefixes
                .push(IpPrefix::new(address, prefix_length)?);
        }
        Ok(self)
    }

    fn ignores_address(&self, address: IpAddr) -> bool {
        self.ignored_addresses.contains(&address)
            || self
                .ignored_prefixes
                .iter()
                .any(|prefix| prefix.contains(address))
    }

    fn removes_for_flags(&self, flags: InterfaceAddressFlags) -> bool {
        self.ignored_flags.bits() & flags.bits() != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressEventPolicyError {
    InvalidPrefixLength { address: IpAddr, prefix_length: u8 },
    UnsupportedMappedPrefix { address: IpAddr, prefix_length: u8 },
}

impl fmt::Display for AddressEventPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefixLength {
                address,
                prefix_length,
            } => write!(
                formatter,
                "prefix length {prefix_length} is invalid for address {address}"
            ),
            Self::UnsupportedMappedPrefix {
                address,
                prefix_length,
            } => write!(
                formatter,
                "IPv4-mapped address {address} cannot use prefix length {prefix_length} below 96"
            ),
        }
    }
}

impl Error for AddressEventPolicyError {}

#[derive(Clone, Copy, Debug)]
enum IpPrefix {
    V4 { network: u32, prefix_length: u8 },
    V6 { network: u128, prefix_length: u8 },
}

impl IpPrefix {
    fn new(address: IpAddr, prefix_length: u8) -> Result<Self, AddressEventPolicyError> {
        let original = address;
        let (address, prefix_length) = normalize_configured_prefix(address, prefix_length)?;
        match address {
            IpAddr::V4(address) if prefix_length <= 32 => Ok(Self::V4 {
                network: mask_v4(u32::from(address), prefix_length),
                prefix_length,
            }),
            IpAddr::V6(address) if prefix_length <= 128 => Ok(Self::V6 {
                network: mask_v6(u128::from_be_bytes(address.octets()), prefix_length),
                prefix_length,
            }),
            _ => Err(AddressEventPolicyError::InvalidPrefixLength {
                address: original,
                prefix_length,
            }),
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (
                Self::V4 {
                    network,
                    prefix_length,
                },
                IpAddr::V4(address),
            ) => mask_v4(u32::from(address), prefix_length) == network,
            (
                Self::V6 {
                    network,
                    prefix_length,
                },
                IpAddr::V6(address),
            ) => mask_v6(u128::from_be_bytes(address.octets()), prefix_length) == network,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressEventDecodeErrorKind {
    TruncatedHeader,
    InvalidMessageLength,
    MissingMessagePadding,
    TruncatedAddressMessage,
    InvalidAttributeLength,
    MissingAttributePadding,
    MissingAddress,
    InvalidAddressLength,
    InvalidFlagsLength,
    DuplicateSemanticAttribute,
    InvalidInterfaceIndex,
    InvalidPrefixLength,
    UnsupportedMappedPrefix,
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
pub(crate) struct AddressEventDecodeError {
    kind: AddressEventDecodeErrorKind,
    offset: usize,
}

impl AddressEventDecodeError {
    const fn new(kind: AddressEventDecodeErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    #[must_use]
    pub(crate) const fn kind(self) -> AddressEventDecodeErrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }
}

impl From<NetlinkFrameError> for AddressEventDecodeError {
    fn from(error: NetlinkFrameError) -> Self {
        Self::new(
            match error.kind() {
                NetlinkFrameErrorKind::TruncatedHeader => {
                    AddressEventDecodeErrorKind::TruncatedHeader
                }
                NetlinkFrameErrorKind::InvalidMessageLength => {
                    AddressEventDecodeErrorKind::InvalidMessageLength
                }
                NetlinkFrameErrorKind::MissingMessagePadding => {
                    AddressEventDecodeErrorKind::MissingMessagePadding
                }
            },
            error.offset(),
        )
    }
}

impl From<NetlinkDoneError> for AddressEventDecodeError {
    fn from(error: NetlinkDoneError) -> Self {
        Self::new(
            match error.kind() {
                NetlinkDoneErrorKind::InvalidPayload => {
                    AddressEventDecodeErrorKind::InvalidDonePayload
                }
                NetlinkDoneErrorKind::ErrorStatus => AddressEventDecodeErrorKind::DoneErrorStatus,
            },
            error.offset(),
        )
    }
}

impl fmt::Display for AddressEventDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid rtnetlink address datagram at byte {}: {}",
            self.offset,
            match self.kind {
                AddressEventDecodeErrorKind::TruncatedHeader => "truncated netlink header",
                AddressEventDecodeErrorKind::InvalidMessageLength => {
                    "invalid netlink message length"
                }
                AddressEventDecodeErrorKind::MissingMessagePadding => {
                    "missing aligned netlink message padding"
                }
                AddressEventDecodeErrorKind::TruncatedAddressMessage => {
                    "truncated interface-address message"
                }
                AddressEventDecodeErrorKind::InvalidAttributeLength => {
                    "invalid netlink attribute length"
                }
                AddressEventDecodeErrorKind::MissingAttributePadding => {
                    "missing aligned netlink attribute padding"
                }
                AddressEventDecodeErrorKind::MissingAddress => {
                    "interface-address message has no address attribute"
                }
                AddressEventDecodeErrorKind::InvalidAddressLength => {
                    "interface-address attribute has the wrong length for its family"
                }
                AddressEventDecodeErrorKind::InvalidFlagsLength => {
                    "IFA_FLAGS attribute must contain exactly one u32"
                }
                AddressEventDecodeErrorKind::DuplicateSemanticAttribute => {
                    "duplicate semantic interface-address attribute"
                }
                AddressEventDecodeErrorKind::InvalidInterfaceIndex => {
                    "interface-address message has interface index zero"
                }
                AddressEventDecodeErrorKind::InvalidPrefixLength => {
                    "interface-address prefix length is invalid for its normalized address"
                }
                AddressEventDecodeErrorKind::UnsupportedMappedPrefix => {
                    "IPv4-mapped address prefix is below the 96-bit mapping boundary"
                }
                AddressEventDecodeErrorKind::NetlinkOverrun => "netlink reported message overrun",
                AddressEventDecodeErrorKind::NetlinkError => "netlink returned NLMSG_ERROR",
                AddressEventDecodeErrorKind::InterruptedDump => {
                    "netlink message reports an interrupted dump"
                }
                AddressEventDecodeErrorKind::MixedSequence => {
                    "netlink datagram contains mixed sequence numbers"
                }
                AddressEventDecodeErrorKind::DuplicateDone => {
                    "netlink datagram contains more than one NLMSG_DONE"
                }
                AddressEventDecodeErrorKind::MessageAfterDone => {
                    "netlink datagram contains a message after NLMSG_DONE"
                }
                AddressEventDecodeErrorKind::InvalidDonePayload => {
                    "NLMSG_DONE payload or extended-ack attributes are malformed"
                }
                AddressEventDecodeErrorKind::DoneErrorStatus => {
                    "NLMSG_DONE reports a nonzero error status"
                }
            }
        )
    }
}

impl Error for AddressEventDecodeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AddressDatagram {
    sequence: Option<u32>,
    events: Vec<InterfaceAddressEvent>,
    completion: Option<NetlinkMessageHeader>,
}

impl AddressDatagram {
    #[must_use]
    pub(crate) const fn sequence(&self) -> Option<u32> {
        self.sequence
    }

    #[must_use]
    pub(crate) fn events(&self) -> &[InterfaceAddressEvent] {
        &self.events
    }

    #[must_use]
    pub(crate) const fn completion(&self) -> Option<NetlinkMessageHeader> {
        self.completion
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RtnetlinkAddressEventDecoder {
    policy: AddressEventPolicy,
}

impl RtnetlinkAddressEventDecoder {
    #[must_use]
    pub(crate) const fn new(policy: AddressEventPolicy) -> Self {
        Self { policy }
    }

    pub(crate) fn decode_datagram(
        &self,
        datagram: &[u8],
    ) -> Result<AddressDatagram, AddressEventDecodeError> {
        let mut sequence = None;
        let mut events = Vec::new();
        let mut completion = None;

        for message in NetlinkMessageIter::new(datagram) {
            let message = message.map_err(AddressEventDecodeError::from)?;
            let header = message.header();
            if sequence.is_some_and(|expected| expected != header.sequence()) {
                return Err(AddressEventDecodeError::new(
                    AddressEventDecodeErrorKind::MixedSequence,
                    message.offset(),
                ));
            }
            sequence.get_or_insert(header.sequence());

            if completion.is_some() {
                return Err(AddressEventDecodeError::new(
                    if header.message_type() == NLMSG_DONE {
                        AddressEventDecodeErrorKind::DuplicateDone
                    } else {
                        AddressEventDecodeErrorKind::MessageAfterDone
                    },
                    message.offset(),
                ));
            }

            if header.flags() & NLM_F_DUMP_INTR != 0 {
                return Err(AddressEventDecodeError::new(
                    AddressEventDecodeErrorKind::InterruptedDump,
                    message.offset(),
                ));
            }

            match header.message_type() {
                NLMSG_OVERRUN => {
                    return Err(AddressEventDecodeError::new(
                        AddressEventDecodeErrorKind::NetlinkOverrun,
                        message.offset(),
                    ));
                }
                NLMSG_ERROR => {
                    return Err(AddressEventDecodeError::new(
                        AddressEventDecodeErrorKind::NetlinkError,
                        message.offset(),
                    ));
                }
                NLMSG_DONE => {
                    validate_done_payload(
                        message.payload(),
                        header.flags(),
                        message.offset() + NETLINK_HEADER_LENGTH,
                    )
                    .map_err(AddressEventDecodeError::from)?;
                    if completion.replace(header).is_some() {
                        return Err(AddressEventDecodeError::new(
                            AddressEventDecodeErrorKind::DuplicateDone,
                            message.offset(),
                        ));
                    }
                }
                RTM_NEWADDR | RTM_DELADDR => {
                    if let Some(event) = self.decode_address_message(
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

        Ok(AddressDatagram {
            sequence,
            events,
            completion,
        })
    }

    fn decode_address_message(
        &self,
        message_type: u16,
        body: &[u8],
        body_offset: usize,
    ) -> Result<Option<InterfaceAddressEvent>, AddressEventDecodeError> {
        if body.len() < INTERFACE_ADDRESS_MESSAGE_LENGTH {
            return Err(AddressEventDecodeError::new(
                AddressEventDecodeErrorKind::TruncatedAddressMessage,
                body_offset,
            ));
        }

        let family = body[0];
        if !matches!(family, AF_INET | AF_INET6) {
            return Ok(None);
        }
        let family_is_enabled = family != AF_INET6 || self.policy.ipv6_enabled;

        let attributes = &body[INTERFACE_ADDRESS_MESSAGE_LENGTH..];
        let mut peer_address = None;
        let mut local_address = None;
        let mut extended_flags = None;
        let mut attribute_offset = 0;
        while attribute_offset < attributes.len() {
            let remaining = &attributes[attribute_offset..];
            let attribute_header_offset =
                body_offset + INTERFACE_ADDRESS_MESSAGE_LENGTH + attribute_offset;
            if remaining.len() < NETLINK_ATTRIBUTE_HEADER_LENGTH {
                return Err(AddressEventDecodeError::new(
                    AddressEventDecodeErrorKind::InvalidAttributeLength,
                    attribute_header_offset,
                ));
            }
            let attribute_length = read_u16(remaining) as usize;
            if attribute_length < NETLINK_ATTRIBUTE_HEADER_LENGTH
                || attribute_length > remaining.len()
            {
                return Err(AddressEventDecodeError::new(
                    AddressEventDecodeErrorKind::InvalidAttributeLength,
                    attribute_header_offset,
                ));
            }
            let aligned_length = align4(attribute_length);
            if aligned_length > remaining.len() {
                return Err(AddressEventDecodeError::new(
                    AddressEventDecodeErrorKind::MissingAttributePadding,
                    attribute_header_offset,
                ));
            }
            let attribute_type = read_u16(&remaining[2..]);
            let value = &remaining[NETLINK_ATTRIBUTE_HEADER_LENGTH..attribute_length];
            let value_offset = attribute_header_offset + NETLINK_ATTRIBUTE_HEADER_LENGTH;
            match attribute_type {
                IFA_ADDRESS if peer_address.is_some() => {
                    return Err(AddressEventDecodeError::new(
                        AddressEventDecodeErrorKind::DuplicateSemanticAttribute,
                        attribute_header_offset,
                    ));
                }
                IFA_ADDRESS if value.len() != expected_address_length(family) => {
                    return Err(AddressEventDecodeError::new(
                        AddressEventDecodeErrorKind::InvalidAddressLength,
                        value_offset,
                    ));
                }
                IFA_ADDRESS => peer_address = Some((value, value_offset)),
                IFA_LOCAL if local_address.is_some() => {
                    return Err(AddressEventDecodeError::new(
                        AddressEventDecodeErrorKind::DuplicateSemanticAttribute,
                        attribute_header_offset,
                    ));
                }
                IFA_LOCAL if value.len() != expected_address_length(family) => {
                    return Err(AddressEventDecodeError::new(
                        AddressEventDecodeErrorKind::InvalidAddressLength,
                        value_offset,
                    ));
                }
                IFA_LOCAL => local_address = Some((value, value_offset)),
                IFA_FLAGS if value.len() != std::mem::size_of::<u32>() => {
                    return Err(AddressEventDecodeError::new(
                        AddressEventDecodeErrorKind::InvalidFlagsLength,
                        value_offset,
                    ));
                }
                IFA_FLAGS if extended_flags.is_some() => {
                    return Err(AddressEventDecodeError::new(
                        AddressEventDecodeErrorKind::DuplicateSemanticAttribute,
                        attribute_header_offset,
                    ));
                }
                IFA_FLAGS => extended_flags = Some(read_u32(value)),
                _ => {}
            }
            attribute_offset += aligned_length;
        }

        let raw_address = if family == AF_INET {
            local_address.or(peer_address)
        } else {
            peer_address
        };
        let Some((raw_address, raw_address_offset)) = raw_address else {
            return Err(AddressEventDecodeError::new(
                AddressEventDecodeErrorKind::MissingAddress,
                body_offset + INTERFACE_ADDRESS_MESSAGE_LENGTH,
            ));
        };
        let expected_address_length = expected_address_length(family);
        if raw_address.len() != expected_address_length {
            return Err(AddressEventDecodeError::new(
                AddressEventDecodeErrorKind::InvalidAddressLength,
                raw_address_offset,
            ));
        }
        let Some(address) = decode_address(family, raw_address) else {
            unreachable!("address length and family were validated above");
        };
        let prefix_length = body[1];
        let (address, prefix_length) =
            normalize_event_address(address, prefix_length).map_err(|()| {
                AddressEventDecodeError::new(
                    AddressEventDecodeErrorKind::UnsupportedMappedPrefix,
                    body_offset + 1,
                )
            })?;
        let interface_index = InterfaceIndex::new(read_u32(&body[4..])).ok_or_else(|| {
            AddressEventDecodeError::new(
                AddressEventDecodeErrorKind::InvalidInterfaceIndex,
                body_offset + 4,
            )
        })?;
        let flags =
            InterfaceAddressFlags::from_bits(extended_flags.unwrap_or_else(|| u32::from(body[2])));
        let record = InterfaceAddressRecord::new(interface_index, address, prefix_length, flags)
            .map_err(|_| {
                AddressEventDecodeError::new(
                    AddressEventDecodeErrorKind::InvalidPrefixLength,
                    body_offset + 1,
                )
            })?;

        if !family_is_enabled || !is_global_usable(address) || self.policy.ignores_address(address)
        {
            return Ok(None);
        }

        let kind = if message_type == RTM_DELADDR
            || body[3] != 0
            || self.policy.removes_for_flags(flags)
        {
            AddressEventKind::Remove
        } else {
            AddressEventKind::Add
        };
        Ok(Some(InterfaceAddressEvent { kind, record }))
    }
}

fn normalize_configured_prefix(
    address: IpAddr,
    prefix_length: u8,
) -> Result<(IpAddr, u8), AddressEventPolicyError> {
    let IpAddr::V6(ipv6) = address else {
        return Ok((address, prefix_length));
    };
    let Some(ipv4) = ipv6.to_ipv4_mapped() else {
        return Ok((address, prefix_length));
    };
    if prefix_length > 128 {
        return Err(AddressEventPolicyError::InvalidPrefixLength {
            address,
            prefix_length,
        });
    }
    if prefix_length < 96 {
        return Err(AddressEventPolicyError::UnsupportedMappedPrefix {
            address,
            prefix_length,
        });
    }
    Ok((IpAddr::V4(ipv4), prefix_length - 96))
}

fn normalize_event_address(address: IpAddr, prefix_length: u8) -> Result<(IpAddr, u8), ()> {
    let IpAddr::V6(ipv6) = address else {
        return Ok((address, prefix_length));
    };
    let Some(ipv4) = ipv6.to_ipv4_mapped() else {
        return Ok((address, prefix_length));
    };
    if prefix_length < 96 {
        return Err(());
    }
    Ok((IpAddr::V4(ipv4), prefix_length - 96))
}

fn decode_address(family: u8, bytes: &[u8]) -> Option<IpAddr> {
    match family {
        AF_INET => <[u8; 4]>::try_from(bytes)
            .ok()
            .map(Ipv4Addr::from)
            .map(IpAddr::V4),
        AF_INET6 => <[u8; 16]>::try_from(bytes)
            .ok()
            .map(Ipv6Addr::from)
            .map(IpAddr::V6),
        _ => None,
    }
}

const fn expected_address_length(family: u8) -> usize {
    if family == AF_INET { 4 } else { 16 }
}

fn is_global_usable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified() && !address.is_loopback() && !address.is_link_local()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified() && !address.is_loopback() && !address.is_unicast_link_local()
        }
    }
}

fn normalize_exact_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

fn mask_v4(value: u32, prefix_length: u8) -> u32 {
    if prefix_length == 0 {
        0
    } else {
        value & (u32::MAX << (32 - prefix_length))
    }
}

fn mask_v6(value: u128, prefix_length: u8) -> u128 {
    if prefix_length == 0 {
        0
    } else {
        value & (u128::MAX << (128 - prefix_length))
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes[..2].try_into().expect("validated two-byte field"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes[..4].try_into().expect("validated four-byte field"))
}

#[cfg(test)]
mod tests;
