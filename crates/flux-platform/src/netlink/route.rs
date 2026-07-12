use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;

use flux_core::{
    InterfaceIndex, NetworkAddressFamily, NetworkRouteRecord, RouteFlags, RouteGateway,
    RouteNexthop, RouteNexthopFlags, RoutePath, RoutePreference, RoutePrefix, RoutePrefixErrorKind,
    RouteProperties, RouteProtocol, RouteScope, RouteTableId, RouteType,
};

use super::{
    NETLINK_HEADER_LENGTH, NLA_F_NESTED, NLA_F_NET_BYTEORDER, NLM_F_DUMP_INTR, NLMSG_DONE,
    NLMSG_ERROR, NLMSG_OVERRUN, NetlinkAttribute, NetlinkAttributeError, NetlinkAttributeErrorKind,
    NetlinkAttributeIter, NetlinkDoneError, NetlinkDoneErrorKind, NetlinkFrameError,
    NetlinkFrameErrorKind, NetlinkMessageHeader, NetlinkMessageIter, align4, validate_done_payload,
};

const ROUTE_MESSAGE_LENGTH: usize = 12;
const ROUTE_NEXTHOP_LENGTH: usize = 8;
const ROUTE_CACHE_INFO_LENGTH: usize = 32;
const ROUTE_MFC_STATS_LENGTH: usize = 24;
const MAX_MULTIPATH_NEXTHOPS: usize = 8_191;

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const NLM_F_REPLACE: u16 = 0x100;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const RT_TABLE_COMPAT: u8 = 252;

const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_IIF: u16 = 3;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_METRICS: u16 = 8;
const RTA_MULTIPATH: u16 = 9;
const RTA_FLOW: u16 = 11;
const RTA_CACHEINFO: u16 = 12;
const RTA_TABLE: u16 = 15;
const RTA_MARK: u16 = 16;
const RTA_MFC_STATS: u16 = 17;
const RTA_VIA: u16 = 18;
const RTA_PREF: u16 = 20;
const RTA_ENCAP_TYPE: u16 = 21;
const RTA_ENCAP: u16 = 22;
const RTA_EXPIRES: u16 = 23;
const RTA_PAD: u16 = 24;
const RTA_UID: u16 = 25;
const RTA_TTL_PROPAGATE: u16 = 26;
const RTA_IP_PROTO: u16 = 27;
const RTA_SPORT: u16 = 28;
const RTA_DPORT: u16 = 29;
const RTA_NH_ID: u16 = 30;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InterfaceRouteEvent {
    Upsert {
        record: NetworkRouteRecord,
        replace: bool,
    },
    Remove(NetworkRouteRecord),
}

impl InterfaceRouteEvent {
    #[must_use]
    pub(crate) const fn record(&self) -> &NetworkRouteRecord {
        match self {
            Self::Upsert { record, .. } | Self::Remove(record) => record,
        }
    }

    #[must_use]
    pub(crate) const fn replace(&self) -> bool {
        match self {
            Self::Upsert { replace, .. } => *replace,
            Self::Remove(_) => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteEventDecodeErrorKind {
    TruncatedHeader,
    InvalidMessageLength,
    MissingMessagePadding,
    TruncatedRouteMessage,
    InvalidAttributeLength,
    MissingAttributePadding,
    InvalidAttributeFlags,
    DuplicateSemanticAttribute,
    MissingDestination,
    InvalidDestinationLength,
    InvalidDestinationPrefixLength,
    NonzeroDestinationHostBits,
    MissingSource,
    InvalidSourceLength,
    InvalidSourcePrefixLength,
    NonzeroSourceHostBits,
    InvalidTableLength,
    InconsistentTable,
    InvalidOutputInterfaceLength,
    InvalidOutputInterface,
    InvalidGatewayLength,
    ConflictingGatewayAttributes,
    InvalidViaLength,
    InvalidViaFamily,
    ViaUnsupported,
    InvalidPriorityLength,
    InvalidPreferredSourceLength,
    InvalidCacheInfoLength,
    InvalidPreferenceLength,
    PreferenceUnsupported,
    InvalidNexthopIdLength,
    InvalidNexthopId,
    InvalidScalarLength,
    ConflictingPathAttributes,
    EmptyMultipath,
    TruncatedNexthop,
    InvalidNexthopLength,
    MissingNexthopPadding,
    InvalidNexthopInterface,
    TooManyNexthops,
    InvalidRouteRecord,
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
pub(crate) struct RouteEventDecodeError {
    kind: RouteEventDecodeErrorKind,
    offset: usize,
}

impl RouteEventDecodeError {
    const fn new(kind: RouteEventDecodeErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    #[must_use]
    pub(crate) const fn kind(self) -> RouteEventDecodeErrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }
}

impl From<NetlinkFrameError> for RouteEventDecodeError {
    fn from(error: NetlinkFrameError) -> Self {
        Self::new(
            match error.kind() {
                NetlinkFrameErrorKind::TruncatedHeader => {
                    RouteEventDecodeErrorKind::TruncatedHeader
                }
                NetlinkFrameErrorKind::InvalidMessageLength => {
                    RouteEventDecodeErrorKind::InvalidMessageLength
                }
                NetlinkFrameErrorKind::MissingMessagePadding => {
                    RouteEventDecodeErrorKind::MissingMessagePadding
                }
            },
            error.offset(),
        )
    }
}

impl From<NetlinkAttributeError> for RouteEventDecodeError {
    fn from(error: NetlinkAttributeError) -> Self {
        Self::new(
            match error.kind() {
                NetlinkAttributeErrorKind::InvalidAttributeLength => {
                    RouteEventDecodeErrorKind::InvalidAttributeLength
                }
                NetlinkAttributeErrorKind::MissingAttributePadding => {
                    RouteEventDecodeErrorKind::MissingAttributePadding
                }
                NetlinkAttributeErrorKind::InvalidAttributeFlags => {
                    RouteEventDecodeErrorKind::InvalidAttributeFlags
                }
            },
            error.offset(),
        )
    }
}

impl From<NetlinkDoneError> for RouteEventDecodeError {
    fn from(error: NetlinkDoneError) -> Self {
        Self::new(
            match error.kind() {
                NetlinkDoneErrorKind::InvalidPayload => {
                    RouteEventDecodeErrorKind::InvalidDonePayload
                }
                NetlinkDoneErrorKind::ErrorStatus => RouteEventDecodeErrorKind::DoneErrorStatus,
            },
            error.offset(),
        )
    }
}

impl fmt::Display for RouteEventDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid rtnetlink route datagram at byte {}: {}",
            self.offset,
            match self.kind {
                RouteEventDecodeErrorKind::TruncatedHeader => "truncated netlink header",
                RouteEventDecodeErrorKind::InvalidMessageLength => {
                    "invalid netlink message length"
                }
                RouteEventDecodeErrorKind::MissingMessagePadding => {
                    "missing aligned netlink message padding"
                }
                RouteEventDecodeErrorKind::TruncatedRouteMessage => "truncated route message",
                RouteEventDecodeErrorKind::InvalidAttributeLength => {
                    "invalid netlink attribute length"
                }
                RouteEventDecodeErrorKind::MissingAttributePadding => {
                    "missing aligned netlink attribute padding"
                }
                RouteEventDecodeErrorKind::InvalidAttributeFlags => {
                    "recognized route attribute carries incompatible flags"
                }
                RouteEventDecodeErrorKind::DuplicateSemanticAttribute => {
                    "duplicate semantic route attribute"
                }
                RouteEventDecodeErrorKind::MissingDestination => {
                    "non-default route has no destination attribute"
                }
                RouteEventDecodeErrorKind::InvalidDestinationLength => {
                    "destination has the wrong length for its address family"
                }
                RouteEventDecodeErrorKind::InvalidDestinationPrefixLength => {
                    "destination prefix length is invalid"
                }
                RouteEventDecodeErrorKind::NonzeroDestinationHostBits => {
                    "destination prefix has nonzero host bits"
                }
                RouteEventDecodeErrorKind::MissingSource => {
                    "source-specific route has no source attribute"
                }
                RouteEventDecodeErrorKind::InvalidSourceLength => {
                    "source has the wrong length for its address family"
                }
                RouteEventDecodeErrorKind::InvalidSourcePrefixLength => {
                    "source prefix length is invalid"
                }
                RouteEventDecodeErrorKind::NonzeroSourceHostBits => {
                    "source prefix has nonzero host bits"
                }
                RouteEventDecodeErrorKind::InvalidTableLength => {
                    "RTA_TABLE must contain exactly one u32"
                }
                RouteEventDecodeErrorKind::InconsistentTable => {
                    "route header and RTA_TABLE disagree"
                }
                RouteEventDecodeErrorKind::InvalidOutputInterfaceLength => {
                    "RTA_OIF must contain exactly one u32"
                }
                RouteEventDecodeErrorKind::InvalidOutputInterface => {
                    "route output interface is outside the positive kernel int domain"
                }
                RouteEventDecodeErrorKind::InvalidGatewayLength => {
                    "RTA_GATEWAY has the wrong length for the route family"
                }
                RouteEventDecodeErrorKind::ConflictingGatewayAttributes => {
                    "route contains both RTA_GATEWAY and RTA_VIA"
                }
                RouteEventDecodeErrorKind::InvalidViaLength => {
                    "RTA_VIA has an invalid family or address length"
                }
                RouteEventDecodeErrorKind::InvalidViaFamily => {
                    "RTA_VIA uses an unsupported address family"
                }
                RouteEventDecodeErrorKind::ViaUnsupported => {
                    "RTA_VIA is unsupported for IPv6 routes"
                }
                RouteEventDecodeErrorKind::InvalidPriorityLength => {
                    "RTA_PRIORITY must contain exactly one u32"
                }
                RouteEventDecodeErrorKind::InvalidPreferredSourceLength => {
                    "RTA_PREFSRC has the wrong length for the route family"
                }
                RouteEventDecodeErrorKind::InvalidCacheInfoLength => {
                    "RTA_CACHEINFO must contain exactly one rta_cacheinfo"
                }
                RouteEventDecodeErrorKind::InvalidPreferenceLength => {
                    "RTA_PREF must contain exactly one u8"
                }
                RouteEventDecodeErrorKind::PreferenceUnsupported => {
                    "RTA_PREF is unsupported for IPv4 routes"
                }
                RouteEventDecodeErrorKind::InvalidNexthopIdLength => {
                    "RTA_NH_ID must contain exactly one u32"
                }
                RouteEventDecodeErrorKind::InvalidNexthopId => {
                    "RTA_NH_ID must be nonzero"
                }
                RouteEventDecodeErrorKind::InvalidScalarLength => {
                    "ignored scalar route attribute has an invalid length"
                }
                RouteEventDecodeErrorKind::ConflictingPathAttributes => {
                    "RTA_MULTIPATH conflicts with a top-level route path attribute"
                }
                RouteEventDecodeErrorKind::EmptyMultipath => {
                    "RTA_MULTIPATH contains no nexthops"
                }
                RouteEventDecodeErrorKind::TruncatedNexthop => {
                    "RTA_MULTIPATH ends inside a nexthop header"
                }
                RouteEventDecodeErrorKind::InvalidNexthopLength => {
                    "multipath nexthop length is invalid"
                }
                RouteEventDecodeErrorKind::MissingNexthopPadding => {
                    "multipath nexthop is missing aligned padding"
                }
                RouteEventDecodeErrorKind::InvalidNexthopInterface => {
                    "multipath nexthop has a negative interface index"
                }
                RouteEventDecodeErrorKind::TooManyNexthops => {
                    "RTA_MULTIPATH exceeds its wire-derived nexthop limit"
                }
                RouteEventDecodeErrorKind::InvalidRouteRecord => {
                    "route fields cannot form a canonical record"
                }
                RouteEventDecodeErrorKind::NetlinkOverrun => "netlink reported message overrun",
                RouteEventDecodeErrorKind::NetlinkError => "netlink returned NLMSG_ERROR",
                RouteEventDecodeErrorKind::InterruptedDump => {
                    "netlink message reports an interrupted dump"
                }
                RouteEventDecodeErrorKind::MixedSequence => {
                    "netlink datagram contains mixed sequence numbers"
                }
                RouteEventDecodeErrorKind::DuplicateDone => {
                    "netlink datagram contains more than one NLMSG_DONE"
                }
                RouteEventDecodeErrorKind::MessageAfterDone => {
                    "netlink datagram contains a message after NLMSG_DONE"
                }
                RouteEventDecodeErrorKind::InvalidDonePayload => {
                    "NLMSG_DONE payload or extended-ack attributes are malformed"
                }
                RouteEventDecodeErrorKind::DoneErrorStatus => {
                    "NLMSG_DONE reports a nonzero error status"
                }
            }
        )
    }
}

impl Error for RouteEventDecodeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RouteDatagram {
    sequence: Option<u32>,
    events: Vec<InterfaceRouteEvent>,
    completion: Option<NetlinkMessageHeader>,
}

impl RouteDatagram {
    #[must_use]
    pub(crate) const fn sequence(&self) -> Option<u32> {
        self.sequence
    }

    #[must_use]
    pub(crate) fn events(&self) -> &[InterfaceRouteEvent] {
        &self.events
    }

    #[must_use]
    pub(crate) const fn completion(&self) -> Option<NetlinkMessageHeader> {
        self.completion
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RtnetlinkRouteEventDecoder {
    include_ipv6: bool,
}

impl RtnetlinkRouteEventDecoder {
    #[must_use]
    pub(crate) const fn new(include_ipv6: bool) -> Self {
        Self { include_ipv6 }
    }

    pub(crate) fn decode_datagram(
        &self,
        datagram: &[u8],
    ) -> Result<RouteDatagram, RouteEventDecodeError> {
        let mut sequence = None;
        let mut events = Vec::new();
        let mut completion = None;

        for message in NetlinkMessageIter::new(datagram) {
            let message = message.map_err(RouteEventDecodeError::from)?;
            let header = message.header();
            if sequence.is_some_and(|expected| expected != header.sequence()) {
                return Err(RouteEventDecodeError::new(
                    RouteEventDecodeErrorKind::MixedSequence,
                    message.offset(),
                ));
            }
            sequence.get_or_insert(header.sequence());

            if completion.is_some() {
                return Err(RouteEventDecodeError::new(
                    if header.message_type() == NLMSG_DONE {
                        RouteEventDecodeErrorKind::DuplicateDone
                    } else {
                        RouteEventDecodeErrorKind::MessageAfterDone
                    },
                    message.offset(),
                ));
            }

            if header.flags() & NLM_F_DUMP_INTR != 0 {
                return Err(RouteEventDecodeError::new(
                    RouteEventDecodeErrorKind::InterruptedDump,
                    message.offset(),
                ));
            }

            match header.message_type() {
                NLMSG_OVERRUN => {
                    return Err(RouteEventDecodeError::new(
                        RouteEventDecodeErrorKind::NetlinkOverrun,
                        message.offset(),
                    ));
                }
                NLMSG_ERROR => {
                    return Err(RouteEventDecodeError::new(
                        RouteEventDecodeErrorKind::NetlinkError,
                        message.offset(),
                    ));
                }
                NLMSG_DONE => {
                    validate_done_payload(
                        message.payload(),
                        header.flags(),
                        message.offset() + NETLINK_HEADER_LENGTH,
                    )
                    .map_err(RouteEventDecodeError::from)?;
                    completion = Some(header);
                }
                RTM_NEWROUTE | RTM_DELROUTE => {
                    if let Some(event) = self.decode_route_message(
                        header.message_type(),
                        header.flags(),
                        message.payload(),
                        message.offset() + NETLINK_HEADER_LENGTH,
                    )? {
                        events.push(event);
                    }
                }
                _ => {}
            }
        }

        Ok(RouteDatagram {
            sequence,
            events,
            completion,
        })
    }

    fn decode_route_message(
        &self,
        message_type: u16,
        message_flags: u16,
        body: &[u8],
        body_offset: usize,
    ) -> Result<Option<InterfaceRouteEvent>, RouteEventDecodeError> {
        if body.len() < ROUTE_MESSAGE_LENGTH {
            return Err(RouteEventDecodeError::new(
                RouteEventDecodeErrorKind::TruncatedRouteMessage,
                body_offset,
            ));
        }

        let attributes = &body[ROUTE_MESSAGE_LENGTH..];
        let attributes_offset = body_offset + ROUTE_MESSAGE_LENGTH;
        let Some(family) = decode_family(u16::from(body[0])) else {
            validate_attribute_framing(attributes, attributes_offset)?;
            return Ok(None);
        };

        let decoded = decode_route_attributes(family, attributes, attributes_offset)?;
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
        let table = reconcile_table(body[4], decoded.table)?;
        let flags = RouteFlags::from_raw(read_u32(&body[8..]));
        let path = if let Some(multipath) = decoded.multipath {
            if decoded.output_interface.is_some() || decoded.gateway.is_some() {
                return Err(RouteEventDecodeError::new(
                    RouteEventDecodeErrorKind::ConflictingPathAttributes,
                    multipath.offset,
                ));
            }
            RoutePath::Multipath(multipath.nexthops.into_boxed_slice())
        } else if decoded.output_interface.is_some() || decoded.gateway.is_some() {
            RoutePath::Single {
                output_interface: decoded.output_interface,
                gateway: decoded.gateway.map(|gateway| gateway.value),
            }
        } else {
            RoutePath::None
        };

        let properties = RouteProperties::new(
            body[3],
            RouteTableId::from_raw(table),
            RouteProtocol::from_raw(body[5]),
            RouteScope::from_raw(body[6]),
            RouteType::from_raw(body[7]),
            flags,
        );
        let mut record = NetworkRouteRecord::new(
            destination,
            source,
            properties,
            decoded.priority.unwrap_or(0),
            path,
        )
        .map_err(|_| {
            RouteEventDecodeError::new(RouteEventDecodeErrorKind::InvalidRouteRecord, body_offset)
        })?;
        if let Some(preferred_source) = decoded.preferred_source {
            record = record
                .with_preferred_source(preferred_source.value)
                .map_err(|_| {
                    RouteEventDecodeError::new(
                        RouteEventDecodeErrorKind::InvalidRouteRecord,
                        preferred_source.offset,
                    )
                })?;
        }
        if let Some(preference) = decoded.preference {
            if family != NetworkAddressFamily::Ipv6 {
                return Err(RouteEventDecodeError::new(
                    RouteEventDecodeErrorKind::PreferenceUnsupported,
                    preference.offset,
                ));
            }
            record = record
                .with_preference(RoutePreference::from_raw(preference.value))
                .map_err(|_| {
                    RouteEventDecodeError::new(
                        RouteEventDecodeErrorKind::InvalidRouteRecord,
                        preference.offset,
                    )
                })?;
        }
        if let Some(nexthop_id) = decoded.nexthop_id {
            record = record.with_nexthop_id(nexthop_id);
        }

        if (family == NetworkAddressFamily::Ipv6 && !self.include_ipv6)
            || flags.raw() & RouteFlags::CLONED.raw() != 0
        {
            return Ok(None);
        }

        Ok(Some(if message_type == RTM_DELROUTE {
            InterfaceRouteEvent::Remove(record)
        } else {
            InterfaceRouteEvent::Upsert {
                record,
                replace: message_flags & NLM_F_REPLACE != 0,
            }
        }))
    }
}

#[derive(Clone, Copy)]
struct Located<T> {
    value: T,
    offset: usize,
}

struct DecodedMultipath {
    nexthops: Vec<RouteNexthop>,
    offset: usize,
}

#[derive(Default)]
struct DecodedRouteAttributes {
    destination: Option<Located<IpAddr>>,
    source: Option<Located<IpAddr>>,
    table: Option<Located<u32>>,
    output_interface: Option<InterfaceIndex>,
    gateway: Option<Located<RouteGateway>>,
    priority: Option<u32>,
    preferred_source: Option<Located<IpAddr>>,
    preference: Option<Located<u8>>,
    nexthop_id: Option<NonZeroU32>,
    multipath: Option<DecodedMultipath>,
}

fn decode_route_attributes(
    family: NetworkAddressFamily,
    attributes: &[u8],
    attributes_offset: usize,
) -> Result<DecodedRouteAttributes, RouteEventDecodeError> {
    let mut decoded = DecodedRouteAttributes::default();
    let mut seen = [false; (RTA_NH_ID + 1) as usize];

    for attribute in NetlinkAttributeIter::new(attributes, attributes_offset) {
        let attribute = attribute.map_err(RouteEventDecodeError::from)?;
        let attribute_type = attribute.attribute_type();
        match attribute_type {
            RTA_DST => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.destination = Some(decode_family_address(
                    family,
                    attribute,
                    RouteEventDecodeErrorKind::InvalidDestinationLength,
                )?);
            }
            RTA_SRC => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.source = Some(decode_family_address(
                    family,
                    attribute,
                    RouteEventDecodeErrorKind::InvalidSourceLength,
                )?);
            }
            RTA_IIF | RTA_FLOW | RTA_MARK | RTA_EXPIRES | RTA_UID => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u32>(),
                    RouteEventDecodeErrorKind::InvalidScalarLength,
                    attribute.value_offset(),
                )?;
            }
            RTA_OIF => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u32>(),
                    RouteEventDecodeErrorKind::InvalidOutputInterfaceLength,
                    attribute.value_offset(),
                )?;
                let raw_interface_index = read_u32(attribute.value());
                if raw_interface_index > i32::MAX as u32 {
                    return Err(RouteEventDecodeError::new(
                        RouteEventDecodeErrorKind::InvalidOutputInterface,
                        attribute.value_offset(),
                    ));
                }
                decoded.output_interface =
                    Some(InterfaceIndex::new(raw_interface_index).ok_or_else(|| {
                        RouteEventDecodeError::new(
                            RouteEventDecodeErrorKind::InvalidOutputInterface,
                            attribute.value_offset(),
                        )
                    })?);
            }
            RTA_GATEWAY => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                if decoded.gateway.is_some() {
                    return Err(conflicting_gateway(attribute.offset()));
                }
                let address = decode_family_address(
                    family,
                    attribute,
                    RouteEventDecodeErrorKind::InvalidGatewayLength,
                )?;
                decoded.gateway = Some(Located {
                    value: RouteGateway::Direct(address.value),
                    offset: address.offset,
                });
            }
            RTA_PRIORITY => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u32>(),
                    RouteEventDecodeErrorKind::InvalidPriorityLength,
                    attribute.value_offset(),
                )?;
                decoded.priority = Some(read_u32(attribute.value()));
            }
            RTA_PREFSRC => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.preferred_source = Some(decode_family_address(
                    family,
                    attribute,
                    RouteEventDecodeErrorKind::InvalidPreferredSourceLength,
                )?);
            }
            RTA_METRICS | RTA_ENCAP => {
                require_nested_compatible_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                validate_attribute_framing(attribute.value(), attribute.value_offset())?;
            }
            RTA_MULTIPATH => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                decoded.multipath = Some(decode_multipath(
                    family,
                    attribute.value(),
                    attribute.value_offset(),
                    attribute.offset(),
                )?);
            }
            RTA_CACHEINFO => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    ROUTE_CACHE_INFO_LENGTH,
                    RouteEventDecodeErrorKind::InvalidCacheInfoLength,
                    attribute.value_offset(),
                )?;
            }
            RTA_TABLE => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u32>(),
                    RouteEventDecodeErrorKind::InvalidTableLength,
                    attribute.value_offset(),
                )?;
                decoded.table = Some(Located {
                    value: read_u32(attribute.value()),
                    offset: attribute.value_offset(),
                });
            }
            RTA_MFC_STATS => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    ROUTE_MFC_STATS_LENGTH,
                    RouteEventDecodeErrorKind::InvalidScalarLength,
                    attribute.value_offset(),
                )?;
            }
            RTA_VIA => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                if decoded.gateway.is_some() {
                    return Err(conflicting_gateway(attribute.offset()));
                }
                decoded.gateway = Some(Located {
                    value: RouteGateway::Via(decode_via(family, attribute)?),
                    offset: attribute.value_offset(),
                });
            }
            RTA_PREF => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u8>(),
                    RouteEventDecodeErrorKind::InvalidPreferenceLength,
                    attribute.value_offset(),
                )?;
                decoded.preference = Some(Located {
                    value: attribute.value()[0],
                    offset: attribute.value_offset(),
                });
            }
            RTA_ENCAP_TYPE => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u16>(),
                    RouteEventDecodeErrorKind::InvalidScalarLength,
                    attribute.value_offset(),
                )?;
            }
            RTA_SPORT | RTA_DPORT => {
                require_network_scalar_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u16>(),
                    RouteEventDecodeErrorKind::InvalidScalarLength,
                    attribute.value_offset(),
                )?;
            }
            RTA_TTL_PROPAGATE | RTA_IP_PROTO => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u8>(),
                    RouteEventDecodeErrorKind::InvalidScalarLength,
                    attribute.value_offset(),
                )?;
            }
            RTA_PAD => {
                require_plain_attribute(attribute)?;
                require_length(
                    attribute.value(),
                    0,
                    RouteEventDecodeErrorKind::InvalidScalarLength,
                    attribute.value_offset(),
                )?;
            }
            RTA_NH_ID => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u32>(),
                    RouteEventDecodeErrorKind::InvalidNexthopIdLength,
                    attribute.value_offset(),
                )?;
                decoded.nexthop_id =
                    Some(NonZeroU32::new(read_u32(attribute.value())).ok_or_else(|| {
                        RouteEventDecodeError::new(
                            RouteEventDecodeErrorKind::InvalidNexthopId,
                            attribute.value_offset(),
                        )
                    })?);
            }
            _ => {}
        }
    }

    Ok(decoded)
}

fn decode_multipath(
    family: NetworkAddressFamily,
    value: &[u8],
    value_offset: usize,
    attribute_offset: usize,
) -> Result<DecodedMultipath, RouteEventDecodeError> {
    if value.is_empty() {
        return Err(RouteEventDecodeError::new(
            RouteEventDecodeErrorKind::EmptyMultipath,
            value_offset,
        ));
    }

    let mut nexthops = Vec::new();
    let mut offset = 0;
    while offset < value.len() {
        let remaining = &value[offset..];
        let nexthop_offset = value_offset + offset;
        if remaining.len() < ROUTE_NEXTHOP_LENGTH {
            return Err(RouteEventDecodeError::new(
                RouteEventDecodeErrorKind::TruncatedNexthop,
                nexthop_offset,
            ));
        }
        let length = usize::from(read_u16(remaining));
        if !(ROUTE_NEXTHOP_LENGTH..=remaining.len()).contains(&length) {
            return Err(RouteEventDecodeError::new(
                RouteEventDecodeErrorKind::InvalidNexthopLength,
                nexthop_offset,
            ));
        }
        let aligned_length = align4(length);
        if aligned_length > remaining.len() {
            return Err(RouteEventDecodeError::new(
                RouteEventDecodeErrorKind::MissingNexthopPadding,
                nexthop_offset,
            ));
        }

        let raw_interface_index = read_i32(&remaining[4..]);
        let output_interface = if raw_interface_index == 0 {
            None
        } else {
            let positive = u32::try_from(raw_interface_index).map_err(|_| {
                RouteEventDecodeError::new(
                    RouteEventDecodeErrorKind::InvalidNexthopInterface,
                    nexthop_offset + 4,
                )
            })?;
            Some(InterfaceIndex::new(positive).ok_or_else(|| {
                RouteEventDecodeError::new(
                    RouteEventDecodeErrorKind::InvalidNexthopInterface,
                    nexthop_offset + 4,
                )
            })?)
        };
        let gateway = decode_nexthop_attributes(
            family,
            &remaining[ROUTE_NEXTHOP_LENGTH..length],
            nexthop_offset + ROUTE_NEXTHOP_LENGTH,
        )?;
        nexthops.push(RouteNexthop::new(
            output_interface,
            gateway,
            RouteNexthopFlags::from_raw(remaining[2]),
            remaining[3],
        ));
        if nexthops.len() > MAX_MULTIPATH_NEXTHOPS {
            return Err(RouteEventDecodeError::new(
                RouteEventDecodeErrorKind::TooManyNexthops,
                nexthop_offset,
            ));
        }
        offset += aligned_length;
    }

    Ok(DecodedMultipath {
        nexthops,
        offset: attribute_offset,
    })
}

fn decode_nexthop_attributes(
    family: NetworkAddressFamily,
    attributes: &[u8],
    attributes_offset: usize,
) -> Result<Option<RouteGateway>, RouteEventDecodeError> {
    let mut gateway = None;
    let mut seen = [false; (RTA_NH_ID + 1) as usize];
    for attribute in NetlinkAttributeIter::new(attributes, attributes_offset) {
        let attribute = attribute.map_err(RouteEventDecodeError::from)?;
        let attribute_type = attribute.attribute_type();
        match attribute_type {
            RTA_GATEWAY => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                if gateway.is_some() {
                    return Err(conflicting_gateway(attribute.offset()));
                }
                gateway = Some(RouteGateway::Direct(
                    decode_family_address(
                        family,
                        attribute,
                        RouteEventDecodeErrorKind::InvalidGatewayLength,
                    )?
                    .value,
                ));
            }
            RTA_VIA => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                if gateway.is_some() {
                    return Err(conflicting_gateway(attribute.offset()));
                }
                gateway = Some(RouteGateway::Via(decode_via(family, attribute)?));
            }
            RTA_FLOW => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u32>(),
                    RouteEventDecodeErrorKind::InvalidScalarLength,
                    attribute.value_offset(),
                )?;
            }
            RTA_ENCAP_TYPE => {
                require_plain_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                require_length(
                    attribute.value(),
                    size_of::<u16>(),
                    RouteEventDecodeErrorKind::InvalidScalarLength,
                    attribute.value_offset(),
                )?;
            }
            RTA_ENCAP => {
                require_nested_compatible_attribute(attribute)?;
                mark_seen(&mut seen, attribute_type, attribute.offset())?;
                validate_attribute_framing(attribute.value(), attribute.value_offset())?;
            }
            RTA_PAD => {
                require_plain_attribute(attribute)?;
                require_length(
                    attribute.value(),
                    0,
                    RouteEventDecodeErrorKind::InvalidScalarLength,
                    attribute.value_offset(),
                )?;
            }
            _ => {}
        }
    }
    Ok(gateway)
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
) -> Result<RoutePrefix, RouteEventDecodeError> {
    if prefix_length > maximum_prefix_length(family) {
        return Err(RouteEventDecodeError::new(
            match role {
                PrefixRole::Destination => {
                    RouteEventDecodeErrorKind::InvalidDestinationPrefixLength
                }
                PrefixRole::Source => RouteEventDecodeErrorKind::InvalidSourcePrefixLength,
            },
            prefix_offset,
        ));
    }
    let Some(address) = address else {
        if prefix_length == 0 {
            return Ok(RoutePrefix::unspecified(family));
        }
        return Err(RouteEventDecodeError::new(
            match role {
                PrefixRole::Destination => RouteEventDecodeErrorKind::MissingDestination,
                PrefixRole::Source => RouteEventDecodeErrorKind::MissingSource,
            },
            missing_offset,
        ));
    };

    RoutePrefix::new(address.value, prefix_length).map_err(|error| {
        RouteEventDecodeError::new(
            match (role, error.kind()) {
                (PrefixRole::Destination, RoutePrefixErrorKind::InvalidPrefixLength) => {
                    RouteEventDecodeErrorKind::InvalidDestinationPrefixLength
                }
                (PrefixRole::Destination, RoutePrefixErrorKind::HostBitsSet) => {
                    RouteEventDecodeErrorKind::NonzeroDestinationHostBits
                }
                (PrefixRole::Source, RoutePrefixErrorKind::InvalidPrefixLength) => {
                    RouteEventDecodeErrorKind::InvalidSourcePrefixLength
                }
                (PrefixRole::Source, RoutePrefixErrorKind::HostBitsSet) => {
                    RouteEventDecodeErrorKind::NonzeroSourceHostBits
                }
            },
            address.offset,
        )
    })
}

fn reconcile_table(
    header_table: u8,
    attribute_table: Option<Located<u32>>,
) -> Result<u32, RouteEventDecodeError> {
    let Some(attribute_table) = attribute_table else {
        return Ok(u32::from(header_table));
    };
    let consistent = if let Ok(compact) = u8::try_from(attribute_table.value) {
        compact == header_table
    } else {
        header_table == RT_TABLE_COMPAT
    };
    if consistent {
        Ok(attribute_table.value)
    } else {
        Err(RouteEventDecodeError::new(
            RouteEventDecodeErrorKind::InconsistentTable,
            attribute_table.offset,
        ))
    }
}

fn decode_family_address(
    family: NetworkAddressFamily,
    attribute: NetlinkAttribute<'_>,
    length_error: RouteEventDecodeErrorKind,
) -> Result<Located<IpAddr>, RouteEventDecodeError> {
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

fn decode_via(
    route_family: NetworkAddressFamily,
    attribute: NetlinkAttribute<'_>,
) -> Result<IpAddr, RouteEventDecodeError> {
    if attribute.value().len() < size_of::<u16>() {
        return Err(RouteEventDecodeError::new(
            RouteEventDecodeErrorKind::InvalidViaLength,
            attribute.value_offset(),
        ));
    }
    let family = decode_family(read_u16(attribute.value())).ok_or_else(|| {
        RouteEventDecodeError::new(
            RouteEventDecodeErrorKind::InvalidViaFamily,
            attribute.value_offset(),
        )
    })?;
    let address = &attribute.value()[size_of::<u16>()..];
    require_length(
        address,
        address_length(family),
        RouteEventDecodeErrorKind::InvalidViaLength,
        attribute.value_offset() + size_of::<u16>(),
    )?;
    if route_family != NetworkAddressFamily::Ipv4 {
        return Err(RouteEventDecodeError::new(
            RouteEventDecodeErrorKind::ViaUnsupported,
            attribute.offset(),
        ));
    }
    Ok(decode_address(family, address))
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
) -> Result<(), RouteEventDecodeError> {
    for attribute in NetlinkAttributeIter::new(attributes, attributes_offset) {
        let _ = attribute.map_err(RouteEventDecodeError::from)?;
    }
    Ok(())
}

fn mark_seen(
    seen: &mut [bool],
    attribute_type: u16,
    offset: usize,
) -> Result<(), RouteEventDecodeError> {
    let slot = &mut seen[usize::from(attribute_type)];
    if std::mem::replace(slot, true) {
        Err(RouteEventDecodeError::new(
            RouteEventDecodeErrorKind::DuplicateSemanticAttribute,
            offset,
        ))
    } else {
        Ok(())
    }
}

fn require_plain_attribute(attribute: NetlinkAttribute<'_>) -> Result<(), RouteEventDecodeError> {
    if attribute.flags() == 0 {
        Ok(())
    } else {
        Err(RouteEventDecodeError::new(
            RouteEventDecodeErrorKind::InvalidAttributeFlags,
            attribute.offset(),
        ))
    }
}

fn require_nested_compatible_attribute(
    attribute: NetlinkAttribute<'_>,
) -> Result<(), RouteEventDecodeError> {
    if matches!(attribute.flags(), 0 | NLA_F_NESTED) {
        Ok(())
    } else {
        Err(RouteEventDecodeError::new(
            RouteEventDecodeErrorKind::InvalidAttributeFlags,
            attribute.offset(),
        ))
    }
}

fn require_network_scalar_attribute(
    attribute: NetlinkAttribute<'_>,
) -> Result<(), RouteEventDecodeError> {
    if matches!(attribute.flags(), 0 | NLA_F_NET_BYTEORDER) {
        Ok(())
    } else {
        Err(RouteEventDecodeError::new(
            RouteEventDecodeErrorKind::InvalidAttributeFlags,
            attribute.offset(),
        ))
    }
}

fn require_length(
    value: &[u8],
    expected: usize,
    kind: RouteEventDecodeErrorKind,
    offset: usize,
) -> Result<(), RouteEventDecodeError> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(RouteEventDecodeError::new(kind, offset))
    }
}

fn conflicting_gateway(offset: usize) -> RouteEventDecodeError {
    RouteEventDecodeError::new(
        RouteEventDecodeErrorKind::ConflictingGatewayAttributes,
        offset,
    )
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
#[path = "route_tests.rs"]
mod tests;
