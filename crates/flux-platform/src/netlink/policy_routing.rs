use std::error::Error;
use std::fmt;
use std::num::{NonZeroI32, NonZeroU32};

use flux_core::{
    InterfaceIndex, InterfaceName, NetworkAddressFamily, NetworkRouteRecord, NetworkRuleRecord,
    RouteFlags, RoutePath, RoutePreference, RoutePrefix, RouteProperties, RouteProtocol,
    RouteScope, RouteTableId, RouteType, RuleAction, RuleFlags, RuleFwMark, RulePrefix,
    RulePriority, RuleProperties, RuleProtocol, RuleTableId,
};

use super::route::{InterfaceRouteEvent, RouteEventDecodeErrorKind, RtnetlinkRouteEventDecoder};
use super::rule::{NetworkRuleEvent, RtnetlinkRuleEventDecoder, RuleEventDecodeErrorKind};
use super::{
    NETLINK_ATTRIBUTE_HEADER_LENGTH, NETLINK_HEADER_LENGTH, NLMSG_ERROR, NetlinkAttributeIter,
    NetlinkMessageIter, align4,
};
use crate::xtables::{XtablesLocalOutputRoutingRequirement, XtablesRestoreFamily};

const ROUTING_HEADER_LENGTH: usize = 12;
const NLMSGERR_HEADER_LENGTH: usize = 4 + NETLINK_HEADER_LENGTH;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const AF_NETLINK: u16 = 16;
const SOCKADDR_NL_LENGTH: u32 = 12;

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_CAPPED: u16 = 0x0100;
const NLM_F_REPLACE: u16 = 0x0100;
const NLM_F_ACK_TLVS: u16 = 0x0200;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;

const RT_TABLE_UNSPEC: u8 = 0;
const RT_TABLE_COMPAT: u8 = 252;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_HOST: u8 = 254;
const RTN_LOCAL: u8 = 2;
const FR_ACT_TO_TBL: u8 = 1;

const RTA_OIF: u16 = 4;
const RTA_PRIORITY: u16 = 6;
const RTA_METRICS: u16 = 8;
const RTA_CACHEINFO: u16 = 12;
const RTA_TABLE: u16 = 15;
const RTA_PREF: u16 = 20;
const RTA_PAD: u16 = 24;

const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_PAD: u16 = 18;
const FRA_PROTOCOL: u16 = 21;

const NLMSGERR_ATTR_MSG: u16 = 1;
const NLMSGERR_ATTR_OFFS: u16 = 2;

pub(crate) const MAX_POLICY_ROUTING_REQUEST_BYTES: usize = 96;
pub(crate) const MAX_POLICY_ROUTING_ACK_BYTES: usize = 4 * 1024;
pub(crate) const MAX_POLICY_ROUTING_EXT_ACK_MESSAGE_BYTES: usize = 256;
pub(crate) const MAX_POLICY_ROUTING_READBACK_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_POLICY_ROUTING_READBACK_MESSAGES: usize = 8_192;
const MAX_POLICY_ROUTING_EXT_ACK_ATTRIBUTES: usize = 16;
const MAX_POLICY_ROUTING_READBACK_EVENTS: usize = 4_096;
const IPV6_ROUTE_PREFERENCE_MEDIUM: u8 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedInterfaceIdentity {
    name: InterfaceName,
    index: InterfaceIndex,
}

impl ManagedInterfaceIdentity {
    #[must_use]
    pub(crate) const fn name(self) -> InterfaceName {
        self.name
    }

    #[must_use]
    pub(crate) const fn index(self) -> InterfaceIndex {
        self.index
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedLocalRouteIdentity {
    family: NetworkAddressFamily,
    destination: RoutePrefix,
    table: RouteTableId,
    protocol: RouteProtocol,
    scope: RouteScope,
    route_type: RouteType,
    metric: NonZeroU32,
    output_interface: InterfaceIndex,
}

impl ManagedLocalRouteIdentity {
    #[must_use]
    pub(crate) const fn family(self) -> NetworkAddressFamily {
        self.family
    }

    #[must_use]
    pub(crate) const fn destination(self) -> RoutePrefix {
        self.destination
    }

    #[must_use]
    pub(crate) const fn table(self) -> RouteTableId {
        self.table
    }

    #[must_use]
    pub(crate) const fn protocol(self) -> RouteProtocol {
        self.protocol
    }

    #[must_use]
    pub(crate) const fn scope(self) -> RouteScope {
        self.scope
    }

    #[must_use]
    pub(crate) const fn route_type(self) -> RouteType {
        self.route_type
    }

    #[must_use]
    pub(crate) const fn metric(self) -> NonZeroU32 {
        self.metric
    }

    #[must_use]
    pub(crate) const fn output_interface(self) -> InterfaceIndex {
        self.output_interface
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFwmarkRuleIdentity {
    family: NetworkAddressFamily,
    priority: RulePriority,
    table: RouteTableId,
    mark: RuleFwMark,
    protocol: RuleProtocol,
}

impl ManagedFwmarkRuleIdentity {
    #[must_use]
    pub(crate) const fn family(self) -> NetworkAddressFamily {
        self.family
    }

    #[must_use]
    pub(crate) const fn priority(self) -> RulePriority {
        self.priority
    }

    #[must_use]
    pub(crate) const fn table(self) -> RouteTableId {
        self.table
    }

    #[must_use]
    pub(crate) const fn mark(self) -> RuleFwMark {
        self.mark
    }

    #[must_use]
    pub(crate) const fn protocol(self) -> RuleProtocol {
        self.protocol
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedPolicyRoutingIdentity {
    family: NetworkAddressFamily,
    loopback: ManagedInterfaceIdentity,
    route: ManagedLocalRouteIdentity,
    rule: ManagedFwmarkRuleIdentity,
}

impl ManagedPolicyRoutingIdentity {
    pub(crate) fn bind(
        requirement: XtablesLocalOutputRoutingRequirement,
        loopback_index: InterfaceIndex,
    ) -> Result<Self, ManagedPolicyRoutingIdentityError> {
        let family = restore_family(requirement.family());
        let destination = RoutePrefix::new(
            requirement.route_destination(),
            requirement.route_prefix_length(),
        )
        .map_err(|_| ManagedPolicyRoutingIdentityError::DestinationNotDefault)?;
        if destination != RoutePrefix::unspecified(family) {
            return Err(ManagedPolicyRoutingIdentityError::DestinationNotDefault);
        }
        let expected_scope = canonical_route_scope(family);
        if requirement.route_scope() != expected_scope {
            return Err(ManagedPolicyRoutingIdentityError::NonCanonicalRouteScope {
                expected: expected_scope,
                actual: requirement.route_scope(),
            });
        }
        if requirement.route_type().raw() != RTN_LOCAL {
            return Err(ManagedPolicyRoutingIdentityError::NonLocalRouteType {
                actual: requirement.route_type(),
            });
        }
        if requirement.loopback_interface().as_bytes() != b"lo" {
            return Err(
                ManagedPolicyRoutingIdentityError::LoopbackInterfaceMismatch {
                    actual: requirement.loopback_interface(),
                },
            );
        }

        let loopback = ManagedInterfaceIdentity {
            name: requirement.loopback_interface(),
            index: loopback_index,
        };
        let route = ManagedLocalRouteIdentity {
            family,
            destination,
            table: requirement.table(),
            protocol: requirement.route_protocol(),
            scope: requirement.route_scope(),
            route_type: requirement.route_type(),
            metric: requirement.route_metric(),
            output_interface: loopback_index,
        };
        let rule = ManagedFwmarkRuleIdentity {
            family,
            priority: requirement.priority(),
            table: requirement.table(),
            mark: requirement.mark(),
            protocol: requirement.rule_protocol(),
        };
        Ok(Self {
            family,
            loopback,
            route,
            rule,
        })
    }

    #[must_use]
    pub(crate) const fn family(self) -> NetworkAddressFamily {
        self.family
    }

    #[must_use]
    pub(crate) const fn loopback(self) -> ManagedInterfaceIdentity {
        self.loopback
    }

    #[must_use]
    pub(crate) const fn route(self) -> ManagedLocalRouteIdentity {
        self.route
    }

    #[must_use]
    pub(crate) const fn rule(self) -> ManagedFwmarkRuleIdentity {
        self.rule
    }

    pub(crate) fn from_recovery(
        record: ManagedPolicyRoutingRecoveryRecord,
    ) -> Result<Self, ManagedPolicyRoutingIdentityError> {
        if record.loopback_name.as_bytes() != b"lo" {
            return Err(
                ManagedPolicyRoutingIdentityError::LoopbackInterfaceMismatch {
                    actual: record.loopback_name,
                },
            );
        }
        if record.destination != RoutePrefix::unspecified(record.family) {
            return Err(ManagedPolicyRoutingIdentityError::DestinationNotDefault);
        }
        let expected_scope = canonical_route_scope(record.family);
        if record.route_scope != expected_scope {
            return Err(ManagedPolicyRoutingIdentityError::NonCanonicalRouteScope {
                expected: expected_scope,
                actual: record.route_scope,
            });
        }
        if record.route_type.raw() != RTN_LOCAL {
            return Err(ManagedPolicyRoutingIdentityError::NonLocalRouteType {
                actual: record.route_type,
            });
        }
        if record.output_interface != record.loopback_index {
            return Err(ManagedPolicyRoutingIdentityError::InvalidRecovery(
                "route output interface differs from the bound loopback index",
            ));
        }
        if record.route_table != record.rule_table {
            return Err(ManagedPolicyRoutingIdentityError::InvalidRecovery(
                "route and rule tables differ",
            ));
        }
        if matches!(record.route_table.get(), 0 | 252 | 253 | 254 | 255) {
            return Err(ManagedPolicyRoutingIdentityError::InvalidRecovery(
                "managed table is reserved",
            ));
        }
        if record.route_protocol.raw() == 0 || record.rule_protocol.raw() == 0 {
            return Err(ManagedPolicyRoutingIdentityError::InvalidRecovery(
                "managed route and rule protocols must be nonzero",
            ));
        }
        if record.rule_priority.get() == 0 {
            return Err(ManagedPolicyRoutingIdentityError::InvalidRecovery(
                "managed rule priority must be nonzero",
            ));
        }
        let loopback = ManagedInterfaceIdentity {
            name: record.loopback_name,
            index: record.loopback_index,
        };
        Ok(Self {
            family: record.family,
            loopback,
            route: ManagedLocalRouteIdentity {
                family: record.family,
                destination: record.destination,
                table: record.route_table,
                protocol: record.route_protocol,
                scope: record.route_scope,
                route_type: record.route_type,
                metric: record.route_metric,
                output_interface: record.output_interface,
            },
            rule: ManagedFwmarkRuleIdentity {
                family: record.family,
                priority: record.rule_priority,
                table: record.rule_table,
                mark: record.mark,
                protocol: record.rule_protocol,
            },
        })
    }

    #[must_use]
    pub(crate) const fn recovery_record(self) -> ManagedPolicyRoutingRecoveryRecord {
        ManagedPolicyRoutingRecoveryRecord {
            family: self.family,
            loopback_name: self.loopback.name,
            loopback_index: self.loopback.index,
            destination: self.route.destination,
            route_table: self.route.table,
            route_protocol: self.route.protocol,
            route_scope: self.route.scope,
            route_type: self.route.route_type,
            route_metric: self.route.metric,
            output_interface: self.route.output_interface,
            rule_priority: self.rule.priority,
            rule_table: self.rule.table,
            mark: self.rule.mark,
            rule_protocol: self.rule.protocol,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedPolicyRoutingRecoveryRecord {
    pub(crate) family: NetworkAddressFamily,
    pub(crate) loopback_name: InterfaceName,
    pub(crate) loopback_index: InterfaceIndex,
    pub(crate) destination: RoutePrefix,
    pub(crate) route_table: RouteTableId,
    pub(crate) route_protocol: RouteProtocol,
    pub(crate) route_scope: RouteScope,
    pub(crate) route_type: RouteType,
    pub(crate) route_metric: NonZeroU32,
    pub(crate) output_interface: InterfaceIndex,
    pub(crate) rule_priority: RulePriority,
    pub(crate) rule_table: RouteTableId,
    pub(crate) mark: RuleFwMark,
    pub(crate) rule_protocol: RuleProtocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedPolicyRoutingIdentityError {
    DestinationNotDefault,
    NonCanonicalRouteScope {
        expected: RouteScope,
        actual: RouteScope,
    },
    NonLocalRouteType {
        actual: RouteType,
    },
    LoopbackInterfaceMismatch {
        actual: InterfaceName,
    },
    InvalidRecovery(&'static str),
}

impl fmt::Display for ManagedPolicyRoutingIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestinationNotDefault => {
                formatter.write_str("managed local route is not the family default prefix")
            }
            Self::NonCanonicalRouteScope { expected, actual } => write!(
                formatter,
                "managed local route scope {} is not kernel-canonical scope {}",
                actual.raw(),
                expected.raw()
            ),
            Self::NonLocalRouteType { actual } => write!(
                formatter,
                "managed local route type {} is not RTN_LOCAL",
                actual.raw()
            ),
            Self::LoopbackInterfaceMismatch { actual } => write!(
                formatter,
                "managed local route interface {:?} is not loopback 'lo'",
                actual.as_bytes()
            ),
            Self::InvalidRecovery(reason) => {
                write!(
                    formatter,
                    "invalid recovered policy-routing identity: {reason}"
                )
            }
        }
    }
}

impl Error for ManagedPolicyRoutingIdentityError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyRoutingMutation {
    AddRoute(ManagedLocalRouteIdentity),
    DeleteRoute(ManagedLocalRouteIdentity),
    AddRule(ManagedFwmarkRuleIdentity),
    DeleteRule(ManagedFwmarkRuleIdentity),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyRoutingMutationKind {
    AddRoute,
    DeleteRoute,
    AddRule,
    DeleteRule,
}

impl PolicyRoutingMutation {
    #[must_use]
    pub(crate) const fn kind(self) -> PolicyRoutingMutationKind {
        match self {
            Self::AddRoute(_) => PolicyRoutingMutationKind::AddRoute,
            Self::DeleteRoute(_) => PolicyRoutingMutationKind::DeleteRoute,
            Self::AddRule(_) => PolicyRoutingMutationKind::AddRule,
            Self::DeleteRule(_) => PolicyRoutingMutationKind::DeleteRule,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EncodedPolicyRoutingRequest {
    bytes: Box<[u8]>,
    sequence: NonZeroU32,
    kind: PolicyRoutingMutationKind,
}

impl EncodedPolicyRoutingRequest {
    #[must_use]
    pub(crate) const fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub(crate) const fn sequence(&self) -> NonZeroU32 {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> PolicyRoutingMutationKind {
        self.kind
    }

    fn message_type(&self) -> u16 {
        read_u16(&self.bytes[4..])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyRoutingEncodeError {
    RequestTooLarge,
    AttributeTooLarge,
}

impl fmt::Display for PolicyRoutingEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RequestTooLarge => "policy-routing netlink request exceeds its byte bound",
            Self::AttributeTooLarge => "policy-routing netlink attribute exceeds the u16 ABI bound",
        })
    }
}

impl Error for PolicyRoutingEncodeError {}

pub(crate) fn encode_policy_routing_mutation(
    mutation: PolicyRoutingMutation,
    sequence: NonZeroU32,
) -> Result<EncodedPolicyRoutingRequest, PolicyRoutingEncodeError> {
    let kind = mutation.kind();
    let bytes = match mutation {
        PolicyRoutingMutation::AddRoute(identity) => encode_route(identity, true, sequence)?,
        PolicyRoutingMutation::DeleteRoute(identity) => encode_route(identity, false, sequence)?,
        PolicyRoutingMutation::AddRule(identity) => encode_rule(identity, true, sequence)?,
        PolicyRoutingMutation::DeleteRule(identity) => encode_rule(identity, false, sequence)?,
    };
    Ok(EncodedPolicyRoutingRequest {
        bytes,
        sequence,
        kind,
    })
}

fn encode_route(
    identity: ManagedLocalRouteIdentity,
    add: bool,
    sequence: NonZeroU32,
) -> Result<Box<[u8]>, PolicyRoutingEncodeError> {
    let message_type = if add { RTM_NEWROUTE } else { RTM_DELROUTE };
    let flags = mutation_flags(add);
    let mut body = [0_u8; ROUTING_HEADER_LENGTH];
    body[0] = family_byte(identity.family());
    body[1] = identity.destination().prefix_length();
    body[4] = request_table_byte(identity.table());
    body[5] = identity.protocol().raw();
    body[6] = identity.scope().raw();
    body[7] = identity.route_type().raw();

    let mut request = begin_request(message_type, flags, sequence, &body);
    append_u32_attribute(&mut request, RTA_TABLE, identity.table().get())?;
    append_u32_attribute(&mut request, RTA_OIF, identity.output_interface().get())?;
    append_u32_attribute(&mut request, RTA_PRIORITY, identity.metric().get())?;
    finish_request(request)
}

fn encode_rule(
    identity: ManagedFwmarkRuleIdentity,
    add: bool,
    sequence: NonZeroU32,
) -> Result<Box<[u8]>, PolicyRoutingEncodeError> {
    let message_type = if add { RTM_NEWRULE } else { RTM_DELRULE };
    let flags = mutation_flags(add);
    let mut body = [0_u8; ROUTING_HEADER_LENGTH];
    body[0] = family_byte(identity.family());
    body[4] = request_table_byte(identity.table());
    body[7] = FR_ACT_TO_TBL;

    let mut request = begin_request(message_type, flags, sequence, &body);
    append_u32_attribute(&mut request, FRA_TABLE, identity.table().get())?;
    append_u32_attribute(&mut request, FRA_PRIORITY, identity.priority().get())?;
    append_u32_attribute(&mut request, FRA_FWMARK, identity.mark().value())?;
    append_u32_attribute(&mut request, FRA_FWMASK, identity.mark().mask())?;
    append_attribute(&mut request, FRA_PROTOCOL, &[identity.protocol().raw()])?;
    finish_request(request)
}

const fn mutation_flags(add: bool) -> u16 {
    if add {
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    } else {
        NLM_F_REQUEST | NLM_F_ACK
    }
}

fn begin_request(
    message_type: u16,
    flags: u16,
    sequence: NonZeroU32,
    body: &[u8; ROUTING_HEADER_LENGTH],
) -> Vec<u8> {
    let mut request = Vec::with_capacity(MAX_POLICY_ROUTING_REQUEST_BYTES);
    request.extend_from_slice(&0_u32.to_ne_bytes());
    request.extend_from_slice(&message_type.to_ne_bytes());
    request.extend_from_slice(&flags.to_ne_bytes());
    request.extend_from_slice(&sequence.get().to_ne_bytes());
    request.extend_from_slice(&0_u32.to_ne_bytes());
    request.extend_from_slice(body);
    request
}

fn append_u32_attribute(
    request: &mut Vec<u8>,
    attribute_type: u16,
    value: u32,
) -> Result<(), PolicyRoutingEncodeError> {
    append_attribute(request, attribute_type, &value.to_ne_bytes())
}

fn append_attribute(
    request: &mut Vec<u8>,
    attribute_type: u16,
    value: &[u8],
) -> Result<(), PolicyRoutingEncodeError> {
    let length = NETLINK_ATTRIBUTE_HEADER_LENGTH
        .checked_add(value.len())
        .ok_or(PolicyRoutingEncodeError::AttributeTooLarge)?;
    let length = u16::try_from(length).map_err(|_| PolicyRoutingEncodeError::AttributeTooLarge)?;
    let aligned = align4(usize::from(length));
    let new_length = request
        .len()
        .checked_add(aligned)
        .ok_or(PolicyRoutingEncodeError::RequestTooLarge)?;
    if new_length > MAX_POLICY_ROUTING_REQUEST_BYTES {
        return Err(PolicyRoutingEncodeError::RequestTooLarge);
    }
    let start = request.len();
    request.resize(new_length, 0);
    request[start..start + 2].copy_from_slice(&length.to_ne_bytes());
    request[start + 2..start + 4].copy_from_slice(&attribute_type.to_ne_bytes());
    request[start + NETLINK_ATTRIBUTE_HEADER_LENGTH
        ..start + NETLINK_ATTRIBUTE_HEADER_LENGTH + value.len()]
        .copy_from_slice(value);
    Ok(())
}

fn finish_request(mut request: Vec<u8>) -> Result<Box<[u8]>, PolicyRoutingEncodeError> {
    if request.len() > MAX_POLICY_ROUTING_REQUEST_BYTES {
        return Err(PolicyRoutingEncodeError::RequestTooLarge);
    }
    let length =
        u32::try_from(request.len()).map_err(|_| PolicyRoutingEncodeError::RequestTooLarge)?;
    request[..4].copy_from_slice(&length.to_ne_bytes());
    Ok(request.into_boxed_slice())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PolicyRoutingAckSender {
    address_length: u32,
    family: u16,
    port_id: u32,
    groups: u32,
}

impl PolicyRoutingAckSender {
    #[must_use]
    pub(crate) const fn new(address_length: u32, family: u16, port_id: u32, groups: u32) -> Self {
        Self {
            address_length,
            family,
            port_id,
            groups,
        }
    }

    #[must_use]
    pub(crate) const fn kernel_unicast() -> Self {
        Self::new(SOCKADDR_NL_LENGTH, AF_NETLINK, 0, 0)
    }

    pub(crate) const fn is_kernel_unicast(self) -> bool {
        self.address_length == SOCKADDR_NL_LENGTH
            && self.family == AF_NETLINK
            && self.port_id == 0
            && self.groups == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyRoutingExtendedAck {
    message: Option<Box<str>>,
    offset: Option<u32>,
    unknown_attributes: u8,
}

impl PolicyRoutingExtendedAck {
    #[must_use]
    pub(crate) fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    #[must_use]
    pub(crate) const fn offset(&self) -> Option<u32> {
        self.offset
    }

    #[must_use]
    pub(crate) const fn unknown_attributes(&self) -> u8 {
        self.unknown_attributes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyRoutingAckStatus {
    Accepted,
    Rejected { errno: NonZeroI32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyRoutingAck {
    status: PolicyRoutingAckStatus,
    extended: PolicyRoutingExtendedAck,
}

impl PolicyRoutingAck {
    #[must_use]
    pub(crate) const fn status(&self) -> PolicyRoutingAckStatus {
        self.status
    }

    #[must_use]
    pub(crate) const fn extended(&self) -> &PolicyRoutingExtendedAck {
        &self.extended
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyRoutingAckDecodeErrorKind {
    DatagramTooLarge,
    UnexpectedSender,
    InvalidFrame,
    MissingAck,
    MultipleMessages,
    UnexpectedMessageType,
    UnexpectedSequence,
    UnexpectedPortId,
    InvalidAckFlags,
    TruncatedAck,
    EmbeddedRequestMismatch,
    InvalidErrno,
    UnexpectedAckPayload,
    InvalidExtendedAck,
    TooManyExtendedAckAttributes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PolicyRoutingAckDecodeError {
    kind: PolicyRoutingAckDecodeErrorKind,
    offset: usize,
}

impl PolicyRoutingAckDecodeError {
    const fn new(kind: PolicyRoutingAckDecodeErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    #[must_use]
    pub(crate) const fn kind(self) -> PolicyRoutingAckDecodeErrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }
}

impl fmt::Display for PolicyRoutingAckDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid policy-routing ACK at byte {}: {:?}",
            self.offset, self.kind
        )
    }
}

impl Error for PolicyRoutingAckDecodeError {}

pub(crate) fn decode_policy_routing_ack(
    datagram: &[u8],
    sender: PolicyRoutingAckSender,
    local_port_id: NonZeroU32,
    request: &EncodedPolicyRoutingRequest,
) -> Result<PolicyRoutingAck, PolicyRoutingAckDecodeError> {
    if datagram.len() > MAX_POLICY_ROUTING_ACK_BYTES {
        return Err(PolicyRoutingAckDecodeError::new(
            PolicyRoutingAckDecodeErrorKind::DatagramTooLarge,
            0,
        ));
    }
    if !sender.is_kernel_unicast() {
        return Err(PolicyRoutingAckDecodeError::new(
            PolicyRoutingAckDecodeErrorKind::UnexpectedSender,
            0,
        ));
    }

    let mut messages = NetlinkMessageIter::new(datagram);
    let message = messages
        .next()
        .ok_or_else(|| {
            PolicyRoutingAckDecodeError::new(PolicyRoutingAckDecodeErrorKind::MissingAck, 0)
        })?
        .map_err(|error| {
            PolicyRoutingAckDecodeError::new(
                PolicyRoutingAckDecodeErrorKind::InvalidFrame,
                error.offset(),
            )
        })?;
    if messages.next().is_some() {
        return Err(PolicyRoutingAckDecodeError::new(
            PolicyRoutingAckDecodeErrorKind::MultipleMessages,
            message.offset(),
        ));
    }
    let header = message.header();
    if header.message_type() != NLMSG_ERROR {
        return Err(PolicyRoutingAckDecodeError::new(
            PolicyRoutingAckDecodeErrorKind::UnexpectedMessageType,
            message.offset() + 4,
        ));
    }
    if header.sequence() != request.sequence().get() {
        return Err(PolicyRoutingAckDecodeError::new(
            PolicyRoutingAckDecodeErrorKind::UnexpectedSequence,
            message.offset() + 8,
        ));
    }
    if header.port_id() != local_port_id.get() {
        return Err(PolicyRoutingAckDecodeError::new(
            PolicyRoutingAckDecodeErrorKind::UnexpectedPortId,
            message.offset() + 12,
        ));
    }
    if header.flags() & !(NLM_F_CAPPED | NLM_F_ACK_TLVS) != 0 {
        return Err(PolicyRoutingAckDecodeError::new(
            PolicyRoutingAckDecodeErrorKind::InvalidAckFlags,
            message.offset() + 6,
        ));
    }

    let payload = message.payload();
    if payload.len() < NLMSGERR_HEADER_LENGTH {
        return Err(PolicyRoutingAckDecodeError::new(
            PolicyRoutingAckDecodeErrorKind::TruncatedAck,
            message.offset() + NETLINK_HEADER_LENGTH,
        ));
    }
    let raw_error = read_i32(payload);
    if payload[4..NLMSGERR_HEADER_LENGTH] != request.bytes()[..NETLINK_HEADER_LENGTH] {
        return Err(PolicyRoutingAckDecodeError::new(
            PolicyRoutingAckDecodeErrorKind::EmbeddedRequestMismatch,
            message.offset() + NETLINK_HEADER_LENGTH + 4,
        ));
    }

    let status = if raw_error == 0 {
        PolicyRoutingAckStatus::Accepted
    } else if raw_error > 0 {
        return Err(PolicyRoutingAckDecodeError::new(
            PolicyRoutingAckDecodeErrorKind::InvalidErrno,
            message.offset() + NETLINK_HEADER_LENGTH,
        ));
    } else {
        let errno = raw_error
            .checked_neg()
            .and_then(NonZeroI32::new)
            .ok_or_else(|| {
                PolicyRoutingAckDecodeError::new(
                    PolicyRoutingAckDecodeErrorKind::InvalidErrno,
                    message.offset() + NETLINK_HEADER_LENGTH,
                )
            })?;
        PolicyRoutingAckStatus::Rejected { errno }
    };

    let capped = header.flags() & NLM_F_CAPPED != 0 || raw_error == 0;
    let attributes_start = if capped {
        NLMSGERR_HEADER_LENGTH
    } else {
        let embedded_length = read_u32(&payload[4..]) as usize;
        if embedded_length != request.bytes().len() {
            return Err(PolicyRoutingAckDecodeError::new(
                PolicyRoutingAckDecodeErrorKind::EmbeddedRequestMismatch,
                message.offset() + NETLINK_HEADER_LENGTH + 4,
            ));
        }
        let echoed_end = 4_usize
            .checked_add(align4(embedded_length))
            .ok_or_else(|| {
                PolicyRoutingAckDecodeError::new(
                    PolicyRoutingAckDecodeErrorKind::TruncatedAck,
                    message.offset() + NETLINK_HEADER_LENGTH,
                )
            })?;
        if payload.len() < echoed_end
            || payload[NLMSGERR_HEADER_LENGTH..4 + embedded_length]
                != request.bytes()[NETLINK_HEADER_LENGTH..]
            || payload[4 + embedded_length..echoed_end]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(PolicyRoutingAckDecodeError::new(
                PolicyRoutingAckDecodeErrorKind::EmbeddedRequestMismatch,
                message.offset() + NETLINK_HEADER_LENGTH + NLMSGERR_HEADER_LENGTH,
            ));
        }
        echoed_end
    };

    let attributes = &payload[attributes_start..];
    let has_tlvs = header.flags() & NLM_F_ACK_TLVS != 0;
    if has_tlvs == attributes.is_empty() {
        return Err(PolicyRoutingAckDecodeError::new(
            PolicyRoutingAckDecodeErrorKind::UnexpectedAckPayload,
            message.offset() + NETLINK_HEADER_LENGTH + attributes_start,
        ));
    }

    let mut extended = PolicyRoutingExtendedAck {
        message: None,
        offset: None,
        unknown_attributes: 0,
    };
    let mut attribute_count = 0_usize;
    for attribute in NetlinkAttributeIter::new(
        attributes,
        message.offset() + NETLINK_HEADER_LENGTH + attributes_start,
    ) {
        attribute_count = attribute_count.saturating_add(1);
        if attribute_count > MAX_POLICY_ROUTING_EXT_ACK_ATTRIBUTES {
            return Err(PolicyRoutingAckDecodeError::new(
                PolicyRoutingAckDecodeErrorKind::TooManyExtendedAckAttributes,
                message.offset() + NETLINK_HEADER_LENGTH + attributes_start,
            ));
        }
        let attribute = attribute.map_err(|error| {
            PolicyRoutingAckDecodeError::new(
                PolicyRoutingAckDecodeErrorKind::InvalidExtendedAck,
                error.offset(),
            )
        })?;
        match attribute.attribute_type() {
            NLMSGERR_ATTR_MSG => {
                if attribute.flags() != 0
                    || extended.message.is_some()
                    || attribute.value().is_empty()
                    || attribute.value().len() > MAX_POLICY_ROUTING_EXT_ACK_MESSAGE_BYTES + 1
                    || attribute.value().last() != Some(&0)
                    || attribute.value()[..attribute.value().len() - 1].contains(&0)
                {
                    return Err(PolicyRoutingAckDecodeError::new(
                        PolicyRoutingAckDecodeErrorKind::InvalidExtendedAck,
                        attribute.value_offset(),
                    ));
                }
                let message =
                    std::str::from_utf8(&attribute.value()[..attribute.value().len() - 1])
                        .map_err(|_| {
                            PolicyRoutingAckDecodeError::new(
                                PolicyRoutingAckDecodeErrorKind::InvalidExtendedAck,
                                attribute.value_offset(),
                            )
                        })?;
                extended.message = Some(Box::from(message));
            }
            NLMSGERR_ATTR_OFFS => {
                if attribute.flags() != 0
                    || extended.offset.is_some()
                    || attribute.value().len() != 4
                {
                    return Err(PolicyRoutingAckDecodeError::new(
                        PolicyRoutingAckDecodeErrorKind::InvalidExtendedAck,
                        attribute.value_offset(),
                    ));
                }
                let offset = read_u32(attribute.value());
                if offset >= request.bytes().len() as u32 {
                    return Err(PolicyRoutingAckDecodeError::new(
                        PolicyRoutingAckDecodeErrorKind::InvalidExtendedAck,
                        attribute.value_offset(),
                    ));
                }
                extended.offset = Some(offset);
            }
            _ => {
                extended.unknown_attributes =
                    extended.unknown_attributes.checked_add(1).ok_or_else(|| {
                        PolicyRoutingAckDecodeError::new(
                            PolicyRoutingAckDecodeErrorKind::TooManyExtendedAckAttributes,
                            attribute.offset(),
                        )
                    })?;
            }
        }
    }

    Ok(PolicyRoutingAck { status, extended })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ManagedObjectObservation {
    exact_count: usize,
    conflict_count: usize,
}

impl ManagedObjectObservation {
    #[must_use]
    pub(crate) const fn exact_count(self) -> usize {
        self.exact_count
    }

    #[must_use]
    pub(crate) const fn conflict_count(self) -> usize {
        self.conflict_count
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ManagedPolicyRoutingObservation {
    route: ManagedObjectObservation,
    rule: ManagedObjectObservation,
}

impl ManagedPolicyRoutingObservation {
    #[must_use]
    pub(crate) const fn route(self) -> ManagedObjectObservation {
        self.route
    }

    #[must_use]
    pub(crate) const fn rule(self) -> ManagedObjectObservation {
        self.rule
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyRoutingReadbackErrorKind {
    DumpBytesExceeded,
    TooManyMessages,
    InvalidRouteFrame,
    InvalidRuleFrame,
    TooManyEvents,
    RouteDecode(RouteEventDecodeErrorKind),
    RuleDecode(RuleEventDecodeErrorKind),
    MissingRouteCompletion,
    MissingRuleCompletion,
    UnexpectedRouteSequence,
    UnexpectedRuleSequence,
    RouteRemovalInDump,
    RuleRemovalInDump,
    RawProjectionMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PolicyRoutingReadbackError {
    kind: PolicyRoutingReadbackErrorKind,
    offset: usize,
}

impl PolicyRoutingReadbackError {
    const fn new(kind: PolicyRoutingReadbackErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    #[must_use]
    pub(crate) const fn kind(self) -> PolicyRoutingReadbackErrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }
}

impl fmt::Display for PolicyRoutingReadbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid policy-routing readback at byte {}: {:?}",
            self.offset, self.kind
        )
    }
}

impl Error for PolicyRoutingReadbackError {}

pub(crate) fn observe_managed_policy_routing(
    identity: ManagedPolicyRoutingIdentity,
    route_dump: &[u8],
    route_sequence: NonZeroU32,
    rule_dump: &[u8],
    rule_sequence: NonZeroU32,
) -> Result<ManagedPolicyRoutingObservation, PolicyRoutingReadbackError> {
    if route_dump
        .len()
        .checked_add(rule_dump.len())
        .is_none_or(|bytes| bytes > MAX_POLICY_ROUTING_READBACK_BYTES)
    {
        return Err(PolicyRoutingReadbackError::new(
            PolicyRoutingReadbackErrorKind::DumpBytesExceeded,
            0,
        ));
    }
    let route_counts = preflight_route_event_count(route_dump)?;
    let rule_counts = preflight_rule_event_count(rule_dump)?;
    if route_counts
        .messages
        .checked_add(rule_counts.messages)
        .is_none_or(|count| count > MAX_POLICY_ROUTING_READBACK_MESSAGES)
    {
        return Err(PolicyRoutingReadbackError::new(
            PolicyRoutingReadbackErrorKind::TooManyMessages,
            0,
        ));
    }
    if route_counts
        .events
        .checked_add(rule_counts.events)
        .is_none_or(|count| count > MAX_POLICY_ROUTING_READBACK_EVENTS)
    {
        return Err(PolicyRoutingReadbackError::new(
            PolicyRoutingReadbackErrorKind::TooManyEvents,
            0,
        ));
    }

    let route_datagram = RtnetlinkRouteEventDecoder::new(true)
        .decode_datagram(route_dump)
        .map_err(|error| {
            PolicyRoutingReadbackError::new(
                PolicyRoutingReadbackErrorKind::RouteDecode(error.kind()),
                error.offset(),
            )
        })?;
    require_complete_dump(
        route_datagram.sequence(),
        route_datagram.completion().is_some(),
        route_sequence,
        PolicyRoutingReadbackErrorKind::MissingRouteCompletion,
        PolicyRoutingReadbackErrorKind::UnexpectedRouteSequence,
    )?;
    if route_datagram
        .events()
        .iter()
        .any(|event| matches!(event, InterfaceRouteEvent::Remove(_)))
    {
        return Err(PolicyRoutingReadbackError::new(
            PolicyRoutingReadbackErrorKind::RouteRemovalInDump,
            0,
        ));
    }

    let rule_datagram = RtnetlinkRuleEventDecoder::new(true)
        .decode_datagram(rule_dump)
        .map_err(|error| {
            PolicyRoutingReadbackError::new(
                PolicyRoutingReadbackErrorKind::RuleDecode(error.kind()),
                error.offset(),
            )
        })?;
    require_complete_dump(
        rule_datagram.sequence(),
        rule_datagram.completion().is_some(),
        rule_sequence,
        PolicyRoutingReadbackErrorKind::MissingRuleCompletion,
        PolicyRoutingReadbackErrorKind::UnexpectedRuleSequence,
    )?;
    if rule_datagram
        .events()
        .iter()
        .any(|event| matches!(event, NetworkRuleEvent::Remove(_)))
    {
        return Err(PolicyRoutingReadbackError::new(
            PolicyRoutingReadbackErrorKind::RuleRemovalInDump,
            0,
        ));
    }

    let expected_route = expected_route_record(identity.route());
    let semantic_route_exact = route_datagram
        .events()
        .iter()
        .filter(|event| {
            matches!(
                event,
                InterfaceRouteEvent::Upsert {
                    record,
                    replace: false,
                } if record == &expected_route
            )
        })
        .count();
    let expected_rule = expected_rule_record(identity.rule());
    let semantic_rule_exact = rule_datagram
        .events()
        .iter()
        .filter(
            |event| matches!(event, NetworkRuleEvent::Upsert(record) if record == &expected_rule),
        )
        .count();

    let route = observe_raw_routes(route_dump, identity.route())?;
    let rule = observe_raw_rules(rule_dump, identity.rule())?;
    if route.exact_count > semantic_route_exact || rule.exact_count > semantic_rule_exact {
        return Err(PolicyRoutingReadbackError::new(
            PolicyRoutingReadbackErrorKind::RawProjectionMismatch,
            0,
        ));
    }

    Ok(ManagedPolicyRoutingObservation { route, rule })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PolicyRoutingReadbackCounts {
    messages: usize,
    events: usize,
}

fn preflight_route_event_count(
    dump: &[u8],
) -> Result<PolicyRoutingReadbackCounts, PolicyRoutingReadbackError> {
    preflight_event_count(
        dump,
        RTM_NEWROUTE,
        RTM_DELROUTE,
        PolicyRoutingReadbackErrorKind::InvalidRouteFrame,
    )
}

fn preflight_rule_event_count(
    dump: &[u8],
) -> Result<PolicyRoutingReadbackCounts, PolicyRoutingReadbackError> {
    preflight_event_count(
        dump,
        RTM_NEWRULE,
        RTM_DELRULE,
        PolicyRoutingReadbackErrorKind::InvalidRuleFrame,
    )
}

fn preflight_event_count(
    dump: &[u8],
    upsert_type: u16,
    remove_type: u16,
    frame_error: PolicyRoutingReadbackErrorKind,
) -> Result<PolicyRoutingReadbackCounts, PolicyRoutingReadbackError> {
    let mut counts = PolicyRoutingReadbackCounts::default();
    for message in NetlinkMessageIter::new(dump) {
        let message = message
            .map_err(|error| PolicyRoutingReadbackError::new(frame_error, error.offset()))?;
        counts.messages = counts.messages.saturating_add(1);
        if counts.messages > MAX_POLICY_ROUTING_READBACK_MESSAGES {
            return Err(PolicyRoutingReadbackError::new(
                PolicyRoutingReadbackErrorKind::TooManyMessages,
                message.offset(),
            ));
        }
        if matches!(message.header().message_type(), kind if kind == upsert_type || kind == remove_type)
        {
            counts.events = counts.events.saturating_add(1);
            if counts.events > MAX_POLICY_ROUTING_READBACK_EVENTS {
                return Err(PolicyRoutingReadbackError::new(
                    PolicyRoutingReadbackErrorKind::TooManyEvents,
                    message.offset(),
                ));
            }
        }
    }
    Ok(counts)
}

fn require_complete_dump(
    actual_sequence: Option<u32>,
    has_completion: bool,
    expected_sequence: NonZeroU32,
    missing_completion: PolicyRoutingReadbackErrorKind,
    unexpected_sequence: PolicyRoutingReadbackErrorKind,
) -> Result<(), PolicyRoutingReadbackError> {
    if !has_completion {
        return Err(PolicyRoutingReadbackError::new(missing_completion, 0));
    }
    if actual_sequence != Some(expected_sequence.get()) {
        return Err(PolicyRoutingReadbackError::new(unexpected_sequence, 0));
    }
    Ok(())
}

fn expected_route_record(identity: ManagedLocalRouteIdentity) -> NetworkRouteRecord {
    let record = NetworkRouteRecord::new(
        identity.destination(),
        RoutePrefix::unspecified(identity.family()),
        RouteProperties::new(
            0,
            identity.table(),
            identity.protocol(),
            identity.scope(),
            identity.route_type(),
            RouteFlags::from_raw(0),
        ),
        identity.metric().get(),
        RoutePath::Single {
            output_interface: Some(identity.output_interface()),
            gateway: None,
        },
    )
    .expect("validated managed route identity forms a canonical route record");
    if identity.family() == NetworkAddressFamily::Ipv6 {
        record
            .with_preference(RoutePreference::from_raw(IPV6_ROUTE_PREFERENCE_MEDIUM))
            .expect("IPv6 managed route accepts the kernel-canonical preference")
    } else {
        record
    }
}

fn expected_rule_record(identity: ManagedFwmarkRuleIdentity) -> NetworkRuleRecord {
    NetworkRuleRecord::new(
        RulePrefix::unspecified(identity.family()),
        RulePrefix::unspecified(identity.family()),
        RuleProperties::new(
            0,
            RuleTableId::from_raw(identity.table().get()),
            RuleAction::TO_TABLE,
            identity.protocol(),
            RuleFlags::from_raw(0),
        ),
        identity.priority(),
        None,
    )
    .expect("validated managed rule identity forms a canonical rule record")
    .with_fwmark(identity.mark())
}

fn observe_raw_routes(
    dump: &[u8],
    identity: ManagedLocalRouteIdentity,
) -> Result<ManagedObjectObservation, PolicyRoutingReadbackError> {
    let mut candidate_count = 0_usize;
    let mut exact_count = 0_usize;
    for message in NetlinkMessageIter::new(dump) {
        let message = message.map_err(|error| {
            PolicyRoutingReadbackError::new(
                PolicyRoutingReadbackErrorKind::InvalidRouteFrame,
                error.offset(),
            )
        })?;
        let message_type = message.header().message_type();
        if !matches!(message_type, RTM_NEWROUTE | RTM_DELROUTE) {
            continue;
        }
        let body = message.payload();
        if body.len() < ROUTING_HEADER_LENGTH {
            return Err(PolicyRoutingReadbackError::new(
                PolicyRoutingReadbackErrorKind::RawProjectionMismatch,
                message.offset() + NETLINK_HEADER_LENGTH,
            ));
        }
        let Some(family) = decode_family_byte(body[0]) else {
            continue;
        };
        if message_type == RTM_DELROUTE {
            return Err(PolicyRoutingReadbackError::new(
                PolicyRoutingReadbackErrorKind::RouteRemovalInDump,
                message.offset(),
            ));
        }

        let mut table = None;
        let mut output_interface = None;
        let mut metric = None;
        let mut preference = None;
        let mut exact_attributes = true;
        for attribute in NetlinkAttributeIter::new(
            &body[ROUTING_HEADER_LENGTH..],
            message.offset() + NETLINK_HEADER_LENGTH + ROUTING_HEADER_LENGTH,
        ) {
            let attribute = attribute.map_err(|error| {
                PolicyRoutingReadbackError::new(
                    PolicyRoutingReadbackErrorKind::RawProjectionMismatch,
                    error.offset(),
                )
            })?;
            if attribute.flags() != 0 {
                exact_attributes = false;
            }
            match attribute.attribute_type() {
                RTA_TABLE => {
                    if table.is_some() || attribute.value().len() != 4 {
                        exact_attributes = false;
                    } else {
                        table = Some(read_u32(attribute.value()));
                    }
                }
                RTA_OIF => {
                    if output_interface.is_some() || attribute.value().len() != 4 {
                        exact_attributes = false;
                    } else {
                        output_interface = Some(read_u32(attribute.value()));
                    }
                }
                RTA_PRIORITY => {
                    if metric.is_some() || attribute.value().len() != 4 {
                        exact_attributes = false;
                    } else {
                        metric = Some(read_u32(attribute.value()));
                    }
                }
                RTA_PREF => {
                    if preference.is_some() || attribute.value().len() != 1 {
                        exact_attributes = false;
                    } else {
                        preference = Some(attribute.value()[0]);
                    }
                }
                RTA_METRICS => {
                    if !attribute.value().is_empty() {
                        exact_attributes = false;
                    }
                }
                RTA_CACHEINFO | RTA_PAD => {}
                _ => exact_attributes = false,
            }
        }

        let effective_table = table.unwrap_or(u32::from(body[4]));
        if family != identity.family() || effective_table != identity.table().get() {
            continue;
        }
        candidate_count = candidate_count.saturating_add(1);
        let exact_header = message.header().flags() & NLM_F_REPLACE == 0
            && body[0] == family_byte(identity.family())
            && body[1] == identity.destination().prefix_length()
            && body[2] == 0
            && body[3] == 0
            && body[4] == dump_table_byte(identity.table())
            && body[5] == identity.protocol().raw()
            && body[6] == identity.scope().raw()
            && body[7] == identity.route_type().raw()
            && read_u32(&body[8..]) == 0;
        if exact_header
            && exact_attributes
            && table == Some(identity.table().get())
            && output_interface == Some(identity.output_interface().get())
            && metric == Some(identity.metric().get())
            && match identity.family() {
                NetworkAddressFamily::Ipv4 => preference.is_none(),
                NetworkAddressFamily::Ipv6 => preference == Some(IPV6_ROUTE_PREFERENCE_MEDIUM),
            }
        {
            exact_count = exact_count.saturating_add(1);
        }
    }

    Ok(ManagedObjectObservation {
        exact_count,
        conflict_count: candidate_count.saturating_sub(exact_count),
    })
}

fn observe_raw_rules(
    dump: &[u8],
    identity: ManagedFwmarkRuleIdentity,
) -> Result<ManagedObjectObservation, PolicyRoutingReadbackError> {
    let mut candidate_count = 0_usize;
    let mut exact_count = 0_usize;
    for message in NetlinkMessageIter::new(dump) {
        let message = message.map_err(|error| {
            PolicyRoutingReadbackError::new(
                PolicyRoutingReadbackErrorKind::InvalidRuleFrame,
                error.offset(),
            )
        })?;
        let message_type = message.header().message_type();
        if !matches!(message_type, RTM_NEWRULE | RTM_DELRULE) {
            continue;
        }
        let body = message.payload();
        if body.len() < ROUTING_HEADER_LENGTH {
            return Err(PolicyRoutingReadbackError::new(
                PolicyRoutingReadbackErrorKind::RawProjectionMismatch,
                message.offset() + NETLINK_HEADER_LENGTH,
            ));
        }
        let Some(family) = decode_family_byte(body[0]) else {
            continue;
        };
        if message_type == RTM_DELRULE {
            return Err(PolicyRoutingReadbackError::new(
                PolicyRoutingReadbackErrorKind::RuleRemovalInDump,
                message.offset(),
            ));
        }

        let mut table = None;
        let mut priority = None;
        let mut fwmark = None;
        let mut fwmask = None;
        let mut protocol = None;
        let mut suppress_prefix_length = None;
        let mut exact_attributes = true;
        for attribute in NetlinkAttributeIter::new(
            &body[ROUTING_HEADER_LENGTH..],
            message.offset() + NETLINK_HEADER_LENGTH + ROUTING_HEADER_LENGTH,
        ) {
            let attribute = attribute.map_err(|error| {
                PolicyRoutingReadbackError::new(
                    PolicyRoutingReadbackErrorKind::RawProjectionMismatch,
                    error.offset(),
                )
            })?;
            if attribute.flags() != 0 {
                exact_attributes = false;
            }
            match attribute.attribute_type() {
                FRA_TABLE => {
                    if table.is_some() || attribute.value().len() != 4 {
                        exact_attributes = false;
                    } else {
                        table = Some(read_u32(attribute.value()));
                    }
                }
                FRA_PRIORITY => {
                    if priority.is_some() || attribute.value().len() != 4 {
                        exact_attributes = false;
                    } else {
                        priority = Some(read_u32(attribute.value()));
                    }
                }
                FRA_FWMARK => {
                    if fwmark.is_some() || attribute.value().len() != 4 {
                        exact_attributes = false;
                    } else {
                        fwmark = Some(read_u32(attribute.value()));
                    }
                }
                FRA_FWMASK => {
                    if fwmask.is_some() || attribute.value().len() != 4 {
                        exact_attributes = false;
                    } else {
                        fwmask = Some(read_u32(attribute.value()));
                    }
                }
                FRA_PROTOCOL => {
                    if protocol.is_some() || attribute.value().len() != 1 {
                        exact_attributes = false;
                    } else {
                        protocol = Some(attribute.value()[0]);
                    }
                }
                FRA_SUPPRESS_PREFIXLEN => {
                    if suppress_prefix_length.is_some() || attribute.value().len() != 4 {
                        exact_attributes = false;
                    } else {
                        suppress_prefix_length = Some(read_u32(attribute.value()));
                    }
                }
                FRA_PAD => {}
                _ => exact_attributes = false,
            }
        }

        let effective_table = table.unwrap_or(u32::from(body[4]));
        let effective_priority = priority.unwrap_or(0);
        if family != identity.family()
            || (effective_priority != identity.priority().get()
                && effective_table != identity.table().get())
        {
            continue;
        }
        candidate_count = candidate_count.saturating_add(1);
        let exact_header = body[0] == family_byte(identity.family())
            && body[1] == 0
            && body[2] == 0
            && body[3] == 0
            && body[4] == dump_table_byte(identity.table())
            && body[5] == 0
            && body[6] == 0
            && body[7] == FR_ACT_TO_TBL
            && read_u32(&body[8..]) == 0;
        if exact_header
            && exact_attributes
            && table == Some(identity.table().get())
            && priority == Some(identity.priority().get())
            && fwmark == Some(identity.mark().value())
            && fwmask == Some(identity.mark().mask())
            && protocol == Some(identity.protocol().raw())
            && suppress_prefix_length == Some(u32::MAX)
        {
            exact_count = exact_count.saturating_add(1);
        }
    }

    Ok(ManagedObjectObservation {
        exact_count,
        conflict_count: candidate_count.saturating_sub(exact_count),
    })
}

const fn decode_family_byte(raw: u8) -> Option<NetworkAddressFamily> {
    match raw {
        AF_INET => Some(NetworkAddressFamily::Ipv4),
        AF_INET6 => Some(NetworkAddressFamily::Ipv6),
        _ => None,
    }
}

const fn canonical_route_scope(family: NetworkAddressFamily) -> RouteScope {
    match family {
        NetworkAddressFamily::Ipv4 => RouteScope::from_raw(RT_SCOPE_HOST),
        NetworkAddressFamily::Ipv6 => RouteScope::from_raw(RT_SCOPE_UNIVERSE),
    }
}

const fn restore_family(family: XtablesRestoreFamily) -> NetworkAddressFamily {
    match family {
        XtablesRestoreFamily::Ipv4 => NetworkAddressFamily::Ipv4,
        XtablesRestoreFamily::Ipv6 => NetworkAddressFamily::Ipv6,
    }
}

const fn family_byte(family: NetworkAddressFamily) -> u8 {
    match family {
        NetworkAddressFamily::Ipv4 => AF_INET,
        NetworkAddressFamily::Ipv6 => AF_INET6,
    }
}

fn request_table_byte(table: RouteTableId) -> u8 {
    u8::try_from(table.get()).unwrap_or(RT_TABLE_UNSPEC)
}

fn dump_table_byte(table: RouteTableId) -> u8 {
    u8::try_from(table.get()).unwrap_or(RT_TABLE_COMPAT)
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes[..2].try_into().expect("validated u16 field"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes[..4].try_into().expect("validated u32 field"))
}

fn read_i32(bytes: &[u8]) -> i32 {
    i32::from_ne_bytes(bytes[..4].try_into().expect("validated i32 field"))
}

#[cfg(test)]
pub(super) fn test_managed_policy_routing_identity(
    family: NetworkAddressFamily,
) -> ManagedPolicyRoutingIdentity {
    let loopback_index = InterfaceIndex::new(1).expect("test loopback index");
    ManagedPolicyRoutingIdentity {
        family,
        loopback: ManagedInterfaceIdentity {
            name: InterfaceName::new(b"lo").expect("test loopback name"),
            index: loopback_index,
        },
        route: ManagedLocalRouteIdentity {
            family,
            destination: RoutePrefix::unspecified(family),
            table: RouteTableId::from_raw(20_253),
            protocol: RouteProtocol::from_raw(4),
            scope: canonical_route_scope(family),
            route_type: RouteType::from_raw(RTN_LOCAL),
            metric: NonZeroU32::new(1_024).expect("test route metric"),
            output_interface: loopback_index,
        },
        rule: ManagedFwmarkRuleIdentity {
            family,
            priority: RulePriority::from_raw(30_999),
            table: RouteTableId::from_raw(20_253),
            mark: RuleFwMark::new(0x0020_0000, 0x0060_0000).expect("test fwmark"),
            protocol: RuleProtocol::from_raw(99),
        },
    }
}

#[cfg(test)]
#[path = "policy_routing_tests.rs"]
mod tests;
