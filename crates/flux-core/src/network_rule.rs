use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU8, NonZeroU32, NonZeroU64};

use crate::{InterfaceName, NetworkAddressFamily};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RulePrefix {
    address: IpAddr,
    prefix_length: u8,
}

impl RulePrefix {
    pub fn new(address: IpAddr, prefix_length: u8) -> Result<Self, RulePrefixError> {
        let family = address_family(address);
        if prefix_length > maximum_prefix_length(family) {
            return Err(RulePrefixError::new(
                RulePrefixErrorKind::InvalidPrefixLength,
                address,
                prefix_length,
            ));
        }

        Ok(Self {
            address: canonical_network_address(address, prefix_length),
            prefix_length,
        })
    }

    #[must_use]
    pub const fn unspecified(family: NetworkAddressFamily) -> Self {
        match family {
            NetworkAddressFamily::Ipv4 => Self {
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_length: 0,
            },
            NetworkAddressFamily::Ipv6 => Self {
                address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                prefix_length: 0,
            },
        }
    }

    #[must_use]
    pub const fn family(self) -> NetworkAddressFamily {
        address_family(self.address)
    }

    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    #[must_use]
    pub const fn prefix_length(self) -> u8 {
        self.prefix_length
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RulePrefixErrorKind {
    InvalidPrefixLength,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RulePrefixError {
    kind: RulePrefixErrorKind,
    address: IpAddr,
    prefix_length: u8,
}

impl RulePrefixError {
    const fn new(kind: RulePrefixErrorKind, address: IpAddr, prefix_length: u8) -> Self {
        Self {
            kind,
            address,
            prefix_length,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> RulePrefixErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn address(&self) -> IpAddr {
        self.address
    }

    #[must_use]
    pub const fn prefix_length(&self) -> u8 {
        self.prefix_length
    }
}

impl fmt::Display for RulePrefixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            RulePrefixErrorKind::InvalidPrefixLength => write!(
                formatter,
                "prefix length {} is invalid for policy-rule prefix {}",
                self.prefix_length, self.address
            ),
        }
    }
}

impl Error for RulePrefixError {}

macro_rules! raw_u8_wrapper {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(u8);

        impl $name {
            #[must_use]
            pub const fn from_raw(value: u8) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn raw(self) -> u8 {
                self.0
            }
        }
    };
}

raw_u8_wrapper!(RuleAction);
raw_u8_wrapper!(RuleProtocol);

impl RuleAction {
    pub const UNSPECIFIED: Self = Self(0);
    pub const TO_TABLE: Self = Self(1);
    pub const GOTO: Self = Self(2);
    pub const NOP: Self = Self(3);
    pub const BLACKHOLE: Self = Self(6);
    pub const UNREACHABLE: Self = Self(7);
    pub const PROHIBIT: Self = Self(8);
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RuleTableId(u32);

impl RuleTableId {
    #[must_use]
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RulePriority(u32);

impl RulePriority {
    #[must_use]
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RuleFlags(u32);

impl RuleFlags {
    pub const PERMANENT: Self = Self(0x0000_0001);
    pub const INVERT: Self = Self(0x0000_0002);
    pub const UNRESOLVED: Self = Self(0x0000_0004);
    pub const INPUT_INTERFACE_DETACHED: Self = Self(0x0000_0008);
    pub const OUTPUT_INTERFACE_DETACHED: Self = Self(0x0000_0010);
    pub const FIND_SOURCE_ADDRESS: Self = Self(0x0001_0000);

    #[must_use]
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuleProperties {
    tos: u8,
    table: RuleTableId,
    action: RuleAction,
    protocol: RuleProtocol,
    flags: RuleFlags,
}

impl RuleProperties {
    #[must_use]
    pub const fn new(
        tos: u8,
        table: RuleTableId,
        action: RuleAction,
        protocol: RuleProtocol,
        flags: RuleFlags,
    ) -> Self {
        Self {
            tos,
            table,
            action,
            protocol,
            flags,
        }
    }

    #[must_use]
    pub const fn tos(self) -> u8 {
        self.tos
    }

    #[must_use]
    pub const fn table(self) -> RuleTableId {
        self.table
    }

    #[must_use]
    pub const fn action(self) -> RuleAction {
        self.action
    }

    #[must_use]
    pub const fn protocol(self) -> RuleProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn flags(self) -> RuleFlags {
        self.flags
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuleFwMark {
    value: u32,
    mask: u32,
}

impl RuleFwMark {
    /// Constructs the effective masked selector; semantically inert selectors are absent.
    #[must_use]
    pub const fn new(value: u32, mask: u32) -> Option<Self> {
        let value = value & mask;
        if value == 0 && mask == 0 {
            None
        } else {
            Some(Self { value, mask })
        }
    }

    #[must_use]
    pub const fn value(self) -> u32 {
        self.value
    }

    #[must_use]
    pub const fn mask(self) -> u32 {
        self.mask
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RuleTunnelId(NonZeroU64);

impl RuleTunnelId {
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RuleIpProtocol(NonZeroU8);

impl RuleIpProtocol {
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        match NonZeroU8::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u8 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RuleFlowId(NonZeroU32);

impl RuleFlowId {
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RuleSuppressInterfaceGroup(u32);

impl RuleSuppressInterfaceGroup {
    /// Converts the kernel value, mapping its all-ones disabled sentinel to absence.
    #[must_use]
    pub const fn from_raw(value: u32) -> Option<Self> {
        if value == u32::MAX {
            None
        } else {
            Some(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RuleSuppressPrefixLength(u32);

impl RuleSuppressPrefixLength {
    /// Converts the kernel value, mapping its all-ones disabled sentinel to absence.
    #[must_use]
    pub const fn from_raw(value: u32) -> Option<Self> {
        if value == u32::MAX {
            None
        } else {
            Some(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuleUidRange {
    start: u32,
    end: u32,
}

impl RuleUidRange {
    pub fn new(start: u32, end: u32) -> Result<Self, RuleUidRangeError> {
        if start == u32::MAX || end == u32::MAX {
            return Err(RuleUidRangeError::new(
                RuleUidRangeErrorKind::InvalidUid,
                start,
                end,
            ));
        }
        if start > end {
            return Err(RuleUidRangeError::new(
                RuleUidRangeErrorKind::StartAfterEnd,
                start,
                end,
            ));
        }
        Ok(Self { start, end })
    }

    #[must_use]
    pub const fn start(self) -> u32 {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> u32 {
        self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleUidRangeErrorKind {
    InvalidUid,
    StartAfterEnd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleUidRangeError {
    kind: RuleUidRangeErrorKind,
    start: u32,
    end: u32,
}

impl RuleUidRangeError {
    const fn new(kind: RuleUidRangeErrorKind, start: u32, end: u32) -> Self {
        Self { kind, start, end }
    }

    #[must_use]
    pub const fn kind(self) -> RuleUidRangeErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn start(self) -> u32 {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> u32 {
        self.end
    }
}

impl fmt::Display for RuleUidRangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            RuleUidRangeErrorKind::InvalidUid => write!(
                formatter,
                "policy-rule UID range {}..={} contains the reserved invalid UID",
                self.start, self.end
            ),
            RuleUidRangeErrorKind::StartAfterEnd => write!(
                formatter,
                "policy-rule UID range starts at {} after ending at {}",
                self.start, self.end
            ),
        }
    }
}

impl Error for RuleUidRangeError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RulePortRange {
    start: u16,
    end: u16,
}

impl RulePortRange {
    pub fn new(start: u16, end: u16) -> Result<Self, RulePortRangeError> {
        if start == 0 || end == 0 {
            return Err(RulePortRangeError::new(
                RulePortRangeErrorKind::ZeroPort,
                start,
                end,
            ));
        }
        if end == u16::MAX {
            return Err(RulePortRangeError::new(
                RulePortRangeErrorKind::MaximumPort,
                start,
                end,
            ));
        }
        if start > end {
            return Err(RulePortRangeError::new(
                RulePortRangeErrorKind::StartAfterEnd,
                start,
                end,
            ));
        }
        Ok(Self { start, end })
    }

    #[must_use]
    pub const fn start(self) -> u16 {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> u16 {
        self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RulePortRangeErrorKind {
    ZeroPort,
    MaximumPort,
    StartAfterEnd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RulePortRangeError {
    kind: RulePortRangeErrorKind,
    start: u16,
    end: u16,
}

impl RulePortRangeError {
    const fn new(kind: RulePortRangeErrorKind, start: u16, end: u16) -> Self {
        Self { kind, start, end }
    }

    #[must_use]
    pub const fn kind(self) -> RulePortRangeErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn start(self) -> u16 {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> u16 {
        self.end
    }
}

impl fmt::Display for RulePortRangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            RulePortRangeErrorKind::ZeroPort => write!(
                formatter,
                "policy-rule port range {}..={} contains port zero",
                self.start, self.end
            ),
            RulePortRangeErrorKind::MaximumPort => write!(
                formatter,
                "policy-rule port range {}..={} contains reserved maximum port",
                self.start, self.end
            ),
            RulePortRangeErrorKind::StartAfterEnd => write!(
                formatter,
                "policy-rule port range starts at {} after ending at {}",
                self.start, self.end
            ),
        }
    }
}

impl Error for RulePortRangeError {}

/// Canonical policy-rule selection facts.
///
/// Prefix host bits and firewall-mark bits outside the mask are normalized away. Exact future
/// deletion therefore needs a separate kernel identity rather than treating this projection as
/// a byte-for-byte copy of the rule that produced it. Linux rule lists are ordered multisets:
/// consumers must preserve both dump order and duplicate records rather than treating these facts
/// as a set or sorting solely by priority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkRuleRecord {
    destination: RulePrefix,
    source: RulePrefix,
    properties: RuleProperties,
    priority: RulePriority,
    goto_target: Option<RulePriority>,
    fwmark: Option<RuleFwMark>,
    input_interface: Option<InterfaceName>,
    output_interface: Option<InterfaceName>,
    tunnel_id: Option<RuleTunnelId>,
    suppress_interface_group: Option<RuleSuppressInterfaceGroup>,
    suppress_prefix_length: Option<RuleSuppressPrefixLength>,
    l3mdev: bool,
    uid_range: Option<RuleUidRange>,
    ip_protocol: Option<RuleIpProtocol>,
    source_port_range: Option<RulePortRange>,
    destination_port_range: Option<RulePortRange>,
    flow: Option<RuleFlowId>,
}

impl NetworkRuleRecord {
    pub fn new(
        destination: RulePrefix,
        source: RulePrefix,
        properties: RuleProperties,
        priority: RulePriority,
        goto_target: Option<RulePriority>,
    ) -> Result<Self, NetworkRuleRecordError> {
        let family = destination.family();
        if source.family() != family {
            return Err(NetworkRuleRecordError::new(
                NetworkRuleRecordErrorKind::AddressFamilyMismatch,
            ));
        }
        if family == NetworkAddressFamily::Ipv4 && properties.tos() & !IPV4_TOS_MASK != 0 {
            return Err(NetworkRuleRecordError::new(
                NetworkRuleRecordErrorKind::InvalidIpv4Tos,
            ));
        }
        match (properties.action() == RuleAction::GOTO, goto_target) {
            (true, None) => {
                return Err(NetworkRuleRecordError::new(
                    NetworkRuleRecordErrorKind::MissingGotoTarget,
                ));
            }
            (false, Some(_)) => {
                return Err(NetworkRuleRecordError::new(
                    NetworkRuleRecordErrorKind::UnexpectedGotoTarget,
                ));
            }
            (true, Some(target)) if target <= priority => {
                return Err(NetworkRuleRecordError::new(
                    NetworkRuleRecordErrorKind::BackwardGoto,
                ));
            }
            (true, Some(_)) | (false, None) => {}
        }

        Ok(Self {
            destination,
            source,
            properties,
            priority,
            goto_target,
            fwmark: None,
            input_interface: None,
            output_interface: None,
            tunnel_id: None,
            suppress_interface_group: None,
            suppress_prefix_length: None,
            l3mdev: false,
            uid_range: None,
            ip_protocol: None,
            source_port_range: None,
            destination_port_range: None,
            flow: None,
        })
    }

    #[must_use]
    pub fn with_fwmark(mut self, fwmark: RuleFwMark) -> Self {
        self.fwmark = Some(fwmark);
        self
    }

    #[must_use]
    pub fn with_input_interface(mut self, interface: InterfaceName) -> Self {
        self.input_interface = Some(interface);
        self
    }

    #[must_use]
    pub fn with_output_interface(mut self, interface: InterfaceName) -> Self {
        self.output_interface = Some(interface);
        self
    }

    #[must_use]
    pub fn with_tunnel_id(mut self, tunnel_id: RuleTunnelId) -> Self {
        self.tunnel_id = Some(tunnel_id);
        self
    }

    #[must_use]
    pub fn with_suppress_interface_group(mut self, group: RuleSuppressInterfaceGroup) -> Self {
        self.suppress_interface_group = Some(group);
        self
    }

    #[must_use]
    pub fn with_suppress_prefix_length(mut self, prefix_length: RuleSuppressPrefixLength) -> Self {
        self.suppress_prefix_length = Some(prefix_length);
        self
    }

    pub fn with_l3mdev(mut self) -> Result<Self, NetworkRuleRecordError> {
        if self.properties.table().get() != 0 {
            return Err(NetworkRuleRecordError::new(
                NetworkRuleRecordErrorKind::L3mdevTableConflict,
            ));
        }
        self.l3mdev = true;
        Ok(self)
    }

    #[must_use]
    pub fn with_uid_range(mut self, uid_range: RuleUidRange) -> Self {
        self.uid_range = Some(uid_range);
        self
    }

    #[must_use]
    pub fn with_ip_protocol(mut self, protocol: RuleIpProtocol) -> Self {
        self.ip_protocol = Some(protocol);
        self
    }

    #[must_use]
    pub fn with_source_port_range(mut self, range: RulePortRange) -> Self {
        self.source_port_range = Some(range);
        self
    }

    #[must_use]
    pub fn with_destination_port_range(mut self, range: RulePortRange) -> Self {
        self.destination_port_range = Some(range);
        self
    }

    pub fn with_flow(mut self, flow: RuleFlowId) -> Result<Self, NetworkRuleRecordError> {
        if self.destination.family() != NetworkAddressFamily::Ipv4 {
            return Err(NetworkRuleRecordError::new(
                NetworkRuleRecordErrorKind::FlowUnsupported,
            ));
        }
        self.flow = Some(flow);
        Ok(self)
    }

    #[must_use]
    pub const fn destination(&self) -> RulePrefix {
        self.destination
    }

    #[must_use]
    pub const fn source(&self) -> RulePrefix {
        self.source
    }

    #[must_use]
    pub const fn properties(&self) -> RuleProperties {
        self.properties
    }

    #[must_use]
    pub const fn priority(&self) -> RulePriority {
        self.priority
    }

    #[must_use]
    pub const fn goto_target(&self) -> Option<RulePriority> {
        self.goto_target
    }

    #[must_use]
    pub const fn fwmark(&self) -> Option<RuleFwMark> {
        self.fwmark
    }

    #[must_use]
    pub const fn input_interface(&self) -> Option<&InterfaceName> {
        self.input_interface.as_ref()
    }

    #[must_use]
    pub const fn output_interface(&self) -> Option<&InterfaceName> {
        self.output_interface.as_ref()
    }

    #[must_use]
    pub const fn tunnel_id(&self) -> Option<RuleTunnelId> {
        self.tunnel_id
    }

    #[must_use]
    pub const fn suppress_interface_group(&self) -> Option<RuleSuppressInterfaceGroup> {
        self.suppress_interface_group
    }

    #[must_use]
    pub const fn suppress_prefix_length(&self) -> Option<RuleSuppressPrefixLength> {
        self.suppress_prefix_length
    }

    #[must_use]
    pub const fn l3mdev(&self) -> bool {
        self.l3mdev
    }

    #[must_use]
    pub const fn uid_range(&self) -> Option<RuleUidRange> {
        self.uid_range
    }

    #[must_use]
    pub const fn ip_protocol(&self) -> Option<RuleIpProtocol> {
        self.ip_protocol
    }

    #[must_use]
    pub const fn source_port_range(&self) -> Option<RulePortRange> {
        self.source_port_range
    }

    #[must_use]
    pub const fn destination_port_range(&self) -> Option<RulePortRange> {
        self.destination_port_range
    }

    #[must_use]
    pub const fn flow(&self) -> Option<RuleFlowId> {
        self.flow
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkRuleRecordErrorKind {
    AddressFamilyMismatch,
    InvalidIpv4Tos,
    MissingGotoTarget,
    UnexpectedGotoTarget,
    BackwardGoto,
    L3mdevTableConflict,
    FlowUnsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkRuleRecordError {
    kind: NetworkRuleRecordErrorKind,
}

impl NetworkRuleRecordError {
    const fn new(kind: NetworkRuleRecordErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> NetworkRuleRecordErrorKind {
        self.kind
    }
}

impl fmt::Display for NetworkRuleRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            NetworkRuleRecordErrorKind::AddressFamilyMismatch => {
                "policy-rule addresses do not use one address family"
            }
            NetworkRuleRecordErrorKind::InvalidIpv4Tos => {
                "policy-rule IPv4 TOS contains bits outside IPTOS_TOS_MASK"
            }
            NetworkRuleRecordErrorKind::MissingGotoTarget => {
                "goto policy rule is missing its target priority"
            }
            NetworkRuleRecordErrorKind::UnexpectedGotoTarget => {
                "non-goto policy rule has a goto target priority"
            }
            NetworkRuleRecordErrorKind::BackwardGoto => {
                "policy-rule goto target is not after its own priority"
            }
            NetworkRuleRecordErrorKind::L3mdevTableConflict => {
                "l3mdev policy rule also names a routing table"
            }
            NetworkRuleRecordErrorKind::FlowUnsupported => {
                "flow/class ID is unsupported for IPv6 policy rules"
            }
        })
    }
}

impl Error for NetworkRuleRecordError {}

const IPV4_TOS_MASK: u8 = 0x1e;

const fn address_family(address: IpAddr) -> NetworkAddressFamily {
    match address {
        IpAddr::V4(_) => NetworkAddressFamily::Ipv4,
        IpAddr::V6(_) => NetworkAddressFamily::Ipv6,
    }
}

const fn maximum_prefix_length(family: NetworkAddressFamily) -> u8 {
    match family {
        NetworkAddressFamily::Ipv4 => 32,
        NetworkAddressFamily::Ipv6 => 128,
    }
}

fn canonical_network_address(address: IpAddr, prefix_length: u8) -> IpAddr {
    match address {
        IpAddr::V4(_) if prefix_length == 0 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(address) if prefix_length < 32 => IpAddr::V4(Ipv4Addr::from(
            u32::from(address) & (u32::MAX << (32 - prefix_length)),
        )),
        IpAddr::V6(_) if prefix_length == 0 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(address) if prefix_length < 128 => IpAddr::V6(Ipv6Addr::from(
            u128::from(address) & (u128::MAX << (128 - prefix_length)),
        )),
        address => address,
    }
}
