use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;

use crate::InterfaceIndex;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NetworkAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoutePrefix {
    address: IpAddr,
    prefix_length: u8,
}

impl RoutePrefix {
    pub fn new(address: IpAddr, prefix_length: u8) -> Result<Self, RoutePrefixError> {
        let family = address_family(address);
        if prefix_length > maximum_prefix_length(family) {
            return Err(RoutePrefixError::new(
                RoutePrefixErrorKind::InvalidPrefixLength,
                address,
                prefix_length,
            ));
        }
        if has_nonzero_host_bits(address, prefix_length) {
            return Err(RoutePrefixError::new(
                RoutePrefixErrorKind::HostBitsSet,
                address,
                prefix_length,
            ));
        }

        Ok(Self {
            address,
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
pub enum RoutePrefixErrorKind {
    InvalidPrefixLength,
    HostBitsSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutePrefixError {
    kind: RoutePrefixErrorKind,
    address: IpAddr,
    prefix_length: u8,
}

impl RoutePrefixError {
    const fn new(kind: RoutePrefixErrorKind, address: IpAddr, prefix_length: u8) -> Self {
        Self {
            kind,
            address,
            prefix_length,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> RoutePrefixErrorKind {
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

impl fmt::Display for RoutePrefixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            RoutePrefixErrorKind::InvalidPrefixLength => write!(
                formatter,
                "prefix length {} is invalid for route prefix {}",
                self.prefix_length, self.address
            ),
            RoutePrefixErrorKind::HostBitsSet => write!(
                formatter,
                "route prefix {}/{} has nonzero host bits",
                self.address, self.prefix_length
            ),
        }
    }
}

impl Error for RoutePrefixError {}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RouteTableId(u32);

impl RouteTableId {
    #[must_use]
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

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

raw_u8_wrapper!(RouteProtocol);
raw_u8_wrapper!(RouteScope);
raw_u8_wrapper!(RouteType);
raw_u8_wrapper!(RouteNexthopFlags);
raw_u8_wrapper!(RoutePreference);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RouteFlags(u32);

impl RouteFlags {
    pub const CLONED: Self = Self(0x200);

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
pub enum RouteGateway {
    /// A same-address-family gateway encoded by `RTA_GATEWAY`, not a gateway-free direct route.
    Direct(IpAddr),
    Via(IpAddr),
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteNexthop {
    output_interface: Option<InterfaceIndex>,
    gateway: Option<RouteGateway>,
    flags: RouteNexthopFlags,
    /// Raw `rtnh_hops`; Linux encodes the nexthop weight minus one.
    hops: u8,
}

impl RouteNexthop {
    #[must_use]
    pub const fn new(
        output_interface: Option<InterfaceIndex>,
        gateway: Option<RouteGateway>,
        flags: RouteNexthopFlags,
        hops: u8,
    ) -> Self {
        Self {
            output_interface,
            gateway,
            flags,
            hops,
        }
    }

    #[must_use]
    pub const fn output_interface(self) -> Option<InterfaceIndex> {
        self.output_interface
    }

    #[must_use]
    pub const fn gateway(self) -> Option<RouteGateway> {
        self.gateway
    }

    #[must_use]
    pub const fn flags(self) -> RouteNexthopFlags {
        self.flags
    }

    /// Returns the raw `rtnh_hops` wire value; Linux interprets it as weight minus one.
    #[must_use]
    pub const fn hops(self) -> u8 {
        self.hops
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RoutePath {
    None,
    Single {
        output_interface: Option<InterfaceIndex>,
        gateway: Option<RouteGateway>,
    },
    Multipath(Box<[RouteNexthop]>),
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteProperties {
    tos: u8,
    table: RouteTableId,
    protocol: RouteProtocol,
    scope: RouteScope,
    route_type: RouteType,
    flags: RouteFlags,
}

impl RouteProperties {
    #[must_use]
    pub const fn new(
        tos: u8,
        table: RouteTableId,
        protocol: RouteProtocol,
        scope: RouteScope,
        route_type: RouteType,
        flags: RouteFlags,
    ) -> Self {
        Self {
            tos,
            table,
            protocol,
            scope,
            route_type,
            flags,
        }
    }

    #[must_use]
    pub const fn tos(self) -> u8 {
        self.tos
    }

    #[must_use]
    pub const fn table(self) -> RouteTableId {
        self.table
    }

    #[must_use]
    pub const fn protocol(self) -> RouteProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn scope(self) -> RouteScope {
        self.scope
    }

    #[must_use]
    pub const fn route_type(self) -> RouteType {
        self.route_type
    }

    #[must_use]
    pub const fn flags(self) -> RouteFlags {
        self.flags
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkRouteRecord {
    destination: RoutePrefix,
    source: RoutePrefix,
    properties: RouteProperties,
    priority: u32,
    preferred_source: Option<IpAddr>,
    preference: Option<RoutePreference>,
    nexthop_id: Option<NonZeroU32>,
    path: RoutePath,
}

impl NetworkRouteRecord {
    pub fn new(
        destination: RoutePrefix,
        source: RoutePrefix,
        properties: RouteProperties,
        priority: u32,
        path: RoutePath,
    ) -> Result<Self, NetworkRouteRecordError> {
        let family = destination.family();
        if source.family() != family {
            return Err(NetworkRouteRecordError::new(
                NetworkRouteRecordErrorKind::AddressFamilyMismatch,
            ));
        }

        let path = normalize_path(path)?;
        validate_path(family, &path)?;

        Ok(Self {
            destination,
            source,
            properties,
            priority,
            preferred_source: None,
            preference: None,
            nexthop_id: None,
            path,
        })
    }

    pub fn with_preferred_source(
        mut self,
        preferred_source: IpAddr,
    ) -> Result<Self, NetworkRouteRecordError> {
        if address_family(preferred_source) != self.destination.family() {
            return Err(NetworkRouteRecordError::new(
                NetworkRouteRecordErrorKind::AddressFamilyMismatch,
            ));
        }
        self.preferred_source = Some(preferred_source);
        Ok(self)
    }

    pub fn with_preference(
        mut self,
        preference: RoutePreference,
    ) -> Result<Self, NetworkRouteRecordError> {
        if self.destination.family() != NetworkAddressFamily::Ipv6 {
            return Err(NetworkRouteRecordError::new(
                NetworkRouteRecordErrorKind::PreferenceUnsupported,
            ));
        }
        self.preference = Some(preference);
        Ok(self)
    }

    #[must_use]
    pub fn with_nexthop_id(mut self, nexthop_id: NonZeroU32) -> Self {
        self.nexthop_id = Some(nexthop_id);
        self
    }

    #[must_use]
    pub const fn destination(&self) -> RoutePrefix {
        self.destination
    }

    #[must_use]
    pub const fn source(&self) -> RoutePrefix {
        self.source
    }

    #[must_use]
    pub const fn properties(&self) -> RouteProperties {
        self.properties
    }

    #[must_use]
    pub const fn priority(&self) -> u32 {
        self.priority
    }

    #[must_use]
    pub const fn preferred_source(&self) -> Option<IpAddr> {
        self.preferred_source
    }

    #[must_use]
    pub const fn preference(&self) -> Option<RoutePreference> {
        self.preference
    }

    #[must_use]
    pub const fn nexthop_id(&self) -> Option<NonZeroU32> {
        self.nexthop_id
    }

    #[must_use]
    pub const fn path(&self) -> &RoutePath {
        &self.path
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkRouteRecordErrorKind {
    AddressFamilyMismatch,
    DirectGatewayFamilyMismatch,
    ViaGatewayUnsupported,
    EmptyMultipath,
    PreferenceUnsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkRouteRecordError {
    kind: NetworkRouteRecordErrorKind,
}

impl NetworkRouteRecordError {
    const fn new(kind: NetworkRouteRecordErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(&self) -> NetworkRouteRecordErrorKind {
        self.kind
    }
}

impl fmt::Display for NetworkRouteRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            NetworkRouteRecordErrorKind::AddressFamilyMismatch => {
                "route addresses do not use one address family"
            }
            NetworkRouteRecordErrorKind::DirectGatewayFamilyMismatch => {
                "direct route gateway does not use the route address family"
            }
            NetworkRouteRecordErrorKind::ViaGatewayUnsupported => {
                "via gateways are unsupported for IPv6 routes"
            }
            NetworkRouteRecordErrorKind::EmptyMultipath => "multipath route has no nexthops",
            NetworkRouteRecordErrorKind::PreferenceUnsupported => {
                "router preference is unsupported for IPv4 routes"
            }
        })
    }
}

impl Error for NetworkRouteRecordError {}

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

fn has_nonzero_host_bits(address: IpAddr, prefix_length: u8) -> bool {
    match address {
        IpAddr::V4(address) => {
            prefix_length < 32 && u32::from(address) & (u32::MAX >> prefix_length) != 0
        }
        IpAddr::V6(address) => {
            prefix_length < 128 && u128::from(address) & (u128::MAX >> prefix_length) != 0
        }
    }
}

fn normalize_path(path: RoutePath) -> Result<RoutePath, NetworkRouteRecordError> {
    match path {
        RoutePath::Single {
            output_interface: None,
            gateway: None,
        } => Ok(RoutePath::None),
        RoutePath::Multipath(nexthops) if nexthops.is_empty() => Err(NetworkRouteRecordError::new(
            NetworkRouteRecordErrorKind::EmptyMultipath,
        )),
        path => Ok(path),
    }
}

fn validate_path(
    family: NetworkAddressFamily,
    path: &RoutePath,
) -> Result<(), NetworkRouteRecordError> {
    match path {
        RoutePath::None => Ok(()),
        RoutePath::Single { gateway, .. } => validate_gateway(family, *gateway),
        RoutePath::Multipath(nexthops) => {
            for nexthop in nexthops {
                validate_gateway(family, nexthop.gateway())?;
            }
            Ok(())
        }
    }
}

fn validate_gateway(
    family: NetworkAddressFamily,
    gateway: Option<RouteGateway>,
) -> Result<(), NetworkRouteRecordError> {
    match gateway {
        Some(RouteGateway::Direct(address)) if address_family(address) != family => Err(
            NetworkRouteRecordError::new(NetworkRouteRecordErrorKind::DirectGatewayFamilyMismatch),
        ),
        Some(RouteGateway::Via(_)) if family != NetworkAddressFamily::Ipv4 => Err(
            NetworkRouteRecordError::new(NetworkRouteRecordErrorKind::ViaGatewayUnsupported),
        ),
        None | Some(RouteGateway::Direct(_) | RouteGateway::Via(_)) => Ok(()),
    }
}
