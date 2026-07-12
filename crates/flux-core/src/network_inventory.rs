use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::ops::{BitOr, BitOrAssign};

use crate::network_route::NetworkRouteRecord;
use crate::network_rule::NetworkRuleRecord;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct NetworkEpoch(NonZeroU64);

impl NetworkEpoch {
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

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

    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => Self::new(value),
            None => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct InterfaceIndex(NonZeroU32);

impl InterfaceIndex {
    /// Constructs a real Linux interface index from its positive kernel `int` domain.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value > i32::MAX as u32 {
            return None;
        }
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

/// Maximum interface-name payload stored without the kernel's terminal NUL.
pub const INTERFACE_NAME_MAX_BYTES: usize = 15;
/// Maximum raw `IFLA_INFO_KIND` bytes that fit inside its u16-sized `IFLA_LINKINFO` parent.
pub const INTERFACE_LINK_KIND_MAX_BYTES: usize = 65_523;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InterfaceName {
    length: u8,
    bytes: [u8; INTERFACE_NAME_MAX_BYTES],
}

impl InterfaceName {
    #[must_use]
    pub fn new(value: &[u8]) -> Option<Self> {
        if value.is_empty() || value.len() > INTERFACE_NAME_MAX_BYTES || value.contains(&0) {
            return None;
        }

        let mut bytes = [0; INTERFACE_NAME_MAX_BYTES];
        bytes[..value.len()].copy_from_slice(value);
        Some(Self {
            length: value.len() as u8,
            bytes,
        })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()).ok()
    }
}

impl fmt::Debug for InterfaceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("InterfaceName")
            .field(&self.as_bytes())
            .finish()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InterfaceLinkKind(Box<[u8]>);

impl InterfaceLinkKind {
    #[must_use]
    pub fn new(value: &[u8]) -> Option<Self> {
        if value.is_empty() || value.len() > INTERFACE_LINK_KIND_MAX_BYTES || value.contains(&0) {
            return None;
        }

        Some(Self(value.into()))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()).ok()
    }
}

impl fmt::Debug for InterfaceLinkKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("InterfaceLinkKind")
            .field(&self.as_bytes())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct InterfaceLinkFlags(u32);

impl InterfaceLinkFlags {
    pub const UP: Self = Self(1 << 0);
    pub const BROADCAST: Self = Self(1 << 1);
    pub const DEBUG: Self = Self(1 << 2);
    pub const LOOPBACK: Self = Self(1 << 3);
    pub const POINT_TO_POINT: Self = Self(1 << 4);
    pub const NO_TRAILERS: Self = Self(1 << 5);
    pub const RUNNING: Self = Self(1 << 6);
    pub const NO_ARP: Self = Self(1 << 7);
    pub const PROMISCUOUS: Self = Self(1 << 8);
    pub const ALL_MULTICAST: Self = Self(1 << 9);
    pub const MASTER: Self = Self(1 << 10);
    pub const SLAVE: Self = Self(1 << 11);
    pub const MULTICAST: Self = Self(1 << 12);
    pub const PORT_SELECT: Self = Self(1 << 13);
    pub const AUTOMEDIA: Self = Self(1 << 14);
    pub const DYNAMIC: Self = Self(1 << 15);
    pub const LOWER_UP: Self = Self(1 << 16);
    pub const DORMANT: Self = Self(1 << 17);
    pub const ECHO: Self = Self(1 << 18);

    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl BitOr for InterfaceLinkFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for InterfaceLinkFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct InterfaceHardwareType(u16);

impl InterfaceHardwareType {
    #[must_use]
    pub const fn from_raw(value: u16) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct InterfaceOperationalState(u8);

impl InterfaceOperationalState {
    pub const UNKNOWN: Self = Self(0);
    pub const NOT_PRESENT: Self = Self(1);
    pub const DOWN: Self = Self(2);
    pub const LOWER_LAYER_DOWN: Self = Self(3);
    pub const TESTING: Self = Self(4);
    pub const DORMANT: Self = Self(5);
    pub const UP: Self = Self(6);

    #[must_use]
    pub const fn from_raw(value: u8) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InterfaceLinkRecord {
    interface_index: InterfaceIndex,
    name: InterfaceName,
    hardware_type: InterfaceHardwareType,
    flags: InterfaceLinkFlags,
    mtu: Option<u32>,
    operational_state: Option<InterfaceOperationalState>,
    carrier: Option<bool>,
    kind: Option<InterfaceLinkKind>,
}

impl InterfaceLinkRecord {
    #[must_use]
    pub fn new(
        interface_index: InterfaceIndex,
        name: InterfaceName,
        hardware_type: InterfaceHardwareType,
        flags: InterfaceLinkFlags,
    ) -> Self {
        Self {
            interface_index,
            name,
            hardware_type,
            flags,
            mtu: None,
            operational_state: None,
            carrier: None,
            kind: None,
        }
    }

    #[must_use]
    pub fn with_mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    #[must_use]
    pub fn with_operational_state(mut self, state: InterfaceOperationalState) -> Self {
        self.operational_state = Some(state);
        self
    }

    #[must_use]
    pub fn with_carrier(mut self, carrier: bool) -> Self {
        self.carrier = Some(carrier);
        self
    }

    #[must_use]
    pub fn with_kind(mut self, kind: InterfaceLinkKind) -> Self {
        self.kind = Some(kind);
        self
    }

    #[must_use]
    pub const fn interface_index(&self) -> InterfaceIndex {
        self.interface_index
    }

    #[must_use]
    pub const fn name(&self) -> &InterfaceName {
        &self.name
    }

    #[must_use]
    pub const fn hardware_type(&self) -> InterfaceHardwareType {
        self.hardware_type
    }

    #[must_use]
    pub const fn flags(&self) -> InterfaceLinkFlags {
        self.flags
    }

    #[must_use]
    pub const fn mtu(&self) -> Option<u32> {
        self.mtu
    }

    #[must_use]
    pub const fn operational_state(&self) -> Option<InterfaceOperationalState> {
        self.operational_state
    }

    #[must_use]
    pub const fn carrier(&self) -> Option<bool> {
        self.carrier
    }

    #[must_use]
    pub fn kind(&self) -> Option<&InterfaceLinkKind> {
        self.kind.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct InterfaceAddressFlags(u32);

impl InterfaceAddressFlags {
    pub const SECONDARY: Self = Self(0x01);
    pub const TEMPORARY: Self = Self(0x01);
    pub const NO_DAD: Self = Self(0x02);
    pub const OPTIMISTIC: Self = Self(0x04);
    pub const DAD_FAILED: Self = Self(0x08);
    pub const HOME_ADDRESS: Self = Self(0x10);
    pub const DEPRECATED: Self = Self(0x20);
    pub const TENTATIVE: Self = Self(0x40);
    pub const PERMANENT: Self = Self(0x80);
    pub const MANAGE_TEMPORARY_ADDRESSES: Self = Self(0x100);
    pub const NO_PREFIX_ROUTE: Self = Self(0x200);
    pub const MULTICAST_AUTO_JOIN: Self = Self(0x400);
    pub const STABLE_PRIVACY: Self = Self(0x800);

    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl BitOr for InterfaceAddressFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for InterfaceAddressFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InterfaceAddressRecord {
    interface_index: InterfaceIndex,
    address: IpAddr,
    prefix_length: u8,
    flags: InterfaceAddressFlags,
}

impl InterfaceAddressRecord {
    pub fn new(
        interface_index: InterfaceIndex,
        address: IpAddr,
        prefix_length: u8,
        flags: InterfaceAddressFlags,
    ) -> Result<Self, InterfaceAddressRecordError> {
        let maximum_prefix_length = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_length > maximum_prefix_length {
            return Err(InterfaceAddressRecordError {
                address,
                prefix_length,
            });
        }

        Ok(Self {
            interface_index,
            address,
            prefix_length,
            flags,
        })
    }

    #[must_use]
    pub const fn interface_index(self) -> InterfaceIndex {
        self.interface_index
    }

    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    #[must_use]
    pub const fn prefix_length(self) -> u8 {
        self.prefix_length
    }

    #[must_use]
    pub const fn flags(self) -> InterfaceAddressFlags {
        self.flags
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceAddressRecordErrorKind {
    InvalidPrefixLength,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceAddressRecordError {
    address: IpAddr,
    prefix_length: u8,
}

impl InterfaceAddressRecordError {
    #[must_use]
    pub const fn kind(self) -> InterfaceAddressRecordErrorKind {
        InterfaceAddressRecordErrorKind::InvalidPrefixLength
    }
}

impl fmt::Display for InterfaceAddressRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "prefix length {} is invalid for interface address {}",
            self.prefix_length, self.address
        )
    }
}

impl Error for InterfaceAddressRecordError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkInventory {
    epoch: NetworkEpoch,
    links: Box<[InterfaceLinkRecord]>,
    addresses: Box<[InterfaceAddressRecord]>,
    routes: Box<[NetworkRouteRecord]>,
    rules: Box<[NetworkRuleRecord]>,
}

impl NetworkInventory {
    #[must_use]
    pub const fn epoch(&self) -> NetworkEpoch {
        self.epoch
    }

    #[must_use]
    pub fn links(&self) -> &[InterfaceLinkRecord] {
        &self.links
    }

    #[must_use]
    pub fn addresses(&self) -> &[InterfaceAddressRecord] {
        &self.addresses
    }

    /// Returns routes in kernel dump order, including exact duplicates.
    #[must_use]
    pub fn routes(&self) -> &[NetworkRouteRecord] {
        &self.routes
    }

    /// Returns policy rules in kernel dump order, including exact duplicates.
    #[must_use]
    pub fn rules(&self) -> &[NetworkRuleRecord] {
        &self.rules
    }

    #[must_use]
    pub fn materially_differs_from(&self, candidate: &Self) -> bool {
        self.links != candidate.links
            || self.addresses != candidate.addresses
            || self.routes != candidate.routes
            || self.rules != candidate.rules
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceLinkConflict {
    interface_index: InterfaceIndex,
}

impl InterfaceLinkConflict {
    #[must_use]
    pub const fn interface_index(self) -> InterfaceIndex {
        self.interface_index
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceNameConflict {
    name: InterfaceName,
    first_interface_index: InterfaceIndex,
    second_interface_index: InterfaceIndex,
}

impl InterfaceNameConflict {
    #[must_use]
    pub const fn name(self) -> InterfaceName {
        self.name
    }

    #[must_use]
    pub const fn first_interface_index(self) -> InterfaceIndex {
        self.first_interface_index
    }

    #[must_use]
    pub const fn second_interface_index(self) -> InterfaceIndex {
        self.second_interface_index
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressFlagConflict {
    interface_index: InterfaceIndex,
    address: IpAddr,
    prefix_length: u8,
    first_flags: InterfaceAddressFlags,
    second_flags: InterfaceAddressFlags,
}

impl AddressFlagConflict {
    #[must_use]
    pub const fn interface_index(self) -> InterfaceIndex {
        self.interface_index
    }

    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    #[must_use]
    pub const fn prefix_length(self) -> u8 {
        self.prefix_length
    }

    #[must_use]
    pub const fn first_flags(self) -> InterfaceAddressFlags {
        self.first_flags
    }

    #[must_use]
    pub const fn second_flags(self) -> InterfaceAddressFlags {
        self.second_flags
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkInventoryError {
    ConflictingLinkFacts(InterfaceLinkConflict),
    ConflictingInterfaceName(InterfaceNameConflict),
    ConflictingAddressFlags(AddressFlagConflict),
    EpochExhausted,
}

impl fmt::Display for NetworkInventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConflictingLinkFacts(conflict) => write!(
                formatter,
                "interface index {} has conflicting canonical link facts",
                conflict.interface_index.get()
            ),
            Self::ConflictingInterfaceName(conflict) => write!(
                formatter,
                "primary interface name {:?} is shared by interface indices {} and {}",
                conflict.name,
                conflict.first_interface_index.get(),
                conflict.second_interface_index.get()
            ),
            Self::ConflictingAddressFlags(conflict) => write!(
                formatter,
                "interface address {} on index {} with prefix length {} has conflicting flags {:#x} and {:#x}",
                conflict.address,
                conflict.interface_index.get(),
                conflict.prefix_length,
                conflict.first_flags.bits(),
                conflict.second_flags.bits()
            ),
            Self::EpochExhausted => formatter.write_str("network inventory epoch is exhausted"),
        }
    }
}

impl Error for NetworkInventoryError {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkInventoryTracker {
    current: Option<NetworkInventory>,
}

impl NetworkInventoryTracker {
    #[must_use]
    pub const fn new() -> Self {
        Self { current: None }
    }

    #[must_use]
    pub const fn current(&self) -> Option<&NetworkInventory> {
        self.current.as_ref()
    }

    pub fn publish_complete(
        &mut self,
        links: impl IntoIterator<Item = InterfaceLinkRecord>,
        addresses: impl IntoIterator<Item = InterfaceAddressRecord>,
    ) -> Result<&NetworkInventory, NetworkInventoryError> {
        self.publish_complete_with_routing(links, addresses, std::iter::empty(), std::iter::empty())
    }

    /// Atomically publishes one complete link/address/route/rule snapshot.
    ///
    /// Link and address facts are canonical sets. Route and rule facts are
    /// ordered multisets, so their input order and multiplicity are retained.
    pub fn publish_complete_with_routing(
        &mut self,
        links: impl IntoIterator<Item = InterfaceLinkRecord>,
        addresses: impl IntoIterator<Item = InterfaceAddressRecord>,
        routes: impl IntoIterator<Item = NetworkRouteRecord>,
        rules: impl IntoIterator<Item = NetworkRuleRecord>,
    ) -> Result<&NetworkInventory, NetworkInventoryError> {
        let links = canonicalize_complete_links(links)?;
        let addresses = canonicalize_complete_addresses(addresses)?;
        let routes = routes.into_iter().collect::<Vec<_>>().into_boxed_slice();
        let rules = rules.into_iter().collect::<Vec<_>>().into_boxed_slice();
        if self.current.as_ref().is_some_and(|current| {
            current.links == links
                && current.addresses == addresses
                && current.routes == routes
                && current.rules == rules
        }) {
            return Ok(self.current.as_ref().expect("current inventory is present"));
        }

        let epoch = match self.current.as_ref() {
            Some(current) => current
                .epoch
                .checked_next()
                .ok_or(NetworkInventoryError::EpochExhausted)?,
            None => NetworkEpoch::INITIAL,
        };
        self.current = Some(NetworkInventory {
            epoch,
            links,
            addresses,
            routes,
            rules,
        });
        Ok(self
            .current
            .as_ref()
            .expect("published inventory is present"))
    }
}

fn canonicalize_complete_links(
    links: impl IntoIterator<Item = InterfaceLinkRecord>,
) -> Result<Box<[InterfaceLinkRecord]>, NetworkInventoryError> {
    let mut links: Vec<_> = links.into_iter().collect();
    links.sort();

    let mut canonical: Vec<InterfaceLinkRecord> = Vec::with_capacity(links.len());
    for record in links {
        if let Some(previous) = canonical.last()
            && previous.interface_index == record.interface_index
        {
            if previous != &record {
                return Err(NetworkInventoryError::ConflictingLinkFacts(
                    InterfaceLinkConflict {
                        interface_index: record.interface_index,
                    },
                ));
            }
            continue;
        }
        canonical.push(record);
    }

    let mut names: Vec<_> = canonical
        .iter()
        .map(|record| (record.name, record.interface_index))
        .collect();
    names.sort_unstable();
    for pair in names.windows(2) {
        let [
            (first_name, first_interface_index),
            (second_name, second_interface_index),
        ] = pair
        else {
            unreachable!("a two-element window always contains two names");
        };
        if first_name == second_name {
            return Err(NetworkInventoryError::ConflictingInterfaceName(
                InterfaceNameConflict {
                    name: *first_name,
                    first_interface_index: *first_interface_index,
                    second_interface_index: *second_interface_index,
                },
            ));
        }
    }

    Ok(canonical.into_boxed_slice())
}

fn canonicalize_complete_addresses(
    addresses: impl IntoIterator<Item = InterfaceAddressRecord>,
) -> Result<Box<[InterfaceAddressRecord]>, NetworkInventoryError> {
    let mut addresses: Vec<_> = addresses.into_iter().collect();
    addresses.sort_by_key(|record| {
        (
            record.interface_index,
            record.address,
            record.prefix_length,
            record.flags,
        )
    });

    let mut canonical: Vec<InterfaceAddressRecord> = Vec::with_capacity(addresses.len());
    for record in addresses {
        if let Some(previous) = canonical.last().copied()
            && previous.interface_index == record.interface_index
            && previous.address == record.address
            && previous.prefix_length == record.prefix_length
        {
            if previous.flags != record.flags {
                return Err(NetworkInventoryError::ConflictingAddressFlags(
                    AddressFlagConflict {
                        interface_index: record.interface_index,
                        address: record.address,
                        prefix_length: record.prefix_length,
                        first_flags: previous.flags,
                        second_flags: record.flags,
                    },
                ));
            }
            continue;
        }
        canonical.push(record);
    }
    Ok(canonical.into_boxed_slice())
}
