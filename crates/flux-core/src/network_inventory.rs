use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::ops::{BitOr, BitOrAssign};

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
    addresses: Box<[InterfaceAddressRecord]>,
}

impl NetworkInventory {
    #[must_use]
    pub const fn epoch(&self) -> NetworkEpoch {
        self.epoch
    }

    #[must_use]
    pub fn addresses(&self) -> &[InterfaceAddressRecord] {
        &self.addresses
    }

    #[must_use]
    pub fn materially_differs_from(&self, candidate: &Self) -> bool {
        self.addresses != candidate.addresses
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
    ConflictingAddressFlags(AddressFlagConflict),
    EpochExhausted,
}

impl fmt::Display for NetworkInventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
        addresses: impl IntoIterator<Item = InterfaceAddressRecord>,
    ) -> Result<&NetworkInventory, NetworkInventoryError> {
        let addresses = canonicalize_complete_addresses(addresses)?;
        if self
            .current
            .as_ref()
            .is_some_and(|current| current.addresses == addresses)
        {
            return Ok(self.current.as_ref().expect("current inventory is present"));
        }

        let epoch = match self.current.as_ref() {
            Some(current) => current
                .epoch
                .checked_next()
                .ok_or(NetworkInventoryError::EpochExhausted)?,
            None => NetworkEpoch::INITIAL,
        };
        self.current = Some(NetworkInventory { epoch, addresses });
        Ok(self
            .current
            .as_ref()
            .expect("published inventory is present"))
    }
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
