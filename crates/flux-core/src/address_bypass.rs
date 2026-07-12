use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;

use crate::network_inventory::{
    InterfaceAddressFlags, InterfaceAddressRecord, NetworkEpoch, NetworkInventory,
    NetworkInventorySnapshotId,
};
use crate::network_route::NetworkAddressFamily;
use crate::network_rule::{
    NetworkRuleRecord, RuleAction, RuleFlags, RulePrefix, RulePriority, RuleProperties,
    RuleProtocol, RuleTableId,
};

/// Compile-time ceiling for one address-derived rule plan.
pub const MAX_ADDRESS_BYPASS_RULES: u32 = 4_096;
/// Maximum detailed RPDB conflicts retained in one planning error.
pub const MAX_ADDRESS_BYPASS_CONFLICTS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AddressBypassRuleBudget(NonZeroU32);

impl AddressBypassRuleBudget {
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) if value.get() <= MAX_ADDRESS_BYPASS_RULES => Some(Self(value)),
            Some(_) | None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Caller-resolved routing selection for address-derived safety rules.
///
/// This structural specification deliberately has no default and performs no priority allocation
/// or Android-policy audit. Its caller must supply values selected by a separate, versioned RPDB
/// audit. Planning then rejects every unowned object occupying the selected per-family priority
/// slots in one complete inventory snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressBypassRoutingSpec {
    lookup_table: RuleTableId,
    protocol: RuleProtocol,
    ipv4_priority: Option<RulePriority>,
    ipv6_priority: Option<RulePriority>,
}

impl AddressBypassRoutingSpec {
    pub fn new(
        lookup_table: RuleTableId,
        protocol: RuleProtocol,
        ipv4_priority: Option<RulePriority>,
        ipv6_priority: Option<RulePriority>,
    ) -> Result<Self, AddressBypassRoutingSpecError> {
        if lookup_table.get() == 0 {
            return Err(AddressBypassRoutingSpecError::new(
                AddressBypassRoutingSpecErrorKind::UnspecifiedLookupTable,
            ));
        }
        if ipv4_priority.is_some_and(|priority| priority.get() == 0) {
            return Err(AddressBypassRoutingSpecError::new(
                AddressBypassRoutingSpecErrorKind::UnspecifiedPriority(NetworkAddressFamily::Ipv4),
            ));
        }
        if ipv6_priority.is_some_and(|priority| priority.get() == 0) {
            return Err(AddressBypassRoutingSpecError::new(
                AddressBypassRoutingSpecErrorKind::UnspecifiedPriority(NetworkAddressFamily::Ipv6),
            ));
        }
        if ipv4_priority.is_none() && ipv6_priority.is_none() {
            return Err(AddressBypassRoutingSpecError::new(
                AddressBypassRoutingSpecErrorKind::NoEnabledFamilies,
            ));
        }

        Ok(Self {
            lookup_table,
            protocol,
            ipv4_priority,
            ipv6_priority,
        })
    }

    #[must_use]
    pub const fn lookup_table(self) -> RuleTableId {
        self.lookup_table
    }

    #[must_use]
    pub const fn protocol(self) -> RuleProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn ipv4_priority(self) -> Option<RulePriority> {
        self.ipv4_priority
    }

    #[must_use]
    pub const fn ipv6_priority(self) -> Option<RulePriority> {
        self.ipv6_priority
    }

    const fn priority_for(self, family: NetworkAddressFamily) -> Option<RulePriority> {
        match family {
            NetworkAddressFamily::Ipv4 => self.ipv4_priority,
            NetworkAddressFamily::Ipv6 => self.ipv6_priority,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressBypassRoutingSpecErrorKind {
    NoEnabledFamilies,
    UnspecifiedLookupTable,
    UnspecifiedPriority(NetworkAddressFamily),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressBypassRoutingSpecError {
    kind: AddressBypassRoutingSpecErrorKind,
}

impl AddressBypassRoutingSpecError {
    const fn new(kind: AddressBypassRoutingSpecErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> AddressBypassRoutingSpecErrorKind {
        self.kind
    }
}

impl fmt::Display for AddressBypassRoutingSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            AddressBypassRoutingSpecErrorKind::NoEnabledFamilies => {
                formatter.write_str("address-bypass routing selection enables no address family")
            }
            AddressBypassRoutingSpecErrorKind::UnspecifiedLookupTable => {
                formatter.write_str("address-bypass routing selection uses table zero")
            }
            AddressBypassRoutingSpecErrorKind::UnspecifiedPriority(family) => write!(
                formatter,
                "address-bypass routing selection uses priority zero for {family:?}"
            ),
        }
    }
}

impl Error for AddressBypassRoutingSpecError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AddressBypassPrefix {
    network: IpAddr,
    prefix_length: u8,
}

impl AddressBypassPrefix {
    pub fn new(address: IpAddr, prefix_length: u8) -> Result<Self, AddressBypassPrefixError> {
        let original_address = address;
        let original_prefix_length = prefix_length;
        let (address, prefix_length) = normalize_configured_prefix(address, prefix_length)?;
        let maximum = maximum_prefix_length(address_family(address));
        if prefix_length > maximum {
            return Err(AddressBypassPrefixError::new(
                AddressBypassPrefixErrorKind::InvalidPrefixLength,
                original_address,
                original_prefix_length,
            ));
        }

        Ok(Self {
            network: canonical_network_address(address, prefix_length),
            prefix_length,
        })
    }

    #[must_use]
    pub const fn network(self) -> IpAddr {
        self.network
    }

    #[must_use]
    pub const fn prefix_length(self) -> u8 {
        self.prefix_length
    }

    #[must_use]
    pub fn contains(self, address: IpAddr) -> bool {
        let address = normalize_exact_address(address);
        address_family(address) == address_family(self.network)
            && canonical_network_address(address, self.prefix_length) == self.network
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressBypassPrefixErrorKind {
    InvalidPrefixLength,
    UnsupportedMappedPrefix,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressBypassPrefixError {
    kind: AddressBypassPrefixErrorKind,
    address: IpAddr,
    prefix_length: u8,
}

impl AddressBypassPrefixError {
    const fn new(kind: AddressBypassPrefixErrorKind, address: IpAddr, prefix_length: u8) -> Self {
        Self {
            kind,
            address,
            prefix_length,
        }
    }

    #[must_use]
    pub const fn kind(self) -> AddressBypassPrefixErrorKind {
        self.kind
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

impl fmt::Display for AddressBypassPrefixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            AddressBypassPrefixErrorKind::InvalidPrefixLength => write!(
                formatter,
                "prefix length {} is invalid for address-bypass prefix {}",
                self.prefix_length, self.address
            ),
            AddressBypassPrefixErrorKind::UnsupportedMappedPrefix => write!(
                formatter,
                "IPv4-mapped address-bypass prefix {}/{} crosses the mapping boundary",
                self.address, self.prefix_length
            ),
        }
    }
}

impl Error for AddressBypassPrefixError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressHostSetPolicy {
    families: AddressHostFamilySelection,
    rule_budget: AddressBypassRuleBudget,
    ignored_flags: InterfaceAddressFlags,
    ignored_addresses: BTreeSet<IpAddr>,
    ignored_prefixes: BTreeSet<AddressBypassPrefix>,
}

impl AddressHostSetPolicy {
    #[must_use]
    pub const fn new(
        families: AddressHostFamilySelection,
        rule_budget: AddressBypassRuleBudget,
    ) -> Self {
        Self {
            families,
            rule_budget,
            ignored_flags: InterfaceAddressFlags::from_bits(0),
            ignored_addresses: BTreeSet::new(),
            ignored_prefixes: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn with_ignored_flags(mut self, flags: InterfaceAddressFlags) -> Self {
        self.ignored_flags = flags;
        self
    }

    #[must_use]
    pub fn with_ignored_addresses(mut self, addresses: impl IntoIterator<Item = IpAddr>) -> Self {
        self.ignored_addresses
            .extend(addresses.into_iter().map(normalize_exact_address));
        self
    }

    pub fn with_ignored_prefixes(
        mut self,
        prefixes: impl IntoIterator<Item = (IpAddr, u8)>,
    ) -> Result<Self, AddressBypassPrefixError> {
        for (address, prefix_length) in prefixes {
            self.ignored_prefixes
                .insert(AddressBypassPrefix::new(address, prefix_length)?);
        }
        Ok(self)
    }

    #[must_use]
    pub const fn families(&self) -> AddressHostFamilySelection {
        self.families
    }

    #[must_use]
    pub const fn rule_budget(&self) -> AddressBypassRuleBudget {
        self.rule_budget
    }

    fn selected_address(
        &self,
        record: InterfaceAddressRecord,
    ) -> Result<Option<IpAddr>, AddressBypassInventoryAddressErrorKind> {
        let address = normalize_inventory_address(record)?;
        if !is_global_usable(address)
            || !self.families.includes(address_family(address))
            || record.flags().intersects(self.ignored_flags)
            || self.ignored_addresses.contains(&address)
            || self
                .ignored_prefixes
                .iter()
                .any(|prefix| prefix.contains(address))
        {
            Ok(None)
        } else {
            Ok(Some(address))
        }
    }
}

/// Nonempty address-family selection for one address-derived host set.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AddressHostFamilySelection {
    Ipv4,
    Ipv6,
    DualStack,
}

impl AddressHostFamilySelection {
    const fn from_routing(routing: AddressBypassRoutingSpec) -> Self {
        match (
            routing.ipv4_priority().is_some(),
            routing.ipv6_priority().is_some(),
        ) {
            (true, false) => Self::Ipv4,
            (false, true) => Self::Ipv6,
            (true, true) => Self::DualStack,
            (false, false) => unreachable!(),
        }
    }

    #[must_use]
    pub const fn includes(self, family: NetworkAddressFamily) -> bool {
        matches!(
            (self, family),
            (Self::Ipv4 | Self::DualStack, NetworkAddressFamily::Ipv4)
                | (Self::Ipv6 | Self::DualStack, NetworkAddressFamily::Ipv6)
        )
    }
}

/// Deterministic selected local-interface host addresses for one complete inventory snapshot.
///
/// This is realization-neutral evidence. A later Capture Program may consume it as a pre-mark
/// bypass set, while the compatibility planner below projects the same hosts into RPDB rules. The
/// plan proves neither backend ordering nor kernel mutation ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressHostSetPlan {
    snapshot_id: NetworkInventorySnapshotId,
    epoch: NetworkEpoch,
    families: AddressHostFamilySelection,
    hosts: Box<[IpAddr]>,
}

impl AddressHostSetPlan {
    #[must_use]
    pub const fn snapshot_id(&self) -> NetworkInventorySnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub const fn epoch(&self) -> NetworkEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn families(&self) -> AddressHostFamilySelection {
        self.families
    }

    #[must_use]
    pub fn hosts(&self) -> &[IpAddr] {
        &self.hosts
    }

    pub fn ensure_current(
        &self,
        inventory: &NetworkInventory,
    ) -> Result<(), StaleAddressHostSetPlan> {
        if inventory.snapshot_id() == self.snapshot_id {
            Ok(())
        } else {
            Err(StaleAddressHostSetPlan {
                planned_snapshot_id: self.snapshot_id,
                current_snapshot_id: inventory.snapshot_id(),
                planned_epoch: self.epoch,
                current_epoch: inventory.epoch(),
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressHostSetPlanError {
    HostBudgetExceeded {
        budget: AddressBypassRuleBudget,
        required_at_least: u32,
    },
    InvalidInventoryAddress {
        record: InterfaceAddressRecord,
        reason: AddressBypassInventoryAddressErrorKind,
    },
}

impl fmt::Display for AddressHostSetPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostBudgetExceeded {
                budget,
                required_at_least,
            } => write!(
                formatter,
                "address host set requires at least {required_at_least} hosts but its budget is {}",
                budget.get()
            ),
            Self::InvalidInventoryAddress { record, reason } => write!(
                formatter,
                "interface address {}/{} on index {} is invalid for address host-set planning: {reason:?}",
                record.address(),
                record.prefix_length(),
                record.interface_index().get()
            ),
        }
    }
}

impl Error for AddressHostSetPlanError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleAddressHostSetPlan {
    planned_snapshot_id: NetworkInventorySnapshotId,
    current_snapshot_id: NetworkInventorySnapshotId,
    planned_epoch: NetworkEpoch,
    current_epoch: NetworkEpoch,
}

impl StaleAddressHostSetPlan {
    #[must_use]
    pub const fn planned_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.planned_snapshot_id
    }

    #[must_use]
    pub const fn current_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.current_snapshot_id
    }

    #[must_use]
    pub const fn planned_epoch(self) -> NetworkEpoch {
        self.planned_epoch
    }

    #[must_use]
    pub const fn current_epoch(self) -> NetworkEpoch {
        self.current_epoch
    }
}

impl fmt::Display for StaleAddressHostSetPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "address host-set plan snapshot {} at epoch {} is stale relative to snapshot {} at epoch {}",
            self.planned_snapshot_id.get(),
            self.planned_epoch.get(),
            self.current_snapshot_id.get(),
            self.current_epoch.get()
        )
    }
}

impl Error for StaleAddressHostSetPlan {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressBypassPolicy {
    routing: AddressBypassRoutingSpec,
    host_set: AddressHostSetPolicy,
}

impl AddressBypassPolicy {
    #[must_use]
    pub const fn new(
        routing: AddressBypassRoutingSpec,
        rule_budget: AddressBypassRuleBudget,
    ) -> Self {
        Self {
            routing,
            host_set: AddressHostSetPolicy::new(
                AddressHostFamilySelection::from_routing(routing),
                rule_budget,
            ),
        }
    }

    #[must_use]
    pub fn with_ignored_flags(mut self, flags: InterfaceAddressFlags) -> Self {
        self.host_set = self.host_set.with_ignored_flags(flags);
        self
    }

    #[must_use]
    pub fn with_ignored_addresses(mut self, addresses: impl IntoIterator<Item = IpAddr>) -> Self {
        self.host_set = self.host_set.with_ignored_addresses(addresses);
        self
    }

    pub fn with_ignored_prefixes(
        mut self,
        prefixes: impl IntoIterator<Item = (IpAddr, u8)>,
    ) -> Result<Self, AddressBypassPrefixError> {
        self.host_set = self.host_set.with_ignored_prefixes(prefixes)?;
        Ok(self)
    }

    #[must_use]
    pub const fn routing(&self) -> AddressBypassRoutingSpec {
        self.routing
    }

    #[must_use]
    pub const fn rule_budget(&self) -> AddressBypassRuleBudget {
        self.host_set.rule_budget()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AddressBypassRuleIntent {
    destination: IpAddr,
    lookup_table: RuleTableId,
    priority: RulePriority,
    protocol: RuleProtocol,
}

impl AddressBypassRuleIntent {
    fn new(destination: IpAddr, routing: AddressBypassRoutingSpec) -> Self {
        let family = address_family(destination);
        Self {
            destination,
            lookup_table: routing.lookup_table(),
            priority: routing
                .priority_for(family)
                .expect("selected address family has a routing priority"),
            protocol: routing.protocol(),
        }
    }

    #[must_use]
    pub const fn family(self) -> NetworkAddressFamily {
        address_family(self.destination)
    }

    #[must_use]
    pub const fn destination(self) -> IpAddr {
        self.destination
    }

    #[must_use]
    pub const fn lookup_table(self) -> RuleTableId {
        self.lookup_table
    }

    #[must_use]
    pub const fn priority(self) -> RulePriority {
        self.priority
    }

    #[must_use]
    pub const fn protocol(self) -> RuleProtocol {
        self.protocol
    }

    /// Returns the canonical observed-rule projection expected after future mutation.
    ///
    /// This is not a raw netlink deletion identity. A future writer must retain its exact encoded
    /// attributes and durable ownership evidence separately.
    #[must_use]
    pub fn to_rule_record(self) -> NetworkRuleRecord {
        let family = self.family();
        let destination = RulePrefix::new(self.destination, maximum_prefix_length(family))
            .expect("host prefix is valid for its address family");
        NetworkRuleRecord::new(
            destination,
            RulePrefix::unspecified(family),
            RuleProperties::new(
                0,
                self.lookup_table,
                RuleAction::TO_TABLE,
                self.protocol,
                RuleFlags::default(),
            ),
            self.priority,
            None,
        )
        .expect("minimal address-bypass rule is canonical")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressBypassRuleConflictKind {
    ExactRuleWithoutOwnership,
    DuplicateExactRule,
    UnexpectedRuleAtSelectedPriority,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressBypassRuleConflict {
    kind: AddressBypassRuleConflictKind,
    dump_index: usize,
    observed: NetworkRuleRecord,
}

impl AddressBypassRuleConflict {
    #[must_use]
    pub const fn kind(&self) -> AddressBypassRuleConflictKind {
        self.kind
    }

    #[must_use]
    pub const fn dump_index(&self) -> usize {
        self.dump_index
    }

    #[must_use]
    pub const fn observed(&self) -> &NetworkRuleRecord {
        &self.observed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressBypassInventoryAddressErrorKind {
    UnsupportedMappedPrefix,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressBypassPlanError {
    RuleBudgetExceeded {
        budget: AddressBypassRuleBudget,
        required_at_least: u32,
    },
    RoutingConflict {
        conflicts: Box<[AddressBypassRuleConflict]>,
        omitted_conflicts: u32,
    },
    InvalidInventoryAddress {
        record: InterfaceAddressRecord,
        reason: AddressBypassInventoryAddressErrorKind,
    },
}

impl fmt::Display for AddressBypassPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuleBudgetExceeded {
                budget,
                required_at_least,
            } => write!(
                formatter,
                "address-bypass plan requires at least {required_at_least} rules but its budget is {}",
                budget.get()
            ),
            Self::RoutingConflict {
                conflicts,
                omitted_conflicts,
            } => write!(
                formatter,
                "address-bypass routing selection conflicts with {} observed rules and omits {omitted_conflicts} additional conflicts",
                conflicts.len()
            ),
            Self::InvalidInventoryAddress { record, reason } => write!(
                formatter,
                "interface address {}/{} on index {} is invalid for address-bypass planning: {reason:?}",
                record.address(),
                record.prefix_length(),
                record.interface_index().get()
            ),
        }
    }
}

impl Error for AddressBypassPlanError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressBypassPlan {
    snapshot_id: NetworkInventorySnapshotId,
    epoch: NetworkEpoch,
    routing: AddressBypassRoutingSpec,
    intents: Box<[AddressBypassRuleIntent]>,
}

impl AddressBypassPlan {
    #[must_use]
    pub const fn snapshot_id(&self) -> NetworkInventorySnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub const fn epoch(&self) -> NetworkEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn routing(&self) -> AddressBypassRoutingSpec {
        self.routing
    }

    #[must_use]
    pub const fn intents(&self) -> &[AddressBypassRuleIntent] {
        &self.intents
    }

    pub fn ensure_current(
        &self,
        inventory: &NetworkInventory,
    ) -> Result<(), StaleAddressBypassPlan> {
        if inventory.snapshot_id() == self.snapshot_id {
            Ok(())
        } else {
            Err(StaleAddressBypassPlan {
                planned_snapshot_id: self.snapshot_id,
                current_snapshot_id: inventory.snapshot_id(),
                planned_epoch: self.epoch,
                current_epoch: inventory.epoch(),
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleAddressBypassPlan {
    planned_snapshot_id: NetworkInventorySnapshotId,
    current_snapshot_id: NetworkInventorySnapshotId,
    planned_epoch: NetworkEpoch,
    current_epoch: NetworkEpoch,
}

impl StaleAddressBypassPlan {
    #[must_use]
    pub const fn planned_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.planned_snapshot_id
    }

    #[must_use]
    pub const fn current_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.current_snapshot_id
    }

    #[must_use]
    pub const fn planned_epoch(self) -> NetworkEpoch {
        self.planned_epoch
    }

    #[must_use]
    pub const fn current_epoch(self) -> NetworkEpoch {
        self.current_epoch
    }
}

impl fmt::Display for StaleAddressBypassPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "address-bypass plan snapshot {} at epoch {} is stale relative to snapshot {} at epoch {}",
            self.planned_snapshot_id.get(),
            self.planned_epoch.get(),
            self.current_snapshot_id.get(),
            self.current_epoch.get()
        )
    }
}

impl Error for StaleAddressBypassPlan {}

pub fn plan_address_host_set(
    inventory: &NetworkInventory,
    policy: &AddressHostSetPolicy,
) -> Result<AddressHostSetPlan, AddressHostSetPlanError> {
    let mut hosts = BTreeSet::new();
    let budget = policy.rule_budget();
    for record in inventory.addresses() {
        let selected = policy.selected_address(*record).map_err(|reason| {
            AddressHostSetPlanError::InvalidInventoryAddress {
                record: *record,
                reason,
            }
        })?;
        if let Some(address) = selected {
            hosts.insert(address);
            if hosts.len() > budget.get() as usize {
                return Err(AddressHostSetPlanError::HostBudgetExceeded {
                    budget,
                    required_at_least: budget.get() + 1,
                });
            }
        }
    }

    Ok(AddressHostSetPlan {
        snapshot_id: inventory.snapshot_id(),
        epoch: inventory.epoch(),
        families: policy.families(),
        hosts: hosts.into_iter().collect::<Vec<_>>().into_boxed_slice(),
    })
}

pub fn plan_address_bypass(
    inventory: &NetworkInventory,
    policy: &AddressBypassPolicy,
) -> Result<AddressBypassPlan, AddressBypassPlanError> {
    let host_set =
        plan_address_host_set(inventory, &policy.host_set).map_err(|error| match error {
            AddressHostSetPlanError::HostBudgetExceeded {
                budget,
                required_at_least,
            } => AddressBypassPlanError::RuleBudgetExceeded {
                budget,
                required_at_least,
            },
            AddressHostSetPlanError::InvalidInventoryAddress { record, reason } => {
                AddressBypassPlanError::InvalidInventoryAddress { record, reason }
            }
        })?;

    let intents = host_set
        .hosts()
        .iter()
        .copied()
        .map(|address| AddressBypassRuleIntent::new(address, policy.routing()))
        .collect::<Vec<_>>();
    let mut expected = BTreeMap::new();
    for (index, intent) in intents.iter().copied().enumerate() {
        expected.insert(intent.to_rule_record(), index);
    }

    let mut exact_seen = BTreeSet::new();
    let mut conflicts = Vec::new();
    let mut omitted_conflicts = 0_u32;
    for (dump_index, observed) in inventory.rules().iter().enumerate() {
        let family = observed.destination().family();
        if policy.routing().priority_for(family) != Some(observed.priority()) {
            continue;
        }

        let kind = match expected.get(observed).copied() {
            Some(index) if exact_seen.insert(index) => {
                AddressBypassRuleConflictKind::ExactRuleWithoutOwnership
            }
            Some(_) => AddressBypassRuleConflictKind::DuplicateExactRule,
            None => AddressBypassRuleConflictKind::UnexpectedRuleAtSelectedPriority,
        };
        if conflicts.len() < MAX_ADDRESS_BYPASS_CONFLICTS {
            conflicts.push(AddressBypassRuleConflict {
                kind,
                dump_index,
                observed: observed.clone(),
            });
        } else {
            omitted_conflicts = omitted_conflicts.saturating_add(1);
        }
    }
    if !conflicts.is_empty() || omitted_conflicts != 0 {
        return Err(AddressBypassPlanError::RoutingConflict {
            conflicts: conflicts.into_boxed_slice(),
            omitted_conflicts,
        });
    }

    Ok(AddressBypassPlan {
        snapshot_id: inventory.snapshot_id(),
        epoch: inventory.epoch(),
        routing: policy.routing(),
        intents: intents.into_boxed_slice(),
    })
}

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

fn normalize_exact_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

fn normalize_inventory_address(
    record: InterfaceAddressRecord,
) -> Result<IpAddr, AddressBypassInventoryAddressErrorKind> {
    let IpAddr::V6(ipv6) = record.address() else {
        return Ok(record.address());
    };
    let Some(ipv4) = ipv6.to_ipv4_mapped() else {
        return Ok(record.address());
    };
    if record.prefix_length() < 96 {
        return Err(AddressBypassInventoryAddressErrorKind::UnsupportedMappedPrefix);
    }
    Ok(IpAddr::V4(ipv4))
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

fn normalize_configured_prefix(
    address: IpAddr,
    prefix_length: u8,
) -> Result<(IpAddr, u8), AddressBypassPrefixError> {
    let IpAddr::V6(ipv6) = address else {
        return Ok((address, prefix_length));
    };
    let Some(ipv4) = ipv6.to_ipv4_mapped() else {
        return Ok((address, prefix_length));
    };
    if prefix_length > 128 {
        return Err(AddressBypassPrefixError::new(
            AddressBypassPrefixErrorKind::InvalidPrefixLength,
            address,
            prefix_length,
        ));
    }
    if prefix_length < 96 {
        return Err(AddressBypassPrefixError::new(
            AddressBypassPrefixErrorKind::UnsupportedMappedPrefix,
            address,
            prefix_length,
        ));
    }
    Ok((IpAddr::V4(ipv4), prefix_length - 96))
}

fn canonical_network_address(address: IpAddr, prefix_length: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let value = u32::from(address);
            let network = if prefix_length == 0 {
                0
            } else {
                value & (u32::MAX << (32 - prefix_length))
            };
            IpAddr::V4(Ipv4Addr::from(network))
        }
        IpAddr::V6(address) => {
            let value = u128::from_be_bytes(address.octets());
            let network = if prefix_length == 0 {
                0
            } else {
                value & (u128::MAX << (128 - prefix_length))
            };
            IpAddr::V6(Ipv6Addr::from(network.to_be_bytes()))
        }
    }
}
