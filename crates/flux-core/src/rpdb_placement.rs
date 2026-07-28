use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;

use crate::address_bypass::{AddressBypassRoutingSpec, AddressBypassRoutingSpecError};
use crate::network_inventory::{NetworkEpoch, NetworkInventory, NetworkInventorySnapshotId};
use crate::network_route::NetworkAddressFamily;
use crate::network_rule::{NetworkRuleRecord, RuleAction, RulePriority, RuleProtocol, RuleTableId};

const ADDRESS_BYPASS_LOOKUP_TABLE: u32 = 254;
const RESERVED_PRIVATE_TABLES: [u32; 4] = [0, 253, 254, 255];

const DEFERRED_ROUTING_PREREQUISITES: [DeferredRoutingPrerequisite; 5] = [
    DeferredRoutingPrerequisite::MarkLease,
    DeferredRoutingPrerequisite::BootIdentityBinding,
    DeferredRoutingPrerequisite::NetworkNamespaceBinding,
    DeferredRoutingPrerequisite::DurableOwnershipJournal,
    DeferredRoutingPrerequisite::ExactKernelMutationIdentity,
];

/// Revision of the external classifier that assigned meaning to observed RPDB rules.
///
/// The revision is deliberately caller-owned. This module validates placement relative to those
/// classifications but does not infer Android VPN or per-UID policy from numeric priorities.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RpdbClassifierRevision(NonZeroU64);

impl RpdbClassifierRevision {
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

/// External classification aligned one-to-one with the ordered rule inventory.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RpdbRuleClassification {
    /// The classified rule must evaluate before both proposed Flux rules.
    MustPrecedeFlux,
    /// Both proposed Flux rules must evaluate before the classified rule.
    TerminalBarrier,
    /// External evidence proves that the rule does not constrain this placement.
    DoesNotConstrainFlux,
    /// The external classifier lacks sufficient evidence for this rule.
    Unknown,
}

/// Versioned classifications for one exact ordered rule snapshot.
///
/// Platform classifiers may also attach crate-owned static policy bounds for rules that can be
/// absent from the current dump but remain reserved by the selected versioned grammar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpdbRuleAudit {
    snapshot_id: NetworkInventorySnapshotId,
    epoch: NetworkEpoch,
    classifier_revision: RpdbClassifierRevision,
    classifications: Box<[RpdbRuleClassification]>,
    ipv4_static_window: Option<RpdbPriorityWindow>,
    ipv6_static_window: Option<RpdbPriorityWindow>,
}

impl RpdbRuleAudit {
    pub fn new(
        classifier_revision: RpdbClassifierRevision,
        inventory: &NetworkInventory,
        classifications: impl IntoIterator<Item = RpdbRuleClassification>,
    ) -> Result<Self, RpdbRuleAuditError> {
        let classifications = classifications
            .into_iter()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let expected = inventory.rules().len();
        let actual = classifications.len();
        if actual != expected {
            return Err(RpdbRuleAuditError::ClassificationCountMismatch { expected, actual });
        }

        Ok(Self {
            snapshot_id: inventory.snapshot_id(),
            epoch: inventory.epoch(),
            classifier_revision,
            classifications,
            ipv4_static_window: None,
            ipv6_static_window: None,
        })
    }

    /// Adds classifier-owned static bounds that may not have a currently observed rule.
    ///
    /// This is crate-private because the public constructor deliberately models only aligned rule
    /// classifications. Versioned platform classifiers add static policy ranges through their
    /// own safe API rather than letting arbitrary callers strengthen or weaken an audit ad hoc.
    pub(crate) fn with_static_priority_window(
        mut self,
        family: NetworkAddressFamily,
        last_must_precede: RulePriority,
        first_terminal_barrier: RulePriority,
    ) -> Self {
        debug_assert!(last_must_precede < first_terminal_barrier);
        let window = Some(RpdbPriorityWindow {
            last_must_precede,
            first_terminal_barrier,
        });
        match family {
            NetworkAddressFamily::Ipv4 => self.ipv4_static_window = window,
            NetworkAddressFamily::Ipv6 => self.ipv6_static_window = window,
        }
        self
    }

    #[must_use]
    pub const fn snapshot_id(&self) -> NetworkInventorySnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub const fn epoch(&self) -> NetworkEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn classifier_revision(&self) -> RpdbClassifierRevision {
        self.classifier_revision
    }

    #[must_use]
    pub fn classifications(&self) -> &[RpdbRuleClassification] {
        &self.classifications
    }

    const fn static_priority_window(
        &self,
        family: NetworkAddressFamily,
    ) -> Option<RpdbPriorityWindow> {
        match family {
            NetworkAddressFamily::Ipv4 => self.ipv4_static_window,
            NetworkAddressFamily::Ipv6 => self.ipv6_static_window,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpdbRuleAuditError {
    ClassificationCountMismatch { expected: usize, actual: usize },
}

impl fmt::Display for RpdbRuleAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClassificationCountMismatch { expected, actual } => write!(
                formatter,
                "RPDB audit has {actual} classifications for {expected} observed rules"
            ),
        }
    }
}

impl Error for RpdbRuleAuditError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RpdbPriorityRole {
    AddressBypass,
    Proxy,
}

/// Candidate priorities and Flux-private route table for one address family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RpdbFamilyPlacement {
    address_bypass_priority: Option<RulePriority>,
    proxy_priority: RulePriority,
    private_table: RuleTableId,
}

impl RpdbFamilyPlacement {
    pub fn with_address_bypass(
        address_bypass_priority: RulePriority,
        proxy_priority: RulePriority,
        private_table: RuleTableId,
    ) -> Result<Self, RpdbFamilyPlacementError> {
        if address_bypass_priority.get() == 0 {
            return Err(RpdbFamilyPlacementError::UnspecifiedPriority {
                role: RpdbPriorityRole::AddressBypass,
            });
        }
        if proxy_priority.get() == 0 {
            return Err(RpdbFamilyPlacementError::UnspecifiedPriority {
                role: RpdbPriorityRole::Proxy,
            });
        }
        if address_bypass_priority >= proxy_priority {
            return Err(RpdbFamilyPlacementError::PriorityOrder {
                bypass: address_bypass_priority,
                proxy: proxy_priority,
            });
        }
        if RESERVED_PRIVATE_TABLES.contains(&private_table.get()) {
            return Err(RpdbFamilyPlacementError::ReservedPrivateTable {
                table: private_table,
            });
        }

        Ok(Self {
            address_bypass_priority: Some(address_bypass_priority),
            proxy_priority,
            private_table,
        })
    }

    /// Builds a one-rule placement for Capture Programs that bypass addresses before marking.
    pub fn proxy_only(
        proxy_priority: RulePriority,
        private_table: RuleTableId,
    ) -> Result<Self, RpdbFamilyPlacementError> {
        if proxy_priority.get() == 0 {
            return Err(RpdbFamilyPlacementError::UnspecifiedPriority {
                role: RpdbPriorityRole::Proxy,
            });
        }
        if RESERVED_PRIVATE_TABLES.contains(&private_table.get()) {
            return Err(RpdbFamilyPlacementError::ReservedPrivateTable {
                table: private_table,
            });
        }

        Ok(Self {
            address_bypass_priority: None,
            proxy_priority,
            private_table,
        })
    }

    #[must_use]
    pub const fn address_bypass_priority(self) -> Option<RulePriority> {
        self.address_bypass_priority
    }

    #[must_use]
    pub const fn proxy_priority(self) -> RulePriority {
        self.proxy_priority
    }

    #[must_use]
    pub const fn private_table(self) -> RuleTableId {
        self.private_table
    }

    const fn first_priority(self) -> RulePriority {
        match self.address_bypass_priority {
            Some(priority) => priority,
            None => self.proxy_priority,
        }
    }

    /// Whether every material priority lies strictly inside one ordered window.
    #[must_use]
    pub const fn fits_priority_window(
        self,
        lower_exclusive: RulePriority,
        upper_exclusive: RulePriority,
    ) -> bool {
        match self.address_bypass_priority {
            Some(bypass) => {
                lower_exclusive.get() < bypass.get()
                    && bypass.get() < self.proxy_priority.get()
                    && self.proxy_priority.get() < upper_exclusive.get()
            }
            None => {
                lower_exclusive.get() < self.proxy_priority.get()
                    && self.proxy_priority.get() < upper_exclusive.get()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpdbFamilyPlacementError {
    UnspecifiedPriority {
        role: RpdbPriorityRole,
    },
    PriorityOrder {
        bypass: RulePriority,
        proxy: RulePriority,
    },
    ReservedPrivateTable {
        table: RuleTableId,
    },
}

impl fmt::Display for RpdbFamilyPlacementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnspecifiedPriority { role } => {
                write!(formatter, "RPDB {role:?} priority is zero")
            }
            Self::PriorityOrder { bypass, proxy } => write!(
                formatter,
                "RPDB address-bypass priority {} is not before proxy priority {}",
                bypass.get(),
                proxy.get()
            ),
            Self::ReservedPrivateTable { table } => write!(
                formatter,
                "routing table {} is reserved and cannot be Flux-private",
                table.get()
            ),
        }
    }
}

impl Error for RpdbFamilyPlacementError {}

/// Atomic IPv4/IPv6 placement request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RpdbPlacementRequest {
    ipv4: Option<RpdbFamilyPlacement>,
    ipv6: Option<RpdbFamilyPlacement>,
}

impl RpdbPlacementRequest {
    pub const fn new(
        ipv4: Option<RpdbFamilyPlacement>,
        ipv6: Option<RpdbFamilyPlacement>,
    ) -> Result<Self, RpdbPlacementRequestError> {
        if ipv4.is_none() && ipv6.is_none() {
            return Err(RpdbPlacementRequestError::NoEnabledFamilies);
        }
        Ok(Self { ipv4, ipv6 })
    }

    #[must_use]
    pub const fn ipv4(self) -> Option<RpdbFamilyPlacement> {
        self.ipv4
    }

    #[must_use]
    pub const fn ipv6(self) -> Option<RpdbFamilyPlacement> {
        self.ipv6
    }

    #[must_use]
    pub const fn family(self, family: NetworkAddressFamily) -> Option<RpdbFamilyPlacement> {
        match family {
            NetworkAddressFamily::Ipv4 => self.ipv4,
            NetworkAddressFamily::Ipv6 => self.ipv6,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpdbPlacementRequestError {
    NoEnabledFamilies,
}

impl fmt::Display for RpdbPlacementRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RPDB placement request enables no address family")
    }
}

impl Error for RpdbPlacementRequestError {}

/// Proven numeric bounds surrounding one admitted family placement.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RpdbPriorityWindow {
    last_must_precede: RulePriority,
    first_terminal_barrier: RulePriority,
}

impl RpdbPriorityWindow {
    #[must_use]
    pub const fn last_must_precede(self) -> RulePriority {
        self.last_must_precede
    }

    #[must_use]
    pub const fn first_terminal_barrier(self) -> RulePriority {
        self.first_terminal_barrier
    }
}

/// Prerequisites deliberately not proven by the placement audit.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DeferredRoutingPrerequisite {
    MarkLease,
    BootIdentityBinding,
    NetworkNamespaceBinding,
    DurableOwnershipJournal,
    ExactKernelMutationIdentity,
}

/// Process-local evidence for collision-free RPDB placement in one exact snapshot.
///
/// This lease is not activation authority. In particular, it does not prove selector overlap,
/// route reachability, Android VPN safety, object ownership, or exact mutation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpdbPlacementLease {
    snapshot_id: NetworkInventorySnapshotId,
    epoch: NetworkEpoch,
    classifier_revision: RpdbClassifierRevision,
    request: RpdbPlacementRequest,
    ipv4_window: Option<RpdbPriorityWindow>,
    ipv6_window: Option<RpdbPriorityWindow>,
}

impl RpdbPlacementLease {
    #[must_use]
    pub const fn snapshot_id(self) -> NetworkInventorySnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub const fn epoch(self) -> NetworkEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn classifier_revision(self) -> RpdbClassifierRevision {
        self.classifier_revision
    }

    #[must_use]
    pub const fn request(self) -> RpdbPlacementRequest {
        self.request
    }

    #[must_use]
    pub const fn family(self, family: NetworkAddressFamily) -> Option<RpdbFamilyPlacement> {
        self.request.family(family)
    }

    #[must_use]
    pub const fn window(self, family: NetworkAddressFamily) -> Option<RpdbPriorityWindow> {
        match family {
            NetworkAddressFamily::Ipv4 => self.ipv4_window,
            NetworkAddressFamily::Ipv6 => self.ipv6_window,
        }
    }

    pub fn ensure_current(
        &self,
        inventory: &NetworkInventory,
        classifier_revision: RpdbClassifierRevision,
    ) -> Result<(), StaleRpdbPlacementLease> {
        if inventory.snapshot_id() == self.snapshot_id
            && inventory.epoch() == self.epoch
            && classifier_revision == self.classifier_revision
        {
            Ok(())
        } else {
            Err(StaleRpdbPlacementLease {
                leased_snapshot_id: self.snapshot_id,
                current_snapshot_id: inventory.snapshot_id(),
                leased_epoch: self.epoch,
                current_epoch: inventory.epoch(),
                leased_classifier_revision: self.classifier_revision,
                current_classifier_revision: classifier_revision,
            })
        }
    }

    /// Projects the admitted bypass priorities into the structural address-bypass API.
    ///
    /// The bypass target is deliberately fixed to Linux table 254 (main). The per-family private
    /// tables belong to later Flux proxy routing and are never used as address-bypass targets.
    pub fn address_bypass_routing_spec(
        &self,
        protocol: RuleProtocol,
    ) -> Result<AddressBypassRoutingSpec, AddressBypassRoutingSpecError> {
        AddressBypassRoutingSpec::new(
            RuleTableId::from_raw(ADDRESS_BYPASS_LOOKUP_TABLE),
            protocol,
            self.request
                .ipv4
                .and_then(RpdbFamilyPlacement::address_bypass_priority),
            self.request
                .ipv6
                .and_then(RpdbFamilyPlacement::address_bypass_priority),
        )
    }

    #[must_use]
    /// Returns the identity and ownership prerequisites modeled explicitly by this checkpoint.
    ///
    /// This is not an exhaustive activation checklist. The lease-level documentation also defers
    /// semantic classifier implementation, selector overlap, route reachability, native encoding,
    /// and contained device canaries.
    pub const fn deferred_prerequisites(self) -> &'static [DeferredRoutingPrerequisite] {
        &DEFERRED_ROUTING_PREREQUISITES
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleRpdbPlacementLease {
    leased_snapshot_id: NetworkInventorySnapshotId,
    current_snapshot_id: NetworkInventorySnapshotId,
    leased_epoch: NetworkEpoch,
    current_epoch: NetworkEpoch,
    leased_classifier_revision: RpdbClassifierRevision,
    current_classifier_revision: RpdbClassifierRevision,
}

impl StaleRpdbPlacementLease {
    #[must_use]
    pub const fn leased_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.leased_snapshot_id
    }

    #[must_use]
    pub const fn current_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.current_snapshot_id
    }

    #[must_use]
    pub const fn leased_epoch(self) -> NetworkEpoch {
        self.leased_epoch
    }

    #[must_use]
    pub const fn current_epoch(self) -> NetworkEpoch {
        self.current_epoch
    }

    #[must_use]
    pub const fn leased_classifier_revision(self) -> RpdbClassifierRevision {
        self.leased_classifier_revision
    }

    #[must_use]
    pub const fn current_classifier_revision(self) -> RpdbClassifierRevision {
        self.current_classifier_revision
    }
}

impl fmt::Display for StaleRpdbPlacementLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "RPDB placement lease for snapshot {} at epoch {} and classifier revision {} is stale relative to snapshot {} at epoch {} and revision {}",
            self.leased_snapshot_id.get(),
            self.leased_epoch.get(),
            self.leased_classifier_revision.get(),
            self.current_snapshot_id.get(),
            self.current_epoch.get(),
            self.current_classifier_revision.get()
        )
    }
}

impl Error for StaleRpdbPlacementLease {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpdbPlacementPlanError {
    AuditSnapshotMismatch {
        inventory: NetworkInventorySnapshotId,
        audit: NetworkInventorySnapshotId,
    },
    AuditEpochMismatch {
        inventory: NetworkEpoch,
        audit: NetworkEpoch,
    },
    UnknownRule {
        family: NetworkAddressFamily,
        dump_index: usize,
    },
    OpaqueRule {
        family: NetworkAddressFamily,
        dump_index: usize,
    },
    MissingMustPrecedeBoundary {
        family: NetworkAddressFamily,
    },
    MissingTerminalBarrier {
        family: NetworkAddressFamily,
    },
    PriorityOccupied {
        family: NetworkAddressFamily,
        role: RpdbPriorityRole,
        dump_index: usize,
    },
    GotoIntersectsCandidateWindow {
        family: NetworkAddressFamily,
        dump_index: usize,
        source: RulePriority,
        target: RulePriority,
        first_candidate: RulePriority,
        proxy: RulePriority,
    },
    PriorityWindowViolation {
        family: NetworkAddressFamily,
        last_must_precede: RulePriority,
        address_bypass: Option<RulePriority>,
        proxy: RulePriority,
        first_terminal_barrier: RulePriority,
    },
    PrivateTableRouteOccupied {
        family: NetworkAddressFamily,
        dump_index: usize,
        table: RuleTableId,
    },
    PrivateTableRuleOccupied {
        family: NetworkAddressFamily,
        dump_index: usize,
        table: RuleTableId,
    },
}

impl fmt::Display for RpdbPlacementPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuditSnapshotMismatch { inventory, audit } => write!(
                formatter,
                "RPDB audit snapshot {} does not match inventory snapshot {}",
                audit.get(),
                inventory.get()
            ),
            Self::AuditEpochMismatch { inventory, audit } => write!(
                formatter,
                "RPDB audit epoch {} does not match inventory epoch {}",
                audit.get(),
                inventory.get()
            ),
            Self::UnknownRule { family, dump_index } => write!(
                formatter,
                "RPDB rule {dump_index} for {family:?} has no trusted classification"
            ),
            Self::OpaqueRule { family, dump_index } => write!(
                formatter,
                "RPDB rule {dump_index} for {family:?} contains unmodeled attributes"
            ),
            Self::MissingMustPrecedeBoundary { family } => write!(
                formatter,
                "RPDB placement for {family:?} has no must-precede boundary"
            ),
            Self::MissingTerminalBarrier { family } => write!(
                formatter,
                "RPDB placement for {family:?} has no terminal barrier"
            ),
            Self::PriorityOccupied {
                family,
                role,
                dump_index,
            } => write!(
                formatter,
                "RPDB {role:?} priority for {family:?} is occupied by rule {dump_index}"
            ),
            Self::GotoIntersectsCandidateWindow {
                family,
                dump_index,
                source,
                target,
                first_candidate,
                proxy,
            } => write!(
                formatter,
                "RPDB GOTO rule {dump_index} for {family:?} from {} to {} intersects candidate window {}..{}",
                source.get(),
                target.get(),
                first_candidate.get(),
                proxy.get()
            ),
            Self::PriorityWindowViolation {
                family,
                last_must_precede,
                address_bypass: Some(address_bypass),
                proxy,
                first_terminal_barrier,
            } => write!(
                formatter,
                "RPDB placement for {family:?} does not satisfy {} < {} < {} < {}",
                last_must_precede.get(),
                address_bypass.get(),
                proxy.get(),
                first_terminal_barrier.get()
            ),
            Self::PriorityWindowViolation {
                family,
                last_must_precede,
                address_bypass: None,
                proxy,
                first_terminal_barrier,
            } => write!(
                formatter,
                "RPDB placement for {family:?} does not satisfy {} < {} < {}",
                last_must_precede.get(),
                proxy.get(),
                first_terminal_barrier.get()
            ),
            Self::PrivateTableRouteOccupied {
                family,
                dump_index,
                table,
            } => write!(
                formatter,
                "Flux-private table {} for {family:?} is occupied by route {dump_index}",
                table.get()
            ),
            Self::PrivateTableRuleOccupied {
                family,
                dump_index,
                table,
            } => write!(
                formatter,
                "Flux-private table {} for {family:?} is referenced by rule {dump_index}",
                table.get()
            ),
        }
    }
}

impl Error for RpdbPlacementPlanError {}

/// Audits an atomic placement request against one complete inventory and aligned classification.
pub fn plan_rpdb_placement(
    inventory: &NetworkInventory,
    audit: &RpdbRuleAudit,
    request: RpdbPlacementRequest,
) -> Result<RpdbPlacementLease, RpdbPlacementPlanError> {
    if inventory.epoch() != audit.epoch {
        return Err(RpdbPlacementPlanError::AuditEpochMismatch {
            inventory: inventory.epoch(),
            audit: audit.epoch,
        });
    }
    if inventory.snapshot_id() != audit.snapshot_id {
        return Err(RpdbPlacementPlanError::AuditSnapshotMismatch {
            inventory: inventory.snapshot_id(),
            audit: audit.snapshot_id,
        });
    }

    let ipv4_window = request
        .ipv4
        .map(|placement| plan_family(inventory, audit, NetworkAddressFamily::Ipv4, placement))
        .transpose()?;
    let ipv6_window = request
        .ipv6
        .map(|placement| plan_family(inventory, audit, NetworkAddressFamily::Ipv6, placement))
        .transpose()?;

    Ok(RpdbPlacementLease {
        snapshot_id: inventory.snapshot_id(),
        epoch: inventory.epoch(),
        classifier_revision: audit.classifier_revision,
        request,
        ipv4_window,
        ipv6_window,
    })
}

fn plan_family(
    inventory: &NetworkInventory,
    audit: &RpdbRuleAudit,
    family: NetworkAddressFamily,
    placement: RpdbFamilyPlacement,
) -> Result<RpdbPriorityWindow, RpdbPlacementPlanError> {
    let static_window = audit.static_priority_window(family);
    let mut last_must_precede = static_window.map(RpdbPriorityWindow::last_must_precede);
    let mut first_terminal_barrier = static_window.map(RpdbPriorityWindow::first_terminal_barrier);

    for (dump_index, (rule, classification)) in inventory
        .rules()
        .iter()
        .zip(audit.classifications.iter())
        .enumerate()
    {
        if rule.destination().family() != family {
            continue;
        }
        if !rule.has_complete_attribute_coverage() {
            return Err(RpdbPlacementPlanError::OpaqueRule { family, dump_index });
        }

        match classification {
            RpdbRuleClassification::MustPrecedeFlux => {
                last_must_precede = Some(last_must_precede.map_or(rule.priority(), |current| {
                    std::cmp::max(current, rule.priority())
                }));
            }
            RpdbRuleClassification::TerminalBarrier => {
                first_terminal_barrier =
                    Some(first_terminal_barrier.map_or(rule.priority(), |current| {
                        std::cmp::min(current, rule.priority())
                    }));
            }
            RpdbRuleClassification::DoesNotConstrainFlux => {}
            RpdbRuleClassification::Unknown => {
                return Err(RpdbPlacementPlanError::UnknownRule { family, dump_index });
            }
        }
    }

    let last_must_precede =
        last_must_precede.ok_or(RpdbPlacementPlanError::MissingMustPrecedeBoundary { family })?;
    let first_terminal_barrier =
        first_terminal_barrier.ok_or(RpdbPlacementPlanError::MissingTerminalBarrier { family })?;

    for (dump_index, rule) in inventory.rules().iter().enumerate() {
        if rule.destination().family() != family {
            continue;
        }
        let role = if rule.priority() == placement.proxy_priority {
            Some(RpdbPriorityRole::Proxy)
        } else if placement
            .address_bypass_priority()
            .is_some_and(|priority| rule.priority() == priority)
        {
            Some(RpdbPriorityRole::AddressBypass)
        } else {
            None
        };
        if let Some(role) = role {
            return Err(RpdbPlacementPlanError::PriorityOccupied {
                family,
                role,
                dump_index,
            });
        }
    }

    for (dump_index, rule) in inventory.rules().iter().enumerate() {
        if rule.destination().family() != family {
            continue;
        }
        if let Some(target) = rule.goto_target()
            && rule.priority() <= placement.proxy_priority
            && target >= placement.first_priority()
        {
            return Err(RpdbPlacementPlanError::GotoIntersectsCandidateWindow {
                family,
                dump_index,
                source: rule.priority(),
                target,
                first_candidate: placement.first_priority(),
                proxy: placement.proxy_priority,
            });
        }
    }

    if !placement.fits_priority_window(last_must_precede, first_terminal_barrier) {
        return Err(RpdbPlacementPlanError::PriorityWindowViolation {
            family,
            last_must_precede,
            address_bypass: placement.address_bypass_priority,
            proxy: placement.proxy_priority,
            first_terminal_barrier,
        });
    }

    for (dump_index, route) in inventory.routes().iter().enumerate() {
        if route.destination().family() == family
            && route.properties().table().get() == placement.private_table.get()
        {
            return Err(RpdbPlacementPlanError::PrivateTableRouteOccupied {
                family,
                dump_index,
                table: placement.private_table,
            });
        }
    }

    for (dump_index, rule) in inventory.rules().iter().enumerate() {
        if rule.destination().family() == family
            && rule_may_reference_table(rule, placement.private_table)
        {
            return Err(RpdbPlacementPlanError::PrivateTableRuleOccupied {
                family,
                dump_index,
                table: placement.private_table,
            });
        }
    }

    Ok(RpdbPriorityWindow {
        last_must_precede,
        first_terminal_barrier,
    })
}

fn rule_may_reference_table(rule: &NetworkRuleRecord, table: RuleTableId) -> bool {
    if rule.properties().table() != table {
        return false;
    }

    let action = rule.properties().action();
    let known_non_table_action = action == RuleAction::GOTO
        || action == RuleAction::NOP
        || action == RuleAction::BLACKHOLE
        || action == RuleAction::UNREACHABLE
        || action == RuleAction::PROHIBIT;
    !known_non_table_action
}
