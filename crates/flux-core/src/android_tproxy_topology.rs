use std::error::Error;
use std::fmt;

use crate::android_rpdb::{
    AndroidRpdbClassificationReport, AndroidRpdbPolicyProfile, AndroidRpdbRuleRole,
};
use crate::network_inventory::{
    InterfaceIndex, InterfaceLinkFlags, InterfaceName, NetworkEpoch, NetworkInventory,
    NetworkInventorySnapshotId,
};
use crate::network_route::NetworkAddressFamily;
use crate::network_rule::{RuleFwMark, RulePriority, RuleTableId};
use crate::rpdb_placement::{RpdbClassifierRevision, RpdbRuleClassification};

const ANDROID_LOCAL_NETWORK_PRIORITY: RulePriority = RulePriority::from_raw(20_000);
const ANDROID_TETHERING_PRIORITY: RulePriority = RulePriority::from_raw(21_000);

const COMMON_DEFERRED_ANDROID_TPROXY_PREREQUISITES: [DeferredAndroidTproxyPrerequisite; 10] = [
    DeferredAndroidTproxyPrerequisite::PositiveMarkAuthority,
    DeferredAndroidTproxyPrerequisite::ExactCaptureOrdering,
    DeferredAndroidTproxyPrerequisite::DomainIdentityHandoff,
    DeferredAndroidTproxyPrerequisite::NetworkSelectionHandoff,
    DeferredAndroidTproxyPrerequisite::RouteReachabilityCanary,
    DeferredAndroidTproxyPrerequisite::BootAndNamespaceBinding,
    DeferredAndroidTproxyPrerequisite::ObserverContinuity,
    DeferredAndroidTproxyPrerequisite::DurableOwnershipJournal,
    DeferredAndroidTproxyPrerequisite::ExactMutationIdentity,
    DeferredAndroidTproxyPrerequisite::EngineLoopEscape,
];

const PRE_MARK_DEFERRED_ANDROID_TPROXY_PREREQUISITES: [DeferredAndroidTproxyPrerequisite; 11] = [
    DeferredAndroidTproxyPrerequisite::OneRuleAddressHandling,
    DeferredAndroidTproxyPrerequisite::PositiveMarkAuthority,
    DeferredAndroidTproxyPrerequisite::ExactCaptureOrdering,
    DeferredAndroidTproxyPrerequisite::DomainIdentityHandoff,
    DeferredAndroidTproxyPrerequisite::NetworkSelectionHandoff,
    DeferredAndroidTproxyPrerequisite::RouteReachabilityCanary,
    DeferredAndroidTproxyPrerequisite::BootAndNamespaceBinding,
    DeferredAndroidTproxyPrerequisite::ObserverContinuity,
    DeferredAndroidTproxyPrerequisite::DurableOwnershipJournal,
    DeferredAndroidTproxyPrerequisite::ExactMutationIdentity,
    DeferredAndroidTproxyPrerequisite::EngineLoopEscape,
];

/// Traffic domain anchored to one exact, observed Android network-selection rule.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidTproxyTrafficDomainKind {
    /// Locally originated traffic that would otherwise reach one exact default-network rule.
    ResidualLocalOutput,
    /// Forwarded traffic entering through the exact interface of one tethering rule.
    TetherIngress,
}

/// Routing shape whose integer-priority demand is being assessed.
///
/// Neither shape is an activation plan. `PreMarkAddressHostSet` assumes that a later Capture
/// Program proves address-derived bypass before every mark restore/write and proxy action.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidTproxyRoutingShape {
    DedicatedAddressBypassRule,
    PreMarkAddressHostSet,
}

impl AndroidTproxyRoutingShape {
    #[must_use]
    pub const fn required_priority_slots(self) -> u8 {
        match self {
            Self::DedicatedAddressBypassRule => 2,
            Self::PreMarkAddressHostSet => 1,
        }
    }
}

/// Exact selector evidence retained for one traffic domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AndroidTproxyDomainSelector {
    family: NetworkAddressFamily,
    input_interface: InterfaceName,
    android_fwmark: Option<RuleFwMark>,
}

impl AndroidTproxyDomainSelector {
    #[must_use]
    pub const fn family(self) -> NetworkAddressFamily {
        self.family
    }

    #[must_use]
    pub const fn input_interface(self) -> InterfaceName {
        self.input_interface
    }

    /// Android-owned mark predicate copied from the selection anchor.
    ///
    /// A later Flux rule must conjunct this predicate with a separately authorized Flux mark while
    /// preserving Android-owned bits. This is not mark allocation authority.
    #[must_use]
    pub const fn android_fwmark(self) -> Option<RuleFwMark> {
        self.android_fwmark
    }
}

/// Exact observed Android rule used as the domain's active selection anchor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AndroidTproxySelectionAnchor {
    dump_index: usize,
    role: AndroidRpdbRuleRole,
    priority: RulePriority,
    lookup_table: RuleTableId,
}

impl AndroidTproxySelectionAnchor {
    #[must_use]
    pub const fn dump_index(self) -> usize {
        self.dump_index
    }

    #[must_use]
    pub const fn role(self) -> AndroidRpdbRuleRole {
        self.role
    }

    #[must_use]
    pub const fn priority(self) -> RulePriority {
        self.priority
    }

    /// Observed table evidence only; a table number is not a stable Android network identity.
    #[must_use]
    pub const fn lookup_table(self) -> RuleTableId {
        self.lookup_table
    }
}

/// Open integer interval in which a domain-specific Flux rule would have to reside.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AndroidTproxyPriorityInterval {
    android_first_through: RulePriority,
    flux_first_before: RulePriority,
}

impl AndroidTproxyPriorityInterval {
    #[must_use]
    pub const fn android_first_through(self) -> RulePriority {
        self.android_first_through
    }

    #[must_use]
    pub const fn flux_first_before(self) -> RulePriority {
        self.flux_first_before
    }

    #[must_use]
    pub const fn open_priority_count(self) -> u32 {
        self.flux_first_before
            .get()
            .saturating_sub(self.android_first_through.get())
            .saturating_sub(1)
    }

    #[must_use]
    pub const fn first_open_priority(self) -> Option<RulePriority> {
        if self.open_priority_count() == 0 {
            None
        } else {
            Some(RulePriority::from_raw(self.android_first_through.get() + 1))
        }
    }

    #[must_use]
    pub const fn last_open_priority(self) -> Option<RulePriority> {
        if self.open_priority_count() == 0 {
            None
        } else {
            Some(RulePriority::from_raw(self.flux_first_before.get() - 1))
        }
    }
}

/// Exact selector reason that one trusted Android rule cannot match this domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidTproxySelectorDisjointReason {
    InputInterfaceMismatch,
    FwmarkPredicateConflict,
}

/// Domain-relative disposition aligned one-to-one with the ordered inventory rule list.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidTproxyRuleDisposition {
    OtherFamily,
    /// Android policy remains before any candidate in the reported open interval.
    AndroidFirst,
    /// Flux would run before this overlapping Android selection and therefore needs a handoff.
    FluxFirstRequiresHandoff,
    SelectorDisjoint(AndroidTproxySelectorDisjointReason),
    Unknown,
}

/// Completeness of aligned classifier and selector evidence for this one domain.
///
/// `Complete` does not satisfy any item in `DeferredAndroidTproxyPrerequisite`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidTproxyEvidenceCoverage {
    Complete,
    Incomplete,
}

/// Structural result only; no variant is priority allocation or Android-policy safety evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidTproxyStructuralFeasibility {
    IncompatibleTrafficDomain {
        shape: AndroidTproxyRoutingShape,
        domain: AndroidTproxyTrafficDomainKind,
    },
    IncompleteEvidence {
        unknown_rule_count: u32,
    },
    InsufficientPrioritySlots {
        shape: AndroidTproxyRoutingShape,
        required: u8,
        available: u32,
    },
    ResidualCandidateWindow {
        shape: AndroidTproxyRoutingShape,
        required: u8,
        available: u32,
    },
}

/// Preconditions deliberately not proven by this structural report.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DeferredAndroidTproxyPrerequisite {
    OneRuleAddressHandling,
    PositiveMarkAuthority,
    ExactCaptureOrdering,
    DomainIdentityHandoff,
    NetworkSelectionHandoff,
    RouteReachabilityCanary,
    BootAndNamespaceBinding,
    ObserverContinuity,
    DurableOwnershipJournal,
    ExactMutationIdentity,
    EngineLoopEscape,
}

/// Snapshot-bound, traffic-domain-aware Android TPROXY topology evidence.
///
/// The report intentionally exposes no selected priority, placement lease, mark lease, route
/// intent, or mutation identity. Even a complete `ResidualCandidateWindow` still intercepts
/// before the anchor chooses the eventual Android network and therefore requires every deferred
/// prerequisite below.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidTproxyTopologyFeasibilityReport {
    snapshot_id: NetworkInventorySnapshotId,
    epoch: NetworkEpoch,
    classifier_revision: RpdbClassifierRevision,
    profile: AndroidRpdbPolicyProfile,
    kind: AndroidTproxyTrafficDomainKind,
    selector: AndroidTproxyDomainSelector,
    input_interface_index: InterfaceIndex,
    anchor: AndroidTproxySelectionAnchor,
    interval: AndroidTproxyPriorityInterval,
    dispositions: Box<[AndroidTproxyRuleDisposition]>,
    unknown_rule_count: u32,
}

impl AndroidTproxyTopologyFeasibilityReport {
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
    pub const fn profile(&self) -> AndroidRpdbPolicyProfile {
        self.profile
    }

    #[must_use]
    pub const fn kind(&self) -> AndroidTproxyTrafficDomainKind {
        self.kind
    }

    #[must_use]
    pub const fn selector(&self) -> AndroidTproxyDomainSelector {
        self.selector
    }

    #[must_use]
    pub const fn input_interface_index(&self) -> InterfaceIndex {
        self.input_interface_index
    }

    #[must_use]
    pub const fn anchor(&self) -> AndroidTproxySelectionAnchor {
        self.anchor
    }

    #[must_use]
    pub const fn interval(&self) -> AndroidTproxyPriorityInterval {
        self.interval
    }

    #[must_use]
    pub fn dispositions(&self) -> &[AndroidTproxyRuleDisposition] {
        &self.dispositions
    }

    #[must_use]
    pub const fn unknown_rule_count(&self) -> u32 {
        self.unknown_rule_count
    }

    #[must_use]
    pub const fn evidence_coverage(&self) -> AndroidTproxyEvidenceCoverage {
        if self.unknown_rule_count == 0 {
            AndroidTproxyEvidenceCoverage::Complete
        } else {
            AndroidTproxyEvidenceCoverage::Incomplete
        }
    }

    #[must_use]
    pub const fn structural_feasibility(
        &self,
        shape: AndroidTproxyRoutingShape,
    ) -> AndroidTproxyStructuralFeasibility {
        if matches!(
            (self.kind, shape),
            (
                AndroidTproxyTrafficDomainKind::TetherIngress,
                AndroidTproxyRoutingShape::DedicatedAddressBypassRule
            )
        ) {
            return AndroidTproxyStructuralFeasibility::IncompatibleTrafficDomain {
                shape,
                domain: self.kind,
            };
        }
        if self.unknown_rule_count != 0 {
            return AndroidTproxyStructuralFeasibility::IncompleteEvidence {
                unknown_rule_count: self.unknown_rule_count,
            };
        }

        let required = shape.required_priority_slots();
        let available = self.interval.open_priority_count();
        if available < required as u32 {
            AndroidTproxyStructuralFeasibility::InsufficientPrioritySlots {
                shape,
                required,
                available,
            }
        } else {
            AndroidTproxyStructuralFeasibility::ResidualCandidateWindow {
                shape,
                required,
                available,
            }
        }
    }

    #[must_use]
    pub const fn deferred_prerequisites(
        &self,
        shape: AndroidTproxyRoutingShape,
    ) -> &'static [DeferredAndroidTproxyPrerequisite] {
        match shape {
            AndroidTproxyRoutingShape::DedicatedAddressBypassRule => {
                &COMMON_DEFERRED_ANDROID_TPROXY_PREREQUISITES
            }
            AndroidTproxyRoutingShape::PreMarkAddressHostSet => {
                &PRE_MARK_DEFERRED_ANDROID_TPROXY_PREREQUISITES
            }
        }
    }

    pub fn ensure_current(
        &self,
        inventory: &NetworkInventory,
        classification: &AndroidRpdbClassificationReport,
    ) -> Result<(), StaleAndroidTproxyTopologyReport> {
        if assess_android_tproxy_topology(inventory, classification, self.anchor.dump_index())
            .is_ok_and(|current| &current == self)
        {
            Ok(())
        } else {
            Err(StaleAndroidTproxyTopologyReport {
                reported_snapshot_id: self.snapshot_id,
                current_inventory_snapshot_id: inventory.snapshot_id(),
                current_classification_snapshot_id: classification.audit().snapshot_id(),
                reported_epoch: self.epoch,
                current_inventory_epoch: inventory.epoch(),
                current_classification_epoch: classification.audit().epoch(),
                reported_profile: self.profile,
                current_profile: classification.profile(),
                reported_classifier_revision: self.classifier_revision,
                current_classifier_revision: classification.audit().classifier_revision(),
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleAndroidTproxyTopologyReport {
    reported_snapshot_id: NetworkInventorySnapshotId,
    current_inventory_snapshot_id: NetworkInventorySnapshotId,
    current_classification_snapshot_id: NetworkInventorySnapshotId,
    reported_epoch: NetworkEpoch,
    current_inventory_epoch: NetworkEpoch,
    current_classification_epoch: NetworkEpoch,
    reported_profile: AndroidRpdbPolicyProfile,
    current_profile: AndroidRpdbPolicyProfile,
    reported_classifier_revision: RpdbClassifierRevision,
    current_classifier_revision: RpdbClassifierRevision,
}

impl StaleAndroidTproxyTopologyReport {
    #[must_use]
    pub const fn reported_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.reported_snapshot_id
    }

    #[must_use]
    pub const fn current_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.current_inventory_snapshot_id
    }

    #[must_use]
    pub const fn current_classification_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.current_classification_snapshot_id
    }

    #[must_use]
    pub const fn reported_epoch(self) -> NetworkEpoch {
        self.reported_epoch
    }

    #[must_use]
    pub const fn current_epoch(self) -> NetworkEpoch {
        self.current_inventory_epoch
    }

    #[must_use]
    pub const fn current_classification_epoch(self) -> NetworkEpoch {
        self.current_classification_epoch
    }

    #[must_use]
    pub const fn reported_profile(self) -> AndroidRpdbPolicyProfile {
        self.reported_profile
    }

    #[must_use]
    pub const fn current_profile(self) -> AndroidRpdbPolicyProfile {
        self.current_profile
    }

    #[must_use]
    pub const fn reported_classifier_revision(self) -> RpdbClassifierRevision {
        self.reported_classifier_revision
    }

    #[must_use]
    pub const fn current_classifier_revision(self) -> RpdbClassifierRevision {
        self.current_classifier_revision
    }
}

impl fmt::Display for StaleAndroidTproxyTopologyReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Android TPROXY topology report for snapshot {} at epoch {} with profile {:?} and classifier revision {} is stale relative to inventory snapshot {} at epoch {} and classification snapshot {} at epoch {} with profile {:?} and revision {}",
            self.reported_snapshot_id.get(),
            self.reported_epoch.get(),
            self.reported_profile,
            self.reported_classifier_revision.get(),
            self.current_inventory_snapshot_id.get(),
            self.current_inventory_epoch.get(),
            self.current_classification_snapshot_id.get(),
            self.current_classification_epoch.get(),
            self.current_profile,
            self.current_classifier_revision.get()
        )
    }
}

impl Error for StaleAndroidTproxyTopologyReport {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidTproxyTopologyError {
    ClassifierSnapshotMismatch {
        inventory: NetworkInventorySnapshotId,
        classifier: NetworkInventorySnapshotId,
    },
    ClassifierEpochMismatch {
        inventory: NetworkEpoch,
        classifier: NetworkEpoch,
    },
    AnchorOutOfBounds {
        dump_index: usize,
        rule_count: usize,
    },
    UnsupportedAnchorRole {
        dump_index: usize,
        role: Option<AndroidRpdbRuleRole>,
    },
    UntrustedAnchor {
        dump_index: usize,
    },
    MissingAnchorInputInterface {
        dump_index: usize,
    },
    MissingAnchorLink {
        dump_index: usize,
        name: InterfaceName,
    },
    AnchorLinkIsDown {
        dump_index: usize,
        interface_index: InterfaceIndex,
    },
    LocalAnchorIsNotLoopback {
        dump_index: usize,
        interface_index: InterfaceIndex,
    },
    TetherAnchorUsesLoopback {
        dump_index: usize,
        interface_index: InterfaceIndex,
    },
    AmbiguousSelectionAnchor {
        dump_index: usize,
        conflicting_dump_index: usize,
        table: RuleTableId,
        conflicting_table: RuleTableId,
    },
}

impl fmt::Display for AndroidTproxyTopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClassifierSnapshotMismatch {
                inventory,
                classifier,
            } => write!(
                formatter,
                "Android classifier snapshot {} does not match topology inventory snapshot {}",
                classifier.get(),
                inventory.get()
            ),
            Self::ClassifierEpochMismatch {
                inventory,
                classifier,
            } => write!(
                formatter,
                "Android classifier epoch {} does not match topology inventory epoch {}",
                classifier.get(),
                inventory.get()
            ),
            Self::AnchorOutOfBounds {
                dump_index,
                rule_count,
            } => write!(
                formatter,
                "Android TPROXY anchor index {dump_index} is outside {rule_count} observed rules"
            ),
            Self::UnsupportedAnchorRole { dump_index, role } => write!(
                formatter,
                "Android TPROXY anchor rule {dump_index} has unsupported role {role:?}"
            ),
            Self::UntrustedAnchor { dump_index } => write!(
                formatter,
                "Android TPROXY anchor rule {dump_index} belongs to an incomplete classifier family"
            ),
            Self::MissingAnchorInputInterface { dump_index } => write!(
                formatter,
                "Android TPROXY anchor rule {dump_index} has no exact input interface"
            ),
            Self::MissingAnchorLink { dump_index, name } => write!(
                formatter,
                "Android TPROXY anchor rule {dump_index} references absent link {name:?}"
            ),
            Self::AnchorLinkIsDown {
                dump_index,
                interface_index,
            } => write!(
                formatter,
                "Android TPROXY anchor rule {dump_index} resolves to down interface index {}",
                interface_index.get()
            ),
            Self::LocalAnchorIsNotLoopback {
                dump_index,
                interface_index,
            } => write!(
                formatter,
                "local-output anchor rule {dump_index} resolves to non-loopback interface index {}",
                interface_index.get()
            ),
            Self::TetherAnchorUsesLoopback {
                dump_index,
                interface_index,
            } => write!(
                formatter,
                "tether anchor rule {dump_index} resolves to loopback interface index {}",
                interface_index.get()
            ),
            Self::AmbiguousSelectionAnchor {
                dump_index,
                conflicting_dump_index,
                table,
                conflicting_table,
            } => write!(
                formatter,
                "Android TPROXY anchor rule {dump_index} table {} overlaps rule {conflicting_dump_index} table {}",
                table.get(),
                conflicting_table.get()
            ),
        }
    }
}

impl Error for AndroidTproxyTopologyError {}

/// Assesses one exact observed default-network or tethering selection anchor.
///
/// The anchor index is intentionally explicit. Static profile priorities reserve future Android
/// rules but do not prove that a usable network-selection rule currently exists.
pub fn assess_android_tproxy_topology(
    inventory: &NetworkInventory,
    classification: &AndroidRpdbClassificationReport,
    anchor_dump_index: usize,
) -> Result<AndroidTproxyTopologyFeasibilityReport, AndroidTproxyTopologyError> {
    if inventory.epoch() != classification.audit().epoch() {
        return Err(AndroidTproxyTopologyError::ClassifierEpochMismatch {
            inventory: inventory.epoch(),
            classifier: classification.audit().epoch(),
        });
    }
    if inventory.snapshot_id() != classification.audit().snapshot_id() {
        return Err(AndroidTproxyTopologyError::ClassifierSnapshotMismatch {
            inventory: inventory.snapshot_id(),
            classifier: classification.audit().snapshot_id(),
        });
    }

    let rule = inventory.rules().get(anchor_dump_index).ok_or(
        AndroidTproxyTopologyError::AnchorOutOfBounds {
            dump_index: anchor_dump_index,
            rule_count: inventory.rules().len(),
        },
    )?;
    let role = classification.roles()[anchor_dump_index];
    let kind = match role {
        Some(AndroidRpdbRuleRole::DefaultNetwork) => {
            AndroidTproxyTrafficDomainKind::ResidualLocalOutput
        }
        Some(AndroidRpdbRuleRole::Tethering) => AndroidTproxyTrafficDomainKind::TetherIngress,
        _ => {
            return Err(AndroidTproxyTopologyError::UnsupportedAnchorRole {
                dump_index: anchor_dump_index,
                role,
            });
        }
    };
    if classification.audit().classifications()[anchor_dump_index]
        == RpdbRuleClassification::Unknown
    {
        return Err(AndroidTproxyTopologyError::UntrustedAnchor {
            dump_index: anchor_dump_index,
        });
    }

    let input_interface =
        *rule
            .input_interface()
            .ok_or(AndroidTproxyTopologyError::MissingAnchorInputInterface {
                dump_index: anchor_dump_index,
            })?;
    let link = inventory
        .links()
        .iter()
        .find(|link| link.name() == &input_interface)
        .ok_or(AndroidTproxyTopologyError::MissingAnchorLink {
            dump_index: anchor_dump_index,
            name: input_interface,
        })?;
    if !link.flags().intersects(InterfaceLinkFlags::UP) {
        return Err(AndroidTproxyTopologyError::AnchorLinkIsDown {
            dump_index: anchor_dump_index,
            interface_index: link.interface_index(),
        });
    }
    match kind {
        AndroidTproxyTrafficDomainKind::ResidualLocalOutput
            if !link.flags().intersects(InterfaceLinkFlags::LOOPBACK) =>
        {
            return Err(AndroidTproxyTopologyError::LocalAnchorIsNotLoopback {
                dump_index: anchor_dump_index,
                interface_index: link.interface_index(),
            });
        }
        AndroidTproxyTrafficDomainKind::TetherIngress
            if link.flags().intersects(InterfaceLinkFlags::LOOPBACK) =>
        {
            return Err(AndroidTproxyTopologyError::TetherAnchorUsesLoopback {
                dump_index: anchor_dump_index,
                interface_index: link.interface_index(),
            });
        }
        AndroidTproxyTrafficDomainKind::ResidualLocalOutput
        | AndroidTproxyTrafficDomainKind::TetherIngress => {}
    }

    let selector = AndroidTproxyDomainSelector {
        family: rule.destination().family(),
        input_interface,
        android_fwmark: rule.fwmark(),
    };
    reject_ambiguous_anchor(
        inventory,
        classification,
        anchor_dump_index,
        role.expect("supported anchor retains a role"),
        selector,
        rule.properties().table(),
    )?;

    let interval = match kind {
        AndroidTproxyTrafficDomainKind::ResidualLocalOutput => {
            let contract = classification.profile().priority_contract();
            AndroidTproxyPriorityInterval {
                android_first_through: contract.uid_default_unreachable_maximum(),
                flux_first_before: contract.default_network(),
            }
        }
        AndroidTproxyTrafficDomainKind::TetherIngress => AndroidTproxyPriorityInterval {
            android_first_through: ANDROID_LOCAL_NETWORK_PRIORITY,
            flux_first_before: ANDROID_TETHERING_PRIORITY,
        },
    };

    let mut dispositions = Vec::with_capacity(inventory.rules().len());
    let mut unknown_rule_count = 0_u32;
    for (dump_index, candidate) in inventory.rules().iter().enumerate() {
        let disposition = if candidate.destination().family() != selector.family() {
            AndroidTproxyRuleDisposition::OtherFamily
        } else if classification.audit().classifications()[dump_index]
            == RpdbRuleClassification::Unknown
            || classification.roles()[dump_index].is_none()
        {
            unknown_rule_count = unknown_rule_count.saturating_add(1);
            AndroidTproxyRuleDisposition::Unknown
        } else if candidate
            .input_interface()
            .is_some_and(|input| input != &selector.input_interface())
        {
            AndroidTproxyRuleDisposition::SelectorDisjoint(
                AndroidTproxySelectorDisjointReason::InputInterfaceMismatch,
            )
        } else if fwmark_predicates_disjoint(selector.android_fwmark(), candidate.fwmark()) {
            AndroidTproxyRuleDisposition::SelectorDisjoint(
                AndroidTproxySelectorDisjointReason::FwmarkPredicateConflict,
            )
        } else if candidate.priority() < interval.flux_first_before() {
            AndroidTproxyRuleDisposition::AndroidFirst
        } else {
            AndroidTproxyRuleDisposition::FluxFirstRequiresHandoff
        };
        dispositions.push(disposition);
    }

    Ok(AndroidTproxyTopologyFeasibilityReport {
        snapshot_id: inventory.snapshot_id(),
        epoch: inventory.epoch(),
        classifier_revision: classification.audit().classifier_revision(),
        profile: classification.profile(),
        kind,
        selector,
        input_interface_index: link.interface_index(),
        anchor: AndroidTproxySelectionAnchor {
            dump_index: anchor_dump_index,
            role: role.expect("supported anchor retains a role"),
            priority: rule.priority(),
            lookup_table: rule.properties().table(),
        },
        interval,
        dispositions: dispositions.into_boxed_slice(),
        unknown_rule_count,
    })
}

fn reject_ambiguous_anchor(
    inventory: &NetworkInventory,
    classification: &AndroidRpdbClassificationReport,
    anchor_dump_index: usize,
    anchor_role: AndroidRpdbRuleRole,
    selector: AndroidTproxyDomainSelector,
    anchor_table: RuleTableId,
) -> Result<(), AndroidTproxyTopologyError> {
    for (dump_index, candidate) in inventory.rules().iter().enumerate() {
        if dump_index == anchor_dump_index
            || classification.roles()[dump_index] != Some(anchor_role)
            || classification.audit().classifications()[dump_index]
                == RpdbRuleClassification::Unknown
            || candidate.destination().family() != selector.family()
            || candidate
                .input_interface()
                .is_some_and(|input| input != &selector.input_interface())
            || fwmark_predicates_disjoint(selector.android_fwmark(), candidate.fwmark())
            || candidate.properties().table() == anchor_table
        {
            continue;
        }

        return Err(AndroidTproxyTopologyError::AmbiguousSelectionAnchor {
            dump_index: anchor_dump_index,
            conflicting_dump_index: dump_index,
            table: anchor_table,
            conflicting_table: candidate.properties().table(),
        });
    }
    Ok(())
}

const fn fwmark_predicates_disjoint(left: Option<RuleFwMark>, right: Option<RuleFwMark>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            (left.value() ^ right.value()) & (left.mask() & right.mask()) != 0
        }
        (Some(_), None) | (None, Some(_)) | (None, None) => false,
    }
}
