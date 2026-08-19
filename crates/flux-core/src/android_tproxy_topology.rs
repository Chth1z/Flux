use std::error::Error;
use std::fmt;

use crate::android_netd::AndroidNetdSourceProfile;
use crate::android_rpdb::{AndroidRpdbClassificationReport, AndroidRpdbRuleRole};
use crate::canonical_evidence::CanonicalEvidenceDigest;
use crate::network_inventory::{
    InterfaceIndex, InterfaceLinkFlags, InterfaceName, NetworkEpoch, NetworkInventory,
    NetworkInventorySnapshotId,
};
use crate::network_route::NetworkAddressFamily;
use crate::network_rule::{RuleFwMark, RulePriority, RuleTableId};
use crate::rpdb_placement::{RpdbClassifierRevision, RpdbRuleClassification};

const ANDROID_LOCAL_NETWORK_PRIORITY: RulePriority = RulePriority::from_raw(20_000);
const ANDROID_TETHERING_PRIORITY: RulePriority = RulePriority::from_raw(21_000);
const ANDROID_TPROXY_TOPOLOGY_EVIDENCE_DIGEST_DOMAIN: &[u8] =
    b"Flux Android TPROXY topology evidence\0canonical-schema-v1\0sha256-v1\0";

/// Maximum traffic domains accepted by one atomic topology-scope request.
pub const MAX_ANDROID_TPROXY_REQUESTED_DOMAINS: usize = 64;
/// Maximum exact anchors retained by one topology-scope report.
pub const MAX_ANDROID_TPROXY_SCOPE_ANCHORS: usize = 64;

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

/// One logical traffic-scope domain requested from the Android topology assessor.
///
/// Exact selector identity remains in each matched per-anchor report. Residual local OUTPUT is
/// requested by family, while tether ingress additionally names the exact input interface.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidTproxyTrafficDomainRequest {
    ResidualLocalOutput {
        family: NetworkAddressFamily,
    },
    TetherIngress {
        family: NetworkAddressFamily,
        input_interface: InterfaceName,
    },
}

impl AndroidTproxyTrafficDomainRequest {
    #[must_use]
    pub const fn residual_local_output(family: NetworkAddressFamily) -> Self {
        Self::ResidualLocalOutput { family }
    }

    #[must_use]
    pub const fn tether_ingress(
        family: NetworkAddressFamily,
        input_interface: InterfaceName,
    ) -> Self {
        Self::TetherIngress {
            family,
            input_interface,
        }
    }

    #[must_use]
    pub const fn family(self) -> NetworkAddressFamily {
        match self {
            Self::ResidualLocalOutput { family } | Self::TetherIngress { family, .. } => family,
        }
    }

    #[must_use]
    pub const fn kind(self) -> AndroidTproxyTrafficDomainKind {
        match self {
            Self::ResidualLocalOutput { .. } => AndroidTproxyTrafficDomainKind::ResidualLocalOutput,
            Self::TetherIngress { .. } => AndroidTproxyTrafficDomainKind::TetherIngress,
        }
    }

    #[must_use]
    pub const fn input_interface(self) -> Option<InterfaceName> {
        match self {
            Self::ResidualLocalOutput { .. } => None,
            Self::TetherIngress {
                input_interface, ..
            } => Some(input_interface),
        }
    }

    const fn expected_role(self) -> AndroidRpdbRuleRole {
        match self {
            Self::ResidualLocalOutput { .. } => AndroidRpdbRuleRole::DefaultNetwork,
            Self::TetherIngress { .. } => AndroidRpdbRuleRole::Tethering,
        }
    }
}

impl fmt::Display for AndroidTproxyTrafficDomainRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResidualLocalOutput { family } => {
                write!(formatter, "{family:?} residual local OUTPUT")
            }
            Self::TetherIngress {
                family,
                input_interface,
            } => write!(
                formatter,
                "{family:?} tether ingress on {input_interface:?}"
            ),
        }
    }
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

/// Atomic routing shape and traffic-domain scope to assess.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidTproxyTopologyScopeRequest {
    shape: AndroidTproxyRoutingShape,
    domains: Box<[AndroidTproxyTrafficDomainRequest]>,
}

impl AndroidTproxyTopologyScopeRequest {
    pub fn new(
        shape: AndroidTproxyRoutingShape,
        requested_domains: impl IntoIterator<Item = AndroidTproxyTrafficDomainRequest>,
    ) -> Result<Self, AndroidTproxyTopologyScopeRequestError> {
        let mut domains = Vec::new();
        for domain in requested_domains {
            if domains.len() == MAX_ANDROID_TPROXY_REQUESTED_DOMAINS {
                return Err(
                    AndroidTproxyTopologyScopeRequestError::TooManyRequestedDomains {
                        maximum: MAX_ANDROID_TPROXY_REQUESTED_DOMAINS,
                        required_at_least: MAX_ANDROID_TPROXY_REQUESTED_DOMAINS + 1,
                    },
                );
            }
            domains.push(domain);
        }
        if domains.is_empty() {
            return Err(AndroidTproxyTopologyScopeRequestError::NoRequestedDomains);
        }
        domains.sort_unstable();
        if let Some(duplicate) = domains
            .windows(2)
            .find(|window| window[0] == window[1])
            .map(|window| window[0])
        {
            return Err(
                AndroidTproxyTopologyScopeRequestError::DuplicateRequestedDomain { duplicate },
            );
        }

        Ok(Self {
            shape,
            domains: domains.into_boxed_slice(),
        })
    }

    #[must_use]
    pub const fn shape(&self) -> AndroidTproxyRoutingShape {
        self.shape
    }

    #[must_use]
    pub fn domains(&self) -> &[AndroidTproxyTrafficDomainRequest] {
        &self.domains
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidTproxyTopologyScopeRequestError {
    NoRequestedDomains,
    TooManyRequestedDomains {
        maximum: usize,
        required_at_least: usize,
    },
    DuplicateRequestedDomain {
        duplicate: AndroidTproxyTrafficDomainRequest,
    },
}

impl fmt::Display for AndroidTproxyTopologyScopeRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRequestedDomains => {
                formatter.write_str("Android TPROXY topology scope requests no traffic domains")
            }
            Self::TooManyRequestedDomains {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "Android TPROXY topology scope requests at least {required_at_least} domains but its limit is {maximum}"
            ),
            Self::DuplicateRequestedDomain { duplicate } => write!(
                formatter,
                "Android TPROXY topology scope requests {duplicate} more than once"
            ),
        }
    }
}

impl Error for AndroidTproxyTopologyScopeRequestError {}

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
    /// One exact rule occurrence retained by the active native Flux owner.
    RetainedFluxOwner,
    /// Android policy remains before any candidate in the reported open interval.
    AndroidFirst,
    /// Flux would run before this overlapping Android selection and therefore needs a handoff.
    FluxFirstRequiresHandoff,
    /// One complete exact peer-rule cohort authenticated by reviewed canary-facility policy.
    ///
    /// This is not a generic role or selector-disjointness claim. The RPDB classifier records this
    /// disposition only after re-deriving the policy-and-selection-bound cohort from live rules.
    ReviewedCanaryFacility,
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

/// Atomic structural summary across every exact anchor in one requested scope.
///
/// Definite incompatibility or slot exhaustion takes precedence over incomplete evidence. The
/// residual-window variant still grants no priority, mark, route, ownership, or mutation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidTproxyTopologyScopeStructuralFeasibility {
    DefiniteStructuralRejection { rejected_anchor_count: u32 },
    IncompleteEvidence { incomplete_anchor_count: u32 },
    AllMatchedAnchorsHaveResidualCandidateWindows { anchor_count: u32 },
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
    profile: AndroidNetdSourceProfile,
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
    pub const fn profile(&self) -> AndroidNetdSourceProfile {
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

        let required = shape.required_priority_slots();
        let available = self.interval.open_priority_count();
        if available < required as u32 {
            return AndroidTproxyStructuralFeasibility::InsufficientPrioritySlots {
                shape,
                required,
                available,
            };
        }
        if self.unknown_rule_count != 0 {
            return AndroidTproxyStructuralFeasibility::IncompleteEvidence {
                unknown_rule_count: self.unknown_rule_count,
            };
        }

        AndroidTproxyStructuralFeasibility::ResidualCandidateWindow {
            shape,
            required,
            available,
        }
    }

    #[must_use]
    pub const fn deferred_prerequisites(
        &self,
        shape: AndroidTproxyRoutingShape,
    ) -> &'static [DeferredAndroidTproxyPrerequisite] {
        deferred_prerequisites_for_shape(shape)
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
    reported_profile: AndroidNetdSourceProfile,
    current_profile: AndroidNetdSourceProfile,
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
    pub const fn reported_profile(self) -> AndroidNetdSourceProfile {
        self.reported_profile
    }

    #[must_use]
    pub const fn current_profile(self) -> AndroidNetdSourceProfile {
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

/// One requested traffic domain aligned with one exact observed Android selection anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidTproxyTopologyScopeEntry {
    domain: AndroidTproxyTrafficDomainRequest,
    report: AndroidTproxyTopologyFeasibilityReport,
    structural_feasibility: AndroidTproxyStructuralFeasibility,
}

impl AndroidTproxyTopologyScopeEntry {
    #[must_use]
    pub const fn domain(&self) -> AndroidTproxyTrafficDomainRequest {
        self.domain
    }

    #[must_use]
    pub const fn report(&self) -> &AndroidTproxyTopologyFeasibilityReport {
        &self.report
    }

    #[must_use]
    pub const fn structural_feasibility(&self) -> AndroidTproxyStructuralFeasibility {
        self.structural_feasibility
    }
}

/// Snapshot-bound, atomically assessed Android TPROXY topology scope.
///
/// The scope is constructed directly from the current inventory and classifier rather than from
/// caller-asserted per-anchor reports. Every recognized anchor matching every requested domain is
/// retained under one routing shape. Negative structural evidence remains inspectable; even an
/// all-residual result is diagnostic-only and exposes no selected priority, table choice, mark,
/// route intent, lease, ownership, encoding, or mutation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidTproxyTopologyScopeReport {
    snapshot_id: NetworkInventorySnapshotId,
    epoch: NetworkEpoch,
    classifier_revision: RpdbClassifierRevision,
    profile: AndroidNetdSourceProfile,
    request: AndroidTproxyTopologyScopeRequest,
    entries: Box<[AndroidTproxyTopologyScopeEntry]>,
    structural_feasibility: AndroidTproxyTopologyScopeStructuralFeasibility,
}

impl AndroidTproxyTopologyScopeReport {
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
    pub const fn profile(&self) -> AndroidNetdSourceProfile {
        self.profile
    }

    #[must_use]
    pub const fn request(&self) -> &AndroidTproxyTopologyScopeRequest {
        &self.request
    }

    #[must_use]
    pub fn entries(&self) -> &[AndroidTproxyTopologyScopeEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn structural_feasibility(&self) -> AndroidTproxyTopologyScopeStructuralFeasibility {
        self.structural_feasibility
    }

    pub(crate) fn evidence_digest(&self) -> [u8; 32] {
        let mut digest =
            CanonicalEvidenceDigest::new(ANDROID_TPROXY_TOPOLOGY_EVIDENCE_DIGEST_DOMAIN);
        digest.u64(self.snapshot_id.get());
        digest.u64(self.epoch.get());
        digest.u64(self.classifier_revision.get());
        digest.bytes(self.profile.source_revision().as_bytes());
        digest_topology_scope_request(&mut digest, &self.request);
        digest.usize(self.entries.len());
        for entry in &self.entries {
            digest_traffic_domain_request(&mut digest, entry.domain);
            digest_topology_report(&mut digest, &entry.report);
            digest_structural_feasibility(&mut digest, entry.structural_feasibility);
        }
        digest_scope_structural_feasibility(&mut digest, self.structural_feasibility);
        digest.finish()
    }

    #[must_use]
    pub const fn deferred_prerequisites(&self) -> &'static [DeferredAndroidTproxyPrerequisite] {
        deferred_prerequisites_for_shape(self.request.shape)
    }

    pub fn ensure_current(
        &self,
        inventory: &NetworkInventory,
        classification: &AndroidRpdbClassificationReport,
    ) -> Result<(), StaleAndroidTproxyTopologyScopeReport> {
        if assess_android_tproxy_topology_scope(inventory, classification, &self.request)
            .is_ok_and(|current| &current == self)
        {
            Ok(())
        } else {
            Err(StaleAndroidTproxyTopologyScopeReport {
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

fn digest_topology_scope_request(
    digest: &mut CanonicalEvidenceDigest,
    request: &AndroidTproxyTopologyScopeRequest,
) {
    digest.tag(routing_shape_tag(request.shape));
    digest.usize(request.domains.len());
    for domain in &request.domains {
        digest_traffic_domain_request(digest, *domain);
    }
}

fn digest_traffic_domain_request(
    digest: &mut CanonicalEvidenceDigest,
    request: AndroidTproxyTrafficDomainRequest,
) {
    match request {
        AndroidTproxyTrafficDomainRequest::ResidualLocalOutput { family } => {
            digest.tag(0);
            digest.tag(family_tag(family));
        }
        AndroidTproxyTrafficDomainRequest::TetherIngress {
            family,
            input_interface,
        } => {
            digest.tag(1);
            digest.tag(family_tag(family));
            digest.bytes(input_interface.as_bytes());
        }
    }
}

fn digest_topology_report(
    digest: &mut CanonicalEvidenceDigest,
    report: &AndroidTproxyTopologyFeasibilityReport,
) {
    digest.u64(report.snapshot_id.get());
    digest.u64(report.epoch.get());
    digest.u64(report.classifier_revision.get());
    digest.bytes(report.profile.source_revision().as_bytes());
    digest.tag(traffic_domain_kind_tag(report.kind));

    digest.tag(family_tag(report.selector.family));
    digest.bytes(report.selector.input_interface.as_bytes());
    match report.selector.android_fwmark {
        Some(mark) => {
            digest.tag(1);
            digest.u32(mark.value());
            digest.u32(mark.mask());
        }
        None => digest.tag(0),
    }
    digest.u32(report.input_interface_index.get());

    digest.usize(report.anchor.dump_index);
    digest.tag(android_rpdb_role_tag(report.anchor.role));
    digest.u32(report.anchor.priority.get());
    digest.u32(report.anchor.lookup_table.get());
    digest.u32(report.interval.android_first_through.get());
    digest.u32(report.interval.flux_first_before.get());
    digest.usize(report.dispositions.len());
    for disposition in &report.dispositions {
        match disposition {
            AndroidTproxyRuleDisposition::OtherFamily => digest.tag(0),
            AndroidTproxyRuleDisposition::AndroidFirst => digest.tag(1),
            AndroidTproxyRuleDisposition::FluxFirstRequiresHandoff => digest.tag(2),
            AndroidTproxyRuleDisposition::SelectorDisjoint(reason) => {
                digest.tag(3);
                digest.tag(match reason {
                    AndroidTproxySelectorDisjointReason::InputInterfaceMismatch => 0,
                    AndroidTproxySelectorDisjointReason::FwmarkPredicateConflict => 1,
                });
            }
            AndroidTproxyRuleDisposition::Unknown => digest.tag(4),
            AndroidTproxyRuleDisposition::ReviewedCanaryFacility => digest.tag(5),
            AndroidTproxyRuleDisposition::RetainedFluxOwner => digest.tag(6),
        }
    }
    digest.u32(report.unknown_rule_count);
}

fn digest_structural_feasibility(
    digest: &mut CanonicalEvidenceDigest,
    feasibility: AndroidTproxyStructuralFeasibility,
) {
    match feasibility {
        AndroidTproxyStructuralFeasibility::IncompatibleTrafficDomain { shape, domain } => {
            digest.tag(0);
            digest.tag(routing_shape_tag(shape));
            digest.tag(traffic_domain_kind_tag(domain));
        }
        AndroidTproxyStructuralFeasibility::IncompleteEvidence { unknown_rule_count } => {
            digest.tag(1);
            digest.u32(unknown_rule_count);
        }
        AndroidTproxyStructuralFeasibility::InsufficientPrioritySlots {
            shape,
            required,
            available,
        } => {
            digest.tag(2);
            digest.tag(routing_shape_tag(shape));
            digest.tag(required);
            digest.u32(available);
        }
        AndroidTproxyStructuralFeasibility::ResidualCandidateWindow {
            shape,
            required,
            available,
        } => {
            digest.tag(3);
            digest.tag(routing_shape_tag(shape));
            digest.tag(required);
            digest.u32(available);
        }
    }
}

fn digest_scope_structural_feasibility(
    digest: &mut CanonicalEvidenceDigest,
    feasibility: AndroidTproxyTopologyScopeStructuralFeasibility,
) {
    match feasibility {
        AndroidTproxyTopologyScopeStructuralFeasibility::DefiniteStructuralRejection {
            rejected_anchor_count,
        } => {
            digest.tag(0);
            digest.u32(rejected_anchor_count);
        }
        AndroidTproxyTopologyScopeStructuralFeasibility::IncompleteEvidence {
            incomplete_anchor_count,
        } => {
            digest.tag(1);
            digest.u32(incomplete_anchor_count);
        }
        AndroidTproxyTopologyScopeStructuralFeasibility::AllMatchedAnchorsHaveResidualCandidateWindows {
            anchor_count,
        } => {
            digest.tag(2);
            digest.u32(anchor_count);
        }
    }
}

const fn family_tag(family: NetworkAddressFamily) -> u8 {
    match family {
        NetworkAddressFamily::Ipv4 => 4,
        NetworkAddressFamily::Ipv6 => 6,
    }
}

const fn traffic_domain_kind_tag(kind: AndroidTproxyTrafficDomainKind) -> u8 {
    match kind {
        AndroidTproxyTrafficDomainKind::ResidualLocalOutput => 0,
        AndroidTproxyTrafficDomainKind::TetherIngress => 1,
    }
}

const fn routing_shape_tag(shape: AndroidTproxyRoutingShape) -> u8 {
    match shape {
        AndroidTproxyRoutingShape::DedicatedAddressBypassRule => 0,
        AndroidTproxyRoutingShape::PreMarkAddressHostSet => 1,
    }
}

const fn android_rpdb_role_tag(role: AndroidRpdbRuleRole) -> u8 {
    match role {
        AndroidRpdbRuleRole::KernelLocal => 0,
        AndroidRpdbRuleRole::VpnOverrideSystem => 1,
        AndroidRpdbRuleRole::VpnOverrideOutputInterface => 2,
        AndroidRpdbRuleRole::VpnOutputToLocal => 3,
        AndroidRpdbRuleRole::SecureVpn => 4,
        AndroidRpdbRuleRole::ProhibitNonVpn => 5,
        AndroidRpdbRuleRole::UidExplicitNetwork => 6,
        AndroidRpdbRuleRole::UidExplicitUnreachable => 7,
        AndroidRpdbRuleRole::LocalNetworkExplicit => 8,
        AndroidRpdbRuleRole::ExplicitNetwork => 9,
        AndroidRpdbRuleRole::OutputInterface => 10,
        AndroidRpdbRuleRole::LegacySystem => 11,
        AndroidRpdbRuleRole::LegacyNetwork => 12,
        AndroidRpdbRuleRole::LocalNetwork => 13,
        AndroidRpdbRuleRole::PhysicalLocalNetwork => 14,
        AndroidRpdbRuleRole::Tethering => 15,
        AndroidRpdbRuleRole::UidImplicitNetwork => 16,
        AndroidRpdbRuleRole::UidImplicitUnreachable => 17,
        AndroidRpdbRuleRole::ImplicitNetwork => 18,
        AndroidRpdbRuleRole::BypassableVpnNoLocalExclusion => 19,
        AndroidRpdbRuleRole::UidLocalRoutes => 20,
        AndroidRpdbRuleRole::LocalRoutes => 21,
        AndroidRpdbRuleRole::BypassableVpnLocalExclusion => 22,
        AndroidRpdbRuleRole::VpnFallthrough => 23,
        AndroidRpdbRuleRole::UidDefaultNetwork => 24,
        AndroidRpdbRuleRole::UidDefaultUnreachable => 25,
        AndroidRpdbRuleRole::DefaultNetwork => 26,
        AndroidRpdbRuleRole::FinalUnreachable => 27,
        AndroidRpdbRuleRole::ReviewedEarlyUidLookup => 28,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleAndroidTproxyTopologyScopeReport {
    reported_snapshot_id: NetworkInventorySnapshotId,
    current_inventory_snapshot_id: NetworkInventorySnapshotId,
    current_classification_snapshot_id: NetworkInventorySnapshotId,
    reported_epoch: NetworkEpoch,
    current_inventory_epoch: NetworkEpoch,
    current_classification_epoch: NetworkEpoch,
    reported_profile: AndroidNetdSourceProfile,
    current_profile: AndroidNetdSourceProfile,
    reported_classifier_revision: RpdbClassifierRevision,
    current_classifier_revision: RpdbClassifierRevision,
}

impl StaleAndroidTproxyTopologyScopeReport {
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
    pub const fn reported_profile(self) -> AndroidNetdSourceProfile {
        self.reported_profile
    }

    #[must_use]
    pub const fn current_profile(self) -> AndroidNetdSourceProfile {
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

impl fmt::Display for StaleAndroidTproxyTopologyScopeReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Android TPROXY topology scope for snapshot {} at epoch {} with profile {:?} and classifier revision {} is stale relative to inventory snapshot {} at epoch {} and classification snapshot {} at epoch {} with profile {:?} and revision {}",
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

impl Error for StaleAndroidTproxyTopologyScopeReport {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidTproxyTopologyScopeError {
    MissingRequestedDomain {
        domain: AndroidTproxyTrafficDomainRequest,
    },
    TooManyMatchedAnchors {
        maximum: usize,
        required_at_least: usize,
    },
    Topology(AndroidTproxyTopologyError),
}

impl fmt::Display for AndroidTproxyTopologyScopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequestedDomain { domain } => write!(
                formatter,
                "Android TPROXY topology scope found no recognized anchor for {domain}"
            ),
            Self::TooManyMatchedAnchors {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "Android TPROXY topology scope matches at least {required_at_least} anchors but its limit is {maximum}"
            ),
            Self::Topology(error) => error.fmt(formatter),
        }
    }
}

impl Error for AndroidTproxyTopologyScopeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Topology(error) => Some(error),
            Self::MissingRequestedDomain { .. } | Self::TooManyMatchedAnchors { .. } => None,
        }
    }
}

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
    assess_android_tproxy_topology_inner(inventory, classification, anchor_dump_index)
}

fn assess_android_tproxy_topology_inner(
    inventory: &NetworkInventory,
    classification: &AndroidRpdbClassificationReport,
    anchor_dump_index: usize,
) -> Result<AndroidTproxyTopologyFeasibilityReport, AndroidTproxyTopologyError> {
    let retained_owner = classification.retained_owner();
    ensure_classifier_matches_inventory(inventory, classification)?;

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
        } else if retained_owner.is_some_and(|owner| owner.contains_rule_index(dump_index)) {
            AndroidTproxyRuleDisposition::RetainedFluxOwner
        } else if classification.audit().classifications()[dump_index]
            == RpdbRuleClassification::Unknown
        {
            unknown_rule_count = unknown_rule_count.saturating_add(1);
            AndroidTproxyRuleDisposition::Unknown
        } else if classification
            .reviewed_canary_rule_indices()
            .contains(&dump_index)
        {
            debug_assert_eq!(
                classification.audit().classifications()[dump_index],
                RpdbRuleClassification::DoesNotConstrainFlux
            );
            debug_assert!(classification.roles()[dump_index].is_none());
            AndroidTproxyRuleDisposition::ReviewedCanaryFacility
        } else if classification.roles()[dump_index].is_none() {
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

/// Atomically assesses every recognized Android selection anchor matching the requested scope.
///
/// Requests are already bounded, sorted, and duplicate-free. Each domain must have at least one
/// recognized anchor; every match is assessed rather than letting the caller cherry-pick one rule.
/// Structural negatives remain report data. This function is pure and grants no activation or
/// mutation authority.
pub fn assess_android_tproxy_topology_scope(
    inventory: &NetworkInventory,
    classification: &AndroidRpdbClassificationReport,
    request: &AndroidTproxyTopologyScopeRequest,
) -> Result<AndroidTproxyTopologyScopeReport, AndroidTproxyTopologyScopeError> {
    assess_android_tproxy_topology_scope_inner(inventory, classification, request)
}

fn assess_android_tproxy_topology_scope_inner(
    inventory: &NetworkInventory,
    classification: &AndroidRpdbClassificationReport,
    request: &AndroidTproxyTopologyScopeRequest,
) -> Result<AndroidTproxyTopologyScopeReport, AndroidTproxyTopologyScopeError> {
    ensure_classifier_matches_inventory(inventory, classification)
        .map_err(AndroidTproxyTopologyScopeError::Topology)?;

    let mut entries = Vec::new();
    let mut rejected_anchor_count = 0_u32;
    let mut incomplete_anchor_count = 0_u32;
    for domain in request.domains() {
        let mut matched = false;
        for (dump_index, rule) in inventory.rules().iter().enumerate() {
            if !requested_domain_matches(*domain, rule, classification.roles()[dump_index]) {
                continue;
            }
            matched = true;
            if entries.len() == MAX_ANDROID_TPROXY_SCOPE_ANCHORS {
                return Err(AndroidTproxyTopologyScopeError::TooManyMatchedAnchors {
                    maximum: MAX_ANDROID_TPROXY_SCOPE_ANCHORS,
                    required_at_least: MAX_ANDROID_TPROXY_SCOPE_ANCHORS + 1,
                });
            }
            let report =
                assess_android_tproxy_topology_inner(inventory, classification, dump_index)
                    .map_err(AndroidTproxyTopologyScopeError::Topology)?;
            let structural_feasibility = report.structural_feasibility(request.shape());
            match structural_feasibility {
                AndroidTproxyStructuralFeasibility::IncompatibleTrafficDomain { .. }
                | AndroidTproxyStructuralFeasibility::InsufficientPrioritySlots { .. } => {
                    rejected_anchor_count = rejected_anchor_count.saturating_add(1);
                }
                AndroidTproxyStructuralFeasibility::IncompleteEvidence { .. } => {
                    incomplete_anchor_count = incomplete_anchor_count.saturating_add(1);
                }
                AndroidTproxyStructuralFeasibility::ResidualCandidateWindow { .. } => {}
            }
            entries.push(AndroidTproxyTopologyScopeEntry {
                domain: *domain,
                report,
                structural_feasibility,
            });
        }
        if !matched {
            return Err(AndroidTproxyTopologyScopeError::MissingRequestedDomain {
                domain: *domain,
            });
        }
    }

    let anchor_count =
        u32::try_from(entries.len()).expect("the Android TPROXY scope anchor bound fits in u32");
    let structural_feasibility = if rejected_anchor_count != 0 {
        AndroidTproxyTopologyScopeStructuralFeasibility::DefiniteStructuralRejection {
            rejected_anchor_count,
        }
    } else if incomplete_anchor_count != 0 {
        AndroidTproxyTopologyScopeStructuralFeasibility::IncompleteEvidence {
            incomplete_anchor_count,
        }
    } else {
        AndroidTproxyTopologyScopeStructuralFeasibility::AllMatchedAnchorsHaveResidualCandidateWindows {
            anchor_count,
        }
    };

    Ok(AndroidTproxyTopologyScopeReport {
        snapshot_id: inventory.snapshot_id(),
        epoch: inventory.epoch(),
        classifier_revision: classification.audit().classifier_revision(),
        profile: classification.profile(),
        request: request.clone(),
        entries: entries.into_boxed_slice(),
        structural_feasibility,
    })
}

const fn deferred_prerequisites_for_shape(
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

fn ensure_classifier_matches_inventory(
    inventory: &NetworkInventory,
    classification: &AndroidRpdbClassificationReport,
) -> Result<(), AndroidTproxyTopologyError> {
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
    Ok(())
}

fn requested_domain_matches(
    domain: AndroidTproxyTrafficDomainRequest,
    rule: &crate::network_rule::NetworkRuleRecord,
    role: Option<AndroidRpdbRuleRole>,
) -> bool {
    role == Some(domain.expected_role())
        && rule.destination().family() == domain.family()
        && domain
            .input_interface()
            .is_none_or(|input_interface| rule.input_interface() == Some(&input_interface))
}

fn reject_ambiguous_anchor(
    inventory: &NetworkInventory,
    classification: &AndroidRpdbClassificationReport,
    anchor_dump_index: usize,
    anchor_role: AndroidRpdbRuleRole,
    selector: AndroidTproxyDomainSelector,
    anchor_table: RuleTableId,
) -> Result<(), AndroidTproxyTopologyError> {
    let retained_owner = classification.retained_owner();
    for (dump_index, candidate) in inventory.rules().iter().enumerate() {
        if dump_index == anchor_dump_index
            || retained_owner.is_some_and(|owner| owner.contains_rule_index(dump_index))
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
