use std::error::Error;
use std::fmt;
use std::num::NonZeroU32;

use crate::android_rpdb::{AndroidRpdbClassificationReport, AndroidRpdbRetainedOwner};
use crate::canonical_evidence::CanonicalEvidenceDigest;
use crate::network_inventory::{NetworkEpoch, NetworkInventory, NetworkInventorySnapshotId};
use crate::network_route::NetworkAddressFamily;
use crate::network_rule::{RuleFwMark, RulePriority};

/// Android's defined low 16-bit network-ID field.
pub const ANDROID_NET_ID_FWMARK_MASK: u32 = 0x0000_ffff;
/// Maximum detailed conflicts retained in one partial fwmark audit.
pub const MAX_FWMARK_PARTIAL_CONFLICTS: usize = 64;

const FWMARK_PARTIAL_AUDIT_EVIDENCE_DIGEST_DOMAIN: &[u8] =
    b"Flux partial fwmark audit evidence\0canonical-schema-v1\0sha256-v1\0";

const FWMARK_SOURCE_STATUSES: [FwmarkSourceStatus; 9] = [
    FwmarkSourceStatus::new(
        FwmarkEvidenceSource::AndroidNetId,
        FwmarkEvidenceState::Available,
    ),
    FwmarkSourceStatus::new(FwmarkEvidenceSource::Rpdb, FwmarkEvidenceState::Available),
    FwmarkSourceStatus::new(
        FwmarkEvidenceSource::DeviceMarkPolicy,
        FwmarkEvidenceState::Unavailable,
    ),
    FwmarkSourceStatus::new(
        FwmarkEvidenceSource::Xtables,
        FwmarkEvidenceState::Unavailable,
    ),
    FwmarkSourceStatus::new(
        FwmarkEvidenceSource::Nftables,
        FwmarkEvidenceState::Unavailable,
    ),
    FwmarkSourceStatus::new(
        FwmarkEvidenceSource::TrafficControlAndBpf,
        FwmarkEvidenceState::Unavailable,
    ),
    FwmarkSourceStatus::new(FwmarkEvidenceSource::Xfrm, FwmarkEvidenceState::Unavailable),
    FwmarkSourceStatus::new(
        FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
        FwmarkEvidenceState::Unavailable,
    ),
    FwmarkSourceStatus::new(
        FwmarkEvidenceSource::ExistingFluxOwnership,
        FwmarkEvidenceState::Unavailable,
    ),
];
const RPDB_SOURCE_STATUS_INDEX: usize = 1;

const DEFERRED_FWMARK_PREREQUISITES: [DeferredFwmarkPrerequisite; 11] = [
    DeferredFwmarkPrerequisite::PositiveAllocationAuthority,
    DeferredFwmarkPrerequisite::DeviceMarkPolicy,
    DeferredFwmarkPrerequisite::ExternalRulesetCensus,
    DeferredFwmarkPrerequisite::TrafficControlAndBpfCensus,
    DeferredFwmarkPrerequisite::ConnmarkAndSocketSemantics,
    DeferredFwmarkPrerequisite::BootIdentityBinding,
    DeferredFwmarkPrerequisite::NetworkNamespaceBinding,
    DeferredFwmarkPrerequisite::DurableOwnershipJournal,
    DeferredFwmarkPrerequisite::ExactWriterSemantics,
    DeferredFwmarkPrerequisite::ObserverContinuity,
    DeferredFwmarkPrerequisite::ActivationCanary,
];

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FwmarkRole {
    Proxy,
    Bypass,
}

/// Structurally valid common mark field proposed for Flux packet, socket, and conntrack use.
///
/// Zero remains the unclassified state. The two nonzero role values share one mask, and every
/// future writer must use masked merge semantics rather than overwrite the complete mark.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FwmarkCandidate {
    mask: NonZeroU32,
    proxy: RuleFwMark,
    bypass: RuleFwMark,
}

impl FwmarkCandidate {
    pub fn new(
        mask: u32,
        proxy_value: u32,
        bypass_value: u32,
    ) -> Result<Self, FwmarkCandidateError> {
        let mask = NonZeroU32::new(mask).ok_or(FwmarkCandidateError::EmptyMask)?;
        for (role, value) in [
            (FwmarkRole::Proxy, proxy_value),
            (FwmarkRole::Bypass, bypass_value),
        ] {
            if value & !mask.get() != 0 {
                return Err(FwmarkCandidateError::ValueOutsideMask {
                    role,
                    value,
                    mask: mask.get(),
                });
            }
            if value == 0 {
                return Err(FwmarkCandidateError::ZeroRoleValue { role });
            }
        }
        if proxy_value == bypass_value {
            return Err(FwmarkCandidateError::DuplicateRoleValue { value: proxy_value });
        }

        let proxy = RuleFwMark::new(proxy_value, mask.get())
            .expect("nonzero mark mask always yields a material selector");
        let bypass = RuleFwMark::new(bypass_value, mask.get())
            .expect("nonzero mark mask always yields a material selector");
        Ok(Self {
            mask,
            proxy,
            bypass,
        })
    }

    #[must_use]
    pub const fn mask(self) -> u32 {
        self.mask.get()
    }

    #[must_use]
    pub const fn proxy_value(self) -> u32 {
        self.proxy.value()
    }

    #[must_use]
    pub const fn bypass_value(self) -> u32 {
        self.bypass.value()
    }

    #[must_use]
    pub const fn selector(self, role: FwmarkRole) -> RuleFwMark {
        match role {
            FwmarkRole::Proxy => self.proxy,
            FwmarkRole::Bypass => self.bypass,
        }
    }

    /// Computes a masked merge without modifying any bit outside this candidate's field.
    ///
    /// This arithmetic helper does not authorize a socket, packet, or conntrack mark write.
    #[must_use]
    pub const fn merge(self, existing: u32, role: FwmarkRole) -> u32 {
        (existing & !self.mask()) | self.selector(role).value()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FwmarkCandidateError {
    EmptyMask,
    ValueOutsideMask {
        role: FwmarkRole,
        value: u32,
        mask: u32,
    },
    ZeroRoleValue {
        role: FwmarkRole,
    },
    DuplicateRoleValue {
        value: u32,
    },
}

impl fmt::Display for FwmarkCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMask => formatter.write_str("Flux fwmark candidate has an empty mask"),
            Self::ValueOutsideMask { role, value, mask } => write!(
                formatter,
                "Flux fwmark {role:?} value {value:#010x} contains bits outside mask {mask:#010x}"
            ),
            Self::ZeroRoleValue { role } => {
                write!(formatter, "Flux fwmark {role:?} value is zero")
            }
            Self::DuplicateRoleValue { value } => write!(
                formatter,
                "Flux fwmark proxy and bypass roles both use {value:#010x}"
            ),
        }
    }
}

impl Error for FwmarkCandidateError {}

/// Evidence domains required before a mark field can become an activation-capable lease.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FwmarkEvidenceSource {
    AndroidNetId,
    Rpdb,
    DeviceMarkPolicy,
    Xtables,
    Nftables,
    TrafficControlAndBpf,
    Xfrm,
    ConnmarkAndSocketTransfers,
    ExistingFluxOwnership,
}

/// Availability of conflict evidence in this deliberately partial checkpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FwmarkEvidenceState {
    Available,
    /// The source was observed, but some semantics are not modeled strongly enough for proof.
    Opaque,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FwmarkSourceStatus {
    source: FwmarkEvidenceSource,
    state: FwmarkEvidenceState,
}

impl FwmarkSourceStatus {
    const fn new(source: FwmarkEvidenceSource, state: FwmarkEvidenceState) -> Self {
        Self { source, state }
    }

    #[must_use]
    pub const fn source(self) -> FwmarkEvidenceSource {
        self.source
    }

    #[must_use]
    pub const fn state(self) -> FwmarkEvidenceState {
        self.state
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DeferredFwmarkPrerequisite {
    PositiveAllocationAuthority,
    DeviceMarkPolicy,
    ExternalRulesetCensus,
    TrafficControlAndBpfCensus,
    ConnmarkAndSocketSemantics,
    BootIdentityBinding,
    NetworkNamespaceBinding,
    DurableOwnershipJournal,
    ExactWriterSemantics,
    ObserverContinuity,
    ActivationCanary,
}

/// Definite conflict evidence available before the missing external mark observers exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FwmarkPartialConflict {
    AndroidNetIdOverlap {
        overlap: u32,
    },
    RpdbSelectorOverlap {
        dump_index: usize,
        family: NetworkAddressFamily,
        priority: RulePriority,
        selector: RuleFwMark,
        overlap: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FwmarkPartialAuditOutcome {
    /// At least one currently provable collision rejects the candidate.
    Conflicting,
    /// No currently provable collision exists, but required evidence is unavailable.
    Incomplete,
}

/// Snapshot-bound partial mark-field report with deliberately no safe or accepted outcome.
///
/// This checkpoint can prove Android `netId` and RPDB selector collisions only. It cannot infer an
/// allocatable field from negative observation, because generic Android exposes no public mark
/// allocator and Rust does not yet census live xtables, nftables, TC/BPF, socket, or connmark use.
/// Consequently this type cannot be converted into a mark lease or activation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FwmarkPartialAudit {
    snapshot_id: NetworkInventorySnapshotId,
    epoch: NetworkEpoch,
    candidate: FwmarkCandidate,
    outcome: FwmarkPartialAuditOutcome,
    sources: [FwmarkSourceStatus; FWMARK_SOURCE_STATUSES.len()],
    excluded_reviewed_canary_rule_indices: Box<[usize]>,
    conflicts: Box<[FwmarkPartialConflict]>,
    omitted_conflicts: u32,
}

impl FwmarkPartialAudit {
    #[must_use]
    pub const fn snapshot_id(&self) -> NetworkInventorySnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub const fn epoch(&self) -> NetworkEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn candidate(&self) -> FwmarkCandidate {
        self.candidate
    }

    #[must_use]
    pub const fn outcome(&self) -> FwmarkPartialAuditOutcome {
        self.outcome
    }

    #[must_use]
    /// Returns evidence domains modeled by this partial checkpoint.
    ///
    /// Future activation audits may require additional domains; this is not a completeness
    /// manifest that can authorize allocation.
    pub fn sources(&self) -> &[FwmarkSourceStatus] {
        &self.sources
    }

    #[must_use]
    pub fn conflicts(&self) -> &[FwmarkPartialConflict] {
        &self.conflicts
    }

    #[must_use]
    pub fn excluded_reviewed_canary_rule_indices(&self) -> &[usize] {
        &self.excluded_reviewed_canary_rule_indices
    }

    #[must_use]
    pub const fn omitted_conflicts(&self) -> u32 {
        self.omitted_conflicts
    }

    pub(crate) fn evidence_digest(&self) -> [u8; 32] {
        let mut digest = CanonicalEvidenceDigest::new(FWMARK_PARTIAL_AUDIT_EVIDENCE_DIGEST_DOMAIN);
        digest.u64(self.snapshot_id.get());
        digest.u64(self.epoch.get());
        update_fwmark_candidate_evidence(&mut digest, self.candidate);
        digest.tag(match self.outcome {
            FwmarkPartialAuditOutcome::Conflicting => 0,
            FwmarkPartialAuditOutcome::Incomplete => 1,
        });
        digest.usize(self.sources.len());
        for source in self.sources {
            digest.tag(fwmark_evidence_source_tag(source.source));
            digest.tag(match source.state {
                FwmarkEvidenceState::Available => 0,
                FwmarkEvidenceState::Opaque => 1,
                FwmarkEvidenceState::Unavailable => 2,
            });
        }
        digest.usize(self.excluded_reviewed_canary_rule_indices.len());
        for dump_index in &self.excluded_reviewed_canary_rule_indices {
            digest.usize(*dump_index);
        }
        digest.usize(self.conflicts.len());
        for conflict in &self.conflicts {
            match conflict {
                FwmarkPartialConflict::AndroidNetIdOverlap { overlap } => {
                    digest.tag(0);
                    digest.u32(*overlap);
                }
                FwmarkPartialConflict::RpdbSelectorOverlap {
                    dump_index,
                    family,
                    priority,
                    selector,
                    overlap,
                } => {
                    digest.tag(1);
                    digest.usize(*dump_index);
                    digest.tag(network_family_tag(*family));
                    digest.u32(priority.get());
                    digest.u32(selector.value());
                    digest.u32(selector.mask());
                    digest.u32(*overlap);
                }
            }
        }
        digest.u32(self.omitted_conflicts);
        digest.finish()
    }

    #[must_use]
    /// Returns the currently identified minimum prerequisites for a future mark lease.
    ///
    /// The list is intentionally descriptive rather than activation authority and may grow when
    /// concrete platform collectors expose additional mark-reading or mark-writing domains.
    pub fn deferred_prerequisites(&self) -> &[DeferredFwmarkPrerequisite] {
        &DEFERRED_FWMARK_PREREQUISITES
    }

    pub fn ensure_current(
        &self,
        inventory: &NetworkInventory,
    ) -> Result<(), StaleFwmarkPartialAudit> {
        if inventory.snapshot_id() == self.snapshot_id && inventory.epoch() == self.epoch {
            Ok(())
        } else {
            Err(StaleFwmarkPartialAudit {
                audited_snapshot_id: self.snapshot_id,
                current_snapshot_id: inventory.snapshot_id(),
                audited_epoch: self.epoch,
                current_epoch: inventory.epoch(),
            })
        }
    }
}

pub(crate) fn update_fwmark_candidate_evidence(
    digest: &mut CanonicalEvidenceDigest,
    candidate: FwmarkCandidate,
) {
    digest.u32(candidate.mask());
    digest.u32(candidate.proxy_value());
    digest.u32(candidate.bypass_value());
}

pub(crate) const fn fwmark_evidence_source_tag(source: FwmarkEvidenceSource) -> u8 {
    match source {
        FwmarkEvidenceSource::AndroidNetId => 0,
        FwmarkEvidenceSource::Rpdb => 1,
        FwmarkEvidenceSource::DeviceMarkPolicy => 2,
        FwmarkEvidenceSource::Xtables => 3,
        FwmarkEvidenceSource::Nftables => 4,
        FwmarkEvidenceSource::TrafficControlAndBpf => 5,
        FwmarkEvidenceSource::Xfrm => 6,
        FwmarkEvidenceSource::ConnmarkAndSocketTransfers => 7,
        FwmarkEvidenceSource::ExistingFluxOwnership => 8,
    }
}

pub(crate) const fn network_family_tag(family: NetworkAddressFamily) -> u8 {
    match family {
        NetworkAddressFamily::Ipv4 => 4,
        NetworkAddressFamily::Ipv6 => 6,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleFwmarkPartialAudit {
    audited_snapshot_id: NetworkInventorySnapshotId,
    current_snapshot_id: NetworkInventorySnapshotId,
    audited_epoch: NetworkEpoch,
    current_epoch: NetworkEpoch,
}

impl StaleFwmarkPartialAudit {
    #[must_use]
    pub const fn audited_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.audited_snapshot_id
    }

    #[must_use]
    pub const fn current_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.current_snapshot_id
    }

    #[must_use]
    pub const fn audited_epoch(self) -> NetworkEpoch {
        self.audited_epoch
    }

    #[must_use]
    pub const fn current_epoch(self) -> NetworkEpoch {
        self.current_epoch
    }
}

impl fmt::Display for StaleFwmarkPartialAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "partial fwmark audit snapshot {} at epoch {} is stale relative to snapshot {} at epoch {}",
            self.audited_snapshot_id.get(),
            self.audited_epoch.get(),
            self.current_snapshot_id.get(),
            self.current_epoch.get()
        )
    }
}

impl Error for StaleFwmarkPartialAudit {}

/// Audits the conflicts that can be proven from the current core inventory.
///
/// A conflict-free report remains `Incomplete`; callers must not interpret it as a free mark field.
#[must_use]
pub fn audit_fwmark_candidate_partial(
    inventory: &NetworkInventory,
    candidate: FwmarkCandidate,
) -> FwmarkPartialAudit {
    audit_fwmark_candidate_partial_with_exclusions(inventory, candidate, &[], None)
}

pub(crate) fn audit_fwmark_candidate_partial_with_classification(
    inventory: &NetworkInventory,
    classification: &AndroidRpdbClassificationReport,
    candidate: FwmarkCandidate,
) -> FwmarkPartialAudit {
    debug_assert_eq!(
        classification.audit().snapshot_id(),
        inventory.snapshot_id()
    );
    debug_assert_eq!(classification.audit().epoch(), inventory.epoch());
    audit_fwmark_candidate_partial_with_exclusions(
        inventory,
        candidate,
        classification.reviewed_canary_rule_indices(),
        classification.retained_owner(),
    )
}

fn audit_fwmark_candidate_partial_with_exclusions(
    inventory: &NetworkInventory,
    candidate: FwmarkCandidate,
    excluded_reviewed_canary_rule_indices: &[usize],
    retained_owner: Option<&AndroidRpdbRetainedOwner>,
) -> FwmarkPartialAudit {
    let mut conflicts = Vec::new();
    let mut omitted_conflicts = 0_u32;
    let mut sources = FWMARK_SOURCE_STATUSES;
    if inventory
        .rules()
        .iter()
        .any(|rule| !rule.has_complete_attribute_coverage())
    {
        sources[RPDB_SOURCE_STATUS_INDEX] =
            FwmarkSourceStatus::new(FwmarkEvidenceSource::Rpdb, FwmarkEvidenceState::Opaque);
    }

    let android_overlap = candidate.mask() & ANDROID_NET_ID_FWMARK_MASK;
    if android_overlap != 0 {
        retain_conflict(
            &mut conflicts,
            &mut omitted_conflicts,
            FwmarkPartialConflict::AndroidNetIdOverlap {
                overlap: android_overlap,
            },
        );
    }

    for (dump_index, rule) in inventory.rules().iter().enumerate() {
        if excluded_reviewed_canary_rule_indices
            .binary_search(&dump_index)
            .is_ok()
            || retained_owner.is_some_and(|owner| owner.contains_rule_index(dump_index))
        {
            continue;
        }
        let Some(selector) = rule.fwmark() else {
            continue;
        };
        let overlap = candidate.mask() & selector.mask();
        if overlap == 0 {
            continue;
        }
        retain_conflict(
            &mut conflicts,
            &mut omitted_conflicts,
            FwmarkPartialConflict::RpdbSelectorOverlap {
                dump_index,
                family: rule.destination().family(),
                priority: rule.priority(),
                selector,
                overlap,
            },
        );
    }

    let outcome = if conflicts.is_empty() && omitted_conflicts == 0 {
        FwmarkPartialAuditOutcome::Incomplete
    } else {
        FwmarkPartialAuditOutcome::Conflicting
    };
    FwmarkPartialAudit {
        snapshot_id: inventory.snapshot_id(),
        epoch: inventory.epoch(),
        candidate,
        outcome,
        sources,
        excluded_reviewed_canary_rule_indices: excluded_reviewed_canary_rule_indices
            .to_vec()
            .into_boxed_slice(),
        conflicts: conflicts.into_boxed_slice(),
        omitted_conflicts,
    }
}

fn retain_conflict(
    conflicts: &mut Vec<FwmarkPartialConflict>,
    omitted_conflicts: &mut u32,
    conflict: FwmarkPartialConflict,
) {
    if conflicts.len() < MAX_FWMARK_PARTIAL_CONFLICTS {
        conflicts.push(conflict);
    } else {
        *omitted_conflicts = omitted_conflicts.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android_netd::AndroidNetdSourceProfile;
    use crate::android_rpdb::{
        AndroidRpdbRetainedOwner, classify_android_rpdb_with_retained_owner,
    };
    use crate::network_inventory::NetworkInventoryTracker;
    use crate::network_route::{
        NetworkRouteRecord, RouteFlags, RoutePath, RoutePrefix, RouteProperties, RouteProtocol,
        RouteScope, RouteTableId, RouteType,
    };
    use crate::network_rule::{
        NetworkRuleRecord, RuleAction, RuleFlags, RuleFwMark, RulePrefix, RulePriority,
        RuleProperties, RuleProtocol, RuleTableId,
    };

    const CANDIDATE_MASK: u32 = 0x0300_0000;
    const PROXY_VALUE: u32 = 0x0100_0000;
    const BYPASS_VALUE: u32 = 0x0200_0000;

    #[test]
    fn retained_owner_rule_does_not_self_conflict() {
        let inventory = inventory([marked_rule(100)]);
        let retained_owner = retained_owner(&inventory, [(0, 0)]);
        let classification = classify_android_rpdb_with_retained_owner(
            &inventory,
            AndroidNetdSourceProfile::AospNetd20250324,
            &retained_owner,
        )
        .expect("owner-aware Android RPDB classification");
        let candidate = candidate();
        let generic = audit_fwmark_candidate_partial(&inventory, candidate);
        assert_eq!(generic.outcome(), FwmarkPartialAuditOutcome::Conflicting);
        assert_eq!(generic.conflicts().len(), 1);

        let partial = audit_fwmark_candidate_partial_with_classification(
            &inventory,
            &classification,
            candidate,
        );

        assert_eq!(partial.outcome(), FwmarkPartialAuditOutcome::Incomplete);
        assert!(partial.conflicts().is_empty());
    }

    #[test]
    fn foreign_overlapping_selector_remains_a_partial_conflict() {
        let inventory = inventory([marked_rule(100), marked_rule(200)]);
        let retained_owner = retained_owner(&inventory, [(0, 0)]);
        let classification = classify_android_rpdb_with_retained_owner(
            &inventory,
            AndroidNetdSourceProfile::AospNetd20250324,
            &retained_owner,
        )
        .expect("owner-aware Android RPDB classification");

        let partial = audit_fwmark_candidate_partial_with_classification(
            &inventory,
            &classification,
            candidate(),
        );

        assert_eq!(partial.outcome(), FwmarkPartialAuditOutcome::Conflicting);
        assert_eq!(partial.conflicts().len(), 1);
        assert!(matches!(
            partial.conflicts()[0],
            FwmarkPartialConflict::RpdbSelectorOverlap { dump_index: 1, .. }
        ));
    }

    fn candidate() -> FwmarkCandidate {
        FwmarkCandidate::new(CANDIDATE_MASK, PROXY_VALUE, BYPASS_VALUE)
            .expect("test candidate has two role values")
    }

    fn marked_rule(priority: u32) -> NetworkRuleRecord {
        NetworkRuleRecord::new(
            RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
            RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
            RuleProperties::new(
                0,
                RuleTableId::from_raw(100),
                RuleAction::TO_TABLE,
                RuleProtocol::from_raw(0),
                RuleFlags::default(),
            ),
            RulePriority::from_raw(priority),
            None,
        )
        .expect("test rule")
        .with_fwmark(RuleFwMark::new(PROXY_VALUE, CANDIDATE_MASK).expect("test selector"))
    }

    fn route() -> NetworkRouteRecord {
        NetworkRouteRecord::new(
            RoutePrefix::unspecified(NetworkAddressFamily::Ipv4),
            RoutePrefix::unspecified(NetworkAddressFamily::Ipv4),
            RouteProperties::new(
                0,
                RouteTableId::from_raw(100),
                RouteProtocol::from_raw(2),
                RouteScope::from_raw(0),
                RouteType::from_raw(1),
                RouteFlags::default(),
            ),
            0,
            RoutePath::None,
        )
        .expect("test route")
    }

    fn inventory(rules: impl IntoIterator<Item = NetworkRuleRecord>) -> NetworkInventory {
        NetworkInventoryTracker::new()
            .publish_complete_with_routing([], [], [route()], rules)
            .expect("complete test inventory")
            .clone()
    }

    fn retained_owner(
        inventory: &NetworkInventory,
        indices: impl IntoIterator<Item = (usize, usize)>,
    ) -> AndroidRpdbRetainedOwner {
        // SAFETY: every test pair is built from the exact route/rule records in this immutable
        // fixture; production callers perform the equivalent platform identity proof first.
        unsafe { AndroidRpdbRetainedOwner::from_verified_inventory_unchecked(inventory, indices) }
            .expect("exact retained-owner fixture")
    }
}
