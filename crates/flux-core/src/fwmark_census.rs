use std::error::Error;
use std::fmt;

use crate::android_mark_authority::{
    FwmarkCensusCoverageRecord, FwmarkCensusCoverageState, FwmarkPlane, FwmarkUseOperation,
    FwmarkUseRecord, MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
};
use crate::android_netd::AndroidNetdSourceProfile;
use crate::android_rpdb::{
    AndroidRpdbClassificationReport, AndroidRpdbRetainedOwner, AndroidRpdbRetainedOwnerError,
};
use crate::fwmark_audit::{ANDROID_NET_ID_FWMARK_MASK, FwmarkEvidenceSource};
use crate::network_inventory::{NetworkEpoch, NetworkInventory, NetworkInventorySnapshotId};

const ANDROID_NET_ID_COVERAGE_RECORDS: usize = 3;
const ANDROID_NET_ID_MARK_USE_RECORDS: usize = 3;
const ANDROID_12_13_INCOMING_PACKET_FWMARK_MASK: u32 = 0xffef_ffff;
const ANDROID_2025_INCOMING_PACKET_FWMARK_MASK: u32 = 0x7fef_ffff;
const RPDB_COVERAGE_RECORDS: usize = 3;

/// Static Android `netId` source evidence for a future complete fwmark census.
///
/// The selected AOSP netd profiles define bits 0-15 as `netId`. Their incoming-packet rule writes
/// every mark bit except UID billing and, in the 2025 profile, ingress CPU wakeup; `FwmarkServer`
/// reads then updates the low-16-bit field in socket marks. Direct conntrack use is absent;
/// packet/socket/conntrack copy operations belong to the separate `ConnmarkAndSocketTransfers`
/// source. This fragment does not select a profile for a device and exposes no conversion into a
/// complete census or planning authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidNetIdFwmarkCensusFragment {
    profile: AndroidNetdSourceProfile,
    coverage: [FwmarkCensusCoverageRecord; ANDROID_NET_ID_COVERAGE_RECORDS],
    raw_mark_uses: [FwmarkUseRecord; ANDROID_NET_ID_MARK_USE_RECORDS],
}

impl AndroidNetIdFwmarkCensusFragment {
    #[must_use]
    pub const fn profile(&self) -> AndroidNetdSourceProfile {
        self.profile
    }

    #[must_use]
    pub const fn source_revision(&self) -> &'static str {
        self.profile.source_revision()
    }

    /// Returns Android `netId` coverage in packet, socket, then conntrack plane order.
    #[must_use]
    pub const fn coverage(&self) -> &[FwmarkCensusCoverageRecord] {
        &self.coverage
    }

    /// Returns packet masked-write, socket predicate-read, then socket masked-write evidence.
    #[must_use]
    pub const fn raw_mark_uses(&self) -> &[FwmarkUseRecord] {
        &self.raw_mark_uses
    }
}

/// Projects the direct Android `netId` operations defined by one explicit source-pinned profile.
///
/// All currently modeled profiles share the same low-16-bit socket semantics, while their exact
/// incoming-packet writer masks differ. Keeping the profile explicit prevents this static fragment
/// from authenticating a runtime netd binary or being mistaken for point-in-time cross-source
/// coordination.
#[must_use]
pub fn project_android_net_id_fwmark_census_fragment(
    profile: AndroidNetdSourceProfile,
) -> AndroidNetIdFwmarkCensusFragment {
    let coverage = [
        FwmarkCensusCoverageRecord::new(
            FwmarkEvidenceSource::AndroidNetId,
            FwmarkPlane::Packet,
            FwmarkCensusCoverageState::CompletePresent,
        ),
        FwmarkCensusCoverageRecord::new(
            FwmarkEvidenceSource::AndroidNetId,
            FwmarkPlane::Socket,
            FwmarkCensusCoverageState::CompletePresent,
        ),
        FwmarkCensusCoverageRecord::new(
            FwmarkEvidenceSource::AndroidNetId,
            FwmarkPlane::Conntrack,
            FwmarkCensusCoverageState::CompleteAbsent,
        ),
    ];
    let raw_mark_uses = [
        FwmarkUseRecord::new(
            FwmarkEvidenceSource::AndroidNetId,
            FwmarkPlane::Packet,
            FwmarkUseOperation::MaskedWrite,
            incoming_packet_fwmark_mask(profile),
        )
        .expect("the source-pinned Android incoming-packet mask is nonzero"),
        FwmarkUseRecord::new(
            FwmarkEvidenceSource::AndroidNetId,
            FwmarkPlane::Socket,
            FwmarkUseOperation::PredicateRead,
            ANDROID_NET_ID_FWMARK_MASK,
        )
        .expect("the Android netId mask is nonzero"),
        FwmarkUseRecord::new(
            FwmarkEvidenceSource::AndroidNetId,
            FwmarkPlane::Socket,
            FwmarkUseOperation::MaskedWrite,
            ANDROID_NET_ID_FWMARK_MASK,
        )
        .expect("the Android netId mask is nonzero"),
    ];

    AndroidNetIdFwmarkCensusFragment {
        profile,
        coverage,
        raw_mark_uses,
    }
}

const fn incoming_packet_fwmark_mask(profile: AndroidNetdSourceProfile) -> u32 {
    match profile {
        AndroidNetdSourceProfile::AospAndroid12R1 | AndroidNetdSourceProfile::AospAndroid13R1 => {
            ANDROID_12_13_INCOMING_PACKET_FWMARK_MASK
        }
        AndroidNetdSourceProfile::AospNetd20250324 => ANDROID_2025_INCOMING_PACKET_FWMARK_MASK,
    }
}

/// Inventory-bound RPDB source evidence for a future complete fwmark census.
///
/// Linux FIB rules predicate on a transient flow mark populated from packet marks on packet-origin
/// paths and socket marks on local-output paths. Each modeled RPDB selector therefore contributes
/// one packet-plane and one socket-plane predicate read. RPDB does not directly read conntrack
/// marks. This fragment deliberately exposes no conversion into a complete census or planning
/// authority; the other evidence sources and cross-source coordination remain required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpdbFwmarkCensusFragment {
    snapshot_id: NetworkInventorySnapshotId,
    epoch: NetworkEpoch,
    coverage: [FwmarkCensusCoverageRecord; RPDB_COVERAGE_RECORDS],
    raw_mark_uses: Box<[FwmarkUseRecord]>,
}

impl RpdbFwmarkCensusFragment {
    #[must_use]
    pub const fn snapshot_id(&self) -> NetworkInventorySnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub const fn epoch(&self) -> NetworkEpoch {
        self.epoch
    }

    /// Returns RPDB coverage in packet, socket, then conntrack plane order.
    #[must_use]
    pub fn coverage(&self) -> &[FwmarkCensusCoverageRecord] {
        &self.coverage
    }

    /// Returns raw evidence in rule dump order, retaining duplicate selectors.
    ///
    /// Every selector contributes its packet-plane record immediately followed by its
    /// socket-plane record. No sorting or deduplication occurs in this fragment.
    #[must_use]
    pub fn raw_mark_uses(&self) -> &[FwmarkUseRecord] {
        &self.raw_mark_uses
    }

    pub fn ensure_current(
        &self,
        inventory: &NetworkInventory,
    ) -> Result<(), StaleRpdbFwmarkCensusFragment> {
        if inventory.snapshot_id() == self.snapshot_id && inventory.epoch() == self.epoch {
            Ok(())
        } else {
            Err(StaleRpdbFwmarkCensusFragment {
                observed_snapshot_id: self.snapshot_id,
                current_snapshot_id: inventory.snapshot_id(),
                observed_epoch: self.epoch,
                current_epoch: inventory.epoch(),
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpdbFwmarkCensusFragmentError {
    ClassificationInventoryMismatch {
        classified_snapshot_id: NetworkInventorySnapshotId,
        current_snapshot_id: NetworkInventorySnapshotId,
        classified_epoch: NetworkEpoch,
        current_epoch: NetworkEpoch,
    },
    TooManyMarkUseRecords {
        maximum: usize,
        required_at_least: usize,
    },
    RetainedOwner(AndroidRpdbRetainedOwnerError),
}

impl fmt::Display for RpdbFwmarkCensusFragmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClassificationInventoryMismatch {
                classified_snapshot_id,
                current_snapshot_id,
                classified_epoch,
                current_epoch,
            } => write!(
                formatter,
                "RPDB classification snapshot {} at epoch {} does not match census inventory {} at epoch {}",
                classified_snapshot_id.get(),
                classified_epoch.get(),
                current_snapshot_id.get(),
                current_epoch.get()
            ),
            Self::TooManyMarkUseRecords {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "RPDB fwmark census fragment has at least {required_at_least} raw mark-use records but its limit is {maximum}"
            ),
            Self::RetainedOwner(error) => error.fmt(formatter),
        }
    }
}

impl Error for RpdbFwmarkCensusFragmentError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleRpdbFwmarkCensusFragment {
    observed_snapshot_id: NetworkInventorySnapshotId,
    current_snapshot_id: NetworkInventorySnapshotId,
    observed_epoch: NetworkEpoch,
    current_epoch: NetworkEpoch,
}

impl StaleRpdbFwmarkCensusFragment {
    #[must_use]
    pub const fn observed_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.observed_snapshot_id
    }

    #[must_use]
    pub const fn current_snapshot_id(self) -> NetworkInventorySnapshotId {
        self.current_snapshot_id
    }

    #[must_use]
    pub const fn observed_epoch(self) -> NetworkEpoch {
        self.observed_epoch
    }

    #[must_use]
    pub const fn current_epoch(self) -> NetworkEpoch {
        self.current_epoch
    }
}

impl fmt::Display for StaleRpdbFwmarkCensusFragment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "RPDB fwmark census fragment snapshot {} at epoch {} is stale relative to snapshot {} at epoch {}",
            self.observed_snapshot_id.get(),
            self.observed_epoch.get(),
            self.current_snapshot_id.get(),
            self.current_epoch.get()
        )
    }
}

impl Error for StaleRpdbFwmarkCensusFragment {}

/// Projects ordered RPDB selector evidence from one complete network-inventory snapshot.
///
/// The projection retains known selectors even when an opaque rule prevents packet/socket
/// completeness. It rejects evidence beyond the complete census's raw-record budget rather than
/// truncating or canonicalizing it.
pub fn project_rpdb_fwmark_census_fragment(
    inventory: &NetworkInventory,
) -> Result<RpdbFwmarkCensusFragment, RpdbFwmarkCensusFragmentError> {
    project_rpdb_fwmark_census_fragment_with_exclusions(inventory, &[], None)
}

/// Projects RPDB mark uses while excluding only the exact reviewed canary peer-rule cohort
/// authenticated by the supplied classification report. Generic Android reports carry an empty
/// cohort and therefore behave identically to [`project_rpdb_fwmark_census_fragment`].
pub fn project_rpdb_fwmark_census_fragment_with_classification(
    inventory: &NetworkInventory,
    classification: &AndroidRpdbClassificationReport,
) -> Result<RpdbFwmarkCensusFragment, RpdbFwmarkCensusFragmentError> {
    let audit = classification.audit();
    if audit.snapshot_id() != inventory.snapshot_id() || audit.epoch() != inventory.epoch() {
        return Err(
            RpdbFwmarkCensusFragmentError::ClassificationInventoryMismatch {
                classified_snapshot_id: audit.snapshot_id(),
                current_snapshot_id: inventory.snapshot_id(),
                classified_epoch: audit.epoch(),
                current_epoch: inventory.epoch(),
            },
        );
    }
    project_rpdb_fwmark_census_fragment_with_exclusions(
        inventory,
        classification.reviewed_canary_rule_indices(),
        classification.retained_owner(),
    )
}

fn project_rpdb_fwmark_census_fragment_with_exclusions(
    inventory: &NetworkInventory,
    excluded_reviewed_canary_rule_indices: &[usize],
    retained_owner: Option<&AndroidRpdbRetainedOwner>,
) -> Result<RpdbFwmarkCensusFragment, RpdbFwmarkCensusFragmentError> {
    let mut raw_mark_uses = Vec::new();
    let mut has_selector = false;
    let mut has_opaque_rule = false;

    if let Some(retained_owner) = retained_owner {
        retained_owner
            .ensure_current(inventory)
            .map_err(RpdbFwmarkCensusFragmentError::RetainedOwner)?;
    }

    for (dump_index, rule) in inventory.rules().iter().enumerate() {
        has_opaque_rule |= !rule.has_complete_attribute_coverage();
        if retained_owner.is_some_and(|owner| owner.contains_rule_index(dump_index)) {
            continue;
        }
        if excluded_reviewed_canary_rule_indices
            .binary_search(&dump_index)
            .is_ok()
        {
            continue;
        }
        let Some(selector) = rule.fwmark() else {
            continue;
        };
        has_selector = true;

        for plane in [FwmarkPlane::Packet, FwmarkPlane::Socket] {
            if raw_mark_uses.len() == MAX_COMPLETE_FWMARK_CENSUS_MARK_USES {
                return Err(RpdbFwmarkCensusFragmentError::TooManyMarkUseRecords {
                    maximum: MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
                    required_at_least: MAX_COMPLETE_FWMARK_CENSUS_MARK_USES + 1,
                });
            }
            raw_mark_uses.push(
                FwmarkUseRecord::new(
                    FwmarkEvidenceSource::Rpdb,
                    plane,
                    FwmarkUseOperation::PredicateRead,
                    selector.mask(),
                )
                .expect("a modeled RPDB selector always has a nonzero mask"),
            );
        }
    }

    let flow_mark_coverage = if has_opaque_rule {
        FwmarkCensusCoverageState::Opaque
    } else if has_selector {
        FwmarkCensusCoverageState::CompletePresent
    } else {
        FwmarkCensusCoverageState::CompleteAbsent
    };
    let coverage = [
        FwmarkCensusCoverageRecord::new(
            FwmarkEvidenceSource::Rpdb,
            FwmarkPlane::Packet,
            flow_mark_coverage,
        ),
        FwmarkCensusCoverageRecord::new(
            FwmarkEvidenceSource::Rpdb,
            FwmarkPlane::Socket,
            flow_mark_coverage,
        ),
        FwmarkCensusCoverageRecord::new(
            FwmarkEvidenceSource::Rpdb,
            FwmarkPlane::Conntrack,
            FwmarkCensusCoverageState::CompleteAbsent,
        ),
    ];

    Ok(RpdbFwmarkCensusFragment {
        snapshot_id: inventory.snapshot_id(),
        epoch: inventory.epoch(),
        coverage,
        raw_mark_uses: raw_mark_uses.into_boxed_slice(),
    })
}
