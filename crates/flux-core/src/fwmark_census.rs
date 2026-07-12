use std::error::Error;
use std::fmt;

use crate::android_mark_authority::{
    FwmarkCensusCoverageRecord, FwmarkCensusCoverageState, FwmarkPlane, FwmarkUseOperation,
    FwmarkUseRecord, MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
};
use crate::fwmark_audit::FwmarkEvidenceSource;
use crate::network_inventory::{NetworkEpoch, NetworkInventory, NetworkInventorySnapshotId};

const RPDB_COVERAGE_RECORDS: usize = 3;

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
    TooManyMarkUseRecords {
        maximum: usize,
        required_at_least: usize,
    },
}

impl fmt::Display for RpdbFwmarkCensusFragmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyMarkUseRecords {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "RPDB fwmark census fragment has at least {required_at_least} raw mark-use records but its limit is {maximum}"
            ),
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
    let mut raw_mark_uses = Vec::new();
    let mut has_selector = false;
    let mut has_opaque_rule = false;

    for rule in inventory.rules() {
        has_opaque_rule |= !rule.has_complete_attribute_coverage();
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
