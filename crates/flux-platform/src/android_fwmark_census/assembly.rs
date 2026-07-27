use std::error::Error;
use std::fmt;

use flux_core::{
    AndroidMarkDevicePolicy, AndroidMarkDevicePolicyKind, AndroidMarkPolicyAssuranceClass,
    AndroidNetIdFwmarkCensusFragment, AndroidNetdSourceProfile, CapabilityProfile,
    CapabilityProfileDigest, FwmarkCandidate, FwmarkCensusCoverageRecord,
    FwmarkCensusCoverageState, FwmarkEvidenceSource, FwmarkNetfilterBuiltinHook,
    FwmarkOrderedLateWritePlacement, FwmarkOrderedLateWriteQualification, FwmarkPlane,
    FwmarkUseOperation, FwmarkUseRecord, MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
    MAX_ORDERED_LATE_PACKET_WRITES, NetworkAddressFamily, NetworkInventory,
    NetworkNamespaceIdentity, RpdbFwmarkCensusFragment,
};
use sha2::{Digest, Sha256};

use super::{
    AndroidExistingFluxOwnershipObservation, AndroidNftablesFwmarkObservation,
    AndroidTrafficControlBpfFwmarkObservation, AndroidXfrmFwmarkObservation,
    AndroidXtablesFwmarkObservation,
};

pub const ANDROID_FWMARK_CENSUS_PROJECTION_CELLS: usize = 27;
pub const ANDROID_FWMARK_CENSUS_PROJECTION_METRICS: usize = 36;

const PROJECTION_DIGEST_DOMAIN: &[u8] =
    b"Flux Android fwmark census diagnostic projection\0canonical-schema-v1\0sha256-v1\0";
const ALL_SOURCES: [FwmarkEvidenceSource; 9] = [
    FwmarkEvidenceSource::AndroidNetId,
    FwmarkEvidenceSource::Rpdb,
    FwmarkEvidenceSource::DeviceMarkPolicy,
    FwmarkEvidenceSource::LegacyXtables,
    FwmarkEvidenceSource::Nftables,
    FwmarkEvidenceSource::TrafficControlAndBpf,
    FwmarkEvidenceSource::Xfrm,
    FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
    FwmarkEvidenceSource::ExistingFluxOwnership,
];
const ALL_PLANES: [FwmarkPlane; 3] = [
    FwmarkPlane::Packet,
    FwmarkPlane::Socket,
    FwmarkPlane::Conntrack,
];

/// Aggregate identity of one sanitized, non-authorizing census projection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AndroidFwmarkCensusProjectionDigest([u8; 32]);

impl AndroidFwmarkCensusProjectionDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Stable label for one bounded diagnostic count.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AndroidFwmarkCensusMetricKind {
    InventoryLinks,
    InventoryAddresses,
    InventoryRoutes,
    InventoryRules,
    XtablesTables,
    XtablesChains,
    XtablesRules,
    XtablesFluxOwnedChains,
    NftablesKernelSupported,
    NftablesTables,
    NftablesChains,
    NftablesRules,
    NftablesExpressions,
    NftablesOpaqueExpressions,
    TrafficControlAttachedFilters,
    BpfLoadedPrograms,
    BpfRelevantPrograms,
    BpfInaccessiblePrograms,
    BpfOpaquePrograms,
    BpfInstructions,
    XfrmKernelSupported,
    XfrmStates,
    XfrmPolicies,
    XfrmMarkAttributes,
    XfrmOpaqueAttributes,
    ExistingFluxDurableRootPresent,
    ExistingFluxEmptyTargetArchivePresent,
    ExistingFluxDurableArtifacts,
    ExistingFluxArchivedTargets,
    ExistingFluxProcesses,
    ExistingFluxChains,
    ExistingFluxRoutes,
    ExistingFluxRules,
    RawMarkUses,
    CanonicalMarkUses,
    OrderedLateWrites,
}

impl AndroidFwmarkCensusMetricKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InventoryLinks => "inventory-links",
            Self::InventoryAddresses => "inventory-addresses",
            Self::InventoryRoutes => "inventory-routes",
            Self::InventoryRules => "inventory-rules",
            Self::XtablesTables => "xtables-tables",
            Self::XtablesChains => "xtables-chains",
            Self::XtablesRules => "xtables-rules",
            Self::XtablesFluxOwnedChains => "xtables-flux-owned-chains",
            Self::NftablesKernelSupported => "nftables-kernel-supported",
            Self::NftablesTables => "nftables-tables",
            Self::NftablesChains => "nftables-chains",
            Self::NftablesRules => "nftables-rules",
            Self::NftablesExpressions => "nftables-expressions",
            Self::NftablesOpaqueExpressions => "nftables-opaque-expressions",
            Self::TrafficControlAttachedFilters => "traffic-control-attached-filters",
            Self::BpfLoadedPrograms => "bpf-loaded-programs",
            Self::BpfRelevantPrograms => "bpf-relevant-programs",
            Self::BpfInaccessiblePrograms => "bpf-inaccessible-programs",
            Self::BpfOpaquePrograms => "bpf-opaque-programs",
            Self::BpfInstructions => "bpf-instructions",
            Self::XfrmKernelSupported => "xfrm-kernel-supported",
            Self::XfrmStates => "xfrm-states",
            Self::XfrmPolicies => "xfrm-policies",
            Self::XfrmMarkAttributes => "xfrm-mark-attributes",
            Self::XfrmOpaqueAttributes => "xfrm-opaque-attributes",
            Self::ExistingFluxDurableRootPresent => "existing-flux-durable-root-present",
            Self::ExistingFluxEmptyTargetArchivePresent => {
                "existing-flux-empty-target-archive-present"
            }
            Self::ExistingFluxDurableArtifacts => "existing-flux-durable-artifacts",
            Self::ExistingFluxArchivedTargets => "existing-flux-archived-targets",
            Self::ExistingFluxProcesses => "existing-flux-processes",
            Self::ExistingFluxChains => "existing-flux-chains",
            Self::ExistingFluxRoutes => "existing-flux-routes",
            Self::ExistingFluxRules => "existing-flux-rules",
            Self::RawMarkUses => "raw-mark-uses",
            Self::CanonicalMarkUses => "canonical-mark-uses",
            Self::OrderedLateWrites => "ordered-late-writes",
        }
    }
}

/// One stable metric label and its bounded count.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AndroidFwmarkCensusMetric {
    kind: AndroidFwmarkCensusMetricKind,
    value: u64,
}

impl AndroidFwmarkCensusMetric {
    const fn new(kind: AndroidFwmarkCensusMetricKind, value: u64) -> Self {
        Self { kind, value }
    }

    #[must_use]
    pub const fn kind(self) -> AndroidFwmarkCensusMetricKind {
        self.kind
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }
}

/// Sanitized point-in-time diagnostic assembled from every fwmark evidence source.
///
/// This type intentionally does not implement `Clone` and exposes no conversion into
/// `CompleteFwmarkCensus`. The later freshness coordinator must consume a new projection only after
/// identical external snapshots bracket the native inventory transaction.
///
/// ```compile_fail
/// use flux_platform::AndroidFwmarkCensusProjection;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AndroidFwmarkCensusProjection>();
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct AndroidFwmarkCensusProjection {
    cells: [FwmarkCensusCoverageRecord; ANDROID_FWMARK_CENSUS_PROJECTION_CELLS],
    mark_uses: Box<[FwmarkUseRecord]>,
    ordered_late_writes: Box<[FwmarkOrderedLateWriteQualification]>,
    metrics: [AndroidFwmarkCensusMetric; ANDROID_FWMARK_CENSUS_PROJECTION_METRICS],
    digest: AndroidFwmarkCensusProjectionDigest,
}

impl AndroidFwmarkCensusProjection {
    #[must_use]
    pub const fn cells(
        &self,
    ) -> &[FwmarkCensusCoverageRecord; ANDROID_FWMARK_CENSUS_PROJECTION_CELLS] {
        &self.cells
    }

    #[must_use]
    pub fn mark_uses(&self) -> &[FwmarkUseRecord] {
        &self.mark_uses
    }

    #[must_use]
    pub fn ordered_late_writes(&self) -> &[FwmarkOrderedLateWriteQualification] {
        &self.ordered_late_writes
    }

    #[must_use]
    pub const fn metrics(
        &self,
    ) -> &[AndroidFwmarkCensusMetric; ANDROID_FWMARK_CENSUS_PROJECTION_METRICS] {
        &self.metrics
    }

    #[must_use]
    pub const fn digest(&self) -> AndroidFwmarkCensusProjectionDigest {
        self.digest
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.cells.iter().all(|record| record.state().is_complete())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidFwmarkCensusAssemblyError {
    RpdbInventoryMismatch,
    ExistingFluxInventoryMismatch,
    ExistingFluxCapabilityProfileMismatch,
    ExistingFluxNetworkNamespaceMismatch,
    ExistingFluxXtablesMismatch,
    XtablesNetdSourceProfileMismatch,
    DevicePolicyNetdSourceProfileMismatch,
    DevicePolicyCapabilityProfileMismatch,
    DevicePolicyNetworkNamespaceMismatch,
    DevicePolicyCandidateMismatch,
    CoverageSourceMismatch {
        expected: FwmarkEvidenceSource,
        observed: FwmarkEvidenceSource,
    },
    DuplicateCoverage {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
    },
    MissingCoverage {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
    },
    MarkUseSourceMismatch {
        expected: FwmarkEvidenceSource,
        observed: FwmarkEvidenceSource,
    },
    TooManyMarkUses {
        maximum: usize,
        required_at_least: usize,
    },
    TooManyOrderedLateWrites {
        maximum: usize,
        required_at_least: usize,
    },
    DuplicateOrderedLateWrite,
    OrderedLateWriteHasNoMarkUse,
    PresentCoverageHasNoMarkUse {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
    },
    AbsentCoverageHasMarkUse {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
    },
    MetricOverflow,
}

impl fmt::Display for AndroidFwmarkCensusAssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RpdbInventoryMismatch => {
                formatter.write_str("RPDB fwmark evidence belongs to another inventory")
            }
            Self::ExistingFluxInventoryMismatch => {
                formatter.write_str("existing-Flux ownership evidence belongs to another inventory")
            }
            Self::ExistingFluxCapabilityProfileMismatch => formatter.write_str(
                "existing-Flux ownership evidence belongs to another Capability Profile",
            ),
            Self::ExistingFluxNetworkNamespaceMismatch => formatter
                .write_str("existing-Flux ownership evidence belongs to another network namespace"),
            Self::ExistingFluxXtablesMismatch => formatter
                .write_str("existing-Flux ownership evidence belongs to another xtables snapshot"),
            Self::XtablesNetdSourceProfileMismatch => formatter
                .write_str("xtables and Android netId evidence use different netd source profiles"),
            Self::DevicePolicyNetdSourceProfileMismatch => formatter.write_str(
                "device-policy and Android netId evidence use different netd source profiles",
            ),
            Self::DevicePolicyCapabilityProfileMismatch => {
                formatter.write_str("device-policy evidence belongs to another Capability Profile")
            }
            Self::DevicePolicyNetworkNamespaceMismatch => {
                formatter.write_str("device-policy evidence belongs to another network namespace")
            }
            Self::DevicePolicyCandidateMismatch => formatter
                .write_str("device-policy and xtables evidence use different mark candidates"),
            Self::CoverageSourceMismatch { expected, observed } => write!(
                formatter,
                "{expected:?} coverage contains a record attributed to {observed:?}"
            ),
            Self::DuplicateCoverage { source, plane } => write!(
                formatter,
                "census projection repeats {source:?} coverage for the {plane:?} plane"
            ),
            Self::MissingCoverage { source, plane } => write!(
                formatter,
                "census projection omits {source:?} coverage for the {plane:?} plane"
            ),
            Self::MarkUseSourceMismatch { expected, observed } => write!(
                formatter,
                "{expected:?} mark-use input contains a record attributed to {observed:?}"
            ),
            Self::TooManyMarkUses {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "census projection has at least {required_at_least} raw mark uses but its limit is {maximum}"
            ),
            Self::TooManyOrderedLateWrites {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "census projection has at least {required_at_least} ordered-late writes but its limit is {maximum}"
            ),
            Self::DuplicateOrderedLateWrite => {
                formatter.write_str("census projection repeats an ordered-late write")
            }
            Self::OrderedLateWriteHasNoMarkUse => formatter.write_str(
                "census projection retains an ordered-late write without its canonical mark use",
            ),
            Self::PresentCoverageHasNoMarkUse { source, plane } => write!(
                formatter,
                "census projection declares {source:?} present on {plane:?} without a mark use"
            ),
            Self::AbsentCoverageHasMarkUse { source, plane } => write!(
                formatter,
                "census projection declares {source:?} absent on {plane:?} but retains a mark use"
            ),
            Self::MetricOverflow => {
                formatter.write_str("a census diagnostic count does not fit the stable u64 grammar")
            }
        }
    }
}

impl Error for AndroidFwmarkCensusAssemblyError {}

/// Assembles every source into one bounded diagnostic projection without granting authority.
#[allow(clippy::too_many_arguments)]
pub fn assemble_android_fwmark_census_projection(
    inventory: &NetworkInventory,
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    device_policy: &AndroidMarkDevicePolicy,
    android_net_id: &AndroidNetIdFwmarkCensusFragment,
    rpdb: &RpdbFwmarkCensusFragment,
    xtables: &AndroidXtablesFwmarkObservation,
    nftables: &AndroidNftablesFwmarkObservation,
    traffic_control_bpf: &AndroidTrafficControlBpfFwmarkObservation,
    xfrm: &AndroidXfrmFwmarkObservation,
    existing_flux: &AndroidExistingFluxOwnershipObservation,
) -> Result<AndroidFwmarkCensusProjection, AndroidFwmarkCensusAssemblyError> {
    validate_bindings(
        inventory,
        capability_profile,
        network_namespace,
        device_policy,
        android_net_id,
        rpdb,
        xtables,
        existing_flux,
    )?;

    let mut raw_mark_uses = Vec::new();
    append_mark_uses(
        &mut raw_mark_uses,
        FwmarkEvidenceSource::AndroidNetId,
        android_net_id.raw_mark_uses(),
    )?;
    append_mark_uses(
        &mut raw_mark_uses,
        FwmarkEvidenceSource::Rpdb,
        rpdb.raw_mark_uses(),
    )?;
    append_mark_uses(
        &mut raw_mark_uses,
        FwmarkEvidenceSource::LegacyXtables,
        xtables.legacy_mark_uses(),
    )?;
    append_mark_uses(
        &mut raw_mark_uses,
        FwmarkEvidenceSource::Nftables,
        nftables.mark_uses(),
    )?;
    append_mark_uses(
        &mut raw_mark_uses,
        FwmarkEvidenceSource::TrafficControlAndBpf,
        traffic_control_bpf.mark_uses(),
    )?;
    append_mark_uses(
        &mut raw_mark_uses,
        FwmarkEvidenceSource::Xfrm,
        xfrm.mark_uses(),
    )?;
    append_mark_uses(
        &mut raw_mark_uses,
        FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
        xtables.transfer_mark_uses(),
    )?;
    append_mark_uses(
        &mut raw_mark_uses,
        FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
        nftables.transfer_mark_uses(),
    )?;
    let raw_mark_use_count = raw_mark_uses.len();
    raw_mark_uses.sort_unstable();
    raw_mark_uses.dedup();
    let canonical_mark_uses = raw_mark_uses;

    let policy_states = device_policy_states(device_policy);
    let legacy_states = complete_coverage_from_uses(xtables.legacy_mark_uses());
    let xtables_transfer_states = complete_coverage_from_uses(xtables.transfer_mark_uses());
    let nftables_transfer_states = normalize_source_coverage(
        FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
        nftables.transfer_coverage(),
    )?;
    let transfer_states = std::array::from_fn(|index| {
        combine_coverage_states(
            xtables_transfer_states[index],
            nftables_transfer_states[index],
        )
    });
    let states = [
        normalize_source_coverage(
            FwmarkEvidenceSource::AndroidNetId,
            android_net_id.coverage(),
        )?,
        normalize_source_coverage(FwmarkEvidenceSource::Rpdb, rpdb.coverage())?,
        policy_states,
        legacy_states,
        normalize_source_coverage(FwmarkEvidenceSource::Nftables, nftables.coverage())?,
        normalize_source_coverage(
            FwmarkEvidenceSource::TrafficControlAndBpf,
            traffic_control_bpf.coverage(),
        )?,
        normalize_source_coverage(FwmarkEvidenceSource::Xfrm, xfrm.coverage())?,
        transfer_states,
        normalize_source_coverage(
            FwmarkEvidenceSource::ExistingFluxOwnership,
            existing_flux.coverage(),
        )?,
    ];
    let cells = std::array::from_fn(|index| {
        let source_index = index / ALL_PLANES.len();
        let plane_index = index % ALL_PLANES.len();
        FwmarkCensusCoverageRecord::new(
            ALL_SOURCES[source_index],
            ALL_PLANES[plane_index],
            states[source_index][plane_index],
        )
    });
    validate_coverage_use_consistency(&cells, &canonical_mark_uses)?;

    let ordered_late_writes =
        normalize_ordered_late_writes(xtables.ordered_late_writes(), &canonical_mark_uses)?;
    let metrics = build_metrics(
        inventory,
        xtables,
        nftables,
        traffic_control_bpf,
        xfrm,
        existing_flux,
        raw_mark_use_count,
        canonical_mark_uses.len(),
        ordered_late_writes.len(),
    )?;
    let bindings = ProjectionDigestBindings {
        inventory,
        capability_profile_digest: capability_profile.digest(),
        network_namespace,
        device_policy,
        android_net_id,
        rpdb,
        xtables,
        nftables,
        traffic_control_bpf,
        xfrm,
        existing_flux,
    };
    let digest = digest_projection(
        &bindings,
        &cells,
        &canonical_mark_uses,
        &ordered_late_writes,
        &metrics,
    );

    Ok(AndroidFwmarkCensusProjection {
        cells,
        mark_uses: canonical_mark_uses.into_boxed_slice(),
        ordered_late_writes,
        metrics,
        digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_bindings(
    inventory: &NetworkInventory,
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    device_policy: &AndroidMarkDevicePolicy,
    android_net_id: &AndroidNetIdFwmarkCensusFragment,
    rpdb: &RpdbFwmarkCensusFragment,
    xtables: &AndroidXtablesFwmarkObservation,
    existing_flux: &AndroidExistingFluxOwnershipObservation,
) -> Result<(), AndroidFwmarkCensusAssemblyError> {
    if rpdb.snapshot_id() != inventory.snapshot_id() || rpdb.epoch() != inventory.epoch() {
        return Err(AndroidFwmarkCensusAssemblyError::RpdbInventoryMismatch);
    }
    if existing_flux.snapshot_id() != inventory.snapshot_id()
        || existing_flux.epoch() != inventory.epoch()
    {
        return Err(AndroidFwmarkCensusAssemblyError::ExistingFluxInventoryMismatch);
    }
    if existing_flux.capability_profile_digest() != capability_profile.digest() {
        return Err(AndroidFwmarkCensusAssemblyError::ExistingFluxCapabilityProfileMismatch);
    }
    if existing_flux.network_namespace() != network_namespace {
        return Err(AndroidFwmarkCensusAssemblyError::ExistingFluxNetworkNamespaceMismatch);
    }
    if existing_flux.xtables_digest() != xtables.digest() {
        return Err(AndroidFwmarkCensusAssemblyError::ExistingFluxXtablesMismatch);
    }
    if xtables.netd_source_profile() != android_net_id.profile() {
        return Err(AndroidFwmarkCensusAssemblyError::XtablesNetdSourceProfileMismatch);
    }
    if let Some(grant) = device_policy.positive_grant() {
        if grant.netd_source_profile() != android_net_id.profile() {
            return Err(AndroidFwmarkCensusAssemblyError::DevicePolicyNetdSourceProfileMismatch);
        }
        if grant.capability_profile().digest() != capability_profile.digest() {
            return Err(AndroidFwmarkCensusAssemblyError::DevicePolicyCapabilityProfileMismatch);
        }
        if grant.network_namespace() != network_namespace {
            return Err(AndroidFwmarkCensusAssemblyError::DevicePolicyNetworkNamespaceMismatch);
        }
        if grant.candidate() != xtables.candidate() {
            return Err(AndroidFwmarkCensusAssemblyError::DevicePolicyCandidateMismatch);
        }
    }
    Ok(())
}

fn append_mark_uses(
    output: &mut Vec<FwmarkUseRecord>,
    expected_source: FwmarkEvidenceSource,
    records: &[FwmarkUseRecord],
) -> Result<(), AndroidFwmarkCensusAssemblyError> {
    for record in records {
        if record.source() != expected_source {
            return Err(AndroidFwmarkCensusAssemblyError::MarkUseSourceMismatch {
                expected: expected_source,
                observed: record.source(),
            });
        }
        if output.len() == MAX_COMPLETE_FWMARK_CENSUS_MARK_USES {
            return Err(AndroidFwmarkCensusAssemblyError::TooManyMarkUses {
                maximum: MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
                required_at_least: MAX_COMPLETE_FWMARK_CENSUS_MARK_USES + 1,
            });
        }
        output.push(*record);
    }
    Ok(())
}

fn normalize_source_coverage(
    expected_source: FwmarkEvidenceSource,
    records: &[FwmarkCensusCoverageRecord],
) -> Result<[FwmarkCensusCoverageState; 3], AndroidFwmarkCensusAssemblyError> {
    let mut states = [None; ALL_PLANES.len()];
    for record in records {
        if record.source() != expected_source {
            return Err(AndroidFwmarkCensusAssemblyError::CoverageSourceMismatch {
                expected: expected_source,
                observed: record.source(),
            });
        }
        let index = plane_index(record.plane());
        if states[index].replace(record.state()).is_some() {
            return Err(AndroidFwmarkCensusAssemblyError::DuplicateCoverage {
                source: expected_source,
                plane: record.plane(),
            });
        }
    }
    for (index, state) in states.iter().enumerate() {
        if state.is_none() {
            return Err(AndroidFwmarkCensusAssemblyError::MissingCoverage {
                source: expected_source,
                plane: ALL_PLANES[index],
            });
        }
    }
    Ok(states.map(|state| state.expect("all coverage planes were validated")))
}

fn complete_coverage_from_uses(records: &[FwmarkUseRecord]) -> [FwmarkCensusCoverageState; 3] {
    ALL_PLANES.map(|plane| {
        if records.iter().any(|record| record.plane() == plane) {
            FwmarkCensusCoverageState::CompletePresent
        } else {
            FwmarkCensusCoverageState::CompleteAbsent
        }
    })
}

fn device_policy_states(device_policy: &AndroidMarkDevicePolicy) -> [FwmarkCensusCoverageState; 3] {
    let Some(grant) = device_policy.positive_grant() else {
        return [FwmarkCensusCoverageState::Unavailable; ALL_PLANES.len()];
    };
    ALL_PLANES.map(|plane| {
        if grant.planes().contains(plane) {
            FwmarkCensusCoverageState::CompleteAbsent
        } else {
            FwmarkCensusCoverageState::Unavailable
        }
    })
}

fn combine_coverage_states(
    first: FwmarkCensusCoverageState,
    second: FwmarkCensusCoverageState,
) -> FwmarkCensusCoverageState {
    let first_rank = coverage_precedence(first);
    let second_rank = coverage_precedence(second);
    if first_rank < 2 && second_rank < 2 {
        if first == FwmarkCensusCoverageState::CompletePresent
            || second == FwmarkCensusCoverageState::CompletePresent
        {
            FwmarkCensusCoverageState::CompletePresent
        } else {
            FwmarkCensusCoverageState::CompleteAbsent
        }
    } else if first_rank >= second_rank {
        first
    } else {
        second
    }
}

const fn coverage_precedence(state: FwmarkCensusCoverageState) -> u8 {
    match state {
        FwmarkCensusCoverageState::CompleteAbsent => 0,
        FwmarkCensusCoverageState::CompletePresent => 1,
        FwmarkCensusCoverageState::Unavailable => 2,
        FwmarkCensusCoverageState::Opaque => 3,
        FwmarkCensusCoverageState::Incomplete => 4,
        FwmarkCensusCoverageState::Transient => 5,
        FwmarkCensusCoverageState::Denied => 6,
    }
}

fn validate_coverage_use_consistency(
    cells: &[FwmarkCensusCoverageRecord; ANDROID_FWMARK_CENSUS_PROJECTION_CELLS],
    mark_uses: &[FwmarkUseRecord],
) -> Result<(), AndroidFwmarkCensusAssemblyError> {
    for cell in cells {
        let has_mark_use = mark_uses
            .iter()
            .any(|record| record.source() == cell.source() && record.plane() == cell.plane());
        match (cell.state(), has_mark_use) {
            (FwmarkCensusCoverageState::CompletePresent, false) => {
                return Err(
                    AndroidFwmarkCensusAssemblyError::PresentCoverageHasNoMarkUse {
                        source: cell.source(),
                        plane: cell.plane(),
                    },
                );
            }
            (FwmarkCensusCoverageState::CompleteAbsent, true) => {
                return Err(AndroidFwmarkCensusAssemblyError::AbsentCoverageHasMarkUse {
                    source: cell.source(),
                    plane: cell.plane(),
                });
            }
            (FwmarkCensusCoverageState::CompletePresent, true)
            | (FwmarkCensusCoverageState::CompleteAbsent, false)
            | (
                FwmarkCensusCoverageState::Incomplete
                | FwmarkCensusCoverageState::Opaque
                | FwmarkCensusCoverageState::Denied
                | FwmarkCensusCoverageState::Transient
                | FwmarkCensusCoverageState::Unavailable,
                _,
            ) => {}
        }
    }
    Ok(())
}

fn normalize_ordered_late_writes(
    records: &[FwmarkOrderedLateWriteQualification],
    mark_uses: &[FwmarkUseRecord],
) -> Result<Box<[FwmarkOrderedLateWriteQualification]>, AndroidFwmarkCensusAssemblyError> {
    if records.len() > MAX_ORDERED_LATE_PACKET_WRITES {
        return Err(AndroidFwmarkCensusAssemblyError::TooManyOrderedLateWrites {
            maximum: MAX_ORDERED_LATE_PACKET_WRITES,
            required_at_least: records.len(),
        });
    }
    let mut records = records.to_vec();
    records.sort_unstable();
    if records.windows(2).any(|records| records[0] == records[1]) {
        return Err(AndroidFwmarkCensusAssemblyError::DuplicateOrderedLateWrite);
    }
    if records
        .iter()
        .any(|record| !mark_uses.contains(&record.mark_use()))
    {
        return Err(AndroidFwmarkCensusAssemblyError::OrderedLateWriteHasNoMarkUse);
    }
    Ok(records.into_boxed_slice())
}

#[allow(clippy::too_many_arguments)]
fn build_metrics(
    inventory: &NetworkInventory,
    xtables: &AndroidXtablesFwmarkObservation,
    nftables: &AndroidNftablesFwmarkObservation,
    traffic_control_bpf: &AndroidTrafficControlBpfFwmarkObservation,
    xfrm: &AndroidXfrmFwmarkObservation,
    existing_flux: &AndroidExistingFluxOwnershipObservation,
    raw_mark_use_count: usize,
    canonical_mark_use_count: usize,
    ordered_late_write_count: usize,
) -> Result<
    [AndroidFwmarkCensusMetric; ANDROID_FWMARK_CENSUS_PROJECTION_METRICS],
    AndroidFwmarkCensusAssemblyError,
> {
    use AndroidFwmarkCensusMetricKind as Kind;

    Ok([
        metric(Kind::InventoryLinks, inventory.links().len())?,
        metric(Kind::InventoryAddresses, inventory.addresses().len())?,
        metric(Kind::InventoryRoutes, inventory.routes().len())?,
        metric(Kind::InventoryRules, inventory.rules().len())?,
        metric(Kind::XtablesTables, xtables.table_count())?,
        metric(Kind::XtablesChains, xtables.chain_count())?,
        metric(Kind::XtablesRules, xtables.rule_count())?,
        metric(
            Kind::XtablesFluxOwnedChains,
            xtables.flux_owned_chain_count(),
        )?,
        bool_metric(Kind::NftablesKernelSupported, nftables.kernel_supported()),
        metric(Kind::NftablesTables, nftables.table_count())?,
        metric(Kind::NftablesChains, nftables.chain_count())?,
        metric(Kind::NftablesRules, nftables.rule_count())?,
        metric(Kind::NftablesExpressions, nftables.expression_count())?,
        metric(
            Kind::NftablesOpaqueExpressions,
            nftables.opaque_expression_count(),
        )?,
        metric(
            Kind::TrafficControlAttachedFilters,
            traffic_control_bpf.attached_traffic_control_filter_count(),
        )?,
        metric(
            Kind::BpfLoadedPrograms,
            traffic_control_bpf.loaded_program_count(),
        )?,
        metric(
            Kind::BpfRelevantPrograms,
            traffic_control_bpf.relevant_program_count(),
        )?,
        metric(
            Kind::BpfInaccessiblePrograms,
            traffic_control_bpf.inaccessible_program_count(),
        )?,
        metric(
            Kind::BpfOpaquePrograms,
            traffic_control_bpf.opaque_program_count(),
        )?,
        metric(
            Kind::BpfInstructions,
            traffic_control_bpf.instruction_count(),
        )?,
        bool_metric(Kind::XfrmKernelSupported, xfrm.kernel_supported()),
        metric(Kind::XfrmStates, xfrm.state_count())?,
        metric(Kind::XfrmPolicies, xfrm.policy_count())?,
        metric(Kind::XfrmMarkAttributes, xfrm.mark_attribute_count())?,
        metric(Kind::XfrmOpaqueAttributes, xfrm.opaque_attribute_count())?,
        bool_metric(
            Kind::ExistingFluxDurableRootPresent,
            existing_flux.durable_root_present(),
        ),
        bool_metric(
            Kind::ExistingFluxEmptyTargetArchivePresent,
            existing_flux.empty_target_archive_present(),
        ),
        metric(
            Kind::ExistingFluxDurableArtifacts,
            existing_flux.durable_artifact_count(),
        )?,
        metric(
            Kind::ExistingFluxArchivedTargets,
            existing_flux.archived_target_count(),
        )?,
        metric(
            Kind::ExistingFluxProcesses,
            existing_flux.flux_process_count(),
        )?,
        metric(Kind::ExistingFluxChains, existing_flux.flux_chain_count())?,
        metric(Kind::ExistingFluxRoutes, existing_flux.flux_route_count())?,
        metric(Kind::ExistingFluxRules, existing_flux.flux_rule_count())?,
        metric(Kind::RawMarkUses, raw_mark_use_count)?,
        metric(Kind::CanonicalMarkUses, canonical_mark_use_count)?,
        metric(Kind::OrderedLateWrites, ordered_late_write_count)?,
    ])
}

fn metric(
    kind: AndroidFwmarkCensusMetricKind,
    value: usize,
) -> Result<AndroidFwmarkCensusMetric, AndroidFwmarkCensusAssemblyError> {
    Ok(AndroidFwmarkCensusMetric::new(
        kind,
        u64::try_from(value).map_err(|_| AndroidFwmarkCensusAssemblyError::MetricOverflow)?,
    ))
}

const fn bool_metric(
    kind: AndroidFwmarkCensusMetricKind,
    value: bool,
) -> AndroidFwmarkCensusMetric {
    AndroidFwmarkCensusMetric::new(kind, value as u64)
}

struct ProjectionDigestBindings<'a> {
    inventory: &'a NetworkInventory,
    capability_profile_digest: CapabilityProfileDigest,
    network_namespace: NetworkNamespaceIdentity,
    device_policy: &'a AndroidMarkDevicePolicy,
    android_net_id: &'a AndroidNetIdFwmarkCensusFragment,
    rpdb: &'a RpdbFwmarkCensusFragment,
    xtables: &'a AndroidXtablesFwmarkObservation,
    nftables: &'a AndroidNftablesFwmarkObservation,
    traffic_control_bpf: &'a AndroidTrafficControlBpfFwmarkObservation,
    xfrm: &'a AndroidXfrmFwmarkObservation,
    existing_flux: &'a AndroidExistingFluxOwnershipObservation,
}

fn digest_projection(
    bindings: &ProjectionDigestBindings<'_>,
    cells: &[FwmarkCensusCoverageRecord; ANDROID_FWMARK_CENSUS_PROJECTION_CELLS],
    mark_uses: &[FwmarkUseRecord],
    ordered_late_writes: &[FwmarkOrderedLateWriteQualification],
    metrics: &[AndroidFwmarkCensusMetric; ANDROID_FWMARK_CENSUS_PROJECTION_METRICS],
) -> AndroidFwmarkCensusProjectionDigest {
    let mut digest = Sha256::new();
    digest.update(PROJECTION_DIGEST_DOMAIN);
    digest.update(bindings.inventory.snapshot_id().get().to_be_bytes());
    digest.update(bindings.inventory.epoch().get().to_be_bytes());
    digest.update(bindings.capability_profile_digest.as_bytes());
    digest.update(bindings.network_namespace.device().to_be_bytes());
    digest.update(bindings.network_namespace.inode().to_be_bytes());
    digest_policy(&mut digest, bindings.device_policy);
    digest.update([netd_source_profile_tag(bindings.android_net_id.profile())]);
    digest.update(bindings.rpdb.snapshot_id().get().to_be_bytes());
    digest.update(bindings.rpdb.epoch().get().to_be_bytes());
    digest.update(bindings.xtables.digest().as_bytes());
    digest_candidate(&mut digest, bindings.xtables.candidate());
    digest.update(bindings.nftables.digest().as_bytes());
    digest.update(bindings.traffic_control_bpf.digest().as_bytes());
    digest.update(bindings.xfrm.digest().as_bytes());
    digest.update(bindings.existing_flux.digest().as_bytes());
    digest.update(
        bindings
            .existing_flux
            .ownership_journal_identity()
            .as_bytes(),
    );
    digest.update(
        bindings
            .existing_flux
            .ownership_journal_revision()
            .get()
            .to_be_bytes(),
    );

    digest.update((cells.len() as u64).to_be_bytes());
    for cell in cells {
        digest.update([source_tag(cell.source())]);
        digest.update([plane_tag(cell.plane())]);
        digest.update([coverage_state_tag(cell.state())]);
    }
    digest.update((mark_uses.len() as u64).to_be_bytes());
    for mark_use in mark_uses {
        digest_mark_use(&mut digest, *mark_use);
    }
    digest.update((ordered_late_writes.len() as u64).to_be_bytes());
    for record in ordered_late_writes {
        digest_mark_use(&mut digest, record.mark_use());
        digest.update([family_tag(record.family())]);
        digest.update([hook_tag(record.hook())]);
        digest_bytes(&mut digest, record.child_chain().as_str().as_bytes());
        digest.update(record.hook_ordinal().to_be_bytes());
        digest.update(record.rule_ordinal().to_be_bytes());
        digest.update(record.selector_digest().as_bytes());
        digest.update([placement_tag(record.placement())]);
    }
    digest.update((metrics.len() as u64).to_be_bytes());
    for metric in metrics {
        digest.update([metric.kind as u8]);
        digest.update(metric.value.to_be_bytes());
    }
    AndroidFwmarkCensusProjectionDigest(digest.finalize().into())
}

fn digest_policy(digest: &mut Sha256, policy: &AndroidMarkDevicePolicy) {
    let identity = policy.identity();
    digest.update([match identity.kind() {
        AndroidMarkDevicePolicyKind::GenericAospNoGrant => 0,
        AndroidMarkDevicePolicyKind::DeviceQualifiedCooperative => 1,
    }]);
    digest.update(policy.revision().get().to_be_bytes());
    digest_option_tagged(digest, identity.assurance_class(), |digest, assurance| {
        digest.update([match assurance {
            AndroidMarkPolicyAssuranceClass::AuthenticatedSource => 0,
            AndroidMarkPolicyAssuranceClass::ExactArtifactObservedBehavior => 1,
        }]);
    });
    digest_option_tagged(digest, identity.catalog_entry(), |digest, entry| {
        digest_bytes(digest, entry.as_str().as_bytes());
    });
    digest_option_tagged(digest, identity.name(), |digest, name| {
        digest_bytes(digest, name.as_str().as_bytes());
    });
    digest_option_tagged(digest, identity.artifact_digest(), |digest, artifact| {
        digest.update(artifact.as_bytes());
    });
    digest_option_tagged(digest, policy.positive_grant(), |digest, grant| {
        digest_candidate(digest, grant.candidate());
        digest.update([netd_source_profile_tag(grant.netd_source_profile())]);
        digest.update(grant.capability_profile().digest().as_bytes());
        digest.update(grant.network_namespace().device().to_be_bytes());
        digest.update(grant.network_namespace().inode().to_be_bytes());
        digest.update([grant.planes().bits()]);
        digest.update((grant.ordered_late_writes().len() as u64).to_be_bytes());
        for record in grant.ordered_late_writes() {
            digest_mark_use(digest, record.mark_use());
            digest.update([family_tag(record.family())]);
            digest.update([hook_tag(record.hook())]);
            digest_bytes(digest, record.child_chain().as_str().as_bytes());
            digest.update(record.hook_ordinal().to_be_bytes());
            digest.update(record.rule_ordinal().to_be_bytes());
            digest.update(record.selector_digest().as_bytes());
            digest.update([placement_tag(record.placement())]);
        }
    });
}

fn digest_option_tagged<T>(
    digest: &mut Sha256,
    value: Option<T>,
    update: impl FnOnce(&mut Sha256, T),
) {
    match value {
        Some(value) => {
            digest.update([1]);
            update(digest, value);
        }
        None => digest.update([0]),
    }
}

fn digest_candidate(digest: &mut Sha256, candidate: FwmarkCandidate) {
    digest.update(candidate.mask().to_be_bytes());
    digest.update(candidate.proxy_value().to_be_bytes());
    digest.update(candidate.bypass_value().to_be_bytes());
}

fn digest_mark_use(digest: &mut Sha256, mark_use: FwmarkUseRecord) {
    digest.update([source_tag(mark_use.source())]);
    digest.update([plane_tag(mark_use.plane())]);
    digest.update([operation_tag(mark_use.operation())]);
    digest.update(mark_use.mask().to_be_bytes());
}

fn digest_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

const fn plane_index(plane: FwmarkPlane) -> usize {
    match plane {
        FwmarkPlane::Packet => 0,
        FwmarkPlane::Socket => 1,
        FwmarkPlane::Conntrack => 2,
    }
}

const fn source_tag(source: FwmarkEvidenceSource) -> u8 {
    match source {
        FwmarkEvidenceSource::AndroidNetId => 0,
        FwmarkEvidenceSource::Rpdb => 1,
        FwmarkEvidenceSource::DeviceMarkPolicy => 2,
        FwmarkEvidenceSource::LegacyXtables => 3,
        FwmarkEvidenceSource::Nftables => 4,
        FwmarkEvidenceSource::TrafficControlAndBpf => 5,
        FwmarkEvidenceSource::Xfrm => 6,
        FwmarkEvidenceSource::ConnmarkAndSocketTransfers => 7,
        FwmarkEvidenceSource::ExistingFluxOwnership => 8,
    }
}

const fn plane_tag(plane: FwmarkPlane) -> u8 {
    match plane {
        FwmarkPlane::Packet => 0,
        FwmarkPlane::Socket => 1,
        FwmarkPlane::Conntrack => 2,
    }
}

const fn coverage_state_tag(state: FwmarkCensusCoverageState) -> u8 {
    match state {
        FwmarkCensusCoverageState::CompletePresent => 0,
        FwmarkCensusCoverageState::CompleteAbsent => 1,
        FwmarkCensusCoverageState::Incomplete => 2,
        FwmarkCensusCoverageState::Opaque => 3,
        FwmarkCensusCoverageState::Denied => 4,
        FwmarkCensusCoverageState::Transient => 5,
        FwmarkCensusCoverageState::Unavailable => 6,
    }
}

const fn operation_tag(operation: FwmarkUseOperation) -> u8 {
    match operation {
        FwmarkUseOperation::PredicateRead => 0,
        FwmarkUseOperation::MaskedWrite => 1,
        FwmarkUseOperation::TransferRead => 2,
        FwmarkUseOperation::TransferWrite => 3,
    }
}

const fn netd_source_profile_tag(profile: AndroidNetdSourceProfile) -> u8 {
    match profile {
        AndroidNetdSourceProfile::AospAndroid12R1 => 0,
        AndroidNetdSourceProfile::AospAndroid13R1 => 1,
        AndroidNetdSourceProfile::AospNetd20250324 => 2,
    }
}

const fn family_tag(family: NetworkAddressFamily) -> u8 {
    match family {
        NetworkAddressFamily::Ipv4 => 0,
        NetworkAddressFamily::Ipv6 => 1,
    }
}

const fn hook_tag(hook: FwmarkNetfilterBuiltinHook) -> u8 {
    match hook {
        FwmarkNetfilterBuiltinHook::Input => 0,
        FwmarkNetfilterBuiltinHook::Postrouting => 1,
    }
}

const fn placement_tag(placement: FwmarkOrderedLateWritePlacement) -> u8 {
    match placement {
        FwmarkOrderedLateWritePlacement::InputAfterRouting => 0,
        FwmarkOrderedLateWritePlacement::PostroutingAfterFinalFluxUse => 1,
    }
}

#[cfg(test)]
mod tests;
