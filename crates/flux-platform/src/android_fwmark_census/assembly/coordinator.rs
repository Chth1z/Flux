use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use flux_core::{
    AndroidMarkPlanningAuthority, AndroidMarkPlanningAuthorizationError, AndroidNetdSourceProfile,
    AndroidRpdbClassificationReport, AndroidRpdbRetainedOwner, AndroidTproxyTopologyScopeError,
    AndroidTproxyTopologyScopeRequest, CapabilityProfile, CapabilityProfileDigest,
    CapabilityProfileRevision, CapturePathBehavioralEvidence, CompleteFwmarkCensus,
    CompleteFwmarkCensusError, FwmarkCandidate, FwmarkCensusCollectorEvidenceDigest,
    FwmarkCensusCollectorRevision, NetworkInventory, NetworkNamespaceIdentity, ObservationKind,
    ReviewedAndroidPlatformProfileCatalogError, ReviewedCanaryFacilityPolicy,
    ReviewedCanaryFacilitySelection, ReviewedCanaryRpdbClassificationError,
    ReviewedPolicyCatalogEntryId, RpdbFwmarkCensusFragmentError,
    assess_android_tproxy_topology_scope, authorize_android_mark_planning, classify_android_rpdb,
    classify_android_rpdb_with_retained_owner, classify_android_rpdb_with_reviewed_canary_facility,
    classify_android_rpdb_with_reviewed_canary_facility_and_retained_owner,
    project_android_net_id_fwmark_census_fragment,
    project_rpdb_fwmark_census_fragment_with_classification,
    select_reviewed_android_platform_profile,
};
use sha2::{Digest, Sha256};

use super::{
    AndroidFwmarkCensusAssemblyError, AndroidFwmarkCensusProjection,
    assemble_android_fwmark_census_projection,
};
use crate::ProcessIdentity;
use crate::android_fwmark_census::{
    AndroidExistingFluxOwnershipObservation, AndroidNftablesFwmarkObservation,
    AndroidTrafficControlBpfFwmarkObservation, AndroidXfrmFwmarkObservation,
    AndroidXtablesFwmarkObservation,
};
use crate::android_kernel_capabilities::{AndroidKernelConfigDigest, AndroidKernelConfigSnapshot};
use crate::netlink::policy_routing::{exact_managed_route_index, exact_managed_rule_index};
use crate::xtables::NativeCaptureOwnershipObservation;

pub const ANDROID_FWMARK_CENSUS_COLLECTOR_REVISION: FwmarkCensusCollectorRevision =
    FwmarkCensusCollectorRevision::new(2).expect("collector revision two is nonzero");
pub const MAX_ANDROID_FWMARK_CENSUS_STAGE_BOUND: Duration = Duration::from_secs(30);

const EXTERNAL_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
    b"Flux Android fwmark external snapshot\0canonical-schema-v2\0sha256-v1\0";

/// Purpose of one coherent census collection.
///
/// Diagnostic mode can never create a complete census. Planning-authority mode consumes the
/// projection once after every freshness check and delegates the final positive decision to core.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidFwmarkCensusCoordinatorPurpose {
    Diagnostic,
    PlanningAuthority,
}

/// Stable collection stage used for failure attribution and sequence tests.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidFwmarkCensusCollectionStage {
    CapabilityBefore,
    ExternalBefore,
    NetworkInventory,
    ExistingFluxOwnership,
    ExternalAfter,
    CapabilityAfter,
}

impl AndroidFwmarkCensusCollectionStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityBefore => "capability-before",
            Self::ExternalBefore => "external-before",
            Self::NetworkInventory => "network-inventory",
            Self::ExistingFluxOwnership => "existing-flux-ownership",
            Self::ExternalAfter => "external-after",
            Self::CapabilityAfter => "capability-after",
        }
    }
}

/// Side of the native inventory transaction on which an external snapshot was collected.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidFwmarkCensusExternalPhase {
    Before,
    After,
}

impl AndroidFwmarkCensusExternalPhase {
    #[must_use]
    pub const fn collection_stage(self) -> AndroidFwmarkCensusCollectionStage {
        match self {
            Self::Before => AndroidFwmarkCensusCollectionStage::ExternalBefore,
            Self::After => AndroidFwmarkCensusCollectionStage::ExternalAfter,
        }
    }
}

/// Canonical identity of the privacy-reduced external observations surrounding one inventory.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AndroidFwmarkCensusExternalSnapshotDigest([u8; 32]);

impl AndroidFwmarkCensusExternalSnapshotDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Complete external mark observations collected on one side of the native inventory transaction.
///
/// This value is cloneable because it is non-authorizing. The coordinator compares the complete
/// typed values, not only their aggregate digest. It retains the typed kernel configuration for
/// later path selection; raw network observations, endpoints, and device identities remain absent
/// from its public interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidFwmarkCensusExternalSnapshot {
    kernel_config: Arc<AndroidKernelConfigSnapshot>,
    xtables: AndroidXtablesFwmarkObservation,
    nftables: AndroidNftablesFwmarkObservation,
    traffic_control_bpf: AndroidTrafficControlBpfFwmarkObservation,
    xfrm: AndroidXfrmFwmarkObservation,
    digest: AndroidFwmarkCensusExternalSnapshotDigest,
}

impl AndroidFwmarkCensusExternalSnapshot {
    #[must_use]
    pub fn new(
        kernel_config: Arc<AndroidKernelConfigSnapshot>,
        xtables: AndroidXtablesFwmarkObservation,
        nftables: AndroidNftablesFwmarkObservation,
        traffic_control_bpf: AndroidTrafficControlBpfFwmarkObservation,
        xfrm: AndroidXfrmFwmarkObservation,
    ) -> Self {
        let kernel_config_digest = kernel_config.digest();
        let digest = digest_external_snapshot(
            kernel_config_digest,
            &xtables,
            &nftables,
            &traffic_control_bpf,
            &xfrm,
        );
        Self {
            kernel_config,
            xtables,
            nftables,
            traffic_control_bpf,
            xfrm,
            digest,
        }
    }

    #[must_use]
    pub const fn digest(&self) -> AndroidFwmarkCensusExternalSnapshotDigest {
        self.digest
    }

    #[must_use]
    pub fn kernel_config_digest(&self) -> AndroidKernelConfigDigest {
        self.kernel_config.digest()
    }

    #[must_use]
    pub fn kernel_config(&self) -> &AndroidKernelConfigSnapshot {
        &self.kernel_config
    }
}

/// Inputs fixed before any source is invoked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidFwmarkCensusCoordinatorRequest {
    netd_source_profile: AndroidNetdSourceProfile,
    candidate: FwmarkCandidate,
    topology_scope: AndroidTproxyTopologyScopeRequest,
    reviewed_canary_facility: Option<(
        ReviewedCanaryFacilityPolicy,
        ReviewedCanaryFacilitySelection,
    )>,
    stage_bound: Duration,
    deadline: Option<Instant>,
}

impl AndroidFwmarkCensusCoordinatorRequest {
    pub fn new(
        netd_source_profile: AndroidNetdSourceProfile,
        candidate: FwmarkCandidate,
        topology_scope: AndroidTproxyTopologyScopeRequest,
        stage_bound: Duration,
    ) -> Result<Self, AndroidFwmarkCensusCoordinatorRequestError> {
        if stage_bound.is_zero() || stage_bound > MAX_ANDROID_FWMARK_CENSUS_STAGE_BOUND {
            return Err(
                AndroidFwmarkCensusCoordinatorRequestError::InvalidStageBound {
                    maximum: MAX_ANDROID_FWMARK_CENSUS_STAGE_BOUND,
                    actual: stage_bound,
                },
            );
        }
        Ok(Self {
            netd_source_profile,
            candidate,
            topology_scope,
            reviewed_canary_facility: None,
            stage_bound,
            deadline: None,
        })
    }

    #[must_use]
    pub fn with_reviewed_canary_facility(
        mut self,
        policy: ReviewedCanaryFacilityPolicy,
        selection: ReviewedCanaryFacilitySelection,
    ) -> Self {
        self.reviewed_canary_facility = Some((policy, selection));
        self
    }

    /// Sets one optional absolute deadline for the complete census transaction.
    ///
    /// Ordinary callers leave this unset and retain the independent per-stage bound. An active
    /// Capture Path audit supplies its immutable completion deadline so each bounded collector
    /// receives only the remaining global budget.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    #[must_use]
    pub const fn netd_source_profile(&self) -> AndroidNetdSourceProfile {
        self.netd_source_profile
    }

    #[must_use]
    pub const fn candidate(&self) -> FwmarkCandidate {
        self.candidate
    }

    #[must_use]
    pub const fn topology_scope(&self) -> &AndroidTproxyTopologyScopeRequest {
        &self.topology_scope
    }

    #[must_use]
    pub const fn stage_bound(&self) -> Duration {
        self.stage_bound
    }

    #[must_use]
    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidFwmarkCensusCoordinatorRequestError {
    InvalidStageBound { maximum: Duration, actual: Duration },
}

impl fmt::Display for AndroidFwmarkCensusCoordinatorRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStageBound { maximum, actual } => write!(
                formatter,
                "Android fwmark census stage bound {actual:?} must be nonzero and at most {maximum:?}"
            ),
        }
    }
}

impl Error for AndroidFwmarkCensusCoordinatorRequestError {}

/// Trusted read-only source used by the production-shaped coordinator.
///
/// Implementations are responsible for obtaining complete external observations, but cannot
/// choose collection order or invoke the projection-to-authority conversion. Each method must be
/// read-only. Device mutation and cleanup belong to later, separately authorized runners.
pub trait AndroidFwmarkCensusCoordinatorSource {
    type Error: Error + 'static;

    fn collect_capability_profile(
        &mut self,
        stage: AndroidFwmarkCensusCollectionStage,
    ) -> Result<CapabilityProfile, Self::Error>;

    fn collect_external_snapshot(
        &mut self,
        phase: AndroidFwmarkCensusExternalPhase,
        netd_source_profile: AndroidNetdSourceProfile,
        candidate: FwmarkCandidate,
        reviewed_policy: Option<&ReviewedPolicyCatalogEntryId>,
        bound: Duration,
    ) -> Result<AndroidFwmarkCensusExternalSnapshot, Self::Error>;

    /// Collects an external snapshot while retaining exactly one already-authenticated native
    /// owner.  The default is conservative for sources that have not implemented the narrow
    /// owner-aware path; production Android overrides it so an active audit can consume the
    /// owner's xtables evidence without treating it as foreign state.
    fn collect_external_snapshot_for_active_owner(
        &mut self,
        phase: AndroidFwmarkCensusExternalPhase,
        netd_source_profile: AndroidNetdSourceProfile,
        candidate: FwmarkCandidate,
        reviewed_policy: Option<&ReviewedPolicyCatalogEntryId>,
        active_owner: &NativeCaptureOwnershipObservation,
        bound: Duration,
    ) -> Result<AndroidFwmarkCensusExternalSnapshot, Self::Error> {
        let _ = active_owner;
        self.collect_external_snapshot(
            phase,
            netd_source_profile,
            candidate,
            reviewed_policy,
            bound,
        )
    }

    fn collect_network_inventory(
        &mut self,
        bound: Duration,
    ) -> Result<Arc<NetworkInventory>, Self::Error>;

    fn collect_existing_flux_ownership(
        &mut self,
        inventory: &NetworkInventory,
        capability_profile: &CapabilityProfile,
        network_namespace: NetworkNamespaceIdentity,
        xtables: &AndroidXtablesFwmarkObservation,
    ) -> Result<AndroidExistingFluxOwnershipObservation, Self::Error>;

    /// Collects existing-Flux ownership while retaining one exact, already-authenticated native
    /// owner. Implementations that cannot prove the narrow owner-aware exception fall back to the
    /// ordinary absence proof, which remains fail-closed for active-owner callers.
    fn collect_existing_flux_ownership_for_active_owner(
        &mut self,
        inventory: &NetworkInventory,
        capability_profile: &CapabilityProfile,
        network_namespace: NetworkNamespaceIdentity,
        xtables: &AndroidXtablesFwmarkObservation,
        active_owner: &NativeCaptureOwnershipObservation,
        expected_engine: ProcessIdentity,
    ) -> Result<AndroidExistingFluxOwnershipObservation, Self::Error> {
        let _ = (active_owner, expected_engine);
        self.collect_existing_flux_ownership(
            inventory,
            capability_profile,
            network_namespace,
            xtables,
        )
    }
}

struct BoundInventoryCoordinatorSource<'a, S> {
    source: &'a mut S,
    inventory: Arc<NetworkInventory>,
}

impl<S> AndroidFwmarkCensusCoordinatorSource for BoundInventoryCoordinatorSource<'_, S>
where
    S: AndroidFwmarkCensusCoordinatorSource,
{
    type Error = S::Error;

    fn collect_capability_profile(
        &mut self,
        stage: AndroidFwmarkCensusCollectionStage,
    ) -> Result<CapabilityProfile, Self::Error> {
        self.source.collect_capability_profile(stage)
    }

    fn collect_external_snapshot(
        &mut self,
        phase: AndroidFwmarkCensusExternalPhase,
        netd_source_profile: AndroidNetdSourceProfile,
        candidate: FwmarkCandidate,
        reviewed_policy: Option<&ReviewedPolicyCatalogEntryId>,
        bound: Duration,
    ) -> Result<AndroidFwmarkCensusExternalSnapshot, Self::Error> {
        self.source.collect_external_snapshot(
            phase,
            netd_source_profile,
            candidate,
            reviewed_policy,
            bound,
        )
    }

    fn collect_external_snapshot_for_active_owner(
        &mut self,
        phase: AndroidFwmarkCensusExternalPhase,
        netd_source_profile: AndroidNetdSourceProfile,
        candidate: FwmarkCandidate,
        reviewed_policy: Option<&ReviewedPolicyCatalogEntryId>,
        active_owner: &NativeCaptureOwnershipObservation,
        bound: Duration,
    ) -> Result<AndroidFwmarkCensusExternalSnapshot, Self::Error> {
        self.source.collect_external_snapshot_for_active_owner(
            phase,
            netd_source_profile,
            candidate,
            reviewed_policy,
            active_owner,
            bound,
        )
    }

    fn collect_network_inventory(
        &mut self,
        _bound: Duration,
    ) -> Result<Arc<NetworkInventory>, Self::Error> {
        Ok(Arc::clone(&self.inventory))
    }

    fn collect_existing_flux_ownership(
        &mut self,
        inventory: &NetworkInventory,
        capability_profile: &CapabilityProfile,
        network_namespace: NetworkNamespaceIdentity,
        xtables: &AndroidXtablesFwmarkObservation,
    ) -> Result<AndroidExistingFluxOwnershipObservation, Self::Error> {
        self.source.collect_existing_flux_ownership(
            inventory,
            capability_profile,
            network_namespace,
            xtables,
        )
    }

    fn collect_existing_flux_ownership_for_active_owner(
        &mut self,
        inventory: &NetworkInventory,
        capability_profile: &CapabilityProfile,
        network_namespace: NetworkNamespaceIdentity,
        xtables: &AndroidXtablesFwmarkObservation,
        active_owner: &NativeCaptureOwnershipObservation,
        expected_engine: ProcessIdentity,
    ) -> Result<AndroidExistingFluxOwnershipObservation, Self::Error> {
        self.source
            .collect_existing_flux_ownership_for_active_owner(
                inventory,
                capability_profile,
                network_namespace,
                xtables,
                active_owner,
                expected_engine,
            )
    }
}

/// Single-use planning evidence from one coherent, freshness-bracketed census.
#[derive(Debug, Eq, PartialEq)]
pub struct AndroidFwmarkCensusPlanningEvidence {
    mark_authority: AndroidMarkPlanningAuthority,
    classification: AndroidRpdbClassificationReport,
    kernel_config: Arc<AndroidKernelConfigSnapshot>,
    capture_path_evidence: CapturePathBehavioralEvidence,
}

impl AndroidFwmarkCensusPlanningEvidence {
    fn new(
        mark_authority: AndroidMarkPlanningAuthority,
        classification: AndroidRpdbClassificationReport,
        kernel_config: Arc<AndroidKernelConfigSnapshot>,
        capture_path_evidence: CapturePathBehavioralEvidence,
    ) -> Self {
        Self {
            mark_authority,
            classification,
            kernel_config,
            capture_path_evidence,
        }
    }

    #[must_use]
    pub const fn mark_authority(&self) -> &AndroidMarkPlanningAuthority {
        &self.mark_authority
    }

    #[must_use]
    pub const fn classification(&self) -> &AndroidRpdbClassificationReport {
        &self.classification
    }

    #[must_use]
    pub fn kernel_config(&self) -> &AndroidKernelConfigSnapshot {
        &self.kernel_config
    }

    #[must_use]
    pub const fn capture_path_evidence(&self) -> &CapturePathBehavioralEvidence {
        &self.capture_path_evidence
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        AndroidMarkPlanningAuthority,
        Arc<AndroidKernelConfigSnapshot>,
        CapturePathBehavioralEvidence,
    ) {
        (
            self.mark_authority,
            self.kernel_config,
            self.capture_path_evidence,
        )
    }
}

/// Successful output from exactly one coherent collection.
///
/// Both variants are boxed to keep the enum small. The enum intentionally does not implement
/// `Clone`; planning authority and its consumed census remain single-use.
#[derive(Debug, Eq, PartialEq)]
pub enum AndroidFwmarkCensusCoordinatorOutcome {
    Diagnostic(Box<AndroidFwmarkCensusProjection>),
    PlanningAuthority(Box<AndroidFwmarkCensusPlanningEvidence>),
}

impl AndroidFwmarkCensusCoordinatorOutcome {
    #[must_use]
    pub fn diagnostic(&self) -> Option<&AndroidFwmarkCensusProjection> {
        match self {
            Self::Diagnostic(projection) => Some(projection),
            Self::PlanningAuthority(_) => None,
        }
    }

    #[must_use]
    pub fn planning_evidence(&self) -> Option<&AndroidFwmarkCensusPlanningEvidence> {
        match self {
            Self::Diagnostic(_) => None,
            Self::PlanningAuthority(evidence) => Some(evidence),
        }
    }
}

#[derive(Debug)]
pub enum AndroidFwmarkCensusCoordinatorError<E> {
    Collection {
        stage: AndroidFwmarkCensusCollectionStage,
        source: E,
    },
    DeadlineExceeded {
        stage: AndroidFwmarkCensusCollectionStage,
    },
    CapabilityDeviceIdentityUnavailable {
        observation: ObservationKind,
    },
    CapabilityDrift {
        before_revision: CapabilityProfileRevision,
        after_revision: CapabilityProfileRevision,
        before: CapabilityProfileDigest,
        after: CapabilityProfileDigest,
    },
    ExternalSnapshotContextMismatch {
        phase: AndroidFwmarkCensusExternalPhase,
        expected_profile: AndroidNetdSourceProfile,
        observed_profile: AndroidNetdSourceProfile,
        expected_candidate: FwmarkCandidate,
        observed_candidate: FwmarkCandidate,
    },
    ExternalSnapshotDrift {
        before: AndroidFwmarkCensusExternalSnapshotDigest,
        after: AndroidFwmarkCensusExternalSnapshotDigest,
    },
    PlatformProfile(ReviewedAndroidPlatformProfileCatalogError),
    SelectedNetdSourceProfileMismatch {
        selected: AndroidNetdSourceProfile,
        requested: AndroidNetdSourceProfile,
    },
    ReviewedCanaryFacilityPolicyMismatch,
    RetainedOwnerRoutingMismatch,
    ReviewedCanaryRpdb(Box<ReviewedCanaryRpdbClassificationError>),
    Topology(Box<AndroidTproxyTopologyScopeError>),
    Rpdb(RpdbFwmarkCensusFragmentError),
    Assembly(AndroidFwmarkCensusAssemblyError),
    CompleteCensus(CompleteFwmarkCensusError),
    Authorization(Box<AndroidMarkPlanningAuthorizationError>),
}

impl<E> AndroidFwmarkCensusCoordinatorError<E> {
    #[must_use]
    pub const fn collection_stage(&self) -> Option<AndroidFwmarkCensusCollectionStage> {
        match self {
            Self::Collection { stage, .. } => Some(*stage),
            Self::DeadlineExceeded { stage } => Some(*stage),
            Self::CapabilityDeviceIdentityUnavailable { .. }
            | Self::CapabilityDrift { .. }
            | Self::ExternalSnapshotContextMismatch { .. }
            | Self::ExternalSnapshotDrift { .. }
            | Self::PlatformProfile(_)
            | Self::SelectedNetdSourceProfileMismatch { .. }
            | Self::ReviewedCanaryFacilityPolicyMismatch
            | Self::RetainedOwnerRoutingMismatch
            | Self::ReviewedCanaryRpdb(_)
            | Self::Topology(_)
            | Self::Rpdb(_)
            | Self::Assembly(_)
            | Self::CompleteCensus(_)
            | Self::Authorization(_) => None,
        }
    }
}

impl<E: fmt::Display> fmt::Display for AndroidFwmarkCensusCoordinatorError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Collection { stage, source } => write!(
                formatter,
                "Android fwmark census {} collection failed: {source}",
                stage.as_str()
            ),
            Self::DeadlineExceeded { stage } => write!(
                formatter,
                "Android fwmark census {} collection exceeded its absolute deadline",
                stage.as_str()
            ),
            Self::CapabilityDeviceIdentityUnavailable { observation } => write!(
                formatter,
                "Android fwmark census requires a verified device identity, not {observation:?}"
            ),
            Self::CapabilityDrift {
                before_revision,
                after_revision,
                ..
            } => write!(
                formatter,
                "Android fwmark census capability profile drifted from revision {} to {}",
                before_revision.get(),
                after_revision.get()
            ),
            Self::ExternalSnapshotContextMismatch {
                phase,
                expected_profile,
                observed_profile,
                expected_candidate,
                observed_candidate,
            } => write!(
                formatter,
                "Android fwmark census {phase:?} external snapshot binds profile {observed_profile:?} and candidate {:#010x}/{:#010x}/{:#010x} rather than profile {expected_profile:?} and candidate {:#010x}/{:#010x}/{:#010x}",
                observed_candidate.mask(),
                observed_candidate.proxy_value(),
                observed_candidate.bypass_value(),
                expected_candidate.mask(),
                expected_candidate.proxy_value(),
                expected_candidate.bypass_value()
            ),
            Self::ExternalSnapshotDrift { .. } => formatter.write_str(
                "Android fwmark census external snapshots differ across the native inventory transaction",
            ),
            Self::PlatformProfile(error) => {
                write!(formatter, "Android platform-profile binding failed: {error}")
            }
            Self::SelectedNetdSourceProfileMismatch {
                selected,
                requested,
            } => write!(
                formatter,
                "reviewed Android policy selected {selected:?} but the census request uses {requested:?}"
            ),
            Self::ReviewedCanaryFacilityPolicyMismatch => formatter.write_str(
                "Android fwmark census can exempt canary peer rules only under the exact selected facility policy",
            ),
            Self::RetainedOwnerRoutingMismatch => formatter.write_str(
                "Android fwmark census could not prove one exact retained native route/rule owner",
            ),
            Self::ReviewedCanaryRpdb(error) => {
                write!(formatter, "reviewed canary RPDB classification failed: {error}")
            }
            Self::Topology(error) => write!(formatter, "Android topology assessment failed: {error}"),
            Self::Rpdb(error) => write!(formatter, "Android RPDB census projection failed: {error}"),
            Self::Assembly(error) => write!(formatter, "Android fwmark census assembly failed: {error}"),
            Self::CompleteCensus(error) => {
                write!(formatter, "Android fwmark census is non-authorizing: {error}")
            }
            Self::Authorization(error) => {
                write!(formatter, "Android mark planning authorization failed: {error}")
            }
        }
    }
}

impl<E: Error + 'static> Error for AndroidFwmarkCensusCoordinatorError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Collection { source, .. } => Some(source),
            Self::PlatformProfile(error) => Some(error),
            Self::ReviewedCanaryRpdb(error) => Some(error.as_ref()),
            Self::Topology(error) => Some(error.as_ref()),
            Self::Rpdb(error) => Some(error),
            Self::Assembly(error) => Some(error),
            Self::CompleteCensus(error) => Some(error),
            Self::Authorization(error) => Some(error.as_ref()),
            Self::CapabilityDeviceIdentityUnavailable { .. }
            | Self::DeadlineExceeded { .. }
            | Self::CapabilityDrift { .. }
            | Self::ExternalSnapshotContextMismatch { .. }
            | Self::ExternalSnapshotDrift { .. }
            | Self::SelectedNetdSourceProfileMismatch { .. }
            | Self::ReviewedCanaryFacilityPolicyMismatch => None,
            Self::RetainedOwnerRoutingMismatch => None,
        }
    }
}

fn stage_bound_for<E>(
    request: &AndroidFwmarkCensusCoordinatorRequest,
    stage: AndroidFwmarkCensusCollectionStage,
) -> Result<Duration, AndroidFwmarkCensusCoordinatorError<E>> {
    let Some(deadline) = request.deadline else {
        return Ok(request.stage_bound);
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(AndroidFwmarkCensusCoordinatorError::DeadlineExceeded { stage })
    } else {
        Ok(request.stage_bound.min(remaining))
    }
}

/// Runs one read-only, freshness-bracketed Android fwmark census transaction.
///
/// The fixed order is capability A, external A, native inventory, existing-Flux ownership,
/// external B, capability B. No policy is bound to topology and no complete census is constructed
/// until the two full capability profiles and two complete typed external snapshots are equal.
pub fn coordinate_android_fwmark_census<S: AndroidFwmarkCensusCoordinatorSource>(
    source: &mut S,
    request: &AndroidFwmarkCensusCoordinatorRequest,
    purpose: AndroidFwmarkCensusCoordinatorPurpose,
) -> Result<AndroidFwmarkCensusCoordinatorOutcome, AndroidFwmarkCensusCoordinatorError<S::Error>> {
    coordinate_android_fwmark_census_inner(source, request, purpose, None)
}

fn coordinate_android_fwmark_census_inner<S: AndroidFwmarkCensusCoordinatorSource>(
    source: &mut S,
    request: &AndroidFwmarkCensusCoordinatorRequest,
    purpose: AndroidFwmarkCensusCoordinatorPurpose,
    active_owner: Option<(&NativeCaptureOwnershipObservation, ProcessIdentity)>,
) -> Result<AndroidFwmarkCensusCoordinatorOutcome, AndroidFwmarkCensusCoordinatorError<S::Error>> {
    let capability_before_stage = AndroidFwmarkCensusCollectionStage::CapabilityBefore;
    let capability_before = {
        let _ = stage_bound_for::<S::Error>(request, capability_before_stage)?;
        let result = source.collect_capability_profile(capability_before_stage);
        let _ = stage_bound_for::<S::Error>(request, capability_before_stage)?;
        result.map_err(|source| AndroidFwmarkCensusCoordinatorError::Collection {
            stage: capability_before_stage,
            source,
        })?
    };
    let network_namespace = capability_before
        .device_identity()
        .verified()
        .map(|identity| identity.network_namespace())
        .ok_or_else(|| {
            AndroidFwmarkCensusCoordinatorError::CapabilityDeviceIdentityUnavailable {
                observation: capability_before.device_identity().kind(),
            }
        })?;
    let platform_profile_selection =
        select_reviewed_android_platform_profile(&capability_before, network_namespace)
            .map_err(AndroidFwmarkCensusCoordinatorError::PlatformProfile)?;
    if let Some(selected) = platform_profile_selection.netd_source_profile()
        && selected != request.netd_source_profile
    {
        return Err(
            AndroidFwmarkCensusCoordinatorError::SelectedNetdSourceProfileMismatch {
                selected,
                requested: request.netd_source_profile,
            },
        );
    }
    if let Some((requested_policy, _)) = request.reviewed_canary_facility.as_ref()
        && platform_profile_selection.canary_facility_policy() != Some(requested_policy)
    {
        return Err(AndroidFwmarkCensusCoordinatorError::ReviewedCanaryFacilityPolicyMismatch);
    }

    let external_before_stage = AndroidFwmarkCensusExternalPhase::Before.collection_stage();
    let external_before = {
        let bound = stage_bound_for::<S::Error>(request, external_before_stage)?;
        let result = collect_external_snapshot(
            source,
            active_owner.map(|(owner, _)| owner),
            AndroidFwmarkCensusExternalPhase::Before,
            request.netd_source_profile,
            request.candidate,
            platform_profile_selection.mark_policy_catalog_entry(),
            bound,
        );
        let _ = stage_bound_for::<S::Error>(request, external_before_stage)?;
        result.map_err(|source| AndroidFwmarkCensusCoordinatorError::Collection {
            stage: external_before_stage,
            source,
        })?
    };
    validate_external_context(
        &external_before,
        request,
        AndroidFwmarkCensusExternalPhase::Before,
    )?;

    let inventory_stage = AndroidFwmarkCensusCollectionStage::NetworkInventory;
    let inventory = {
        let bound = stage_bound_for::<S::Error>(request, inventory_stage)?;
        let result = source.collect_network_inventory(bound);
        let _ = stage_bound_for::<S::Error>(request, inventory_stage)?;
        result.map_err(|source| AndroidFwmarkCensusCoordinatorError::Collection {
            stage: inventory_stage,
            source,
        })?
    };
    let existing_flux_stage = AndroidFwmarkCensusCollectionStage::ExistingFluxOwnership;
    let existing_flux = {
        let _ = stage_bound_for::<S::Error>(request, existing_flux_stage)?;
        let result = match active_owner {
            Some((active_owner, expected_engine)) => source
                .collect_existing_flux_ownership_for_active_owner(
                    &inventory,
                    &capability_before,
                    network_namespace,
                    &external_before.xtables,
                    active_owner,
                    expected_engine,
                ),
            None => source.collect_existing_flux_ownership(
                &inventory,
                &capability_before,
                network_namespace,
                &external_before.xtables,
            ),
        };
        let _ = stage_bound_for::<S::Error>(request, existing_flux_stage)?;
        result.map_err(|source| AndroidFwmarkCensusCoordinatorError::Collection {
            stage: existing_flux_stage,
            source,
        })?
    };
    let external_after_stage = AndroidFwmarkCensusExternalPhase::After.collection_stage();
    let external_after = {
        let bound = stage_bound_for::<S::Error>(request, external_after_stage)?;
        let result = collect_external_snapshot(
            source,
            active_owner.map(|(owner, _)| owner),
            AndroidFwmarkCensusExternalPhase::After,
            request.netd_source_profile,
            request.candidate,
            platform_profile_selection.mark_policy_catalog_entry(),
            bound,
        );
        let _ = stage_bound_for::<S::Error>(request, external_after_stage)?;
        result.map_err(|source| AndroidFwmarkCensusCoordinatorError::Collection {
            stage: external_after_stage,
            source,
        })?
    };
    let capability_after_stage = AndroidFwmarkCensusCollectionStage::CapabilityAfter;
    let capability_after = {
        let _ = stage_bound_for::<S::Error>(request, capability_after_stage)?;
        let result = source.collect_capability_profile(capability_after_stage);
        let _ = stage_bound_for::<S::Error>(request, capability_after_stage)?;
        result.map_err(|source| AndroidFwmarkCensusCoordinatorError::Collection {
            stage: capability_after_stage,
            source,
        })?
    };

    if capability_before != capability_after {
        return Err(AndroidFwmarkCensusCoordinatorError::CapabilityDrift {
            before_revision: capability_before.revision(),
            after_revision: capability_after.revision(),
            before: capability_before.digest(),
            after: capability_after.digest(),
        });
    }
    validate_external_context(
        &external_after,
        request,
        AndroidFwmarkCensusExternalPhase::After,
    )?;
    if external_before != external_after {
        return Err(AndroidFwmarkCensusCoordinatorError::ExternalSnapshotDrift {
            before: external_before.digest,
            after: external_after.digest,
        });
    }

    let retained_owner = active_owner
        .map(|(active_owner, _)| {
            active_owner
                .retained_owner()
                .routing()
                .iter()
                .copied()
                .map(|identity| {
                    let route_index = exact_managed_route_index(&inventory, identity)
                        .ok_or(AndroidFwmarkCensusCoordinatorError::RetainedOwnerRoutingMismatch)?;
                    let rule_index = exact_managed_rule_index(&inventory, identity)
                        .ok_or(AndroidFwmarkCensusCoordinatorError::RetainedOwnerRoutingMismatch)?;
                    Ok((route_index, rule_index))
                })
                .collect::<Result<Vec<_>, AndroidFwmarkCensusCoordinatorError<S::Error>>>()
                .and_then(|indices| {
                    // SAFETY: each pair was obtained immediately above from the platform-private
                    // exact identity audit against this immutable inventory.  That audit checks
                    // every modeled route/rule field and requires one exact route and rule with
                    // no duplicate or same-coordinate conflict before returning an index.
                    unsafe {
                        AndroidRpdbRetainedOwner::from_verified_inventory_unchecked(
                            &inventory, indices,
                        )
                    }
                    .map_err(|_| AndroidFwmarkCensusCoordinatorError::RetainedOwnerRoutingMismatch)
                })
        })
        .transpose()?;
    let classification = match (
        request.reviewed_canary_facility.as_ref(),
        retained_owner.as_ref(),
    ) {
        (Some((policy, selection)), Some(retained_owner)) => {
            classify_android_rpdb_with_reviewed_canary_facility_and_retained_owner(
                &inventory,
                request.netd_source_profile,
                policy,
                *selection,
                retained_owner,
            )
            .map_err(|error| {
                AndroidFwmarkCensusCoordinatorError::ReviewedCanaryRpdb(Box::new(error))
            })?
        }
        (Some((policy, selection)), None) => classify_android_rpdb_with_reviewed_canary_facility(
            &inventory,
            request.netd_source_profile,
            policy,
            *selection,
        )
        .map_err(|error| {
            AndroidFwmarkCensusCoordinatorError::ReviewedCanaryRpdb(Box::new(error))
        })?,
        (None, Some(retained_owner)) => classify_android_rpdb_with_retained_owner(
            &inventory,
            request.netd_source_profile,
            retained_owner,
        )
        .map_err(|_| AndroidFwmarkCensusCoordinatorError::RetainedOwnerRoutingMismatch)?,
        (None, None) => classify_android_rpdb(&inventory, request.netd_source_profile),
    };
    let topology_scope =
        assess_android_tproxy_topology_scope(&inventory, &classification, &request.topology_scope)
            .map_err(|error| AndroidFwmarkCensusCoordinatorError::Topology(Box::new(error)))?;
    let bound_platform_profile = platform_profile_selection
        .bind_topology(&topology_scope)
        .map_err(AndroidFwmarkCensusCoordinatorError::PlatformProfile)?;
    let (device_policy, capture_path_evidence) = bound_platform_profile.into_parts();
    let android_net_id = project_android_net_id_fwmark_census_fragment(request.netd_source_profile);
    let rpdb = project_rpdb_fwmark_census_fragment_with_classification(&inventory, &classification)
        .map_err(AndroidFwmarkCensusCoordinatorError::Rpdb)?;
    let projection = assemble_android_fwmark_census_projection(
        &inventory,
        &capability_before,
        network_namespace,
        external_before.kernel_config_digest(),
        &device_policy,
        &android_net_id,
        &rpdb,
        &external_before.xtables,
        &external_before.nftables,
        &external_before.traffic_control_bpf,
        &external_before.xfrm,
        &existing_flux,
    )
    .map_err(AndroidFwmarkCensusCoordinatorError::Assembly)?;

    if purpose == AndroidFwmarkCensusCoordinatorPurpose::Diagnostic {
        return Ok(AndroidFwmarkCensusCoordinatorOutcome::Diagnostic(Box::new(
            projection,
        )));
    }

    let ownership_journal_identity = existing_flux.ownership_journal_identity();
    let ownership_journal_revision = existing_flux.ownership_journal_revision();
    let census = complete_census_from_projection(
        projection,
        &inventory,
        &capability_before,
        network_namespace,
        &device_policy,
        ownership_journal_identity,
        ownership_journal_revision,
    )
    .map_err(AndroidFwmarkCensusCoordinatorError::CompleteCensus)?;
    let authority = authorize_android_mark_planning(
        &inventory,
        &classification,
        &topology_scope,
        &capability_before,
        network_namespace,
        ownership_journal_identity,
        ownership_journal_revision,
        ANDROID_FWMARK_CENSUS_COLLECTOR_REVISION,
        &device_policy,
        request.candidate,
        census,
    )
    .map_err(|error| AndroidFwmarkCensusCoordinatorError::Authorization(Box::new(error)))?;
    Ok(AndroidFwmarkCensusCoordinatorOutcome::PlanningAuthority(
        Box::new(AndroidFwmarkCensusPlanningEvidence::new(
            authority,
            classification,
            Arc::clone(&external_before.kernel_config),
            capture_path_evidence,
        )),
    ))
}

/// Runs the coherent census around the exact immutable inventory supplied by its caller.
///
/// This is the production Generation path: the coordinator still brackets the inventory stage
/// with complete external and capability observations, but cannot substitute a second route
/// snapshot whose process-local identity would differ from the Generation being assembled.
pub fn coordinate_android_fwmark_census_for_inventory<S: AndroidFwmarkCensusCoordinatorSource>(
    source: &mut S,
    request: &AndroidFwmarkCensusCoordinatorRequest,
    purpose: AndroidFwmarkCensusCoordinatorPurpose,
    inventory: Arc<NetworkInventory>,
) -> Result<AndroidFwmarkCensusCoordinatorOutcome, AndroidFwmarkCensusCoordinatorError<S::Error>> {
    coordinate_android_fwmark_census(
        &mut BoundInventoryCoordinatorSource { source, inventory },
        request,
        purpose,
    )
}

/// Runs the coherent census around one immutable inventory while retaining one exact active
/// native owner.  The owner is passed through the narrow source seam for both external brackets;
/// the inventory itself is never cloned, filtered, or replaced.
pub fn coordinate_android_fwmark_census_for_inventory_with_active_owner<
    S: AndroidFwmarkCensusCoordinatorSource,
>(
    source: &mut S,
    request: &AndroidFwmarkCensusCoordinatorRequest,
    purpose: AndroidFwmarkCensusCoordinatorPurpose,
    inventory: Arc<NetworkInventory>,
    active_owner: &NativeCaptureOwnershipObservation,
    expected_engine: ProcessIdentity,
) -> Result<AndroidFwmarkCensusCoordinatorOutcome, AndroidFwmarkCensusCoordinatorError<S::Error>> {
    coordinate_android_fwmark_census_inner(
        &mut BoundInventoryCoordinatorSource { source, inventory },
        request,
        purpose,
        Some((active_owner, expected_engine)),
    )
}

fn collect_external_snapshot<S: AndroidFwmarkCensusCoordinatorSource>(
    source: &mut S,
    active_owner: Option<&NativeCaptureOwnershipObservation>,
    phase: AndroidFwmarkCensusExternalPhase,
    netd_source_profile: AndroidNetdSourceProfile,
    candidate: FwmarkCandidate,
    reviewed_policy: Option<&ReviewedPolicyCatalogEntryId>,
    bound: Duration,
) -> Result<AndroidFwmarkCensusExternalSnapshot, S::Error> {
    match active_owner {
        Some(active_owner) => source.collect_external_snapshot_for_active_owner(
            phase,
            netd_source_profile,
            candidate,
            reviewed_policy,
            active_owner,
            bound,
        ),
        None => source.collect_external_snapshot(
            phase,
            netd_source_profile,
            candidate,
            reviewed_policy,
            bound,
        ),
    }
}

fn validate_external_context<E>(
    snapshot: &AndroidFwmarkCensusExternalSnapshot,
    request: &AndroidFwmarkCensusCoordinatorRequest,
    phase: AndroidFwmarkCensusExternalPhase,
) -> Result<(), AndroidFwmarkCensusCoordinatorError<E>> {
    let observed_profile = snapshot.xtables.netd_source_profile();
    let observed_candidate = snapshot.xtables.candidate();
    if observed_profile == request.netd_source_profile && observed_candidate == request.candidate {
        Ok(())
    } else {
        Err(
            AndroidFwmarkCensusCoordinatorError::ExternalSnapshotContextMismatch {
                phase,
                expected_profile: request.netd_source_profile,
                observed_profile,
                expected_candidate: request.candidate,
                observed_candidate,
            },
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn complete_census_from_projection(
    projection: AndroidFwmarkCensusProjection,
    inventory: &NetworkInventory,
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    device_policy: &flux_core::AndroidMarkDevicePolicy,
    ownership_journal_identity: flux_core::OwnershipJournalIdentity,
    ownership_journal_revision: flux_core::OwnershipJournalRevision,
) -> Result<CompleteFwmarkCensus, CompleteFwmarkCensusError> {
    let AndroidFwmarkCensusProjection {
        cells,
        mark_uses,
        ordered_late_writes,
        exact_mark_sentinels,
        metrics: _,
        digest,
    } = projection;
    CompleteFwmarkCensus::from_complete_observation(
        inventory,
        capability_profile,
        network_namespace,
        device_policy.identity(),
        device_policy.revision(),
        ANDROID_FWMARK_CENSUS_COLLECTOR_REVISION,
        FwmarkCensusCollectorEvidenceDigest::new(*digest.as_bytes()),
        ownership_journal_identity,
        ownership_journal_revision,
        cells,
        mark_uses.into_vec(),
        ordered_late_writes.into_vec(),
        exact_mark_sentinels.into_vec(),
    )
}

fn digest_external_snapshot(
    kernel_config_digest: AndroidKernelConfigDigest,
    xtables: &AndroidXtablesFwmarkObservation,
    nftables: &AndroidNftablesFwmarkObservation,
    traffic_control_bpf: &AndroidTrafficControlBpfFwmarkObservation,
    xfrm: &AndroidXfrmFwmarkObservation,
) -> AndroidFwmarkCensusExternalSnapshotDigest {
    let mut digest = Sha256::new();
    digest.update(EXTERNAL_SNAPSHOT_DIGEST_DOMAIN);
    digest.update(b"kernel-config\0");
    digest.update(kernel_config_digest.as_bytes());
    digest.update(b"xtables\0");
    digest.update(xtables.digest().as_bytes());
    digest.update(b"nftables\0");
    digest.update(nftables.digest().as_bytes());
    digest.update(b"traffic-control-bpf\0");
    digest.update(traffic_control_bpf.digest().as_bytes());
    digest.update(b"xfrm\0");
    digest.update(xfrm.digest().as_bytes());
    AndroidFwmarkCensusExternalSnapshotDigest(digest.finalize().into())
}

#[cfg(test)]
mod tests;
