use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use flux_core::{
    AndroidMarkPlanningAuthority, AndroidMarkPlanningAuthorizationError, AndroidNetdSourceProfile,
    AndroidTproxyTopologyScopeError, AndroidTproxyTopologyScopeRequest, CapabilityProfile,
    CapabilityProfileDigest, CapabilityProfileRevision, CompleteFwmarkCensus,
    CompleteFwmarkCensusError, FwmarkCandidate, FwmarkCensusCollectorRevision, NetworkInventory,
    NetworkNamespaceIdentity, ObservationKind, ReviewedAndroidMarkPolicyCatalogError,
    RpdbFwmarkCensusFragmentError, assess_android_tproxy_topology_scope,
    authorize_android_mark_planning, classify_android_rpdb,
    project_android_net_id_fwmark_census_fragment, project_rpdb_fwmark_census_fragment,
    select_reviewed_android_mark_policy,
};
use sha2::{Digest, Sha256};

use super::{
    AndroidFwmarkCensusAssemblyError, AndroidFwmarkCensusProjection,
    assemble_android_fwmark_census_projection,
};
use crate::android_fwmark_census::{
    AndroidExistingFluxOwnershipObservation, AndroidNftablesFwmarkObservation,
    AndroidTrafficControlBpfFwmarkObservation, AndroidXfrmFwmarkObservation,
    AndroidXtablesFwmarkObservation,
};

pub const ANDROID_FWMARK_CENSUS_COLLECTOR_REVISION: FwmarkCensusCollectorRevision =
    FwmarkCensusCollectorRevision::INITIAL;
pub const MAX_ANDROID_FWMARK_CENSUS_STAGE_BOUND: Duration = Duration::from_secs(30);

const EXTERNAL_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
    b"Flux Android fwmark external snapshot\0canonical-schema-v1\0sha256-v1\0";

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
/// typed values, not only their aggregate digest. It exposes only the aggregate identity publicly;
/// raw xtables text, BPF instructions, XFRM selectors, endpoints, and device identities are absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidFwmarkCensusExternalSnapshot {
    xtables: AndroidXtablesFwmarkObservation,
    nftables: AndroidNftablesFwmarkObservation,
    traffic_control_bpf: AndroidTrafficControlBpfFwmarkObservation,
    xfrm: AndroidXfrmFwmarkObservation,
    digest: AndroidFwmarkCensusExternalSnapshotDigest,
}

impl AndroidFwmarkCensusExternalSnapshot {
    #[must_use]
    pub fn new(
        xtables: AndroidXtablesFwmarkObservation,
        nftables: AndroidNftablesFwmarkObservation,
        traffic_control_bpf: AndroidTrafficControlBpfFwmarkObservation,
        xfrm: AndroidXfrmFwmarkObservation,
    ) -> Self {
        let digest = digest_external_snapshot(&xtables, &nftables, &traffic_control_bpf, &xfrm);
        Self {
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
}

/// Inputs fixed before any source is invoked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidFwmarkCensusCoordinatorRequest {
    netd_source_profile: AndroidNetdSourceProfile,
    candidate: FwmarkCandidate,
    topology_scope: AndroidTproxyTopologyScopeRequest,
    stage_bound: Duration,
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
            stage_bound,
        })
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
        bound: Duration,
    ) -> Result<AndroidFwmarkCensusExternalSnapshot, Self::Error>;

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
}

/// Successful output from exactly one coherent collection.
///
/// Both variants are boxed to keep the enum small. The enum intentionally does not implement
/// `Clone`; planning authority and its consumed census remain single-use.
#[derive(Debug, Eq, PartialEq)]
pub enum AndroidFwmarkCensusCoordinatorOutcome {
    Diagnostic(Box<AndroidFwmarkCensusProjection>),
    PlanningAuthority(Box<AndroidMarkPlanningAuthority>),
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
    pub fn planning_authority(&self) -> Option<&AndroidMarkPlanningAuthority> {
        match self {
            Self::Diagnostic(_) => None,
            Self::PlanningAuthority(authority) => Some(authority),
        }
    }
}

#[derive(Debug)]
pub enum AndroidFwmarkCensusCoordinatorError<E> {
    Collection {
        stage: AndroidFwmarkCensusCollectionStage,
        source: E,
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
    Policy(ReviewedAndroidMarkPolicyCatalogError),
    SelectedNetdSourceProfileMismatch {
        selected: AndroidNetdSourceProfile,
        requested: AndroidNetdSourceProfile,
    },
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
            Self::CapabilityDeviceIdentityUnavailable { .. }
            | Self::CapabilityDrift { .. }
            | Self::ExternalSnapshotContextMismatch { .. }
            | Self::ExternalSnapshotDrift { .. }
            | Self::Policy(_)
            | Self::SelectedNetdSourceProfileMismatch { .. }
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
            Self::Policy(error) => write!(formatter, "Android mark policy binding failed: {error}"),
            Self::SelectedNetdSourceProfileMismatch {
                selected,
                requested,
            } => write!(
                formatter,
                "reviewed Android policy selected {selected:?} but the census request uses {requested:?}"
            ),
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
            Self::Policy(error) => Some(error),
            Self::Topology(error) => Some(error.as_ref()),
            Self::Rpdb(error) => Some(error),
            Self::Assembly(error) => Some(error),
            Self::CompleteCensus(error) => Some(error),
            Self::Authorization(error) => Some(error.as_ref()),
            Self::CapabilityDeviceIdentityUnavailable { .. }
            | Self::CapabilityDrift { .. }
            | Self::ExternalSnapshotContextMismatch { .. }
            | Self::ExternalSnapshotDrift { .. }
            | Self::SelectedNetdSourceProfileMismatch { .. } => None,
        }
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
    let capability_before = source
        .collect_capability_profile(AndroidFwmarkCensusCollectionStage::CapabilityBefore)
        .map_err(|source| AndroidFwmarkCensusCoordinatorError::Collection {
            stage: AndroidFwmarkCensusCollectionStage::CapabilityBefore,
            source,
        })?;
    let network_namespace = capability_before
        .device_identity()
        .verified()
        .map(|identity| identity.network_namespace())
        .ok_or_else(|| {
            AndroidFwmarkCensusCoordinatorError::CapabilityDeviceIdentityUnavailable {
                observation: capability_before.device_identity().kind(),
            }
        })?;
    let policy_selection =
        select_reviewed_android_mark_policy(&capability_before, network_namespace)
            .map_err(AndroidFwmarkCensusCoordinatorError::Policy)?;
    if let Some(selected) = policy_selection.netd_source_profile()
        && selected != request.netd_source_profile
    {
        return Err(
            AndroidFwmarkCensusCoordinatorError::SelectedNetdSourceProfileMismatch {
                selected,
                requested: request.netd_source_profile,
            },
        );
    }

    let external_before = source
        .collect_external_snapshot(
            AndroidFwmarkCensusExternalPhase::Before,
            request.netd_source_profile,
            request.candidate,
            request.stage_bound,
        )
        .map_err(|source| AndroidFwmarkCensusCoordinatorError::Collection {
            stage: AndroidFwmarkCensusExternalPhase::Before.collection_stage(),
            source,
        })?;
    validate_external_context(
        &external_before,
        request,
        AndroidFwmarkCensusExternalPhase::Before,
    )?;

    let inventory = source
        .collect_network_inventory(request.stage_bound)
        .map_err(|source| AndroidFwmarkCensusCoordinatorError::Collection {
            stage: AndroidFwmarkCensusCollectionStage::NetworkInventory,
            source,
        })?;
    let existing_flux = source
        .collect_existing_flux_ownership(
            &inventory,
            &capability_before,
            network_namespace,
            &external_before.xtables,
        )
        .map_err(|source| AndroidFwmarkCensusCoordinatorError::Collection {
            stage: AndroidFwmarkCensusCollectionStage::ExistingFluxOwnership,
            source,
        })?;
    let external_after = source
        .collect_external_snapshot(
            AndroidFwmarkCensusExternalPhase::After,
            request.netd_source_profile,
            request.candidate,
            request.stage_bound,
        )
        .map_err(|source| AndroidFwmarkCensusCoordinatorError::Collection {
            stage: AndroidFwmarkCensusExternalPhase::After.collection_stage(),
            source,
        })?;
    let capability_after = source
        .collect_capability_profile(AndroidFwmarkCensusCollectionStage::CapabilityAfter)
        .map_err(|source| AndroidFwmarkCensusCoordinatorError::Collection {
            stage: AndroidFwmarkCensusCollectionStage::CapabilityAfter,
            source,
        })?;

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

    let classification = classify_android_rpdb(&inventory, request.netd_source_profile);
    let topology_scope =
        assess_android_tproxy_topology_scope(&inventory, &classification, &request.topology_scope)
            .map_err(|error| AndroidFwmarkCensusCoordinatorError::Topology(Box::new(error)))?;
    let device_policy = policy_selection
        .bind_topology(&topology_scope)
        .map_err(AndroidFwmarkCensusCoordinatorError::Policy)?;
    let android_net_id = project_android_net_id_fwmark_census_fragment(request.netd_source_profile);
    let rpdb = project_rpdb_fwmark_census_fragment(&inventory)
        .map_err(AndroidFwmarkCensusCoordinatorError::Rpdb)?;
    let projection = assemble_android_fwmark_census_projection(
        &inventory,
        &capability_before,
        network_namespace,
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
        Box::new(authority),
    ))
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
        metrics: _,
        digest: _,
    } = projection;
    CompleteFwmarkCensus::from_complete_observation(
        inventory,
        capability_profile,
        network_namespace,
        device_policy.identity(),
        device_policy.revision(),
        ANDROID_FWMARK_CENSUS_COLLECTOR_REVISION,
        ownership_journal_identity,
        ownership_journal_revision,
        cells,
        mark_uses.into_vec(),
        ordered_late_writes.into_vec(),
    )
}

fn digest_external_snapshot(
    xtables: &AndroidXtablesFwmarkObservation,
    nftables: &AndroidNftablesFwmarkObservation,
    traffic_control_bpf: &AndroidTrafficControlBpfFwmarkObservation,
    xfrm: &AndroidXfrmFwmarkObservation,
) -> AndroidFwmarkCensusExternalSnapshotDigest {
    let mut digest = Sha256::new();
    digest.update(EXTERNAL_SNAPSHOT_DIGEST_DOMAIN);
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
