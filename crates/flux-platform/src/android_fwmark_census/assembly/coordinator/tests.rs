use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use flux_core::{
    AndroidMarkPlanningAuthorizationError, AndroidTproxyRoutingShape,
    AndroidTproxyTopologyScopeRequest, AndroidTproxyTrafficDomainRequest, CapabilityProfile,
    CapabilityProfileRevision, FwmarkCandidate, NetworkAddressFamily, NetworkInventory,
    NetworkNamespaceIdentity,
};

use super::*;
use crate::android_fwmark_census::assembly::tests::fixture;
use crate::android_fwmark_census::{existing_flux, nftables};

const EMPTY_XTABLES: &[u8] = b"*mangle\n:INPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n";

#[test]
fn request_rejects_unbounded_stage_durations() {
    let topology = topology_request();
    let fixture = fixture(Ipv4Addr::new(203, 0, 113, 77), true);
    let grant = fixture
        .device_policy
        .positive_grant()
        .expect("reviewed positive grant");

    assert!(matches!(
        AndroidFwmarkCensusCoordinatorRequest::new(
            grant.netd_source_profile(),
            grant.candidate(),
            topology.clone(),
            Duration::ZERO,
        ),
        Err(AndroidFwmarkCensusCoordinatorRequestError::InvalidStageBound { .. })
    ));
    assert!(matches!(
        AndroidFwmarkCensusCoordinatorRequest::new(
            grant.netd_source_profile(),
            grant.candidate(),
            topology,
            MAX_ANDROID_FWMARK_CENSUS_STAGE_BOUND + Duration::from_nanos(1),
        ),
        Err(AndroidFwmarkCensusCoordinatorRequestError::InvalidStageBound { .. })
    ));
}

#[test]
fn diagnostic_brackets_the_only_inventory_in_fixed_order() {
    let (mut source, request) = source_and_request();
    let outcome = coordinate_android_fwmark_census(
        &mut source,
        &request,
        AndroidFwmarkCensusCoordinatorPurpose::Diagnostic,
    )
    .expect("coherent diagnostic collection");

    let projection = outcome.diagnostic().expect("diagnostic outcome");
    assert!(projection.is_complete());
    assert!(outcome.planning_authority().is_none());
    assert_eq!(source.events, complete_sequence());
}

#[test]
fn capability_drift_rejects_after_both_brackets_without_assembly() {
    let (mut source, request) = source_and_request();
    source.capability_after = revised_profile(&source.capability_before);

    let error = coordinate_android_fwmark_census(
        &mut source,
        &request,
        AndroidFwmarkCensusCoordinatorPurpose::PlanningAuthority,
    )
    .expect_err("capability drift must reject");
    let AndroidFwmarkCensusCoordinatorError::CapabilityDrift {
        before_revision,
        after_revision,
        before,
        after,
    } = error
    else {
        panic!("unexpected coordinator error: {error:?}");
    };
    assert_ne!(before_revision, after_revision);
    assert_ne!(before, after);
    assert_eq!(source.events, complete_sequence());
}

#[test]
fn external_drift_rejects_after_capability_revalidation() {
    let (mut source, request) = source_and_request();
    source.external_after = AndroidFwmarkCensusExternalSnapshot::new(
        source.external_after.kernel_config_digest(),
        source.external_after.xtables.clone(),
        nftables::test_absent_observation(false),
        source.external_after.traffic_control_bpf.clone(),
        source.external_after.xfrm.clone(),
    );

    let error = coordinate_android_fwmark_census(
        &mut source,
        &request,
        AndroidFwmarkCensusCoordinatorPurpose::Diagnostic,
    )
    .expect_err("external A/B drift must reject");
    let AndroidFwmarkCensusCoordinatorError::ExternalSnapshotDrift { before, after } = error else {
        panic!("unexpected coordinator error: {error:?}");
    };
    assert_ne!(before, after);
    assert_eq!(source.events, complete_sequence());
}

#[test]
fn kernel_config_drift_is_external_snapshot_drift() {
    let (mut source, request) = source_and_request();
    source.external_after = AndroidFwmarkCensusExternalSnapshot::new(
        test_kernel_config_digest(true),
        source.external_after.xtables.clone(),
        source.external_after.nftables.clone(),
        source.external_after.traffic_control_bpf.clone(),
        source.external_after.xfrm.clone(),
    );

    let error = coordinate_android_fwmark_census(
        &mut source,
        &request,
        AndroidFwmarkCensusCoordinatorPurpose::Diagnostic,
    )
    .expect_err("kernel config A/B drift must reject");
    assert!(matches!(
        error,
        AndroidFwmarkCensusCoordinatorError::ExternalSnapshotDrift { .. }
    ));
    assert_eq!(source.events, complete_sequence());
}

#[test]
fn capability_drift_precedes_simultaneous_external_drift() {
    let (mut source, request) = source_and_request();
    source.capability_after = revised_profile(&source.capability_before);
    source.external_after = AndroidFwmarkCensusExternalSnapshot::new(
        source.external_after.kernel_config_digest(),
        source.external_after.xtables.clone(),
        nftables::test_absent_observation(false),
        source.external_after.traffic_control_bpf.clone(),
        source.external_after.xfrm.clone(),
    );

    let error = coordinate_android_fwmark_census(
        &mut source,
        &request,
        AndroidFwmarkCensusCoordinatorPurpose::PlanningAuthority,
    )
    .expect_err("capability drift has deterministic precedence");
    assert!(matches!(
        error,
        AndroidFwmarkCensusCoordinatorError::CapabilityDrift { .. }
    ));
    assert_eq!(source.events, complete_sequence());
}

#[test]
fn wrong_before_snapshot_context_stops_before_native_collection() {
    let (mut source, request) = source_and_request();
    let other_candidate = FwmarkCandidate::new(0x0c00_0000, 0x0400_0000, 0x0800_0000)
        .expect("other syntactic candidate");
    let xtables = crate::android_fwmark_census::observe_android_xtables_fwmarks(
        EMPTY_XTABLES,
        EMPTY_XTABLES,
        request.netd_source_profile(),
        other_candidate,
    )
    .expect("complete alternate-context snapshot");
    source.external_before = AndroidFwmarkCensusExternalSnapshot::new(
        source.external_before.kernel_config_digest(),
        xtables,
        source.external_before.nftables.clone(),
        source.external_before.traffic_control_bpf.clone(),
        source.external_before.xfrm.clone(),
    );

    let error = coordinate_android_fwmark_census(
        &mut source,
        &request,
        AndroidFwmarkCensusCoordinatorPurpose::Diagnostic,
    )
    .expect_err("wrong observation context must reject");
    assert!(matches!(
        error,
        AndroidFwmarkCensusCoordinatorError::ExternalSnapshotContextMismatch {
            phase: AndroidFwmarkCensusExternalPhase::Before,
            ..
        }
    ));
    assert_eq!(
        source.events,
        vec![
            AndroidFwmarkCensusCollectionStage::CapabilityBefore,
            AndroidFwmarkCensusCollectionStage::ExternalBefore,
        ]
    );
}

#[test]
fn source_failure_reports_the_exact_stage_and_stops() {
    let (mut source, request) = source_and_request();
    source.fail_at = Some(AndroidFwmarkCensusCollectionStage::ExistingFluxOwnership);

    let error = coordinate_android_fwmark_census(
        &mut source,
        &request,
        AndroidFwmarkCensusCoordinatorPurpose::Diagnostic,
    )
    .expect_err("injected source failure");
    assert_eq!(
        error.collection_stage(),
        Some(AndroidFwmarkCensusCollectionStage::ExistingFluxOwnership)
    );
    assert_eq!(
        source.events,
        vec![
            AndroidFwmarkCensusCollectionStage::CapabilityBefore,
            AndroidFwmarkCensusCollectionStage::ExternalBefore,
            AndroidFwmarkCensusCollectionStage::NetworkInventory,
            AndroidFwmarkCensusCollectionStage::ExistingFluxOwnership,
        ]
    );
}

#[test]
fn planning_mode_reaches_core_only_after_complete_freshness_checks() {
    let (mut source, request) = source_and_request();
    let error = coordinate_android_fwmark_census(
        &mut source,
        &request,
        AndroidFwmarkCensusCoordinatorPurpose::PlanningAuthority,
    )
    .expect_err("policy v1 intentionally lacks ordered-writer qualification");

    let AndroidFwmarkCensusCoordinatorError::Authorization(error) = error else {
        panic!("unexpected coordinator error: {error:?}");
    };
    assert!(matches!(
        error.as_ref(),
        AndroidMarkPlanningAuthorizationError::OrderedPacketWriteQualificationRequired { .. }
    ));
    assert_eq!(source.events, complete_sequence());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FakeSourceError(AndroidFwmarkCensusCollectionStage);

impl fmt::Display for FakeSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "injected failure at {}", self.0.as_str())
    }
}

impl Error for FakeSourceError {}

struct FakeSource {
    capability_before: CapabilityProfile,
    capability_after: CapabilityProfile,
    external_before: AndroidFwmarkCensusExternalSnapshot,
    external_after: AndroidFwmarkCensusExternalSnapshot,
    inventory: Arc<NetworkInventory>,
    fail_at: Option<AndroidFwmarkCensusCollectionStage>,
    events: Vec<AndroidFwmarkCensusCollectionStage>,
}

impl FakeSource {
    fn record(&mut self, stage: AndroidFwmarkCensusCollectionStage) -> Result<(), FakeSourceError> {
        self.events.push(stage);
        if self.fail_at == Some(stage) {
            Err(FakeSourceError(stage))
        } else {
            Ok(())
        }
    }
}

impl AndroidFwmarkCensusCoordinatorSource for FakeSource {
    type Error = FakeSourceError;

    fn collect_capability_profile(
        &mut self,
        stage: AndroidFwmarkCensusCollectionStage,
    ) -> Result<CapabilityProfile, Self::Error> {
        self.record(stage)?;
        match stage {
            AndroidFwmarkCensusCollectionStage::CapabilityBefore => {
                Ok(self.capability_before.clone())
            }
            AndroidFwmarkCensusCollectionStage::CapabilityAfter => {
                Ok(self.capability_after.clone())
            }
            _ => panic!("invalid capability stage {stage:?}"),
        }
    }

    fn collect_external_snapshot(
        &mut self,
        phase: AndroidFwmarkCensusExternalPhase,
        netd_source_profile: AndroidNetdSourceProfile,
        _candidate: FwmarkCandidate,
        reviewed_policy: Option<&ReviewedPolicyCatalogEntryId>,
        bound: Duration,
    ) -> Result<AndroidFwmarkCensusExternalSnapshot, Self::Error> {
        let stage = phase.collection_stage();
        self.record(stage)?;
        assert_eq!(bound, Duration::from_secs(1));
        let snapshot = match phase {
            AndroidFwmarkCensusExternalPhase::Before => &self.external_before,
            AndroidFwmarkCensusExternalPhase::After => &self.external_after,
        };
        assert_eq!(snapshot.xtables.netd_source_profile(), netd_source_profile);
        assert_eq!(
            reviewed_policy.map(ReviewedPolicyCatalogEntryId::as_str),
            Some("samsung-sm-s9180-fzdp-observed-behavior-v1")
        );
        Ok(snapshot.clone())
    }

    fn collect_network_inventory(
        &mut self,
        bound: Duration,
    ) -> Result<Arc<NetworkInventory>, Self::Error> {
        self.record(AndroidFwmarkCensusCollectionStage::NetworkInventory)?;
        assert_eq!(bound, Duration::from_secs(1));
        Ok(Arc::clone(&self.inventory))
    }

    fn collect_existing_flux_ownership(
        &mut self,
        inventory: &NetworkInventory,
        capability_profile: &CapabilityProfile,
        network_namespace: NetworkNamespaceIdentity,
        xtables: &AndroidXtablesFwmarkObservation,
    ) -> Result<AndroidExistingFluxOwnershipObservation, Self::Error> {
        self.record(AndroidFwmarkCensusCollectionStage::ExistingFluxOwnership)?;
        assert_eq!(inventory, self.inventory.as_ref());
        Ok(existing_flux::test_clean_observation(
            inventory.snapshot_id(),
            inventory.epoch(),
            capability_profile.digest(),
            network_namespace,
            xtables.digest(),
        ))
    }
}

fn source_and_request() -> (FakeSource, AndroidFwmarkCensusCoordinatorRequest) {
    let fixture = fixture(Ipv4Addr::new(203, 0, 113, 77), true);
    let grant = fixture
        .device_policy
        .positive_grant()
        .expect("reviewed positive grant");
    let request = AndroidFwmarkCensusCoordinatorRequest::new(
        grant.netd_source_profile(),
        grant.candidate(),
        topology_request(),
        Duration::from_secs(1),
    )
    .expect("bounded coordinator request");
    let external = AndroidFwmarkCensusExternalSnapshot::new(
        test_kernel_config_digest(false),
        fixture.xtables,
        fixture.nftables,
        fixture.traffic_control_bpf,
        fixture.xfrm,
    );
    let source = FakeSource {
        capability_before: fixture.capability_profile.clone(),
        capability_after: fixture.capability_profile,
        external_before: external.clone(),
        external_after: external,
        inventory: Arc::new(fixture.inventory),
        fail_at: None,
        events: Vec::new(),
    };
    (source, request)
}

fn test_kernel_config_digest(nftables_built_in: bool) -> AndroidKernelConfigDigest {
    let bytes = if nftables_built_in {
        b"CONFIG_NF_TABLES=y\n".as_slice()
    } else {
        b"# CONFIG_NF_TABLES is not set\n".as_slice()
    };
    crate::parse_android_kernel_config(bytes)
        .expect("canonical test kernel config")
        .digest()
}

fn topology_request() -> AndroidTproxyTopologyScopeRequest {
    AndroidTproxyTopologyScopeRequest::new(
        AndroidTproxyRoutingShape::PreMarkAddressHostSet,
        [AndroidTproxyTrafficDomainRequest::residual_local_output(
            NetworkAddressFamily::Ipv4,
        )],
    )
    .expect("bounded topology request")
}

fn revised_profile(profile: &CapabilityProfile) -> CapabilityProfile {
    CapabilityProfile::new(
        CapabilityProfileRevision::new(profile.revision().get() + 1).expect("next revision"),
        profile.boot_identity().clone(),
        profile.device_identity().clone(),
        profile.kernel().clone(),
        profile.selinux().clone(),
    )
}

fn complete_sequence() -> Vec<AndroidFwmarkCensusCollectionStage> {
    vec![
        AndroidFwmarkCensusCollectionStage::CapabilityBefore,
        AndroidFwmarkCensusCollectionStage::ExternalBefore,
        AndroidFwmarkCensusCollectionStage::NetworkInventory,
        AndroidFwmarkCensusCollectionStage::ExistingFluxOwnership,
        AndroidFwmarkCensusCollectionStage::ExternalAfter,
        AndroidFwmarkCensusCollectionStage::CapabilityAfter,
    ]
}
