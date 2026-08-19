use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::sync::Arc;
use std::time::{Duration, Instant};

use flux_core::{
    AndroidMarkPlanningAuthorizationError, AndroidTproxyRoutingShape,
    AndroidTproxyTopologyScopeRequest, AndroidTproxyTrafficDomainRequest, BootIdentity,
    CapabilityProfile, CapabilityProfileRevision, FwmarkCandidate, GenerationId,
    NetworkAddressFamily, NetworkInventory, NetworkInventoryTracker, NetworkNamespaceIdentity,
    NetworkRouteRecord, NetworkRuleRecord, OwnershipJournalIdentity, OwnershipJournalRevision,
    RouteFlags, RoutePath, RoutePrefix, RouteProperties, RouteProtocol, RpdbFamilyPlacement,
    RpdbFwmarkCensusFragment, RuleAction, RuleFlags, RulePrefix, RuleProperties, RuleProtocol,
    RuleTableId,
};

use super::*;
use crate::ProcessIdentity;
use crate::android_fwmark_census::assembly::tests::fixture;
use crate::android_fwmark_census::{existing_flux, nftables};
use crate::netlink::policy_routing::ManagedPolicyRoutingIdentity;
use crate::xtables::{
    NativeCaptureOwnershipObservation, NativeCaptureRetainedOwner, NativeCaptureTargetIdentity,
    XtablesExpectedState, XtablesExpectedStatePhase, XtablesRestoreAction, XtablesRestoreContext,
    XtablesRestoreFamily, parse_xtables_restore,
};

const EMPTY_XTABLES: &[u8] = b"*mangle\n:INPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n";
const ACTIVE_OWNER_XTABLES_APPLY: &[u8] = b"*mangle\n:FLX4SP - [0:0]\n:FLX4P0000000007 - [0:0]\n-A FLX4P0000000007 -m mark --mark 0x01000000/0x03000000 -j ACCEPT\n-A FLX4SP -j FLX4P0000000007\n-I POSTROUTING -j FLX4SP\nCOMMIT\n";
const ACTIVE_OWNER_XTABLES_SAVE: &[u8] = b"*mangle\n:INPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n:FLX4SP - [0:0]\n:FLX4P0000000007 - [0:0]\n-A POSTROUTING -j FLX4SP\n-A FLX4SP -j FLX4P0000000007\n-A FLX4P0000000007 -m mark --mark 0x01000000/0x03000000 -j ACCEPT\nCOMMIT\n";

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
    assert!(outcome.planning_evidence().is_none());
    assert_eq!(source.events, complete_sequence());
}

#[test]
fn external_snapshot_clones_retain_one_kernel_config_allocation() {
    let (source, _) = source_and_request();

    assert!(Arc::ptr_eq(
        &source.external_before.kernel_config,
        &source.external_after.kernel_config,
    ));
    assert_eq!(
        source.external_before.kernel_config_digest(),
        source.external_before.kernel_config().digest(),
    );
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
fn expired_request_rejects_before_invoking_source() {
    let (mut source, request) = source_and_request();
    let request = request.with_deadline(Instant::now());

    let error = coordinate_android_fwmark_census(
        &mut source,
        &request,
        AndroidFwmarkCensusCoordinatorPurpose::Diagnostic,
    )
    .expect_err("an expired request must fail before capability collection");
    assert!(matches!(
        error,
        AndroidFwmarkCensusCoordinatorError::DeadlineExceeded {
            stage: AndroidFwmarkCensusCollectionStage::CapabilityBefore,
        }
    ));
    assert!(source.events.is_empty());
    assert!(source.observed_bounds.is_empty());
}

#[test]
fn near_future_deadline_shortens_first_duration_bound() {
    let (mut source, request) = source_and_request();
    let configured_stage_bound = Duration::from_secs(2);
    let request = AndroidFwmarkCensusCoordinatorRequest::new(
        request.netd_source_profile(),
        request.candidate(),
        request.topology_scope().clone(),
        configured_stage_bound,
    )
    .expect("bounded coordinator request")
    .with_deadline(Instant::now() + Duration::from_secs(1));
    source.fail_at = Some(AndroidFwmarkCensusCollectionStage::ExternalBefore);

    let error = coordinate_android_fwmark_census(
        &mut source,
        &request,
        AndroidFwmarkCensusCoordinatorPurpose::Diagnostic,
    )
    .expect_err("the fixture stops after observing the shortened bound");
    assert!(matches!(
        error,
        AndroidFwmarkCensusCoordinatorError::Collection {
            stage: AndroidFwmarkCensusCollectionStage::ExternalBefore,
            ..
        }
    ));
    let [(stage, observed_bound)] = source.observed_bounds.as_slice() else {
        panic!(
            "expected one observed bound, got {:?}",
            source.observed_bounds
        );
    };
    assert_eq!(*stage, AndroidFwmarkCensusCollectionStage::ExternalBefore);
    assert!(*observed_bound > Duration::ZERO);
    assert!(*observed_bound < configured_stage_bound);
    assert_eq!(
        source.events,
        vec![
            AndroidFwmarkCensusCollectionStage::CapabilityBefore,
            AndroidFwmarkCensusCollectionStage::ExternalBefore,
        ]
    );
}

#[test]
fn external_drift_rejects_after_capability_revalidation() {
    let (mut source, request) = source_and_request();
    source.external_after = AndroidFwmarkCensusExternalSnapshot::new(
        Arc::new(source.external_after.kernel_config().clone()),
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
        test_kernel_config(true),
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
        Arc::new(source.external_after.kernel_config().clone()),
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
        Arc::new(source.external_before.kernel_config().clone()),
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
    assert!(
        matches!(
            error.as_ref(),
            AndroidMarkPlanningAuthorizationError::OrderedPacketWriteQualificationRequired { .. }
        ),
        "unexpected authorization error: {error:?}"
    );
    assert_eq!(source.events, complete_sequence());
}

#[test]
fn active_owner_inventory_census_uses_owner_seams_without_filtering_raw_observations() {
    let (mut source, request) = source_and_request();
    let (inventory, active_owner, unfiltered_xtables, unfiltered_rpdb, owner_rule_index) =
        active_owner_inventory();
    let owner_xtables =
        crate::android_fwmark_census::observe_android_xtables_fwmarks_for_active_owner(
            ACTIVE_OWNER_XTABLES_SAVE,
            EMPTY_XTABLES,
            request.netd_source_profile(),
            request.candidate(),
            &active_owner,
        )
        .expect("exact active-owner xtables projection");
    let external = AndroidFwmarkCensusExternalSnapshot::new(
        test_kernel_config(false),
        owner_xtables.clone(),
        source.external_before.nftables.clone(),
        source.external_before.traffic_control_bpf.clone(),
        source.external_before.xfrm.clone(),
    );
    source.inventory = Arc::clone(&inventory);
    source.active_owner_external_before = Some(external.clone());
    source.active_owner_external_after = Some(external);

    let error = coordinate_android_fwmark_census_for_inventory_with_active_owner(
        &mut source,
        &request,
        AndroidFwmarkCensusCoordinatorPurpose::PlanningAuthority,
        Arc::clone(&inventory),
        &active_owner,
        test_engine_identity(),
    )
    .expect_err("fixture still lacks the reviewed ordered-writer qualification");
    let AndroidFwmarkCensusCoordinatorError::Authorization(error) = error else {
        panic!("unexpected active-owner coordinator error: {error:?}");
    };
    assert!(
        matches!(
            error.as_ref(),
            AndroidMarkPlanningAuthorizationError::OrderedPacketWriteQualificationRequired { .. }
        ),
        "unexpected active-owner authorization error: {error:?}"
    );
    assert_eq!(
        source.active_owner_external_phases,
        [
            AndroidFwmarkCensusExternalPhase::Before,
            AndroidFwmarkCensusExternalPhase::After,
        ]
    );
    assert_eq!(source.active_owner_existing_flux_calls, 1);
    assert_eq!(
        source.active_owner_expected_engine,
        Some(test_engine_identity())
    );
    assert_eq!(
        source.events,
        vec![
            AndroidFwmarkCensusCollectionStage::CapabilityBefore,
            AndroidFwmarkCensusCollectionStage::ExternalBefore,
            AndroidFwmarkCensusCollectionStage::ExistingFluxOwnership,
            AndroidFwmarkCensusCollectionStage::ExternalAfter,
            AndroidFwmarkCensusCollectionStage::CapabilityAfter,
        ]
    );

    assert_eq!(
        owner_xtables.table_count(),
        unfiltered_xtables.table_count()
    );
    assert_eq!(
        owner_xtables.chain_count(),
        unfiltered_xtables.chain_count()
    );
    assert_eq!(owner_xtables.rule_count(), unfiltered_xtables.rule_count());
    assert_eq!(owner_xtables.digest(), unfiltered_xtables.digest());
    assert_ne!(
        owner_xtables.legacy_mark_uses(),
        unfiltered_xtables.legacy_mark_uses(),
        "only semantic owner evidence may be removed from xtables"
    );
    assert_eq!(
        inventory.routes().len(),
        1,
        "the retained route remains in the raw RPDB inventory"
    );
    assert_eq!(
        inventory.rules().len(),
        9,
        "the retained rule remains in the raw RPDB inventory"
    );
    assert!(
        unfiltered_rpdb
            .raw_mark_uses()
            .iter()
            .any(|record| record.mask() == 0x0300_0000),
        "the complete RPDB fragment contains the retained owner's selector"
    );
    assert_eq!(
        owner_rule_index,
        inventory
            .rules()
            .iter()
            .position(|rule| rule.fwmark().is_some_and(|mark| mark.mask() == 0x0300_0000))
            .expect("owner rule remains addressable in raw inventory")
    );
}

#[test]
fn active_owner_inventory_rejects_duplicate_managed_route() {
    let (mut source, request) = source_and_request();
    let (inventory, active_owner, _, _, _) = active_owner_inventory();
    let mut routes = inventory.routes().to_vec();
    routes.push(routes[0].clone());
    let mut tracker = NetworkInventoryTracker::new();
    let duplicate_inventory = Arc::new(
        tracker
            .publish_complete_with_routing(
                inventory.links().iter().cloned(),
                inventory.addresses().iter().cloned(),
                routes,
                inventory.rules().iter().cloned(),
            )
            .expect("duplicate route inventory")
            .clone(),
    );
    source.inventory = Arc::clone(&duplicate_inventory);
    let external = source.external_before.clone();
    source.active_owner_external_before = Some(external.clone());
    source.active_owner_external_after = Some(external);

    let error = coordinate_android_fwmark_census_for_inventory_with_active_owner(
        &mut source,
        &request,
        AndroidFwmarkCensusCoordinatorPurpose::Diagnostic,
        duplicate_inventory,
        &active_owner,
        test_engine_identity(),
    )
    .expect_err("duplicate managed routing must fail closed");
    assert!(matches!(
        error,
        AndroidFwmarkCensusCoordinatorError::RetainedOwnerRoutingMismatch
    ));
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
    active_owner_external_before: Option<AndroidFwmarkCensusExternalSnapshot>,
    active_owner_external_after: Option<AndroidFwmarkCensusExternalSnapshot>,
    inventory: Arc<NetworkInventory>,
    fail_at: Option<AndroidFwmarkCensusCollectionStage>,
    events: Vec<AndroidFwmarkCensusCollectionStage>,
    observed_bounds: Vec<(AndroidFwmarkCensusCollectionStage, Duration)>,
    active_owner_external_phases: Vec<AndroidFwmarkCensusExternalPhase>,
    active_owner_existing_flux_calls: usize,
    active_owner_expected_engine: Option<ProcessIdentity>,
}

impl FakeSource {
    fn record_bound(&mut self, stage: AndroidFwmarkCensusCollectionStage, bound: Duration) {
        self.observed_bounds.push((stage, bound));
    }

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
        self.record_bound(stage, bound);
        self.record(stage)?;
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

    fn collect_external_snapshot_for_active_owner(
        &mut self,
        phase: AndroidFwmarkCensusExternalPhase,
        netd_source_profile: AndroidNetdSourceProfile,
        candidate: FwmarkCandidate,
        reviewed_policy: Option<&ReviewedPolicyCatalogEntryId>,
        _active_owner: &NativeCaptureOwnershipObservation,
        bound: Duration,
    ) -> Result<AndroidFwmarkCensusExternalSnapshot, Self::Error> {
        self.record_bound(phase.collection_stage(), bound);
        self.active_owner_external_phases.push(phase);
        self.record(phase.collection_stage())?;
        let snapshot = match phase {
            AndroidFwmarkCensusExternalPhase::Before => self
                .active_owner_external_before
                .as_ref()
                .expect("active-owner before snapshot configured"),
            AndroidFwmarkCensusExternalPhase::After => self
                .active_owner_external_after
                .as_ref()
                .expect("active-owner after snapshot configured"),
        };
        assert_eq!(snapshot.xtables.netd_source_profile(), netd_source_profile);
        assert_eq!(snapshot.xtables.candidate(), candidate);
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
        self.record_bound(AndroidFwmarkCensusCollectionStage::NetworkInventory, bound);
        self.record(AndroidFwmarkCensusCollectionStage::NetworkInventory)?;
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

    fn collect_existing_flux_ownership_for_active_owner(
        &mut self,
        inventory: &NetworkInventory,
        capability_profile: &CapabilityProfile,
        network_namespace: NetworkNamespaceIdentity,
        xtables: &AndroidXtablesFwmarkObservation,
        _active_owner: &NativeCaptureOwnershipObservation,
        expected_engine: ProcessIdentity,
    ) -> Result<AndroidExistingFluxOwnershipObservation, Self::Error> {
        self.active_owner_existing_flux_calls += 1;
        self.active_owner_expected_engine = Some(expected_engine);
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

fn test_engine_identity() -> ProcessIdentity {
    ProcessIdentity::new(
        NonZeroU32::new(50).expect("test engine PID"),
        NonZeroU64::new(500).expect("test engine start time"),
    )
}

fn active_owner_inventory() -> (
    Arc<NetworkInventory>,
    NativeCaptureOwnershipObservation,
    AndroidXtablesFwmarkObservation,
    RpdbFwmarkCensusFragment,
    usize,
) {
    let fixture = fixture(Ipv4Addr::new(203, 0, 113, 77), true);
    let grant = fixture
        .device_policy
        .positive_grant()
        .expect("reviewed positive grant");
    let placement = RpdbFamilyPlacement::proxy_only(
        flux_core::RulePriority::from_raw(30_999),
        RuleTableId::from_raw(20_253),
    )
    .expect("private test placement");
    let identity = ManagedPolicyRoutingIdentity::bind_planned_android_target(
        NetworkAddressFamily::Ipv4,
        placement,
        grant.candidate(),
        flux_core::InterfaceIndex::new(1).expect("loopback index"),
        NonZeroU32::new(1_024).expect("route metric"),
        RouteProtocol::from_raw(4),
        RuleProtocol::from_raw(99),
    );
    let route = NetworkRouteRecord::new(
        identity.route().destination(),
        RoutePrefix::unspecified(identity.family()),
        RouteProperties::new(
            0,
            identity.route().table(),
            identity.route().protocol(),
            identity.route().scope(),
            identity.route().route_type(),
            RouteFlags::from_raw(0),
        ),
        identity.route().metric().get(),
        RoutePath::Single {
            output_interface: Some(identity.route().output_interface()),
            gateway: None,
        },
    )
    .expect("exact managed route record");
    let rule = NetworkRuleRecord::new(
        RulePrefix::unspecified(identity.family()),
        RulePrefix::unspecified(identity.family()),
        RuleProperties::new(
            0,
            RuleTableId::from_raw(identity.rule().table().get()),
            RuleAction::TO_TABLE,
            identity.rule().protocol(),
            RuleFlags::from_raw(0),
        ),
        identity.rule().priority(),
        None,
    )
    .expect("exact managed rule shape")
    .with_fwmark(identity.rule().mark());
    let mut rules = fixture.inventory.rules().to_vec();
    let owner_rule_index = rules
        .iter()
        .position(|candidate| candidate.priority() > identity.rule().priority())
        .expect("owner rule belongs before Android default-network rule");
    rules.insert(owner_rule_index, rule);
    let mut tracker = NetworkInventoryTracker::new();
    let inventory = Arc::new(
        tracker
            .publish_complete_with_routing(
                fixture.inventory.links().iter().cloned(),
                fixture.inventory.addresses().iter().cloned(),
                [route],
                rules,
            )
            .expect("inventory with exact active-owner routing")
            .clone(),
    );
    let unfiltered_xtables = crate::android_fwmark_census::observe_android_xtables_fwmarks(
        ACTIVE_OWNER_XTABLES_SAVE,
        EMPTY_XTABLES,
        grant.netd_source_profile(),
        grant.candidate(),
    )
    .expect("complete unfiltered xtables projection");
    let unfiltered_rpdb = flux_core::project_rpdb_fwmark_census_fragment(&inventory)
        .expect("complete unfiltered RPDB projection");
    let artifact = parse_xtables_restore(
        ACTIVE_OWNER_XTABLES_APPLY,
        XtablesRestoreContext::new(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4),
    )
    .expect("active-owner apply artifact");
    let expected_state = XtablesExpectedState::from_apply_artifacts(
        XtablesRestoreFamily::Ipv4,
        XtablesExpectedStatePhase::Active,
        [&artifact],
    )
    .expect("active-owner expected xtables state");
    let target =
        NativeCaptureTargetIdentity::new(GenerationId::INITIAL, [0x21; 32], [0x22; 32], [0x23; 32]);
    let active_owner = NativeCaptureOwnershipObservation::new(
        target,
        BootIdentity::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").expect("test boot identity"),
        fixture.network_namespace,
        OwnershipJournalIdentity::new([0x24; 32]).expect("test journal identity"),
        OwnershipJournalRevision::INITIAL,
        NonZeroU16::new(1).expect("test journal schema"),
        7,
        NonZeroU64::new(8).expect("test journal inode"),
        [0x25; 32],
        NativeCaptureRetainedOwner::new(target, Some(expected_state), None, [identity]),
    );
    (
        inventory,
        active_owner,
        unfiltered_xtables,
        unfiltered_rpdb,
        owner_rule_index,
    )
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
        test_kernel_config(false),
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
        active_owner_external_before: None,
        active_owner_external_after: None,
        inventory: Arc::new(fixture.inventory),
        fail_at: None,
        events: Vec::new(),
        observed_bounds: Vec::new(),
        active_owner_external_phases: Vec::new(),
        active_owner_existing_flux_calls: 0,
        active_owner_expected_engine: None,
    };
    (source, request)
}

fn test_kernel_config(nftables_built_in: bool) -> Arc<AndroidKernelConfigSnapshot> {
    let bytes = if nftables_built_in {
        b"CONFIG_NF_TABLES=y\n".as_slice()
    } else {
        b"# CONFIG_NF_TABLES is not set\n".as_slice()
    };
    Arc::new(crate::parse_android_kernel_config(bytes).expect("canonical test kernel config"))
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
