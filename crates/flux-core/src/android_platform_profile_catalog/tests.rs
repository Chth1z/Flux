use super::*;
#[cfg(flux_android_qualification)]
use crate::android_mark_authority::FwmarkOrderedLateWriteQualification;
use crate::android_mark_authority::{AndroidMarkDeviceGrantKind, FwmarkPlaneSet};
use crate::android_netd::AndroidNetdSourceProfile;
use crate::android_rpdb::{
    ReviewedCanaryRpdbClassificationError, ReviewedCanaryRpdbPlacementError, classify_android_rpdb,
    classify_android_rpdb_with_reviewed_canary_facility,
    plan_android_rpdb_placement_with_reviewed_canary_facility,
};
use crate::android_tproxy_topology::{
    AndroidTproxyRoutingShape, AndroidTproxyTopologyScopeRequest,
    AndroidTproxyTrafficDomainRequest, assess_android_tproxy_topology_scope,
};
use crate::canary_facility_policy::ReviewedCanaryFacilitySelection;
use crate::capability::{
    BootIdentity, CapabilityProfileRevision, DeviceIdentity, KernelFacts, KernelRelease,
    Observation, SelinuxMode, ToolId, VerifiedBootIdentity, VerifiedBootState,
};
use crate::capture_path::{CapturePathId, CapturePathQualificationState};
use crate::fwmark_audit::audit_fwmark_candidate_partial;
use crate::fwmark_census::{
    project_rpdb_fwmark_census_fragment, project_rpdb_fwmark_census_fragment_with_classification,
};
use crate::network_inventory::{
    InterfaceHardwareType, InterfaceIndex, InterfaceLinkFlags, InterfaceLinkRecord, InterfaceName,
    NetworkInventory, NetworkInventoryTracker,
};
use crate::network_route::NetworkAddressFamily;
use crate::network_rule::{
    NetworkRuleRecord, RuleAction, RuleFlags, RuleFwMark, RuleIpProtocol, RulePortRange,
    RulePrefix, RulePriority, RuleProperties, RuleProtocol, RuleTableId, RuleUidRange,
};
use crate::rpdb_placement::{RpdbFamilyPlacement, RpdbPlacementRequest};
use sha2::{Digest, Sha256};

const NET_ID_MASK: u32 = 0x0000_ffff;
const EXPLICIT_NETWORK: u32 = 0x0001_0000;
const NETWORK_PERMISSION: u32 = 0x0004_0000;
const SYSTEM_PERMISSION: u32 = 0x000c_0000;
const CANDIDATE_MASK: u32 = 0x0300_0000;
const PROXY_VALUE: u32 = 0x0100_0000;
const BYPASS_VALUE: u32 = 0x0200_0000;

const SELECTOR: ReviewedPolicySelectorLiteral = ReviewedPolicySelectorLiteral {
    android_product: "google/redfin/redfin",
    android_build: "google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys",
    vendor_build: "google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys",
    security_patch: "2023-08-05",
    kernel_build: "5.10.198-android13-gki synthetic-build",
    selinux_policy: artifact_literal(0x21, 4_096),
    netd: artifact_literal(0x22, 8_192),
    connectivity: artifact_literal(0x23, 16_384),
};
const MARK_POLICY: ReviewedAndroidMarkPolicyLiteral = ReviewedAndroidMarkPolicyLiteral {
    assurance_class: AndroidMarkPolicyAssuranceClass::AuthenticatedSource,
    name: "synthetic cooperative policy",
    revision: 1,
    artifact_digest: [0x31; 32],
    netd_source_profile: AndroidNetdSourceProfile::AospAndroid13R1,
    candidate_mask: CANDIDATE_MASK,
    proxy_value: PROXY_VALUE,
    bypass_value: BYPASS_VALUE,
    planes: FwmarkPlaneSet::ALL.bits(),
    ordered_late_writes: &[],
    ordered_late_write_alternatives: &[],
    exact_mark_sentinels: &[],
};
const CAPTURE_PATH_EVIDENCE: ReviewedCapturePathEvidenceLiteral =
    ReviewedCapturePathEvidenceLiteral {
        revision: 7,
        artifact_digest: [0x41; 32],
        qualifications: CapturePathQualifications::new(
            CapturePathQualificationState::Unqualified,
            CapturePathQualificationState::Qualified,
            CapturePathQualificationState::Unqualified,
        ),
    };
const CANARY_ADDRESSES: &[ReviewedCanaryFacilityAddressLiteral] =
    &[ReviewedCanaryFacilityAddressLiteral {
        daemon_ipv4: std::net::Ipv4Addr::new(8, 8, 8, 7),
        peer_ipv4: std::net::Ipv4Addr::new(8, 8, 8, 8),
        daemon_ipv6: Some(std::net::Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1110,
        )),
        peer_ipv6: Some(std::net::Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
        )),
    }];
const CANARY_PORTS: &[ReviewedCanaryResponderPortsLiteral] =
    &[ReviewedCanaryResponderPortsLiteral {
        tcp_echo: 41_001,
        udp_echo: 41_002,
        dns: 41_003,
    }];
const CANARY_FACILITY_POLICY: ReviewedCanaryFacilityPolicyLiteral =
    ReviewedCanaryFacilityPolicyLiteral {
        revision: 1,
        artifact_digest: [0x51; 32],
        daemon_veth_name: "fxcan0",
        peer_veth_name: "fxcanp",
        probe_uid: 20_001,
        probe_gid: 20_001,
        engine_uid: 20_002,
        engine_gid: 20_002,
        addresses: CANARY_ADDRESSES,
        ports: CANARY_PORTS,
        netd_source_profile: AndroidNetdSourceProfile::AospAndroid13R1,
        early_uid_lookup_priorities: &[],
        proxy_rule_priority: 30_997,
        peer_rule_priority: 30_998,
        proxy_capture_table: 20_253,
        peer_table: 20_254,
        peer_return_table: 254,
        rule_protocol: 186,
        route_protocol: 186,
        route_metric: 1_031,
        proxy_mark_value: PROXY_VALUE,
        proxy_mark_mask: CANDIDATE_MASK,
    };
const ENTRY: ReviewedAndroidPlatformProfileCatalogEntry =
    ReviewedAndroidPlatformProfileCatalogEntry {
        id: "google-redfin-tq3a-20230805-v1",
        selector: SELECTOR,
        mark_policy: Some(MARK_POLICY),
        capture_path: Some(CAPTURE_PATH_EVIDENCE),
        canary_facility: Some(CANARY_FACILITY_POLICY),
    };

#[test]
fn unmatched_production_selector_returns_explicit_zero_grants() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let topology = topology_scope();

    let selection = select_reviewed_android_platform_profile(&profile, namespace)
        .expect("compiled platform catalog is valid");

    assert!(!selection.is_match());
    assert!(selection.catalog_entry().is_none());
    assert!(selection.netd_source_profile().is_none());
    assert!(!selection.has_reviewed_capture_path_evidence());
    let bound = selection
        .bind_topology(&topology)
        .expect("zero grant binds without positive topology authority");
    assert!(bound.canary_facility_policy().is_none());
    let (policy, capture_path) = bound.into_parts();
    assert_eq!(policy.grant_kind(), AndroidMarkDeviceGrantKind::NoGrant);
    assert_eq!(
        capture_path.qualifications(),
        CapturePathQualifications::default()
    );
    assert!(capture_path.reviewed_identity().is_none());
    assert_eq!(capture_path.capability_profile_digest(), profile.digest());
    assert_eq!(capture_path.network_namespace(), namespace);
}

#[test]
fn exact_entry_selects_positive_policy_and_retains_catalog_provenance() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let topology = topology_scope();

    let selection = select_from_catalog(&[ENTRY], &profile, namespace).expect("exact match");

    assert!(selection.is_match());
    assert!(selection.has_reviewed_capture_path_evidence());
    assert!(selection.canary_facility_policy().is_some());
    assert_eq!(
        selection.netd_source_profile(),
        Some(AndroidNetdSourceProfile::AospAndroid13R1)
    );
    assert_eq!(
        selection
            .catalog_entry()
            .map(ReviewedPolicyCatalogEntryId::as_str),
        Some("google-redfin-tq3a-20230805-v1")
    );
    let projected_capture_path = selection.capture_path_evidence();
    let bound = selection
        .bind_topology(&topology)
        .expect("selected profile binds matching topology");
    let canary = bound
        .canary_facility_policy()
        .expect("exact entry carries reviewed canary facility policy");
    assert_eq!(canary.credentials().engine_uid().get(), 20_002);
    assert_eq!(canary.rpdb().proxy_rule_priority().get(), 30_997);
    assert_eq!(canary.rpdb().peer_rule_priority().get(), 30_998);
    let (policy, capture_path) = bound.into_parts();
    let grant = policy.positive_grant().expect("matched positive policy");

    assert_eq!(policy.grant_kind(), AndroidMarkDeviceGrantKind::Positive);
    assert_eq!(policy.revision().get(), 1);
    assert_eq!(grant.candidate().mask(), CANDIDATE_MASK);
    assert_eq!(
        grant.netd_source_profile(),
        AndroidNetdSourceProfile::AospAndroid13R1
    );
    assert_eq!(grant.planes(), FwmarkPlaneSet::ALL);
    assert_eq!(
        grant.assurance_class(),
        AndroidMarkPolicyAssuranceClass::AuthenticatedSource
    );
    assert_eq!(grant.capability_profile(), &profile);
    assert_eq!(grant.network_namespace(), namespace);
    assert_eq!(
        policy
            .identity()
            .artifact_digest()
            .expect("policy artifact")
            .as_bytes(),
        &[0x31; 32]
    );
    assert_eq!(
        capture_path
            .qualifications()
            .state(CapturePathId::XtablesTproxy),
        CapturePathQualificationState::Qualified
    );
    let reviewed = capture_path
        .reviewed_identity()
        .expect("synthetic profile includes reviewed Capture Path evidence");
    assert_eq!(
        reviewed.catalog_entry().as_str(),
        "google-redfin-tq3a-20230805-v1"
    );
    assert_eq!(reviewed.revision().get(), 7);
    assert_eq!(reviewed.artifact_digest().as_bytes(), &[0x41; 32]);
    assert_eq!(projected_capture_path, capture_path);
}

#[test]
fn reviewed_canary_rule_cohort_is_the_only_non_android_classification_exception() {
    let (policy, selection) = synthetic_reviewed_canary_policy();
    assert!(
        policy
            .bind_live_selection(
                std::net::Ipv4Addr::new(8, 8, 4, 4),
                None,
                std::num::NonZeroU16::new(41_001).expect("TCP port"),
                std::num::NonZeroU16::new(41_002).expect("UDP port"),
                std::num::NonZeroU16::new(41_003).expect("DNS port"),
            )
            .is_err()
    );

    let mut rules =
        android_13_rules_for_families([NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6]);
    rules.extend(reviewed_canary_rules(&policy, selection));
    rules.sort_by_key(NetworkRuleRecord::priority);
    let inventory = inventory_with_rules(rules.clone());
    let classification = classify_android_rpdb_with_reviewed_canary_facility(
        &inventory,
        AndroidNetdSourceProfile::AospNetd20250324,
        &policy,
        selection,
    )
    .expect("complete exact cohort is reviewed");
    assert_eq!(classification.unknown_rule_count(), 0);
    let candidate = FwmarkCandidate::new(CANDIDATE_MASK, PROXY_VALUE, BYPASS_VALUE)
        .expect("reviewed candidate");
    let generic_partial = audit_fwmark_candidate_partial(&inventory, candidate);
    assert_eq!(generic_partial.conflicts().len(), 8);
    let reviewed_partial = crate::fwmark_audit::audit_fwmark_candidate_partial_with_classification(
        &inventory,
        &classification,
        candidate,
    );
    assert!(reviewed_partial.conflicts().is_empty());
    assert_eq!(
        reviewed_partial
            .excluded_reviewed_canary_rule_indices()
            .len(),
        8
    );
    let generic_rpdb =
        project_rpdb_fwmark_census_fragment(&inventory).expect("generic RPDB mark-use projection");
    let reviewed_rpdb =
        project_rpdb_fwmark_census_fragment_with_classification(&inventory, &classification)
            .expect("reviewed RPDB mark-use projection");
    assert_eq!(
        generic_rpdb.raw_mark_uses().len(),
        reviewed_rpdb.raw_mark_uses().len() + 16
    );
    let placement = RpdbFamilyPlacement::proxy_only(
        policy.rpdb().proxy_rule_priority(),
        RuleTableId::from_raw(policy.rpdb().proxy_capture_table().get()),
    )
    .expect("reviewed proxy placement");
    plan_android_rpdb_placement_with_reviewed_canary_facility(
        &inventory,
        &classification,
        RpdbPlacementRequest::new(Some(placement), Some(placement)).expect("dual-stack placement"),
        &policy,
        selection,
    )
    .expect("reviewed proxy and peer slots coexist before Android default network");
    let topology_request = AndroidTproxyTopologyScopeRequest::new(
        AndroidTproxyRoutingShape::PreMarkAddressHostSet,
        [
            AndroidTproxyTrafficDomainRequest::residual_local_output(NetworkAddressFamily::Ipv4),
            AndroidTproxyTrafficDomainRequest::residual_local_output(NetworkAddressFamily::Ipv6),
        ],
    )
    .expect("dual-stack topology request");
    let topology =
        assess_android_tproxy_topology_scope(&inventory, &classification, &topology_request)
            .expect("reviewed peer cohort remains complete topology evidence");
    assert_eq!(
        topology.structural_feasibility(),
        crate::AndroidTproxyTopologyScopeStructuralFeasibility::AllMatchedAnchorsHaveResidualCandidateWindows {
            anchor_count: 2,
        }
    );
    assert_eq!(
        topology
            .entries()
            .iter()
            .flat_map(|entry| entry.report().dispositions())
            .filter(|disposition| {
                **disposition == crate::AndroidTproxyRuleDisposition::ReviewedCanaryFacility
            })
            .count(),
        8
    );

    let generic_report =
        classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospNetd20250324);
    let generic_topology =
        assess_android_tproxy_topology_scope(&inventory, &generic_report, &topology_request)
            .expect("generic classifier still finds both Android anchors");
    assert_eq!(
        generic_topology.structural_feasibility(),
        crate::AndroidTproxyTopologyScopeStructuralFeasibility::IncompleteEvidence {
            incomplete_anchor_count: 2,
        },
        "only the exact reviewed classifier may complete the peer-cohort topology"
    );
    let generic_partial_via_classification =
        crate::fwmark_audit::audit_fwmark_candidate_partial_with_classification(
            &inventory,
            &generic_report,
            candidate,
        );
    assert_eq!(generic_partial_via_classification, generic_partial);
    assert_eq!(
        project_rpdb_fwmark_census_fragment_with_classification(&inventory, &generic_report)
            .expect("generic classification does not exempt RPDB uses"),
        generic_rpdb
    );
    assert_eq!(
        plan_android_rpdb_placement_with_reviewed_canary_facility(
            &inventory,
            &generic_report,
            RpdbPlacementRequest::new(Some(placement), Some(placement))
                .expect("dual-stack placement"),
            &policy,
            selection,
        ),
        Err(ReviewedCanaryRpdbPlacementError::ClassificationReportMismatch)
    );
    let wrong_placement = RpdbFamilyPlacement::proxy_only(
        RulePriority::from_raw(policy.rpdb().proxy_rule_priority().get() - 1),
        RuleTableId::from_raw(policy.rpdb().proxy_capture_table().get()),
    )
    .expect("structurally valid wrong placement");
    assert_eq!(
        plan_android_rpdb_placement_with_reviewed_canary_facility(
            &inventory,
            &classification,
            RpdbPlacementRequest::new(Some(wrong_placement), None).expect("IPv4 placement"),
            &policy,
            selection,
        ),
        Err(ReviewedCanaryRpdbPlacementError::PlacementRequestMismatch)
    );

    let missing_peer_index = rules
        .iter()
        .position(|rule| rule.priority() == policy.rpdb().peer_rule_priority())
        .expect("reviewed peer rule is present");
    rules.remove(missing_peer_index);
    assert_reviewed_canary_cohort_rejected(&policy, selection, rules);

    let cohort = reviewed_canary_rules(&policy, selection);
    let mut duplicate =
        android_13_rules_for_families([NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6]);
    duplicate.extend(cohort.iter().cloned());
    duplicate.push(cohort[0].clone());
    assert_reviewed_canary_cohort_rejected(&policy, selection, duplicate);

    for altered in [
        cohort[0]
            .clone()
            .with_uid_range(RuleUidRange::new(20_003, 20_003).expect("altered engine UID range")),
        cohort[0].clone().with_fwmark(
            RuleFwMark::new(0x0100_0000, policy.rpdb().proxy_mark_mask().get())
                .expect("altered proxy mark"),
        ),
        cohort[0].clone().with_destination_port_range(
            RulePortRange::new(41_004, 41_004).expect("altered responder port"),
        ),
        rebuild_canary_rule(
            &cohort[0],
            RulePriority::from_raw(policy.rpdb().peer_rule_priority().get() - 1),
            RuleTableId::from_raw(policy.rpdb().peer_table().get()),
        ),
        rebuild_canary_rule(
            &cohort[0],
            policy.rpdb().peer_rule_priority(),
            RuleTableId::from_raw(policy.rpdb().peer_table().get() - 1),
        ),
    ] {
        let mut altered_cohort = cohort.clone();
        altered_cohort[0] = altered;
        let mut altered_rules =
            android_13_rules_for_families([NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6]);
        altered_rules.extend(altered_cohort);
        assert_reviewed_canary_cohort_rejected(&policy, selection, altered_rules);
    }
}

#[test]
fn unrelated_unknown_ipv4_rules_keep_reviewed_dual_stack_topology_incomplete() {
    let (policy, selection) = synthetic_reviewed_canary_policy();
    let mut rules =
        android_13_rules_for_families([NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6]);
    rules.extend(reviewed_canary_rules(&policy, selection));
    rules.extend(reviewed_vendor_early_uid_lookup_rules());
    rules.sort_by_key(NetworkRuleRecord::priority);
    let inventory = inventory_with_rules(rules);
    let classification = classify_android_rpdb_with_reviewed_canary_facility(
        &inventory,
        AndroidNetdSourceProfile::AospNetd20250324,
        &policy,
        selection,
    )
    .expect("unrelated rules do not substitute the exact reviewed cohort");

    assert_eq!(classification.unknown_rule_count(), 2);
    let topology_request = AndroidTproxyTopologyScopeRequest::new(
        AndroidTproxyRoutingShape::PreMarkAddressHostSet,
        [
            AndroidTproxyTrafficDomainRequest::residual_local_output(NetworkAddressFamily::Ipv4),
            AndroidTproxyTrafficDomainRequest::residual_local_output(NetworkAddressFamily::Ipv6),
        ],
    )
    .expect("dual-stack topology request");
    let topology =
        assess_android_tproxy_topology_scope(&inventory, &classification, &topology_request)
            .expect("both reviewed Android anchors remain present");

    assert_eq!(
        topology.structural_feasibility(),
        crate::AndroidTproxyTopologyScopeStructuralFeasibility::IncompleteEvidence {
            incomplete_anchor_count: 1,
        },
        "unreviewed IPv4 rules must keep only the IPv4 anchor fail-closed"
    );
    let ipv4 = topology
        .entries()
        .iter()
        .find(|entry| entry.domain().family() == NetworkAddressFamily::Ipv4)
        .expect("IPv4 topology entry");
    let ipv6 = topology
        .entries()
        .iter()
        .find(|entry| entry.domain().family() == NetworkAddressFamily::Ipv6)
        .expect("IPv6 topology entry");
    assert_eq!(ipv4.report().unknown_rule_count(), 2);
    assert_eq!(ipv6.report().unknown_rule_count(), 0);
    assert_eq!(
        topology
            .entries()
            .iter()
            .flat_map(|entry| entry.report().dispositions())
            .filter(|disposition| {
                **disposition == crate::AndroidTproxyRuleDisposition::ReviewedCanaryFacility
            })
            .count(),
        8,
        "unknown vendor rules must not erase or widen the exact reviewed cohort"
    );
}

#[test]
fn reviewed_device_policy_admits_only_its_exact_early_uid_lookup_cohort() {
    let (policy, selection) = synthetic_reviewed_canary_policy_with_early_lookups([1, 2]);
    let mut rules =
        android_13_rules_for_families([NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6]);
    rules.extend(reviewed_canary_rules(&policy, selection));
    rules.extend(reviewed_vendor_early_uid_lookup_rules());
    rules.sort_by_key(NetworkRuleRecord::priority);
    let inventory = inventory_with_rules(rules.clone());
    let classification = classify_android_rpdb_with_reviewed_canary_facility(
        &inventory,
        AndroidNetdSourceProfile::AospNetd20250324,
        &policy,
        selection,
    )
    .expect("exact reviewed early UID lookup cohort");

    assert_eq!(classification.unknown_rule_count(), 0);
    assert_eq!(
        classification
            .roles()
            .iter()
            .filter(|role| **role == Some(crate::AndroidRpdbRuleRole::ReviewedEarlyUidLookup))
            .count(),
        2
    );
    let topology_request = AndroidTproxyTopologyScopeRequest::new(
        AndroidTproxyRoutingShape::PreMarkAddressHostSet,
        [
            AndroidTproxyTrafficDomainRequest::residual_local_output(NetworkAddressFamily::Ipv4),
            AndroidTproxyTrafficDomainRequest::residual_local_output(NetworkAddressFamily::Ipv6),
        ],
    )
    .expect("dual-stack topology request");
    let topology =
        assess_android_tproxy_topology_scope(&inventory, &classification, &topology_request)
            .expect("reviewed vendor cohort retains both Android anchors");
    assert_eq!(
        topology.structural_feasibility(),
        crate::AndroidTproxyTopologyScopeStructuralFeasibility::AllMatchedAnchorsHaveResidualCandidateWindows {
            anchor_count: 2,
        }
    );

    let generic = classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospNetd20250324);
    assert_eq!(generic.unknown_rule_count(), 10);

    let missing_priority_two = rules
        .iter()
        .filter(|rule| rule.priority().get() != 2)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        classify_android_rpdb_with_reviewed_canary_facility(
            &inventory_with_rules(missing_priority_two),
            AndroidNetdSourceProfile::AospNetd20250324,
            &policy,
            selection,
        ),
        Err(ReviewedCanaryRpdbClassificationError::EarlyUidLookupCohortMismatch)
    );

    let priority_one = rules
        .iter()
        .position(|rule| rule.priority().get() == 1)
        .expect("priority-one vendor rule");
    rules[priority_one] = RuleSpec::netd(1, 1_001, RuleAction::TO_TABLE).build();
    assert_eq!(
        classify_android_rpdb_with_reviewed_canary_facility(
            &inventory_with_rules(rules),
            AndroidNetdSourceProfile::AospNetd20250324,
            &policy,
            selection,
        ),
        Err(ReviewedCanaryRpdbClassificationError::EarlyUidLookupCohortMismatch)
    );
}

#[test]
fn exact_production_samsung_selector_grants_marks_but_not_capture_path_behavior() {
    let namespace = namespace(20, 234_673);
    let selector = SAMSUNG_SM_S9180_FZDP_PLATFORM_PROFILE_V1.selector;
    let profile = capability_profile_for_selector(namespace, 0x71, selector);
    let selection = select_reviewed_android_platform_profile(&profile, namespace)
        .expect("exact reviewed Samsung platform selector");

    assert_eq!(
        selection.assurance_class(),
        Some(AndroidMarkPolicyAssuranceClass::ExactArtifactObservedBehavior)
    );
    assert_eq!(
        selection
            .catalog_entry()
            .map(ReviewedPolicyCatalogEntryId::as_str),
        Some("samsung-sm-s9180-fzdp-observed-behavior-v1")
    );
    assert_eq!(
        selection.netd_source_profile(),
        Some(AndroidNetdSourceProfile::AospNetd20250324),
        "the source-named profile is a semantic grammar under observed-behavior assurance"
    );
    assert!(!selection.has_reviewed_capture_path_evidence());

    let bound = selection
        .bind_topology(&topology_scope_for(
            AndroidNetdSourceProfile::AospNetd20250324,
        ))
        .expect("matching reviewed semantic topology");
    let (policy, capture_path) = bound.into_parts();
    let grant = policy.positive_grant().expect("exact positive assertion");
    assert_eq!(
        grant.assurance_class(),
        AndroidMarkPolicyAssuranceClass::ExactArtifactObservedBehavior
    );
    assert!(grant.ordered_late_writes().is_empty());
    assert_eq!(
        capture_path.qualifications(),
        CapturePathQualifications::default()
    );
    assert!(capture_path.reviewed_identity().is_none());
}

#[cfg(not(flux_android_qualification))]
#[test]
fn qualification_selector_is_absent_from_every_ordinary_catalog_build() {
    let namespace = namespace(20, 234_674);
    let profile = capability_profile_for_selector(
        namespace,
        0x72,
        SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELECTOR,
    );
    let selection = select_reviewed_android_platform_profile(&profile, namespace)
        .expect("unmatched qualification selector returns zero grants");

    assert!(!selection.is_match());
    assert!(selection.canary_facility_policy().is_none());
    assert!(!selection.has_reviewed_capture_path_evidence());
}

#[cfg(flux_android_qualification)]
#[test]
fn qualification_cfg_selects_only_the_exact_nonshipping_profile() {
    let namespace = namespace(20, 234_674);
    let profile = capability_profile_for_selector(
        namespace,
        0x72,
        SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELECTOR,
    );
    let selection = select_reviewed_android_platform_profile(&profile, namespace)
        .expect("exact non-shipping qualification selector");

    assert_eq!(
        selection
            .catalog_entry()
            .map(ReviewedPolicyCatalogEntryId::as_str),
        Some("samsung-sm-s9180-fzdp-qkernel-20260722-qualification-v1")
    );
    assert!(selection.has_reviewed_capture_path_evidence());
    assert!(selection.canary_facility_policy().is_some());
    let facility = selection
        .canary_facility_policy()
        .expect("qualification facility policy");
    assert_eq!(facility.revision().get(), 3);
    assert!(facility.early_uid_lookup_priorities().is_empty());
    assert_eq!(
        selection.mark_candidate(),
        Some(
            FwmarkCandidate::new(0x0c00_0000, 0x0400_0000, 0x0800_0000)
                .expect("qualification candidate"),
        )
    );
    let bound = selection
        .bind_topology(&topology_scope_for(
            AndroidNetdSourceProfile::AospNetd20250324,
        ))
        .expect("qualification topology binding");
    let grant = bound
        .mark_policy()
        .positive_grant()
        .expect("qualification mark grant");
    assert_eq!(bound.mark_policy().revision().get(), 4);
    assert_eq!(grant.ordered_late_writes().len(), 10);
    assert_eq!(grant.ordered_late_write_alternatives().len(), 1);
    assert_eq!(grant.ordered_late_write_alternatives()[0].len(), 12);
    assert_eq!(
        qualification_ordered_write_projection_digest(grant.ordered_late_writes()),
        [
            0xd0, 0x61, 0x2c, 0xb2, 0x9f, 0x59, 0x62, 0x75, 0xf9, 0x42, 0x10, 0xd7, 0x7a, 0x9d,
            0x6a, 0x0b, 0x6a, 0xa4, 0x44, 0x4b, 0x85, 0xca, 0x26, 0xc3, 0xca, 0x56, 0x42, 0x07,
            0x30, 0x0e, 0xec, 0xfd,
        ]
    );
    assert_eq!(
        qualification_ordered_write_projection_digest(&grant.ordered_late_write_alternatives()[0]),
        [
            0x17, 0x91, 0x2f, 0xee, 0x01, 0x26, 0xde, 0x69, 0xa0, 0x62, 0x5d, 0x7b, 0x00, 0xf4,
            0x36, 0x01, 0x99, 0x99, 0xab, 0xd2, 0xf2, 0x45, 0x46, 0xf9, 0x03, 0x40, 0xc0, 0xa9,
            0x26, 0x97, 0xbd, 0xd5,
        ]
    );
    assert_eq!(grant.exact_mark_sentinels().len(), 2);
}

#[cfg(flux_android_qualification)]
fn qualification_ordered_write_projection_digest(
    records: &[FwmarkOrderedLateWriteQualification],
) -> [u8; 32] {
    let mut live_projection = format!("ordered_count={}\n", records.len());
    for record in records {
        use std::fmt::Write as _;
        let selector = record
            .selector_digest()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        writeln!(
            live_projection,
            "source={:?} plane={:?} operation={:?} mask=0x{:08x} family={:?} hook={:?} chain={} hook_ordinal={} rule_ordinal={} placement={:?} selector={selector}",
            record.mark_use().source(),
            record.mark_use().plane(),
            record.mark_use().operation(),
            record.mark_use().mask(),
            record.family(),
            record.hook(),
            record.child_chain().as_str(),
            record.hook_ordinal(),
            record.rule_ordinal(),
            record.placement(),
        )
        .expect("write in-memory qualification projection");
    }
    Sha256::digest(live_projection.trim_end()).into()
}

#[cfg(flux_android_qualification)]
#[test]
fn qualification_policy_keeps_retired_early_uid_rules_unknown() {
    let namespace = namespace(20, 234_674);
    let profile = capability_profile_for_selector(
        namespace,
        0x72,
        SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELECTOR,
    );
    let selection = select_reviewed_android_platform_profile(&profile, namespace)
        .expect("exact non-shipping qualification selector");
    let policy = selection
        .canary_facility_policy()
        .expect("qualification facility policy");
    let live_selection = policy
        .bind_live_selection(
            std::net::Ipv4Addr::new(9, 254, 254, 253),
            Some(std::net::Ipv6Addr::new(
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0xf111,
            )),
            std::num::NonZeroU16::new(41_801).expect("TCP port"),
            std::num::NonZeroU16::new(41_802).expect("UDP port"),
            std::num::NonZeroU16::new(41_803).expect("DNS port"),
        )
        .expect("reviewed live selection");
    let mut rules =
        android_13_rules_for_families([NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6]);
    rules.extend(reviewed_canary_rules(policy, live_selection));
    rules.extend(reviewed_vendor_early_uid_lookup_rules());
    rules.sort_by_key(NetworkRuleRecord::priority);
    let inventory = inventory_with_rules(rules);
    let classification = classify_android_rpdb_with_reviewed_canary_facility(
        &inventory,
        AndroidNetdSourceProfile::AospNetd20250324,
        policy,
        live_selection,
    )
    .expect("retired early UID rules remain ordinary unknowns");

    assert_eq!(classification.unknown_rule_count(), 2);
    assert_eq!(
        classification
            .roles()
            .iter()
            .filter(|role| **role == Some(crate::AndroidRpdbRuleRole::ReviewedEarlyUidLookup))
            .count(),
        0
    );
    let topology_request = AndroidTproxyTopologyScopeRequest::new(
        AndroidTproxyRoutingShape::PreMarkAddressHostSet,
        [
            AndroidTproxyTrafficDomainRequest::residual_local_output(NetworkAddressFamily::Ipv4),
            AndroidTproxyTrafficDomainRequest::residual_local_output(NetworkAddressFamily::Ipv6),
        ],
    )
    .expect("dual-stack topology request");
    let topology =
        assess_android_tproxy_topology_scope(&inventory, &classification, &topology_request)
            .expect("unknown retired rules remain topology evidence");
    assert_eq!(
        topology.structural_feasibility(),
        crate::AndroidTproxyTopologyScopeStructuralFeasibility::IncompleteEvidence {
            incomplete_anchor_count: 1,
        }
    );
}

#[cfg(flux_android_qualification)]
#[test]
fn qualification_diagnostic_reports_only_drifting_selector_field_names() {
    let namespace = namespace(20, 234_674);
    let exact = capability_profile_for_selector(
        namespace,
        0x72,
        SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELECTOR,
    );
    assert!(qualification_selector_mismatch_fields(&exact).is_empty());

    let changed = capability_profile_for_selector(
        namespace,
        0x72,
        ReviewedPolicySelectorLiteral {
            kernel_build: "5.15.211-Qkernel changed-build",
            ..SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELECTOR
        },
    );
    assert_eq!(
        qualification_selector_mismatch_fields(&changed),
        vec!["kernel_build"]
    );

    let changed = capability_profile_for_selector(
        namespace,
        0x72,
        ReviewedPolicySelectorLiteral {
            selinux_policy: ReviewedArtifactLiteral {
                size: SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELECTOR
                    .selinux_policy
                    .size
                    + 1,
                ..SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELECTOR.selinux_policy
            },
            ..SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELECTOR
        },
    );
    assert_eq!(
        qualification_selector_mismatch_fields(&changed),
        vec!["selinux_policy_size"]
    );
}

#[test]
fn policy_artifact_digest_is_compiled_from_the_exact_reviewed_document() {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/samsung-sm-s9180-fzdp-observed-behavior-v1.md"
    ));
    let digest = Sha256::digest(bytes);
    assert_eq!(
        digest.as_slice(),
        SAMSUNG_SM_S9180_FZDP_PLATFORM_PROFILE_V1
            .mark_policy
            .expect("Samsung profile has a mark-policy aspect")
            .artifact_digest
    );
}

#[test]
fn qualification_artifact_digest_is_compiled_from_the_exact_nonshipping_document() {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/policy/samsung-sm-s9180-fzdp-qkernel-20260722-qualification-v1.md"
    ));
    assert_eq!(
        Sha256::digest(bytes).as_slice(),
        SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ARTIFACT_DIGEST
    );
}

#[test]
fn assurance_classes_remain_distinct_for_otherwise_identical_entries() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let authenticated = select_from_catalog(&[ENTRY], &profile, namespace)
        .expect("authenticated synthetic policy")
        .bind_topology(&topology_scope())
        .expect("matching authenticated topology")
        .into_parts()
        .0;
    let observed_entry = ReviewedAndroidPlatformProfileCatalogEntry {
        mark_policy: Some(ReviewedAndroidMarkPolicyLiteral {
            assurance_class: AndroidMarkPolicyAssuranceClass::ExactArtifactObservedBehavior,
            ..MARK_POLICY
        }),
        ..ENTRY
    };
    let observed = select_from_catalog(&[observed_entry], &profile, namespace)
        .expect("observed-behavior synthetic policy")
        .bind_topology(&topology_scope())
        .expect("matching observed topology")
        .into_parts()
        .0;

    assert_ne!(authenticated.identity(), observed.identity());
    assert_eq!(
        authenticated.identity().assurance_class(),
        Some(AndroidMarkPolicyAssuranceClass::AuthenticatedSource)
    );
    assert_eq!(
        observed.identity().assurance_class(),
        Some(AndroidMarkPolicyAssuranceClass::ExactArtifactObservedBehavior)
    );
}

#[test]
fn runtime_tool_identity_binds_the_grant_without_becoming_a_self_hash_selector() {
    let namespace = namespace(4, 40);
    let first = capability_profile_with_tool(namespace, 0x24);
    let changed = capability_profile_with_tool(namespace, 0x25);
    let first_identity = first.device_identity().verified().expect("first identity");
    let changed_identity = changed
        .device_identity()
        .verified()
        .expect("changed identity");

    assert_ne!(first, changed);
    assert_eq!(
        ReviewedPolicySelector::from_device_identity(first_identity),
        ReviewedPolicySelector::from_device_identity(changed_identity),
        "the compile-time selector cannot contain the executing ELF's self-referential digest"
    );

    let selection = select_from_catalog(&[ENTRY], &changed, namespace).expect("platform match");
    let policy = selection
        .bind_topology(&topology_scope())
        .expect("matching topology")
        .into_parts()
        .0;
    assert_eq!(
        policy
            .positive_grant()
            .expect("positive grant")
            .capability_profile(),
        &changed,
        "the exact executing-tool artifact remains freshness-bound after selection"
    );
}

#[test]
fn selected_netd_profile_must_build_the_bound_topology() {
    let namespace = namespace(4, 40);
    let selection =
        select_from_catalog(&[ENTRY], &capability_profile(namespace), namespace).expect("match");
    let topology = topology_scope_for(AndroidNetdSourceProfile::AospNetd20250324);

    assert_eq!(
        selection.bind_topology(&topology),
        Err(
            ReviewedAndroidPlatformProfileCatalogError::MarkPolicyConstruction(
                AndroidMarkDevicePolicyError::NetdSourceProfileMismatch {
                    selected: AndroidNetdSourceProfile::AospAndroid13R1,
                    topology: AndroidNetdSourceProfile::AospNetd20250324,
                }
            )
        )
    );
}

#[test]
fn every_stable_selector_fact_drift_returns_zero_grant() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let changed_selectors = [
        ReviewedPolicySelectorLiteral {
            android_product: "google/redfin/other",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            android_build: "google/redfin/redfin:13/TQ3A.230805.001/2:user/release-keys",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            vendor_build: "google/redfin/redfin:13/TQ3A.230805.001/2:user/release-keys",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            security_patch: "2023-09-05",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            kernel_build: "5.10.198-android13-gki other-build",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            selinux_policy: artifact_literal(0x41, 4_096),
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            netd: artifact_literal(0x42, 8_192),
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            connectivity: artifact_literal(0x43, 16_384),
            ..SELECTOR
        },
    ];

    for selector in changed_selectors {
        let changed = ReviewedAndroidPlatformProfileCatalogEntry { selector, ..ENTRY };
        let selection = select_from_catalog(&[changed], &profile, namespace)
            .expect("valid nonmatching catalog");

        assert!(!selection.is_match());
        let bound = selection
            .bind_topology(&topology_scope())
            .expect("nonmatch remains a zero grant");
        let (policy, capture_path) = bound.into_parts();
        assert_eq!(policy.grant_kind(), AndroidMarkDeviceGrantKind::NoGrant);
        assert_eq!(
            capture_path.qualifications(),
            CapturePathQualifications::default()
        );
        assert!(capture_path.reviewed_identity().is_none());
    }
}

#[test]
fn optional_aspects_are_independent_and_share_one_exact_selector() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let mark_only = ReviewedAndroidPlatformProfileCatalogEntry {
        capture_path: None,
        canary_facility: None,
        ..ENTRY
    };
    let capture_only = ReviewedAndroidPlatformProfileCatalogEntry {
        mark_policy: None,
        canary_facility: None,
        ..ENTRY
    };

    let mark_bound = select_from_catalog(&[mark_only], &profile, namespace)
        .expect("mark-only profile")
        .bind_topology(&topology_scope())
        .expect("mark-only topology");
    assert_eq!(
        mark_bound.mark_policy().grant_kind(),
        AndroidMarkDeviceGrantKind::Positive
    );
    assert_eq!(
        mark_bound.capture_path_evidence().qualifications(),
        CapturePathQualifications::default()
    );
    assert!(
        mark_bound
            .capture_path_evidence()
            .reviewed_identity()
            .is_none()
    );

    let capture_bound = select_from_catalog(&[capture_only], &profile, namespace)
        .expect("capture-only profile")
        .bind_topology(&topology_scope())
        .expect("capture-only topology");
    assert_eq!(
        capture_bound.mark_policy().grant_kind(),
        AndroidMarkDeviceGrantKind::NoGrant
    );
    assert_eq!(
        capture_bound
            .capture_path_evidence()
            .qualifications()
            .state(CapturePathId::XtablesTproxy),
        CapturePathQualificationState::Qualified
    );
    assert!(
        capture_bound
            .capture_path_evidence()
            .reviewed_identity()
            .is_some()
    );
}

#[test]
fn behavioral_evidence_digest_is_canonical_and_binds_fresh_context() {
    let namespace = namespace(4, 40);
    let first = capability_profile_with_tool(namespace, 0x24);
    let changed_tool = capability_profile_with_tool(namespace, 0x25);
    let first_evidence = select_from_catalog(&[ENTRY], &first, namespace)
        .expect("first exact profile")
        .bind_topology(&topology_scope())
        .expect("first bound profile")
        .into_parts()
        .1;
    let changed_evidence = select_from_catalog(&[ENTRY], &changed_tool, namespace)
        .expect("same stable selector with changed running tool")
        .bind_topology(&topology_scope())
        .expect("changed bound profile")
        .into_parts()
        .1;
    let revised_capture = ReviewedAndroidPlatformProfileCatalogEntry {
        capture_path: Some(ReviewedCapturePathEvidenceLiteral {
            revision: 8,
            ..CAPTURE_PATH_EVIDENCE
        }),
        ..ENTRY
    };
    let revised_evidence = select_from_catalog(&[revised_capture], &first, namespace)
        .expect("revised reviewed evidence")
        .bind_topology(&topology_scope())
        .expect("revised bound profile")
        .into_parts()
        .1;

    assert_ne!(first_evidence.digest(), changed_evidence.digest());
    assert_ne!(first_evidence.digest(), revised_evidence.digest());
    assert_eq!(
        first_evidence.digest().as_bytes(),
        &[
            0xde, 0xa3, 0xd7, 0xc4, 0xab, 0x25, 0x2a, 0x11, 0x20, 0x5b, 0x0f, 0x7c, 0x7a, 0xc6,
            0x84, 0xa1, 0x09, 0xeb, 0xa0, 0x29, 0xdd, 0xa1, 0x00, 0x38, 0x54, 0x50, 0xed, 0x03,
            0x7d, 0x5f, 0x36, 0x5c,
        ],
        "schema-v1 evidence bytes must be independent of target pointer width"
    );
    assert_ne!(
        first_evidence.capability_profile_digest(),
        changed_evidence.capability_profile_digest()
    );
}

#[test]
fn duplicate_ids_selectors_and_oversized_catalogs_fail_closed() {
    let different_selector = ReviewedPolicySelectorLiteral {
        android_build: "google/redfin/redfin:13/TQ3A.230805.001/2:user/release-keys",
        ..SELECTOR
    };
    let repeated_id = ReviewedAndroidPlatformProfileCatalogEntry {
        selector: different_selector,
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[ENTRY, repeated_id]),
        Err(
            ReviewedAndroidPlatformProfileCatalogError::DuplicateEntryId {
                first: 0,
                second: 1,
            }
        )
    );

    let repeated_selector = ReviewedAndroidPlatformProfileCatalogEntry {
        id: "google-redfin-tq3a-20230805-v2",
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[ENTRY, repeated_selector]),
        Err(
            ReviewedAndroidPlatformProfileCatalogError::DuplicateSelector {
                first: 0,
                second: 1,
            }
        )
    );

    let oversized = [ENTRY; MAX_REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG_ENTRIES + 1];
    assert_eq!(
        validate_catalog(&oversized),
        Err(ReviewedAndroidPlatformProfileCatalogError::TooManyEntries {
            maximum: MAX_REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG_ENTRIES,
            required_at_least: MAX_REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG_ENTRIES + 1,
        })
    );
}

#[test]
fn malformed_candidate_and_planes_fail_closed() {
    let ineligible_candidate = ReviewedAndroidPlatformProfileCatalogEntry {
        mark_policy: Some(ReviewedAndroidMarkPolicyLiteral {
            candidate_mask: 0xc000_0000,
            proxy_value: 0x8000_0000,
            bypass_value: 0x4000_0000,
            ..MARK_POLICY
        }),
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[ineligible_candidate]),
        Err(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry {
            index: 0,
            field: ReviewedAndroidPlatformProfileCatalogField::MarkCandidate,
        })
    );

    let unknown_planes = ReviewedAndroidPlatformProfileCatalogEntry {
        mark_policy: Some(ReviewedAndroidMarkPolicyLiteral {
            planes: 0x80,
            ..MARK_POLICY
        }),
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[unknown_planes]),
        Err(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry {
            index: 0,
            field: ReviewedAndroidPlatformProfileCatalogField::MarkPlanes,
        })
    );

    let empty_planes = ReviewedAndroidPlatformProfileCatalogEntry {
        mark_policy: Some(ReviewedAndroidMarkPolicyLiteral {
            planes: 0,
            ..MARK_POLICY
        }),
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[empty_planes]),
        Err(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry {
            index: 0,
            field: ReviewedAndroidPlatformProfileCatalogField::MarkPlanes,
        })
    );
}

#[test]
fn empty_or_malformed_capture_aspects_fail_closed() {
    let empty = ReviewedAndroidPlatformProfileCatalogEntry {
        mark_policy: None,
        capture_path: None,
        canary_facility: None,
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[empty]),
        Err(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry {
            index: 0,
            field: ReviewedAndroidPlatformProfileCatalogField::ProfileAspects,
        })
    );

    for (capture_path, field) in [
        (
            ReviewedCapturePathEvidenceLiteral {
                revision: 0,
                ..CAPTURE_PATH_EVIDENCE
            },
            ReviewedAndroidPlatformProfileCatalogField::CapturePathEvidenceRevision,
        ),
        (
            ReviewedCapturePathEvidenceLiteral {
                artifact_digest: [0; 32],
                ..CAPTURE_PATH_EVIDENCE
            },
            ReviewedAndroidPlatformProfileCatalogField::CapturePathEvidenceArtifactDigest,
        ),
        (
            ReviewedCapturePathEvidenceLiteral {
                qualifications: CapturePathQualifications::default(),
                ..CAPTURE_PATH_EVIDENCE
            },
            ReviewedAndroidPlatformProfileCatalogField::CapturePathQualifications,
        ),
    ] {
        let malformed = ReviewedAndroidPlatformProfileCatalogEntry {
            capture_path: Some(capture_path),
            ..ENTRY
        };
        assert_eq!(
            validate_catalog(&[malformed]),
            Err(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry { index: 0, field })
        );
    }
}

#[test]
fn malformed_unrelated_entry_poisoning_is_rejected_before_exact_selection() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let malformed_unrelated = ReviewedAndroidPlatformProfileCatalogEntry {
        id: "unrelated-invalid-entry",
        selector: ReviewedPolicySelectorLiteral {
            android_product: "other/product/device",
            ..SELECTOR
        },
        mark_policy: Some(ReviewedAndroidMarkPolicyLiteral {
            revision: 0,
            ..MARK_POLICY
        }),
        ..ENTRY
    };

    assert_eq!(
        select_from_catalog(&[ENTRY, malformed_unrelated], &profile, namespace),
        Err(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry {
            index: 1,
            field: ReviewedAndroidPlatformProfileCatalogField::MarkPolicyRevision,
        })
    );
}

#[test]
fn selection_rejects_unverified_boot_identity_and_namespace_drift() {
    let profile_namespace = namespace(4, 40);
    let verified = capability_profile(profile_namespace);
    let unavailable_boot = CapabilityProfile::initial(
        Observation::Unavailable,
        verified.device_identity().clone(),
        verified.kernel().clone(),
        verified.selinux().clone(),
    );
    assert_eq!(
        select_from_catalog(&[ENTRY], &unavailable_boot, profile_namespace,),
        Err(
            ReviewedAndroidPlatformProfileCatalogError::UnverifiedBootIdentity {
                observation: ObservationKind::Unavailable,
            }
        )
    );

    let unavailable = CapabilityProfile::initial(
        Observation::Verified(
            BootIdentity::parse("00112233-4455-6677-8899-aabbccddeeff").expect("boot identity"),
        ),
        Observation::Unavailable,
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new("5.10.198-android13-gki").expect("kernel release"),
        )),
        Observation::Verified(SelinuxMode::Enforcing),
    );
    assert_eq!(
        select_from_catalog(&[ENTRY], &unavailable, profile_namespace),
        Err(
            ReviewedAndroidPlatformProfileCatalogError::UnverifiedDeviceIdentity {
                observation: ObservationKind::Unavailable,
            }
        )
    );

    let profile = capability_profile(profile_namespace);
    let other_namespace = namespace(4, 41);
    assert_eq!(
        select_from_catalog(&[ENTRY], &profile, other_namespace),
        Err(
            ReviewedAndroidPlatformProfileCatalogError::NetworkNamespaceMismatch {
                profile: profile_namespace,
                observed: other_namespace,
            }
        )
    );
}

const fn artifact_literal(byte: u8, size: u64) -> ReviewedArtifactLiteral {
    ReviewedArtifactLiteral {
        digest: [byte; 32],
        size,
    }
}

fn namespace(device: u64, inode: u64) -> NetworkNamespaceIdentity {
    NetworkNamespaceIdentity::new(device, inode).expect("nonzero namespace inode")
}

fn capability_profile(network_namespace: NetworkNamespaceIdentity) -> CapabilityProfile {
    capability_profile_with_tool(network_namespace, 0x24)
}

fn capability_profile_with_tool(
    network_namespace: NetworkNamespaceIdentity,
    tool_digest_byte: u8,
) -> CapabilityProfile {
    capability_profile_for_selector(network_namespace, tool_digest_byte, SELECTOR)
}

fn capability_profile_for_selector(
    network_namespace: NetworkNamespaceIdentity,
    tool_digest_byte: u8,
    selector: ReviewedPolicySelectorLiteral,
) -> CapabilityProfile {
    CapabilityProfile::new(
        CapabilityProfileRevision::INITIAL,
        Observation::Verified(
            BootIdentity::parse("00112233-4455-6677-8899-aabbccddeeff").expect("boot identity"),
        ),
        Observation::Verified(
            DeviceIdentity::new(
                AndroidProductIdentity::new(selector.android_product).expect("product"),
                AndroidBuildIdentity::new(selector.android_build).expect("Android build"),
                VendorBuildIdentity::new(selector.vendor_build).expect("vendor build"),
                SecurityPatchLevel::new(selector.security_patch).expect("security patch"),
                VerifiedBootIdentity::new(
                    VerifiedBootState::Green,
                    true,
                    Sha256Digest::new([0x11; 32]).expect("vbmeta digest"),
                ),
                KernelBuildIdentity::new(selector.kernel_build).expect("kernel build"),
                SelinuxPolicyIdentity::from(artifact_from_literal(selector.selinux_policy)),
                artifact_from_literal(selector.netd),
                artifact_from_literal(selector.connectivity),
                [(
                    ToolId::new("fluxd").expect("tool ID"),
                    artifact(tool_digest_byte, 32_768),
                )],
                network_namespace,
            )
            .expect("device identity"),
        ),
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new(
                selector
                    .kernel_build
                    .split_once(' ')
                    .map_or(selector.kernel_build, |(release, _)| release),
            )
            .expect("kernel release"),
        )),
        Observation::Verified(SelinuxMode::Enforcing),
    )
}

fn artifact_from_literal(literal: ReviewedArtifactLiteral) -> ArtifactIdentity {
    ArtifactIdentity::new(
        Sha256Digest::new(literal.digest).expect("artifact digest"),
        literal.size,
    )
    .expect("nonempty artifact")
}

fn artifact(byte: u8, size: u64) -> ArtifactIdentity {
    ArtifactIdentity::new(
        Sha256Digest::new([byte; 32]).expect("artifact digest"),
        size,
    )
    .expect("nonempty artifact")
}

fn topology_scope() -> AndroidTproxyTopologyScopeReport {
    topology_scope_for(AndroidNetdSourceProfile::AospAndroid13R1)
}

fn topology_scope_for(profile: AndroidNetdSourceProfile) -> AndroidTproxyTopologyScopeReport {
    let mut tracker = NetworkInventoryTracker::new();
    let inventory = tracker
        .publish_complete_with_routing(
            [InterfaceLinkRecord::new(
                InterfaceIndex::new(1).expect("loopback index"),
                InterfaceName::new(b"lo").expect("loopback name"),
                InterfaceHardwareType::from_raw(1),
                InterfaceLinkFlags::UP | InterfaceLinkFlags::LOOPBACK,
            )],
            [],
            [],
            android_13_rules(),
        )
        .expect("complete inventory")
        .clone();
    let classification = classify_android_rpdb(&inventory, profile);
    let request = AndroidTproxyTopologyScopeRequest::new(
        AndroidTproxyRoutingShape::PreMarkAddressHostSet,
        [AndroidTproxyTrafficDomainRequest::residual_local_output(
            NetworkAddressFamily::Ipv4,
        )],
    )
    .expect("topology request");
    assess_android_tproxy_topology_scope(&inventory, &classification, &request)
        .expect("trusted residual local-output scope")
}

fn android_13_rules() -> Vec<NetworkRuleRecord> {
    android_13_rules_for_families([NetworkAddressFamily::Ipv4])
}

fn android_13_rules_for_families(
    families: impl IntoIterator<Item = NetworkAddressFamily>,
) -> Vec<NetworkRuleRecord> {
    let mut rules = Vec::new();
    for family in families {
        rules.extend([
            RuleSpec::netd(0, 255, RuleAction::TO_TABLE)
                .family(family)
                .protocol(2)
                .build(),
            RuleSpec::netd(10_000, 99, RuleAction::TO_TABLE)
                .family(family)
                .mark(SYSTEM_PERMISSION, EXPLICIT_NETWORK | SYSTEM_PERMISSION)
                .build(),
            RuleSpec::netd(16_000, 97, RuleAction::TO_TABLE)
                .family(family)
                .mark(99 | EXPLICIT_NETWORK, NET_ID_MASK | EXPLICIT_NETWORK)
                .input(b"lo")
                .build(),
            RuleSpec::netd(18_000, 99, RuleAction::TO_TABLE)
                .family(family)
                .mark(0, EXPLICIT_NETWORK)
                .build(),
            RuleSpec::netd(19_000, 98, RuleAction::TO_TABLE)
                .family(family)
                .mark(0, EXPLICIT_NETWORK)
                .build(),
            RuleSpec::netd(20_000, 97, RuleAction::TO_TABLE)
                .family(family)
                .mark(0, EXPLICIT_NETWORK)
                .build(),
            RuleSpec::netd(31_000, 1_003, RuleAction::TO_TABLE)
                .family(family)
                .mark(NETWORK_PERMISSION, NET_ID_MASK | NETWORK_PERMISSION)
                .input(b"lo")
                .build(),
            RuleSpec::netd(32_000, 0, RuleAction::UNREACHABLE)
                .family(family)
                .build(),
        ]);
    }
    rules.sort_by_key(NetworkRuleRecord::priority);
    rules
}

fn reviewed_canary_rules(
    policy: &ReviewedCanaryFacilityPolicy,
    selection: ReviewedCanaryFacilitySelection,
) -> Vec<NetworkRuleRecord> {
    let rpdb = policy.rpdb();
    std::iter::once(std::net::IpAddr::V4(selection.peer_ipv4()))
        .chain(selection.peer_ipv6().map(std::net::IpAddr::V6))
        .flat_map(|destination| {
            [
                (6, selection.tcp_echo().get()),
                (17, selection.udp_echo().get()),
                (6, selection.dns().get()),
                (17, selection.dns().get()),
            ]
            .into_iter()
            .map(move |(protocol, port)| (destination, protocol, port))
        })
        .map(|(destination, protocol, port)| {
            let (family, prefix_length) = match destination {
                std::net::IpAddr::V4(_) => (NetworkAddressFamily::Ipv4, 32),
                std::net::IpAddr::V6(_) => (NetworkAddressFamily::Ipv6, 128),
            };
            NetworkRuleRecord::new(
                RulePrefix::new(destination, prefix_length).expect("peer host prefix"),
                RulePrefix::unspecified(family),
                RuleProperties::new(
                    0,
                    RuleTableId::from_raw(rpdb.peer_table().get()),
                    RuleAction::TO_TABLE,
                    RuleProtocol::from_raw(rpdb.rule_protocol().get()),
                    RuleFlags::default(),
                ),
                rpdb.peer_rule_priority(),
                None,
            )
            .expect("peer rule")
            .with_fwmark(RuleFwMark::new(0, rpdb.proxy_mark_mask().get()).expect("zero proxy mark"))
            .with_uid_range(
                RuleUidRange::new(
                    policy.credentials().engine_uid().get(),
                    policy.credentials().engine_uid().get(),
                )
                .expect("engine UID range"),
            )
            .with_ip_protocol(RuleIpProtocol::new(protocol).expect("IP protocol"))
            .with_destination_port_range(
                RulePortRange::new(port, port).expect("destination port range"),
            )
        })
        .collect()
}

fn synthetic_reviewed_canary_policy() -> (
    ReviewedCanaryFacilityPolicy,
    ReviewedCanaryFacilitySelection,
) {
    synthetic_reviewed_canary_policy_with_early_lookups([])
}

fn synthetic_reviewed_canary_policy_with_early_lookups(
    early_uid_lookup_priorities: impl IntoIterator<Item = u32>,
) -> (
    ReviewedCanaryFacilityPolicy,
    ReviewedCanaryFacilitySelection,
) {
    let policy = ReviewedCanaryFacilityPolicy::reviewed(
        ReviewedPolicyCatalogEntryId::new("synthetic-canary").expect("catalog entry"),
        1,
        [0x51; 32],
        b"fxcan0",
        b"fxcanp",
        20_001,
        20_001,
        20_002,
        20_002,
        [(
            std::net::Ipv4Addr::new(8, 8, 8, 7),
            std::net::Ipv4Addr::new(8, 8, 8, 8),
            Some(std::net::Ipv6Addr::new(
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1110,
            )),
            Some(std::net::Ipv6Addr::new(
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
            )),
        )],
        [(41_001, 41_002, 41_003)],
        AndroidNetdSourceProfile::AospNetd20250324,
        early_uid_lookup_priorities,
        30_997,
        30_998,
        20_253,
        20_254,
        254,
        186,
        186,
        1_031,
        PROXY_VALUE,
        CANDIDATE_MASK,
    )
    .expect("reviewed canary policy");
    let selection = policy
        .bind_live_selection(
            std::net::Ipv4Addr::new(8, 8, 8, 8),
            Some(std::net::Ipv6Addr::new(
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
            )),
            std::num::NonZeroU16::new(41_001).expect("TCP port"),
            std::num::NonZeroU16::new(41_002).expect("UDP port"),
            std::num::NonZeroU16::new(41_003).expect("DNS port"),
        )
        .expect("reviewed live selection");
    (policy, selection)
}

fn reviewed_vendor_early_uid_lookup_rules() -> [NetworkRuleRecord; 2] {
    let priority_one = NetworkRuleRecord::new(
        RulePrefix::new(std::net::Ipv4Addr::new(10, 0, 0, 0).into(), 8)
            .expect("vendor destination prefix"),
        RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
        RuleProperties::new(
            0,
            RuleTableId::from_raw(1_001),
            RuleAction::TO_TABLE,
            RuleProtocol::from_raw(0),
            RuleFlags::default(),
        ),
        RulePriority::from_raw(1),
        None,
    )
    .expect("priority-one vendor rule")
    .with_uid_range(RuleUidRange::new(10_001, 10_001).expect("priority-one vendor UID"));
    let priority_two = RuleSpec::netd(2, 1_002, RuleAction::TO_TABLE)
        .build()
        .with_uid_range(RuleUidRange::new(10_002, 10_002).expect("priority-two vendor UID"));
    [priority_one, priority_two]
}

fn rebuild_canary_rule(
    rule: &NetworkRuleRecord,
    priority: RulePriority,
    table: RuleTableId,
) -> NetworkRuleRecord {
    NetworkRuleRecord::new(
        rule.destination(),
        rule.source(),
        RuleProperties::new(
            rule.properties().tos(),
            table,
            rule.properties().action(),
            rule.properties().protocol(),
            rule.properties().flags(),
        ),
        priority,
        rule.goto_target(),
    )
    .expect("rebuilt canary rule")
    .with_fwmark(rule.fwmark().expect("canary fwmark"))
    .with_uid_range(rule.uid_range().expect("canary UID range"))
    .with_ip_protocol(rule.ip_protocol().expect("canary IP protocol"))
    .with_destination_port_range(
        rule.destination_port_range()
            .expect("canary destination port"),
    )
}

fn assert_reviewed_canary_cohort_rejected(
    policy: &ReviewedCanaryFacilityPolicy,
    selection: ReviewedCanaryFacilitySelection,
    mut rules: Vec<NetworkRuleRecord>,
) {
    rules.sort_by_key(NetworkRuleRecord::priority);
    let inventory = inventory_with_rules(rules);
    assert_eq!(
        classify_android_rpdb_with_reviewed_canary_facility(
            &inventory,
            policy.netd_source_profile(),
            policy,
            selection,
        ),
        Err(ReviewedCanaryRpdbClassificationError::OwnedCohortMismatch)
    );
}

fn inventory_with_rules(rules: Vec<NetworkRuleRecord>) -> NetworkInventory {
    let mut tracker = NetworkInventoryTracker::new();
    tracker
        .publish_complete_with_routing(
            [InterfaceLinkRecord::new(
                InterfaceIndex::new(1).expect("loopback index"),
                InterfaceName::new(b"lo").expect("loopback name"),
                InterfaceHardwareType::from_raw(1),
                InterfaceLinkFlags::UP | InterfaceLinkFlags::LOOPBACK,
            )],
            [],
            [],
            rules,
        )
        .expect("complete inventory")
        .clone()
}

struct RuleSpec {
    family: NetworkAddressFamily,
    priority: u32,
    table: u32,
    action: RuleAction,
    protocol: u8,
    fwmark: Option<RuleFwMark>,
    input: Option<InterfaceName>,
}

impl RuleSpec {
    fn netd(priority: u32, table: u32, action: RuleAction) -> Self {
        Self {
            family: NetworkAddressFamily::Ipv4,
            priority,
            table,
            action,
            protocol: 0,
            fwmark: None,
            input: None,
        }
    }

    fn family(mut self, family: NetworkAddressFamily) -> Self {
        self.family = family;
        self
    }

    fn protocol(mut self, protocol: u8) -> Self {
        self.protocol = protocol;
        self
    }

    fn mark(mut self, value: u32, mask: u32) -> Self {
        self.fwmark = RuleFwMark::new(value, mask);
        self
    }

    fn input(mut self, name: &[u8]) -> Self {
        self.input = Some(InterfaceName::new(name).expect("interface name"));
        self
    }

    fn build(self) -> NetworkRuleRecord {
        let mut record = NetworkRuleRecord::new(
            RulePrefix::unspecified(self.family),
            RulePrefix::unspecified(self.family),
            RuleProperties::new(
                0,
                RuleTableId::from_raw(self.table),
                self.action,
                RuleProtocol::from_raw(self.protocol),
                RuleFlags::default(),
            ),
            RulePriority::from_raw(self.priority),
            None,
        )
        .expect("rule fixture");
        if let Some(fwmark) = self.fwmark {
            record = record.with_fwmark(fwmark);
        }
        if let Some(input) = self.input {
            record = record.with_input_interface(input);
        }
        record
    }
}
