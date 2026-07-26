use crate::{
    ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK, AndroidBuildIdentity, AndroidMarkDeviceGrantKind,
    AndroidMarkDevicePolicy, AndroidMarkDevicePolicyArtifactDigest,
    AndroidMarkDevicePolicyArtifactDigestError, AndroidMarkDevicePolicyError,
    AndroidMarkDevicePolicyKind, AndroidMarkDevicePolicyName, AndroidMarkDevicePolicyNameError,
    AndroidMarkDevicePolicyRevision, AndroidMarkPlanningAuthorizationError,
    AndroidNetdSourceProfile, AndroidProductIdentity, AndroidRpdbClassificationReport,
    AndroidTproxyRoutingShape, AndroidTproxyTopologyScopeReport, AndroidTproxyTopologyScopeRequest,
    AndroidTproxyTrafficDomainRequest, ArtifactIdentity, BootIdentity,
    COMPLETE_FWMARK_CENSUS_COVERAGE_RECORDS, CapabilityProfile, CapabilityProfileRevision,
    CompleteFwmarkCensus, CompleteFwmarkCensusError, DeferredAndroidMarkActivationPrerequisite,
    DeferredAndroidTproxyPrerequisite, DeviceIdentity, FwmarkCandidate,
    FwmarkCensusCollectorRevision, FwmarkCensusCoverageRecord, FwmarkCensusCoverageState,
    FwmarkEvidenceSource, FwmarkEvidenceState, FwmarkOrderedPacketWriteRequirement,
    FwmarkPartialAuditOutcome, FwmarkPlane, FwmarkPlaneSet, FwmarkUseOperation, FwmarkUseRecord,
    FwmarkUseRecordError, InterfaceHardwareType, InterfaceIndex, InterfaceLinkFlags,
    InterfaceLinkRecord, InterfaceName, KernelBuildIdentity, KernelFacts, KernelRelease,
    LegacyAddressSynchronization, LegacyArtifactReadiness, LegacyArtifactResolution,
    LegacyBridgeFacts, LegacyMutationWriter, LegacyRuleBackend,
    MAX_ANDROID_MARK_DEVICE_POLICY_NAME_BYTES, MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
    NetworkAddressFamily, NetworkInventory, NetworkInventoryTracker, NetworkNamespaceIdentity,
    NetworkRuleRecord, Observation, OpaqueRuleAttribute, OwnershipJournalIdentity,
    OwnershipJournalIdentityError, OwnershipJournalRevision, RuleAction, RuleAttributeOpacity,
    RuleFlags, RuleFwMark, RuleOpaqueAttributeFingerprint, RulePrefix, RulePriority,
    RuleProperties, RuleProtocol, RuleTableId, SecurityPatchLevel, SelinuxMode,
    SelinuxPolicyIdentity, Sha256Digest, ToolId, VendorBuildIdentity, VerifiedBootIdentity,
    VerifiedBootState, assess_android_tproxy_topology_scope, authorize_android_mark_planning,
    classify_android_rpdb,
};

use super::{
    MAX_REVIEWED_POLICY_CATALOG_ENTRY_ID_BYTES, ReviewedPolicyCatalogEntryId,
    ReviewedPolicyCatalogEntryIdError,
};

const NET_ID_MASK: u32 = 0x0000_ffff;
const EXPLICIT_NETWORK: u32 = 0x0001_0000;
const NETWORK_PERMISSION: u32 = 0x0004_0000;
const SYSTEM_PERMISSION: u32 = 0x000c_0000;
const DEFAULT_NETWORK_TABLE: u32 = 1_003;

const CANDIDATE_MASK: u32 = 0x0300_0000;
const PROXY_VALUE: u32 = 0x0100_0000;
const BYPASS_VALUE: u32 = 0x0200_0000;

const SOURCES: [FwmarkEvidenceSource; 9] = [
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

const PLANES: [FwmarkPlane; 3] = [
    FwmarkPlane::Packet,
    FwmarkPlane::Socket,
    FwmarkPlane::Conntrack,
];

const OPERATIONS: [FwmarkUseOperation; 4] = [
    FwmarkUseOperation::PredicateRead,
    FwmarkUseOperation::MaskedWrite,
    FwmarkUseOperation::TransferRead,
    FwmarkUseOperation::TransferWrite,
];

#[test]
fn generic_aosp_is_always_a_zero_grant() {
    let context = TestContext::standard();
    let policy = AndroidMarkDevicePolicy::generic_aosp();
    assert_eq!(policy.grant_kind(), AndroidMarkDeviceGrantKind::NoGrant);
    assert_eq!(
        policy.identity().kind(),
        AndroidMarkDevicePolicyKind::GenericAospNoGrant
    );
    assert!(policy.positive_grant().is_none());

    let census = census_with(
        &context.inventory,
        &context.capability_profile,
        context.network_namespace,
        &policy,
        context.collector_revision,
        context.ownership_journal_identity,
        context.ownership_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("generic AOSP can still be the identity bound by a negative census");
    let error = authorize_android_mark_planning(
        &context.inventory,
        &context.classification,
        &context.topology_scope,
        &context.capability_profile,
        context.network_namespace,
        context.ownership_journal_identity,
        context.ownership_journal_revision,
        context.collector_revision,
        &policy,
        context.candidate,
        census,
    )
    .expect_err("generic AOSP never supplies positive mark authority");
    assert_eq!(
        error,
        AndroidMarkPlanningAuthorizationError::NoPositiveDeviceGrant {
            policy_kind: AndroidMarkDevicePolicyKind::GenericAospNoGrant,
        }
    );
}

#[test]
fn positive_policy_and_census_require_exact_namespace_consistent_device_identity() {
    let context = TestContext::standard();
    let unavailable = CapabilityProfile::new(
        context.capability_profile.revision(),
        context.capability_profile.boot_identity().clone(),
        Observation::Unavailable,
        context.capability_profile.kernel().clone(),
        context.capability_profile.selinux().clone(),
        context.capability_profile.legacy_bridge().clone(),
    );
    assert!(matches!(
        cooperative_policy(
            "missing-device-identity",
            [0x31; 32],
            AndroidMarkDevicePolicyRevision::INITIAL,
            context.candidate,
            &context.topology_scope,
            &unavailable,
            context.network_namespace,
            FwmarkPlaneSet::ALL,
        )
        .expect_err("a boot ID alone cannot mint a device-qualified grant"),
        AndroidMarkDevicePolicyError::UnverifiedDeviceIdentity { .. }
    ));
    assert!(matches!(
        census_with(
            &context.inventory,
            &unavailable,
            context.network_namespace,
            &AndroidMarkDevicePolicy::generic_aosp(),
            context.collector_revision,
            context.ownership_journal_identity,
            context.ownership_journal_revision,
            complete_absent_coverage(),
            [],
        )
        .expect_err("a census cannot self-assert missing exact device facts"),
        CompleteFwmarkCensusError::UnverifiedDeviceIdentity { .. }
    ));

    let profile_namespace = namespace(11, 20);
    let mismatched = verified_capability_profile(
        context.capability_profile.revision(),
        "01234567-89ab-cdef-0123-456789abcdef",
        SelinuxMode::Enforcing,
        profile_namespace,
    );
    assert_eq!(
        cooperative_policy(
            "namespace-mismatch",
            [0x32; 32],
            AndroidMarkDevicePolicyRevision::INITIAL,
            context.candidate,
            &context.topology_scope,
            &mismatched,
            context.network_namespace,
            FwmarkPlaneSet::ALL,
        )
        .expect_err("the separate observation must match the full profile"),
        AndroidMarkDevicePolicyError::NetworkNamespaceMismatch {
            profile: profile_namespace,
            observed: context.network_namespace,
        }
    );
}

#[test]
fn device_qualified_candidate_eligibility_is_only_a_structural_prerequisite() {
    let context = TestContext::standard();
    assert_eq!(ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK, 0x7fe0_0000);

    let entire_eligible_field = FwmarkCandidate::new(
        ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK,
        0x0020_0000,
        0x0040_0000,
    )
    .expect("two nonzero roles fit within the complete candidate field");
    let policy = cooperative_policy(
        "eligible-complete-field",
        [0x31; 32],
        AndroidMarkDevicePolicyRevision::INITIAL,
        entire_eligible_field,
        &context.topology_scope,
        &context.capability_profile,
        context.network_namespace,
        FwmarkPlaneSet::ALL,
    )
    .expect("the complete device-qualified field is structurally eligible");
    assert_eq!(policy.grant_kind(), AndroidMarkDeviceGrantKind::Positive);

    for ineligible in [
        FwmarkCandidate::new(0x0000_0003, 0x1, 0x2).expect("low candidate is structural"),
        FwmarkCandidate::new(0xc000_0000, 0x4000_0000, 0x8000_0000)
            .expect("upper candidate is structural"),
        FwmarkCandidate::new(0x8020_0000, 0x0020_0000, 0x8000_0000)
            .expect("partially eligible candidate is structural"),
    ] {
        let error = cooperative_policy(
            "ineligible-field",
            [0x32; 32],
            AndroidMarkDevicePolicyRevision::INITIAL,
            ineligible,
            &context.topology_scope,
            &context.capability_profile,
            context.network_namespace,
            FwmarkPlaneSet::ALL,
        )
        .expect_err("bits outside the device-qualified field must be rejected");
        let AndroidMarkDevicePolicyError::IneligibleCandidate(eligibility) = error else {
            panic!("unexpected candidate error: {error:?}");
        };
        assert_eq!(eligibility.mask(), ineligible.mask());
        assert_eq!(
            eligibility.eligible_mask(),
            ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK
        );
    }

    assert_eq!(
        cooperative_policy(
            "empty-plane-set",
            [0x33; 32],
            AndroidMarkDevicePolicyRevision::INITIAL,
            context.candidate,
            &context.topology_scope,
            &context.capability_profile,
            context.network_namespace,
            FwmarkPlaneSet::NONE,
        )
        .expect_err("a positive assertion must name at least one plane"),
        AndroidMarkDevicePolicyError::EmptyPlaneGrant
    );
}

#[test]
fn trust_boundary_values_reject_empty_or_unbounded_identities_and_masks() {
    assert_eq!(
        ReviewedPolicyCatalogEntryId::new("").expect_err("empty catalog entry ID"),
        ReviewedPolicyCatalogEntryIdError::Empty
    );
    assert_eq!(
        ReviewedPolicyCatalogEntryId::new("Uppercase")
            .expect_err("catalog entry IDs use a canonical machine grammar"),
        ReviewedPolicyCatalogEntryIdError::InvalidFormat
    );
    let oversized_entry_id = "x".repeat(MAX_REVIEWED_POLICY_CATALOG_ENTRY_ID_BYTES + 1);
    assert_eq!(
        ReviewedPolicyCatalogEntryId::new(&oversized_entry_id)
            .expect_err("catalog entry IDs are byte bounded"),
        ReviewedPolicyCatalogEntryIdError::TooLong {
            maximum: MAX_REVIEWED_POLICY_CATALOG_ENTRY_ID_BYTES,
            actual: MAX_REVIEWED_POLICY_CATALOG_ENTRY_ID_BYTES + 1,
        }
    );
    assert_eq!(
        AndroidMarkDevicePolicyName::new(" \t ").expect_err("trimmed empty policy name"),
        AndroidMarkDevicePolicyNameError::Empty
    );
    assert_eq!(
        AndroidMarkDevicePolicyName::new("policy\u{7}")
            .expect_err("control characters are not stable policy identity"),
        AndroidMarkDevicePolicyNameError::ControlCharacter
    );
    let oversized_name = "x".repeat(MAX_ANDROID_MARK_DEVICE_POLICY_NAME_BYTES + 1);
    assert_eq!(
        AndroidMarkDevicePolicyName::new(&oversized_name)
            .expect_err("policy identity is byte bounded"),
        AndroidMarkDevicePolicyNameError::TooLong {
            maximum: MAX_ANDROID_MARK_DEVICE_POLICY_NAME_BYTES,
            actual: MAX_ANDROID_MARK_DEVICE_POLICY_NAME_BYTES + 1,
        }
    );
    assert_eq!(
        AndroidMarkDevicePolicyArtifactDigest::new([0; 32])
            .expect_err("an all-zero SHA-256 identity is not evidence"),
        AndroidMarkDevicePolicyArtifactDigestError::AllZero
    );
    assert_eq!(
        OwnershipJournalIdentity::new([0; 32])
            .expect_err("an all-zero journal identity is not durable identity"),
        OwnershipJournalIdentityError::AllZero
    );
    assert_eq!(NetworkNamespaceIdentity::new(1, 0), None);
    assert_eq!(FwmarkPlaneSet::from_bits(0b1000), None);
    assert_eq!(
        FwmarkUseRecord::new(
            FwmarkEvidenceSource::Xfrm,
            FwmarkPlane::Packet,
            FwmarkUseOperation::PredicateRead,
            0,
        )
        .expect_err("mark-use evidence requires a nonzero mask"),
        FwmarkUseRecordError::EmptyMask
    );
}

#[test]
fn complete_census_canonicalizes_the_exact_twenty_seven_record_matrix() {
    let context = TestContext::standard();
    assert_eq!(COMPLETE_FWMARK_CENSUS_COVERAGE_RECORDS, 27);

    let mut coverage = complete_absent_coverage();
    set_coverage_state(
        &mut coverage,
        FwmarkEvidenceSource::Xfrm,
        FwmarkPlane::Socket,
        FwmarkCensusCoverageState::CompletePresent,
    );
    coverage.reverse();
    let mark_use = FwmarkUseRecord::new(
        FwmarkEvidenceSource::Xfrm,
        FwmarkPlane::Socket,
        FwmarkUseOperation::PredicateRead,
        0x0001_0000,
    )
    .expect("nonzero disjoint use");
    let census = context
        .census(coverage, [mark_use])
        .expect("an exact mixed present/absent matrix is complete");

    let expected_pairs = SOURCES
        .into_iter()
        .flat_map(|source| PLANES.into_iter().map(move |plane| (source, plane)))
        .collect::<Vec<_>>();
    assert_eq!(census.coverage().len(), expected_pairs.len());
    assert_eq!(
        census
            .coverage()
            .iter()
            .copied()
            .map(|record| (record.source(), record.plane()))
            .collect::<Vec<_>>(),
        expected_pairs
    );
    assert_eq!(census.mark_uses(), [mark_use]);
    assert_eq!(census.snapshot_id(), context.inventory.snapshot_id());
    assert_eq!(census.epoch(), context.inventory.epoch());
    assert_eq!(census.capability_profile(), &context.capability_profile);
    assert_eq!(census.network_namespace(), context.network_namespace);
    assert_eq!(census.device_policy_identity(), context.policy.identity());
    assert_eq!(census.device_policy_revision(), context.policy.revision());
    assert_eq!(census.collector_revision(), context.collector_revision);
    assert_eq!(
        census.ownership_journal_identity(),
        context.ownership_journal_identity
    );
    assert_eq!(
        census.ownership_journal_revision(),
        context.ownership_journal_revision
    );
}

#[test]
fn every_noncomplete_coverage_state_is_rejected_for_every_source_and_plane() {
    let context = TestContext::standard();
    for state in [
        FwmarkCensusCoverageState::Incomplete,
        FwmarkCensusCoverageState::Opaque,
        FwmarkCensusCoverageState::Denied,
        FwmarkCensusCoverageState::Transient,
        FwmarkCensusCoverageState::Unavailable,
    ] {
        assert!(!state.is_complete());
        for source in SOURCES {
            for plane in PLANES {
                let mut coverage = complete_absent_coverage();
                set_coverage_state(&mut coverage, source, plane, state);
                let error = context
                    .census(coverage, [])
                    .expect_err("noncomplete source-plane evidence must fail closed");
                assert_eq!(
                    error,
                    CompleteFwmarkCensusError::NonCompleteCoverage {
                        source,
                        plane,
                        state,
                    }
                );
            }
        }
    }
}

#[test]
fn every_source_plane_pair_must_be_present_once_and_only_once() {
    let context = TestContext::standard();
    for source in SOURCES {
        for plane in PLANES {
            let mut missing = complete_absent_coverage();
            missing.retain(|record| record.source() != source || record.plane() != plane);
            assert_eq!(
                context
                    .census(missing, [])
                    .expect_err("one omitted pair makes the census incomplete"),
                CompleteFwmarkCensusError::MissingCoverage { source, plane }
            );

            let mut duplicate = complete_absent_coverage();
            let replacement =
                if (source, plane) != (FwmarkEvidenceSource::AndroidNetId, FwmarkPlane::Packet) {
                    (FwmarkEvidenceSource::AndroidNetId, FwmarkPlane::Packet)
                } else {
                    (FwmarkEvidenceSource::AndroidNetId, FwmarkPlane::Socket)
                };
            duplicate.retain(|record| (record.source(), record.plane()) != replacement);
            duplicate.push(FwmarkCensusCoverageRecord::new(
                source,
                plane,
                FwmarkCensusCoverageState::CompleteAbsent,
            ));
            assert_eq!(duplicate.len(), COMPLETE_FWMARK_CENSUS_COVERAGE_RECORDS);
            assert_eq!(
                context
                    .census(duplicate, [])
                    .expect_err("a repeated pair is not coverage for an omitted pair"),
                CompleteFwmarkCensusError::DuplicateCoverage { source, plane }
            );
        }
    }

    let mut too_many = complete_absent_coverage();
    too_many.push(too_many[0]);
    assert_eq!(
        context
            .census(too_many, [])
            .expect_err("the raw coverage assertion is exactly bounded"),
        CompleteFwmarkCensusError::TooManyCoverageRecords {
            maximum: COMPLETE_FWMARK_CENSUS_COVERAGE_RECORDS,
            required_at_least: COMPLETE_FWMARK_CENSUS_COVERAGE_RECORDS + 1,
        }
    );
}

#[test]
fn present_and_absent_coverage_must_agree_with_canonical_mark_uses() {
    let context = TestContext::standard();
    for source in SOURCES {
        for plane in PLANES {
            let mut present = complete_absent_coverage();
            set_coverage_state(
                &mut present,
                source,
                plane,
                FwmarkCensusCoverageState::CompletePresent,
            );
            assert_eq!(
                context
                    .census(present, [])
                    .expect_err("present coverage needs at least one canonical use"),
                CompleteFwmarkCensusError::PresentCoverageHasNoMarkUse { source, plane }
            );

            let use_record =
                FwmarkUseRecord::new(source, plane, FwmarkUseOperation::PredicateRead, 1)
                    .expect("nonzero mark use");
            assert_eq!(
                context
                    .census(complete_absent_coverage(), [use_record])
                    .expect_err("absent coverage cannot retain a use"),
                CompleteFwmarkCensusError::AbsentCoverageHasMarkUse { source, plane }
            );
        }
    }
}

#[test]
fn complete_census_bounds_raw_mark_use_evidence_at_five_hundred_twelve_records() {
    let context = TestContext::standard();
    let source = FwmarkEvidenceSource::TrafficControlAndBpf;
    let plane = FwmarkPlane::Packet;
    let mut coverage = complete_absent_coverage();
    set_coverage_state(
        &mut coverage,
        source,
        plane,
        FwmarkCensusCoverageState::CompletePresent,
    );
    let repeated_use = FwmarkUseRecord::new(source, plane, FwmarkUseOperation::MaskedWrite, 1)
        .expect("nonzero repeated use");
    let accepted_uses = vec![repeated_use; MAX_COMPLETE_FWMARK_CENSUS_MARK_USES];
    let census = context
        .census(coverage.clone(), accepted_uses)
        .expect("exactly 512 raw duplicate uses fit before canonicalization");
    assert_eq!(census.mark_uses(), [repeated_use]);

    let rejected_uses = vec![repeated_use; MAX_COMPLETE_FWMARK_CENSUS_MARK_USES + 1];
    assert_eq!(
        context
            .census(coverage, rejected_uses)
            .expect_err("the 513th raw use must be rejected before canonicalization"),
        CompleteFwmarkCensusError::TooManyMarkUseRecords {
            maximum: MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
            required_at_least: MAX_COMPLETE_FWMARK_CENSUS_MARK_USES + 1,
        }
    );
}

#[test]
fn every_overlap_fails_closed_while_the_netid_input_writer_requires_ordering_qualification() {
    for source in SOURCES {
        for plane in PLANES {
            for operation in OPERATIONS {
                let context = TestContext::standard();
                let mark_use = FwmarkUseRecord::new(source, plane, operation, CANDIDATE_MASK)
                    .expect("candidate overlap is nonzero");
                let census = context
                    .census(coverage_for_uses([mark_use]), [mark_use])
                    .expect("complete conflict census");
                let error = context
                    .authorize(census)
                    .expect_err("every kind of external overlap remains non-authorizing");
                if (source, plane, operation)
                    == (
                        FwmarkEvidenceSource::AndroidNetId,
                        FwmarkPlane::Packet,
                        FwmarkUseOperation::MaskedWrite,
                    )
                {
                    assert!(error.census_conflicts().is_empty());
                    let overlaps = error.ordered_packet_write_overlaps();
                    assert_eq!(overlaps.len(), 1);
                    assert_eq!(overlaps[0].mark_use(), mark_use);
                    assert_eq!(overlaps[0].overlap(), CANDIDATE_MASK);
                    assert_eq!(
                        overlaps[0].requirement(),
                        FwmarkOrderedPacketWriteRequirement::AndroidNetIdInputAfterRouting
                    );
                    assert!(matches!(
                        error,
                        AndroidMarkPlanningAuthorizationError::OrderedPacketWriteQualificationRequired { .. }
                    ));
                } else {
                    assert!(error.ordered_packet_write_overlaps().is_empty());
                    let conflicts = error.census_conflicts();
                    assert_eq!(conflicts.len(), 1);
                    assert_eq!(conflicts[0].mark_use(), mark_use);
                    assert_eq!(conflicts[0].overlap(), CANDIDATE_MASK);
                    assert!(matches!(
                        error,
                        AndroidMarkPlanningAuthorizationError::CensusConflict { .. }
                    ));
                }
            }
        }
    }
}

#[test]
fn definite_conflicts_precede_an_ordered_netid_packet_write() {
    let context = TestContext::standard();
    let ordered = FwmarkUseRecord::new(
        FwmarkEvidenceSource::AndroidNetId,
        FwmarkPlane::Packet,
        FwmarkUseOperation::MaskedWrite,
        CANDIDATE_MASK,
    )
    .expect("ordered packet overlap");
    let definite = FwmarkUseRecord::new(
        FwmarkEvidenceSource::Rpdb,
        FwmarkPlane::Packet,
        FwmarkUseOperation::PredicateRead,
        CANDIDATE_MASK,
    )
    .expect("definite predicate overlap");
    let census = context
        .census(coverage_for_uses([ordered, definite]), [ordered, definite])
        .expect("complete mixed-overlap census");

    let error = context
        .authorize(census)
        .expect_err("the definite conflict must win");
    assert!(matches!(
        error,
        AndroidMarkPlanningAuthorizationError::CensusConflict { .. }
    ));
    assert_eq!(error.census_conflicts().len(), 1);
    assert_eq!(error.census_conflicts()[0].mark_use(), definite);
    assert!(error.ordered_packet_write_overlaps().is_empty());
}

#[test]
fn known_android_writers_readers_xfrm_and_transfers_are_regression_covered() {
    let conflicting_uses = [
        // StrictResolver connmark flags.
        FwmarkUseRecord::new(
            FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
            FwmarkPlane::Conntrack,
            FwmarkUseOperation::PredicateRead,
            0x0300_0000,
        )
        .expect("StrictResolver flags"),
        // Current and Android 12/13 incoming-packet writers.
        FwmarkUseRecord::new(
            FwmarkEvidenceSource::LegacyXtables,
            FwmarkPlane::Packet,
            FwmarkUseOperation::MaskedWrite,
            0x7fef_ffff,
        )
        .expect("current incoming writer"),
        FwmarkUseRecord::new(
            FwmarkEvidenceSource::Nftables,
            FwmarkPlane::Packet,
            FwmarkUseOperation::MaskedWrite,
            0xffef_ffff,
        )
        .expect("Android 12/13 incoming writer"),
        // CLAT effectively reads and writes the complete packet mark.
        FwmarkUseRecord::new(
            FwmarkEvidenceSource::LegacyXtables,
            FwmarkPlane::Packet,
            FwmarkUseOperation::PredicateRead,
            u32::MAX,
        )
        .expect("CLAT full-mark read"),
        FwmarkUseRecord::new(
            FwmarkEvidenceSource::LegacyXtables,
            FwmarkPlane::Packet,
            FwmarkUseOperation::MaskedWrite,
            u32::MAX,
        )
        .expect("CLAT full-mark write"),
        // XFRM and transfer semantics are independent conflict domains.
        FwmarkUseRecord::new(
            FwmarkEvidenceSource::Xfrm,
            FwmarkPlane::Socket,
            FwmarkUseOperation::PredicateRead,
            CANDIDATE_MASK,
        )
        .expect("XFRM policy read"),
        FwmarkUseRecord::new(
            FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
            FwmarkPlane::Packet,
            FwmarkUseOperation::TransferRead,
            CANDIDATE_MASK,
        )
        .expect("packet transfer read"),
        FwmarkUseRecord::new(
            FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
            FwmarkPlane::Conntrack,
            FwmarkUseOperation::TransferWrite,
            CANDIDATE_MASK,
        )
        .expect("conntrack transfer write"),
    ];

    for mark_use in conflicting_uses {
        let context = TestContext::standard();
        let census = context
            .census(coverage_for_uses([mark_use]), [mark_use])
            .expect("complete known-use census");
        let error = context
            .authorize(census)
            .expect_err("the known mask intersects the candidate");
        assert_eq!(error.census_conflicts().len(), 1);
        assert_eq!(
            error.census_conflicts()[0].overlap(),
            mark_use.mask() & CANDIDATE_MASK
        );
    }

    // The AOSP packet-to-conntrack transfer mask is low-only. Recording that complete transfer is
    // mandatory, but it does not falsely conflict with this separately granted high candidate.
    let low_transfer = FwmarkUseRecord::new(
        FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
        FwmarkPlane::Packet,
        FwmarkUseOperation::TransferRead,
        0x000f_ffff,
    )
    .expect("AOSP packet-to-conntrack transfer mask");
    let context = TestContext::standard();
    let census = context
        .census(coverage_for_uses([low_transfer]), [low_transfer])
        .expect("complete low-transfer census");
    context
        .authorize(census)
        .expect("a fully observed disjoint transfer is not a collision");
}

#[test]
fn opaque_rpdb_evidence_rejects_even_when_the_census_claims_complete_coverage() {
    let mut fixture = profile_fixture(false);
    fixture.rules.push(with_opacity(
        RuleSpec::netd(20_500, 1_777, RuleAction::TO_TABLE)
            .family(NetworkAddressFamily::Ipv6)
            .build(),
    ));
    fixture.rules.sort_by_key(NetworkRuleRecord::priority);
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification =
        classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospAndroid13R1);
    let topology_scope = local_scope(&inventory, &classification);
    let capability_profile = verified_capability_profile(
        CapabilityProfileRevision::INITIAL,
        "01234567-89ab-cdef-0123-456789abcdef",
        SelinuxMode::Enforcing,
        namespace(10, 20),
    );
    let network_namespace = namespace(10, 20);
    let policy = cooperative_policy(
        "opaque-rpdb",
        [0x41; 32],
        AndroidMarkDevicePolicyRevision::INITIAL,
        candidate(),
        &topology_scope,
        &capability_profile,
        network_namespace,
        FwmarkPlaneSet::ALL,
    )
    .expect("synthetic policy assertion");
    let collector_revision = FwmarkCensusCollectorRevision::INITIAL;
    let journal_identity = journal_identity(0x51);
    let journal_revision = OwnershipJournalRevision::INITIAL;
    let census = census_with(
        &inventory,
        &capability_profile,
        network_namespace,
        &policy,
        collector_revision,
        journal_identity,
        journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("the external census separately asserts complete RPDB coverage");

    let error = authorize_android_mark_planning(
        &inventory,
        &classification,
        &topology_scope,
        &capability_profile,
        network_namespace,
        journal_identity,
        journal_revision,
        collector_revision,
        &policy,
        candidate(),
        census,
    )
    .expect_err("opaque core RPDB evidence cannot be overridden by the census");
    assert!(matches!(
        error,
        AndroidMarkPlanningAuthorizationError::PartialAuditEvidenceNotAvailable {
            source: FwmarkEvidenceSource::Rpdb,
            state: Some(FwmarkEvidenceState::Opaque),
            ..
        }
    ));
}

#[test]
fn census_conflict_precedes_an_otherwise_incomplete_topology_scope() {
    let mut fixture = profile_fixture(false);
    fixture.rules.push(
        RuleSpec::netd(20_500, 1_777, RuleAction::TO_TABLE)
            .input(b"other0")
            .build(),
    );
    fixture.rules.sort_by_key(NetworkRuleRecord::priority);
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification =
        classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospAndroid13R1);
    let topology_scope = local_scope(&inventory, &classification);
    assert!(matches!(
        topology_scope.structural_feasibility(),
        crate::AndroidTproxyTopologyScopeStructuralFeasibility::IncompleteEvidence { .. }
    ));
    let capability_profile = verified_capability_profile(
        CapabilityProfileRevision::INITIAL,
        "01234567-89ab-cdef-0123-456789abcdef",
        SelinuxMode::Enforcing,
        namespace(10, 20),
    );
    let network_namespace = namespace(10, 20);
    let policy = cooperative_policy(
        "incomplete-topology-conflict",
        [0x44; 32],
        AndroidMarkDevicePolicyRevision::INITIAL,
        candidate(),
        &topology_scope,
        &capability_profile,
        network_namespace,
        FwmarkPlaneSet::ALL,
    )
    .expect("synthetic policy can bind incomplete diagnostic topology evidence");
    let collector_revision = FwmarkCensusCollectorRevision::INITIAL;
    let journal_identity = journal_identity(0x54);
    let journal_revision = OwnershipJournalRevision::INITIAL;
    let mark_use = FwmarkUseRecord::new(
        FwmarkEvidenceSource::Xfrm,
        FwmarkPlane::Packet,
        FwmarkUseOperation::PredicateRead,
        CANDIDATE_MASK,
    )
    .expect("candidate conflict");
    let census = census_with(
        &inventory,
        &capability_profile,
        network_namespace,
        &policy,
        collector_revision,
        journal_identity,
        journal_revision,
        coverage_for_uses([mark_use]),
        [mark_use],
    )
    .expect("complete conflicting census");

    let error = authorize_android_mark_planning(
        &inventory,
        &classification,
        &topology_scope,
        &capability_profile,
        network_namespace,
        journal_identity,
        journal_revision,
        collector_revision,
        &policy,
        candidate(),
        census,
    )
    .expect_err("known mark conflict has precedence over incomplete topology evidence");
    assert!(matches!(
        error,
        AndroidMarkPlanningAuthorizationError::CensusConflict { .. }
    ));
    assert_eq!(error.census_conflicts()[0].mark_use(), mark_use);
}

#[test]
fn candidate_and_exact_topology_scope_are_bound_by_the_positive_grant() {
    let context = TestContext::standard();
    let changed_role_values = FwmarkCandidate::new(CANDIDATE_MASK, BYPASS_VALUE, PROXY_VALUE)
        .expect("same mask with exchanged nonzero roles");
    let role_value_census = context
        .census(complete_absent_coverage(), [])
        .expect("complete census");
    assert_eq!(
        authorize_android_mark_planning(
            &context.inventory,
            &context.classification,
            &context.topology_scope,
            &context.capability_profile,
            context.network_namespace,
            context.ownership_journal_identity,
            context.ownership_journal_revision,
            context.collector_revision,
            &context.policy,
            changed_role_values,
            role_value_census,
        )
        .expect_err("the same mask with different role values is a different candidate"),
        AndroidMarkPlanningAuthorizationError::GrantCandidateMismatch {
            granted: context.candidate,
            requested: changed_role_values,
        }
    );

    let alternate_candidate = FwmarkCandidate::new(0x0c00_0000, 0x0400_0000, 0x0800_0000)
        .expect("alternate eligible candidate");
    let census = context
        .census(complete_absent_coverage(), [])
        .expect("complete census");
    assert_eq!(
        authorize_android_mark_planning(
            &context.inventory,
            &context.classification,
            &context.topology_scope,
            &context.capability_profile,
            context.network_namespace,
            context.ownership_journal_identity,
            context.ownership_journal_revision,
            context.collector_revision,
            &context.policy,
            alternate_candidate,
            census,
        )
        .expect_err("the positive assertion binds exact candidate values and mask"),
        AndroidMarkPlanningAuthorizationError::GrantCandidateMismatch {
            granted: context.candidate,
            requested: alternate_candidate,
        }
    );

    let fixture = profile_fixture(true);
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification =
        classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospAndroid13R1);
    let local = local_scope(&inventory, &classification);
    let tether_request = AndroidTproxyTopologyScopeRequest::new(
        AndroidTproxyRoutingShape::PreMarkAddressHostSet,
        [AndroidTproxyTrafficDomainRequest::tether_ingress(
            NetworkAddressFamily::Ipv4,
            interface(b"rndis0"),
        )],
    )
    .expect("tether request");
    let tether = assess_android_tproxy_topology_scope(&inventory, &classification, &tether_request)
        .expect("trusted tether scope");
    let capability_profile = verified_capability_profile(
        CapabilityProfileRevision::INITIAL,
        "01234567-89ab-cdef-0123-456789abcdef",
        SelinuxMode::Enforcing,
        namespace(10, 20),
    );
    let network_namespace = namespace(10, 20);
    let policy = cooperative_policy(
        "topology-binding",
        [0x42; 32],
        AndroidMarkDevicePolicyRevision::INITIAL,
        candidate(),
        &local,
        &capability_profile,
        network_namespace,
        FwmarkPlaneSet::ALL,
    )
    .expect("policy bound to local scope");
    let collector_revision = FwmarkCensusCollectorRevision::INITIAL;
    let journal_identity = journal_identity(0x52);
    let journal_revision = OwnershipJournalRevision::INITIAL;
    let census = census_with(
        &inventory,
        &capability_profile,
        network_namespace,
        &policy,
        collector_revision,
        journal_identity,
        journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("complete census");
    assert_eq!(
        authorize_android_mark_planning(
            &inventory,
            &classification,
            &tether,
            &capability_profile,
            network_namespace,
            journal_identity,
            journal_revision,
            collector_revision,
            &policy,
            candidate(),
            census,
        )
        .expect_err("a different current scope cannot consume the local grant"),
        AndroidMarkPlanningAuthorizationError::GrantTopologyScopeMismatch
    );
}

#[test]
fn grant_binds_boot_namespace_and_full_capability_facts_not_only_revision() {
    let context = TestContext::standard();

    let different_boot = verified_capability_profile(
        context.capability_profile.revision(),
        "fedcba98-7654-3210-fedc-ba9876543210",
        SelinuxMode::Enforcing,
        context.network_namespace,
    );
    let boot_census = census_with(
        &context.inventory,
        &different_boot,
        context.network_namespace,
        &context.policy,
        context.collector_revision,
        context.ownership_journal_identity,
        context.ownership_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("complete current-boot census");
    assert_eq!(
        authorize_android_mark_planning(
            &context.inventory,
            &context.classification,
            &context.topology_scope,
            &different_boot,
            context.network_namespace,
            context.ownership_journal_identity,
            context.ownership_journal_revision,
            context.collector_revision,
            &context.policy,
            context.candidate,
            boot_census,
        )
        .expect_err("the grant cannot cross verified boots"),
        AndroidMarkPlanningAuthorizationError::GrantBootIdentityMismatch
    );

    for different_namespace in [namespace(10, 21), namespace(11, 20)] {
        let different_namespace_profile = verified_capability_profile(
            context.capability_profile.revision(),
            "01234567-89ab-cdef-0123-456789abcdef",
            SelinuxMode::Enforcing,
            different_namespace,
        );
        let namespace_census = census_with(
            &context.inventory,
            &different_namespace_profile,
            different_namespace,
            &context.policy,
            context.collector_revision,
            context.ownership_journal_identity,
            context.ownership_journal_revision,
            complete_absent_coverage(),
            [],
        )
        .expect("complete current-namespace census");
        assert_eq!(
            authorize_android_mark_planning(
                &context.inventory,
                &context.classification,
                &context.topology_scope,
                &different_namespace_profile,
                different_namespace,
                context.ownership_journal_identity,
                context.ownership_journal_revision,
                context.collector_revision,
                &context.policy,
                context.candidate,
                namespace_census,
            )
            .expect_err("the grant binds namespace device and inode identity"),
            AndroidMarkPlanningAuthorizationError::GrantNetworkNamespaceMismatch {
                granted: context.network_namespace,
                current: different_namespace,
            }
        );
    }

    let same_revision_different_facts = verified_capability_profile(
        context.capability_profile.revision(),
        "01234567-89ab-cdef-0123-456789abcdef",
        SelinuxMode::Permissive,
        context.network_namespace,
    );
    let capability_census = census_with(
        &context.inventory,
        &same_revision_different_facts,
        context.network_namespace,
        &context.policy,
        context.collector_revision,
        context.ownership_journal_identity,
        context.ownership_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("complete current-profile census");
    assert_eq!(
        authorize_android_mark_planning(
            &context.inventory,
            &context.classification,
            &context.topology_scope,
            &same_revision_different_facts,
            context.network_namespace,
            context.ownership_journal_identity,
            context.ownership_journal_revision,
            context.collector_revision,
            &context.policy,
            context.candidate,
            capability_census,
        )
        .expect_err("equal revisions do not make different capability facts equal"),
        AndroidMarkPlanningAuthorizationError::GrantCapabilityProfileMismatch {
            granted_revision: context.capability_profile.revision(),
            current: same_revision_different_facts.revision(),
        }
    );

    let packet_only = cooperative_policy(
        "packet-only",
        [0x43; 32],
        context.policy.revision(),
        context.candidate,
        &context.topology_scope,
        &context.capability_profile,
        context.network_namespace,
        FwmarkPlaneSet::PACKET,
    )
    .expect("a partial plane assertion is representable but insufficient");
    let partial_plane_census = census_with(
        &context.inventory,
        &context.capability_profile,
        context.network_namespace,
        &packet_only,
        context.collector_revision,
        context.ownership_journal_identity,
        context.ownership_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("complete census");
    assert_eq!(
        authorize_android_mark_planning(
            &context.inventory,
            &context.classification,
            &context.topology_scope,
            &context.capability_profile,
            context.network_namespace,
            context.ownership_journal_identity,
            context.ownership_journal_revision,
            context.collector_revision,
            &packet_only,
            context.candidate,
            partial_plane_census,
        )
        .expect_err("planning requires packet, socket, and conntrack coverage"),
        AndroidMarkPlanningAuthorizationError::GrantMissingPlanes {
            granted: FwmarkPlaneSet::PACKET,
            required: FwmarkPlaneSet::ALL,
        }
    );
}

#[test]
fn census_binds_inventory_boot_namespace_and_full_capability_profile() {
    let context = TestContext::standard();

    let unrelated_inventory = {
        let fixture = profile_fixture(false);
        make_inventory(fixture.links, fixture.rules)
    };
    let inventory_census = census_with(
        &unrelated_inventory,
        &context.capability_profile,
        context.network_namespace,
        &context.policy,
        context.collector_revision,
        context.ownership_journal_identity,
        context.ownership_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("complete but unrelated inventory census");
    assert!(matches!(
        context
            .authorize(inventory_census)
            .expect_err("equal contents do not erase inventory identity"),
        AndroidMarkPlanningAuthorizationError::CensusInventoryMismatch { .. }
    ));

    let different_boot = verified_capability_profile(
        context.capability_profile.revision(),
        "fedcba98-7654-3210-fedc-ba9876543210",
        SelinuxMode::Enforcing,
        context.network_namespace,
    );
    let boot_census = census_with(
        &context.inventory,
        &different_boot,
        context.network_namespace,
        &context.policy,
        context.collector_revision,
        context.ownership_journal_identity,
        context.ownership_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("complete census from another boot");
    assert_eq!(
        context
            .authorize(boot_census)
            .expect_err("census boot identity is exact"),
        AndroidMarkPlanningAuthorizationError::CensusBootIdentityMismatch
    );

    let different_namespace = namespace(11, 20);
    let different_namespace_profile = verified_capability_profile(
        context.capability_profile.revision(),
        "01234567-89ab-cdef-0123-456789abcdef",
        SelinuxMode::Enforcing,
        different_namespace,
    );
    let namespace_census = census_with(
        &context.inventory,
        &different_namespace_profile,
        different_namespace,
        &context.policy,
        context.collector_revision,
        context.ownership_journal_identity,
        context.ownership_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("complete census from another namespace");
    assert_eq!(
        context
            .authorize(namespace_census)
            .expect_err("census namespace identity is exact"),
        AndroidMarkPlanningAuthorizationError::CensusNetworkNamespaceMismatch {
            observed: different_namespace,
            current: context.network_namespace,
        }
    );

    let same_revision_different_facts = verified_capability_profile(
        context.capability_profile.revision(),
        "01234567-89ab-cdef-0123-456789abcdef",
        SelinuxMode::Permissive,
        context.network_namespace,
    );
    let capability_census = census_with(
        &context.inventory,
        &same_revision_different_facts,
        context.network_namespace,
        &context.policy,
        context.collector_revision,
        context.ownership_journal_identity,
        context.ownership_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("same-revision census with different facts");
    assert_eq!(
        context
            .authorize(capability_census)
            .expect_err("census binds the whole profile, not its revision number"),
        AndroidMarkPlanningAuthorizationError::CensusCapabilityProfileMismatch {
            observed_revision: same_revision_different_facts.revision(),
            current_revision: context.capability_profile.revision(),
        }
    );
}

#[test]
fn policy_collector_and_ownership_journal_bindings_are_exact() {
    let context = TestContext::standard();

    for different_identity_policy in [
        cooperative_policy_with_catalog_entry(
            "synthetic-redfin-policy-v2",
            "synthetic-cooperative-policy",
            [0x21; 32],
            context.policy.revision(),
            context.candidate,
            &context.topology_scope,
            &context.capability_profile,
            context.network_namespace,
            FwmarkPlaneSet::ALL,
        )
        .expect("policy with independently changed catalog entry"),
        cooperative_policy(
            "different-policy-name",
            [0x21; 32],
            context.policy.revision(),
            context.candidate,
            &context.topology_scope,
            &context.capability_profile,
            context.network_namespace,
            FwmarkPlaneSet::ALL,
        )
        .expect("policy with independently changed name"),
        cooperative_policy(
            "synthetic-cooperative-policy",
            [0x61; 32],
            context.policy.revision(),
            context.candidate,
            &context.topology_scope,
            &context.capability_profile,
            context.network_namespace,
            FwmarkPlaneSet::ALL,
        )
        .expect("policy with independently changed artifact digest"),
    ] {
        let identity_census = census_with(
            &context.inventory,
            &context.capability_profile,
            context.network_namespace,
            &different_identity_policy,
            context.collector_revision,
            context.ownership_journal_identity,
            context.ownership_journal_revision,
            complete_absent_coverage(),
            [],
        )
        .expect("census bound to another policy identity");
        assert_eq!(
            context.authorize(identity_census).expect_err(
                "catalog entry, policy name and artifact digest are independently exact",
            ),
            AndroidMarkPlanningAuthorizationError::CensusDevicePolicyIdentityMismatch
        );
    }

    let changed_policy_revision = AndroidMarkDevicePolicyRevision::new(2).expect("revision two");
    let same_identity_changed_revision = cooperative_policy(
        "synthetic-cooperative-policy",
        [0x21; 32],
        changed_policy_revision,
        context.candidate,
        &context.topology_scope,
        &context.capability_profile,
        context.network_namespace,
        FwmarkPlaneSet::ALL,
    )
    .expect("same identity with a changed policy revision");
    assert_eq!(
        same_identity_changed_revision.identity(),
        context.policy.identity()
    );
    let revision_census = census_with(
        &context.inventory,
        &context.capability_profile,
        context.network_namespace,
        &same_identity_changed_revision,
        context.collector_revision,
        context.ownership_journal_identity,
        context.ownership_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("census bound to a newer policy revision");
    assert_eq!(
        context
            .authorize(revision_census)
            .expect_err("equal policy identity does not erase a revision change"),
        AndroidMarkPlanningAuthorizationError::CensusDevicePolicyRevisionMismatch {
            observed: changed_policy_revision,
            current: context.policy.revision(),
        }
    );

    let changed_collector_revision =
        FwmarkCensusCollectorRevision::new(2).expect("collector revision two");
    let collector_census = census_with(
        &context.inventory,
        &context.capability_profile,
        context.network_namespace,
        &context.policy,
        changed_collector_revision,
        context.ownership_journal_identity,
        context.ownership_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("census from a different collector grammar");
    assert_eq!(
        context
            .authorize(collector_census)
            .expect_err("collector grammar revision is exact"),
        AndroidMarkPlanningAuthorizationError::CensusCollectorRevisionMismatch {
            observed: changed_collector_revision,
            current: context.collector_revision,
        }
    );

    let changed_journal_identity = journal_identity(0x72);
    let journal_identity_census = census_with(
        &context.inventory,
        &context.capability_profile,
        context.network_namespace,
        &context.policy,
        context.collector_revision,
        changed_journal_identity,
        context.ownership_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("same-revision census from a different journal artifact");
    assert_eq!(
        context
            .authorize(journal_identity_census)
            .expect_err("same revision does not erase journal identity"),
        AndroidMarkPlanningAuthorizationError::CensusOwnershipJournalIdentityMismatch {
            observed: changed_journal_identity,
            current: context.ownership_journal_identity,
        }
    );

    let changed_journal_revision = OwnershipJournalRevision::new(2).expect("journal revision two");
    let journal_revision_census = census_with(
        &context.inventory,
        &context.capability_profile,
        context.network_namespace,
        &context.policy,
        context.collector_revision,
        context.ownership_journal_identity,
        changed_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("census from a newer journal revision");
    assert_eq!(
        context
            .authorize(journal_revision_census)
            .expect_err("journal revision is exact"),
        AndroidMarkPlanningAuthorizationError::CensusOwnershipJournalRevisionMismatch {
            observed: changed_journal_revision,
            current: context.ownership_journal_revision,
        }
    );
}

#[test]
fn stale_topology_scope_is_rejected_even_when_an_identical_dump_is_recollected() {
    let context = TestContext::standard();
    let fixture = profile_fixture(false);
    let current_inventory = make_inventory(fixture.links, fixture.rules);
    let current_classification = classify_android_rpdb(
        &current_inventory,
        AndroidNetdSourceProfile::AospAndroid13R1,
    );
    let census = census_with(
        &current_inventory,
        &context.capability_profile,
        context.network_namespace,
        &context.policy,
        context.collector_revision,
        context.ownership_journal_identity,
        context.ownership_journal_revision,
        complete_absent_coverage(),
        [],
    )
    .expect("census from the recollected inventory");
    assert!(matches!(
        authorize_android_mark_planning(
            &current_inventory,
            &current_classification,
            &context.topology_scope,
            &context.capability_profile,
            context.network_namespace,
            context.ownership_journal_identity,
            context.ownership_journal_revision,
            context.collector_revision,
            &context.policy,
            context.candidate,
            census,
        )
        .expect_err("content equality cannot refresh a scope observation"),
        AndroidMarkPlanningAuthorizationError::StaleTopologyScope(_)
    ));
}

#[test]
fn synthetic_cooperative_policy_yields_read_only_planning_authority_and_separate_gaps() {
    let context = TestContext::standard();
    let census = context
        .census(complete_absent_coverage(), [])
        .expect("complete conflict-free census");
    let census_observation = census.observation_id();
    let authority = context
        .authorize(census)
        .expect("all positive synthetic evidence is exact and current");

    assert_eq!(authority.candidate(), context.candidate);
    assert_eq!(authority.topology_scope(), &context.topology_scope);
    assert_eq!(authority.capability_profile(), &context.capability_profile);
    assert_eq!(
        authority.boot_identity(),
        context
            .capability_profile
            .boot_identity()
            .verified()
            .expect("verified fixture boot")
    );
    assert_eq!(authority.network_namespace(), context.network_namespace);
    assert_eq!(authority.policy_identity(), context.policy.identity());
    assert_eq!(authority.policy_revision(), context.policy.revision());
    assert_eq!(authority.planes(), FwmarkPlaneSet::ALL);
    assert_eq!(authority.census().observation_id(), census_observation);
    assert_eq!(
        authority.census_collector_revision(),
        context.collector_revision
    );
    assert_eq!(
        authority.ownership_journal_identity(),
        context.ownership_journal_identity
    );
    assert_eq!(
        authority.ownership_journal_revision(),
        context.ownership_journal_revision
    );
    assert_eq!(
        authority.partial_audit().outcome(),
        FwmarkPartialAuditOutcome::Incomplete
    );
    for source in [
        FwmarkEvidenceSource::AndroidNetId,
        FwmarkEvidenceSource::Rpdb,
    ] {
        assert_eq!(
            authority
                .partial_audit()
                .sources()
                .iter()
                .find(|status| status.source() == source)
                .expect("required partial source")
                .state(),
            FwmarkEvidenceState::Available
        );
    }

    assert_eq!(
        authority.deferred_mark_activation_prerequisites(),
        [
            DeferredAndroidMarkActivationPrerequisite::ExactWriterSemantics,
            DeferredAndroidMarkActivationPrerequisite::ObserverContinuity,
            DeferredAndroidMarkActivationPrerequisite::MarkPreservationCanary,
        ]
    );
    assert_eq!(
        authority.topology_deferred_prerequisites(),
        [
            DeferredAndroidTproxyPrerequisite::OneRuleAddressHandling,
            DeferredAndroidTproxyPrerequisite::ExactCaptureOrdering,
            DeferredAndroidTproxyPrerequisite::DomainIdentityHandoff,
            DeferredAndroidTproxyPrerequisite::NetworkSelectionHandoff,
            DeferredAndroidTproxyPrerequisite::RouteReachabilityCanary,
            DeferredAndroidTproxyPrerequisite::ObserverContinuity,
            DeferredAndroidTproxyPrerequisite::DurableOwnershipJournal,
            DeferredAndroidTproxyPrerequisite::ExactMutationIdentity,
            DeferredAndroidTproxyPrerequisite::EngineLoopEscape,
        ]
    );
    assert!(
        !authority
            .topology_deferred_prerequisites()
            .contains(&DeferredAndroidTproxyPrerequisite::PositiveMarkAuthority)
    );
    assert!(
        !authority
            .topology_deferred_prerequisites()
            .contains(&DeferredAndroidTproxyPrerequisite::BootAndNamespaceBinding)
    );
}

#[test]
fn planning_evidence_digest_binds_census_observation_and_canonical_contents() {
    let context = TestContext::standard();
    let first = context
        .authorize(
            context
                .census(complete_absent_coverage(), [])
                .expect("first complete census"),
        )
        .expect("first planning authority");
    let repeated_digest = first.evidence_digest();
    assert_eq!(repeated_digest, first.evidence_digest());

    let fresh = context
        .authorize(
            context
                .census(complete_absent_coverage(), [])
                .expect("fresh complete census"),
        )
        .expect("fresh planning authority");
    assert_ne!(
        first.census().observation_id(),
        fresh.census().observation_id()
    );
    assert_ne!(repeated_digest, fresh.evidence_digest());

    let observed_use = FwmarkUseRecord::new(
        FwmarkEvidenceSource::LegacyXtables,
        FwmarkPlane::Packet,
        FwmarkUseOperation::PredicateRead,
        0x0000_0001,
    )
    .expect("nonempty nonoverlapping mark use");
    let changed = context
        .authorize(
            context
                .census(coverage_for_uses([observed_use]), [observed_use])
                .expect("complete census with canonical mark use"),
        )
        .expect("changed planning authority");
    assert_ne!(fresh.evidence_digest(), changed.evidence_digest());
}

#[test]
fn reauthorization_consumes_authority_and_requires_a_fresh_census_observation() {
    let context = TestContext::standard();
    let first_census = context
        .census(complete_absent_coverage(), [])
        .expect("first complete census");
    let first_observation = first_census.observation_id();
    let authority = context
        .authorize(first_census)
        .expect("first planning authority");

    let replacement_census = context
        .census(complete_absent_coverage(), [])
        .expect("fresh replacement census");
    let replacement_observation = replacement_census.observation_id();
    assert_ne!(first_observation, replacement_observation);
    let replacement = authority
        .reauthorize(
            &context.inventory,
            &context.classification,
            &context.topology_scope,
            &context.capability_profile,
            context.network_namespace,
            context.ownership_journal_identity,
            context.ownership_journal_revision,
            context.collector_revision,
            &context.policy,
            replacement_census,
        )
        .expect("fresh current evidence reauthorizes the consumed planning authority");
    assert_eq!(
        replacement.census().observation_id(),
        replacement_observation
    );
    assert_eq!(replacement.candidate(), context.candidate);

    let stale_context = TestContext::standard();
    let older_census = stale_context
        .census(complete_absent_coverage(), [])
        .expect("older complete census");
    let older_observation = older_census.observation_id();
    let newer_census = stale_context
        .census(complete_absent_coverage(), [])
        .expect("newer complete census");
    let newer_observation = newer_census.observation_id();
    assert!(older_observation < newer_observation);
    let authority = stale_context
        .authorize(newer_census)
        .expect("authority from the newer census");
    assert_eq!(
        authority
            .reauthorize(
                &stale_context.inventory,
                &stale_context.classification,
                &stale_context.topology_scope,
                &stale_context.capability_profile,
                stale_context.network_namespace,
                stale_context.ownership_journal_identity,
                stale_context.ownership_journal_revision,
                stale_context.collector_revision,
                &stale_context.policy,
                older_census,
            )
            .expect_err("an older unused observation is not a fresh replacement"),
        AndroidMarkPlanningAuthorizationError::NonFreshCensusObservation {
            previous_observation_id: newer_observation,
            replacement_observation_id: older_observation,
        }
    );
}

#[test]
fn census_rejects_unverified_boot_identity_at_its_trust_boundary() {
    let context = TestContext::standard();
    let unverified = CapabilityProfile::new(
        CapabilityProfileRevision::INITIAL,
        Observation::Absent,
        Observation::Verified(verified_device_identity(namespace(10, 20))),
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new("5.10.198-android13-gki").expect("kernel release"),
        )),
        Observation::Verified(SelinuxMode::Enforcing),
        ready_legacy_bridge(),
    );
    assert!(matches!(
        census_with(
            &context.inventory,
            &unverified,
            context.network_namespace,
            &context.policy,
            context.collector_revision,
            context.ownership_journal_identity,
            context.ownership_journal_revision,
            complete_absent_coverage(),
            [],
        )
        .expect_err("a census cannot self-assert an unverified boot"),
        CompleteFwmarkCensusError::UnverifiedBootIdentity { .. }
    ));
}

struct TestContext {
    inventory: NetworkInventory,
    classification: AndroidRpdbClassificationReport,
    topology_scope: AndroidTproxyTopologyScopeReport,
    capability_profile: CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    policy: AndroidMarkDevicePolicy,
    candidate: FwmarkCandidate,
    collector_revision: FwmarkCensusCollectorRevision,
    ownership_journal_identity: OwnershipJournalIdentity,
    ownership_journal_revision: OwnershipJournalRevision,
}

impl TestContext {
    fn standard() -> Self {
        let fixture = profile_fixture(false);
        let inventory = make_inventory(fixture.links, fixture.rules);
        let classification =
            classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospAndroid13R1);
        let topology_scope = local_scope(&inventory, &classification);
        let network_namespace = namespace(10, 20);
        let capability_profile = verified_capability_profile(
            CapabilityProfileRevision::INITIAL,
            "01234567-89ab-cdef-0123-456789abcdef",
            SelinuxMode::Enforcing,
            network_namespace,
        );
        let candidate = candidate();
        let policy = cooperative_policy(
            "synthetic-cooperative-policy",
            [0x21; 32],
            AndroidMarkDevicePolicyRevision::INITIAL,
            candidate,
            &topology_scope,
            &capability_profile,
            network_namespace,
            FwmarkPlaneSet::ALL,
        )
        .expect("valid synthetic cooperative policy");
        Self {
            inventory,
            classification,
            topology_scope,
            capability_profile,
            network_namespace,
            policy,
            candidate,
            collector_revision: FwmarkCensusCollectorRevision::INITIAL,
            ownership_journal_identity: journal_identity(0x71),
            ownership_journal_revision: OwnershipJournalRevision::INITIAL,
        }
    }

    fn census(
        &self,
        coverage: impl IntoIterator<Item = FwmarkCensusCoverageRecord>,
        mark_uses: impl IntoIterator<Item = FwmarkUseRecord>,
    ) -> Result<CompleteFwmarkCensus, CompleteFwmarkCensusError> {
        census_with(
            &self.inventory,
            &self.capability_profile,
            self.network_namespace,
            &self.policy,
            self.collector_revision,
            self.ownership_journal_identity,
            self.ownership_journal_revision,
            coverage,
            mark_uses,
        )
    }

    fn authorize(
        &self,
        census: CompleteFwmarkCensus,
    ) -> Result<crate::AndroidMarkPlanningAuthority, AndroidMarkPlanningAuthorizationError> {
        authorize_android_mark_planning(
            &self.inventory,
            &self.classification,
            &self.topology_scope,
            &self.capability_profile,
            self.network_namespace,
            self.ownership_journal_identity,
            self.ownership_journal_revision,
            self.collector_revision,
            &self.policy,
            self.candidate,
            census,
        )
    }
}

fn candidate() -> FwmarkCandidate {
    FwmarkCandidate::new(CANDIDATE_MASK, PROXY_VALUE, BYPASS_VALUE)
        .expect("structurally valid high-bit candidate")
}

#[allow(clippy::too_many_arguments)]
fn cooperative_policy(
    name: &str,
    digest: [u8; 32],
    revision: AndroidMarkDevicePolicyRevision,
    candidate: FwmarkCandidate,
    topology_scope: &AndroidTproxyTopologyScopeReport,
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    planes: FwmarkPlaneSet,
) -> Result<AndroidMarkDevicePolicy, AndroidMarkDevicePolicyError> {
    cooperative_policy_with_catalog_entry(
        "synthetic-redfin-policy-v1",
        name,
        digest,
        revision,
        candidate,
        topology_scope,
        capability_profile,
        network_namespace,
        planes,
    )
}

#[allow(clippy::too_many_arguments)]
fn cooperative_policy_with_catalog_entry(
    catalog_entry: &str,
    name: &str,
    digest: [u8; 32],
    revision: AndroidMarkDevicePolicyRevision,
    candidate: FwmarkCandidate,
    topology_scope: &AndroidTproxyTopologyScopeReport,
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    planes: FwmarkPlaneSet,
) -> Result<AndroidMarkDevicePolicy, AndroidMarkDevicePolicyError> {
    AndroidMarkDevicePolicy::device_qualified_cooperative(
        ReviewedPolicyCatalogEntryId::new(catalog_entry).expect("valid test catalog entry ID"),
        AndroidMarkDevicePolicyName::new(name).expect("valid test policy name"),
        revision,
        AndroidMarkDevicePolicyArtifactDigest::new(digest).expect("nonzero artifact digest"),
        candidate,
        topology_scope,
        capability_profile,
        network_namespace,
        planes,
    )
}

#[allow(clippy::too_many_arguments)]
fn census_with(
    inventory: &NetworkInventory,
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    policy: &AndroidMarkDevicePolicy,
    collector_revision: FwmarkCensusCollectorRevision,
    ownership_journal_identity: OwnershipJournalIdentity,
    ownership_journal_revision: OwnershipJournalRevision,
    coverage: impl IntoIterator<Item = FwmarkCensusCoverageRecord>,
    mark_uses: impl IntoIterator<Item = FwmarkUseRecord>,
) -> Result<CompleteFwmarkCensus, CompleteFwmarkCensusError> {
    CompleteFwmarkCensus::from_complete_observation(
        inventory,
        capability_profile,
        network_namespace,
        policy.identity(),
        policy.revision(),
        collector_revision,
        ownership_journal_identity,
        ownership_journal_revision,
        coverage,
        mark_uses,
    )
}

fn complete_absent_coverage() -> Vec<FwmarkCensusCoverageRecord> {
    SOURCES
        .into_iter()
        .flat_map(|source| {
            PLANES.into_iter().map(move |plane| {
                FwmarkCensusCoverageRecord::new(
                    source,
                    plane,
                    FwmarkCensusCoverageState::CompleteAbsent,
                )
            })
        })
        .collect()
}

fn coverage_for_uses(
    mark_uses: impl IntoIterator<Item = FwmarkUseRecord>,
) -> Vec<FwmarkCensusCoverageRecord> {
    let mut coverage = complete_absent_coverage();
    for mark_use in mark_uses {
        set_coverage_state(
            &mut coverage,
            mark_use.source(),
            mark_use.plane(),
            FwmarkCensusCoverageState::CompletePresent,
        );
    }
    coverage
}

fn set_coverage_state(
    coverage: &mut [FwmarkCensusCoverageRecord],
    source: FwmarkEvidenceSource,
    plane: FwmarkPlane,
    state: FwmarkCensusCoverageState,
) {
    let record = coverage
        .iter_mut()
        .find(|record| record.source() == source && record.plane() == plane)
        .expect("complete fixture contains every source-plane pair");
    *record = FwmarkCensusCoverageRecord::new(source, plane, state);
}

fn local_scope(
    inventory: &NetworkInventory,
    classification: &AndroidRpdbClassificationReport,
) -> AndroidTproxyTopologyScopeReport {
    let request = AndroidTproxyTopologyScopeRequest::new(
        AndroidTproxyRoutingShape::PreMarkAddressHostSet,
        [AndroidTproxyTrafficDomainRequest::residual_local_output(
            NetworkAddressFamily::Ipv4,
        )],
    )
    .expect("valid local-output request");
    assess_android_tproxy_topology_scope(inventory, classification, &request)
        .expect("trusted residual local-output scope")
}

fn verified_capability_profile(
    revision: CapabilityProfileRevision,
    boot_identity: &str,
    selinux: SelinuxMode,
    network_namespace: NetworkNamespaceIdentity,
) -> CapabilityProfile {
    CapabilityProfile::new(
        revision,
        Observation::Verified(BootIdentity::parse(boot_identity).expect("valid boot identity")),
        Observation::Verified(verified_device_identity(network_namespace)),
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new("5.10.198-android13-gki").expect("bounded kernel release"),
        )),
        Observation::Verified(selinux),
        ready_legacy_bridge(),
    )
}

fn ready_legacy_bridge() -> LegacyBridgeFacts {
    let ready = Observation::Verified(LegacyArtifactReadiness::new(
        LegacyArtifactResolution::Direct,
        true,
    ));
    let bridge = LegacyBridgeFacts::new(ready.clone(), ready.clone(), ready);
    assert_eq!(bridge.mutation_writer(), LegacyMutationWriter::Dispatcher);
    assert_eq!(bridge.rule_backend(), LegacyRuleBackend::IptablesRestore);
    assert_eq!(
        bridge.address_synchronization(),
        LegacyAddressSynchronization::StandaloneAddrsyncdViaScript
    );
    bridge
}

fn namespace(device: u64, inode: u64) -> NetworkNamespaceIdentity {
    NetworkNamespaceIdentity::new(device, inode).expect("nonzero namespace inode")
}

fn verified_device_identity(network_namespace: NetworkNamespaceIdentity) -> DeviceIdentity {
    DeviceIdentity::new(
        AndroidProductIdentity::new("google/redfin/redfin").expect("product identity"),
        AndroidBuildIdentity::new("google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys")
            .expect("Android build identity"),
        VendorBuildIdentity::new("google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys")
            .expect("vendor build identity"),
        SecurityPatchLevel::new("2023-08-05").expect("security patch level"),
        VerifiedBootIdentity::new(
            VerifiedBootState::Green,
            true,
            Sha256Digest::new([0x11; 32]).expect("vbmeta digest"),
        ),
        KernelBuildIdentity::new("5.10.198-android13-gki synthetic-build")
            .expect("kernel build identity"),
        SelinuxPolicyIdentity::from(artifact(0x21, 4_096)),
        artifact(0x22, 8_192),
        artifact(0x23, 16_384),
        [(
            ToolId::new("fluxd").expect("tool identity"),
            artifact(0x24, 32_768),
        )],
        network_namespace,
    )
    .expect("complete device identity")
}

fn artifact(byte: u8, size: u64) -> ArtifactIdentity {
    ArtifactIdentity::new(
        Sha256Digest::new([byte; 32]).expect("nonzero artifact digest"),
        size,
    )
    .expect("nonempty artifact")
}

fn journal_identity(byte: u8) -> OwnershipJournalIdentity {
    OwnershipJournalIdentity::new([byte; 32]).expect("nonzero journal identity")
}

fn profile_fixture(tether: bool) -> Fixture {
    let family = NetworkAddressFamily::Ipv4;
    let mut rules = skeleton_for(family);
    if tether {
        rules.push(
            RuleSpec::netd(21_000, 1_005, RuleAction::TO_TABLE)
                .input(b"rndis0")
                .build(),
        );
    }
    rules.push(default_network_for(family));
    rules.sort_by_key(NetworkRuleRecord::priority);

    let mut links = vec![link(
        1,
        b"lo",
        InterfaceLinkFlags::UP | InterfaceLinkFlags::LOOPBACK,
    )];
    if tether {
        links.push(link(2, b"rndis0", InterfaceLinkFlags::UP));
    }
    Fixture { links, rules }
}

fn skeleton_for(family: NetworkAddressFamily) -> Vec<NetworkRuleRecord> {
    let rules = vec![
        {
            let mut spec = RuleSpec::netd(0, 255, RuleAction::TO_TABLE);
            spec.protocol = 2;
            spec.build()
        },
        RuleSpec::netd(10_000, 99, RuleAction::TO_TABLE)
            .mark(SYSTEM_PERMISSION, EXPLICIT_NETWORK | SYSTEM_PERMISSION)
            .build(),
        RuleSpec::netd(16_000, 97, RuleAction::TO_TABLE)
            .mark(99 | EXPLICIT_NETWORK, NET_ID_MASK | EXPLICIT_NETWORK)
            .input(b"lo")
            .build(),
        RuleSpec::netd(18_000, 99, RuleAction::TO_TABLE)
            .mark(0, EXPLICIT_NETWORK)
            .build(),
        RuleSpec::netd(19_000, 98, RuleAction::TO_TABLE)
            .mark(0, EXPLICIT_NETWORK)
            .build(),
        RuleSpec::netd(20_000, 97, RuleAction::TO_TABLE)
            .mark(0, EXPLICIT_NETWORK)
            .build(),
        RuleSpec::netd(32_000, 0, RuleAction::UNREACHABLE).build(),
    ];
    debug_assert!(
        rules
            .iter()
            .all(|rule| rule.destination().family() == family)
    );
    rules
}

fn default_network_for(_family: NetworkAddressFamily) -> NetworkRuleRecord {
    RuleSpec::netd(31_000, DEFAULT_NETWORK_TABLE, RuleAction::TO_TABLE)
        .mark(NETWORK_PERMISSION, NET_ID_MASK | NETWORK_PERMISSION)
        .input(b"lo")
        .build()
}

fn make_inventory(
    links: impl IntoIterator<Item = InterfaceLinkRecord>,
    rules: impl IntoIterator<Item = NetworkRuleRecord>,
) -> NetworkInventory {
    let mut tracker = NetworkInventoryTracker::new();
    tracker
        .publish_complete_with_routing(links, [], [], rules)
        .expect("valid complete topology fixture")
        .clone()
}

fn link(index: u32, name: &[u8], flags: InterfaceLinkFlags) -> InterfaceLinkRecord {
    InterfaceLinkRecord::new(
        InterfaceIndex::new(index).expect("positive interface index"),
        interface(name),
        InterfaceHardwareType::from_raw(1),
        flags,
    )
}

fn interface(name: &[u8]) -> InterfaceName {
    InterfaceName::new(name).expect("valid interface name")
}

fn with_opacity(rule: NetworkRuleRecord) -> NetworkRuleRecord {
    rule.with_attribute_opacity(
        RuleAttributeOpacity::new(
            [OpaqueRuleAttribute::new(25, 0, 4)],
            0,
            RuleOpaqueAttributeFingerprint::from_bytes([0x25; 32]),
        )
        .expect("bounded opacity evidence"),
    )
}

struct Fixture {
    links: Vec<InterfaceLinkRecord>,
    rules: Vec<NetworkRuleRecord>,
}

#[derive(Clone)]
struct RuleSpec {
    destination: RulePrefix,
    source: RulePrefix,
    table: u32,
    action: RuleAction,
    protocol: u8,
    priority: u32,
    fwmark: Option<RuleFwMark>,
    input: Option<InterfaceName>,
}

impl RuleSpec {
    fn netd(priority: u32, table: u32, action: RuleAction) -> Self {
        Self {
            destination: RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
            source: RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
            table,
            action,
            protocol: 0,
            priority,
            fwmark: None,
            input: None,
        }
    }

    fn mark(mut self, value: u32, mask: u32) -> Self {
        self.fwmark = RuleFwMark::new(value, mask);
        self
    }

    fn family(mut self, family: NetworkAddressFamily) -> Self {
        self.destination = RulePrefix::unspecified(family);
        self.source = RulePrefix::unspecified(family);
        self
    }

    fn input(mut self, name: &[u8]) -> Self {
        self.input = Some(interface(name));
        self
    }

    fn build(self) -> NetworkRuleRecord {
        let mut record = NetworkRuleRecord::new(
            self.destination,
            self.source,
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
        .expect("valid rule fixture");
        if let Some(fwmark) = self.fwmark {
            record = record.with_fwmark(fwmark);
        }
        if let Some(input) = self.input {
            record = record.with_input_interface(input);
        }
        record
    }
}
