use flux_core::{
    ANDROID_NET_ID_FWMARK_MASK, DeferredFwmarkPrerequisite, FwmarkCandidate, FwmarkCandidateError,
    FwmarkEvidenceSource, FwmarkEvidenceState, FwmarkPartialAuditOutcome, FwmarkPartialConflict,
    FwmarkRole, MAX_FWMARK_PARTIAL_CONFLICTS, NetworkAddressFamily, NetworkInventory,
    NetworkInventoryTracker, NetworkRuleRecord, OpaqueRuleAttribute, RuleAction,
    RuleAttributeOpacity, RuleFlags, RuleFwMark, RuleOpaqueAttributeFingerprint, RulePrefix,
    RulePriority, RuleProperties, RuleProtocol, RuleTableId, audit_fwmark_candidate_partial,
};

const CANDIDATE_MASK: u32 = 0x0300_0000;
const PROXY_VALUE: u32 = 0x0100_0000;
const BYPASS_VALUE: u32 = 0x0200_0000;

#[test]
fn candidate_reserves_zero_and_merges_only_its_common_mask() {
    let candidate = candidate();
    assert_eq!(candidate.mask(), CANDIDATE_MASK);
    assert_eq!(candidate.proxy_value(), PROXY_VALUE);
    assert_eq!(candidate.bypass_value(), BYPASS_VALUE);
    assert_eq!(
        candidate.selector(FwmarkRole::Proxy),
        RuleFwMark::new(PROXY_VALUE, CANDIDATE_MASK).expect("proxy selector")
    );
    assert_eq!(
        candidate.selector(FwmarkRole::Bypass),
        RuleFwMark::new(BYPASS_VALUE, CANDIDATE_MASK).expect("bypass selector")
    );

    for existing in [0, u32::MAX, 0xa5a5_5a5a, 0x0123_4567] {
        for (role, expected_value) in [
            (FwmarkRole::Proxy, PROXY_VALUE),
            (FwmarkRole::Bypass, BYPASS_VALUE),
        ] {
            let merged = candidate.merge(existing, role);
            assert_eq!(merged & !CANDIDATE_MASK, existing & !CANDIDATE_MASK);
            assert_eq!(merged & CANDIDATE_MASK, expected_value);
            assert_eq!(candidate.merge(merged, role), merged);
        }
    }

    assert_eq!(
        FwmarkCandidate::new(0, 1, 2).expect_err("empty field"),
        FwmarkCandidateError::EmptyMask
    );
    assert_eq!(
        FwmarkCandidate::new(CANDIDATE_MASK, PROXY_VALUE | 1, BYPASS_VALUE)
            .expect_err("proxy has an outside bit"),
        FwmarkCandidateError::ValueOutsideMask {
            role: FwmarkRole::Proxy,
            value: PROXY_VALUE | 1,
            mask: CANDIDATE_MASK,
        }
    );
    assert_eq!(
        FwmarkCandidate::new(CANDIDATE_MASK, PROXY_VALUE, BYPASS_VALUE | 1)
            .expect_err("bypass has an outside bit"),
        FwmarkCandidateError::ValueOutsideMask {
            role: FwmarkRole::Bypass,
            value: BYPASS_VALUE | 1,
            mask: CANDIDATE_MASK,
        }
    );
    assert_eq!(
        FwmarkCandidate::new(CANDIDATE_MASK, 0, BYPASS_VALUE)
            .expect_err("zero is unclassified, not proxy"),
        FwmarkCandidateError::ZeroRoleValue {
            role: FwmarkRole::Proxy,
        }
    );
    assert_eq!(
        FwmarkCandidate::new(CANDIDATE_MASK, PROXY_VALUE, 0)
            .expect_err("zero is unclassified, not bypass"),
        FwmarkCandidateError::ZeroRoleValue {
            role: FwmarkRole::Bypass,
        }
    );
    assert_eq!(
        FwmarkCandidate::new(CANDIDATE_MASK, PROXY_VALUE, PROXY_VALUE)
            .expect_err("roles must remain distinct"),
        FwmarkCandidateError::DuplicateRoleValue { value: PROXY_VALUE }
    );

    for proxy in [0, 1] {
        for bypass in [0, 1] {
            assert!(
                FwmarkCandidate::new(1, proxy, bypass).is_err(),
                "one bit cannot encode two distinct nonzero roles"
            );
        }
    }
}

#[test]
fn conflict_free_rpdb_evidence_remains_explicitly_incomplete() {
    let inventory = inventory([]);
    let audit = audit_fwmark_candidate_partial(&inventory, candidate());

    assert_eq!(audit.snapshot_id(), inventory.snapshot_id());
    assert_eq!(audit.epoch(), inventory.epoch());
    assert_eq!(audit.candidate(), candidate());
    assert_eq!(audit.outcome(), FwmarkPartialAuditOutcome::Incomplete);
    assert!(audit.conflicts().is_empty());
    assert_eq!(audit.omitted_conflicts(), 0);
    assert_eq!(
        audit
            .sources()
            .iter()
            .copied()
            .map(|status| (status.source(), status.state()))
            .collect::<Vec<_>>(),
        [
            (
                FwmarkEvidenceSource::AndroidNetId,
                FwmarkEvidenceState::Available,
            ),
            (FwmarkEvidenceSource::Rpdb, FwmarkEvidenceState::Available,),
            (
                FwmarkEvidenceSource::DeviceMarkPolicy,
                FwmarkEvidenceState::Unavailable,
            ),
            (
                FwmarkEvidenceSource::LegacyXtables,
                FwmarkEvidenceState::Unavailable,
            ),
            (
                FwmarkEvidenceSource::Nftables,
                FwmarkEvidenceState::Unavailable,
            ),
            (
                FwmarkEvidenceSource::TrafficControlAndBpf,
                FwmarkEvidenceState::Unavailable,
            ),
            (FwmarkEvidenceSource::Xfrm, FwmarkEvidenceState::Unavailable,),
            (
                FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
                FwmarkEvidenceState::Unavailable,
            ),
            (
                FwmarkEvidenceSource::ExistingFluxOwnership,
                FwmarkEvidenceState::Unavailable,
            ),
        ]
    );
    assert_eq!(
        audit.deferred_prerequisites(),
        [
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
        ]
    );
    audit
        .ensure_current(&inventory)
        .expect("same inventory snapshot");
}

#[test]
fn legacy_low_byte_mask_has_a_definite_android_net_id_conflict() {
    let inventory = inventory([]);
    let legacy = FwmarkCandidate::new(0xff, 0x14, 0x11).expect("legacy values are structural");
    let audit = audit_fwmark_candidate_partial(&inventory, legacy);

    assert_eq!(audit.outcome(), FwmarkPartialAuditOutcome::Conflicting);
    assert_eq!(
        audit.conflicts(),
        [FwmarkPartialConflict::AndroidNetIdOverlap { overlap: 0xff }]
    );
    assert_eq!(ANDROID_NET_ID_FWMARK_MASK, 0x0000_ffff);
}

#[test]
fn rpdb_mask_overlap_rejects_exact_different_and_inverted_selectors_in_dump_order() {
    let exact = marked_rule(
        NetworkAddressFamily::Ipv4,
        100,
        PROXY_VALUE,
        CANDIDATE_MASK,
        RuleAction::TO_TABLE,
        RuleFlags::default(),
    );
    let different = marked_rule(
        NetworkAddressFamily::Ipv6,
        200,
        CANDIDATE_MASK,
        CANDIDATE_MASK,
        RuleAction::TO_TABLE,
        RuleFlags::default(),
    );
    let inverted_unknown = marked_rule(
        NetworkAddressFamily::Ipv4,
        300,
        BYPASS_VALUE,
        CANDIDATE_MASK,
        RuleAction::from_raw(250),
        RuleFlags::INVERT,
    );
    let zero_value = marked_rule(
        NetworkAddressFamily::Ipv6,
        400,
        0,
        CANDIDATE_MASK,
        RuleAction::TO_TABLE,
        RuleFlags::default(),
    );
    let partial_mask = marked_rule(
        NetworkAddressFamily::Ipv4,
        500,
        PROXY_VALUE,
        PROXY_VALUE,
        RuleAction::TO_TABLE,
        RuleFlags::default(),
    );
    let duplicate = exact.clone();
    let inventory = inventory([
        exact.clone(),
        different.clone(),
        inverted_unknown.clone(),
        duplicate,
        zero_value.clone(),
        partial_mask.clone(),
    ]);

    let audit = audit_fwmark_candidate_partial(&inventory, candidate());
    assert_eq!(audit.outcome(), FwmarkPartialAuditOutcome::Conflicting);
    assert_eq!(audit.omitted_conflicts(), 0);
    assert_eq!(audit.conflicts().len(), 6);
    for (position, (expected_rule, expected_family, expected_priority)) in [
        (exact, NetworkAddressFamily::Ipv4, 100),
        (different, NetworkAddressFamily::Ipv6, 200),
        (inverted_unknown, NetworkAddressFamily::Ipv4, 300),
        (
            marked_rule(
                NetworkAddressFamily::Ipv4,
                100,
                PROXY_VALUE,
                CANDIDATE_MASK,
                RuleAction::TO_TABLE,
                RuleFlags::default(),
            ),
            NetworkAddressFamily::Ipv4,
            100,
        ),
        (zero_value, NetworkAddressFamily::Ipv6, 400),
        (partial_mask, NetworkAddressFamily::Ipv4, 500),
    ]
    .into_iter()
    .enumerate()
    {
        let expected_selector = expected_rule.fwmark().expect("marked rule");
        assert_eq!(
            audit.conflicts()[position],
            FwmarkPartialConflict::RpdbSelectorOverlap {
                dump_index: position,
                family: expected_family,
                priority: RulePriority::from_raw(expected_priority),
                selector: expected_selector,
                overlap: CANDIDATE_MASK & expected_selector.mask(),
            }
        );
    }
}

#[test]
fn disjoint_or_absent_rpdb_selectors_do_not_turn_incomplete_evidence_into_success() {
    let disjoint = marked_rule(
        NetworkAddressFamily::Ipv4,
        100,
        0x0400_0000,
        0x0c00_0000,
        RuleAction::TO_TABLE,
        RuleFlags::default(),
    );
    let unmarked = unmarked_rule(NetworkAddressFamily::Ipv6, 200);
    let inventory = inventory([disjoint, unmarked]);

    let audit = audit_fwmark_candidate_partial(&inventory, candidate());
    assert_eq!(audit.outcome(), FwmarkPartialAuditOutcome::Incomplete);
    assert!(audit.conflicts().is_empty());
}

#[test]
fn opaque_rpdb_attributes_downgrade_source_evidence_without_hiding_known_conflicts() {
    let opaque_unmarked = with_opacity(unmarked_rule(NetworkAddressFamily::Ipv6, 200));
    let incomplete_inventory = inventory([opaque_unmarked]);
    let incomplete = audit_fwmark_candidate_partial(&incomplete_inventory, candidate());
    assert_eq!(incomplete.outcome(), FwmarkPartialAuditOutcome::Incomplete);
    assert!(incomplete.conflicts().is_empty());
    assert_eq!(
        incomplete
            .sources()
            .iter()
            .find(|status| status.source() == FwmarkEvidenceSource::Rpdb)
            .expect("RPDB source status")
            .state(),
        FwmarkEvidenceState::Opaque
    );

    let opaque_marked = with_opacity(marked_rule(
        NetworkAddressFamily::Ipv4,
        300,
        PROXY_VALUE,
        CANDIDATE_MASK,
        RuleAction::TO_TABLE,
        RuleFlags::default(),
    ));
    let conflicting_inventory = inventory([opaque_marked]);
    let conflicting = audit_fwmark_candidate_partial(&conflicting_inventory, candidate());
    assert_eq!(
        conflicting.outcome(),
        FwmarkPartialAuditOutcome::Conflicting
    );
    assert_eq!(conflicting.conflicts().len(), 1);
    assert_eq!(
        conflicting
            .sources()
            .iter()
            .find(|status| status.source() == FwmarkEvidenceSource::Rpdb)
            .expect("RPDB source status")
            .state(),
        FwmarkEvidenceState::Opaque
    );
}

#[test]
fn conflict_evidence_is_bounded_without_changing_the_rejection_decision() {
    let low_field = FwmarkCandidate::new(0x3, 0x1, 0x2).expect("two low-bit roles");
    let rules = (0..64).map(|index| {
        marked_rule(
            if index % 2 == 0 {
                NetworkAddressFamily::Ipv4
            } else {
                NetworkAddressFamily::Ipv6
            },
            1_000 + index,
            0x1,
            0x3,
            RuleAction::TO_TABLE,
            RuleFlags::default(),
        )
    });
    let inventory = inventory(rules);

    let audit = audit_fwmark_candidate_partial(&inventory, low_field);
    assert_eq!(audit.outcome(), FwmarkPartialAuditOutcome::Conflicting);
    assert_eq!(audit.conflicts().len(), MAX_FWMARK_PARTIAL_CONFLICTS);
    assert_eq!(audit.omitted_conflicts(), 1);
    assert!(matches!(
        audit.conflicts()[0],
        FwmarkPartialConflict::AndroidNetIdOverlap { overlap: 0x3 }
    ));
    assert!(matches!(
        audit.conflicts()[1],
        FwmarkPartialConflict::RpdbSelectorOverlap { dump_index: 0, .. }
    ));
    assert!(matches!(
        audit.conflicts()[MAX_FWMARK_PARTIAL_CONFLICTS - 1],
        FwmarkPartialConflict::RpdbSelectorOverlap { dump_index: 62, .. }
    ));
}

#[test]
fn partial_audits_are_bound_to_exact_inventory_identity() {
    let mut first_tracker = NetworkInventoryTracker::new();
    let first = first_tracker
        .publish_complete_with_routing([], [], [], [])
        .expect("first inventory")
        .clone();
    let audit = audit_fwmark_candidate_partial(&first, candidate());

    let mut unrelated_tracker = NetworkInventoryTracker::new();
    let unrelated = unrelated_tracker
        .publish_complete_with_routing([], [], [], [])
        .expect("unrelated inventory")
        .clone();
    assert_eq!(first.epoch(), unrelated.epoch());
    let unrelated_error = audit
        .ensure_current(&unrelated)
        .expect_err("equal epoch from another tracker is not the audited snapshot");
    assert_eq!(unrelated_error.audited_snapshot_id(), first.snapshot_id());
    assert_eq!(
        unrelated_error.current_snapshot_id(),
        unrelated.snapshot_id()
    );
    assert_eq!(unrelated_error.audited_epoch(), first.epoch());
    assert_eq!(unrelated_error.current_epoch(), unrelated.epoch());

    let changed = first_tracker
        .publish_complete_with_routing([], [], [], [unmarked_rule(NetworkAddressFamily::Ipv4, 1)])
        .expect("changed inventory")
        .clone();
    let changed_error = audit
        .ensure_current(&changed)
        .expect_err("changed inventory invalidates the audit");
    assert_ne!(changed_error.audited_epoch(), changed_error.current_epoch());
}

fn candidate() -> FwmarkCandidate {
    FwmarkCandidate::new(CANDIDATE_MASK, PROXY_VALUE, BYPASS_VALUE)
        .expect("structurally valid high-bit candidate")
}

fn inventory(rules: impl IntoIterator<Item = NetworkRuleRecord>) -> NetworkInventory {
    let mut tracker = NetworkInventoryTracker::new();
    tracker
        .publish_complete_with_routing([], [], [], rules)
        .expect("valid inventory")
        .clone()
}

fn marked_rule(
    family: NetworkAddressFamily,
    priority: u32,
    value: u32,
    mask: u32,
    action: RuleAction,
    flags: RuleFlags,
) -> NetworkRuleRecord {
    unmarked_rule_with_properties(family, priority, action, flags)
        .with_fwmark(RuleFwMark::new(value, mask).expect("material test selector"))
}

fn unmarked_rule(family: NetworkAddressFamily, priority: u32) -> NetworkRuleRecord {
    unmarked_rule_with_properties(family, priority, RuleAction::TO_TABLE, RuleFlags::default())
}

fn with_opacity(rule: NetworkRuleRecord) -> NetworkRuleRecord {
    rule.with_attribute_opacity(
        RuleAttributeOpacity::new(
            [OpaqueRuleAttribute::new(25, 0, 4)],
            0,
            RuleOpaqueAttributeFingerprint::from_bytes([0x25; 32]),
        )
        .expect("bounded test opacity evidence"),
    )
}

fn unmarked_rule_with_properties(
    family: NetworkAddressFamily,
    priority: u32,
    action: RuleAction,
    flags: RuleFlags,
) -> NetworkRuleRecord {
    NetworkRuleRecord::new(
        RulePrefix::unspecified(family),
        RulePrefix::unspecified(family),
        RuleProperties::new(
            0,
            RuleTableId::from_raw(254),
            action,
            RuleProtocol::from_raw(2),
            flags,
        ),
        RulePriority::from_raw(priority),
        None,
    )
    .expect("valid test rule")
}
