use flux_core::{
    FwmarkCensusCoverageRecord, FwmarkCensusCoverageState, FwmarkEvidenceSource, FwmarkPlane,
    FwmarkUseOperation, FwmarkUseRecord, MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
    NetworkAddressFamily, NetworkInventory, NetworkInventoryTracker, NetworkRuleRecord,
    OpaqueRuleAttribute, RpdbFwmarkCensusFragmentError, RuleAction, RuleAttributeOpacity,
    RuleFlags, RuleFwMark, RuleOpaqueAttributeFingerprint, RulePrefix, RulePriority,
    RuleProperties, RuleProtocol, RuleTableId, project_rpdb_fwmark_census_fragment,
};

#[test]
fn empty_rpdb_is_complete_absent_across_all_planes() {
    let inventory = inventory([]);
    let fragment = project_rpdb_fwmark_census_fragment(&inventory).expect("empty RPDB projection");

    assert_eq!(fragment.snapshot_id(), inventory.snapshot_id());
    assert_eq!(fragment.epoch(), inventory.epoch());
    assert_eq!(
        fragment.coverage(),
        [
            coverage(
                FwmarkPlane::Packet,
                FwmarkCensusCoverageState::CompleteAbsent,
            ),
            coverage(
                FwmarkPlane::Socket,
                FwmarkCensusCoverageState::CompleteAbsent,
            ),
            coverage(
                FwmarkPlane::Conntrack,
                FwmarkCensusCoverageState::CompleteAbsent,
            ),
        ]
    );
    assert!(fragment.raw_mark_uses().is_empty());
    fragment
        .ensure_current(&inventory)
        .expect("same inventory remains current");
}

#[test]
fn mixed_family_selectors_emit_packet_socket_pairs_in_dump_order() {
    let first = marked_rule(
        NetworkAddressFamily::Ipv4,
        100,
        0x0100_0000,
        0x0300_0000,
        RuleAction::TO_TABLE,
        RuleFlags::default(),
    );
    let second = marked_rule(
        NetworkAddressFamily::Ipv6,
        200,
        0x0400_0000,
        0x0c00_0000,
        RuleAction::TO_TABLE,
        RuleFlags::default(),
    );
    let inventory = inventory([first, second]);

    let fragment = project_rpdb_fwmark_census_fragment(&inventory).expect("modeled selectors");

    assert_eq!(
        fragment.coverage(),
        [
            coverage(
                FwmarkPlane::Packet,
                FwmarkCensusCoverageState::CompletePresent,
            ),
            coverage(
                FwmarkPlane::Socket,
                FwmarkCensusCoverageState::CompletePresent,
            ),
            coverage(
                FwmarkPlane::Conntrack,
                FwmarkCensusCoverageState::CompleteAbsent,
            ),
        ]
    );
    assert_eq!(
        fragment.raw_mark_uses(),
        [
            mark_use(FwmarkPlane::Packet, 0x0300_0000),
            mark_use(FwmarkPlane::Socket, 0x0300_0000),
            mark_use(FwmarkPlane::Packet, 0x0c00_0000),
            mark_use(FwmarkPlane::Socket, 0x0c00_0000),
        ]
    );
}

#[test]
fn duplicate_rules_and_selector_values_preserve_raw_mask_evidence() {
    let first = marked_rule(
        NetworkAddressFamily::Ipv4,
        100,
        0x0100_0000,
        0x0300_0000,
        RuleAction::TO_TABLE,
        RuleFlags::default(),
    );
    let same_mask_different_value = marked_rule(
        NetworkAddressFamily::Ipv6,
        200,
        0x0200_0000,
        0x0300_0000,
        RuleAction::TO_TABLE,
        RuleFlags::default(),
    );
    let inventory = inventory([first.clone(), first, same_mask_different_value]);

    let fragment = project_rpdb_fwmark_census_fragment(&inventory).expect("duplicate selectors");

    assert_eq!(fragment.raw_mark_uses().len(), 6);
    for pair in fragment.raw_mark_uses().chunks_exact(2) {
        assert_eq!(
            pair,
            [
                mark_use(FwmarkPlane::Packet, 0x0300_0000),
                mark_use(FwmarkPlane::Socket, 0x0300_0000),
            ]
        );
    }
}

#[test]
fn unknown_action_inversion_and_foreign_priority_do_not_hide_reads() {
    let rule = marked_rule(
        NetworkAddressFamily::Ipv4,
        u32::MAX,
        0,
        0x00f0_0000,
        RuleAction::from_raw(250),
        RuleFlags::INVERT,
    );
    let inventory = inventory([rule]);

    let fragment = project_rpdb_fwmark_census_fragment(&inventory).expect("foreign selector");

    assert_eq!(
        fragment.raw_mark_uses(),
        [
            mark_use(FwmarkPlane::Packet, 0x00f0_0000),
            mark_use(FwmarkPlane::Socket, 0x00f0_0000),
        ]
    );
}

#[test]
fn opaque_marked_rule_retains_known_uses_and_marks_flow_planes_opaque() {
    let rule = marked_rule(
        NetworkAddressFamily::Ipv6,
        100,
        0x1000_0000,
        0x3000_0000,
        RuleAction::TO_TABLE,
        RuleFlags::default(),
    )
    .with_attribute_opacity(opacity());
    let inventory = inventory([rule]);

    let fragment = project_rpdb_fwmark_census_fragment(&inventory).expect("opaque selector");

    assert_eq!(
        fragment.coverage(),
        [
            coverage(FwmarkPlane::Packet, FwmarkCensusCoverageState::Opaque),
            coverage(FwmarkPlane::Socket, FwmarkCensusCoverageState::Opaque),
            coverage(
                FwmarkPlane::Conntrack,
                FwmarkCensusCoverageState::CompleteAbsent,
            ),
        ]
    );
    assert_eq!(
        fragment.raw_mark_uses(),
        [
            mark_use(FwmarkPlane::Packet, 0x3000_0000),
            mark_use(FwmarkPlane::Socket, 0x3000_0000),
        ]
    );
}

#[test]
fn opaque_unmarked_rule_makes_flow_planes_opaque_without_inventing_uses() {
    let rule = unmarked_rule(NetworkAddressFamily::Ipv4, 100).with_attribute_opacity(opacity());
    let inventory = inventory([rule]);

    let fragment = project_rpdb_fwmark_census_fragment(&inventory).expect("opaque rule");

    assert_eq!(
        fragment.coverage(),
        [
            coverage(FwmarkPlane::Packet, FwmarkCensusCoverageState::Opaque),
            coverage(FwmarkPlane::Socket, FwmarkCensusCoverageState::Opaque),
            coverage(
                FwmarkPlane::Conntrack,
                FwmarkCensusCoverageState::CompleteAbsent,
            ),
        ]
    );
    assert!(fragment.raw_mark_uses().is_empty());
}

#[test]
fn raw_record_budget_accepts_512_and_rejects_513_without_truncation() {
    let marked = marked_rule(
        NetworkAddressFamily::Ipv4,
        100,
        0x0100_0000,
        0x0300_0000,
        RuleAction::TO_TABLE,
        RuleFlags::default(),
    );
    let accepted_inventory = inventory(std::iter::repeat_n(marked.clone(), 256));
    let accepted = project_rpdb_fwmark_census_fragment(&accepted_inventory)
        .expect("256 selectors produce exactly 512 records");
    assert_eq!(
        accepted.raw_mark_uses().len(),
        MAX_COMPLETE_FWMARK_CENSUS_MARK_USES
    );

    let rejected_inventory = inventory(std::iter::repeat_n(marked, 257));
    assert_eq!(
        project_rpdb_fwmark_census_fragment(&rejected_inventory)
            .expect_err("selector 257 exceeds the raw-use budget"),
        RpdbFwmarkCensusFragmentError::TooManyMarkUseRecords {
            maximum: MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
            required_at_least: MAX_COMPLETE_FWMARK_CENSUS_MARK_USES + 1,
        }
    );
}

#[test]
fn freshness_requires_the_exact_snapshot_and_epoch() {
    let mut tracker = NetworkInventoryTracker::new();
    let initial = tracker
        .publish_complete_with_routing([], [], [], [])
        .expect("initial inventory")
        .clone();
    let fragment = project_rpdb_fwmark_census_fragment(&initial).expect("initial RPDB projection");

    let later = tracker
        .publish_complete_with_routing([], [], [], [unmarked_rule(NetworkAddressFamily::Ipv4, 100)])
        .expect("later inventory")
        .clone();
    let later_error = fragment
        .ensure_current(&later)
        .expect_err("later epoch is stale");
    assert_eq!(later_error.observed_snapshot_id(), initial.snapshot_id());
    assert_eq!(later_error.current_snapshot_id(), later.snapshot_id());
    assert_eq!(later_error.observed_epoch(), initial.epoch());
    assert_eq!(later_error.current_epoch(), later.epoch());

    let same_epoch_other_tracker = inventory([]);
    assert_eq!(same_epoch_other_tracker.epoch(), initial.epoch());
    assert_ne!(
        same_epoch_other_tracker.snapshot_id(),
        initial.snapshot_id()
    );
    let cross_tracker_error = fragment
        .ensure_current(&same_epoch_other_tracker)
        .expect_err("equal epoch from another tracker is stale");
    assert_eq!(
        cross_tracker_error.current_snapshot_id(),
        same_epoch_other_tracker.snapshot_id()
    );
    assert_eq!(cross_tracker_error.current_epoch(), initial.epoch());
}

fn coverage(plane: FwmarkPlane, state: FwmarkCensusCoverageState) -> FwmarkCensusCoverageRecord {
    FwmarkCensusCoverageRecord::new(FwmarkEvidenceSource::Rpdb, plane, state)
}

fn mark_use(plane: FwmarkPlane, mask: u32) -> FwmarkUseRecord {
    FwmarkUseRecord::new(
        FwmarkEvidenceSource::Rpdb,
        plane,
        FwmarkUseOperation::PredicateRead,
        mask,
    )
    .expect("test mask is nonzero")
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
        .with_fwmark(RuleFwMark::new(value, mask).expect("test selector has a nonzero mask"))
}

fn unmarked_rule(family: NetworkAddressFamily, priority: u32) -> NetworkRuleRecord {
    unmarked_rule_with_properties(family, priority, RuleAction::TO_TABLE, RuleFlags::default())
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
            RuleTableId::from_raw(100),
            action,
            RuleProtocol::from_raw(0),
            flags,
        ),
        RulePriority::from_raw(priority),
        None,
    )
    .expect("test rule")
}

fn opacity() -> RuleAttributeOpacity {
    RuleAttributeOpacity::new(
        [OpaqueRuleAttribute::new(250, 0x8000, 4)],
        0,
        RuleOpaqueAttributeFingerprint::from_bytes([0x5a; 32]),
    )
    .expect("test opacity")
}

fn inventory(rules: impl IntoIterator<Item = NetworkRuleRecord>) -> NetworkInventory {
    NetworkInventoryTracker::new()
        .publish_complete_with_routing([], [], [], rules)
        .expect("complete inventory")
        .clone()
}
