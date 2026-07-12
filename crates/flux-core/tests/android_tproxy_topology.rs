use flux_core::{
    AndroidRpdbPolicyProfile, AndroidRpdbRuleRole, AndroidTproxyEvidenceCoverage,
    AndroidTproxyRoutingShape, AndroidTproxyRuleDisposition, AndroidTproxySelectorDisjointReason,
    AndroidTproxyStructuralFeasibility, AndroidTproxyTopologyError, AndroidTproxyTrafficDomainKind,
    DeferredAndroidTproxyPrerequisite, InterfaceHardwareType, InterfaceIndex, InterfaceLinkFlags,
    InterfaceLinkRecord, InterfaceName, NetworkAddressFamily, NetworkInventory,
    NetworkInventoryTracker, NetworkRuleRecord, RuleAction, RuleFlags, RuleFwMark, RulePrefix,
    RulePriority, RuleProperties, RuleProtocol, RuleTableId, RuleUidRange,
    assess_android_tproxy_topology, classify_android_rpdb,
};

const NET_ID_MASK: u32 = 0x0000_ffff;
const EXPLICIT: u32 = 0x0001_0000;
const NETWORK_PERMISSION: u32 = 0x0004_0000;
const SYSTEM_PERMISSION: u32 = 0x000c_0000;
const DEFAULT_NETWORK_TABLE: u32 = 1_003;

#[test]
fn android_12_local_anchor_has_no_single_rule_window() {
    let profile = AndroidRpdbPolicyProfile::AospAndroid12R1;
    let inventory = profile_inventory(profile, false);
    let classification = classify_android_rpdb(&inventory, profile);
    let anchor = classification
        .roles()
        .iter()
        .position(|role| *role == Some(AndroidRpdbRuleRole::DefaultNetwork))
        .expect("recognized anchor remains diagnostic evidence");

    let report = assess_android_tproxy_topology(&inventory, &classification, anchor)
        .expect("trusted active default-network anchor");
    assert_eq!(
        report.kind(),
        AndroidTproxyTrafficDomainKind::ResidualLocalOutput
    );
    assert_eq!(report.selector().input_interface(), interface(b"lo"));
    assert_eq!(report.input_interface_index(), interface_index(1));
    assert_eq!(report.anchor().dump_index(), anchor);
    assert_eq!(report.anchor().role(), AndroidRpdbRuleRole::DefaultNetwork);
    assert_eq!(report.anchor().lookup_table().get(), DEFAULT_NETWORK_TABLE);
    assert_eq!(report.interval().android_first_through().get(), 28_999);
    assert_eq!(report.interval().flux_first_before().get(), 29_000);
    assert_eq!(report.interval().open_priority_count(), 0);
    assert_eq!(report.interval().first_open_priority(), None);
    assert_eq!(
        report.evidence_coverage(),
        AndroidTproxyEvidenceCoverage::Complete
    );
    assert_eq!(
        report.structural_feasibility(AndroidTproxyRoutingShape::PreMarkAddressHostSet),
        AndroidTproxyStructuralFeasibility::InsufficientPrioritySlots {
            shape: AndroidTproxyRoutingShape::PreMarkAddressHostSet,
            required: 1,
            available: 0,
        }
    );
    assert_eq!(
        report.structural_feasibility(AndroidTproxyRoutingShape::DedicatedAddressBypassRule),
        AndroidTproxyStructuralFeasibility::InsufficientPrioritySlots {
            shape: AndroidTproxyRoutingShape::DedicatedAddressBypassRule,
            required: 2,
            available: 0,
        }
    );
}

#[test]
fn android_13_local_anchor_exposes_only_residual_30999_evidence() {
    let profile = AndroidRpdbPolicyProfile::AospAndroid13R1;
    let inventory = profile_inventory(profile, true);
    let classification = classify_android_rpdb(&inventory, profile);
    let anchor = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::DefaultNetwork,
        NetworkAddressFamily::Ipv4,
    );
    let report = assess_android_tproxy_topology(&inventory, &classification, anchor)
        .expect("trusted active default-network anchor");

    assert_eq!(report.interval().android_first_through().get(), 30_998);
    assert_eq!(report.interval().flux_first_before().get(), 31_000);
    assert_eq!(report.interval().open_priority_count(), 1);
    assert_eq!(
        report.interval().first_open_priority().unwrap().get(),
        30_999
    );
    assert_eq!(
        report.interval().last_open_priority().unwrap().get(),
        30_999
    );
    assert_eq!(
        report.structural_feasibility(AndroidTproxyRoutingShape::DedicatedAddressBypassRule),
        AndroidTproxyStructuralFeasibility::InsufficientPrioritySlots {
            shape: AndroidTproxyRoutingShape::DedicatedAddressBypassRule,
            required: 2,
            available: 1,
        }
    );
    assert_eq!(
        report.structural_feasibility(AndroidTproxyRoutingShape::PreMarkAddressHostSet),
        AndroidTproxyStructuralFeasibility::ResidualCandidateWindow {
            shape: AndroidTproxyRoutingShape::PreMarkAddressHostSet,
            required: 1,
            available: 1,
        }
    );
    assert!(
        report
            .deferred_prerequisites(AndroidTproxyRoutingShape::PreMarkAddressHostSet)
            .contains(&DeferredAndroidTproxyPrerequisite::DomainIdentityHandoff)
    );
    assert!(
        report
            .deferred_prerequisites(AndroidTproxyRoutingShape::PreMarkAddressHostSet)
            .contains(&DeferredAndroidTproxyPrerequisite::NetworkSelectionHandoff)
    );
    assert!(
        report
            .deferred_prerequisites(AndroidTproxyRoutingShape::PreMarkAddressHostSet)
            .contains(&DeferredAndroidTproxyPrerequisite::PositiveMarkAuthority)
    );

    let tether = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::Tethering,
        NetworkAddressFamily::Ipv4,
    );
    assert_eq!(
        report.dispositions()[tether],
        AndroidTproxyRuleDisposition::SelectorDisjoint(
            AndroidTproxySelectorDisjointReason::InputInterfaceMismatch,
        )
    );
    let explicit = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::LocalNetworkExplicit,
        NetworkAddressFamily::Ipv4,
    );
    assert_eq!(
        report.dispositions()[explicit],
        AndroidTproxyRuleDisposition::SelectorDisjoint(
            AndroidTproxySelectorDisjointReason::FwmarkPredicateConflict,
        )
    );
    assert_eq!(
        report.dispositions()[anchor],
        AndroidTproxyRuleDisposition::FluxFirstRequiresHandoff
    );
}

#[test]
fn exact_tether_anchor_has_a_separate_20000_to_21000_window() {
    let profile = AndroidRpdbPolicyProfile::AospNetd20250324;
    let inventory = profile_inventory(profile, true);
    let classification = classify_android_rpdb(&inventory, profile);
    let anchor = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::Tethering,
        NetworkAddressFamily::Ipv4,
    );
    let report = assess_android_tproxy_topology(&inventory, &classification, anchor)
        .expect("exact tether rule and live ingress link");

    assert_eq!(report.kind(), AndroidTproxyTrafficDomainKind::TetherIngress);
    assert_eq!(report.selector().input_interface(), interface(b"rndis0"));
    assert_eq!(report.selector().android_fwmark(), None);
    assert_eq!(report.input_interface_index(), interface_index(2));
    assert_eq!(report.anchor().lookup_table().get(), 1_005);
    assert_eq!(report.interval().android_first_through().get(), 20_000);
    assert_eq!(report.interval().flux_first_before().get(), 21_000);
    assert_eq!(report.interval().open_priority_count(), 999);
    assert_eq!(
        report.interval().first_open_priority().unwrap().get(),
        20_001
    );
    assert_eq!(
        report.interval().last_open_priority().unwrap().get(),
        20_999
    );
    assert!(matches!(
        report.structural_feasibility(AndroidTproxyRoutingShape::PreMarkAddressHostSet),
        AndroidTproxyStructuralFeasibility::ResidualCandidateWindow {
            required: 1,
            available: 999,
            ..
        }
    ));
    assert_eq!(
        report.structural_feasibility(AndroidTproxyRoutingShape::DedicatedAddressBypassRule),
        AndroidTproxyStructuralFeasibility::IncompatibleTrafficDomain {
            shape: AndroidTproxyRoutingShape::DedicatedAddressBypassRule,
            domain: AndroidTproxyTrafficDomainKind::TetherIngress,
        }
    );

    let local_explicit = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::LocalNetworkExplicit,
        NetworkAddressFamily::Ipv4,
    );
    assert_eq!(
        report.dispositions()[local_explicit],
        AndroidTproxyRuleDisposition::SelectorDisjoint(
            AndroidTproxySelectorDisjointReason::InputInterfaceMismatch,
        )
    );
    let local_network = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::LocalNetwork,
        NetworkAddressFamily::Ipv4,
    );
    assert_eq!(
        report.dispositions()[local_network],
        AndroidTproxyRuleDisposition::AndroidFirst
    );
    assert_eq!(
        report.dispositions()[anchor],
        AndroidTproxyRuleDisposition::FluxFirstRequiresHandoff
    );
}

#[test]
fn unknown_rules_fail_closed_before_selector_disjointness_is_considered() {
    let profile = AndroidRpdbPolicyProfile::AospAndroid13R1;
    let mut fixture = profile_fixture(profile, true);
    fixture.rules.push(
        RuleSpec::netd(20_500, 1_777, RuleAction::TO_TABLE)
            .input(b"other0")
            .build(),
    );
    sort_rules(&mut fixture.rules);
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification = classify_android_rpdb(&inventory, profile);
    let anchor = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::DefaultNetwork,
        NetworkAddressFamily::Ipv4,
    );
    let unknown_index = inventory
        .rules()
        .iter()
        .position(|rule| rule.priority().get() == 20_500)
        .unwrap();
    let report = assess_android_tproxy_topology(&inventory, &classification, anchor)
        .expect("the anchor remains trusted while another rule is unknown");

    assert_eq!(report.unknown_rule_count(), 1);
    assert_eq!(
        report.evidence_coverage(),
        AndroidTproxyEvidenceCoverage::Incomplete
    );
    assert_eq!(
        report.dispositions()[unknown_index],
        AndroidTproxyRuleDisposition::Unknown
    );
    assert_eq!(
        report.structural_feasibility(AndroidTproxyRoutingShape::PreMarkAddressHostSet),
        AndroidTproxyStructuralFeasibility::IncompleteEvidence {
            unknown_rule_count: 1,
        }
    );
}

#[test]
fn unknown_rules_in_another_family_do_not_poison_the_selected_domain() {
    let profile = AndroidRpdbPolicyProfile::AospAndroid13R1;
    let mut fixture = profile_fixture_for_families(
        profile,
        [NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6],
        false,
    );
    fixture.rules.push(
        RuleSpec::netd(20_500, 1_777, RuleAction::TO_TABLE)
            .family(NetworkAddressFamily::Ipv6)
            .build(),
    );
    sort_rules(&mut fixture.rules);
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification = classify_android_rpdb(&inventory, profile);
    let anchor = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::DefaultNetwork,
        NetworkAddressFamily::Ipv4,
    );
    let report = assess_android_tproxy_topology(&inventory, &classification, anchor)
        .expect("IPv6 uncertainty is outside the IPv4 domain");
    assert_eq!(report.unknown_rule_count(), 0);
    assert_eq!(
        report.evidence_coverage(),
        AndroidTproxyEvidenceCoverage::Complete
    );
}

#[test]
fn static_profile_bounds_cannot_replace_an_observed_active_anchor() {
    let profile = AndroidRpdbPolicyProfile::AospAndroid13R1;
    let fixture = profile_fixture_without_default();
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification = classify_android_rpdb(&inventory, profile);
    let final_unreachable = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::FinalUnreachable,
        NetworkAddressFamily::Ipv4,
    );
    assert!(matches!(
        assess_android_tproxy_topology(&inventory, &classification, final_unreachable),
        Err(AndroidTproxyTopologyError::UnsupportedAnchorRole {
            role: Some(AndroidRpdbRuleRole::FinalUnreachable),
            ..
        })
    ));
    assert!(matches!(
        assess_android_tproxy_topology(&inventory, &classification, inventory.rules().len()),
        Err(AndroidTproxyTopologyError::AnchorOutOfBounds { .. })
    ));
}

#[test]
fn anchor_requires_the_exact_present_admin_up_link_identity() {
    let profile = AndroidRpdbPolicyProfile::AospAndroid13R1;
    let mut fixture = profile_fixture(profile, true);
    fixture
        .links
        .retain(|link| link.name() != &interface(b"rndis0"));
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification = classify_android_rpdb(&inventory, profile);
    let tether = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::Tethering,
        NetworkAddressFamily::Ipv4,
    );
    assert!(matches!(
        assess_android_tproxy_topology(&inventory, &classification, tether),
        Err(AndroidTproxyTopologyError::MissingAnchorLink { .. })
    ));

    let mut fixture = profile_fixture(profile, true);
    fixture.links[1] = link(2, b"rndis0", InterfaceLinkFlags::from_bits(0));
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification = classify_android_rpdb(&inventory, profile);
    let tether = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::Tethering,
        NetworkAddressFamily::Ipv4,
    );
    assert!(matches!(
        assess_android_tproxy_topology(&inventory, &classification, tether),
        Err(AndroidTproxyTopologyError::AnchorLinkIsDown { .. })
    ));

    let mut fixture = profile_fixture(profile, false);
    fixture.links[0] = link(1, b"lo", InterfaceLinkFlags::UP);
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification = classify_android_rpdb(&inventory, profile);
    let default = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::DefaultNetwork,
        NetworkAddressFamily::Ipv4,
    );
    assert!(matches!(
        assess_android_tproxy_topology(&inventory, &classification, default),
        Err(AndroidTproxyTopologyError::LocalAnchorIsNotLoopback { .. })
    ));
}

#[test]
fn overlapping_same_interface_tether_tables_are_ambiguous() {
    let profile = AndroidRpdbPolicyProfile::AospAndroid13R1;
    let mut fixture = profile_fixture(profile, true);
    fixture.rules.push(
        RuleSpec::netd(21_000, 1_006, RuleAction::TO_TABLE)
            .input(b"rndis0")
            .build(),
    );
    sort_rules(&mut fixture.rules);
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification = classify_android_rpdb(&inventory, profile);
    let anchor = inventory
        .rules()
        .iter()
        .enumerate()
        .find(|(_, rule)| {
            rule.priority().get() == 21_000 && rule.properties().table().get() == 1_005
        })
        .map(|(index, _)| index)
        .unwrap();
    assert!(matches!(
        assess_android_tproxy_topology(&inventory, &classification, anchor),
        Err(AndroidTproxyTopologyError::AmbiguousSelectionAnchor {
            table,
            conflicting_table,
            ..
        }) if table.get() == 1_005 && conflicting_table.get() == 1_006
    ));

    let mut fixture = profile_fixture(profile, true);
    fixture.rules.push(
        RuleSpec::netd(21_000, 1_005, RuleAction::TO_TABLE)
            .input(b"rndis0")
            .build(),
    );
    sort_rules(&mut fixture.rules);
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification = classify_android_rpdb(&inventory, profile);
    let anchor = role_index(
        &inventory,
        &classification,
        AndroidRpdbRuleRole::Tethering,
        NetworkAddressFamily::Ipv4,
    );
    assess_android_tproxy_topology(&inventory, &classification, anchor)
        .expect("exact duplicate table evidence is not a second network selection");
}

#[test]
fn overlapping_default_network_selectors_cannot_choose_between_tables() {
    let profile = AndroidRpdbPolicyProfile::AospAndroid13R1;
    let mut fixture = profile_fixture(profile, false);
    fixture.rules.push(
        RuleSpec::netd(31_000, 1_004, RuleAction::TO_TABLE)
            .mark(NETWORK_PERMISSION, NET_ID_MASK | NETWORK_PERMISSION)
            .input(b"lo")
            .build(),
    );
    sort_rules(&mut fixture.rules);
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification = classify_android_rpdb(&inventory, profile);
    let anchor = inventory
        .rules()
        .iter()
        .enumerate()
        .find(|(_, rule)| {
            rule.priority().get() == 31_000
                && rule.properties().table().get() == DEFAULT_NETWORK_TABLE
        })
        .map(|(index, _)| index)
        .unwrap();
    assert!(matches!(
        assess_android_tproxy_topology(&inventory, &classification, anchor),
        Err(AndroidTproxyTopologyError::AmbiguousSelectionAnchor {
            table,
            conflicting_table,
            ..
        }) if table.get() == DEFAULT_NETWORK_TABLE && conflicting_table.get() == 1_004
    ));
}

#[test]
fn nested_android_permission_masks_are_not_mistaken_for_disjoint_anchors() {
    let profile = AndroidRpdbPolicyProfile::AospAndroid13R1;
    let mut fixture = profile_fixture(profile, false);
    fixture.rules.push(
        RuleSpec::netd(31_000, 1_004, RuleAction::TO_TABLE)
            .mark(SYSTEM_PERMISSION, NET_ID_MASK | SYSTEM_PERMISSION)
            .input(b"lo")
            .build(),
    );
    sort_rules(&mut fixture.rules);
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification = classify_android_rpdb(&inventory, profile);
    let network_permission_anchor = inventory
        .rules()
        .iter()
        .enumerate()
        .find(|(_, rule)| {
            rule.priority().get() == 31_000
                && rule.properties().table().get() == DEFAULT_NETWORK_TABLE
        })
        .map(|(index, _)| index)
        .unwrap();
    assert!(matches!(
        assess_android_tproxy_topology(
            &inventory,
            &classification,
            network_permission_anchor,
        ),
        Err(AndroidTproxyTopologyError::AmbiguousSelectionAnchor {
            table,
            conflicting_table,
            ..
        }) if table.get() == DEFAULT_NETWORK_TABLE && conflicting_table.get() == 1_004
    ));
}

#[test]
fn invalid_family_profile_makes_even_a_recognized_anchor_untrusted() {
    let profile = AndroidRpdbPolicyProfile::AospAndroid13R1;
    let mut fixture = profile_fixture(profile, false);
    fixture.rules.retain(|rule| rule.priority().get() != 20_000);
    let inventory = make_inventory(fixture.links, fixture.rules);
    let classification = classify_android_rpdb(&inventory, profile);
    let anchor = classification
        .roles()
        .iter()
        .position(|role| *role == Some(AndroidRpdbRuleRole::DefaultNetwork))
        .expect("recognized anchor remains diagnostic evidence");
    assert!(matches!(
        assess_android_tproxy_topology(&inventory, &classification, anchor),
        Err(AndroidTproxyTopologyError::UntrustedAnchor { .. })
    ));
}

#[test]
fn reports_reject_cross_snapshot_inputs_and_stale_future_use() {
    let profile = AndroidRpdbPolicyProfile::AospAndroid13R1;
    let first = profile_inventory(profile, false);
    let first_classification = classify_android_rpdb(&first, profile);
    let second = profile_inventory(profile, false);
    let anchor = role_index(
        &first,
        &first_classification,
        AndroidRpdbRuleRole::DefaultNetwork,
        NetworkAddressFamily::Ipv4,
    );
    assert!(matches!(
        assess_android_tproxy_topology(&second, &first_classification, anchor),
        Err(AndroidTproxyTopologyError::ClassifierSnapshotMismatch { .. })
    ));

    let report = assess_android_tproxy_topology(&first, &first_classification, anchor)
        .expect("matching snapshot");
    report
        .ensure_current(&first, &first_classification)
        .expect("same evidence");
    let second_classification = classify_android_rpdb(&second, profile);
    let stale = report
        .ensure_current(&second, &second_classification)
        .expect_err("snapshot changed");
    assert_eq!(stale.reported_snapshot_id(), first.snapshot_id());
    assert_eq!(stale.current_snapshot_id(), second.snapshot_id());
    assert_eq!(stale.reported_profile(), profile);
    assert_eq!(stale.current_profile(), profile);

    let wrong_profile = AndroidRpdbPolicyProfile::AospAndroid12R1;
    let wrong_classification = classify_android_rpdb(&first, wrong_profile);
    let stale = report
        .ensure_current(&first, &wrong_classification)
        .expect_err("a different classifier profile cannot be self-asserted current");
    assert_eq!(stale.current_snapshot_id(), first.snapshot_id());
    assert_eq!(
        stale.current_classification_snapshot_id(),
        first.snapshot_id()
    );
    assert_eq!(stale.reported_profile(), profile);
    assert_eq!(stale.current_profile(), wrong_profile);
}

fn profile_inventory(profile: AndroidRpdbPolicyProfile, tether: bool) -> NetworkInventory {
    let fixture = profile_fixture(profile, tether);
    make_inventory(fixture.links, fixture.rules)
}

fn profile_fixture(profile: AndroidRpdbPolicyProfile, tether: bool) -> Fixture {
    profile_fixture_for_families(profile, [NetworkAddressFamily::Ipv4], tether)
}

fn profile_fixture_for_families(
    profile: AndroidRpdbPolicyProfile,
    families: impl IntoIterator<Item = NetworkAddressFamily>,
    tether: bool,
) -> Fixture {
    let mut rules = Vec::new();
    for family in families {
        rules.extend(skeleton_for(family));
        if tether {
            rules.push(
                RuleSpec::netd(21_000, 1_005, RuleAction::TO_TABLE)
                    .family(family)
                    .input(b"rndis0")
                    .build(),
            );
        }
        rules.push(default_network_for(profile, family));
    }
    sort_rules(&mut rules);
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

fn profile_fixture_without_default() -> Fixture {
    let mut rules = skeleton_for(NetworkAddressFamily::Ipv4);
    sort_rules(&mut rules);
    Fixture {
        links: vec![link(
            1,
            b"lo",
            InterfaceLinkFlags::UP | InterfaceLinkFlags::LOOPBACK,
        )],
        rules,
    }
}

fn skeleton_for(family: NetworkAddressFamily) -> Vec<NetworkRuleRecord> {
    vec![
        {
            let mut spec = RuleSpec::netd(0, 255, RuleAction::TO_TABLE).family(family);
            spec.protocol = 2;
            spec.build()
        },
        RuleSpec::netd(10_000, 99, RuleAction::TO_TABLE)
            .family(family)
            .mark(SYSTEM_PERMISSION, EXPLICIT | SYSTEM_PERMISSION)
            .build(),
        RuleSpec::netd(16_000, 97, RuleAction::TO_TABLE)
            .family(family)
            .mark(99 | EXPLICIT, NET_ID_MASK | EXPLICIT)
            .input(b"lo")
            .build(),
        RuleSpec::netd(18_000, 99, RuleAction::TO_TABLE)
            .family(family)
            .mark(0, EXPLICIT)
            .build(),
        RuleSpec::netd(19_000, 98, RuleAction::TO_TABLE)
            .family(family)
            .mark(0, EXPLICIT)
            .build(),
        RuleSpec::netd(20_000, 97, RuleAction::TO_TABLE)
            .family(family)
            .mark(0, EXPLICIT)
            .build(),
        RuleSpec::netd(32_000, 0, RuleAction::UNREACHABLE)
            .family(family)
            .build(),
    ]
}

fn default_network_for(
    profile: AndroidRpdbPolicyProfile,
    family: NetworkAddressFamily,
) -> NetworkRuleRecord {
    RuleSpec::netd(
        profile.priority_contract().default_network().get(),
        DEFAULT_NETWORK_TABLE,
        RuleAction::TO_TABLE,
    )
    .family(family)
    .mark(NETWORK_PERMISSION, NET_ID_MASK | NETWORK_PERMISSION)
    .input(b"lo")
    .build()
}

fn role_index(
    inventory: &NetworkInventory,
    classification: &flux_core::AndroidRpdbClassificationReport,
    role: AndroidRpdbRuleRole,
    family: NetworkAddressFamily,
) -> usize {
    classification
        .roles()
        .iter()
        .enumerate()
        .find(|(index, candidate)| {
            **candidate == Some(role)
                && inventory.rules()[*index].destination().family() == family
                && classification.audit().classifications()[*index]
                    != flux_core::RpdbRuleClassification::Unknown
        })
        .map(|(index, _)| index)
        .expect("expected trusted role")
}

fn make_inventory(
    links: impl IntoIterator<Item = InterfaceLinkRecord>,
    rules: impl IntoIterator<Item = NetworkRuleRecord>,
) -> NetworkInventory {
    let mut tracker = NetworkInventoryTracker::new();
    tracker
        .publish_complete_with_routing(links, [], [], rules)
        .expect("valid topology fixture")
        .clone()
}

fn link(index: u32, name: &[u8], flags: InterfaceLinkFlags) -> InterfaceLinkRecord {
    InterfaceLinkRecord::new(
        interface_index(index),
        interface(name),
        InterfaceHardwareType::from_raw(1),
        flags,
    )
}

fn interface_index(value: u32) -> InterfaceIndex {
    InterfaceIndex::new(value).expect("positive interface index")
}

fn interface(name: &[u8]) -> InterfaceName {
    InterfaceName::new(name).expect("valid interface name")
}

fn sort_rules(rules: &mut [NetworkRuleRecord]) {
    rules.sort_by_key(NetworkRuleRecord::priority);
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
    uid: Option<RuleUidRange>,
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
            uid: None,
        }
    }

    fn family(mut self, family: NetworkAddressFamily) -> Self {
        self.destination = RulePrefix::unspecified(family);
        self.source = RulePrefix::unspecified(family);
        self
    }

    fn mark(mut self, value: u32, mask: u32) -> Self {
        self.fwmark = RuleFwMark::new(value, mask);
        self
    }

    fn input(mut self, name: &[u8]) -> Self {
        self.input = Some(interface(name));
        self
    }

    #[allow(dead_code)]
    fn uid(mut self, start: u32, end: u32) -> Self {
        self.uid = Some(RuleUidRange::new(start, end).expect("UID range"));
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
        if let Some(uid) = self.uid {
            record = record.with_uid_range(uid);
        }
        record
    }
}
