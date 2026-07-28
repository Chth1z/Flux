use std::net::{IpAddr, Ipv4Addr};

use flux_core::{
    AndroidNetdSourceProfile, AndroidRpdbPlacementPlanError, AndroidRpdbPriorityBand,
    AndroidRpdbProfileIssue, AndroidRpdbRuleRole, AndroidRpdbUnknownReason, InterfaceName,
    MAX_ANDROID_RPDB_UNKNOWN_RULES, NetworkAddressFamily, NetworkInventory,
    NetworkInventoryTracker, NetworkRuleRecord, OpaqueRuleAttribute, RpdbFamilyPlacement,
    RpdbPlacementPlanError, RpdbPlacementRequest, RpdbRuleClassification, RuleAction,
    RuleAttributeOpacity, RuleFlags, RuleFlowId, RuleFwMark, RuleIpProtocol,
    RuleOpaqueAttributeFingerprint, RulePortRange, RulePrefix, RulePriority, RuleProperties,
    RuleProtocol, RuleSuppressInterfaceGroup, RuleSuppressPrefixLength, RuleTableId, RuleTunnelId,
    RuleUidRange, classify_android_rpdb, plan_android_rpdb_placement, plan_rpdb_placement,
};

const NET_ID: u32 = 0x64;
const NET_ID_MASK: u32 = 0x0000_ffff;
const EXPLICIT: u32 = 0x0001_0000;
const PROTECTED: u32 = 0x0002_0000;
const NETWORK_PERMISSION: u32 = 0x0004_0000;
const SYSTEM_PERMISSION: u32 = 0x000c_0000;
const NETWORK_TABLE: u32 = 1_003;
const VPN_TABLE: u32 = 1_005;
const LOCAL_COPY_TABLE: u32 = 1_000_000_003;

#[test]
fn profiles_are_explicitly_revisioned_and_expose_the_structural_two_rule_blocker() {
    let profiles = [
        (
            AndroidNetdSourceProfile::AospAndroid12R1,
            "5ca3d903c0253ec29fb4c3e3390f292494612e88",
            28_999,
            29_000,
            0,
        ),
        (
            AndroidNetdSourceProfile::AospAndroid13R1,
            "03311137011f7ca55f263b61a8c86681c1581518",
            30_998,
            31_000,
            1,
        ),
        (
            AndroidNetdSourceProfile::AospNetd20250324,
            "e11b8688b1f99292ade06f89f957c1f7e76ceae9",
            30_998,
            31_000,
            1,
        ),
    ];

    let revisions = profiles
        .iter()
        .map(|(profile, ..)| profile.classifier_revision())
        .collect::<Vec<_>>();
    assert_ne!(revisions[0], revisions[1]);
    assert_ne!(revisions[1], revisions[2]);
    assert_ne!(revisions[0], revisions[2]);

    for (profile, source_revision, last_reserved, default_network, gap) in profiles {
        assert_eq!(profile.source_revision(), source_revision);
        let contract = profile.priority_contract();
        assert_eq!(
            contract.uid_default_unreachable_maximum().get(),
            last_reserved
        );
        assert_eq!(contract.default_network().get(), default_network);
        assert_eq!(contract.intervening_priority_count(), gap);
        assert!(!contract.admits_two_rule_window());
    }
}

#[test]
fn android_12_profile_recognizes_the_complete_role_grammar_in_order() {
    assert_complete_role_fixture(AndroidNetdSourceProfile::AospAndroid12R1);
}

#[test]
fn android_13_profile_recognizes_the_complete_role_grammar_in_order() {
    assert_complete_role_fixture(AndroidNetdSourceProfile::AospAndroid13R1);
}

#[test]
fn paired_ipv4_and_ipv6_initialization_skeletons_are_validated_independently() {
    let mut rules = skeleton_for(NetworkAddressFamily::Ipv4);
    rules.extend(skeleton_for(NetworkAddressFamily::Ipv6));
    sort_rules(&mut rules);
    let inventory = inventory(rules);
    let report = classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospAndroid13R1);

    assert_eq!(report.unknown_rule_count(), 0);
    assert!(report.profile_issues().is_empty());
    for role in [
        AndroidRpdbRuleRole::KernelLocal,
        AndroidRpdbRuleRole::VpnOverrideSystem,
        AndroidRpdbRuleRole::LocalNetworkExplicit,
        AndroidRpdbRuleRole::LegacySystem,
        AndroidRpdbRuleRole::LegacyNetwork,
        AndroidRpdbRuleRole::LocalNetwork,
        AndroidRpdbRuleRole::FinalUnreachable,
    ] {
        assert_eq!(
            report
                .roles()
                .iter()
                .filter(|observed| **observed == Some(role))
                .count(),
            2
        );
    }
}

#[test]
fn pinned_u_plus_profile_adds_only_the_dynamic_physical_local_role() {
    assert_complete_role_fixture(AndroidNetdSourceProfile::AospNetd20250324);

    let physical_local = RuleSpec::netd(20_000, NETWORK_TABLE, RuleAction::TO_TABLE)
        .mark(0, EXPLICIT)
        .build();
    let mut rules = skeleton();
    rules.push(physical_local.clone());
    sort_rules(&mut rules);
    let inventory = inventory(rules.clone());

    let android_13 = classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospAndroid13R1);
    let physical_index = inventory
        .rules()
        .iter()
        .position(|rule| rule == &physical_local)
        .expect("physical-local rule");
    assert_eq!(android_13.roles()[physical_index], None);
    assert_eq!(
        android_13.audit().classifications()[physical_index],
        RpdbRuleClassification::Unknown
    );
    assert_eq!(
        android_13
            .unknown_rules()
            .iter()
            .find(|unknown| unknown.dump_index() == physical_index)
            .expect("signature mismatch")
            .reason(),
        AndroidRpdbUnknownReason::SignatureMismatch {
            expected_band: AndroidRpdbPriorityBand::LocalNetwork,
        }
    );

    let pinned = classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospNetd20250324);
    assert_eq!(pinned.unknown_rule_count(), 0);
    assert_eq!(
        pinned.roles()[physical_index],
        Some(AndroidRpdbRuleRole::PhysicalLocalNetwork)
    );
}

#[test]
fn system_permission_and_base_priority_role_variants_are_recognized() {
    let local_output_override = RuleSpec::netd(11_000, 97, RuleAction::TO_TABLE)
        .input(b"lo")
        .output(b"wlan0")
        .uid(0, 0)
        .build();
    let secure_system = RuleSpec::netd(13_000, VPN_TABLE, RuleAction::TO_TABLE)
        .mark(NET_ID | SYSTEM_PERMISSION, NET_ID_MASK | SYSTEM_PERMISSION)
        .build();
    let output_system = RuleSpec::netd(17_000, NETWORK_TABLE, RuleAction::TO_TABLE)
        .mark(SYSTEM_PERMISSION, SYSTEM_PERMISSION)
        .input(b"lo")
        .output(b"wlan0")
        .build();
    let bypass_system = RuleSpec::netd(24_000, VPN_TABLE, RuleAction::TO_TABLE)
        .mark(NET_ID | SYSTEM_PERMISSION, NET_ID_MASK | SYSTEM_PERMISSION)
        .build();
    let local_exclusion_system = RuleSpec::netd(27_000, VPN_TABLE, RuleAction::TO_TABLE)
        .mark(NET_ID | SYSTEM_PERMISSION, NET_ID_MASK | SYSTEM_PERMISSION)
        .build();
    let default_none = RuleSpec::netd(31_000, NETWORK_TABLE, RuleAction::TO_TABLE)
        .mark(0, NET_ID_MASK)
        .input(b"lo")
        .build();
    let variants = [
        (
            AndroidRpdbRuleRole::VpnOverrideOutputInterface,
            local_output_override,
        ),
        (AndroidRpdbRuleRole::SecureVpn, secure_system),
        (AndroidRpdbRuleRole::OutputInterface, output_system),
        (
            AndroidRpdbRuleRole::BypassableVpnNoLocalExclusion,
            bypass_system,
        ),
        (
            AndroidRpdbRuleRole::BypassableVpnLocalExclusion,
            local_exclusion_system,
        ),
        (AndroidRpdbRuleRole::DefaultNetwork, default_none),
    ];
    let mut rules = skeleton();
    rules.extend(variants.iter().map(|(_, rule)| rule.clone()));
    sort_rules(&mut rules);
    let inventory = inventory(rules);
    let report = classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospAndroid13R1);

    assert_eq!(report.unknown_rule_count(), 0);
    for (expected_role, rule) in variants {
        assert_eq!(
            report.roles()[rule_index(&inventory, &rule)],
            Some(expected_role)
        );
    }
}

#[test]
fn default_subpriority_extremes_follow_the_selected_profile_exactly() {
    let s_default = RuleSpec::netd(27_999, NETWORK_TABLE, RuleAction::TO_TABLE)
        .mark(0, NET_ID_MASK)
        .input(b"lo")
        .uid(10_000, 19_999)
        .build();
    let s_unreachable = RuleSpec::netd(28_999, 0, RuleAction::UNREACHABLE)
        .mark(0, NET_ID_MASK)
        .input(b"lo")
        .uid(20_000, 29_999)
        .build();
    let mut s_rules = skeleton();
    s_rules.extend([s_default.clone(), s_unreachable.clone()]);
    sort_rules(&mut s_rules);
    let s_inventory = inventory(s_rules);
    let s_report = classify_android_rpdb(&s_inventory, AndroidNetdSourceProfile::AospAndroid12R1);
    assert_eq!(s_report.unknown_rule_count(), 0);
    assert_eq!(
        s_report.roles()[rule_index(&s_inventory, &s_default)],
        Some(AndroidRpdbRuleRole::UidDefaultNetwork)
    );
    assert_eq!(
        s_report.roles()[rule_index(&s_inventory, &s_unreachable)],
        Some(AndroidRpdbRuleRole::UidDefaultUnreachable)
    );

    let t_default = RuleSpec::netd(29_998, NETWORK_TABLE, RuleAction::TO_TABLE)
        .mark(0, NET_ID_MASK)
        .input(b"lo")
        .uid(10_000, 19_999)
        .build();
    let t_unreachable = RuleSpec::netd(30_998, 0, RuleAction::UNREACHABLE)
        .mark(0, NET_ID_MASK)
        .input(b"lo")
        .uid(20_000, 29_999)
        .build();
    let forbidden_default = RuleSpec::netd(29_999, NETWORK_TABLE, RuleAction::TO_TABLE)
        .mark(0, NET_ID_MASK)
        .input(b"lo")
        .uid(30_000, 39_999)
        .build();
    let mut t_rules = skeleton();
    t_rules.extend([
        t_default.clone(),
        forbidden_default.clone(),
        t_unreachable.clone(),
    ]);
    sort_rules(&mut t_rules);
    let t_inventory = inventory(t_rules);
    let t_report = classify_android_rpdb(&t_inventory, AndroidNetdSourceProfile::AospAndroid13R1);
    assert_eq!(
        t_report.roles()[rule_index(&t_inventory, &t_default)],
        Some(AndroidRpdbRuleRole::UidDefaultNetwork)
    );
    assert_eq!(
        t_report.roles()[rule_index(&t_inventory, &t_unreachable)],
        Some(AndroidRpdbRuleRole::UidDefaultUnreachable)
    );
    let forbidden_index = rule_index(&t_inventory, &forbidden_default);
    assert_eq!(t_report.roles()[forbidden_index], None);
    assert_eq!(
        t_report
            .unknown_rules()
            .iter()
            .find(|unknown| unknown.dump_index() == forbidden_index)
            .expect("special no-default subpriority is not a default rule")
            .reason(),
        AndroidRpdbUnknownReason::UnrecognizedPriority
    );
}

#[test]
fn profile_sensitive_tail_rules_never_cross_dialects() {
    let s_fallthrough = RuleSpec::netd(26_000, NETWORK_TABLE, RuleAction::TO_TABLE)
        .mark(
            NET_ID | NETWORK_PERMISSION,
            NET_ID_MASK | NETWORK_PERMISSION,
        )
        .build();
    let mut s_rules = skeleton();
    s_rules.push(s_fallthrough.clone());
    sort_rules(&mut s_rules);
    let s_inventory = inventory(s_rules);
    let s_report = classify_android_rpdb(&s_inventory, AndroidNetdSourceProfile::AospAndroid12R1);
    let s_index = rule_index(&s_inventory, &s_fallthrough);
    assert_eq!(
        s_report.roles()[s_index],
        Some(AndroidRpdbRuleRole::VpnFallthrough)
    );

    let t_report = classify_android_rpdb(&s_inventory, AndroidNetdSourceProfile::AospAndroid13R1);
    assert_eq!(t_report.roles()[s_index], None);
    assert_eq!(
        t_report.unknown_rules()[0].reason(),
        AndroidRpdbUnknownReason::SignatureMismatch {
            expected_band: AndroidRpdbPriorityBand::LocalRoutes,
        }
    );

    let t_uid_local = RuleSpec::netd(25_000, LOCAL_COPY_TABLE, RuleAction::TO_TABLE)
        .mark(0, EXPLICIT)
        .input(b"lo")
        .uid(10_000, 19_999)
        .build();
    let mut t_rules = skeleton();
    t_rules.push(t_uid_local.clone());
    sort_rules(&mut t_rules);
    let t_inventory = inventory(t_rules);
    let t_report = classify_android_rpdb(&t_inventory, AndroidNetdSourceProfile::AospAndroid13R1);
    let t_index = rule_index(&t_inventory, &t_uid_local);
    assert_eq!(
        t_report.roles()[t_index],
        Some(AndroidRpdbRuleRole::UidLocalRoutes)
    );

    let s_report = classify_android_rpdb(&t_inventory, AndroidNetdSourceProfile::AospAndroid12R1);
    assert_eq!(s_report.roles()[t_index], None);
    assert_eq!(
        s_report.unknown_rules()[0].reason(),
        AndroidRpdbUnknownReason::UnrecognizedPriority
    );
}

#[test]
fn every_modeled_field_is_part_of_default_network_recognition() {
    let exact = default_network(29_000);
    let mut variants = Vec::new();

    let mut source = RuleSpec::default_network(29_000);
    source.source =
        RulePrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("source prefix");
    variants.push(source.build());

    let mut destination = RuleSpec::default_network(29_000);
    destination.destination =
        RulePrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).expect("destination prefix");
    variants.push(destination.build());

    let mut tos = RuleSpec::default_network(29_000);
    tos.tos = 4;
    variants.push(tos.build());

    let mut protocol = RuleSpec::default_network(29_000);
    protocol.protocol = 2;
    variants.push(protocol.build());

    let mut flags = RuleSpec::default_network(29_000);
    flags.flags = RuleFlags::INVERT;
    variants.push(flags.build());

    let mut action = RuleSpec::default_network(29_000);
    action.action = RuleAction::PROHIBIT;
    action.table = 0;
    variants.push(action.build());

    let mut table = RuleSpec::default_network(29_000);
    table.table = 97;
    variants.push(table.build());

    let mut mark = RuleSpec::default_network(29_000);
    mark.fwmark = RuleFwMark::new(0, EXPLICIT);
    variants.push(mark.build());

    let mut input = RuleSpec::default_network(29_000);
    input.input = None;
    variants.push(input.build());

    let mut output = RuleSpec::default_network(29_000);
    output.output = Some(interface(b"wlan0"));
    variants.push(output.build());

    let mut uid = RuleSpec::default_network(29_000);
    uid.uid = Some(RuleUidRange::new(10_000, 19_999).expect("UID range"));
    variants.push(uid.build());

    let mut tunnel = RuleSpec::default_network(29_000);
    tunnel.tunnel_id = RuleTunnelId::new(1);
    variants.push(tunnel.build());

    let mut suppress_group = RuleSpec::default_network(29_000);
    suppress_group.suppress_group = RuleSuppressInterfaceGroup::from_raw(1);
    variants.push(suppress_group.build());

    let mut suppress_prefix = RuleSpec::default_network(29_000);
    suppress_prefix.suppress_prefix = RuleSuppressPrefixLength::from_raw(0);
    variants.push(suppress_prefix.build());

    let mut ip_protocol = RuleSpec::default_network(29_000);
    ip_protocol.ip_protocol = RuleIpProtocol::new(6);
    variants.push(ip_protocol.build());

    let mut source_port = RuleSpec::default_network(29_000);
    source_port.source_port = Some(RulePortRange::new(1, 1).expect("source port"));
    variants.push(source_port.build());

    let mut destination_port = RuleSpec::default_network(29_000);
    destination_port.destination_port = Some(RulePortRange::new(53, 53).expect("destination port"));
    variants.push(destination_port.build());

    let mut flow = RuleSpec::default_network(29_000);
    flow.flow = RuleFlowId::new(1);
    variants.push(flow.build());

    for variant in variants {
        let mut rules = skeleton();
        rules.push(variant.clone());
        sort_rules(&mut rules);
        let inventory = inventory(rules);
        let report = classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospAndroid12R1);
        let index = rule_index(&inventory, &variant);
        assert_eq!(report.roles()[index], None, "variant: {variant:?}");
        assert_eq!(
            report.audit().classifications()[index],
            RpdbRuleClassification::Unknown
        );
        assert_eq!(report.unknown_rule_count(), 1);
        assert_eq!(
            report.unknown_rules()[0].reason(),
            AndroidRpdbUnknownReason::SignatureMismatch {
                expected_band: AndroidRpdbPriorityBand::DefaultNetwork,
            }
        );
        assert!(report.profile_issues().is_empty());
    }

    let mut exact_rules = skeleton();
    exact_rules.push(exact.clone());
    sort_rules(&mut exact_rules);
    let exact_inventory = inventory(exact_rules);
    let exact_report =
        classify_android_rpdb(&exact_inventory, AndroidNetdSourceProfile::AospAndroid12R1);
    assert_eq!(
        exact_report.roles()[rule_index(&exact_inventory, &exact)],
        Some(AndroidRpdbRuleRole::DefaultNetwork)
    );
}

#[test]
fn every_recognized_role_rejects_an_unrelated_selector() {
    let tunnel_id = RuleTunnelId::new(1).expect("test tunnel ID");
    for profile in [
        AndroidNetdSourceProfile::AospAndroid12R1,
        AndroidNetdSourceProfile::AospAndroid13R1,
        AndroidNetdSourceProfile::AospNetd20250324,
    ] {
        let fixture = complete_role_fixture(profile);
        for (changed_index, (expected_role, _)) in fixture.iter().enumerate() {
            let mut rules = fixture
                .iter()
                .map(|(_, rule)| rule.clone())
                .collect::<Vec<_>>();
            rules[changed_index] = rules[changed_index].clone().with_tunnel_id(tunnel_id);
            let inventory = inventory(rules);
            let report = classify_android_rpdb(&inventory, profile);

            assert_eq!(
                report.roles()[changed_index],
                None,
                "{profile:?} {expected_role:?} accepted an unrelated tunnel selector"
            );
            assert_eq!(
                report.audit().classifications()[changed_index],
                RpdbRuleClassification::Unknown
            );
        }
    }
}

#[test]
fn opaque_rules_remain_unknown_before_any_shape_is_trusted() {
    let opaque = RuleSpec::default_network(29_000).opacity().build();
    let mut rules = skeleton();
    rules.push(opaque.clone());
    sort_rules(&mut rules);
    let inventory = inventory(rules);
    let report = classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospAndroid12R1);
    let index = rule_index(&inventory, &opaque);

    assert_eq!(report.roles()[index], None);
    assert_eq!(report.unknown_rule_count(), 1);
    assert_eq!(
        report.unknown_rules()[0].reason(),
        AndroidRpdbUnknownReason::OpaqueAttributes
    );
}

#[test]
fn missing_anchors_and_nonmonotonic_family_order_downgrade_recognized_rules() {
    let mut missing = skeleton();
    missing.retain(|rule| rule.priority().get() != 19_000);
    let missing_inventory = inventory(missing);
    let missing_report = classify_android_rpdb(
        &missing_inventory,
        AndroidNetdSourceProfile::AospAndroid12R1,
    );
    assert!(missing_report.profile_issues().contains(
        &AndroidRpdbProfileIssue::MissingRequiredRole {
            family: NetworkAddressFamily::Ipv4,
            role: AndroidRpdbRuleRole::LegacyNetwork,
        }
    ));
    assert_eq!(
        missing_report.unknown_rule_count() as usize,
        missing_inventory.rules().len()
    );
    assert!(
        missing_report
            .audit()
            .classifications()
            .iter()
            .all(|classification| *classification == RpdbRuleClassification::Unknown)
    );
    assert!(missing_report.roles().iter().all(Option::is_some));

    let mut wrong_local_net_id = skeleton();
    let local_explicit = wrong_local_net_id
        .iter()
        .position(|rule| rule.priority().get() == 16_000)
        .expect("local explicit anchor");
    wrong_local_net_id[local_explicit] = RuleSpec::netd(16_000, 97, RuleAction::TO_TABLE)
        .mark(100 | EXPLICIT, NET_ID_MASK | EXPLICIT)
        .input(b"lo")
        .build();
    let wrong_local_inventory = inventory(wrong_local_net_id);
    let wrong_local_report = classify_android_rpdb(
        &wrong_local_inventory,
        AndroidNetdSourceProfile::AospAndroid12R1,
    );
    assert!(wrong_local_report.profile_issues().contains(
        &AndroidRpdbProfileIssue::MissingRequiredRole {
            family: NetworkAddressFamily::Ipv4,
            role: AndroidRpdbRuleRole::LocalNetworkExplicit,
        }
    ));
    assert_eq!(
        wrong_local_report.roles()[local_explicit],
        None,
        "a non-local netId cannot satisfy the initialization anchor"
    );

    let mut nonmonotonic = skeleton();
    let legacy_system = nonmonotonic
        .iter()
        .position(|rule| rule.priority().get() == 18_000)
        .expect("legacy system");
    let legacy_network = nonmonotonic
        .iter()
        .position(|rule| rule.priority().get() == 19_000)
        .expect("legacy network");
    nonmonotonic.swap(legacy_system, legacy_network);
    let nonmonotonic_inventory = inventory(nonmonotonic);
    let nonmonotonic_report = classify_android_rpdb(
        &nonmonotonic_inventory,
        AndroidNetdSourceProfile::AospAndroid12R1,
    );
    assert!(matches!(
        nonmonotonic_report.profile_issues()[0],
        AndroidRpdbProfileIssue::NonMonotonicPriority {
            family: NetworkAddressFamily::Ipv4,
            previous_priority,
            priority,
            ..
        } if previous_priority.get() == 19_000 && priority.get() == 18_000
    ));
    assert!(
        nonmonotonic_report
            .audit()
            .classifications()
            .iter()
            .all(|classification| *classification == RpdbRuleClassification::Unknown)
    );
}

#[test]
fn exact_duplicates_preserve_multiplicity_and_diagnostic_evidence_is_bounded() {
    let duplicate = RuleSpec::netd(18_000, 99, RuleAction::TO_TABLE)
        .mark(0, EXPLICIT)
        .build();
    let mut duplicate_rules = skeleton();
    duplicate_rules.push(duplicate.clone());
    sort_rules(&mut duplicate_rules);
    let duplicate_inventory = inventory(duplicate_rules);
    let duplicate_report = classify_android_rpdb(
        &duplicate_inventory,
        AndroidNetdSourceProfile::AospAndroid12R1,
    );
    assert_eq!(duplicate_report.unknown_rule_count(), 0);
    assert_eq!(
        duplicate_report
            .roles()
            .iter()
            .filter(|role| **role == Some(AndroidRpdbRuleRole::LegacySystem))
            .count(),
        2
    );

    let mut unknown_rules = skeleton();
    unknown_rules
        .extend((0..70).map(|_| RuleSpec::netd(30_000, 254, RuleAction::TO_TABLE).build()));
    sort_rules(&mut unknown_rules);
    let unknown_inventory = inventory(unknown_rules);
    let unknown_report = classify_android_rpdb(
        &unknown_inventory,
        AndroidNetdSourceProfile::AospAndroid12R1,
    );
    assert_eq!(unknown_report.unknown_rule_count(), 70);
    assert_eq!(
        unknown_report.unknown_rules().len(),
        MAX_ANDROID_RPDB_UNKNOWN_RULES
    );
    assert_eq!(unknown_report.omitted_unknown_rules(), 6);
    assert!(
        unknown_report
            .unknown_rules()
            .iter()
            .all(|unknown| unknown.reason() == AndroidRpdbUnknownReason::UnrecognizedPriority)
    );
}

#[test]
fn classifier_audit_carries_static_bounds_into_the_generic_and_android_planners() {
    let mut rules = skeleton();
    rules.extend([
        RuleSpec::netd(27_000, NETWORK_TABLE, RuleAction::TO_TABLE)
            .mark(0, NET_ID_MASK)
            .input(b"lo")
            .uid(10_000, 19_999)
            .build(),
        RuleSpec::netd(28_000, 0, RuleAction::UNREACHABLE)
            .mark(0, NET_ID_MASK)
            .input(b"lo")
            .uid(10_000, 19_999)
            .build(),
        default_network(29_000),
    ]);
    sort_rules(&mut rules);
    let inventory = inventory(rules);
    let report = classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospAndroid12R1);
    assert_eq!(report.unknown_rule_count(), 0);

    let placement = RpdbFamilyPlacement::with_address_bypass(
        RulePriority::from_raw(28_500),
        RulePriority::from_raw(28_600),
        RuleTableId::from_raw(500),
    )
    .expect("structural placement");
    let request = RpdbPlacementRequest::new(Some(placement), None).expect("IPv4 request");
    assert_eq!(
        plan_rpdb_placement(&inventory, report.audit(), request)
            .expect_err("classifier-owned static bounds seal the generic audit"),
        RpdbPlacementPlanError::PriorityWindowViolation {
            family: NetworkAddressFamily::Ipv4,
            last_must_precede: RulePriority::from_raw(28_999),
            address_bypass: Some(RulePriority::from_raw(28_500)),
            proxy: RulePriority::from_raw(28_600),
            first_terminal_barrier: RulePriority::from_raw(29_000),
        }
    );

    assert_eq!(
        plan_android_rpdb_placement(&inventory, &report, request)
            .expect_err("the profile reserves the entire dynamic band"),
        AndroidRpdbPlacementPlanError::StaticPriorityWindowViolation {
            family: NetworkAddressFamily::Ipv4,
            last_reserved_must_precede: RulePriority::from_raw(28_999),
            address_bypass: Some(RulePriority::from_raw(28_500)),
            proxy: RulePriority::from_raw(28_600),
            first_default_network: RulePriority::from_raw(29_000),
        }
    );
}

fn assert_complete_role_fixture(profile: AndroidNetdSourceProfile) {
    let fixture = complete_role_fixture(profile);
    let expected_roles = fixture
        .iter()
        .map(|(role, _)| Some(*role))
        .collect::<Vec<_>>();
    let rules = fixture
        .into_iter()
        .map(|(_, rule)| rule)
        .collect::<Vec<_>>();
    let inventory = inventory(rules);
    let report = classify_android_rpdb(&inventory, profile);

    assert_eq!(report.profile(), profile);
    assert_eq!(report.audit().snapshot_id(), inventory.snapshot_id());
    assert_eq!(report.audit().epoch(), inventory.epoch());
    assert_eq!(
        report.audit().classifier_revision(),
        profile.classifier_revision()
    );
    assert_eq!(report.roles(), expected_roles);
    assert_eq!(report.unknown_rule_count(), 0);
    assert!(report.unknown_rules().is_empty());
    assert_eq!(report.omitted_unknown_rules(), 0);
    assert!(report.profile_issues().is_empty());
    for (role, classification) in expected_roles
        .into_iter()
        .zip(report.audit().classifications().iter().copied())
    {
        let role = role.expect("complete fixture role");
        assert_eq!(classification, role.classification());
        assert_ne!(classification, RpdbRuleClassification::DoesNotConstrainFlux);
    }
}

fn complete_role_fixture(
    profile: AndroidNetdSourceProfile,
) -> Vec<(AndroidRpdbRuleRole, NetworkRuleRecord)> {
    let mut fixture = vec![
        (AndroidRpdbRuleRole::KernelLocal, kernel_local()),
        (
            AndroidRpdbRuleRole::VpnOverrideSystem,
            RuleSpec::netd(10_000, 99, RuleAction::TO_TABLE)
                .mark(SYSTEM_PERMISSION, EXPLICIT | SYSTEM_PERMISSION)
                .build(),
        ),
        (
            AndroidRpdbRuleRole::VpnOverrideOutputInterface,
            RuleSpec::netd(11_000, NETWORK_TABLE, RuleAction::TO_TABLE)
                .input(b"lo")
                .output(b"wlan0")
                .uid(0, 0)
                .build(),
        ),
        (
            AndroidRpdbRuleRole::VpnOutputToLocal,
            RuleSpec::netd(12_000, 97, RuleAction::TO_TABLE)
                .input(b"tun0")
                .build(),
        ),
        (
            AndroidRpdbRuleRole::SecureVpn,
            RuleSpec::netd(13_000, VPN_TABLE, RuleAction::TO_TABLE)
                .mark(0, PROTECTED)
                .input(b"lo")
                .uid(10_000, 19_999)
                .build(),
        ),
        (
            AndroidRpdbRuleRole::ProhibitNonVpn,
            RuleSpec::netd(14_000, 0, RuleAction::PROHIBIT)
                .mark(0, PROTECTED)
                .input(b"lo")
                .uid(10_000, 19_999)
                .build(),
        ),
        (
            AndroidRpdbRuleRole::UidExplicitNetwork,
            RuleSpec::netd(15_000, NETWORK_TABLE, RuleAction::TO_TABLE)
                .mark(NET_ID | EXPLICIT, NET_ID_MASK | EXPLICIT)
                .input(b"lo")
                .uid(10_000, 19_999)
                .build(),
        ),
        (
            AndroidRpdbRuleRole::UidExplicitUnreachable,
            RuleSpec::netd(15_001, 0, RuleAction::UNREACHABLE)
                .mark(NET_ID | EXPLICIT, NET_ID_MASK | EXPLICIT)
                .input(b"lo")
                .uid(20_000, 29_999)
                .build(),
        ),
        (
            AndroidRpdbRuleRole::LocalNetworkExplicit,
            RuleSpec::netd(16_000, 97, RuleAction::TO_TABLE)
                .mark(99 | EXPLICIT, NET_ID_MASK | EXPLICIT)
                .input(b"lo")
                .build(),
        ),
        (
            AndroidRpdbRuleRole::ExplicitNetwork,
            RuleSpec::netd(16_001, NETWORK_TABLE, RuleAction::TO_TABLE)
                .mark(
                    NET_ID | EXPLICIT | NETWORK_PERMISSION,
                    NET_ID_MASK | EXPLICIT | NETWORK_PERMISSION,
                )
                .input(b"lo")
                .uid(10_000, 19_999)
                .build(),
        ),
        (
            AndroidRpdbRuleRole::OutputInterface,
            RuleSpec::netd(17_000, NETWORK_TABLE, RuleAction::TO_TABLE)
                .input(b"lo")
                .output(b"wlan0")
                .build(),
        ),
        (
            AndroidRpdbRuleRole::LegacySystem,
            RuleSpec::netd(18_000, 99, RuleAction::TO_TABLE)
                .mark(0, EXPLICIT)
                .build(),
        ),
        (
            AndroidRpdbRuleRole::LegacyNetwork,
            RuleSpec::netd(19_000, 98, RuleAction::TO_TABLE)
                .mark(0, EXPLICIT)
                .build(),
        ),
        (
            AndroidRpdbRuleRole::LocalNetwork,
            RuleSpec::netd(20_000, 97, RuleAction::TO_TABLE)
                .mark(0, EXPLICIT)
                .build(),
        ),
    ];
    if profile == AndroidNetdSourceProfile::AospNetd20250324 {
        fixture.push((
            AndroidRpdbRuleRole::PhysicalLocalNetwork,
            RuleSpec::netd(20_000, NETWORK_TABLE, RuleAction::TO_TABLE)
                .mark(0, EXPLICIT)
                .build(),
        ));
    }
    fixture.extend([
        (
            AndroidRpdbRuleRole::Tethering,
            RuleSpec::netd(21_000, NETWORK_TABLE, RuleAction::TO_TABLE)
                .input(b"rndis0")
                .build(),
        ),
        (
            AndroidRpdbRuleRole::UidImplicitNetwork,
            RuleSpec::netd(22_000, NETWORK_TABLE, RuleAction::TO_TABLE)
                .mark(NET_ID, NET_ID_MASK | EXPLICIT)
                .input(b"lo")
                .uid(10_000, 19_999)
                .build(),
        ),
        (
            AndroidRpdbRuleRole::UidImplicitUnreachable,
            RuleSpec::netd(22_001, 0, RuleAction::UNREACHABLE)
                .mark(NET_ID, NET_ID_MASK | EXPLICIT)
                .input(b"lo")
                .uid(20_000, 29_999)
                .build(),
        ),
        (
            AndroidRpdbRuleRole::ImplicitNetwork,
            RuleSpec::netd(23_000, NETWORK_TABLE, RuleAction::TO_TABLE)
                .mark(NET_ID, NET_ID_MASK | EXPLICIT)
                .input(b"lo")
                .build(),
        ),
        (
            AndroidRpdbRuleRole::BypassableVpnNoLocalExclusion,
            RuleSpec::netd(24_000, VPN_TABLE, RuleAction::TO_TABLE)
                .mark(0, EXPLICIT | PROTECTED)
                .input(b"lo")
                .uid(10_000, 19_999)
                .build(),
        ),
    ]);

    match profile {
        AndroidNetdSourceProfile::AospAndroid12R1 => fixture.extend([
            (
                AndroidRpdbRuleRole::VpnFallthrough,
                RuleSpec::netd(26_000, NETWORK_TABLE, RuleAction::TO_TABLE)
                    .mark(
                        NET_ID | NETWORK_PERMISSION,
                        NET_ID_MASK | NETWORK_PERMISSION,
                    )
                    .build(),
            ),
            (
                AndroidRpdbRuleRole::UidDefaultNetwork,
                RuleSpec::netd(27_000, NETWORK_TABLE, RuleAction::TO_TABLE)
                    .mark(0, NET_ID_MASK)
                    .input(b"lo")
                    .uid(10_000, 19_999)
                    .build(),
            ),
            (
                AndroidRpdbRuleRole::UidDefaultUnreachable,
                RuleSpec::netd(28_000, 0, RuleAction::UNREACHABLE)
                    .mark(0, NET_ID_MASK)
                    .input(b"lo")
                    .uid(20_000, 29_999)
                    .build(),
            ),
            (AndroidRpdbRuleRole::DefaultNetwork, default_network(29_000)),
        ]),
        AndroidNetdSourceProfile::AospAndroid13R1 | AndroidNetdSourceProfile::AospNetd20250324 => {
            fixture.extend([
                (
                    AndroidRpdbRuleRole::UidLocalRoutes,
                    RuleSpec::netd(25_000, LOCAL_COPY_TABLE, RuleAction::TO_TABLE)
                        .mark(0, EXPLICIT)
                        .input(b"lo")
                        .uid(10_000, 19_999)
                        .build(),
                ),
                (
                    AndroidRpdbRuleRole::LocalRoutes,
                    RuleSpec::netd(26_000, LOCAL_COPY_TABLE, RuleAction::TO_TABLE)
                        .mark(0, EXPLICIT)
                        .input(b"lo")
                        .build(),
                ),
                (
                    AndroidRpdbRuleRole::BypassableVpnLocalExclusion,
                    RuleSpec::netd(27_000, VPN_TABLE, RuleAction::TO_TABLE)
                        .mark(0, EXPLICIT | PROTECTED)
                        .input(b"lo")
                        .uid(10_000, 19_999)
                        .build(),
                ),
                (
                    AndroidRpdbRuleRole::VpnFallthrough,
                    RuleSpec::netd(28_000, NETWORK_TABLE, RuleAction::TO_TABLE)
                        .mark(
                            NET_ID | NETWORK_PERMISSION,
                            NET_ID_MASK | NETWORK_PERMISSION,
                        )
                        .build(),
                ),
                (
                    AndroidRpdbRuleRole::UidDefaultNetwork,
                    RuleSpec::netd(29_000, NETWORK_TABLE, RuleAction::TO_TABLE)
                        .mark(0, NET_ID_MASK)
                        .input(b"lo")
                        .uid(10_000, 19_999)
                        .build(),
                ),
                (
                    AndroidRpdbRuleRole::UidDefaultUnreachable,
                    RuleSpec::netd(30_000, 0, RuleAction::UNREACHABLE)
                        .mark(0, NET_ID_MASK)
                        .input(b"lo")
                        .uid(20_000, 29_999)
                        .build(),
                ),
                (AndroidRpdbRuleRole::DefaultNetwork, default_network(31_000)),
            ])
        }
    }
    fixture.push((AndroidRpdbRuleRole::FinalUnreachable, final_unreachable()));
    fixture
}

fn skeleton() -> Vec<NetworkRuleRecord> {
    skeleton_for(NetworkAddressFamily::Ipv4)
}

fn skeleton_for(family: NetworkAddressFamily) -> Vec<NetworkRuleRecord> {
    vec![
        kernel_local_for(family),
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
        final_unreachable_for(family),
    ]
}

fn kernel_local() -> NetworkRuleRecord {
    kernel_local_for(NetworkAddressFamily::Ipv4)
}

fn kernel_local_for(family: NetworkAddressFamily) -> NetworkRuleRecord {
    let mut spec = RuleSpec::netd(0, 255, RuleAction::TO_TABLE);
    spec.protocol = 2;
    spec.family(family).build()
}

fn default_network(priority: u32) -> NetworkRuleRecord {
    RuleSpec::default_network(priority).build()
}

fn final_unreachable() -> NetworkRuleRecord {
    final_unreachable_for(NetworkAddressFamily::Ipv4)
}

fn final_unreachable_for(family: NetworkAddressFamily) -> NetworkRuleRecord {
    RuleSpec::netd(32_000, 0, RuleAction::UNREACHABLE)
        .family(family)
        .build()
}

fn sort_rules(rules: &mut [NetworkRuleRecord]) {
    rules.sort_by_key(NetworkRuleRecord::priority);
}

fn rule_index(inventory: &NetworkInventory, expected: &NetworkRuleRecord) -> usize {
    inventory
        .rules()
        .iter()
        .position(|rule| rule == expected)
        .expect("expected rule in inventory")
}

fn inventory(rules: impl IntoIterator<Item = NetworkRuleRecord>) -> NetworkInventory {
    let mut tracker = NetworkInventoryTracker::new();
    tracker
        .publish_complete_with_routing([], [], [], rules)
        .expect("complete inventory")
        .clone()
}

fn interface(name: &[u8]) -> InterfaceName {
    InterfaceName::new(name).expect("valid interface name")
}

#[derive(Clone)]
struct RuleSpec {
    destination: RulePrefix,
    source: RulePrefix,
    tos: u8,
    table: u32,
    action: RuleAction,
    protocol: u8,
    flags: RuleFlags,
    priority: u32,
    fwmark: Option<RuleFwMark>,
    input: Option<InterfaceName>,
    output: Option<InterfaceName>,
    uid: Option<RuleUidRange>,
    tunnel_id: Option<RuleTunnelId>,
    suppress_group: Option<RuleSuppressInterfaceGroup>,
    suppress_prefix: Option<RuleSuppressPrefixLength>,
    ip_protocol: Option<RuleIpProtocol>,
    source_port: Option<RulePortRange>,
    destination_port: Option<RulePortRange>,
    flow: Option<RuleFlowId>,
    opaque: bool,
}

impl RuleSpec {
    fn netd(priority: u32, table: u32, action: RuleAction) -> Self {
        Self {
            destination: RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
            source: RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
            tos: 0,
            table,
            action,
            protocol: 0,
            flags: RuleFlags::default(),
            priority,
            fwmark: None,
            input: None,
            output: None,
            uid: None,
            tunnel_id: None,
            suppress_group: None,
            suppress_prefix: None,
            ip_protocol: None,
            source_port: None,
            destination_port: None,
            flow: None,
            opaque: false,
        }
    }

    fn default_network(priority: u32) -> Self {
        Self::netd(priority, NETWORK_TABLE, RuleAction::TO_TABLE)
            .mark(NETWORK_PERMISSION, NET_ID_MASK | NETWORK_PERMISSION)
            .input(b"lo")
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

    fn output(mut self, name: &[u8]) -> Self {
        self.output = Some(interface(name));
        self
    }

    fn uid(mut self, start: u32, end: u32) -> Self {
        self.uid = Some(RuleUidRange::new(start, end).expect("valid UID range"));
        self
    }

    fn opacity(mut self) -> Self {
        self.opaque = true;
        self
    }

    fn build(self) -> NetworkRuleRecord {
        let mut record = NetworkRuleRecord::new(
            self.destination,
            self.source,
            RuleProperties::new(
                self.tos,
                RuleTableId::from_raw(self.table),
                self.action,
                RuleProtocol::from_raw(self.protocol),
                self.flags,
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
        if let Some(output) = self.output {
            record = record.with_output_interface(output);
        }
        if let Some(uid) = self.uid {
            record = record.with_uid_range(uid);
        }
        if let Some(tunnel_id) = self.tunnel_id {
            record = record.with_tunnel_id(tunnel_id);
        }
        if let Some(group) = self.suppress_group {
            record = record.with_suppress_interface_group(group);
        }
        if let Some(prefix) = self.suppress_prefix {
            record = record.with_suppress_prefix_length(prefix);
        }
        if let Some(protocol) = self.ip_protocol {
            record = record.with_ip_protocol(protocol);
        }
        if let Some(range) = self.source_port {
            record = record.with_source_port_range(range);
        }
        if let Some(range) = self.destination_port {
            record = record.with_destination_port_range(range);
        }
        if let Some(flow) = self.flow {
            record = record.with_flow(flow).expect("IPv4 flow fixture");
        }
        if self.opaque {
            record = record.with_attribute_opacity(
                RuleAttributeOpacity::new(
                    [OpaqueRuleAttribute::new(25, 0, 4)],
                    0,
                    RuleOpaqueAttributeFingerprint::from_bytes([0x25; 32]),
                )
                .expect("opaque fixture"),
            );
        }
        record
    }
}
