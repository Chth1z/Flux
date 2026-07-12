use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use flux_core::{
    AddressBypassInventoryAddressErrorKind, AddressBypassPlanError, AddressBypassPolicy,
    AddressBypassPrefix, AddressBypassPrefixErrorKind, AddressBypassRoutingSpec,
    AddressBypassRoutingSpecErrorKind, AddressBypassRuleBudget, AddressBypassRuleConflictKind,
    InterfaceAddressFlags, InterfaceAddressRecord, InterfaceIndex, MAX_ADDRESS_BYPASS_CONFLICTS,
    MAX_ADDRESS_BYPASS_RULES, NetworkAddressFamily, NetworkInventory, NetworkInventoryTracker,
    NetworkRuleRecord, RuleAction, RuleFlags, RuleFwMark, RulePrefix, RulePriority, RuleProperties,
    RuleProtocol, RuleTableId, plan_address_bypass,
};

const SYNTHETIC_IPV4_PRIORITY: u32 = 40_001;
const SYNTHETIC_IPV6_PRIORITY: u32 = 40_002;

#[test]
fn planner_derives_deterministic_host_rules_and_deduplicates_addresses() {
    let ipv4_priority = RulePriority::from_raw(SYNTHETIC_IPV4_PRIORITY);
    let ipv6_priority = RulePriority::from_raw(SYNTHETIC_IPV6_PRIORITY);
    let policy = policy(
        AddressBypassRoutingSpec::new(
            RuleTableId::from_raw(254),
            RuleProtocol::from_raw(99),
            Some(ipv4_priority),
            Some(ipv6_priority),
        )
        .expect("explicit routing selection"),
        8,
    );
    let addresses = [
        address(9, IpAddr::V6("2001:db8::2".parse().unwrap()), 64, 0),
        address(8, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 25, 0),
        address(7, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8, 0),
        address(6, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 24, 0),
    ];
    let first = inventory(addresses, []);
    let second = inventory(addresses.into_iter().rev(), []);

    let first_plan = plan_address_bypass(&first, &policy).expect("first deterministic plan");
    let second_plan = plan_address_bypass(&second, &policy).expect("second deterministic plan");
    assert_ne!(first_plan.snapshot_id(), second_plan.snapshot_id());
    assert_eq!(first_plan.routing(), second_plan.routing());
    assert_eq!(first_plan.intents(), second_plan.intents());
    assert_eq!(first_plan.epoch(), first.epoch());
    assert_eq!(first_plan.routing(), policy.routing());
    assert_eq!(first_plan.intents().len(), 3);
    assert_eq!(
        first_plan
            .intents()
            .iter()
            .map(|intent| intent.destination())
            .collect::<Vec<_>>(),
        [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V6("2001:db8::2".parse().unwrap()),
        ]
    );
    for intent in first_plan.intents().iter().copied() {
        let record = intent.to_rule_record();
        let host_prefix = match intent.family() {
            NetworkAddressFamily::Ipv4 => 32,
            NetworkAddressFamily::Ipv6 => 128,
        };
        assert_eq!(record.destination().address(), intent.destination());
        assert_eq!(record.destination().prefix_length(), host_prefix);
        assert_eq!(record.source(), RulePrefix::unspecified(intent.family()));
        assert_eq!(record.properties().table(), RuleTableId::from_raw(254));
        assert_eq!(record.properties().action(), RuleAction::TO_TABLE);
        assert_eq!(record.properties().protocol(), RuleProtocol::from_raw(99));
        assert_eq!(record.properties().flags(), RuleFlags::default());
        assert_eq!(record.priority(), intent.priority());
        assert_eq!(
            record.priority(),
            if intent.family() == NetworkAddressFamily::Ipv4 {
                ipv4_priority
            } else {
                ipv6_priority
            }
        );
        assert_eq!(record.fwmark(), None);
        assert_eq!(record.uid_range(), None);
        assert_eq!(record.input_interface(), None);
        assert_eq!(record.output_interface(), None);
    }
}

#[test]
fn filters_normalize_mapped_inputs_and_apply_all_configurable_address_flags() {
    let ignored_flags = InterfaceAddressFlags::TEMPORARY
        | InterfaceAddressFlags::OPTIMISTIC
        | InterfaceAddressFlags::DAD_FAILED
        | InterfaceAddressFlags::DEPRECATED
        | InterfaceAddressFlags::TENTATIVE
        | InterfaceAddressFlags::STABLE_PRIVACY
        | InterfaceAddressFlags::MANAGE_TEMPORARY_ADDRESSES;
    let mapped_exact = IpAddr::V6("::ffff:192.0.2.9".parse().unwrap());
    let mapped_prefix = IpAddr::V6("::ffff:198.51.100.0".parse().unwrap());
    let policy = policy(ipv4_only_spec(), 16)
        .with_ignored_flags(ignored_flags)
        .with_ignored_addresses([mapped_exact])
        .with_ignored_prefixes([(mapped_prefix, 120)])
        .expect("mapped /120 becomes an IPv4 /24");
    let addresses = [
        address(1, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 24, 0),
        address(2, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)), 24, 0),
        address(3, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 24, 0x01),
        address(4, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 24, 0x04),
        address(5, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)), 24, 0x08),
        address(6, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)), 24, 0x20),
        address(7, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 24, 0x40),
        address(8, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 6)), 24, 0x100),
        address(9, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 24, 0x800),
        address(10, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 24, 0),
        address(11, IpAddr::V6("2001:db8::1".parse().unwrap()), 64, 0),
    ];

    let plan = plan_address_bypass(&inventory(addresses, []), &policy).expect("filtered plan");
    assert_eq!(plan.intents().len(), 1);
    assert_eq!(
        plan.intents()[0].destination(),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))
    );

    let prefix = AddressBypassPrefix::new(mapped_prefix, 120).expect("mapped prefix");
    assert_eq!(prefix.network(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)));
    assert_eq!(prefix.prefix_length(), 24);
    assert!(prefix.contains(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99))));
    assert!(prefix.contains(IpAddr::V6("::ffff:198.51.100.99".parse().unwrap())));
    assert!(!prefix.contains(IpAddr::V4(Ipv4Addr::new(198, 51, 101, 1))));

    let crossing = AddressBypassPrefix::new(mapped_prefix, 95).expect_err("mapping boundary");
    assert_eq!(
        crossing.kind(),
        AddressBypassPrefixErrorKind::UnsupportedMappedPrefix
    );
    assert_eq!(
        AddressBypassPrefix::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33)
            .expect_err("invalid IPv4 prefix")
            .kind(),
        AddressBypassPrefixErrorKind::InvalidPrefixLength
    );
    assert_eq!(
        AddressBypassPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 129)
            .expect_err("invalid IPv6 prefix")
            .kind(),
        AddressBypassPrefixErrorKind::InvalidPrefixLength
    );
}

#[test]
fn budget_is_enforced_after_filtering_and_cross_interface_deduplication() {
    let duplicate = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let within_budget = inventory(
        [address(1, duplicate, 24, 0), address(2, duplicate, 32, 0)],
        [],
    );
    assert_eq!(
        plan_address_bypass(&within_budget, &policy(ipv4_only_spec(), 1))
            .expect("one unique address")
            .intents()
            .len(),
        1
    );

    let over_budget = inventory(
        [
            address(1, duplicate, 24, 0),
            address(2, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 24, 0),
        ],
        [],
    );
    let error = plan_address_bypass(&over_budget, &policy(ipv4_only_spec(), 1))
        .expect_err("two unique rules exceed the bound");
    assert!(matches!(
        error,
        AddressBypassPlanError::RuleBudgetExceeded {
            budget,
            required_at_least: 2,
        } if budget.get() == 1
    ));
}

#[test]
fn exact_unowned_rules_are_conflicts_and_unrelated_priorities_are_ignored() {
    let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let routing = ipv4_only_spec();
    let inventory = inventory(
        [address(1, first, 24, 0), address(2, second, 24, 0)],
        [
            rule(first, 254, SYNTHETIC_IPV4_PRIORITY, 99),
            rule(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 100, 30_000, 2),
        ],
    );

    let error = plan_address_bypass(&inventory, &policy(routing, 8))
        .expect_err("canonical equality is not ownership evidence");
    let AddressBypassPlanError::RoutingConflict {
        conflicts,
        omitted_conflicts,
    } = error
    else {
        panic!("expected a routing conflict");
    };
    assert_eq!(omitted_conflicts, 0);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(
        conflicts[0].kind(),
        AddressBypassRuleConflictKind::ExactRuleWithoutOwnership
    );
    assert_eq!(conflicts[0].dump_index(), 0);
}

#[test]
fn duplicate_and_foreign_rules_at_a_selected_priority_are_conflicts_in_dump_order() {
    let desired = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let exact = rule(desired, 254, SYNTHETIC_IPV4_PRIORITY, 99);
    let foreign = rule(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
        254,
        SYNTHETIC_IPV4_PRIORITY,
        99,
    )
    .with_fwmark(RuleFwMark::new(1, 1).unwrap());
    let inventory = inventory(
        [address(1, desired, 24, 0)],
        [
            rule(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 100, 30_000, 2),
            exact.clone(),
            exact,
            foreign,
        ],
    );

    let error = plan_address_bypass(&inventory, &policy(ipv4_only_spec(), 8))
        .expect_err("selected priority is ambiguous");
    let AddressBypassPlanError::RoutingConflict {
        conflicts,
        omitted_conflicts,
    } = error
    else {
        panic!("expected a routing conflict");
    };
    assert_eq!(omitted_conflicts, 0);
    assert_eq!(conflicts.len(), 3);
    assert_eq!(
        conflicts[0].kind(),
        AddressBypassRuleConflictKind::ExactRuleWithoutOwnership
    );
    assert_eq!(conflicts[0].dump_index(), 1);
    assert_eq!(
        conflicts[1].kind(),
        AddressBypassRuleConflictKind::DuplicateExactRule
    );
    assert_eq!(conflicts[1].dump_index(), 2);
    assert_eq!(
        conflicts[2].kind(),
        AddressBypassRuleConflictKind::UnexpectedRuleAtSelectedPriority
    );
    assert_eq!(conflicts[2].dump_index(), 3);
}

#[test]
fn enabled_family_slots_are_reserved_even_without_a_current_desired_address() {
    let stale_looking = rule(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
        254,
        SYNTHETIC_IPV4_PRIORITY,
        99,
    );
    let inventory = inventory([], [stale_looking.clone()]);

    let error = plan_address_bypass(&inventory, &policy(ipv4_only_spec(), 8))
        .expect_err("unknown ownership cannot become an inferred delete");
    let AddressBypassPlanError::RoutingConflict {
        conflicts,
        omitted_conflicts,
    } = error
    else {
        panic!("expected a routing conflict");
    };
    assert_eq!(omitted_conflicts, 0);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(
        conflicts[0].kind(),
        AddressBypassRuleConflictKind::UnexpectedRuleAtSelectedPriority
    );
    assert_eq!(conflicts[0].observed(), &stale_looking);
}

#[test]
fn same_destination_field_mismatches_never_become_an_exact_identity_match() {
    let desired = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let family = NetworkAddressFamily::Ipv4;
    let destination = RulePrefix::new(desired, 32).unwrap();
    let source = RulePrefix::unspecified(family);
    let priority = RulePriority::from_raw(SYNTHETIC_IPV4_PRIORITY);
    let different_table = NetworkRuleRecord::new(
        destination,
        source,
        RuleProperties::new(
            0,
            RuleTableId::from_raw(253),
            RuleAction::TO_TABLE,
            RuleProtocol::from_raw(99),
            RuleFlags::default(),
        ),
        priority,
        None,
    )
    .unwrap();
    let different_protocol = NetworkRuleRecord::new(
        destination,
        source,
        RuleProperties::new(
            0,
            RuleTableId::from_raw(254),
            RuleAction::TO_TABLE,
            RuleProtocol::from_raw(98),
            RuleFlags::default(),
        ),
        priority,
        None,
    )
    .unwrap();
    let different_action = NetworkRuleRecord::new(
        destination,
        source,
        RuleProperties::new(
            0,
            RuleTableId::from_raw(254),
            RuleAction::BLACKHOLE,
            RuleProtocol::from_raw(99),
            RuleFlags::default(),
        ),
        priority,
        None,
    )
    .unwrap();
    let additional_selector =
        rule(desired, 254, SYNTHETIC_IPV4_PRIORITY, 99).with_fwmark(RuleFwMark::new(1, 1).unwrap());
    let inventory = inventory(
        [address(1, desired, 24, 0)],
        [
            different_table,
            different_protocol,
            different_action,
            additional_selector,
        ],
    );

    let error = plan_address_bypass(&inventory, &policy(ipv4_only_spec(), 8))
        .expect_err("every one-field mismatch remains foreign");
    let AddressBypassPlanError::RoutingConflict {
        conflicts,
        omitted_conflicts,
    } = error
    else {
        panic!("expected routing conflicts");
    };
    assert_eq!(omitted_conflicts, 0);
    assert_eq!(conflicts.len(), 4);
    assert!(conflicts.iter().all(|conflict| {
        conflict.kind() == AddressBypassRuleConflictKind::UnexpectedRuleAtSelectedPriority
    }));
}

#[test]
fn conflict_evidence_is_bounded_and_reports_the_omitted_count() {
    let conflict_count = MAX_ADDRESS_BYPASS_CONFLICTS + 5;
    let rules = (0..conflict_count)
        .map(|index| {
            rule(
                IpAddr::V4(Ipv4Addr::new(
                    198,
                    18,
                    u8::try_from(index / 256).unwrap(),
                    u8::try_from(index % 256).unwrap(),
                )),
                254,
                SYNTHETIC_IPV4_PRIORITY,
                99,
            )
        })
        .collect::<Vec<_>>();
    let error = plan_address_bypass(
        &inventory([], rules),
        &policy(ipv4_only_spec(), MAX_ADDRESS_BYPASS_RULES),
    )
    .expect_err("selected slot is occupied repeatedly");
    let AddressBypassPlanError::RoutingConflict {
        conflicts,
        omitted_conflicts,
    } = error
    else {
        panic!("expected bounded routing conflicts");
    };
    assert_eq!(conflicts.len(), MAX_ADDRESS_BYPASS_CONFLICTS);
    assert_eq!(omitted_conflicts, 5);
    assert_eq!(conflicts[0].dump_index(), 0);
    assert_eq!(
        conflicts[MAX_ADDRESS_BYPASS_CONFLICTS - 1].dump_index(),
        MAX_ADDRESS_BYPASS_CONFLICTS - 1
    );
}

#[test]
fn alternate_inventory_sources_filter_unusable_addresses_and_reject_bad_mapped_prefixes() {
    let usable = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    let filtered_inventory = inventory(
        [
            address(1, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 32, 0),
            address(2, IpAddr::V4(Ipv4Addr::LOCALHOST), 8, 0),
            address(3, IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), 16, 0),
            address(4, IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128, 0),
            address(5, IpAddr::V6(Ipv6Addr::LOCALHOST), 128, 0),
            address(6, IpAddr::V6("fe80::1".parse().unwrap()), 64, 0),
            address(7, usable, 24, 0),
        ],
        [],
    );
    let plan = plan_address_bypass(&filtered_inventory, &policy(ipv4_only_spec(), 8))
        .expect("only one global usable address remains");
    assert_eq!(plan.intents().len(), 1);
    assert_eq!(plan.intents()[0].destination(), usable);

    let invalid_mapped = address(8, IpAddr::V6("::ffff:192.0.2.10".parse().unwrap()), 95, 0);
    let error = plan_address_bypass(
        &inventory([invalid_mapped], []),
        &policy(ipv4_only_spec(), 8),
    )
    .expect_err("mapped inventory prefix crosses the mapping boundary");
    assert_eq!(
        error,
        AddressBypassPlanError::InvalidInventoryAddress {
            record: invalid_mapped,
            reason: AddressBypassInventoryAddressErrorKind::UnsupportedMappedPrefix,
        }
    );

    let valid_mapped = address(9, IpAddr::V6("::ffff:192.0.2.11".parse().unwrap()), 120, 0);
    let mapped_plan =
        plan_address_bypass(&inventory([valid_mapped], []), &policy(ipv4_only_spec(), 8))
            .expect("mapped /120 inventory address normalizes to IPv4");
    assert_eq!(
        mapped_plan.intents()[0].destination(),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))
    );
}

#[test]
fn routing_selection_rejects_structurally_unsafe_or_implicit_values() {
    let table = RuleTableId::from_raw(254);
    let protocol = RuleProtocol::from_raw(99);
    let priority = RulePriority::from_raw(SYNTHETIC_IPV4_PRIORITY);

    assert_eq!(
        AddressBypassRoutingSpec::new(RuleTableId::from_raw(0), protocol, Some(priority), None,)
            .expect_err("table zero")
            .kind(),
        AddressBypassRoutingSpecErrorKind::UnspecifiedLookupTable
    );
    assert_eq!(
        AddressBypassRoutingSpec::new(table, RuleProtocol::from_raw(0), Some(priority), None,)
            .expect("protocol zero remains an explicit observed identity")
            .protocol()
            .raw(),
        0
    );
    assert_eq!(
        AddressBypassRoutingSpec::new(table, protocol, None, None)
            .expect_err("no family")
            .kind(),
        AddressBypassRoutingSpecErrorKind::NoEnabledFamilies
    );
    assert_eq!(
        AddressBypassRoutingSpec::new(table, protocol, Some(RulePriority::from_raw(0)), None,)
            .expect_err("IPv4 priority zero")
            .kind(),
        AddressBypassRoutingSpecErrorKind::UnspecifiedPriority(NetworkAddressFamily::Ipv4)
    );
    assert_eq!(
        AddressBypassRoutingSpec::new(
            table,
            protocol,
            Some(priority),
            Some(RulePriority::from_raw(0)),
        )
        .expect_err("IPv6 priority zero")
        .kind(),
        AddressBypassRoutingSpecErrorKind::UnspecifiedPriority(NetworkAddressFamily::Ipv6)
    );
    assert!(AddressBypassRuleBudget::new(0).is_none());
    assert!(AddressBypassRuleBudget::new(MAX_ADDRESS_BYPASS_RULES).is_some());
    assert!(AddressBypassRuleBudget::new(MAX_ADDRESS_BYPASS_RULES + 1).is_none());
}

#[test]
fn plan_snapshot_identity_must_match_the_inventory_used_by_a_future_writer() {
    let mut tracker = NetworkInventoryTracker::new();
    let first = tracker
        .publish_complete_with_routing(
            [],
            [address(1, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24, 0)],
            [],
            [],
        )
        .expect("first inventory")
        .clone();
    let plan = plan_address_bypass(&first, &policy(ipv4_only_spec(), 8)).expect("first plan");
    plan.ensure_current(&first).expect("same snapshot");

    let second = tracker
        .publish_complete_with_routing(
            [],
            [address(1, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 24, 0)],
            [],
            [],
        )
        .expect("second inventory")
        .clone();
    let stale = plan.ensure_current(&second).expect_err("epoch changed");
    assert_eq!(stale.planned_snapshot_id(), first.snapshot_id());
    assert_eq!(stale.current_snapshot_id(), second.snapshot_id());
    assert_eq!(stale.planned_epoch(), first.epoch());
    assert_eq!(stale.current_epoch(), second.epoch());

    let unrelated = inventory(
        [address(9, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 24, 0)],
        [],
    );
    assert_eq!(unrelated.epoch(), first.epoch());
    let unrelated_error = plan
        .ensure_current(&unrelated)
        .expect_err("equal epoch from another tracker is not the same snapshot");
    assert_eq!(unrelated_error.planned_snapshot_id(), first.snapshot_id());
    assert_eq!(
        unrelated_error.current_snapshot_id(),
        unrelated.snapshot_id()
    );
}

fn policy(routing: AddressBypassRoutingSpec, budget: u32) -> AddressBypassPolicy {
    AddressBypassPolicy::new(
        routing,
        AddressBypassRuleBudget::new(budget).expect("nonzero test budget"),
    )
}

fn ipv4_only_spec() -> AddressBypassRoutingSpec {
    AddressBypassRoutingSpec::new(
        RuleTableId::from_raw(254),
        RuleProtocol::from_raw(99),
        Some(RulePriority::from_raw(SYNTHETIC_IPV4_PRIORITY)),
        None,
    )
    .expect("explicit IPv4 routing selection")
}

fn inventory(
    addresses: impl IntoIterator<Item = InterfaceAddressRecord>,
    rules: impl IntoIterator<Item = NetworkRuleRecord>,
) -> NetworkInventory {
    let mut tracker = NetworkInventoryTracker::new();
    tracker
        .publish_complete_with_routing([], addresses, [], rules)
        .expect("valid test inventory")
        .clone()
}

fn address(
    interface_index: u32,
    address: IpAddr,
    prefix_length: u8,
    flags: u32,
) -> InterfaceAddressRecord {
    InterfaceAddressRecord::new(
        InterfaceIndex::new(interface_index).expect("positive interface index"),
        address,
        prefix_length,
        InterfaceAddressFlags::from_bits(flags),
    )
    .expect("valid interface address")
}

fn rule(destination: IpAddr, table: u32, priority: u32, protocol: u8) -> NetworkRuleRecord {
    let family = match destination {
        IpAddr::V4(_) => NetworkAddressFamily::Ipv4,
        IpAddr::V6(_) => NetworkAddressFamily::Ipv6,
    };
    let prefix_length = match family {
        NetworkAddressFamily::Ipv4 => 32,
        NetworkAddressFamily::Ipv6 => 128,
    };
    NetworkRuleRecord::new(
        RulePrefix::new(destination, prefix_length).expect("host rule prefix"),
        RulePrefix::unspecified(family),
        RuleProperties::new(
            0,
            RuleTableId::from_raw(table),
            RuleAction::TO_TABLE,
            RuleProtocol::from_raw(protocol),
            RuleFlags::default(),
        ),
        RulePriority::from_raw(priority),
        None,
    )
    .expect("minimal test rule")
}
