use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use flux_core::{
    INTERFACE_LINK_KIND_MAX_BYTES, INTERFACE_NAME_MAX_BYTES, InterfaceAddressFlags,
    InterfaceAddressRecord, InterfaceAddressRecordErrorKind, InterfaceHardwareType, InterfaceIndex,
    InterfaceLinkFlags, InterfaceLinkKind, InterfaceLinkRecord, InterfaceName,
    InterfaceOperationalState, NetworkAddressFamily, NetworkEpoch, NetworkInventoryError,
    NetworkInventoryTracker, NetworkRouteRecord, NetworkRuleRecord, RouteFlags, RoutePath,
    RoutePrefix, RouteProperties, RouteProtocol, RouteScope, RouteTableId, RouteType, RuleAction,
    RuleFlags, RulePrefix, RulePriority, RuleProperties, RuleProtocol, RuleTableId,
};

#[test]
fn identifiers_prefixes_and_address_flags_preserve_their_domain_invariants() {
    assert_eq!(NetworkEpoch::new(0), None);
    assert_eq!(InterfaceIndex::new(0), None);
    assert_eq!(
        InterfaceIndex::new(i32::MAX as u32).map(InterfaceIndex::get),
        Some(i32::MAX as u32)
    );
    assert_eq!(InterfaceIndex::new(i32::MAX as u32 + 1), None);
    assert_eq!(InterfaceIndex::new(u32::MAX), None);

    let interface = InterfaceIndex::new(7).expect("nonzero interface index");
    let mut flags = InterfaceAddressFlags::TEMPORARY | InterfaceAddressFlags::STABLE_PRIVACY;
    flags |= InterfaceAddressFlags::from_bits(0x8000_0000);
    let ipv4_error = InterfaceAddressRecord::new(
        interface,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        33,
        flags,
    )
    .expect_err("IPv4 prefixes cannot exceed 32 bits");
    let ipv6_error =
        InterfaceAddressRecord::new(interface, IpAddr::V6(Ipv6Addr::LOCALHOST), 129, flags)
            .expect_err("IPv6 prefixes cannot exceed 128 bits");

    assert_eq!(
        ipv4_error.kind(),
        InterfaceAddressRecordErrorKind::InvalidPrefixLength
    );
    assert_eq!(
        ipv6_error.kind(),
        InterfaceAddressRecordErrorKind::InvalidPrefixLength
    );
    assert_eq!(flags.bits(), 0x8000_0801);
    assert!(flags.intersects(InterfaceAddressFlags::TEMPORARY));
    assert!(!flags.intersects(InterfaceAddressFlags::DEPRECATED));
}

#[test]
fn link_facts_preserve_kernel_identity_without_assuming_utf8_or_known_values() {
    let maximum_name = [b'n'; INTERFACE_NAME_MAX_BYTES];
    let maximum_kind = vec![b'k'; INTERFACE_LINK_KIND_MAX_BYTES];
    let non_utf8_name = InterfaceName::new(&[b'r', b'm', 0xff]).expect("raw interface name");
    let non_utf8_kind = InterfaceLinkKind::new(&[b'v', 0xfe]).expect("raw link kind");

    assert_eq!(
        InterfaceName::new(&maximum_name)
            .expect("maximum interface name")
            .as_bytes(),
        maximum_name
    );
    assert_eq!(
        InterfaceLinkKind::new(&maximum_kind)
            .expect("maximum link kind")
            .as_bytes(),
        maximum_kind.as_slice()
    );
    assert_eq!(non_utf8_name.as_str(), None);
    assert_eq!(non_utf8_kind.as_str(), None);
    for invalid in [
        &b""[..],
        &b"bad\0name"[..],
        &[b'x'; INTERFACE_NAME_MAX_BYTES + 1],
    ] {
        assert_eq!(InterfaceName::new(invalid), None);
    }
    assert_eq!(
        InterfaceName::new(b"raw/name: ok")
            .expect("raw bounded name")
            .as_bytes(),
        b"raw/name: ok"
    );
    assert_eq!(InterfaceLinkKind::new(b""), None);
    assert_eq!(InterfaceLinkKind::new(b"bad\0kind"), None);
    assert_eq!(
        InterfaceLinkKind::new(&vec![b'x'; INTERFACE_LINK_KIND_MAX_BYTES + 1]),
        None
    );
    let first_vendor_kind = InterfaceLinkKind::new(&[b'x'; 64]).expect("vendor kind");
    let mut other_vendor_bytes = [b'x'; 64];
    other_vendor_bytes[63] = b'y';
    let second_vendor_kind =
        InterfaceLinkKind::new(&other_vendor_bytes).expect("distinct vendor kind");
    assert_ne!(first_vendor_kind, second_vendor_kind);

    let interface_index = InterfaceIndex::new(7).expect("nonzero interface index");
    let mut flags = InterfaceLinkFlags::UP | InterfaceLinkFlags::LOWER_UP;
    flags |= InterfaceLinkFlags::from_bits(0x8000_0000);
    let unknown_state = InterfaceOperationalState::from_raw(0xfe);
    let record = InterfaceLinkRecord::new(
        interface_index,
        non_utf8_name,
        InterfaceHardwareType::from_raw(0xfffe),
        flags,
    )
    .with_mtu(0)
    .with_operational_state(unknown_state)
    .with_carrier(false)
    .with_kind(non_utf8_kind.clone());

    assert_eq!(record.interface_index(), interface_index);
    assert_eq!(record.name(), &non_utf8_name);
    assert_eq!(record.hardware_type().raw(), 0xfffe);
    assert_eq!(record.flags().bits(), 0x8001_0001);
    assert!(record.flags().intersects(InterfaceLinkFlags::LOWER_UP));
    assert_eq!(record.mtu(), Some(0));
    assert_eq!(record.operational_state(), Some(unknown_state));
    assert_eq!(unknown_state.raw(), 0xfe);
    assert_eq!(record.carrier(), Some(false));
    assert_eq!(record.kind(), Some(&non_utf8_kind));

    let minimal = InterfaceLinkRecord::new(
        interface_index,
        non_utf8_name,
        InterfaceHardwareType::from_raw(1),
        InterfaceLinkFlags::default(),
    );
    assert_eq!(minimal.mtu(), None);
    assert_eq!(minimal.operational_state(), None);
    assert_eq!(minimal.carrier(), None);
    assert_eq!(minimal.kind(), None);
}

#[test]
fn complete_publications_are_order_independent_and_deduplicate_exact_records() {
    let first = address_record(7, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 24, 0);
    let second = address_record(9, IpAddr::V6(Ipv6Addr::LOCALHOST), 128, 0x80);
    let first_link = link_record(7, b"eth0");
    let second_link = link_record(9, b"tun0");
    let mut left_tracker = NetworkInventoryTracker::new();
    let mut right_tracker = NetworkInventoryTracker::new();
    let left = left_tracker
        .publish_complete(
            [second_link.clone(), first_link.clone(), first_link.clone()],
            [second, first, first],
        )
        .expect("complete inventory");
    let right = right_tracker
        .publish_complete([first_link.clone(), second_link.clone()], [first, second])
        .expect("complete inventory");

    assert_eq!(left.links(), &[first_link.clone(), second_link.clone()]);
    assert_eq!(right.links(), left.links());
    assert_eq!(left.addresses(), &[first, second]);
    assert_eq!(right.addresses(), &[first, second]);
    assert!(!left.materially_differs_from(right));

    let mut link_changed_tracker = NetworkInventoryTracker::new();
    let link_changed = link_changed_tracker
        .publish_complete([first_link.clone()], [first, second])
        .expect("link-only candidate");
    assert!(left.materially_differs_from(link_changed));

    let mut address_changed_tracker = NetworkInventoryTracker::new();
    let address_changed = address_changed_tracker
        .publish_complete([first_link, second_link], [first])
        .expect("address-only candidate");
    assert!(left.materially_differs_from(address_changed));
}

#[test]
fn routing_publications_preserve_order_multiplicity_and_epoch_semantics() {
    let link = link_record(7, b"eth0");
    let address = address_record(7, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 24, 0);
    let first_route = route_record(100, 10);
    let second_route = route_record(200, 20);
    let first_rule = rule_record(100, 1_000);
    let second_rule = rule_record(200, 2_000);
    let routes = [
        second_route.clone(),
        first_route.clone(),
        second_route.clone(),
    ];
    let rules = [first_rule.clone(), second_rule.clone(), first_rule.clone()];
    let mut tracker = NetworkInventoryTracker::new();

    let initial = tracker
        .publish_complete_with_routing([link.clone()], [address], routes.clone(), rules.clone())
        .expect("complete routed inventory");
    let initial_pointer = std::ptr::from_ref(initial);
    let initial_epoch = initial.epoch();
    assert_eq!(initial.routes(), &routes);
    assert_eq!(initial.rules(), &rules);

    let unchanged = tracker
        .publish_complete_with_routing([link.clone()], [address], routes.clone(), rules.clone())
        .expect("unchanged routed inventory");
    assert_eq!(std::ptr::from_ref(unchanged), initial_pointer);
    assert_eq!(unchanged.epoch(), initial_epoch);

    let reordered = tracker
        .publish_complete_with_routing(
            [link],
            [address],
            [first_route, second_route.clone(), second_route],
            rules,
        )
        .expect("order-only route change");
    assert_eq!(reordered.epoch(), initial_epoch.checked_next().unwrap());

    let mut legacy = NetworkInventoryTracker::new();
    let legacy = legacy
        .publish_complete([], [])
        .expect("legacy complete publication");
    assert!(legacy.routes().is_empty());
    assert!(legacy.rules().is_empty());
}

#[test]
fn rejected_set_facts_leave_the_prior_ordered_routing_snapshot_intact() {
    let link = link_record(7, b"eth0");
    let address = address_record(7, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 24, 0);
    let route = route_record(100, 10);
    let rule = rule_record(100, 1_000);
    let mut tracker = NetworkInventoryTracker::new();
    let epoch = tracker
        .publish_complete_with_routing([link.clone()], [address], [route.clone()], [rule.clone()])
        .expect("initial routed inventory")
        .epoch();

    tracker
        .publish_complete_with_routing(
            [link, link_record(7, b"wlan0")],
            [address],
            [route_record(200, 20)],
            [rule_record(200, 2_000)],
        )
        .expect_err("conflicting link facts reject the whole candidate");

    let retained = tracker.current().expect("prior inventory remains current");
    assert_eq!(retained.epoch(), epoch);
    assert_eq!(retained.routes(), &[route]);
    assert_eq!(retained.rules(), &[rule]);
}

#[test]
fn conflicting_flags_for_one_canonical_address_are_rejected() {
    let address = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let temporary = address_record(9, address, 128, InterfaceAddressFlags::TEMPORARY.bits());
    let deprecated = address_record(9, address, 128, InterfaceAddressFlags::DEPRECATED.bits());
    let link = link_record(9, b"lo");
    let mut tracker = NetworkInventoryTracker::new();
    let prior_epoch = tracker
        .publish_complete([link.clone()], [temporary])
        .expect("initial complete inventory")
        .epoch();

    let error = tracker
        .publish_complete([link], [deprecated, temporary, temporary])
        .expect_err("one canonical address cannot carry conflicting flag records");
    let NetworkInventoryError::ConflictingAddressFlags(conflict) = error else {
        panic!("unexpected inventory error: {error}");
    };

    assert_eq!(
        conflict.interface_index(),
        InterfaceIndex::new(9).expect("nonzero interface index")
    );
    assert_eq!(conflict.address(), address);
    assert_eq!(conflict.prefix_length(), 128);
    assert_eq!(conflict.first_flags(), InterfaceAddressFlags::TEMPORARY);
    assert_eq!(conflict.second_flags(), InterfaceAddressFlags::DEPRECATED);
    let current = tracker
        .current()
        .expect("prior inventory remains published");
    assert_eq!(current.epoch(), prior_epoch);
    assert_eq!(current.addresses(), &[temporary]);
}

#[test]
fn tracker_advances_the_epoch_once_for_one_material_topology_change() {
    let first = address_record(7, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 24, 0);
    let second = address_record(9, IpAddr::V6(Ipv6Addr::LOCALHOST), 128, 0x80);
    let changed_second = address_record(9, IpAddr::V6(Ipv6Addr::LOCALHOST), 128, 0xa0);
    let first_link = link_record(7, b"eth0");
    let second_link = link_record(9, b"tun0");
    let mut tracker = NetworkInventoryTracker::new();

    let initial_epoch = tracker
        .publish_complete([first_link.clone(), second_link.clone()], [first, second])
        .expect("initial complete snapshot")
        .epoch();
    let equivalent_epoch = tracker
        .publish_complete(
            [second_link.clone(), first_link.clone(), first_link.clone()],
            [second, first, first],
        )
        .expect("equivalent complete snapshot")
        .epoch();
    let changed_epoch = tracker
        .publish_complete([first_link, second_link], [first, changed_second])
        .expect("changed complete snapshot")
        .epoch();

    assert_eq!(initial_epoch, NetworkEpoch::INITIAL);
    assert_eq!(equivalent_epoch, initial_epoch);
    assert_eq!(changed_epoch, initial_epoch.checked_next().unwrap());
    assert_eq!(
        tracker.current().expect("published inventory").epoch(),
        changed_epoch
    );
}

#[test]
fn link_only_and_address_only_changes_advance_separate_epochs() {
    let first_address = address_record(7, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 24, 0);
    let second_address = address_record(7, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), 24, 0);
    let first_link = link_record(7, b"eth0");
    let second_link = link_record(9, b"tun0");
    let mut tracker = NetworkInventoryTracker::new();

    let initial_epoch = tracker
        .publish_complete([first_link.clone()], [first_address])
        .expect("initial combined snapshot")
        .epoch();
    let link_epoch = tracker
        .publish_complete([first_link.clone(), second_link.clone()], [first_address])
        .expect("link-only change")
        .epoch();
    let address_epoch = tracker
        .publish_complete(
            [first_link.clone(), second_link.clone()],
            [first_address, second_address],
        )
        .expect("address-only change")
        .epoch();

    assert_eq!(initial_epoch, NetworkEpoch::INITIAL);
    assert_eq!(link_epoch, initial_epoch.checked_next().unwrap());
    assert_eq!(address_epoch, link_epoch.checked_next().unwrap());
    let current = tracker.current().expect("latest combined snapshot");
    assert_eq!(current.links(), &[first_link, second_link]);
    assert_eq!(current.addresses(), &[first_address, second_address]);
}

#[test]
fn unchanged_combined_snapshot_retains_the_published_inventory() {
    let first_address = address_record(7, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 24, 0);
    let second_address = address_record(9, IpAddr::V6(Ipv6Addr::LOCALHOST), 128, 0x80);
    let first_link = link_record(7, b"eth0");
    let second_link = link_record(9, b"tun0");
    let mut tracker = NetworkInventoryTracker::new();

    let initial = tracker
        .publish_complete(
            [first_link.clone(), second_link.clone()],
            [first_address, second_address],
        )
        .expect("initial combined snapshot");
    let initial_pointer = std::ptr::from_ref(initial);
    let initial_epoch = initial.epoch();
    let unchanged = tracker
        .publish_complete(
            [second_link, first_link.clone(), first_link.clone()],
            [second_address, first_address, first_address],
        )
        .expect("unchanged combined snapshot");

    assert_eq!(std::ptr::from_ref(unchanged), initial_pointer);
    assert_eq!(unchanged.epoch(), initial_epoch);
    assert_eq!(unchanged.links(), &[first_link, link_record(9, b"tun0")]);
    assert_eq!(unchanged.addresses(), &[first_address, second_address]);
}

#[test]
fn conflicting_links_are_rejected() {
    let first = link_record(7, b"eth0");
    let conflicting = link_record(7, b"wlan0");
    let mut tracker = NetworkInventoryTracker::new();

    let error = tracker
        .publish_complete([first, conflicting], [])
        .expect_err("one interface index cannot carry conflicting link facts");
    let NetworkInventoryError::ConflictingLinkFacts(conflict) = error else {
        panic!("unexpected inventory error: {error}");
    };
    assert_eq!(conflict.interface_index().get(), 7);
    assert!(tracker.current().is_none());
}

#[test]
fn one_primary_interface_name_on_different_indices_is_rejected() {
    let retained_link = link_record(3, b"lo");
    let duplicate_name = InterfaceName::new(b"eth0").expect("valid interface name");
    let lower_index = InterfaceIndex::new(7).expect("nonzero interface index");
    let higher_index = InterfaceIndex::new(9).expect("nonzero interface index");
    let mut tracker = NetworkInventoryTracker::new();
    let retained = tracker
        .publish_complete([retained_link.clone()], [])
        .expect("initial inventory");
    let retained_pointer = std::ptr::from_ref(retained);
    let retained_epoch = retained.epoch();

    let error = tracker
        .publish_complete(
            [
                link_record(higher_index.get(), duplicate_name.as_bytes()),
                link_record(lower_index.get(), duplicate_name.as_bytes()),
            ],
            [],
        )
        .expect_err("one primary name cannot identify two interface indices");
    let NetworkInventoryError::ConflictingInterfaceName(conflict) = error else {
        panic!("unexpected inventory error: {error}");
    };

    assert_eq!(conflict.name(), duplicate_name);
    assert_eq!(conflict.first_interface_index(), lower_index);
    assert_eq!(conflict.second_interface_index(), higher_index);
    let current = tracker
        .current()
        .expect("prior inventory remains published");
    assert_eq!(std::ptr::from_ref(current), retained_pointer);
    assert_eq!(current.epoch(), retained_epoch);
    assert_eq!(current.links(), &[retained_link]);
}

fn address_record(
    interface_index: u32,
    address: IpAddr,
    prefix_length: u8,
    flags: u32,
) -> InterfaceAddressRecord {
    InterfaceAddressRecord::new(
        InterfaceIndex::new(interface_index).expect("nonzero interface index"),
        address,
        prefix_length,
        InterfaceAddressFlags::from_bits(flags),
    )
    .expect("valid interface address record")
}

fn link_record(interface_index: u32, name: &[u8]) -> InterfaceLinkRecord {
    InterfaceLinkRecord::new(
        InterfaceIndex::new(interface_index).expect("nonzero interface index"),
        InterfaceName::new(name).expect("valid interface name"),
        InterfaceHardwareType::from_raw(1),
        InterfaceLinkFlags::default(),
    )
}

fn route_record(table: u32, priority: u32) -> NetworkRouteRecord {
    NetworkRouteRecord::new(
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv4),
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv4),
        RouteProperties::new(
            0,
            RouteTableId::from_raw(table),
            RouteProtocol::from_raw(2),
            RouteScope::from_raw(0),
            RouteType::from_raw(1),
            RouteFlags::default(),
        ),
        priority,
        RoutePath::None,
    )
    .expect("valid route record")
}

fn rule_record(table: u32, priority: u32) -> NetworkRuleRecord {
    NetworkRuleRecord::new(
        RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
        RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
        RuleProperties::new(
            0,
            RuleTableId::from_raw(table),
            RuleAction::TO_TABLE,
            RuleProtocol::from_raw(2),
            RuleFlags::default(),
        ),
        RulePriority::from_raw(priority),
        None,
    )
    .expect("valid rule record")
}
