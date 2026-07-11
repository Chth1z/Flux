use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use flux_core::{
    InterfaceAddressFlags, InterfaceAddressRecord, InterfaceAddressRecordErrorKind, InterfaceIndex,
    NetworkEpoch, NetworkInventoryError, NetworkInventoryTracker,
};

#[test]
fn identifiers_prefixes_and_address_flags_preserve_their_domain_invariants() {
    assert_eq!(NetworkEpoch::new(0), None);
    assert_eq!(InterfaceIndex::new(0), None);

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
fn complete_publications_are_order_independent_and_deduplicate_exact_records() {
    let first = address_record(7, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 24, 0);
    let second = address_record(9, IpAddr::V6(Ipv6Addr::LOCALHOST), 128, 0x80);
    let mut left_tracker = NetworkInventoryTracker::new();
    let mut right_tracker = NetworkInventoryTracker::new();
    let left = left_tracker
        .publish_complete([second, first, first])
        .expect("complete inventory");
    let right = right_tracker
        .publish_complete([first, second])
        .expect("complete inventory");

    assert_eq!(left.addresses(), &[first, second]);
    assert_eq!(right.addresses(), &[first, second]);
    assert!(!left.materially_differs_from(right));

    let mut changed_tracker = NetworkInventoryTracker::new();
    let changed = changed_tracker
        .publish_complete([first])
        .expect("complete inventory");
    assert!(left.materially_differs_from(changed));
}

#[test]
fn conflicting_flags_for_one_canonical_address_are_rejected() {
    let address = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let temporary = address_record(9, address, 128, InterfaceAddressFlags::TEMPORARY.bits());
    let deprecated = address_record(9, address, 128, InterfaceAddressFlags::DEPRECATED.bits());
    let mut tracker = NetworkInventoryTracker::new();
    let prior_epoch = tracker
        .publish_complete([temporary])
        .expect("initial complete inventory")
        .epoch();

    let error = tracker
        .publish_complete([deprecated, temporary, temporary])
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
    let mut tracker = NetworkInventoryTracker::new();

    let initial_epoch = tracker
        .publish_complete([first, second])
        .expect("initial complete snapshot")
        .epoch();
    let equivalent_epoch = tracker
        .publish_complete([second, first, first])
        .expect("equivalent complete snapshot")
        .epoch();
    let changed_epoch = tracker
        .publish_complete([first, changed_second])
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
