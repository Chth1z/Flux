use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::time::Instant;

use flux_core::{InterfaceAddressFlags, InterfaceLinkFlags, NetworkEpoch};

use crate::address_sync::{AddressEventPolicy, RtnetlinkAddressEventDecoder};
use crate::netlink::link::RtnetlinkLinkEventDecoder;

const NETLINK_HEADER_LENGTH: usize = 16;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKINFO: u16 = 18;
const IFLA_CARRIER: u16 = 33;
const IFLA_INFO_KIND: u16 = 1;
const NLA_F_NESTED: u16 = 1 << 15;
const IFA_ADDRESS: u16 = 1;
const NLMSG_DONE: u16 = 3;

#[test]
fn source_is_none_before_first_complete_dump() {
    let mut observer = observer();
    let source = observer.source();
    let clone = source.clone();

    assert!(source.snapshot().is_none());
    assert!(clone.snapshot().is_none());

    complete_single_address_dump(&mut observer, 40, Instant::now(), 7, [192, 0, 2, 9], 24, 0);
    let first = source.snapshot().expect("published source snapshot");
    let second = clone.snapshot().expect("published clone snapshot");
    assert!(Arc::ptr_eq(&first, &second));
}

#[test]
fn startup_af_unspec_dump_publishes_both_families_only_after_matching_done() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    observer.begin_dump(dump_sequence(41), now);

    assert_eq!(
        observer.consume(
            decode(address_datagram(41, RTM_NEWADDR, 7, [192, 0, 2, 9], 24, 0,)),
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::Idle
    );
    assert!(source.snapshot().is_none());

    assert_eq!(
        observer.consume(
            decode(ipv6_address_datagram(
                41,
                RTM_NEWADDR,
                8,
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9).octets(),
                64,
                0,
            )),
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::Idle
    );

    assert_eq!(
        observer.consume(
            decode(netlink_message(NLMSG_DONE, 41, &[])),
            now + Duration::from_millis(2),
        ),
        ObserverDriveOutcome::Published(NetworkEpoch::INITIAL)
    );

    let snapshot = source.snapshot().expect("complete startup inventory");
    assert_eq!(snapshot.epoch(), NetworkEpoch::INITIAL);
    assert_eq!(snapshot.addresses().len(), 2);
    assert!(
        snapshot
            .addresses()
            .iter()
            .any(|record| { record.address() == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)) })
    );
    assert!(snapshot.addresses().iter().any(|record| {
        record.address() == IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9))
    }));
}

#[test]
fn coordinated_link_then_address_dump_publishes_one_combined_epoch() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    observer.begin_link_dump(dump_sequence(70), now);

    assert_eq!(
        observer.consume(
            decode(link_datagram(70, 7, b"wlan0", 0x1, Some(1_500))),
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::Idle
    );
    assert_eq!(
        observer.consume(
            decode(netlink_message(NLMSG_DONE, 70, &[])),
            now + Duration::from_millis(2),
        ),
        ObserverDriveOutcome::RequestAddressDump
    );
    assert!(source.snapshot().is_none());

    observer.begin_address_dump(dump_sequence(71), now + Duration::from_millis(3));
    assert_eq!(
        observer.consume(
            decode(address_datagram(71, RTM_NEWADDR, 7, [192, 0, 2, 9], 24, 0,)),
            now + Duration::from_millis(4),
        ),
        ObserverDriveOutcome::Idle
    );
    assert_eq!(
        observer.consume(
            decode(netlink_message(NLMSG_DONE, 71, &[])),
            now + Duration::from_millis(5),
        ),
        ObserverDriveOutcome::Published(NetworkEpoch::INITIAL)
    );

    let snapshot = source.snapshot().expect("combined inventory");
    assert_eq!(snapshot.epoch(), NetworkEpoch::INITIAL);
    assert_eq!(snapshot.links().len(), 1);
    assert_eq!(snapshot.links()[0].interface_index().get(), 7);
    assert_eq!(snapshot.links()[0].name().as_bytes(), b"wlan0");
    assert_eq!(snapshot.links()[0].mtu(), Some(1_500));
    assert_eq!(snapshot.addresses().len(), 1);
}

#[test]
fn transaction_races_span_both_phases_and_preserve_partial_link_fields() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    observer.begin_link_dump(dump_sequence(72), now);

    assert_eq!(
        observer.consume_batch(
            [
                decode(fully_populated_link_datagram(72, 7, b"wlan0", 0x1)),
                decode(netlink_message(NLMSG_DONE, 72, &[])),
                decode_notification(link_datagram(900, 7, b"wlan0", 0x41, None)),
            ],
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::RequestAddressDump
    );
    assert!(source.snapshot().is_none());

    assert_eq!(
        observer.consume(
            decode_notification(address_datagram(
                901,
                RTM_NEWADDR,
                9,
                [198, 51, 100, 4],
                24,
                0,
            )),
            now + Duration::from_millis(2),
        ),
        ObserverDriveOutcome::Idle
    );
    observer.begin_address_dump(dump_sequence(73), now + Duration::from_millis(3));
    assert_eq!(
        observer.consume(
            decode(netlink_message(NLMSG_DONE, 73, &[])),
            now + Duration::from_millis(4),
        ),
        ObserverDriveOutcome::Published(NetworkEpoch::INITIAL)
    );

    let snapshot = source.snapshot().expect("dump plus transaction races");
    assert_eq!(snapshot.links().len(), 1);
    assert_eq!(
        snapshot.links()[0].flags(),
        InterfaceLinkFlags::UP | InterfaceLinkFlags::RUNNING
    );
    assert_eq!(snapshot.links()[0].mtu(), Some(1_500));
    assert_eq!(
        snapshot.links()[0]
            .operational_state()
            .expect("preserved operational state")
            .raw(),
        6
    );
    assert_eq!(snapshot.links()[0].carrier(), Some(true));
    assert_eq!(
        snapshot.links()[0]
            .kind()
            .expect("preserved link kind")
            .as_bytes(),
        b"wireguard"
    );
    assert_eq!(snapshot.addresses().len(), 1);
    assert_eq!(snapshot.addresses()[0].interface_index().get(), 9);
}

#[test]
fn interphase_wait_has_its_own_timeout_and_never_publishes_links_alone() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    observer.begin_link_dump(dump_sequence(74), now);

    let link_done_at = now + Duration::from_millis(1);
    assert_eq!(
        observer.consume(decode(netlink_message(NLMSG_DONE, 74, &[])), link_done_at,),
        ObserverDriveOutcome::RequestAddressDump
    );
    assert!(source.snapshot().is_none());
    let deadline = link_done_at + Duration::from_secs(5);
    assert_eq!(observer.next_deadline(), Some(deadline));
    assert_eq!(
        observer.poll(deadline),
        ObserverDriveOutcome::RequestDump(ObserverFault::DumpTimeout)
    );
    assert!(source.snapshot().is_none());
}

#[test]
fn transaction_race_byte_budget_is_enforced_independently_of_event_count() {
    let now = Instant::now();
    let notification = link_datagram(902, 7, b"wlan0", 0x1, None);
    let capacity = notification.len() - 1;
    let mut observer = observer_with_limits(8, capacity);
    observer.begin_link_dump(dump_sequence(75), now);

    assert_eq!(
        observer.consume(
            decode_notification(notification),
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::RequestDump(ObserverFault::RaceQueueByteOverflow { capacity })
    );
    assert!(observer.source().snapshot().is_none());
}

#[test]
fn link_removal_does_not_invent_an_address_cascade() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    observer.begin_link_dump(dump_sequence(76), now);
    assert_eq!(
        observer.consume_batch(
            [
                decode(link_datagram(76, 7, b"wlan0", 0x1, Some(1_500))),
                decode(netlink_message(NLMSG_DONE, 76, &[])),
            ],
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::RequestAddressDump
    );
    observer.begin_address_dump(dump_sequence(77), now + Duration::from_millis(2));
    assert_eq!(
        observer.consume_batch(
            [
                decode(address_datagram(77, RTM_NEWADDR, 7, [192, 0, 2, 9], 24, 0,)),
                decode(netlink_message(NLMSG_DONE, 77, &[])),
            ],
            now + Duration::from_millis(3),
        ),
        ObserverDriveOutcome::Published(NetworkEpoch::INITIAL)
    );

    assert_eq!(
        observer.consume(
            decode_notification(link_removal_datagram(903, 7)),
            now + Duration::from_millis(10),
        ),
        ObserverDriveOutcome::Idle
    );
    let next_epoch = NetworkEpoch::INITIAL.checked_next().expect("second epoch");
    assert_eq!(
        observer.poll(now + Duration::from_millis(30)),
        ObserverDriveOutcome::Published(next_epoch)
    );
    let snapshot = source.snapshot().expect("link removal committed");
    assert!(snapshot.links().is_empty());
    assert_eq!(snapshot.addresses().len(), 1);
}

#[test]
fn event_during_dump_is_replayed_before_publication() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    observer.begin_dump(dump_sequence(42), now);

    assert_eq!(
        observer.consume(
            decode(address_datagram(42, RTM_NEWADDR, 7, [192, 0, 2, 9], 24, 0,)),
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::Idle
    );
    assert_eq!(
        observer.consume(
            decode(address_datagram(
                0,
                RTM_NEWADDR,
                9,
                [198, 51, 100, 4],
                24,
                0,
            )),
            now + Duration::from_millis(2),
        ),
        ObserverDriveOutcome::Idle
    );
    assert!(source.snapshot().is_none());

    assert_eq!(
        observer.consume(
            decode(netlink_message(NLMSG_DONE, 42, &[])),
            now + Duration::from_millis(3),
        ),
        ObserverDriveOutcome::Published(NetworkEpoch::INITIAL)
    );

    let snapshot = source.snapshot().expect("dump plus raced event");
    assert_eq!(snapshot.addresses().len(), 2);
    assert_eq!(
        snapshot
            .addresses()
            .iter()
            .map(|record| record.address())
            .collect::<Vec<_>>(),
        [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)),
        ]
    );
}

#[test]
fn event_after_done_in_one_receive_batch_is_replayed_before_publication() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    observer.begin_dump(dump_sequence(60), now);

    assert_eq!(
        observer.consume_batch(
            [
                decode(address_datagram(60, RTM_NEWADDR, 7, [192, 0, 2, 9], 24, 0,)),
                decode(netlink_message(NLMSG_DONE, 60, &[])),
                decode(address_datagram(
                    0,
                    RTM_NEWADDR,
                    9,
                    [198, 51, 100, 4],
                    24,
                    0,
                )),
            ],
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::Published(NetworkEpoch::INITIAL)
    );

    let snapshot = source.snapshot().expect("atomic dump batch");
    assert_eq!(snapshot.addresses().len(), 2);
}

#[test]
fn fault_after_done_in_one_receive_batch_discards_the_unpublished_dump() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    observer.begin_dump(dump_sequence(61), now);

    let outcome = observer.consume_batch(
        [
            decode(address_datagram(61, RTM_NEWADDR, 7, [192, 0, 2, 9], 24, 0)),
            decode(netlink_message(NLMSG_DONE, 61, &[])),
            decode(vec![0]),
        ],
        now + Duration::from_millis(1),
    );
    assert!(matches!(
        outcome,
        ObserverDriveOutcome::RequestDump(ObserverFault::Decode(_))
    ));
    assert!(source.snapshot().is_none());

    observer.begin_dump(dump_sequence(62), now + Duration::from_millis(2));
    assert_eq!(
        observer.consume(
            decode(netlink_message(NLMSG_DONE, 62, &[])),
            now + Duration::from_millis(3),
        ),
        ObserverDriveOutcome::Published(NetworkEpoch::INITIAL)
    );
    assert!(
        source
            .snapshot()
            .expect("fresh empty dump")
            .addresses()
            .is_empty()
    );
}

#[test]
fn dump_message_after_done_in_one_receive_batch_requires_resync() {
    let mut observer = observer();
    let now = Instant::now();
    observer.begin_dump(dump_sequence(63), now);

    assert_eq!(
        observer.consume_batch(
            [
                decode(netlink_message(NLMSG_DONE, 63, &[])),
                decode(address_datagram(63, RTM_NEWADDR, 7, [192, 0, 2, 9], 24, 0,)),
            ],
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::RequestDump(ObserverFault::DumpMessageAfterCompletion)
    );
    assert!(observer.source().snapshot().is_none());
}

#[test]
fn conflicting_duplicate_dump_facts_require_a_fresh_dump() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    observer.begin_dump(dump_sequence(43), now);

    assert_eq!(
        observer.consume(
            decode(address_datagram(43, RTM_NEWADDR, 7, [192, 0, 2, 9], 24, 0,)),
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::Idle
    );
    let outcome = observer.consume(
        decode(address_datagram(
            43,
            RTM_DELADDR,
            7,
            [192, 0, 2, 9],
            24,
            0x80,
        )),
        now + Duration::from_millis(2),
    );

    assert!(matches!(
        outcome,
        ObserverDriveOutcome::RequestDump(ObserverFault::ConflictingDumpFact { .. })
    ));
    assert!(source.snapshot().is_none());
    assert_eq!(observer.next_deadline(), None);
}

#[test]
fn loss_before_next_epoch_discards_pending_events_and_requires_resync() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    complete_single_address_dump(&mut observer, 44, now, 7, [192, 0, 2, 9], 24, 0);
    assert_eq!(
        source.snapshot().expect("initial snapshot").epoch(),
        NetworkEpoch::INITIAL
    );

    assert_eq!(
        observer.consume(
            decode(address_datagram(
                0,
                RTM_NEWADDR,
                9,
                [198, 51, 100, 4],
                24,
                0,
            )),
            now + Duration::from_millis(10),
        ),
        ObserverDriveOutcome::Idle
    );
    assert_eq!(
        source.snapshot().expect("last complete snapshot").epoch(),
        NetworkEpoch::INITIAL
    );

    assert_eq!(
        observer.note_loss(ObserverLoss::Enobufs),
        ObserverDriveOutcome::RequestDump(ObserverFault::ReceiveLoss(ObserverLoss::Enobufs))
    );
    assert!(source.snapshot().is_none());
    assert_eq!(
        observer.poll(now + Duration::from_secs(1)),
        ObserverDriveOutcome::Idle
    );

    complete_single_address_dump(
        &mut observer,
        45,
        now + Duration::from_secs(2),
        7,
        [192, 0, 2, 9],
        24,
        0,
    );
    assert_eq!(
        source.snapshot().expect("verified resync").epoch(),
        NetworkEpoch::INITIAL,
        "discarded pending events must not create an epoch"
    );
}

#[test]
fn continuous_churn_publishes_at_maximum_debounce() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    complete_single_address_dump(&mut observer, 46, now, 7, [192, 0, 2, 9], 24, 0);

    for (elapsed_ms, last_octet) in [
        (10, 10),
        (25, 11),
        (40, 12),
        (55, 13),
        (70, 14),
        (85, 15),
        (100, 16),
    ] {
        assert_eq!(
            observer.consume(
                decode(address_datagram(
                    0,
                    RTM_NEWADDR,
                    7,
                    [192, 0, 2, last_octet],
                    24,
                    0,
                )),
                now + Duration::from_millis(elapsed_ms),
            ),
            ObserverDriveOutcome::Idle
        );
    }

    let maximum_deadline = now + Duration::from_millis(110);
    assert_eq!(observer.next_deadline(), Some(maximum_deadline));
    assert_eq!(
        observer.poll(maximum_deadline - Duration::from_millis(1)),
        ObserverDriveOutcome::Idle
    );
    assert_eq!(
        source.snapshot().expect("pre-debounce snapshot").epoch(),
        NetworkEpoch::INITIAL
    );

    let next_epoch = NetworkEpoch::INITIAL.checked_next().expect("second epoch");
    assert_eq!(
        observer.poll(maximum_deadline),
        ObserverDriveOutcome::Published(next_epoch)
    );
    let snapshot = source.snapshot().expect("maximum-debounced snapshot");
    assert_eq!(snapshot.epoch(), next_epoch);
    assert_eq!(snapshot.addresses().len(), 8);
    assert_eq!(observer.poll(maximum_deadline), ObserverDriveOutcome::Idle);
}

#[test]
fn empty_datagram_requests_resync_without_panicking() {
    let mut response_observer = observer();
    let source = response_observer.source();
    let now = Instant::now();
    complete_single_address_dump(&mut response_observer, 47, now, 7, [192, 0, 2, 9], 24, 0);

    assert_eq!(
        response_observer.consume(decode(Vec::new()), now + Duration::from_millis(10)),
        ObserverDriveOutcome::RequestDump(ObserverFault::MissingSequence)
    );
    assert!(source.snapshot().is_none());

    let mut multicast = observer();
    multicast.begin_dump(dump_sequence(78), now);
    assert_eq!(
        multicast.consume(
            decode_notification(Vec::new()),
            now + Duration::from_millis(10),
        ),
        ObserverDriveOutcome::RequestDump(ObserverFault::MissingSequence)
    );
    assert!(multicast.source().snapshot().is_none());
}

#[test]
fn observer_config_rejects_unbounded_or_incoherent_limits() {
    assert_eq!(
        ObserverConfig::new(
            0,
            MAX_RACE_QUEUE_BYTES,
            Duration::from_secs(5),
            Duration::from_millis(20),
            Duration::from_millis(100),
        ),
        Err(ObserverConfigError::InvalidRaceQueueCapacity { actual: 0 })
    );
    assert_eq!(
        ObserverConfig::new(
            MAX_RACE_QUEUE_CAPACITY + 1,
            MAX_RACE_QUEUE_BYTES,
            Duration::from_secs(5),
            Duration::from_millis(20),
            Duration::from_millis(100),
        ),
        Err(ObserverConfigError::InvalidRaceQueueCapacity {
            actual: MAX_RACE_QUEUE_CAPACITY + 1,
        })
    );
    assert_eq!(
        ObserverConfig::new(
            8,
            0,
            Duration::from_secs(5),
            Duration::from_millis(20),
            Duration::from_millis(100),
        ),
        Err(ObserverConfigError::InvalidRaceQueueByteCapacity { actual: 0 })
    );
    assert_eq!(
        ObserverConfig::new(
            8,
            MAX_RACE_QUEUE_BYTES + 1,
            Duration::from_secs(5),
            Duration::from_millis(20),
            Duration::from_millis(100),
        ),
        Err(ObserverConfigError::InvalidRaceQueueByteCapacity {
            actual: MAX_RACE_QUEUE_BYTES + 1,
        })
    );
    assert_eq!(
        ObserverConfig::new(
            8,
            MAX_RACE_QUEUE_BYTES,
            Duration::ZERO,
            Duration::from_millis(20),
            Duration::from_millis(100),
        ),
        Err(ObserverConfigError::ZeroDumpTimeout)
    );
    assert_eq!(
        ObserverConfig::new(
            8,
            MAX_RACE_QUEUE_BYTES,
            Duration::from_secs(5),
            Duration::ZERO,
            Duration::from_millis(100),
        ),
        Err(ObserverConfigError::ZeroQuietDebounce)
    );
    assert_eq!(
        ObserverConfig::new(
            8,
            MAX_RACE_QUEUE_BYTES,
            Duration::from_secs(5),
            Duration::from_millis(20),
            Duration::ZERO,
        ),
        Err(ObserverConfigError::ZeroMaximumDebounce)
    );
    assert_eq!(
        ObserverConfig::new(
            8,
            MAX_RACE_QUEUE_BYTES,
            Duration::from_secs(5),
            Duration::from_millis(101),
            Duration::from_millis(100),
        ),
        Err(ObserverConfigError::QuietExceedsMaximum)
    );
}

#[test]
fn flag_transition_removal_uses_semantic_address_identity() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    complete_single_address_dump(&mut observer, 48, now, 7, [192, 0, 2, 9], 24, 0);

    let transition = address_datagram(
        0,
        RTM_NEWADDR,
        7,
        [192, 0, 2, 9],
        24,
        InterfaceAddressFlags::TEMPORARY.bits() as u8,
    );
    assert_eq!(
        observer.consume(
            decode_with_ignored_flags(transition, InterfaceAddressFlags::TEMPORARY),
            now + Duration::from_millis(10),
        ),
        ObserverDriveOutcome::Idle
    );

    let next_epoch = NetworkEpoch::INITIAL.checked_next().expect("second epoch");
    assert_eq!(
        observer.poll(now + Duration::from_millis(30)),
        ObserverDriveOutcome::Published(next_epoch)
    );
    let snapshot = source.snapshot().expect("flag transition committed");
    assert_eq!(snapshot.epoch(), next_epoch);
    assert!(snapshot.addresses().is_empty());
}

#[test]
fn scope_transitions_remove_and_restore_the_same_semantic_address() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    complete_single_address_dump(&mut observer, 59, now, 7, [192, 0, 2, 9], 24, 0);

    assert_eq!(
        observer.consume(
            decode(address_datagram_with_scope(
                0,
                RTM_NEWADDR,
                7,
                [192, 0, 2, 9],
                24,
                0,
                253,
            )),
            now + Duration::from_millis(10),
        ),
        ObserverDriveOutcome::Idle
    );
    let removed_epoch = NetworkEpoch::INITIAL.checked_next().expect("second epoch");
    assert_eq!(
        observer.poll(now + Duration::from_millis(30)),
        ObserverDriveOutcome::Published(removed_epoch)
    );
    assert!(
        source
            .snapshot()
            .expect("scope removal committed")
            .addresses()
            .is_empty()
    );

    assert_eq!(
        observer.consume(
            decode(address_datagram_with_scope(
                0,
                RTM_NEWADDR,
                7,
                [192, 0, 2, 9],
                24,
                0,
                0,
            )),
            now + Duration::from_millis(40),
        ),
        ObserverDriveOutcome::Idle
    );
    let restored_epoch = removed_epoch.checked_next().expect("third epoch");
    assert_eq!(
        observer.poll(now + Duration::from_millis(60)),
        ObserverDriveOutcome::Published(restored_epoch)
    );
    let snapshot = source.snapshot().expect("global scope restored");
    assert_eq!(snapshot.epoch(), restored_epoch);
    assert_eq!(snapshot.addresses().len(), 1);
}

#[test]
fn quiet_debounce_commits_only_material_complete_snapshots() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    complete_single_address_dump(&mut observer, 49, now, 7, [192, 0, 2, 9], 24, 0);

    let addition = address_datagram(0, RTM_NEWADDR, 7, [192, 0, 2, 10], 24, 0);
    assert_eq!(
        observer.consume(decode(addition.clone()), now + Duration::from_millis(10)),
        ObserverDriveOutcome::Idle
    );
    assert_eq!(
        observer.poll(now + Duration::from_millis(29)),
        ObserverDriveOutcome::Idle
    );
    let next_epoch = NetworkEpoch::INITIAL.checked_next().expect("second epoch");
    assert_eq!(
        observer.poll(now + Duration::from_millis(30)),
        ObserverDriveOutcome::Published(next_epoch)
    );

    assert_eq!(
        observer.consume(decode(addition), now + Duration::from_millis(40)),
        ObserverDriveOutcome::Idle,
        "an exact duplicate is not material churn"
    );
    assert_eq!(observer.next_deadline(), None);

    assert_eq!(
        observer.consume(
            decode(address_datagram(0, RTM_NEWADDR, 7, [192, 0, 2, 11], 24, 0,)),
            now + Duration::from_millis(50),
        ),
        ObserverDriveOutcome::Idle
    );
    assert_eq!(
        observer.consume(
            decode(address_datagram(
                0,
                RTM_DELADDR,
                7,
                [192, 0, 2, 11],
                24,
                0x80,
            )),
            now + Duration::from_millis(60),
        ),
        ObserverDriveOutcome::Idle
    );
    assert_eq!(observer.next_deadline(), None);
    assert_eq!(
        source.snapshot().expect("material snapshot").epoch(),
        next_epoch
    );
}

#[test]
fn decode_error_invalidates_due_batch_without_advancing_epoch() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    complete_single_address_dump(&mut observer, 50, now, 7, [192, 0, 2, 9], 24, 0);
    assert_eq!(
        observer.consume(
            decode(address_datagram(0, RTM_NEWADDR, 7, [192, 0, 2, 10], 24, 0,)),
            now + Duration::from_millis(10),
        ),
        ObserverDriveOutcome::Idle
    );

    let outcome = observer.consume_batch(
        [
            decode(address_datagram(0, RTM_NEWADDR, 7, [192, 0, 2, 11], 24, 0)),
            decode(vec![0]),
        ],
        now + Duration::from_millis(30),
    );
    assert!(matches!(
        outcome,
        ObserverDriveOutcome::RequestDump(ObserverFault::Decode(_))
    ));
    assert!(source.snapshot().is_none());
    assert_eq!(observer.next_deadline(), None);

    complete_single_address_dump(
        &mut observer,
        58,
        now + Duration::from_secs(1),
        7,
        [192, 0, 2, 9],
        24,
        0,
    );
    assert_eq!(
        source.snapshot().expect("equivalent resync").epoch(),
        NetworkEpoch::INITIAL
    );
}

#[test]
fn truncation_and_timeout_invalidate_state_until_a_fresh_dump() {
    let now = Instant::now();
    let mut truncated = observer();
    let truncated_source = truncated.source();
    complete_single_address_dump(&mut truncated, 51, now, 7, [192, 0, 2, 9], 24, 0);
    assert_eq!(
        truncated.consume(
            decode(address_datagram(0, RTM_NEWADDR, 7, [192, 0, 2, 10], 24, 0,)),
            now + Duration::from_millis(10),
        ),
        ObserverDriveOutcome::Idle
    );
    assert_eq!(
        truncated.note_truncation(),
        ObserverDriveOutcome::RequestDump(ObserverFault::ReceiveLoss(ObserverLoss::Truncated))
    );
    assert!(truncated_source.snapshot().is_none());
    assert_eq!(truncated.next_deadline(), None);

    let mut timed_out = observer();
    let timed_out_source = timed_out.source();
    timed_out.begin_dump(dump_sequence(52), now);
    let deadline = now + Duration::from_secs(5);
    assert_eq!(timed_out.next_deadline(), Some(deadline));
    assert_eq!(
        timed_out.poll(deadline),
        ObserverDriveOutcome::RequestDump(ObserverFault::DumpTimeout)
    );
    assert!(timed_out_source.snapshot().is_none());
    assert_eq!(timed_out.poll(deadline), ObserverDriveOutcome::Idle);
}

#[test]
fn foreign_sequence_invalidates_dump_before_completion() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    observer.begin_dump(dump_sequence(53), now);

    assert_eq!(
        observer.consume(
            decode(netlink_message(NLMSG_DONE, 54, &[])),
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::RequestDump(ObserverFault::ForeignSequence {
            expected: Some(53),
            actual: Some(54),
        })
    );
    assert!(source.snapshot().is_none());
    assert_eq!(observer.next_deadline(), None);
}

#[test]
fn dump_race_queue_is_bounded() {
    let mut observer = observer_with_capacity(1);
    let source = observer.source();
    let now = Instant::now();
    observer.begin_dump(dump_sequence(55), now);
    assert_eq!(
        observer.consume(
            decode(address_datagram(0, RTM_NEWADDR, 7, [192, 0, 2, 9], 24, 0,)),
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::Idle
    );

    assert_eq!(
        observer.consume(
            decode(address_datagram(0, RTM_NEWADDR, 7, [192, 0, 2, 10], 24, 0,)),
            now + Duration::from_millis(2),
        ),
        ObserverDriveOutcome::RequestDump(ObserverFault::RaceQueueOverflow { capacity: 1 })
    );
    assert!(source.snapshot().is_none());
    assert_eq!(observer.next_deadline(), None);
}

#[test]
fn late_done_cannot_publish_after_dump_timeout() {
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    observer.begin_dump(dump_sequence(56), now);
    assert_eq!(
        observer.consume(
            decode(address_datagram(56, RTM_NEWADDR, 7, [192, 0, 2, 9], 24, 0,)),
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::Idle
    );

    assert_eq!(
        observer.consume(
            decode(netlink_message(NLMSG_DONE, 56, &[])),
            now + Duration::from_secs(5),
        ),
        ObserverDriveOutcome::RequestDump(ObserverFault::DumpTimeout)
    );
    assert!(source.snapshot().is_none());
    assert_eq!(observer.next_deadline(), None);
}

#[test]
fn loss_cause_and_dump_send_failure_are_preserved_for_the_driver() {
    let mut observer = observer();
    assert_eq!(
        observer.note_loss(ObserverLoss::UnexpectedSender),
        ObserverDriveOutcome::RequestDump(ObserverFault::ReceiveLoss(
            ObserverLoss::UnexpectedSender
        ))
    );

    let now = Instant::now();
    observer.begin_dump(dump_sequence(57), now);
    assert_eq!(
        observer.note_dump_request_failure(),
        ObserverDriveOutcome::RequestDump(ObserverFault::DumpRequestFailed)
    );
    assert_eq!(observer.next_deadline(), None);
}

fn observer() -> NetworkInventoryObserver {
    observer_with_capacity(8)
}

fn observer_with_capacity(race_queue_capacity: usize) -> NetworkInventoryObserver {
    observer_with_limits(race_queue_capacity, MAX_RACE_QUEUE_BYTES)
}

fn observer_with_limits(
    race_queue_capacity: usize,
    race_queue_byte_capacity: usize,
) -> NetworkInventoryObserver {
    NetworkInventoryObserver::new(
        ObserverConfig::new(
            race_queue_capacity,
            race_queue_byte_capacity,
            Duration::from_secs(5),
            Duration::from_millis(20),
            Duration::from_millis(100),
        )
        .expect("valid observer config"),
    )
}

#[allow(clippy::too_many_arguments)]
fn complete_single_address_dump(
    observer: &mut NetworkInventoryObserver,
    sequence: u32,
    now: Instant,
    interface_index: u32,
    address: [u8; 4],
    prefix_length: u8,
    flags: u8,
) {
    observer.begin_dump(dump_sequence(sequence), now);
    assert_eq!(
        observer.consume(
            decode(address_datagram(
                sequence,
                RTM_NEWADDR,
                interface_index,
                address,
                prefix_length,
                flags,
            )),
            now + Duration::from_millis(1),
        ),
        ObserverDriveOutcome::Idle
    );
    assert!(matches!(
        observer.consume(
            decode(netlink_message(NLMSG_DONE, sequence, &[])),
            now + Duration::from_millis(2),
        ),
        ObserverDriveOutcome::Published(_)
    ));
}

fn decode(datagram: Vec<u8>) -> Result<InventoryDatagram, InventoryDecodeError> {
    let origin = test_datagram_origin(&datagram);
    decode_with_policy_and_origin(datagram, AddressEventPolicy::new(true), origin)
}

fn decode_notification(datagram: Vec<u8>) -> Result<InventoryDatagram, InventoryDecodeError> {
    decode_with_policy_and_origin(
        datagram,
        AddressEventPolicy::new(true),
        InventoryDatagramOrigin::Notification,
    )
}

fn dump_sequence(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("test dump sequence is nonzero")
}

fn decode_with_ignored_flags(
    datagram: Vec<u8>,
    ignored_flags: InterfaceAddressFlags,
) -> Result<InventoryDatagram, InventoryDecodeError> {
    let origin = test_datagram_origin(&datagram);
    decode_with_policy_and_origin(
        datagram,
        AddressEventPolicy::new(true).with_ignored_flags(ignored_flags),
        origin,
    )
}

fn decode_with_policy_and_origin(
    datagram: Vec<u8>,
    policy: AddressEventPolicy,
    origin: InventoryDatagramOrigin,
) -> Result<InventoryDatagram, InventoryDecodeError> {
    InventoryDatagram::from_decoded(
        RtnetlinkLinkEventDecoder::new().decode_datagram(&datagram),
        RtnetlinkAddressEventDecoder::new(policy).decode_datagram(&datagram),
        origin,
        datagram.len(),
    )
}

fn test_datagram_origin(datagram: &[u8]) -> InventoryDatagramOrigin {
    if datagram
        .get(8..12)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .is_some_and(|sequence| u32::from_ne_bytes(sequence) == 0)
    {
        InventoryDatagramOrigin::Notification
    } else {
        InventoryDatagramOrigin::Response
    }
}

fn link_datagram(
    sequence: u32,
    interface_index: u32,
    name: &[u8],
    flags: u32,
    mtu: Option<u32>,
) -> Vec<u8> {
    let mut payload = vec![AF_UNSPEC, 0];
    payload.extend(1_u16.to_ne_bytes());
    payload.extend((interface_index as i32).to_ne_bytes());
    payload.extend(flags.to_ne_bytes());
    payload.extend(u32::MAX.to_ne_bytes());
    append_attribute(&mut payload, IFLA_IFNAME, &[name, &[0]].concat());
    if let Some(mtu) = mtu {
        append_attribute(&mut payload, IFLA_MTU, &mtu.to_ne_bytes());
    }
    netlink_message(RTM_NEWLINK, sequence, &payload)
}

fn fully_populated_link_datagram(
    sequence: u32,
    interface_index: u32,
    name: &[u8],
    flags: u32,
) -> Vec<u8> {
    let mut payload = vec![AF_UNSPEC, 0];
    payload.extend(1_u16.to_ne_bytes());
    payload.extend((interface_index as i32).to_ne_bytes());
    payload.extend(flags.to_ne_bytes());
    payload.extend(u32::MAX.to_ne_bytes());
    append_attribute(&mut payload, IFLA_IFNAME, &[name, &[0]].concat());
    append_attribute(&mut payload, IFLA_MTU, &1_500_u32.to_ne_bytes());
    append_attribute(&mut payload, IFLA_OPERSTATE, &[6]);
    append_attribute(&mut payload, IFLA_CARRIER, &[1]);
    let mut link_info = Vec::new();
    append_attribute(&mut link_info, IFLA_INFO_KIND, b"wireguard\0");
    append_attribute(&mut payload, IFLA_LINKINFO | NLA_F_NESTED, &link_info);
    netlink_message(RTM_NEWLINK, sequence, &payload)
}

fn link_removal_datagram(sequence: u32, interface_index: u32) -> Vec<u8> {
    let mut payload = vec![AF_UNSPEC, 0];
    payload.extend(1_u16.to_ne_bytes());
    payload.extend((interface_index as i32).to_ne_bytes());
    payload.extend(0_u32.to_ne_bytes());
    payload.extend(u32::MAX.to_ne_bytes());
    netlink_message(RTM_DELLINK, sequence, &payload)
}

fn address_datagram(
    sequence: u32,
    message_type: u16,
    interface_index: u32,
    address: [u8; 4],
    prefix_length: u8,
    flags: u8,
) -> Vec<u8> {
    address_datagram_with_scope(
        sequence,
        message_type,
        interface_index,
        address,
        prefix_length,
        flags,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
fn address_datagram_with_scope(
    sequence: u32,
    message_type: u16,
    interface_index: u32,
    address: [u8; 4],
    prefix_length: u8,
    flags: u8,
    scope: u8,
) -> Vec<u8> {
    let mut payload = vec![AF_INET, prefix_length, flags, scope];
    payload.extend_from_slice(&interface_index.to_ne_bytes());
    append_attribute(&mut payload, IFA_ADDRESS, &address);
    netlink_message(message_type, sequence, &payload)
}

fn ipv6_address_datagram(
    sequence: u32,
    message_type: u16,
    interface_index: u32,
    address: [u8; 16],
    prefix_length: u8,
    flags: u8,
) -> Vec<u8> {
    let mut payload = vec![AF_INET6, prefix_length, flags, 0];
    payload.extend_from_slice(&interface_index.to_ne_bytes());
    append_attribute(&mut payload, IFA_ADDRESS, &address);
    netlink_message(message_type, sequence, &payload)
}

fn netlink_message(message_type: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
    let length = NETLINK_HEADER_LENGTH + payload.len();
    let mut message = Vec::with_capacity(align4(length));
    message.extend_from_slice(&(length as u32).to_ne_bytes());
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&0_u16.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(payload);
    message.resize(align4(message.len()), 0);
    message
}

fn append_attribute(message: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
    let length = 4 + value.len();
    message.extend_from_slice(&(length as u16).to_ne_bytes());
    message.extend_from_slice(&attribute_type.to_ne_bytes());
    message.extend_from_slice(value);
    message.resize(align4(message.len()), 0);
}

const fn align4(length: usize) -> usize {
    (length + 3) & !3
}
