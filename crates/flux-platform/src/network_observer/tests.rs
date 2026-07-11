use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::time::Instant;

use flux_core::{InterfaceAddressFlags, NetworkEpoch};

use crate::address_sync::{
    AddressDatagram, AddressEventDecodeError, AddressEventPolicy, RtnetlinkAddressEventDecoder,
};

const NETLINK_HEADER_LENGTH: usize = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
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
    let mut observer = observer();
    let source = observer.source();
    let now = Instant::now();
    complete_single_address_dump(&mut observer, 47, now, 7, [192, 0, 2, 9], 24, 0);

    assert_eq!(
        observer.consume(decode(Vec::new()), now + Duration::from_millis(10)),
        ObserverDriveOutcome::RequestDump(ObserverFault::MissingSequence)
    );
    assert!(source.snapshot().is_none());
}

#[test]
fn observer_config_rejects_unbounded_or_incoherent_limits() {
    assert_eq!(
        ObserverConfig::new(
            0,
            Duration::from_secs(5),
            Duration::from_millis(20),
            Duration::from_millis(100),
        ),
        Err(ObserverConfigError::InvalidRaceQueueCapacity { actual: 0 })
    );
    assert_eq!(
        ObserverConfig::new(
            MAX_RACE_QUEUE_CAPACITY + 1,
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
            Duration::ZERO,
            Duration::from_millis(20),
            Duration::from_millis(100),
        ),
        Err(ObserverConfigError::ZeroDumpTimeout)
    );
    assert_eq!(
        ObserverConfig::new(
            8,
            Duration::from_secs(5),
            Duration::ZERO,
            Duration::from_millis(100),
        ),
        Err(ObserverConfigError::ZeroQuietDebounce)
    );
    assert_eq!(
        ObserverConfig::new(
            8,
            Duration::from_secs(5),
            Duration::from_millis(20),
            Duration::ZERO,
        ),
        Err(ObserverConfigError::ZeroMaximumDebounce)
    );
    assert_eq!(
        ObserverConfig::new(
            8,
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
    NetworkInventoryObserver::new(
        ObserverConfig::new(
            race_queue_capacity,
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

fn decode(datagram: Vec<u8>) -> Result<AddressDatagram, AddressEventDecodeError> {
    RtnetlinkAddressEventDecoder::new(AddressEventPolicy::new(true)).decode_datagram(&datagram)
}

fn dump_sequence(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("test dump sequence is nonzero")
}

fn decode_with_ignored_flags(
    datagram: Vec<u8>,
    ignored_flags: InterfaceAddressFlags,
) -> Result<AddressDatagram, AddressEventDecodeError> {
    RtnetlinkAddressEventDecoder::new(
        AddressEventPolicy::new(true).with_ignored_flags(ignored_flags),
    )
    .decode_datagram(&datagram)
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
