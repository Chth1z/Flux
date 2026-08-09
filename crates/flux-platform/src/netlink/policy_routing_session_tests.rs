use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU16;
use std::rc::Rc;

use flux_core::NetworkAddressFamily;

use super::*;
use crate::netlink::policy_routing::test_managed_policy_routing_identity;
use crate::netlink::{NETLINK_HEADER_LENGTH, NetlinkAttributeIter};

const TEST_PORT_ID: u32 = 7;
const NLM_F_CAPPED: u16 = 0x0100;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const RTM_GETRULE: u16 = 34;
const RTA_DST: u16 = 1;
const RTA_TABLE: u16 = 15;
const RTA_MARK: u16 = 16;
const RTA_UID: u16 = 25;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeResponseMode {
    Normal,
    WrongAckSequenceOnce,
    WrongSenderOnce,
}

struct FakeTransport {
    sent_types: Rc<RefCell<Vec<u16>>>,
    last_request: Vec<u8>,
    response_mode: FakeResponseMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LookupResponseMode {
    Resolved,
    Rejected,
    Malformed,
    SendFailure,
    ReceiveFailure,
}

#[derive(Default)]
struct LookupCalls {
    sent: Vec<Box<[u8]>>,
    send_deadlines: Vec<Instant>,
    receive_limits: Vec<usize>,
    receive_deadlines: Vec<Instant>,
}

struct LookupTransport {
    calls: Rc<RefCell<LookupCalls>>,
    last_request: Vec<u8>,
    response_mode: LookupResponseMode,
}

impl LookupTransport {
    fn new(calls: Rc<RefCell<LookupCalls>>, response_mode: LookupResponseMode) -> Self {
        Self {
            calls,
            last_request: Vec::new(),
            response_mode,
        }
    }
}

impl FakeTransport {
    fn new(sent_types: Rc<RefCell<Vec<u16>>>, response_mode: FakeResponseMode) -> Self {
        Self {
            sent_types,
            last_request: Vec::new(),
            response_mode,
        }
    }
}

impl PolicyRoutingTransport for FakeTransport {
    fn evidence(&self) -> PolicyRoutingSessionEvidence {
        PolicyRoutingSessionEvidence {
            local_port_id: NonZeroU32::new(TEST_PORT_ID).unwrap(),
            groups: 0,
            extended_ack: true,
            capped_ack: true,
        }
    }

    fn send_datagram(
        &mut self,
        bytes: &[u8],
        _deadline: Instant,
    ) -> Result<(), PolicyRoutingSessionFailure> {
        self.last_request.clear();
        self.last_request.extend_from_slice(bytes);
        self.sent_types
            .borrow_mut()
            .push(read_u16(&self.last_request[4..]));
        Ok(())
    }

    fn receive_datagram(
        &mut self,
        _maximum_bytes: usize,
        _deadline: Instant,
    ) -> Result<ReceivedPolicyRoutingDatagram, PolicyRoutingSessionFailure> {
        let message_type = read_u16(&self.last_request[4..]);
        let request_sequence = read_u32(&self.last_request[8..]);
        let bytes = if matches!(message_type, RTM_GETROUTE | RTM_GETRULE) {
            netlink_message(NLMSG_DONE, 0, request_sequence, TEST_PORT_ID, &[])
        } else {
            let sequence = if self.response_mode == FakeResponseMode::WrongAckSequenceOnce {
                self.response_mode = FakeResponseMode::Normal;
                request_sequence + 1
            } else {
                request_sequence
            };
            let mut payload = Vec::new();
            payload.extend_from_slice(&0_i32.to_ne_bytes());
            payload.extend_from_slice(&self.last_request[..NETLINK_HEADER_LENGTH]);
            netlink_message(NLMSG_ERROR, NLM_F_CAPPED, sequence, TEST_PORT_ID, &payload)
        };
        let sender = if self.response_mode == FakeResponseMode::WrongSenderOnce {
            self.response_mode = FakeResponseMode::Normal;
            PolicyRoutingAckSender::new(12, 16, 1, 0)
        } else {
            PolicyRoutingAckSender::kernel_unicast()
        };
        Ok(ReceivedPolicyRoutingDatagram {
            bytes: bytes.into_boxed_slice(),
            sender,
        })
    }
}

impl PolicyRoutingTransport for LookupTransport {
    fn evidence(&self) -> PolicyRoutingSessionEvidence {
        PolicyRoutingSessionEvidence {
            local_port_id: NonZeroU32::new(TEST_PORT_ID).unwrap(),
            groups: 0,
            extended_ack: true,
            capped_ack: true,
        }
    }

    fn send_datagram(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), PolicyRoutingSessionFailure> {
        self.last_request.clear();
        self.last_request.extend_from_slice(bytes);
        let mut calls = self.calls.borrow_mut();
        calls.sent.push(bytes.into());
        calls.send_deadlines.push(deadline);
        drop(calls);
        if self.response_mode == LookupResponseMode::SendFailure {
            Err(PolicyRoutingSessionFailure::new(
                "fake lookup send",
                PolicyRoutingSessionFailureKind::SystemCall {
                    raw_os_error: Some(5),
                },
                0,
            ))
        } else {
            Ok(())
        }
    }

    fn receive_datagram(
        &mut self,
        maximum_bytes: usize,
        deadline: Instant,
    ) -> Result<ReceivedPolicyRoutingDatagram, PolicyRoutingSessionFailure> {
        let mut calls = self.calls.borrow_mut();
        calls.receive_limits.push(maximum_bytes);
        calls.receive_deadlines.push(deadline);
        drop(calls);

        if self.response_mode == LookupResponseMode::ReceiveFailure {
            return Err(PolicyRoutingSessionFailure::new(
                "fake lookup receive",
                PolicyRoutingSessionFailureKind::TimedOut,
                0,
            ));
        }
        let bytes = match self.response_mode {
            LookupResponseMode::Resolved => lookup_route_response(&self.last_request, 100),
            LookupResponseMode::Rejected => lookup_rejection_response(&self.last_request, -13),
            LookupResponseMode::Malformed => netlink_message(
                NLMSG_DONE,
                0,
                read_u32(&self.last_request[8..]),
                TEST_PORT_ID,
                &[],
            ),
            LookupResponseMode::SendFailure | LookupResponseMode::ReceiveFailure => {
                unreachable!("transport failure returned before response construction")
            }
        };
        Ok(ReceivedPolicyRoutingDatagram {
            bytes: bytes.into_boxed_slice(),
            sender: PolicyRoutingAckSender::kernel_unicast(),
        })
    }
}

#[test]
fn live_session_rejects_zero_and_unbounded_deadlines_before_opening() {
    for timeout in [
        Duration::ZERO,
        MAX_POLICY_ROUTING_IO_TIMEOUT + Duration::from_nanos(1),
    ] {
        let error = match PolicyRoutingSession::open_with_timeout(timeout) {
            Ok(_) => panic!("invalid timeout unexpectedly opened a live session"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            PolicyRoutingSessionFailureKind::InvalidTimeout
        );
    }
}

#[test]
fn apply_and_delete_use_inverse_safe_order() {
    let identity = test_managed_policy_routing_identity(NetworkAddressFamily::Ipv4);

    let apply_types = Rc::new(RefCell::new(Vec::new()));
    let mut apply = PolicyRoutingSession::from_transport(
        FakeTransport::new(apply_types.clone(), FakeResponseMode::Normal),
        Duration::from_secs(1),
    );
    let receipt = apply.apply(identity).unwrap();
    assert!(receipt.is_complete());
    assert_eq!(&*apply_types.borrow(), &[RTM_NEWROUTE, RTM_NEWRULE]);

    let delete_types = Rc::new(RefCell::new(Vec::new()));
    let mut delete = PolicyRoutingSession::from_transport(
        FakeTransport::new(delete_types.clone(), FakeResponseMode::Normal),
        Duration::from_secs(1),
    );
    let receipt = delete.delete(identity).unwrap();
    assert!(receipt.is_complete());
    assert_eq!(&*delete_types.borrow(), &[RTM_DELRULE, RTM_DELROUTE]);
}

#[test]
fn mutate_one_exposes_one_owner_journal_boundary() {
    let identity = test_managed_policy_routing_identity(NetworkAddressFamily::Ipv4);
    let sent_types = Rc::new(RefCell::new(Vec::new()));
    let mut session = PolicyRoutingSession::from_transport(
        FakeTransport::new(sent_types.clone(), FakeResponseMode::Normal),
        Duration::from_secs(1),
    );

    let receipt = session
        .mutate_one(PolicyRoutingMutation::AddRoute(identity.route()))
        .unwrap();
    assert_eq!(receipt.mutation(), PolicyRoutingMutationKind::AddRoute);
    assert!(matches!(
        receipt.outcome(),
        PolicyRoutingStepOutcome::Accepted(_)
    ));
    assert_eq!(&*sent_types.borrow(), &[RTM_NEWROUTE]);
}

#[test]
fn ambiguous_ack_poisoning_requires_a_fresh_session_before_readback() {
    let identity = test_managed_policy_routing_identity(NetworkAddressFamily::Ipv4);
    let sent_types = Rc::new(RefCell::new(Vec::new()));
    let mut session = PolicyRoutingSession::from_transport(
        FakeTransport::new(sent_types.clone(), FakeResponseMode::WrongAckSequenceOnce),
        Duration::from_secs(1),
    );

    let receipt = session.apply(identity).unwrap();
    assert_eq!(receipt.steps().len(), 1);
    assert!(matches!(
        receipt.steps()[0].outcome(),
        PolicyRoutingStepOutcome::MayHaveMutated(failure)
            if failure.kind()
                == PolicyRoutingSessionFailureKind::AckDecode(
                    PolicyRoutingAckDecodeErrorKind::UnexpectedSequence
                )
    ));
    assert!(receipt.may_have_mutated());
    assert_eq!(
        session.observe(identity).unwrap_err().kind(),
        PolicyRoutingSessionFailureKind::FreshSessionRequired
    );
    assert_eq!(&*sent_types.borrow(), &[RTM_NEWROUTE]);
}

#[test]
fn unexpected_ack_sender_is_uncertain_and_stops_the_transaction() {
    let identity = test_managed_policy_routing_identity(NetworkAddressFamily::Ipv4);
    let sent_types = Rc::new(RefCell::new(Vec::new()));
    let mut session = PolicyRoutingSession::from_transport(
        FakeTransport::new(sent_types.clone(), FakeResponseMode::WrongSenderOnce),
        Duration::from_secs(1),
    );

    let receipt = session.apply(identity).unwrap();
    assert!(matches!(
        receipt.steps()[0].outcome(),
        PolicyRoutingStepOutcome::MayHaveMutated(failure)
            if failure.kind()
                == PolicyRoutingSessionFailureKind::AckDecode(
                    PolicyRoutingAckDecodeErrorKind::UnexpectedSender
                )
    ));
    assert_eq!(&*sent_types.borrow(), &[RTM_NEWROUTE]);
}

#[test]
fn groups_zero_session_collects_complete_route_then_rule_dumps() {
    let identity = test_managed_policy_routing_identity(NetworkAddressFamily::Ipv6);
    let sent_types = Rc::new(RefCell::new(Vec::new()));
    let mut session = PolicyRoutingSession::from_transport(
        FakeTransport::new(sent_types.clone(), FakeResponseMode::Normal),
        Duration::from_secs(1),
    );

    let evidence = session.evidence();
    assert_eq!(evidence.local_port_id().get(), TEST_PORT_ID);
    assert_eq!(evidence.groups(), 0);
    assert!(evidence.extended_ack());
    assert!(evidence.capped_ack());

    let observation = session.observe(identity).unwrap();
    assert_eq!(observation.route().exact_count(), 0);
    assert_eq!(observation.route().conflict_count(), 0);
    assert_eq!(observation.rule().exact_count(), 0);
    assert_eq!(observation.rule().conflict_count(), 0);
    assert_eq!(&*sent_types.borrow(), &[RTM_GETROUTE, RTM_GETRULE]);
}

#[test]
fn one_shot_lookup_uses_the_caller_deadline_and_64_kib_receive_cap() {
    let calls = Rc::new(RefCell::new(LookupCalls::default()));
    let mut session = PolicyRoutingSession::from_transport(
        LookupTransport::new(calls.clone(), LookupResponseMode::Resolved),
        Duration::from_secs(30),
    );
    let caller_deadline = Instant::now() + Duration::from_secs(2);

    let outcome = session
        .lookup_canary_route_until(test_lookup(), caller_deadline)
        .unwrap();
    assert!(matches!(
        outcome,
        CanaryRouteLookupOutcome::Resolved(result) if result.table().get() == 100
    ));

    let calls = calls.borrow();
    assert_eq!(calls.sent.len(), 1);
    assert_eq!(calls.sent[0].len(), 68);
    assert_eq!(read_u16(&calls.sent[0][4..]), RTM_GETROUTE);
    assert_eq!(read_u16(&calls.sent[0][6..]), 1);
    assert_eq!(calls.send_deadlines, [caller_deadline]);
    assert_eq!(calls.receive_deadlines, [caller_deadline]);
    assert_eq!(calls.receive_limits, [MAX_ROUTE_LOOKUP_RESPONSE_BYTES]);
}

#[test]
fn session_timeout_bounds_a_later_caller_deadline() {
    let calls = Rc::new(RefCell::new(LookupCalls::default()));
    let io_timeout = Duration::from_millis(100);
    let mut session = PolicyRoutingSession::from_transport(
        LookupTransport::new(calls.clone(), LookupResponseMode::Resolved),
        io_timeout,
    );
    let started = Instant::now();
    let caller_deadline = started + Duration::from_secs(60);

    session
        .lookup_canary_route_until(test_lookup(), caller_deadline)
        .unwrap();

    let calls = calls.borrow();
    let used = calls.send_deadlines[0];
    assert!(used < caller_deadline);
    assert!(used <= started + io_timeout + Duration::from_millis(20));
    assert_eq!(calls.receive_deadlines, [used]);
}

#[test]
fn expired_caller_deadline_does_not_send_or_poison_the_session() {
    let calls = Rc::new(RefCell::new(LookupCalls::default()));
    let mut session = PolicyRoutingSession::from_transport(
        LookupTransport::new(calls.clone(), LookupResponseMode::Resolved),
        Duration::from_secs(1),
    );

    assert_eq!(
        session
            .lookup_canary_route_until(test_lookup(), Instant::now())
            .unwrap_err()
            .kind(),
        PolicyRoutingSessionFailureKind::TimedOut
    );
    session
        .lookup_canary_route_until(test_lookup(), Instant::now() + Duration::from_secs(1))
        .unwrap();
    assert_eq!(calls.borrow().sent.len(), 1);
}

#[test]
fn definite_kernel_rejection_is_typed_and_keeps_the_session_usable() {
    let calls = Rc::new(RefCell::new(LookupCalls::default()));
    let mut session = PolicyRoutingSession::from_transport(
        LookupTransport::new(calls.clone(), LookupResponseMode::Rejected),
        Duration::from_secs(1),
    );

    for _ in 0..2 {
        let outcome = session
            .lookup_canary_route_until(test_lookup(), Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            outcome,
            CanaryRouteLookupOutcome::Rejected(rejection) if rejection.errno().get() == 13
        ));
    }
    assert_eq!(calls.borrow().sent.len(), 2);
}

#[test]
fn malformed_or_transport_ambiguous_lookup_requires_a_fresh_session() {
    for response_mode in [
        LookupResponseMode::Malformed,
        LookupResponseMode::SendFailure,
        LookupResponseMode::ReceiveFailure,
    ] {
        let calls = Rc::new(RefCell::new(LookupCalls::default()));
        let mut session = PolicyRoutingSession::from_transport(
            LookupTransport::new(calls.clone(), response_mode),
            Duration::from_secs(1),
        );

        let first = session
            .lookup_canary_route_until(test_lookup(), Instant::now() + Duration::from_secs(1))
            .unwrap_err();
        match response_mode {
            LookupResponseMode::Malformed => assert!(matches!(
                first.kind(),
                PolicyRoutingSessionFailureKind::RouteLookupDecode(
                    RouteLookupDecodeErrorKind::UnexpectedControlMessage { .. }
                )
            )),
            LookupResponseMode::SendFailure => assert!(matches!(
                first.kind(),
                PolicyRoutingSessionFailureKind::SystemCall { .. }
            )),
            LookupResponseMode::ReceiveFailure => {
                assert_eq!(first.kind(), PolicyRoutingSessionFailureKind::TimedOut);
            }
            LookupResponseMode::Resolved | LookupResponseMode::Rejected => unreachable!(),
        }

        assert_eq!(
            session
                .lookup_canary_route_until(test_lookup(), Instant::now() + Duration::from_secs(1),)
                .unwrap_err()
                .kind(),
            PolicyRoutingSessionFailureKind::FreshSessionRequired
        );
        assert_eq!(calls.borrow().sent.len(), 1);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn live_groups_zero_session_opens_and_completes_unprivileged_readback() {
    let identity = test_managed_policy_routing_identity(NetworkAddressFamily::Ipv4);
    let mut session = PolicyRoutingSession::open_with_timeout(Duration::from_secs(5)).unwrap();
    let evidence = session.evidence();

    assert_ne!(evidence.local_port_id().get(), 0);
    assert_eq!(evidence.groups(), 0);
    assert!(evidence.extended_ack());
    assert!(evidence.capped_ack());
    session.observe(identity).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn live_groups_zero_session_resolves_a_loopback_canary_lookup() {
    let mut session = PolicyRoutingSession::open_with_timeout(Duration::from_secs(5)).unwrap();
    let lookup = CanaryRouteLookupRequest::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        NonZeroU16::new(41_001).unwrap(),
        NonZeroU32::new(1_000).unwrap(),
        0,
    );

    assert!(matches!(
        session
            .lookup_canary_route_until(lookup, Instant::now() + Duration::from_secs(5))
            .unwrap(),
        CanaryRouteLookupOutcome::Resolved(result) if result.table().get() != 0
    ));
}

fn test_lookup() -> CanaryRouteLookupRequest {
    CanaryRouteLookupRequest::new(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        NonZeroU16::new(41_001).unwrap(),
        NonZeroU32::new(10_321).unwrap(),
        0x1234_5678,
    )
}

fn lookup_route_response(request: &[u8], table: u8) -> Vec<u8> {
    let sequence = read_u32(&request[8..]);
    let mut payload = [0_u8; 12].to_vec();
    payload[0] = request[NETLINK_HEADER_LENGTH];
    payload[1] = request[NETLINK_HEADER_LENGTH + 1];
    payload[4] = table;
    append_netlink_attribute(&mut payload, RTA_TABLE, &u32::from(table).to_ne_bytes());
    for attribute in NetlinkAttributeIter::new(&request[28..], 28).map(Result::unwrap) {
        if matches!(attribute.attribute_type(), RTA_DST | RTA_UID | RTA_MARK) {
            append_netlink_attribute(&mut payload, attribute.attribute_type(), attribute.value());
        }
    }
    netlink_message(RTM_NEWROUTE, 0, sequence, TEST_PORT_ID, &payload)
}

fn lookup_rejection_response(request: &[u8], raw_errno: i32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&raw_errno.to_ne_bytes());
    payload.extend_from_slice(&request[..NETLINK_HEADER_LENGTH]);
    netlink_message(
        NLMSG_ERROR,
        NLM_F_CAPPED,
        read_u32(&request[8..]),
        TEST_PORT_ID,
        &payload,
    )
}

fn netlink_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    port_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let length = NETLINK_HEADER_LENGTH + payload.len();
    let mut message = Vec::with_capacity(super::super::align4(length));
    message.extend_from_slice(&(length as u32).to_ne_bytes());
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&port_id.to_ne_bytes());
    message.extend_from_slice(payload);
    message.resize(super::super::align4(length), 0);
    message
}

fn append_netlink_attribute(message: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
    let length = 4 + value.len();
    message.extend_from_slice(&(length as u16).to_ne_bytes());
    message.extend_from_slice(&attribute_type.to_ne_bytes());
    message.extend_from_slice(value);
    message.resize(super::super::align4(message.len()), 0);
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes[..2].try_into().unwrap())
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes[..4].try_into().unwrap())
}
