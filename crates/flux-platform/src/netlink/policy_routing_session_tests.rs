use std::cell::RefCell;
use std::rc::Rc;

use flux_core::NetworkAddressFamily;

use super::*;
use crate::netlink::NETLINK_HEADER_LENGTH;
use crate::netlink::policy_routing::test_managed_policy_routing_identity;

const TEST_PORT_ID: u32 = 7;
const NLM_F_CAPPED: u16 = 0x0100;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const RTM_GETRULE: u16 = 34;

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

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes[..2].try_into().unwrap())
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes[..4].try_into().unwrap())
}
