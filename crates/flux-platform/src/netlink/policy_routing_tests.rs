use std::num::{NonZeroU16, NonZeroU32};

use flux_core::{
    AddressHostFamilySelection, CaptureApplicationMode, CaptureApplicationPolicy,
    CaptureBypassPolicy, CaptureGroupId, CaptureInterfacePolicy, CaptureIpPrefix,
    CaptureProtocolSet, CaptureTrafficScope, CaptureUserId, CompatibilityEngineCredentials,
    FwmarkCandidate, ShadowCaptureProgramRequest, compile_shadow_capture_program,
};

use super::*;
use crate::netlink::{NLA_F_NESTED, NLMSG_DONE};
use crate::xtables::{
    XtablesCaptureLoweringRequest, XtablesCaptureNamespace, XtablesLocalOutputRoutingSpec,
    XtablesLocalOutputRoutingTarget, XtablesTproxyTarget, lower_xtables_capture,
};

const TEST_SEQUENCE: u32 = 41;
const TEST_RULE_SEQUENCE: u32 = 42;
const TEST_PORT_ID: u32 = 7;
const TEST_TABLE: u32 = 20_253;
const TEST_PRIORITY: u32 = 30_999;
const TEST_METRIC: u32 = 1_024;
const TEST_MARK: u32 = 0x0020_0000;
const TEST_MASK: u32 = 0x0060_0000;
const TEST_ROUTE_PROTOCOL: u8 = 4;
const TEST_RULE_PROTOCOL: u8 = 99;
const NLM_F_MULTI: u16 = 0x0002;
const RTAX_MTU: u16 = 2;

#[test]
fn binding_pins_ipv4_and_ipv6_kernel_canonical_route_identity() {
    for (family, expected_scope) in [
        (NetworkAddressFamily::Ipv4, RT_SCOPE_HOST),
        (NetworkAddressFamily::Ipv6, RT_SCOPE_UNIVERSE),
    ] {
        let requirement = routing_requirement(family);
        let identity = ManagedPolicyRoutingIdentity::bind(
            requirement,
            InterfaceIndex::new(1).expect("loopback index"),
        )
        .expect("bind canonical routing requirement");

        assert_eq!(identity.family(), family);
        assert_eq!(identity.loopback().name().as_bytes(), b"lo");
        assert_eq!(identity.loopback().index().get(), 1);
        assert_eq!(
            identity.route().destination(),
            RoutePrefix::unspecified(family)
        );
        assert_eq!(identity.route().scope().raw(), expected_scope);
        assert_eq!(identity.route().metric().get(), TEST_METRIC);
        assert_eq!(identity.rule().priority().get(), TEST_PRIORITY);
        assert_eq!(identity.rule().protocol().raw(), TEST_RULE_PROTOCOL);
    }
}

#[test]
fn route_mutations_pin_headers_flags_extended_table_oif_and_metric() {
    let identity = identity(NetworkAddressFamily::Ipv4, TEST_TABLE);
    for (mutation, message_type, flags) in [
        (
            PolicyRoutingMutation::AddRoute(identity.route()),
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        ),
        (
            PolicyRoutingMutation::DeleteRoute(identity.route()),
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
        ),
    ] {
        let request = encode_policy_routing_mutation(mutation, nonzero(TEST_SEQUENCE)).unwrap();
        let header = request_header(request.bytes());
        assert_eq!(
            header,
            (
                request.bytes().len() as u32,
                message_type,
                flags,
                TEST_SEQUENCE,
                0
            )
        );
        assert_eq!(request.bytes()[16], AF_INET);
        assert_eq!(&request.bytes()[17..20], &[0, 0, 0]);
        assert_eq!(request.bytes()[20], RT_TABLE_UNSPEC);
        assert_eq!(request.bytes()[21], TEST_ROUTE_PROTOCOL);
        assert_eq!(request.bytes()[22], RT_SCOPE_HOST);
        assert_eq!(request.bytes()[23], RTN_LOCAL);
        assert_eq!(read_u32(&request.bytes()[24..]), 0);
        assert_eq!(
            attributes(request.bytes(), 28),
            vec![
                (RTA_TABLE, TEST_TABLE.to_ne_bytes().to_vec()),
                (RTA_OIF, 1_u32.to_ne_bytes().to_vec()),
                (RTA_PRIORITY, TEST_METRIC.to_ne_bytes().to_vec()),
            ]
        );
    }
}

#[test]
fn compact_request_table_is_mirrored_in_header_and_attribute() {
    let identity = identity(NetworkAddressFamily::Ipv4, 100);
    let route = encode_policy_routing_mutation(
        PolicyRoutingMutation::AddRoute(identity.route()),
        nonzero(TEST_SEQUENCE),
    )
    .unwrap();
    let rule = encode_policy_routing_mutation(
        PolicyRoutingMutation::AddRule(identity.rule()),
        nonzero(TEST_RULE_SEQUENCE),
    )
    .unwrap();

    assert_eq!(route.bytes()[20], 100);
    assert_eq!(rule.bytes()[20], 100);
    assert!(attributes(route.bytes(), 28).contains(&(RTA_TABLE, 100_u32.to_ne_bytes().to_vec())));
    assert!(attributes(rule.bytes(), 28).contains(&(FRA_TABLE, 100_u32.to_ne_bytes().to_vec())));
}

#[test]
fn rule_mutations_pin_zero_reserved_bytes_and_mandatory_protocol() {
    let identity = identity(NetworkAddressFamily::Ipv6, TEST_TABLE);
    for (mutation, message_type, flags) in [
        (
            PolicyRoutingMutation::AddRule(identity.rule()),
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        ),
        (
            PolicyRoutingMutation::DeleteRule(identity.rule()),
            RTM_DELRULE,
            NLM_F_REQUEST | NLM_F_ACK,
        ),
    ] {
        let request =
            encode_policy_routing_mutation(mutation, nonzero(TEST_RULE_SEQUENCE)).unwrap();
        assert_eq!(
            request_header(request.bytes()),
            (
                request.bytes().len() as u32,
                message_type,
                flags,
                TEST_RULE_SEQUENCE,
                0,
            )
        );
        assert_eq!(&request.bytes()[16..20], &[AF_INET6, 0, 0, 0]);
        assert_eq!(&request.bytes()[20..23], &[RT_TABLE_UNSPEC, 0, 0]);
        assert_eq!(request.bytes()[23], FR_ACT_TO_TBL);
        assert_eq!(read_u32(&request.bytes()[24..]), 0);
        assert_eq!(
            attributes(request.bytes(), 28),
            vec![
                (FRA_TABLE, TEST_TABLE.to_ne_bytes().to_vec()),
                (FRA_PRIORITY, TEST_PRIORITY.to_ne_bytes().to_vec()),
                (FRA_FWMARK, TEST_MARK.to_ne_bytes().to_vec()),
                (FRA_FWMASK, TEST_MASK.to_ne_bytes().to_vec()),
                (FRA_PROTOCOL, vec![TEST_RULE_PROTOCOL]),
            ]
        );
    }
}

#[test]
fn capped_success_ack_is_accepted() {
    let request = encoded_rule_request();
    let ack = ack_datagram(&request, 0, NLM_F_CAPPED, &[], false);
    let decoded = decode_policy_routing_ack(
        &ack,
        PolicyRoutingAckSender::kernel_unicast(),
        nonzero(TEST_PORT_ID),
        &request,
    )
    .unwrap();

    assert_eq!(decoded.status(), PolicyRoutingAckStatus::Accepted);
    assert_eq!(decoded.extended().message(), None);
    assert_eq!(decoded.extended().offset(), None);
}

#[test]
fn capped_error_ack_preserves_bounded_extended_ack() {
    let request = encoded_rule_request();
    let mut extended = Vec::new();
    append_test_attribute(&mut extended, NLMSGERR_ATTR_MSG, b"conflict\0");
    append_test_attribute(&mut extended, NLMSGERR_ATTR_OFFS, &24_u32.to_ne_bytes());
    append_test_attribute(&mut extended, 77, &[1, 2]);
    let ack = ack_datagram(
        &request,
        -17,
        NLM_F_CAPPED | NLM_F_ACK_TLVS,
        &extended,
        false,
    );
    let decoded = decode_policy_routing_ack(
        &ack,
        PolicyRoutingAckSender::kernel_unicast(),
        nonzero(TEST_PORT_ID),
        &request,
    )
    .unwrap();

    assert_eq!(
        decoded.status(),
        PolicyRoutingAckStatus::Rejected {
            errno: NonZeroI32::new(17).unwrap(),
        }
    );
    assert_eq!(decoded.extended().message(), Some("conflict"));
    assert_eq!(decoded.extended().offset(), Some(24));
    assert_eq!(decoded.extended().unknown_attributes(), 1);
}

#[test]
fn extended_ack_tolerates_bounded_nested_policy_diagnostics() {
    let request = encoded_rule_request();
    let mut extended = Vec::new();
    append_test_attribute(&mut extended, 4 | NLA_F_NESTED, &[]);
    let ack = ack_datagram(
        &request,
        -22,
        NLM_F_CAPPED | NLM_F_ACK_TLVS,
        &extended,
        false,
    );
    let decoded = decode_policy_routing_ack(
        &ack,
        PolicyRoutingAckSender::kernel_unicast(),
        nonzero(TEST_PORT_ID),
        &request,
    )
    .unwrap();

    assert_eq!(decoded.extended().unknown_attributes(), 1);
}

#[test]
fn uncapped_error_ack_requires_the_complete_echoed_request() {
    let request = encoded_rule_request();
    let ack = ack_datagram(&request, -1, 0, &[], true);
    let decoded = decode_policy_routing_ack(
        &ack,
        PolicyRoutingAckSender::kernel_unicast(),
        nonzero(TEST_PORT_ID),
        &request,
    )
    .unwrap();
    assert_eq!(
        decoded.status(),
        PolicyRoutingAckStatus::Rejected {
            errno: NonZeroI32::new(1).unwrap(),
        }
    );

    let mut mismatched = ack;
    mismatched[NETLINK_HEADER_LENGTH + NLMSGERR_HEADER_LENGTH] ^= 1;
    assert_eq!(
        decode_policy_routing_ack(
            &mismatched,
            PolicyRoutingAckSender::kernel_unicast(),
            nonzero(TEST_PORT_ID),
            &request,
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingAckDecodeErrorKind::EmbeddedRequestMismatch
    );
}

#[test]
fn ack_decoder_rejects_wrong_envelope_malformed_tlv_and_oversized_input() {
    let request = encoded_rule_request();
    let valid = ack_datagram(&request, 0, NLM_F_CAPPED, &[], false);
    assert_eq!(
        decode_policy_routing_ack(
            &valid,
            PolicyRoutingAckSender::new(SOCKADDR_NL_LENGTH, AF_NETLINK, 1, 0),
            nonzero(TEST_PORT_ID),
            &request,
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingAckDecodeErrorKind::UnexpectedSender
    );

    let mut wrong_sequence = valid.clone();
    wrong_sequence[8..12].copy_from_slice(&99_u32.to_ne_bytes());
    assert_eq!(
        decode_policy_routing_ack(
            &wrong_sequence,
            PolicyRoutingAckSender::kernel_unicast(),
            nonzero(TEST_PORT_ID),
            &request,
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingAckDecodeErrorKind::UnexpectedSequence
    );

    let mut wrong_port = valid;
    wrong_port[12..16].copy_from_slice(&99_u32.to_ne_bytes());
    assert_eq!(
        decode_policy_routing_ack(
            &wrong_port,
            PolicyRoutingAckSender::kernel_unicast(),
            nonzero(TEST_PORT_ID),
            &request,
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingAckDecodeErrorKind::UnexpectedPortId
    );

    let malformed = ack_datagram(
        &request,
        -1,
        NLM_F_CAPPED | NLM_F_ACK_TLVS,
        &[3, 0, 1, 0],
        false,
    );
    assert_eq!(
        decode_policy_routing_ack(
            &malformed,
            PolicyRoutingAckSender::kernel_unicast(),
            nonzero(TEST_PORT_ID),
            &request,
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingAckDecodeErrorKind::InvalidExtendedAck
    );

    let oversized = vec![0_u8; MAX_POLICY_ROUTING_ACK_BYTES + 1];
    assert_eq!(
        decode_policy_routing_ack(
            &oversized,
            PolicyRoutingAckSender::kernel_unicast(),
            nonzero(TEST_PORT_ID),
            &request,
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingAckDecodeErrorKind::DatagramTooLarge
    );

    let positive_errno = ack_datagram(&request, 1, NLM_F_CAPPED, &[], false);
    assert_eq!(
        decode_policy_routing_ack(
            &positive_errno,
            PolicyRoutingAckSender::kernel_unicast(),
            nonzero(TEST_PORT_ID),
            &request,
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingAckDecodeErrorKind::InvalidErrno
    );
}

#[test]
fn exact_readback_accepts_kernel_dump_shape_and_allowed_route_ephemera() {
    let identity = identity(NetworkAddressFamily::Ipv4, TEST_TABLE);
    let route_dump = route_dump(
        identity.route(),
        TEST_SEQUENCE,
        &[
            RouteVariation::CacheInfo,
            RouteVariation::Metrics,
            RouteVariation::Pad,
        ],
    );
    let rule_dump = rule_dump(identity.rule(), TEST_RULE_SEQUENCE, &[]);
    let observed = observe_managed_policy_routing(
        identity,
        &route_dump,
        nonzero(TEST_SEQUENCE),
        &rule_dump,
        nonzero(TEST_RULE_SEQUENCE),
    )
    .unwrap();

    assert_eq!(observed.route().exact_count(), 1);
    assert_eq!(observed.route().conflict_count(), 0);
    assert_eq!(observed.rule().exact_count(), 1);
    assert_eq!(observed.rule().conflict_count(), 0);
}

#[test]
fn exact_ipv6_readback_accepts_kernel_cacheinfo_and_medium_preference() {
    let identity = identity(NetworkAddressFamily::Ipv6, TEST_TABLE);
    let route_dump = route_dump(identity.route(), TEST_SEQUENCE, &[]);
    let rule_dump = rule_dump(identity.rule(), TEST_RULE_SEQUENCE, &[]);
    let observed = observe_managed_policy_routing(
        identity,
        &route_dump,
        nonzero(TEST_SEQUENCE),
        &rule_dump,
        nonzero(TEST_RULE_SEQUENCE),
    )
    .unwrap();

    assert_eq!(observed.route().exact_count(), 1);
    assert_eq!(observed.route().conflict_count(), 0);
}

#[test]
fn readback_treats_nonempty_route_metrics_as_conflict() {
    let identity = identity(NetworkAddressFamily::Ipv4, TEST_TABLE);
    let route_dump = route_dump(
        identity.route(),
        TEST_SEQUENCE,
        &[RouteVariation::MtuMetric(1_500)],
    );
    let rule_dump = rule_dump(identity.rule(), TEST_RULE_SEQUENCE, &[]);
    let observed = observe_managed_policy_routing(
        identity,
        &route_dump,
        nonzero(TEST_SEQUENCE),
        &rule_dump,
        nonzero(TEST_RULE_SEQUENCE),
    )
    .unwrap();

    assert_eq!(observed.route().exact_count(), 0);
    assert_eq!(observed.route().conflict_count(), 1);
    assert_eq!(observed.rule().exact_count(), 1);
    assert_eq!(observed.rule().conflict_count(), 0);
}

#[test]
fn readback_preserves_duplicate_exact_objects() {
    let identity = identity(NetworkAddressFamily::Ipv6, TEST_TABLE);
    let route = route_message(identity.route(), TEST_SEQUENCE, RTM_NEWROUTE, &[]);
    let rule = rule_message(identity.rule(), TEST_RULE_SEQUENCE, RTM_NEWRULE, &[]);
    let route_dump = dump_with_messages(&[route.clone(), route], TEST_SEQUENCE);
    let rule_dump = dump_with_messages(&[rule.clone(), rule], TEST_RULE_SEQUENCE);
    let observed = observe_managed_policy_routing(
        identity,
        &route_dump,
        nonzero(TEST_SEQUENCE),
        &rule_dump,
        nonzero(TEST_RULE_SEQUENCE),
    )
    .unwrap();

    assert_eq!(observed.route().exact_count(), 2);
    assert_eq!(observed.route().conflict_count(), 0);
    assert_eq!(observed.rule().exact_count(), 2);
    assert_eq!(observed.rule().conflict_count(), 0);
}

#[test]
fn readback_counts_same_table_and_same_priority_conflicts() {
    let identity = identity(NetworkAddressFamily::Ipv4, TEST_TABLE);
    let route_dump = route_dump(
        identity.route(),
        TEST_SEQUENCE,
        &[RouteVariation::Metric(TEST_METRIC + 1)],
    );
    let rule_dump = rule_dump(
        identity.rule(),
        TEST_RULE_SEQUENCE,
        &[
            RuleVariation::Priority(TEST_PRIORITY + 1),
            RuleVariation::Table(TEST_TABLE + 1),
        ],
    );
    let observed = observe_managed_policy_routing(
        identity,
        &route_dump,
        nonzero(TEST_SEQUENCE),
        &rule_dump,
        nonzero(TEST_RULE_SEQUENCE),
    )
    .unwrap();

    assert_eq!(observed.route().exact_count(), 0);
    assert_eq!(observed.route().conflict_count(), 1);
    assert_eq!(observed.rule().exact_count(), 0);
    assert_eq!(observed.rule().conflict_count(), 2);
}

#[test]
fn raw_route_attribute_and_unmasked_rule_bits_remain_conflicts() {
    let identity = identity(NetworkAddressFamily::Ipv4, TEST_TABLE);
    let route_dump = route_dump(
        identity.route(),
        TEST_SEQUENCE,
        &[RouteVariation::DroppedMark(9)],
    );
    let rule_dump = rule_dump(
        identity.rule(),
        TEST_RULE_SEQUENCE,
        &[RuleVariation::RawMark(TEST_MARK | 1)],
    );
    let observed = observe_managed_policy_routing(
        identity,
        &route_dump,
        nonzero(TEST_SEQUENCE),
        &rule_dump,
        nonzero(TEST_RULE_SEQUENCE),
    )
    .unwrap();

    assert_eq!(observed.route().exact_count(), 0);
    assert_eq!(observed.route().conflict_count(), 1);
    assert_eq!(observed.rule().exact_count(), 0);
    assert_eq!(observed.rule().conflict_count(), 1);
}

#[test]
fn readback_rejects_removals_missing_completion_and_sequence_mismatch() {
    let identity = identity(NetworkAddressFamily::Ipv4, TEST_TABLE);
    let removed_route = dump_with_messages(
        &[route_message(
            identity.route(),
            TEST_SEQUENCE,
            RTM_DELROUTE,
            &[],
        )],
        TEST_SEQUENCE,
    );
    let valid_rule = rule_dump(identity.rule(), TEST_RULE_SEQUENCE, &[]);
    assert_eq!(
        observe_managed_policy_routing(
            identity,
            &removed_route,
            nonzero(TEST_SEQUENCE),
            &valid_rule,
            nonzero(TEST_RULE_SEQUENCE),
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingReadbackErrorKind::RouteRemovalInDump
    );

    let route_without_done = route_message(identity.route(), TEST_SEQUENCE, RTM_NEWROUTE, &[]);
    assert_eq!(
        observe_managed_policy_routing(
            identity,
            &route_without_done,
            nonzero(TEST_SEQUENCE),
            &valid_rule,
            nonzero(TEST_RULE_SEQUENCE),
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingReadbackErrorKind::MissingRouteCompletion
    );

    let valid_route = route_dump(identity.route(), TEST_SEQUENCE, &[]);
    assert_eq!(
        observe_managed_policy_routing(
            identity,
            &valid_route,
            nonzero(TEST_SEQUENCE + 1),
            &valid_rule,
            nonzero(TEST_RULE_SEQUENCE),
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingReadbackErrorKind::UnexpectedRouteSequence
    );
}

#[test]
fn readback_preflights_the_combined_event_bound_before_decoding() {
    let identity = identity(NetworkAddressFamily::Ipv4, TEST_TABLE);
    let route_event = netlink_message(
        RTM_NEWROUTE,
        NLM_F_MULTI,
        TEST_SEQUENCE,
        0,
        &[0; ROUTING_HEADER_LENGTH],
    );
    let mut oversized = Vec::new();
    for _ in 0..=MAX_POLICY_ROUTING_READBACK_EVENTS {
        oversized.extend_from_slice(&route_event);
    }
    assert_eq!(
        observe_managed_policy_routing(
            identity,
            &oversized,
            nonzero(TEST_SEQUENCE),
            &[],
            nonzero(TEST_RULE_SEQUENCE),
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingReadbackErrorKind::TooManyEvents
    );
}

#[test]
fn readback_bounds_combined_bytes_and_all_framed_messages() {
    let identity = identity(NetworkAddressFamily::Ipv4, TEST_TABLE);
    let oversized = vec![0_u8; MAX_POLICY_ROUTING_READBACK_BYTES + 1];
    assert_eq!(
        observe_managed_policy_routing(
            identity,
            &oversized,
            nonzero(TEST_SEQUENCE),
            &[],
            nonzero(TEST_RULE_SEQUENCE),
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingReadbackErrorKind::DumpBytesExceeded
    );

    let noop = netlink_message(1, 0, TEST_SEQUENCE, 0, &[]);
    let mut too_many_messages = Vec::new();
    for _ in 0..=MAX_POLICY_ROUTING_READBACK_MESSAGES {
        too_many_messages.extend_from_slice(&noop);
    }
    assert_eq!(
        observe_managed_policy_routing(
            identity,
            &too_many_messages,
            nonzero(TEST_SEQUENCE),
            &[],
            nonzero(TEST_RULE_SEQUENCE),
        )
        .unwrap_err()
        .kind(),
        PolicyRoutingReadbackErrorKind::TooManyMessages
    );
}

fn identity(family: NetworkAddressFamily, table: u32) -> ManagedPolicyRoutingIdentity {
    let index = InterfaceIndex::new(1).unwrap();
    ManagedPolicyRoutingIdentity {
        family,
        loopback: ManagedInterfaceIdentity {
            name: InterfaceName::new(b"lo").unwrap(),
            index,
        },
        route: ManagedLocalRouteIdentity {
            family,
            destination: RoutePrefix::unspecified(family),
            table: RouteTableId::from_raw(table),
            protocol: RouteProtocol::from_raw(TEST_ROUTE_PROTOCOL),
            scope: canonical_route_scope(family),
            route_type: RouteType::from_raw(RTN_LOCAL),
            metric: nonzero(TEST_METRIC),
            output_interface: index,
        },
        rule: ManagedFwmarkRuleIdentity {
            family,
            priority: RulePriority::from_raw(TEST_PRIORITY),
            table: RouteTableId::from_raw(table),
            mark: RuleFwMark::new(TEST_MARK, TEST_MASK).unwrap(),
            protocol: RuleProtocol::from_raw(TEST_RULE_PROTOCOL),
        },
    }
}

fn routing_requirement(family: NetworkAddressFamily) -> XtablesLocalOutputRoutingRequirement {
    let selected = match family {
        NetworkAddressFamily::Ipv4 => AddressHostFamilySelection::Ipv4,
        NetworkAddressFamily::Ipv6 => AddressHostFamilySelection::Ipv6,
    };
    let scope = CaptureTrafficScope::new(selected, true, false).unwrap();
    let report = compile_shadow_capture_program(ShadowCaptureProgramRequest::new(
        scope,
        CompatibilityEngineCredentials::new(uid(1000), gid(1000)),
        CaptureBypassPolicy::new(std::iter::empty::<CaptureIpPrefix>()).unwrap(),
        None,
        CaptureInterfacePolicy::new([], None, []).unwrap(),
        CaptureApplicationPolicy::new(CaptureApplicationMode::All, []).unwrap(),
        CaptureProtocolSet::TCP_AND_UDP,
    ))
    .unwrap();
    let request = XtablesCaptureLoweringRequest::new(
        report.artifact(),
        XtablesCaptureNamespace::new(nonzero(7)),
        XtablesTproxyTarget::new(
            NonZeroU16::new(1536).unwrap(),
            FwmarkCandidate::new(TEST_MASK, TEST_MARK, 0x0040_0000).unwrap(),
        ),
    );
    let target = || {
        XtablesLocalOutputRoutingTarget::new(
            RulePriority::from_raw(TEST_PRIORITY),
            RouteTableId::from_raw(TEST_TABLE),
            nonzero(TEST_METRIC),
            RouteProtocol::from_raw(TEST_ROUTE_PROTOCOL),
            RuleProtocol::from_raw(TEST_RULE_PROTOCOL),
        )
        .unwrap()
    };
    let routing = XtablesLocalOutputRoutingSpec::new(
        (family == NetworkAddressFamily::Ipv4).then(target),
        (family == NetworkAddressFamily::Ipv6).then(target),
    )
    .unwrap();
    let lowered = lower_xtables_capture(request.with_local_output_routing(routing)).unwrap();
    let family = match family {
        NetworkAddressFamily::Ipv4 => lowered.ipv4().unwrap(),
        NetworkAddressFamily::Ipv6 => lowered.ipv6().unwrap(),
    };
    family.local_output().unwrap().routing()
}

fn encoded_rule_request() -> EncodedPolicyRoutingRequest {
    encode_policy_routing_mutation(
        PolicyRoutingMutation::AddRule(identity(NetworkAddressFamily::Ipv4, TEST_TABLE).rule()),
        nonzero(TEST_RULE_SEQUENCE),
    )
    .unwrap()
}

fn ack_datagram(
    request: &EncodedPolicyRoutingRequest,
    error: i32,
    flags: u16,
    extended: &[u8],
    echo_complete_request: bool,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&error.to_ne_bytes());
    if echo_complete_request {
        payload.extend_from_slice(request.bytes());
    } else {
        payload.extend_from_slice(&request.bytes()[..NETLINK_HEADER_LENGTH]);
    }
    payload.extend_from_slice(extended);
    netlink_message(
        NLMSG_ERROR,
        flags,
        request.sequence().get(),
        TEST_PORT_ID,
        &payload,
    )
}

#[derive(Clone, Copy)]
enum RouteVariation {
    CacheInfo,
    Metrics,
    MtuMetric(u32),
    Pad,
    Metric(u32),
    DroppedMark(u32),
}

fn route_dump(
    identity: ManagedLocalRouteIdentity,
    sequence: u32,
    variations: &[RouteVariation],
) -> Vec<u8> {
    let messages = if variations.iter().all(|variation| {
        matches!(
            variation,
            RouteVariation::CacheInfo | RouteVariation::Metrics | RouteVariation::Pad
        )
    }) {
        vec![route_message(identity, sequence, RTM_NEWROUTE, variations)]
    } else {
        variations
            .iter()
            .map(|variation| route_message(identity, sequence, RTM_NEWROUTE, &[*variation]))
            .collect()
    };
    dump_with_messages(&messages, sequence)
}

fn route_message(
    identity: ManagedLocalRouteIdentity,
    sequence: u32,
    message_type: u16,
    variations: &[RouteVariation],
) -> Vec<u8> {
    let mut metric = identity.metric().get();
    let mut body = [0_u8; ROUTING_HEADER_LENGTH];
    body[0] = family_byte(identity.family());
    body[4] = dump_table_byte(identity.table());
    body[5] = identity.protocol().raw();
    body[6] = identity.scope().raw();
    body[7] = identity.route_type().raw();
    for variation in variations {
        if let RouteVariation::Metric(value) = variation {
            metric = *value;
        }
    }
    let mut payload = body.to_vec();
    append_test_attribute(
        &mut payload,
        RTA_TABLE,
        &identity.table().get().to_ne_bytes(),
    );
    append_test_attribute(
        &mut payload,
        RTA_OIF,
        &identity.output_interface().get().to_ne_bytes(),
    );
    append_test_attribute(&mut payload, RTA_PRIORITY, &metric.to_ne_bytes());
    if identity.family() == NetworkAddressFamily::Ipv6 {
        append_test_attribute(&mut payload, RTA_CACHEINFO, &[0; 32]);
        append_test_attribute(&mut payload, RTA_PREF, &[IPV6_ROUTE_PREFERENCE_MEDIUM]);
    }
    for variation in variations {
        match variation {
            RouteVariation::CacheInfo => {
                append_test_attribute(&mut payload, RTA_CACHEINFO, &[0; 32]);
            }
            RouteVariation::Metrics => append_test_attribute(&mut payload, RTA_METRICS, &[]),
            RouteVariation::MtuMetric(value) => {
                let mut metrics = Vec::new();
                append_test_attribute(&mut metrics, RTAX_MTU, &value.to_ne_bytes());
                append_test_attribute(&mut payload, RTA_METRICS, &metrics);
            }
            RouteVariation::Pad => append_test_attribute(&mut payload, RTA_PAD, &[]),
            RouteVariation::DroppedMark(value) => {
                append_test_attribute(&mut payload, 16, &value.to_ne_bytes());
            }
            RouteVariation::Metric(_) => {}
        }
    }
    netlink_message(message_type, NLM_F_MULTI, sequence, 0, &payload)
}

#[derive(Clone, Copy)]
enum RuleVariation {
    Priority(u32),
    Table(u32),
    RawMark(u32),
}

fn rule_dump(
    identity: ManagedFwmarkRuleIdentity,
    sequence: u32,
    variations: &[RuleVariation],
) -> Vec<u8> {
    let messages = if variations.is_empty() {
        vec![rule_message(identity, sequence, RTM_NEWRULE, &[])]
    } else {
        variations
            .iter()
            .map(|variation| rule_message(identity, sequence, RTM_NEWRULE, &[*variation]))
            .collect()
    };
    dump_with_messages(&messages, sequence)
}

fn rule_message(
    identity: ManagedFwmarkRuleIdentity,
    sequence: u32,
    message_type: u16,
    variations: &[RuleVariation],
) -> Vec<u8> {
    let mut table = identity.table().get();
    let mut priority = identity.priority().get();
    let mut mark = identity.mark().value();
    for variation in variations {
        match variation {
            RuleVariation::Priority(value) => priority = *value,
            RuleVariation::Table(value) => table = *value,
            RuleVariation::RawMark(value) => mark = *value,
        }
    }
    let mut body = [0_u8; ROUTING_HEADER_LENGTH];
    body[0] = family_byte(identity.family());
    body[4] = dump_table_byte(RouteTableId::from_raw(table));
    body[7] = FR_ACT_TO_TBL;
    let mut payload = body.to_vec();
    append_test_attribute(&mut payload, FRA_TABLE, &table.to_ne_bytes());
    append_test_attribute(&mut payload, FRA_PRIORITY, &priority.to_ne_bytes());
    append_test_attribute(&mut payload, FRA_FWMARK, &mark.to_ne_bytes());
    append_test_attribute(
        &mut payload,
        FRA_FWMASK,
        &identity.mark().mask().to_ne_bytes(),
    );
    append_test_attribute(&mut payload, FRA_PROTOCOL, &[identity.protocol().raw()]);
    append_test_attribute(
        &mut payload,
        FRA_SUPPRESS_PREFIXLEN,
        &u32::MAX.to_ne_bytes(),
    );
    netlink_message(message_type, NLM_F_MULTI, sequence, 0, &payload)
}

fn dump_with_messages(messages: &[Vec<u8>], sequence: u32) -> Vec<u8> {
    let mut dump = Vec::new();
    for message in messages {
        dump.extend_from_slice(message);
    }
    dump.extend_from_slice(&netlink_message(NLMSG_DONE, 0, sequence, 0, &[]));
    dump
}

fn netlink_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    port_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let length = NETLINK_HEADER_LENGTH + payload.len();
    let mut message = Vec::with_capacity(align4(length));
    message.extend_from_slice(&(length as u32).to_ne_bytes());
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&port_id.to_ne_bytes());
    message.extend_from_slice(payload);
    message.resize(align4(length), 0);
    message
}

fn append_test_attribute(bytes: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
    let length = NETLINK_ATTRIBUTE_HEADER_LENGTH + value.len();
    bytes.extend_from_slice(&(length as u16).to_ne_bytes());
    bytes.extend_from_slice(&attribute_type.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(align4(bytes.len()), 0);
}

fn attributes(bytes: &[u8], offset: usize) -> Vec<(u16, Vec<u8>)> {
    NetlinkAttributeIter::new(&bytes[offset..], offset)
        .map(|attribute| {
            let attribute = attribute.unwrap();
            (attribute.attribute_type(), attribute.value().to_vec())
        })
        .collect()
}

fn request_header(bytes: &[u8]) -> (u32, u16, u16, u32, u32) {
    (
        read_u32(bytes),
        read_u16(&bytes[4..]),
        read_u16(&bytes[6..]),
        read_u32(&bytes[8..]),
        read_u32(&bytes[12..]),
    )
}

fn nonzero(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

fn uid(value: u32) -> CaptureUserId {
    CaptureUserId::new(value).unwrap()
}

fn gid(value: u32) -> CaptureGroupId {
    CaptureGroupId::new(value).unwrap()
}
