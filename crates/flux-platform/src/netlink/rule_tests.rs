use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::super::{
    NETLINK_ATTRIBUTE_HEADER_LENGTH, NLA_F_NESTED, NLA_F_NET_BYTEORDER, NLA_TYPE_MASK,
    NLM_F_ACK_TLVS, align4,
};
use super::*;

const RTM_NEWLINK: u16 = 16;
const AF_UNSPEC: u8 = 0;
const AF_BRIDGE: u8 = 7;
const NLM_F_REPLACE: u16 = 0x100;

#[test]
fn comprehensive_ipv4_rule_is_canonical_and_preserves_selection_facts() {
    let destination = Ipv4Addr::new(203, 0, 113, 99).octets();
    let source = Ipv4Addr::new(198, 51, 100, 77).octets();
    let table = 1_024_u32.to_ne_bytes();
    let priority = 10_000_u32.to_ne_bytes();
    let fwmark = 0x1234_u32.to_ne_bytes();
    let fwmask = 0x00ff_u32.to_ne_bytes();
    let flow = 42_u32.to_ne_bytes();
    let tunnel_id = 0x0102_0304_0506_0708_u64.to_be_bytes();
    let suppress_group = 7_u32.to_ne_bytes();
    let suppress_prefix = u32::MAX.to_ne_bytes();
    let uid_range = range_u32(1_000, 1_999);
    let source_ports = range_u16(1_024, 2_048);
    let destination_ports = range_u16(443, 8443);
    let datagram = rule_message(
        RTM_NEWRULE,
        NLM_F_REPLACE,
        41,
        AF_INET as u8,
        24,
        24,
        0x1e,
        RT_TABLE_COMPAT,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0x8001_001b,
        &[
            (FRA_DST, destination.as_slice()),
            (FRA_SRC, source.as_slice()),
            (FRA_IIFNAME, b"lo\0"),
            (FRA_OIFNAME, &[0xff, b'0', 0]),
            (FRA_PRIORITY, priority.as_slice()),
            (FRA_TABLE, table.as_slice()),
            (FRA_FWMARK, fwmark.as_slice()),
            (FRA_FWMASK, fwmask.as_slice()),
            (FRA_FLOW, flow.as_slice()),
            (FRA_PAD, &[]),
            (FRA_TUN_ID, tunnel_id.as_slice()),
            (FRA_SUPPRESS_IFGROUP, suppress_group.as_slice()),
            (FRA_SUPPRESS_PREFIXLEN, suppress_prefix.as_slice()),
            (FRA_UID_RANGE, uid_range.as_slice()),
            (FRA_PROTOCOL, &[99]),
            (FRA_IP_PROTO, &[17]),
            (FRA_SPORT_RANGE, source_ports.as_slice()),
            (FRA_DPORT_RANGE, destination_ports.as_slice()),
        ],
    );

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("valid comprehensive IPv4 rule");
    assert_eq!(decoded.sequence(), Some(41));
    assert!(decoded.completion().is_none());
    assert_eq!(decoded.events().len(), 1);
    let NetworkRuleEvent::Upsert(record) = &decoded.events()[0] else {
        panic!("NLM_F_REPLACE must remain an ordinary rule upsert");
    };

    assert_eq!(
        record.destination(),
        RulePrefix::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24).unwrap()
    );
    assert_eq!(
        record.source(),
        RulePrefix::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24).unwrap()
    );
    assert_eq!(record.priority().get(), 10_000);
    assert_eq!(record.properties().tos(), 0x1e);
    assert_eq!(record.properties().table().get(), 1_024);
    assert_eq!(record.properties().action(), RuleAction::TO_TABLE);
    assert_eq!(record.properties().protocol().raw(), 99);
    assert_eq!(record.properties().flags().raw(), 0x8001_001b);
    let mark = record.fwmark().expect("material mark selector");
    assert_eq!(mark.value(), 0x34);
    assert_eq!(mark.mask(), 0xff);
    assert_eq!(record.input_interface().unwrap().as_bytes(), b"lo");
    assert_eq!(record.output_interface().unwrap().as_bytes(), &[0xff, b'0']);
    assert_eq!(record.tunnel_id().unwrap().get(), 0x0102_0304_0506_0708);
    assert_eq!(record.suppress_interface_group().unwrap().get(), 7);
    assert!(record.suppress_prefix_length().is_none());
    assert!(!record.l3mdev());
    let uids = record.uid_range().expect("UID selector");
    assert_eq!((uids.start(), uids.end()), (1_000, 1_999));
    assert_eq!(record.ip_protocol().unwrap().get(), 17);
    let source_ports = record.source_port_range().expect("source ports");
    assert_eq!((source_ports.start(), source_ports.end()), (1_024, 2_048));
    let destination_ports = record.destination_port_range().expect("destination ports");
    assert_eq!(
        (destination_ports.start(), destination_ports.end()),
        (443, 8443)
    );
    assert_eq!(record.flow().unwrap().get(), 42);
    assert!(record.has_complete_attribute_coverage());
}

#[test]
fn ipv6_goto_delete_preserves_raw_tclass_and_masks_prefix_host_bits() {
    let destination = Ipv6Addr::new(0x2001, 0xdb8, 7, 0, 0, 0, 0, 0x1234).octets();
    let priority = 100_u32.to_ne_bytes();
    let target = 200_u32.to_ne_bytes();
    let table = 0_u32.to_ne_bytes();
    let datagram = rule_message(
        RTM_DELRULE,
        0,
        7,
        AF_INET6 as u8,
        64,
        0,
        0xff,
        0,
        0,
        0,
        RuleAction::GOTO.raw(),
        RuleFlags::UNRESOLVED.raw(),
        &[
            (FRA_DST, destination.as_slice()),
            (FRA_PRIORITY, priority.as_slice()),
            (FRA_GOTO, target.as_slice()),
            (FRA_TABLE, table.as_slice()),
            (FRA_PROTOCOL, &[2]),
            // IPv6's 5.10 policy accepts and ignores arbitrary FRA_FLOW data.
            (FRA_FLOW | NLA_F_NESTED, &[1, 2, 3]),
        ],
    );

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("valid IPv6 goto deletion");
    let NetworkRuleEvent::Remove(record) = &decoded.events()[0] else {
        panic!("expected rule removal");
    };
    assert_eq!(
        record.destination().address(),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 7, 0, 0, 0, 0, 0))
    );
    assert_eq!(
        record.source(),
        RulePrefix::unspecified(NetworkAddressFamily::Ipv6)
    );
    assert_eq!(record.properties().tos(), 0xff);
    assert_eq!(record.properties().action(), RuleAction::GOTO);
    assert_eq!(record.goto_target().unwrap().get(), 200);
    assert!(record.flow().is_none());
    assert!(record.has_complete_attribute_coverage());
}

#[test]
fn equal_priority_duplicate_rules_preserve_wire_order_and_multiplicity() {
    let first = basic_rule_with_sequence(9, &[(FRA_IIFNAME, b"lo\0")]);
    let second = basic_rule_with_sequence(9, &[(FRA_IIFNAME, b"lo\0")]);
    let decoded = decoder(true)
        .decode_datagram(&concatenate(&[&first, &second]))
        .expect("duplicate rule facts are valid");

    assert_eq!(decoded.events().len(), 2);
    assert_eq!(decoded.events()[0].record(), decoded.events()[1].record());
}

#[test]
fn disabled_ipv6_rules_are_fully_validated_before_filtering() {
    let destination = Ipv6Addr::LOCALHOST.octets();
    let malformed = rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET6 as u8,
        128,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[(FRA_DST, &destination[..4])],
    );
    assert_eq!(
        decoder(false)
            .decode_datagram(&malformed)
            .expect_err("disabled family still rejects malformed address")
            .kind(),
        RuleEventDecodeErrorKind::InvalidDestinationLength
    );

    let valid = rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET6 as u8,
        128,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[(FRA_DST, &destination)],
    );
    assert!(
        decoder(false)
            .decode_datagram(&valid)
            .expect("valid disabled-family rule")
            .events()
            .is_empty()
    );
}

#[test]
fn unknown_families_validate_only_top_level_attribute_framing() {
    let valid = rule_message(
        RTM_NEWRULE,
        0,
        19,
        AF_BRIDGE,
        u8::MAX,
        u8::MAX,
        u8::MAX,
        u8::MAX,
        u8::MAX,
        u8::MAX,
        u8::MAX,
        u32::MAX,
        &[(FRA_DST | NLA_F_NESTED, &[1, 2, 3])],
    );
    let decoded = decoder(true)
        .decode_datagram(&valid)
        .expect("well-framed unknown-family rule");
    assert_eq!(decoded.sequence(), Some(19));
    assert!(decoded.events().is_empty());

    let mut payload = rule_payload(AF_BRIDGE, 0, 0, 0, 0, 0, 0, 0, 0);
    payload.extend_from_slice(&3_u16.to_ne_bytes());
    payload.extend_from_slice(&FRA_DST.to_ne_bytes());
    assert_eq!(
        error_kind(&netlink_message(RTM_NEWRULE, 0, 1, 0, &payload)),
        RuleEventDecodeErrorKind::InvalidAttributeLength
    );
}

#[test]
fn known_families_require_zero_reserved_header_fields() {
    for (reserved_one, reserved_two, expected_offset) in [(1, 0, 21), (0, 1, 22)] {
        let datagram = rule_message(
            RTM_NEWRULE,
            0,
            1,
            AF_INET as u8,
            0,
            0,
            0,
            254,
            reserved_one,
            reserved_two,
            RuleAction::TO_TABLE.raw(),
            0,
            &[],
        );
        let error = decoder(true)
            .decode_datagram(&datagram)
            .expect_err("nonzero reserved byte");
        assert_eq!(error.kind(), RuleEventDecodeErrorKind::NonzeroReservedField);
        assert_eq!(error.offset(), expected_offset);
    }
}

#[test]
fn prefixes_require_family_width_but_mask_host_bits_canonically() {
    let missing_destination = rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET as u8,
        1,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[],
    );
    assert_eq!(
        error_kind(&missing_destination),
        RuleEventDecodeErrorKind::MissingDestination
    );

    let missing_source = rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET as u8,
        0,
        1,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[],
    );
    assert_eq!(
        error_kind(&missing_source),
        RuleEventDecodeErrorKind::MissingSource
    );

    assert_eq!(
        error_kind(&basic_rule(&[(FRA_DST, &[0; 3])])),
        RuleEventDecodeErrorKind::InvalidDestinationLength
    );
    assert_eq!(
        error_kind(&basic_rule(&[(FRA_SRC, &[0; 3])])),
        RuleEventDecodeErrorKind::InvalidSourceLength
    );

    let invalid_destination_length = rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET as u8,
        33,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[],
    );
    assert_eq!(
        error_kind(&invalid_destination_length),
        RuleEventDecodeErrorKind::InvalidDestinationPrefixLength
    );

    let all_host = Ipv4Addr::new(192, 0, 2, 123).octets();
    let decoded = decoder(true)
        .decode_datagram(&basic_rule(&[(FRA_DST, &all_host)]))
        .expect("zero-length prefix masks the entire supplied address");
    assert_eq!(
        decoded.events()[0].record().destination(),
        RulePrefix::unspecified(NetworkAddressFamily::Ipv4)
    );
}

#[test]
fn known_family_kernel_output_requires_unconditional_attributes() {
    let table = 254_u32.to_ne_bytes();
    let suppress_prefix = u32::MAX.to_ne_bytes();

    let missing_table = raw_rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[
            (FRA_SUPPRESS_PREFIXLEN, &suppress_prefix),
            (FRA_PROTOCOL, &[0]),
        ],
    );
    assert_eq!(
        error_kind(&missing_table),
        RuleEventDecodeErrorKind::MissingTable
    );

    let missing_suppress_prefix = raw_rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[(FRA_TABLE, &table), (FRA_PROTOCOL, &[0])],
    );
    assert_eq!(
        error_kind(&missing_suppress_prefix),
        RuleEventDecodeErrorKind::MissingSuppressPrefixLength
    );

    let missing_protocol = raw_rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[
            (FRA_TABLE, &table),
            (FRA_SUPPRESS_PREFIXLEN, &suppress_prefix),
        ],
    );
    assert_eq!(
        error_kind(&missing_protocol),
        RuleEventDecodeErrorKind::MissingProtocol
    );
}

#[test]
fn extended_and_compact_rule_tables_must_agree_with_the_header() {
    let compact = 100_u32.to_ne_bytes();
    let mismatch = rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        101,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[(FRA_TABLE, &compact)],
    );
    assert_eq!(
        error_kind(&mismatch),
        RuleEventDecodeErrorKind::InconsistentTable
    );

    let extended = 256_u32.to_ne_bytes();
    let wrong_header = rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[(FRA_TABLE, &extended)],
    );
    assert_eq!(
        error_kind(&wrong_header),
        RuleEventDecodeErrorKind::InconsistentTable
    );

    let decoded = decoder(true)
        .decode_datagram(&rule_message(
            RTM_NEWRULE,
            0,
            1,
            AF_INET as u8,
            0,
            0,
            0,
            RT_TABLE_COMPAT,
            0,
            0,
            RuleAction::TO_TABLE.raw(),
            0,
            &[(FRA_TABLE, &1_024_u32.to_ne_bytes())],
        ))
        .expect("valid extended table");
    assert_eq!(
        decoded.events()[0].record().properties().table().get(),
        1_024
    );
}

#[test]
fn interface_names_require_one_terminal_nul_and_kernel_width() {
    let cases: &[(u16, &[u8], RuleEventDecodeErrorKind)] = &[
        (
            FRA_IIFNAME,
            b"",
            RuleEventDecodeErrorKind::InvalidInputInterfaceName,
        ),
        (
            FRA_IIFNAME,
            b"\0",
            RuleEventDecodeErrorKind::InvalidInputInterfaceName,
        ),
        (
            FRA_IIFNAME,
            b"lo",
            RuleEventDecodeErrorKind::InvalidInputInterfaceName,
        ),
        (
            FRA_IIFNAME,
            b"l\0o\0",
            RuleEventDecodeErrorKind::InvalidInputInterfaceName,
        ),
        (
            FRA_IIFNAME,
            b"1234567890123456\0",
            RuleEventDecodeErrorKind::InvalidInputInterfaceName,
        ),
        (
            FRA_OIFNAME,
            b"\0",
            RuleEventDecodeErrorKind::InvalidOutputInterfaceName,
        ),
    ];
    for (attribute_type, value, expected) in cases {
        assert_eq!(
            error_kind(&basic_rule(&[(*attribute_type, *value)])),
            *expected
        );
    }

    let maximum = b"123456789012345\0";
    let decoded = decoder(true)
        .decode_datagram(&basic_rule(&[(FRA_IIFNAME, maximum)]))
        .expect("15-byte interface name");
    assert_eq!(
        decoded.events()[0]
            .record()
            .input_interface()
            .unwrap()
            .as_bytes(),
        b"123456789012345"
    );
}

#[test]
fn action_goto_tos_and_l3mdev_invariants_are_strict() {
    let goto_without_target = rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        RuleAction::GOTO.raw(),
        0,
        &[],
    );
    assert_eq!(
        error_kind(&goto_without_target),
        RuleEventDecodeErrorKind::MissingGotoTarget
    );

    let target = 20_u32.to_ne_bytes();
    assert_eq!(
        error_kind(&basic_rule(&[(FRA_GOTO, &target)])),
        RuleEventDecodeErrorKind::UnexpectedGotoTarget
    );
    assert_eq!(
        error_kind(&rule_message(
            RTM_NEWRULE,
            0,
            1,
            AF_INET as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            RuleAction::GOTO.raw(),
            0,
            &[(FRA_PRIORITY, &20_u32.to_ne_bytes()), (FRA_GOTO, &target)],
        )),
        RuleEventDecodeErrorKind::BackwardGoto
    );
    assert_eq!(
        error_kind(&rule_message(
            RTM_NEWRULE,
            0,
            1,
            AF_INET as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            RuleAction::GOTO.raw(),
            0,
            &[(FRA_GOTO, &0_u32.to_ne_bytes())],
        )),
        RuleEventDecodeErrorKind::InvalidGotoTarget
    );

    let unknown_action = rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        0xfb,
        0,
        &[],
    );
    assert_eq!(
        decoder(true)
            .decode_datagram(&unknown_action)
            .expect("raw unknown action")
            .events()[0]
            .record()
            .properties()
            .action()
            .raw(),
        0xfb
    );

    let invalid_tos = rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        1,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[],
    );
    assert_eq!(
        error_kind(&invalid_tos),
        RuleEventDecodeErrorKind::InvalidIpv4Tos
    );

    for invalid in [0_u8, 2] {
        assert_eq!(
            error_kind(&rule_message(
                RTM_NEWRULE,
                0,
                1,
                AF_INET as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                RuleAction::TO_TABLE.raw(),
                0,
                &[(FRA_L3MDEV, &[invalid])],
            )),
            RuleEventDecodeErrorKind::InvalidL3mdev
        );
    }
    let conflict = basic_rule(&[(FRA_L3MDEV, &[1])]);
    assert_eq!(
        error_kind(&conflict),
        RuleEventDecodeErrorKind::L3mdevTableConflict
    );
    let l3mdev = rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[(FRA_L3MDEV, &[1])],
    );
    assert!(
        decoder(true)
            .decode_datagram(&l3mdev)
            .expect("table-zero l3mdev rule")
            .events()[0]
            .record()
            .l3mdev()
    );
}

#[test]
fn flow_is_strict_for_ipv4_and_framing_only_for_ipv6() {
    assert_eq!(
        error_kind(&basic_rule(&[(FRA_FLOW, &[0; 3])])),
        RuleEventDecodeErrorKind::InvalidFlowLength
    );
    assert_eq!(
        error_kind(&basic_rule(&[(FRA_FLOW, &0_u32.to_ne_bytes())])),
        RuleEventDecodeErrorKind::InvalidFlowId
    );
    assert_eq!(
        error_kind(&basic_rule(&[(
            FRA_FLOW | NLA_F_NESTED,
            &1_u32.to_ne_bytes()
        )])),
        RuleEventDecodeErrorKind::InvalidAttributeFlags
    );

    let ipv6 = rule_message(
        RTM_NEWRULE,
        0,
        1,
        AF_INET6 as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        &[
            (FRA_FLOW | NLA_F_NET_BYTEORDER, &[1]),
            (FRA_FLOW | NLA_F_NESTED, &[1, 2, 3, 4, 5]),
        ],
    );
    let decoded = decoder(true)
        .decode_datagram(&ipv6)
        .expect("IPv6 liberal FRA_FLOW policy");
    let record = decoded.events()[0].record();
    assert!(record.flow().is_none());
    assert!(record.has_complete_attribute_coverage());
}

#[test]
fn tunnel_id_is_plain_big_endian_and_padding_is_repeatable() {
    let value = 0x1122_3344_5566_7788_u64.to_be_bytes();
    let decoded = decoder(true)
        .decode_datagram(&basic_rule(&[
            (FRA_PAD, &[]),
            (FRA_PAD, &[]),
            (FRA_TUN_ID, &value),
        ]))
        .expect("plain big-endian tunnel ID");
    assert_eq!(
        decoded.events()[0].record().tunnel_id().unwrap().get(),
        0x1122_3344_5566_7788
    );

    assert_eq!(
        error_kind(&basic_rule(&[(FRA_TUN_ID, &[0; 7])])),
        RuleEventDecodeErrorKind::InvalidTunnelIdLength
    );
    assert_eq!(
        error_kind(&basic_rule(&[(FRA_TUN_ID, &0_u64.to_be_bytes())])),
        RuleEventDecodeErrorKind::InvalidTunnelId
    );
    assert_eq!(
        error_kind(&basic_rule(&[(FRA_TUN_ID | NLA_F_NET_BYTEORDER, &value)])),
        RuleEventDecodeErrorKind::InvalidAttributeFlags
    );
    assert_eq!(
        error_kind(&basic_rule(&[(FRA_PAD, &[0])])),
        RuleEventDecodeErrorKind::InvalidPaddingLength
    );
}

#[test]
fn scalar_widths_flags_duplicates_and_future_attributes_are_strict() {
    let cases: &[(u16, &[u8], RuleEventDecodeErrorKind)] = &[
        (
            FRA_GOTO,
            &[0; 3],
            RuleEventDecodeErrorKind::InvalidGotoLength,
        ),
        (
            FRA_PRIORITY,
            &[0; 3],
            RuleEventDecodeErrorKind::InvalidPriorityLength,
        ),
        (
            FRA_FWMARK,
            &[0; 3],
            RuleEventDecodeErrorKind::InvalidFwmarkLength,
        ),
        (
            FRA_FWMASK,
            &[0; 3],
            RuleEventDecodeErrorKind::InvalidFwmaskLength,
        ),
        (
            FRA_TABLE,
            &[0; 3],
            RuleEventDecodeErrorKind::InvalidTableLength,
        ),
        (
            FRA_SUPPRESS_IFGROUP,
            &[0; 3],
            RuleEventDecodeErrorKind::InvalidSuppressInterfaceGroupLength,
        ),
        (
            FRA_SUPPRESS_PREFIXLEN,
            &[0; 3],
            RuleEventDecodeErrorKind::InvalidSuppressPrefixLengthLength,
        ),
        (
            FRA_L3MDEV,
            &[0; 2],
            RuleEventDecodeErrorKind::InvalidL3mdevLength,
        ),
        (
            FRA_UID_RANGE,
            &[0; 7],
            RuleEventDecodeErrorKind::InvalidUidRangeLength,
        ),
        (
            FRA_PROTOCOL,
            &[0; 2],
            RuleEventDecodeErrorKind::InvalidProtocolLength,
        ),
        (
            FRA_IP_PROTO,
            &[0; 2],
            RuleEventDecodeErrorKind::InvalidIpProtocolLength,
        ),
        (
            FRA_SPORT_RANGE,
            &[0; 3],
            RuleEventDecodeErrorKind::InvalidSourcePortRangeLength,
        ),
        (
            FRA_DPORT_RANGE,
            &[0; 3],
            RuleEventDecodeErrorKind::InvalidDestinationPortRangeLength,
        ),
    ];
    for (attribute_type, value, expected) in cases {
        assert_eq!(
            error_kind(&basic_rule(&[(*attribute_type, *value)])),
            *expected
        );
    }

    let scalar = 1_u32.to_ne_bytes();
    for attribute_type in [FRA_PRIORITY, FRA_FWMARK, FRA_TABLE, FRA_FWMASK] {
        assert_eq!(
            error_kind(&basic_rule(&[(attribute_type | NLA_F_NESTED, &scalar)])),
            RuleEventDecodeErrorKind::InvalidAttributeFlags
        );
    }
    assert_eq!(
        error_kind(&basic_rule(&[
            (FRA_PRIORITY, &scalar),
            (FRA_PRIORITY, &scalar)
        ])),
        RuleEventDecodeErrorKind::DuplicateSemanticAttribute
    );

    let future_type = FRA_DPORT_RANGE + 1;
    let decoded = decoder(true)
        .decode_datagram(&basic_rule(&[
            (future_type | NLA_F_NESTED, &[0xde, 0xad, 0xbe]),
            (future_type | NLA_F_NET_BYTEORDER, &[1]),
        ]))
        .expect("well-framed future attributes remain forward compatible");
    assert_eq!(decoded.events().len(), 1);
    let opacity = decoded.events()[0]
        .record()
        .attribute_coverage()
        .opacity()
        .expect("future attributes make the rule semantically opaque");
    assert_eq!(
        opacity.retained_details(),
        &[
            OpaqueRuleAttribute::new(future_type, NLA_F_NESTED, 3),
            OpaqueRuleAttribute::new(future_type, NLA_F_NET_BYTEORDER, 1),
        ]
    );
    assert_eq!(opacity.omitted_details(), 0);
    assert_eq!(opacity.total_attributes(), 2);
    let original_fingerprint = opacity.fingerprint();

    let changed_payload = decoder(true)
        .decode_datagram(&basic_rule(&[
            (future_type | NLA_F_NESTED, &[0xde, 0xad, 0xbf]),
            (future_type | NLA_F_NET_BYTEORDER, &[1]),
        ]))
        .expect("changed opaque payload remains observable");
    assert_ne!(
        changed_payload.events()[0]
            .record()
            .attribute_coverage()
            .opacity()
            .unwrap()
            .fingerprint(),
        original_fingerprint
    );

    let reversed = decoder(true)
        .decode_datagram(&basic_rule(&[
            (future_type | NLA_F_NET_BYTEORDER, &[1]),
            (future_type | NLA_F_NESTED, &[0xde, 0xad, 0xbe]),
        ]))
        .expect("opaque attribute order remains observable");
    assert_ne!(
        reversed.events()[0]
            .record()
            .attribute_coverage()
            .opacity()
            .unwrap()
            .fingerprint(),
        original_fingerprint
    );

    let many = vec![(future_type, b"x".as_slice()); MAX_OPAQUE_RULE_ATTRIBUTE_DETAILS + 3];
    let bounded = decoder(true)
        .decode_datagram(&basic_rule(&many))
        .expect("many future attributes remain bounded");
    let bounded_opacity = bounded.events()[0]
        .record()
        .attribute_coverage()
        .opacity()
        .unwrap();
    assert_eq!(
        bounded_opacity.retained_details().len(),
        MAX_OPAQUE_RULE_ATTRIBUTE_DETAILS
    );
    assert_eq!(bounded_opacity.omitted_details(), 3);
    assert_eq!(
        bounded_opacity.total_attributes(),
        u32::try_from(MAX_OPAQUE_RULE_ATTRIBUTE_DETAILS + 3).unwrap()
    );

    let bounded_fingerprint = bounded_opacity.fingerprint();
    let mut changed_omitted = many;
    *changed_omitted.last_mut().expect("opaque attributes") = (future_type, b"y".as_slice());
    let changed_bounded = decoder(true)
        .decode_datagram(&basic_rule(&changed_omitted))
        .expect("an omitted opaque payload remains part of change detection");
    let changed_bounded_opacity = changed_bounded.events()[0]
        .record()
        .attribute_coverage()
        .opacity()
        .unwrap();
    assert_eq!(
        changed_bounded_opacity.retained_details(),
        bounded_opacity.retained_details()
    );
    assert_eq!(
        changed_bounded_opacity.omitted_details(),
        bounded_opacity.omitted_details()
    );
    assert_ne!(changed_bounded_opacity.fingerprint(), bounded_fingerprint);
}

#[test]
fn uid_port_and_ip_protocol_values_follow_linux_5_10_domains() {
    for value in [range_u32(2, 1), range_u32(u32::MAX, u32::MAX)] {
        assert_eq!(
            error_kind(&basic_rule(&[(FRA_UID_RANGE, &value)])),
            RuleEventDecodeErrorKind::InvalidUidRange
        );
    }
    for value in [
        range_u16(0, 1),
        range_u16(1, 0),
        range_u16(2, 1),
        range_u16(1, u16::MAX),
    ] {
        assert_eq!(
            error_kind(&basic_rule(&[(FRA_DPORT_RANGE, &value)])),
            RuleEventDecodeErrorKind::InvalidPortRange
        );
    }
    assert_eq!(
        error_kind(&basic_rule(&[(FRA_IP_PROTO, &[0])])),
        RuleEventDecodeErrorKind::InvalidIpProtocol
    );

    assert_eq!(
        error_kind(&basic_rule(&[(FRA_FWMARK, &0x55_u32.to_ne_bytes())])),
        RuleEventDecodeErrorKind::MissingFwmask
    );

    let inert_mark = decoder(true)
        .decode_datagram(&basic_rule(&[
            (FRA_FWMARK, &0x55_u32.to_ne_bytes()),
            (FRA_FWMASK, &0_u32.to_ne_bytes()),
        ]))
        .expect("zero mask canonicalizes the selector away");
    assert!(inert_mark.events()[0].record().fwmark().is_none());
}

#[test]
fn future_port_masks_preserve_known_range_facts_but_make_the_projection_opaque() {
    // Linux added FRA_SPORT_MASK after the Android 5.10 attribute set modeled here.
    const FRA_SPORT_MASK_FUTURE: u16 = 28;
    let source_ports = range_u16(1_024, 2_048);
    let source_mask = 0xfff0_u16.to_ne_bytes();
    let decoded = decoder(true)
        .decode_datagram(&basic_rule(&[
            (FRA_SPORT_RANGE, &source_ports),
            (FRA_SPORT_MASK_FUTURE, &source_mask),
        ]))
        .expect("future port-mask selector remains observable");
    let record = decoded.events()[0].record();
    let range = record
        .source_port_range()
        .expect("known source-port range remains decoded");
    assert_eq!((range.start(), range.end()), (1_024, 2_048));
    assert_eq!(
        record
            .attribute_coverage()
            .opacity()
            .expect("unmodeled mask blocks semantic completeness")
            .retained_details(),
        &[OpaqueRuleAttribute::new(FRA_SPORT_MASK_FUTURE, 0, 2)]
    );
}

#[test]
fn whole_datagram_loss_and_transaction_metadata_are_strict() {
    let first = basic_rule_with_sequence(1, &[]);
    let second = basic_rule_with_sequence(2, &[]);
    assert_eq!(
        error_kind(&concatenate(&[&first, &second])),
        RuleEventDecodeErrorKind::MixedSequence
    );

    for (message_type, expected) in [
        (NLMSG_ERROR, RuleEventDecodeErrorKind::NetlinkError),
        (NLMSG_OVERRUN, RuleEventDecodeErrorKind::NetlinkOverrun),
    ] {
        assert_eq!(
            error_kind(&netlink_message(message_type, 0, 1, 0, &[])),
            expected
        );
    }

    let interrupted = netlink_message(RTM_NEWLINK, NLM_F_DUMP_INTR, 1, 0, &[]);
    assert_eq!(
        error_kind(&interrupted),
        RuleEventDecodeErrorKind::InterruptedDump
    );

    let done = netlink_message(NLMSG_DONE, 0, 7, 0, &[]);
    let decoded = decoder(true)
        .decode_datagram(&done)
        .expect("empty successful DONE");
    assert_eq!(decoded.sequence(), Some(7));
    assert!(decoded.completion().is_some());

    let mut extended_ack = 0_i32.to_ne_bytes().to_vec();
    append_attribute(&mut extended_ack, 1, b"diagnostic\0");
    decoder(true)
        .decode_datagram(&netlink_message(
            NLMSG_DONE,
            NLM_F_ACK_TLVS,
            7,
            0,
            &extended_ack,
        ))
        .expect("valid extended-ack DONE");

    assert_eq!(
        error_kind(&netlink_message(
            NLMSG_DONE,
            0,
            7,
            0,
            &(-5_i32).to_ne_bytes(),
        )),
        RuleEventDecodeErrorKind::DoneErrorStatus
    );
    assert_eq!(
        error_kind(&netlink_message(NLMSG_DONE, 0, 7, 0, &[0])),
        RuleEventDecodeErrorKind::InvalidDonePayload
    );
    assert_eq!(
        error_kind(&concatenate(&[&done, &done])),
        RuleEventDecodeErrorKind::DuplicateDone
    );
    assert_eq!(
        error_kind(&concatenate(&[&done, &basic_rule_with_sequence(7, &[])])),
        RuleEventDecodeErrorKind::MessageAfterDone
    );
}

#[test]
fn framing_failures_are_reported_without_partial_events() {
    let valid = basic_rule(&[]);
    for length in 1..NETLINK_HEADER_LENGTH {
        assert_eq!(
            error_kind(&valid[..length]),
            RuleEventDecodeErrorKind::TruncatedHeader
        );
    }

    let mut truncated_rule = rule_payload(
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
    );
    truncated_rule.pop();
    assert_eq!(
        error_kind(&netlink_message(RTM_NEWRULE, 0, 1, 0, &truncated_rule)),
        RuleEventDecodeErrorKind::TruncatedRuleMessage
    );

    let mut malformed = valid;
    malformed.extend_from_slice(&[1, 2, 3]);
    assert_eq!(
        error_kind(&malformed),
        RuleEventDecodeErrorKind::TruncatedHeader
    );
}

#[test]
fn message_and_attribute_lengths_padding_and_flag_bits_are_strict() {
    let mut invalid_message_length = basic_rule(&[]);
    invalid_message_length[..4].copy_from_slice(&15_u32.to_ne_bytes());
    assert_eq!(
        error_kind(&invalid_message_length),
        RuleEventDecodeErrorKind::InvalidMessageLength
    );

    let mut missing_message_padding = netlink_message(RTM_NEWLINK, 0, 1, 0, &[1]);
    missing_message_padding.truncate(NETLINK_HEADER_LENGTH + 1);
    assert_eq!(
        error_kind(&missing_message_padding),
        RuleEventDecodeErrorKind::MissingMessagePadding
    );

    let mut invalid_attribute = rule_payload(
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
    );
    invalid_attribute.extend_from_slice(&3_u16.to_ne_bytes());
    invalid_attribute.extend_from_slice(&FRA_PRIORITY.to_ne_bytes());
    assert_eq!(
        error_kind(&netlink_message(RTM_NEWRULE, 0, 1, 0, &invalid_attribute,)),
        RuleEventDecodeErrorKind::InvalidAttributeLength
    );

    let mut missing_attribute_padding = rule_payload(
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
    );
    missing_attribute_padding.extend_from_slice(&5_u16.to_ne_bytes());
    missing_attribute_padding.extend_from_slice(&FRA_PROTOCOL.to_ne_bytes());
    missing_attribute_padding.push(1);
    assert_eq!(
        error_kind(&netlink_message(
            RTM_NEWRULE,
            0,
            1,
            0,
            &missing_attribute_padding,
        )),
        RuleEventDecodeErrorKind::MissingAttributePadding
    );

    assert_eq!(
        error_kind(&basic_rule(&[(
            FRA_PRIORITY | NLA_F_NESTED | NLA_F_NET_BYTEORDER,
            &1_u32.to_ne_bytes(),
        )])),
        RuleEventDecodeErrorKind::InvalidAttributeFlags
    );
}

#[test]
fn unrelated_messages_are_ignored_but_keep_compatible_metadata() {
    let unrelated = netlink_message(RTM_NEWLINK, 0, 55, 99, &[1, 2, 3, 4]);
    let decoded = decoder(true)
        .decode_datagram(&unrelated)
        .expect("well-framed unrelated rtnetlink message");
    assert_eq!(decoded.sequence(), Some(55));
    assert!(decoded.events().is_empty());
    assert!(decoded.completion().is_none());

    let rule = basic_rule_with_sequence(55, &[]);
    let done = netlink_message(NLMSG_DONE, 0, 55, 99, &[]);
    let decoded = decoder(true)
        .decode_datagram(&concatenate(&[&unrelated, &rule, &done]))
        .expect("mixed compatible transaction datagram");
    assert_eq!(decoded.events().len(), 1);
    assert_eq!(decoded.sequence(), Some(55));
    assert_eq!(decoded.completion().unwrap().port_id(), 99);
}

#[test]
fn deterministic_arbitrary_datagrams_never_panic() {
    const CASES: usize = 4_096;
    const MAX_LENGTH: usize = 768;

    let decoder = decoder(true);
    let mut state = 0x91c7_eb27_a103_6d4f_u64;
    for case in 0..CASES {
        let length = (next_random(&mut state) as usize) % (MAX_LENGTH + 1);
        let mut datagram = vec![0_u8; length];
        for byte in &mut datagram {
            *byte = next_random(&mut state) as u8;
        }
        let outcome = std::panic::catch_unwind(|| decoder.decode_datagram(&datagram));
        assert!(
            outcome.is_ok(),
            "decoder panicked for deterministic case {case}"
        );
    }
}

#[test]
fn complex_rule_prefixes_and_structured_mutations_are_atomic_and_panic_free() {
    let fixture = complex_rule_fixture();
    let declared_length = usize::try_from(u32::from_ne_bytes(
        fixture[..4].try_into().expect("netlink length field"),
    ))
    .expect("netlink length fits usize");
    assert_eq!(declared_length, fixture.len());

    let decoded = decoder(true)
        .decode_datagram(&fixture)
        .expect("complete complex rule fixture");
    assert_eq!(decoded.events().len(), 1);

    for prefix_length in 0..fixture.len() {
        let mut prefix = fixture[..prefix_length].to_vec();
        if prefix_length >= NETLINK_HEADER_LENGTH {
            prefix[..4].copy_from_slice(
                &u32::try_from(prefix_length)
                    .expect("fixture prefix length fits u32")
                    .to_ne_bytes(),
            );
            prefix.resize(align4(prefix_length), 0);
        }

        let outcome = std::panic::catch_unwind(|| decoder(true).decode_datagram(&prefix));
        assert!(
            outcome.is_ok(),
            "decoder panicked for complex fixture prefix {prefix_length}"
        );
        if let Ok(decoded) = outcome.expect("panic outcome checked") {
            assert!(
                decoded.events().is_empty(),
                "truncated complex fixture emitted an event at {prefix_length}"
            );
        }
    }

    let mut state = 0xd7b3_a41e_3d84_6f21_u64;
    let mut accepted = 0;
    let mut rejected = 0;
    for offset in NETLINK_HEADER_LENGTH..declared_length {
        let mut mutated = fixture.clone();
        mutated[offset] ^= (next_random(&mut state) as u8) | 1;

        let outcome = std::panic::catch_unwind(|| decoder(true).decode_datagram(&mutated));
        assert!(
            outcome.is_ok(),
            "decoder panicked after mutating complex fixture byte {offset}"
        );
        match outcome.expect("panic outcome checked") {
            Ok(decoded) => {
                assert_eq!(decoded.sequence(), Some(73));
                assert!(decoded.completion().is_none());
                assert!(decoded.events().len() <= 1);
                accepted += 1;
            }
            Err(error) => {
                assert!(!matches!(
                    error.kind(),
                    RuleEventDecodeErrorKind::TruncatedHeader
                        | RuleEventDecodeErrorKind::InvalidMessageLength
                        | RuleEventDecodeErrorKind::MissingMessagePadding
                ));
                rejected += 1;
            }
        }
    }
    assert!(
        accepted > 0,
        "structured mutations should retain valid rules"
    );
    assert!(
        rejected > 0,
        "structured mutations should reach strict decoders"
    );
}

fn decoder(include_ipv6: bool) -> RtnetlinkRuleEventDecoder {
    RtnetlinkRuleEventDecoder::new(include_ipv6)
}

fn error_kind(datagram: &[u8]) -> RuleEventDecodeErrorKind {
    decoder(true)
        .decode_datagram(datagram)
        .expect_err("expected rule decode failure")
        .kind()
}

fn basic_rule(attributes: &[(u16, &[u8])]) -> Vec<u8> {
    basic_rule_with_sequence(1, attributes)
}

fn basic_rule_with_sequence(sequence: u32, attributes: &[(u16, &[u8])]) -> Vec<u8> {
    rule_message(
        RTM_NEWRULE,
        0,
        sequence,
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0,
        attributes,
    )
}

fn complex_rule_fixture() -> Vec<u8> {
    let destination = Ipv4Addr::new(203, 0, 113, 29).octets();
    let source = Ipv4Addr::new(198, 51, 100, 231).octets();
    let table = 1_024_u32.to_ne_bytes();
    let priority = 321_u32.to_ne_bytes();
    let fwmark = 0xa5a5_1234_u32.to_ne_bytes();
    let fwmask = 0xffff_00ff_u32.to_ne_bytes();
    let tunnel_id = 0x0102_0304_0506_0708_u64.to_be_bytes();
    let uid_range = range_u32(10_000, 19_999);
    let source_ports = range_u16(1_024, 4_096);
    let destination_ports = range_u16(8_000, 9_000);

    rule_message(
        RTM_NEWRULE,
        NLM_F_REPLACE,
        73,
        AF_INET as u8,
        24,
        24,
        0x1e,
        RT_TABLE_COMPAT,
        0,
        0,
        RuleAction::TO_TABLE.raw(),
        0x8001_001a,
        &[
            (FRA_SRC, source.as_slice()),
            (FRA_TABLE, table.as_slice()),
            (FRA_PRIORITY, priority.as_slice()),
            (FRA_FWMARK, fwmark.as_slice()),
            (FRA_FWMASK, fwmask.as_slice()),
            (FRA_IIFNAME, b"wlan0\0"),
            (FRA_OIFNAME, b"rmnet0\0"),
            (FRA_PAD, &[]),
            (FRA_TUN_ID, tunnel_id.as_slice()),
            (FRA_UID_RANGE, uid_range.as_slice()),
            (FRA_IP_PROTO, &[6]),
            (FRA_SPORT_RANGE, source_ports.as_slice()),
            (FRA_DPORT_RANGE, destination_ports.as_slice()),
            (FRA_PROTOCOL, &[99]),
            // Keep the required destination prefix last so no proper prefix
            // can form a semantically complete rule event.
            (FRA_DST, destination.as_slice()),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn rule_message(
    message_type: u16,
    message_flags: u16,
    sequence: u32,
    family: u8,
    destination_length: u8,
    source_length: u8,
    tos: u8,
    table: u8,
    reserved_one: u8,
    reserved_two: u8,
    action: u8,
    rule_flags: u32,
    attributes: &[(u16, &[u8])],
) -> Vec<u8> {
    let mut payload = rule_payload(
        family,
        destination_length,
        source_length,
        tos,
        table,
        reserved_one,
        reserved_two,
        action,
        rule_flags,
    );
    for (attribute_type, value) in attributes {
        append_attribute(&mut payload, *attribute_type, value);
    }
    if !attributes
        .iter()
        .any(|(attribute_type, _)| attribute_type & NLA_TYPE_MASK == FRA_TABLE)
    {
        append_attribute(&mut payload, FRA_TABLE, &u32::from(table).to_ne_bytes());
    }
    if !attributes
        .iter()
        .any(|(attribute_type, _)| attribute_type & NLA_TYPE_MASK == FRA_SUPPRESS_PREFIXLEN)
    {
        append_attribute(
            &mut payload,
            FRA_SUPPRESS_PREFIXLEN,
            &u32::MAX.to_ne_bytes(),
        );
    }
    if !attributes
        .iter()
        .any(|(attribute_type, _)| attribute_type & NLA_TYPE_MASK == FRA_PROTOCOL)
    {
        append_attribute(&mut payload, FRA_PROTOCOL, &[0]);
    }
    netlink_message(message_type, message_flags, sequence, 0, &payload)
}

#[allow(clippy::too_many_arguments)]
fn raw_rule_message(
    message_type: u16,
    message_flags: u16,
    sequence: u32,
    family: u8,
    destination_length: u8,
    source_length: u8,
    tos: u8,
    table: u8,
    reserved_one: u8,
    reserved_two: u8,
    action: u8,
    rule_flags: u32,
    attributes: &[(u16, &[u8])],
) -> Vec<u8> {
    let mut payload = rule_payload(
        family,
        destination_length,
        source_length,
        tos,
        table,
        reserved_one,
        reserved_two,
        action,
        rule_flags,
    );
    for (attribute_type, value) in attributes {
        append_attribute(&mut payload, *attribute_type, value);
    }
    netlink_message(message_type, message_flags, sequence, 0, &payload)
}

#[allow(clippy::too_many_arguments)]
fn rule_payload(
    family: u8,
    destination_length: u8,
    source_length: u8,
    tos: u8,
    table: u8,
    reserved_one: u8,
    reserved_two: u8,
    action: u8,
    rule_flags: u32,
) -> Vec<u8> {
    let mut payload = vec![
        family,
        destination_length,
        source_length,
        tos,
        table,
        reserved_one,
        reserved_two,
        action,
    ];
    payload.extend_from_slice(&rule_flags.to_ne_bytes());
    payload
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
    message.resize(align4(message.len()), 0);
    message
}

fn append_attribute(message: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
    let attribute_length = NETLINK_ATTRIBUTE_HEADER_LENGTH + value.len();
    let encoded_length = u16::try_from(attribute_length).expect("test attribute length fits u16");
    message.extend_from_slice(&encoded_length.to_ne_bytes());
    message.extend_from_slice(&attribute_type.to_ne_bytes());
    message.extend_from_slice(value);
    message.resize(align4(message.len()), 0);
}

fn range_u32(start: u32, end: u32) -> Vec<u8> {
    let mut value = start.to_ne_bytes().to_vec();
    value.extend_from_slice(&end.to_ne_bytes());
    value
}

fn range_u16(start: u16, end: u16) -> Vec<u8> {
    let mut value = start.to_ne_bytes().to_vec();
    value.extend_from_slice(&end.to_ne_bytes());
    value
}

fn concatenate(parts: &[&[u8]]) -> Vec<u8> {
    let mut joined = Vec::new();
    for part in parts {
        joined.extend_from_slice(part);
    }
    joined
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
