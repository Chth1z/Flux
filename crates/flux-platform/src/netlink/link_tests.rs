use super::super::{NETLINK_ATTRIBUTE_HEADER_LENGTH, NLM_F_ACK_TLVS};
use super::*;

const AF_BRIDGE: u8 = 7;

#[test]
fn link_decoder_constructs_a_complete_canonical_record() {
    let link_info = nested_attributes(&[(IFLA_INFO_KIND, &[b't', b'u', 0xfe, 0])]);
    let datagram = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        0xfffe,
        7,
        InterfaceLinkFlags::UP.bits() | InterfaceLinkFlags::LOWER_UP.bits() | 0x8000_0000,
        0xffff_0000,
        &[
            (IFLA_IFNAME, b"tun0\0"),
            (IFLA_MTU, &9_000_u32.to_ne_bytes()),
            (IFLA_OPERSTATE, &[0xfe]),
            (IFLA_CARRIER, &[1]),
            (IFLA_LINKINFO | NLA_F_NESTED, &link_info),
        ],
    );

    let decoded = decoder()
        .decode_datagram(&datagram)
        .expect("valid rtnetlink link datagram");

    assert_eq!(decoded.sequence(), Some(1));
    assert!(decoded.completion().is_none());
    assert_eq!(decoded.events().len(), 1);
    let event = &decoded.events()[0];
    assert!(matches!(event, InterfaceLinkEvent::Upsert(_)));
    assert_eq!(event.interface_index().get(), 7);
    let record = event.record().expect("upsert record");
    assert_eq!(record.name().as_bytes(), b"tun0");
    assert_eq!(record.hardware_type().raw(), 0xfffe);
    assert_eq!(record.flags().bits(), 0x8001_0001);
    assert_eq!(record.mtu(), Some(9_000));
    assert_eq!(
        record.operational_state(),
        Some(InterfaceOperationalState::from_raw(0xfe))
    );
    assert_eq!(record.carrier(), Some(true));
    assert_eq!(
        record.kind().expect("link kind").as_bytes(),
        &[b't', b'u', 0xfe]
    );
}

#[test]
fn minimal_link_update_leaves_optional_facts_absent() {
    let datagram = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        0,
        7,
        0,
        u32::MAX,
        &[(IFLA_IFNAME, b"eth0\0")],
    );

    let decoded = decoder()
        .decode_datagram(&datagram)
        .expect("minimal link update");
    let record = decoded.events()[0].record().expect("upsert record");

    assert_eq!(record.mtu(), None);
    assert_eq!(record.operational_state(), None);
    assert_eq!(record.carrier(), None);
    assert_eq!(record.kind(), None);
}

#[test]
fn delete_event_needs_only_a_valid_index() {
    let datagram = link_message(RTM_DELLINK, AF_UNSPEC, 0, 11, 0, 0x1234_5678, &[]);

    let decoded = decoder()
        .decode_datagram(&datagram)
        .expect("valid delete notification");
    let event = &decoded.events()[0];

    assert!(matches!(event, InterfaceLinkEvent::Remove(_)));
    assert_eq!(event.interface_index().get(), 11);
    assert_eq!(event.record(), None);
}

#[test]
fn delete_event_still_rejects_malformed_or_duplicate_recognized_attributes() {
    let malformed = link_message(RTM_DELLINK, AF_UNSPEC, 0, 11, 0, 0, &[(IFLA_MTU, &[0; 3])]);
    let error = decoder()
        .decode_datagram(&malformed)
        .expect_err("malformed delete attribute");
    assert_eq!(error.kind(), LinkEventDecodeErrorKind::InvalidMtuLength);
    assert_eq!(error.offset(), 36);

    let duplicate = link_message(
        RTM_DELLINK,
        AF_UNSPEC,
        0,
        11,
        0,
        0,
        &[(IFLA_IFNAME, b"eth0\0"), (IFLA_IFNAME, b"eth0\0")],
    );
    assert_eq!(
        decoder()
            .decode_datagram(&duplicate)
            .expect_err("duplicate delete attribute")
            .kind(),
        LinkEventDecodeErrorKind::DuplicateSemanticAttribute
    );
}

#[test]
fn non_unspecified_link_families_are_structurally_validated_then_ignored() {
    let datagram = link_message(
        RTM_NEWLINK,
        AF_BRIDGE,
        0,
        7,
        0,
        0,
        &[(IFLA_IFNAME, b"bridge-view\0")],
    );
    let decoded = decoder()
        .decode_datagram(&datagram)
        .expect("well-framed AF_BRIDGE notification");
    assert!(decoded.events().is_empty());

    let mut malformed = datagram;
    malformed.pop();
    let error = decoder()
        .decode_datagram(&malformed)
        .expect_err("family-specific messages still require complete framing");
    assert!(matches!(
        error.kind(),
        LinkEventDecodeErrorKind::InvalidMessageLength
            | LinkEventDecodeErrorKind::MissingMessagePadding
    ));
}

#[test]
fn interface_index_must_fit_the_positive_kernel_int_domain() {
    for invalid in [0, -1, i32::MIN] {
        let datagram = link_message(
            RTM_NEWLINK,
            AF_UNSPEC,
            0,
            invalid,
            0,
            0,
            &[(IFLA_IFNAME, b"eth0\0")],
        );
        let error = decoder()
            .decode_datagram(&datagram)
            .expect_err("invalid ifinfomsg index");
        assert_eq!(
            error.kind(),
            LinkEventDecodeErrorKind::InvalidInterfaceIndex
        );
    }
}

#[test]
fn interface_name_is_required_and_strictly_nul_terminated() {
    let invalid_names: &[&[u8]] = &[b"", b"\0", b"eth0", b"eth\0zero\0", b"1234567890123456\0"];
    for name in invalid_names {
        let datagram = link_message(RTM_NEWLINK, AF_UNSPEC, 0, 7, 0, 0, &[(IFLA_IFNAME, name)]);
        let error = decoder()
            .decode_datagram(&datagram)
            .expect_err("invalid interface name");
        assert_eq!(error.kind(), LinkEventDecodeErrorKind::InvalidInterfaceName);
    }

    let missing = link_message(RTM_NEWLINK, AF_UNSPEC, 0, 7, 0, 0, &[]);
    assert_eq!(
        decoder()
            .decode_datagram(&missing)
            .expect_err("missing primary name")
            .kind(),
        LinkEventDecodeErrorKind::MissingInterfaceName
    );

    let maximum_non_utf8 = [
        b'r', b'm', b'n', b'e', b't', b'_', b'd', b'a', b't', b'a', b'0', b'_', b'x', b'y', 0xff, 0,
    ];
    let valid = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        0,
        7,
        0,
        0,
        &[(IFLA_IFNAME, &maximum_non_utf8)],
    );
    let decoded = decoder()
        .decode_datagram(&valid)
        .expect("maximum non-UTF8 name");
    let record = decoded.events()[0].record().expect("upsert record");
    assert_eq!(record.name().as_bytes(), &maximum_non_utf8[..15]);
    assert_eq!(record.name().as_str(), None);
}

#[test]
fn recognized_scalar_attributes_require_exact_native_widths() {
    let cases: &[(u16, &[u8], LinkEventDecodeErrorKind)] = &[
        (
            IFLA_MTU,
            &[0; 3],
            LinkEventDecodeErrorKind::InvalidMtuLength,
        ),
        (
            IFLA_OPERSTATE,
            &[0; 2],
            LinkEventDecodeErrorKind::InvalidOperationalStateLength,
        ),
        (
            IFLA_CARRIER,
            &[0; 2],
            LinkEventDecodeErrorKind::InvalidCarrierLength,
        ),
    ];

    for (attribute_type, value, expected) in cases {
        let datagram = link_message(
            RTM_NEWLINK,
            AF_UNSPEC,
            0,
            7,
            0,
            0,
            &[(IFLA_IFNAME, b"eth0\0"), (*attribute_type, value)],
        );
        let error = decoder()
            .decode_datagram(&datagram)
            .expect_err("wrong scalar width");
        assert_eq!(error.kind(), *expected);
    }
}

#[test]
fn carrier_accepts_only_boolean_values() {
    let datagram = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        0,
        7,
        0,
        0,
        &[(IFLA_IFNAME, b"eth0\0"), (IFLA_CARRIER, &[2])],
    );
    assert_eq!(
        decoder()
            .decode_datagram(&datagram)
            .expect_err("invalid carrier value")
            .kind(),
        LinkEventDecodeErrorKind::InvalidCarrierValue
    );
}

#[test]
fn duplicate_recognized_attributes_are_ambiguous_even_when_identical() {
    let scalar = 1_u32.to_ne_bytes();
    let nested = nested_attributes(&[(IFLA_INFO_KIND, b"tun\0")]);
    let cases: &[(u16, &[u8])] = &[
        (IFLA_IFNAME, b"eth0\0"),
        (IFLA_MTU, &scalar),
        (IFLA_OPERSTATE, &[1]),
        (IFLA_CARRIER, &[1]),
        (IFLA_LINKINFO | NLA_F_NESTED, &nested),
    ];
    for (attribute_type, value) in cases {
        let mut attributes = vec![(IFLA_IFNAME, &b"eth0\0"[..])];
        attributes.push((*attribute_type, *value));
        if *attribute_type != IFLA_IFNAME {
            attributes.push((*attribute_type, *value));
        }
        let datagram = link_message(RTM_NEWLINK, AF_UNSPEC, 0, 7, 0, 0, &attributes);
        let error = decoder()
            .decode_datagram(&datagram)
            .expect_err("duplicate semantic attribute");
        assert_eq!(
            error.kind(),
            LinkEventDecodeErrorKind::DuplicateSemanticAttribute
        );
    }
}

#[test]
fn known_plain_attributes_reject_netlink_attribute_flags() {
    for flags in [NLA_F_NESTED, NLA_F_NET_BYTEORDER] {
        let datagram = link_message(
            RTM_NEWLINK,
            AF_UNSPEC,
            0,
            7,
            0,
            0,
            &[(IFLA_IFNAME | flags, b"eth0\0")],
        );
        assert_eq!(
            decoder()
                .decode_datagram(&datagram)
                .expect_err("plain attribute flags are ambiguous")
                .kind(),
            LinkEventDecodeErrorKind::InvalidAttributeFlags
        );
    }

    let unknown = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        0,
        7,
        0,
        0,
        &[
            (IFLA_IFNAME, b"eth0\0"),
            (99 | NLA_F_NESTED | NLA_F_NET_BYTEORDER, b"future"),
        ],
    );
    assert_eq!(
        decoder()
            .decode_datagram(&unknown)
            .expect_err("mutually exclusive flags on unknown attribute")
            .kind(),
        LinkEventDecodeErrorKind::InvalidAttributeFlags
    );
}

#[test]
fn link_info_kind_is_nested_bounded_and_unique() {
    let duplicate = nested_attributes(&[(IFLA_INFO_KIND, b"tun\0"), (IFLA_INFO_KIND, b"tun\0")]);
    let invalid_cases = [
        (
            duplicate,
            LinkEventDecodeErrorKind::DuplicateSemanticAttribute,
        ),
        (
            nested_attributes(&[(IFLA_INFO_KIND, b"unterminated")]),
            LinkEventDecodeErrorKind::InvalidLinkKind,
        ),
        (
            nested_attributes(&[(IFLA_INFO_KIND | NLA_F_NESTED, b"tun\0")]),
            LinkEventDecodeErrorKind::InvalidAttributeFlags,
        ),
    ];
    for (link_info, expected) in invalid_cases {
        let datagram = link_message(
            RTM_NEWLINK,
            AF_UNSPEC,
            0,
            7,
            0,
            0,
            &[
                (IFLA_IFNAME, b"tun0\0"),
                (IFLA_LINKINFO | NLA_F_NESTED, &link_info),
            ],
        );
        assert_eq!(
            decoder()
                .decode_datagram(&datagram)
                .expect_err("invalid nested link kind")
                .kind(),
            expected
        );
    }

    let mut malformed = nested_attributes(&[(IFLA_INFO_KIND, b"tun\0")]);
    malformed.pop();
    let datagram = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        0,
        7,
        0,
        0,
        &[
            (IFLA_IFNAME, b"tun0\0"),
            (IFLA_LINKINFO | NLA_F_NESTED, &malformed),
        ],
    );
    assert!(matches!(
        decoder()
            .decode_datagram(&datagram)
            .expect_err("malformed nested attributes")
            .kind(),
        LinkEventDecodeErrorKind::InvalidAttributeLength
            | LinkEventDecodeErrorKind::MissingAttributePadding
    ));

    for outer_type in [IFLA_LINKINFO, IFLA_LINKINFO | NLA_F_NESTED] {
        let link_info = nested_attributes(&[(IFLA_INFO_KIND, b"tun\0")]);
        let datagram = link_message(
            RTM_NEWLINK,
            AF_UNSPEC,
            0,
            7,
            0,
            0,
            &[(IFLA_IFNAME, b"tun0\0"), (outer_type, &link_info)],
        );
        let decoded = decoder()
            .decode_datagram(&datagram)
            .expect("compatible nested representation");
        let kind = decoded.events()[0]
            .record()
            .expect("upsert record")
            .kind()
            .expect("link kind");
        assert_eq!(kind.as_bytes(), b"tun");
    }

    for outer_type in [
        IFLA_LINKINFO | NLA_F_NET_BYTEORDER,
        IFLA_LINKINFO | NLA_F_NESTED | NLA_F_NET_BYTEORDER,
    ] {
        let link_info = nested_attributes(&[(IFLA_INFO_KIND, b"tun\0")]);
        let datagram = link_message(
            RTM_NEWLINK,
            AF_UNSPEC,
            0,
            7,
            0,
            0,
            &[(IFLA_IFNAME, b"tun0\0"), (outer_type, &link_info)],
        );
        assert_eq!(
            decoder()
                .decode_datagram(&datagram)
                .expect_err("network-byte-order link info")
                .kind(),
            LinkEventDecodeErrorKind::InvalidAttributeFlags
        );
    }

    let link_info = nested_attributes(&[(IFLA_INFO_KIND, b"tu\0n\0")]);
    let datagram = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        0,
        7,
        0,
        0,
        &[
            (IFLA_IFNAME, b"tun0\0"),
            (IFLA_LINKINFO | NLA_F_NESTED, &link_info),
        ],
    );
    assert_eq!(
        decoder()
            .decode_datagram(&datagram)
            .expect_err("embedded-NUL link kind")
            .kind(),
        LinkEventDecodeErrorKind::InvalidLinkKind
    );

    let mut vendor_kind = vec![b'x'; 64];
    vendor_kind.push(0);
    let link_info = nested_attributes(&[(IFLA_INFO_KIND, vendor_kind.as_slice())]);
    let datagram = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        0,
        7,
        0,
        0,
        &[
            (IFLA_IFNAME, b"vendor0\0"),
            (IFLA_LINKINFO | NLA_F_NESTED, &link_info),
        ],
    );
    let decoded = decoder()
        .decode_datagram(&datagram)
        .expect("valid long vendor kind");
    let kind = decoded.events()[0]
        .record()
        .expect("upsert record")
        .kind()
        .expect("observed link kind");
    assert_eq!(kind.as_bytes(), &vendor_kind[..64]);

    let mut maximum_kind = vec![b'k'; flux_core::INTERFACE_LINK_KIND_MAX_BYTES];
    maximum_kind.push(0);
    let link_info = nested_attributes(&[(IFLA_INFO_KIND, maximum_kind.as_slice())]);
    let datagram = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        0,
        7,
        0,
        0,
        &[
            (IFLA_IFNAME, b"maximum0\0"),
            (IFLA_LINKINFO | NLA_F_NESTED, &link_info),
        ],
    );
    let decoded = decoder()
        .decode_datagram(&datagram)
        .expect("maximum nested link kind");
    let kind = decoded.events()[0]
        .record()
        .expect("upsert record")
        .kind()
        .expect("maximum link kind");
    assert_eq!(kind.as_bytes(), &maximum_kind[..maximum_kind.len() - 1]);
}

#[test]
fn mixed_link_upserts_and_removals_preserve_wire_order() {
    let mut datagram = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        0,
        7,
        0,
        0,
        &[(IFLA_IFNAME, b"tun0\0")],
    );
    datagram.extend(link_message(RTM_DELLINK, AF_UNSPEC, 0, 9, 0, 0, &[]));

    let decoded = decoder()
        .decode_datagram(&datagram)
        .expect("mixed link event datagram");
    assert!(matches!(
        &decoded.events()[0],
        InterfaceLinkEvent::Upsert(_)
    ));
    assert!(matches!(
        &decoded.events()[1],
        InterfaceLinkEvent::Remove(_)
    ));
    assert_eq!(decoded.events()[0].interface_index().get(), 7);
    assert_eq!(decoded.events()[1].interface_index().get(), 9);
}

#[test]
fn attribute_order_unknown_attributes_and_change_masks_do_not_change_events() {
    let first = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        1,
        7,
        0x1234,
        0,
        &[
            (IFLA_IFNAME, b"eth0\0"),
            (99, b"future"),
            (IFLA_MTU, &1_500_u32.to_ne_bytes()),
        ],
    );
    let second = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        1,
        7,
        0x1234,
        u32::MAX,
        &[
            (IFLA_MTU, &1_500_u32.to_ne_bytes()),
            (IFLA_IFNAME, b"eth0\0"),
        ],
    );

    let first_decoded = decoder().decode_datagram(&first).unwrap();
    let second_decoded = decoder().decode_datagram(&second).unwrap();
    assert_eq!(first_decoded.events()[0], second_decoded.events()[0]);
}

#[test]
fn loss_control_and_sequence_ambiguity_reject_the_whole_datagram() {
    let valid = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        0,
        7,
        0,
        0,
        &[(IFLA_IFNAME, b"eth0\0")],
    );
    let cases = [
        (
            netlink_message(NLMSG_OVERRUN, 0, 1, 0, &[]),
            LinkEventDecodeErrorKind::NetlinkOverrun,
        ),
        (
            netlink_message(NLMSG_ERROR, 0, 1, 0, &0_i32.to_ne_bytes()),
            LinkEventDecodeErrorKind::NetlinkError,
        ),
        (
            netlink_message(99, NLM_F_DUMP_INTR, 1, 0, &[]),
            LinkEventDecodeErrorKind::InterruptedDump,
        ),
        (
            netlink_message(99, 0, 2, 0, &[]),
            LinkEventDecodeErrorKind::MixedSequence,
        ),
    ];
    for (suffix, expected) in cases {
        let mut datagram = valid.clone();
        datagram.extend(suffix);
        assert_eq!(
            decoder()
                .decode_datagram(&datagram)
                .expect_err("datagram must be rejected atomically")
                .kind(),
            expected
        );
    }
}

#[test]
fn done_messages_are_strict_and_terminate_the_datagram_sequence() {
    for payload in [&[][..], &0_i32.to_ne_bytes()[..]] {
        let decoded = decoder()
            .decode_datagram(&netlink_message(NLMSG_DONE, 0, 77, 0, payload))
            .expect("valid completion");
        assert_eq!(decoded.completion().expect("completion").sequence(), 77);
    }

    let invalid_cases = [
        (
            netlink_message(NLMSG_DONE, 0, 77, 0, &[0]),
            LinkEventDecodeErrorKind::InvalidDonePayload,
        ),
        (
            netlink_message(NLMSG_DONE, 0, 77, 0, &(-5_i32).to_ne_bytes()),
            LinkEventDecodeErrorKind::DoneErrorStatus,
        ),
    ];
    for (datagram, expected) in invalid_cases {
        assert_eq!(
            decoder()
                .decode_datagram(&datagram)
                .expect_err("invalid completion")
                .kind(),
            expected
        );
    }

    let mut duplicate = netlink_message(NLMSG_DONE, 0, 77, 0, &[]);
    duplicate.extend(netlink_message(NLMSG_DONE, 0, 77, 0, &[]));
    assert_eq!(
        decoder()
            .decode_datagram(&duplicate)
            .expect_err("duplicate completion")
            .kind(),
        LinkEventDecodeErrorKind::DuplicateDone
    );

    let mut after_done = netlink_message(NLMSG_DONE, 0, 77, 0, &[]);
    after_done.extend(netlink_message(99, 0, 77, 0, &[]));
    assert_eq!(
        decoder()
            .decode_datagram(&after_done)
            .expect_err("message after completion")
            .kind(),
        LinkEventDecodeErrorKind::MessageAfterDone
    );
}

#[test]
fn done_message_accepts_only_flagged_well_formed_extended_ack_attributes() {
    let mut payload = 0_i32.to_ne_bytes().to_vec();
    append_attribute(&mut payload, 1, b"dump warning\0");

    let decoded = decoder()
        .decode_datagram(&netlink_message(
            NLMSG_DONE,
            NLM_F_ACK_TLVS,
            77,
            0,
            &payload,
        ))
        .expect("valid extended dump acknowledgement");
    assert_eq!(decoded.completion().expect("completion").sequence(), 77);

    assert_eq!(
        decoder()
            .decode_datagram(&netlink_message(NLMSG_DONE, 0, 77, 0, &payload))
            .expect_err("unflagged extended acknowledgement")
            .kind(),
        LinkEventDecodeErrorKind::InvalidDonePayload
    );

    payload.pop();
    assert_eq!(
        decoder()
            .decode_datagram(&netlink_message(
                NLMSG_DONE,
                NLM_F_ACK_TLVS,
                77,
                0,
                &payload,
            ))
            .expect_err("malformed extended acknowledgement")
            .kind(),
        LinkEventDecodeErrorKind::InvalidDonePayload
    );
}

#[test]
fn malformed_trailing_frames_and_every_fixture_prefix_never_emit_partial_events() {
    let valid = link_message(
        RTM_NEWLINK,
        AF_UNSPEC,
        0,
        7,
        0,
        0,
        &[
            (IFLA_IFNAME, b"eth0\0"),
            (IFLA_MTU, &1_500_u32.to_ne_bytes()),
        ],
    );
    for length in 0..valid.len() {
        let outcome = std::panic::catch_unwind(|| decoder().decode_datagram(&valid[..length]));
        assert!(
            outcome.is_ok(),
            "decoder panicked for prefix length {length}"
        );
        if let Ok(decoded) = outcome.unwrap() {
            assert!(
                decoded.events().is_empty(),
                "truncated prefix emitted an event at {length}"
            );
        }
    }

    let mut malformed = valid;
    malformed.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    assert_eq!(
        decoder()
            .decode_datagram(&malformed)
            .expect_err("malformed trailing frame")
            .kind(),
        LinkEventDecodeErrorKind::TruncatedHeader
    );
}

#[test]
fn deterministic_arbitrary_datagrams_never_panic() {
    const CASES: usize = 4_096;
    const MAX_LENGTH: usize = 512;

    let decoder = decoder();
    let mut state = 0x8cb9_2baa_7d3f_16e1_u64;
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
fn unrelated_message_types_are_ignored_after_framing_validation() {
    let decoded = decoder()
        .decode_datagram(&netlink_message(99, 0, 1, 0, &[1, 2, 3, 4]))
        .expect("well-framed unrelated message");
    assert_eq!(decoded.sequence(), Some(1));
    assert!(decoded.events().is_empty());
}

fn decoder() -> RtnetlinkLinkEventDecoder {
    RtnetlinkLinkEventDecoder::new()
}

#[allow(clippy::too_many_arguments)]
fn link_message(
    message_type: u16,
    family: u8,
    hardware_type: u16,
    interface_index: i32,
    flags: u32,
    change_mask: u32,
    attributes: &[(u16, &[u8])],
) -> Vec<u8> {
    let mut payload = vec![family, 0];
    payload.extend_from_slice(&hardware_type.to_ne_bytes());
    payload.extend_from_slice(&interface_index.to_ne_bytes());
    payload.extend_from_slice(&flags.to_ne_bytes());
    payload.extend_from_slice(&change_mask.to_ne_bytes());
    for (attribute_type, value) in attributes {
        append_attribute(&mut payload, *attribute_type, value);
    }
    netlink_message(message_type, 0, 1, 0, &payload)
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
    message.resize(super::super::align4(message.len()), 0);
    message
}

fn nested_attributes(attributes: &[(u16, &[u8])]) -> Vec<u8> {
    let mut nested = Vec::new();
    for (attribute_type, value) in attributes {
        append_attribute(&mut nested, *attribute_type, value);
    }
    nested
}

fn append_attribute(message: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
    let attribute_length = NETLINK_ATTRIBUTE_HEADER_LENGTH + value.len();
    message.extend_from_slice(&(attribute_length as u16).to_ne_bytes());
    message.extend_from_slice(&attribute_type.to_ne_bytes());
    message.extend_from_slice(value);
    message.resize(super::super::align4(message.len()), 0);
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
