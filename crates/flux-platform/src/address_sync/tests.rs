use super::*;

#[test]
fn address_decoder_constructs_a_validated_core_record() {
    let datagram = address_message(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        7,
        &[(IFA_ADDRESS, &[192, 0, 2, 9])],
    );

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("valid rtnetlink datagram");

    assert_eq!(decoded.sequence(), Some(1));
    assert!(decoded.completion().is_none());
    assert_eq!(decoded.events().len(), 1);
    let event = decoded.events()[0];
    let record = event.record();
    assert_eq!(event.kind(), AddressEventKind::Add);
    assert_eq!(record.interface_index().get(), 7);
    assert_eq!(record.address(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
    assert_eq!(record.prefix_length(), 24);
    assert_eq!(record.flags().bits(), 0);
}

#[test]
fn ipv4_local_address_and_extended_flags_override_peer_and_legacy_fields() {
    let extended_flags = IFA_F_STABLE_PRIVACY;
    let datagram = address_message(
        RTM_DELADDR,
        AF_INET,
        32,
        IFA_F_TEMPORARY as u8,
        11,
        &[
            (IFA_ADDRESS, &[192, 0, 2, 20]),
            (IFA_LOCAL, &[198, 51, 100, 4]),
            (IFA_FLAGS, &extended_flags.to_ne_bytes()),
        ],
    );

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("valid rtnetlink datagram");

    let event = decoded.events()[0];
    assert_eq!(event.kind(), AddressEventKind::Remove);
    assert_eq!(
        event.record().address(),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))
    );
    assert_eq!(event.record().flags().bits(), extended_flags);
}

#[test]
fn address_policy_filters_exact_addresses_and_prefixes() {
    let mut datagram = address_message(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        4,
        &[(IFA_ADDRESS, &[198, 51, 100, 7])],
    );
    datagram.extend(address_message(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        5,
        &[(IFA_ADDRESS, &[203, 0, 113, 19])],
    ));
    datagram.extend(address_message(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        6,
        &[(IFA_ADDRESS, &[192, 0, 2, 5])],
    ));
    let policy = AddressEventPolicy::new(true)
        .with_ignored_addresses([IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))])
        .with_ignored_prefixes([(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24)])
        .expect("valid ignored prefix");

    let decoded = RtnetlinkAddressEventDecoder::new(policy)
        .decode_datagram(&datagram)
        .expect("valid rtnetlink datagram");

    assert_eq!(
        decoded
            .events()
            .iter()
            .map(|event| event.record().address())
            .collect::<Vec<_>>(),
        [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))]
    );
}

#[test]
fn flag_transitions_emit_removals_instead_of_leaving_stale_records() {
    let temporary = IFA_F_TEMPORARY.to_ne_bytes();
    let mut datagram = address_message(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        3,
        &[(IFA_ADDRESS, &[10, 0, 0, 2])],
    );
    datagram.extend(address_message(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        3,
        &[(IFA_ADDRESS, &[10, 0, 0, 2]), (IFA_FLAGS, &temporary)],
    ));
    datagram.extend(address_message(
        RTM_DELADDR,
        AF_INET,
        24,
        0,
        4,
        &[(IFA_ADDRESS, &[10, 0, 0, 3]), (IFA_FLAGS, &temporary)],
    ));
    let policy = AddressEventPolicy::new(true)
        .with_ignored_flags(InterfaceAddressFlags::from_bits(IFA_F_TEMPORARY));

    let decoded = RtnetlinkAddressEventDecoder::new(policy)
        .decode_datagram(&datagram)
        .expect("valid flag transition datagram");

    assert_eq!(
        decoded
            .events()
            .iter()
            .map(|event| event.kind())
            .collect::<Vec<_>>(),
        [
            AddressEventKind::Add,
            AddressEventKind::Remove,
            AddressEventKind::Remove,
        ]
    );
}

#[test]
fn scope_transitions_emit_removals_instead_of_leaving_stale_records() {
    let mut datagram = address_message_with_scope(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        253,
        3,
        &[(IFA_ADDRESS, &[10, 0, 0, 2])],
    );
    datagram.extend(address_message_with_scope(
        RTM_DELADDR,
        AF_INET,
        24,
        0,
        254,
        4,
        &[(IFA_ADDRESS, &[10, 0, 0, 3])],
    ));

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("valid scope transition datagram");

    assert_eq!(
        decoded
            .events()
            .iter()
            .map(|event| event.kind())
            .collect::<Vec<_>>(),
        [AddressEventKind::Remove, AddressEventKind::Remove]
    );
}

#[test]
fn address_policy_rejects_out_of_range_and_unsupported_mapped_prefixes() {
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0));
    assert_eq!(
        AddressEventPolicy::new(true)
            .with_ignored_prefixes([(v4, 33)])
            .expect_err("IPv4 prefixes stop at 32 bits"),
        AddressEventPolicyError::InvalidPrefixLength {
            address: v4,
            prefix_length: 33,
        }
    );

    let mapped = IpAddr::V6("::ffff:192.0.2.0".parse().expect("mapped IPv6"));
    assert_eq!(
        AddressEventPolicy::new(true)
            .with_ignored_prefixes([(mapped, 95)])
            .expect_err("mapped prefixes below 96 cannot become IPv4 prefixes"),
        AddressEventPolicyError::UnsupportedMappedPrefix {
            address: mapped,
            prefix_length: 95,
        }
    );
}

#[test]
fn mapped_configured_prefixes_are_normalized_to_ipv4() {
    let mapped = IpAddr::V6("::ffff:192.0.2.0".parse().expect("mapped IPv6"));
    let policy = AddressEventPolicy::new(true)
        .with_ignored_prefixes([(mapped, 120)])
        .expect("mapped /120 becomes IPv4 /24");
    let datagram = address_message(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        7,
        &[(IFA_ADDRESS, &[192, 0, 2, 9])],
    );

    let decoded = RtnetlinkAddressEventDecoder::new(policy)
        .decode_datagram(&datagram)
        .expect("valid event");

    assert!(decoded.events().is_empty());
}

#[test]
fn mapped_events_are_normalized_with_their_prefix() {
    let mapped: Ipv6Addr = "::ffff:192.0.2.9".parse().expect("mapped IPv6");
    let datagram = address_message(
        RTM_NEWADDR,
        AF_INET6,
        120,
        0,
        7,
        &[(IFA_ADDRESS, &mapped.octets())],
    );

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("mapped /120 becomes IPv4 /24");

    let record = decoded.events()[0].record();
    assert_eq!(record.address(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
    assert_eq!(record.prefix_length(), 24);
}

#[test]
fn mapped_events_below_the_ipv4_boundary_are_rejected() {
    let mapped: Ipv6Addr = "::ffff:192.0.2.9".parse().expect("mapped IPv6");
    let datagram = address_message(
        RTM_NEWADDR,
        AF_INET6,
        95,
        0,
        7,
        &[(IFA_ADDRESS, &mapped.octets())],
    );

    let error = decoder(true)
        .decode_datagram(&datagram)
        .expect_err("mapped prefixes below 96 are ambiguous");

    assert_eq!(
        error.kind(),
        AddressEventDecodeErrorKind::UnsupportedMappedPrefix
    );
}

#[test]
fn zero_interface_index_and_invalid_prefixes_are_rejected_at_the_boundary() {
    let zero_index = address_message(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        0,
        &[(IFA_ADDRESS, &[192, 0, 2, 9])],
    );
    assert_eq!(
        decoder(true)
            .decode_datagram(&zero_index)
            .expect_err("interface index zero is invalid")
            .kind(),
        AddressEventDecodeErrorKind::InvalidInterfaceIndex
    );

    let invalid_prefix = address_message(
        RTM_NEWADDR,
        AF_INET,
        33,
        0,
        7,
        &[(IFA_ADDRESS, &[192, 0, 2, 9])],
    );
    assert_eq!(
        decoder(true)
            .decode_datagram(&invalid_prefix)
            .expect_err("IPv4 prefixes stop at 32 bits")
            .kind(),
        AddressEventDecodeErrorKind::InvalidPrefixLength
    );
}

#[test]
fn malformed_address_and_extended_flags_lengths_are_structured_errors() {
    let invalid_address = address_message(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        7,
        &[(IFA_ADDRESS, &[192, 0, 2, 9, 1])],
    );
    assert_eq!(
        decoder(true)
            .decode_datagram(&invalid_address)
            .expect_err("IPv4 addresses contain exactly four bytes")
            .kind(),
        AddressEventDecodeErrorKind::InvalidAddressLength
    );

    let invalid_flags = address_message(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        7,
        &[(IFA_ADDRESS, &[192, 0, 2, 9]), (IFA_FLAGS, &[0x01, 0x00])],
    );
    assert_eq!(
        decoder(true)
            .decode_datagram(&invalid_flags)
            .expect_err("IFA_FLAGS contains exactly one u32")
            .kind(),
        AddressEventDecodeErrorKind::InvalidFlagsLength
    );
}

#[test]
fn valid_local_address_cannot_hide_a_malformed_peer_attribute() {
    let datagram = address_message(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        7,
        &[
            (IFA_ADDRESS, &[192, 0, 2, 9, 1]),
            (IFA_LOCAL, &[198, 51, 100, 4]),
        ],
    );

    let error = decoder(true)
        .decode_datagram(&datagram)
        .expect_err("every semantic address attribute must be valid");

    assert_eq!(
        error.kind(),
        AddressEventDecodeErrorKind::InvalidAddressLength
    );
}

#[test]
fn disabled_ipv6_policy_does_not_hide_a_malformed_address_message() {
    let datagram = address_message(
        RTM_NEWADDR,
        AF_INET6,
        64,
        0,
        7,
        &[(IFA_ADDRESS, &[0x20, 0x01, 0x0d, 0xb8])],
    );

    let error = decoder(false)
        .decode_datagram(&datagram)
        .expect_err("policy filtering follows structural validation");

    assert_eq!(
        error.kind(),
        AddressEventDecodeErrorKind::InvalidAddressLength
    );
}

#[test]
fn duplicate_semantic_attributes_reject_the_whole_datagram() {
    let flags = IFA_F_TEMPORARY.to_ne_bytes();
    let ambiguous_messages = [
        address_message(
            RTM_NEWADDR,
            AF_INET,
            24,
            0,
            8,
            &[
                (IFA_ADDRESS, &[198, 51, 100, 1]),
                (IFA_ADDRESS, &[198, 51, 100, 2]),
            ],
        ),
        address_message(
            RTM_NEWADDR,
            AF_INET,
            24,
            0,
            8,
            &[
                (IFA_LOCAL, &[198, 51, 100, 1]),
                (IFA_LOCAL, &[198, 51, 100, 2]),
            ],
        ),
        address_message(
            RTM_NEWADDR,
            AF_INET,
            24,
            0,
            8,
            &[
                (IFA_ADDRESS, &[198, 51, 100, 1]),
                (IFA_FLAGS, &flags),
                (IFA_FLAGS, &flags),
            ],
        ),
    ];

    for ambiguous in ambiguous_messages {
        let mut datagram = address_message(
            RTM_NEWADDR,
            AF_INET,
            24,
            0,
            7,
            &[(IFA_ADDRESS, &[192, 0, 2, 9])],
        );
        let ambiguous_message_offset = datagram.len();
        datagram.extend(ambiguous);

        let error = decoder(true)
            .decode_datagram(&datagram)
            .expect_err("no events escape from an ambiguous datagram");

        assert_eq!(
            error.kind(),
            AddressEventDecodeErrorKind::DuplicateSemanticAttribute
        );
        assert!(error.offset() >= ambiguous_message_offset);
    }
}

#[test]
fn valid_event_followed_by_any_loss_marker_rejects_the_whole_datagram() {
    let cases = [
        (
            netlink_message(NLMSG_OVERRUN, 0, 44, 0, &[]),
            AddressEventDecodeErrorKind::NetlinkOverrun,
        ),
        (
            netlink_message(NLMSG_ERROR, 0, 44, 0, &0_i32.to_ne_bytes()),
            AddressEventDecodeErrorKind::NetlinkError,
        ),
        (
            netlink_message(99, NLM_F_DUMP_INTR, 44, 0, &[]),
            AddressEventDecodeErrorKind::InterruptedDump,
        ),
    ];

    for (loss, expected) in cases {
        let mut datagram = address_message_with_header(
            RTM_NEWADDR,
            0,
            44,
            0,
            AF_INET,
            24,
            0,
            7,
            &[(IFA_ADDRESS, &[192, 0, 2, 9])],
        );
        let loss_offset = datagram.len();
        datagram.extend(loss);

        let error = decoder(true)
            .decode_datagram(&datagram)
            .expect_err("partial events must be discarded after loss");

        assert_eq!(error.kind(), expected);
        assert!(error.offset() >= loss_offset);
    }
}

#[test]
fn mixed_sequences_reject_the_whole_datagram() {
    let mut datagram = address_message_with_header(
        RTM_NEWADDR,
        0,
        7,
        0,
        AF_INET,
        24,
        0,
        7,
        &[(IFA_ADDRESS, &[192, 0, 2, 9])],
    );
    datagram.extend(address_message_with_header(
        RTM_NEWADDR,
        0,
        8,
        0,
        AF_INET,
        24,
        0,
        8,
        &[(IFA_ADDRESS, &[192, 0, 2, 10])],
    ));

    let error = decoder(true)
        .decode_datagram(&datagram)
        .expect_err("one datagram cannot mix netlink sequences");

    assert_eq!(error.kind(), AddressEventDecodeErrorKind::MixedSequence);
}

#[test]
fn done_message_is_preserved_with_its_header() {
    let mut datagram = address_message_with_header(
        RTM_NEWADDR,
        0,
        77,
        0,
        AF_INET,
        24,
        0,
        7,
        &[(IFA_ADDRESS, &[192, 0, 2, 9])],
    );
    datagram.extend(netlink_message(NLMSG_DONE, 0, 77, 0, &[]));

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("complete dump datagram");

    let done = decoded.completion().expect("NLMSG_DONE is reported");
    assert_eq!(done.message_type(), NLMSG_DONE);
    assert_eq!(done.sequence(), 77);
    assert_eq!(done.flags(), 0);
    assert_eq!(done.port_id(), 0);
    assert_eq!(decoded.events().len(), 1);
}

#[test]
fn zero_status_done_message_is_accepted() {
    let datagram = netlink_message(NLMSG_DONE, 0, 77, 0, &0_i32.to_ne_bytes());

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("zero status completes the dump");

    assert_eq!(decoded.completion().expect("completion").sequence(), 77);
}

#[test]
fn valid_event_followed_by_failing_or_malformed_done_is_rejected_atomically() {
    let cases = [
        (
            netlink_message(NLMSG_DONE, 0, 77, 0, &(-5_i32).to_ne_bytes()),
            AddressEventDecodeErrorKind::DoneErrorStatus,
        ),
        (
            netlink_message(NLMSG_DONE, 0, 77, 0, &[0]),
            AddressEventDecodeErrorKind::InvalidDonePayload,
        ),
        (
            netlink_message(NLMSG_DONE, 0, 77, 0, &[0; 8]),
            AddressEventDecodeErrorKind::InvalidDonePayload,
        ),
    ];

    for (done, expected) in cases {
        let mut datagram = address_message_with_header(
            RTM_NEWADDR,
            0,
            77,
            0,
            AF_INET,
            24,
            0,
            7,
            &[(IFA_ADDRESS, &[192, 0, 2, 9])],
        );
        let done_offset = datagram.len();
        datagram.extend(done);

        let error = decoder(true)
            .decode_datagram(&datagram)
            .expect_err("failing completion discards prior events");

        assert_eq!(error.kind(), expected);
        assert!(error.offset() >= done_offset);
    }
}

#[test]
fn messages_after_done_are_rejected_as_ambiguous() {
    let mut datagram = netlink_message(NLMSG_DONE, 0, 77, 0, &[]);
    datagram.extend(address_message_with_header(
        RTM_NEWADDR,
        0,
        77,
        0,
        AF_INET,
        24,
        0,
        7,
        &[(IFA_ADDRESS, &[192, 0, 2, 9])],
    ));

    let error = decoder(true)
        .decode_datagram(&datagram)
        .expect_err("NLMSG_DONE terminates its sequence");

    assert_eq!(error.kind(), AddressEventDecodeErrorKind::MessageAfterDone);
}

#[test]
fn ipv6_local_attributes_are_validated_and_duplicate_checked() {
    let address: Ipv6Addr = "2001:db8::1".parse().expect("IPv6 address");
    let local: Ipv6Addr = "2001:db8::2".parse().expect("IPv6 local address");
    let malformed = address_message(
        RTM_NEWADDR,
        AF_INET6,
        64,
        0,
        7,
        &[(IFA_ADDRESS, &address.octets()), (IFA_LOCAL, &[0, 1, 2, 3])],
    );
    assert_eq!(
        decoder(true)
            .decode_datagram(&malformed)
            .expect_err("known IPv6 IFA_LOCAL must have IPv6 length")
            .kind(),
        AddressEventDecodeErrorKind::InvalidAddressLength
    );

    let duplicate = address_message(
        RTM_NEWADDR,
        AF_INET6,
        64,
        0,
        7,
        &[
            (IFA_ADDRESS, &address.octets()),
            (IFA_LOCAL, &local.octets()),
            (IFA_LOCAL, &local.octets()),
        ],
    );
    assert_eq!(
        decoder(true)
            .decode_datagram(&duplicate)
            .expect_err("duplicate IPv6 IFA_LOCAL is ambiguous")
            .kind(),
        AddressEventDecodeErrorKind::DuplicateSemanticAttribute
    );
}

#[test]
fn deterministic_arbitrary_datagrams_never_panic() {
    const CASES: usize = 4_096;
    const MAX_LENGTH: usize = 512;

    let decoder = decoder(true);
    let mut state = 0x4d59_5df4_d0f3_3173_u64;

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
fn malformed_trailing_message_rejects_the_whole_datagram() {
    let mut datagram = address_message(
        RTM_NEWADDR,
        AF_INET,
        24,
        0,
        7,
        &[(IFA_ADDRESS, &[192, 0, 2, 9])],
    );
    let malformed_offset = datagram.len();
    datagram.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

    let error = decoder(true)
        .decode_datagram(&datagram)
        .expect_err("a partial event vector would make loss recovery ambiguous");

    assert_eq!(error.kind(), AddressEventDecodeErrorKind::TruncatedHeader);
    assert_eq!(error.offset(), malformed_offset);
}

#[test]
fn unrelated_message_types_are_not_misclassified_as_additions() {
    let datagram = netlink_message(99, 0, 1, 0, &[1, 2, 3, 4]);

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("well-framed unrelated message");

    assert!(decoded.events().is_empty());
    assert_eq!(decoded.sequence(), Some(1));
}

fn decoder(ipv6_enabled: bool) -> RtnetlinkAddressEventDecoder {
    RtnetlinkAddressEventDecoder::new(AddressEventPolicy::new(ipv6_enabled))
}

fn address_message(
    message_type: u16,
    family: u8,
    prefix_length: u8,
    flags: u8,
    interface_index: u32,
    attributes: &[(u16, &[u8])],
) -> Vec<u8> {
    address_message_with_header(
        message_type,
        0,
        1,
        0,
        family,
        prefix_length,
        flags,
        interface_index,
        attributes,
    )
}

#[allow(clippy::too_many_arguments)]
fn address_message_with_scope(
    message_type: u16,
    family: u8,
    prefix_length: u8,
    flags: u8,
    scope: u8,
    interface_index: u32,
    attributes: &[(u16, &[u8])],
) -> Vec<u8> {
    let mut message = address_message(
        message_type,
        family,
        prefix_length,
        flags,
        interface_index,
        attributes,
    );
    message[NETLINK_HEADER_LENGTH + 3] = scope;
    message
}

#[allow(clippy::too_many_arguments)]
fn address_message_with_header(
    message_type: u16,
    netlink_flags: u16,
    sequence: u32,
    port_id: u32,
    family: u8,
    prefix_length: u8,
    flags: u8,
    interface_index: u32,
    attributes: &[(u16, &[u8])],
) -> Vec<u8> {
    let mut payload = vec![family, prefix_length, flags, 0];
    payload.extend_from_slice(&interface_index.to_ne_bytes());
    for (attribute_type, value) in attributes {
        append_attribute(&mut payload, *attribute_type, value);
    }
    netlink_message(message_type, netlink_flags, sequence, port_id, &payload)
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
    message.extend_from_slice(&(attribute_length as u16).to_ne_bytes());
    message.extend_from_slice(&attribute_type.to_ne_bytes());
    message.extend_from_slice(value);
    message.resize(align4(message.len()), 0);
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
