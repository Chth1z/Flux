use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU16, NonZeroU32};

use super::*;

const TEST_SEQUENCE: u32 = 0x0102_0304;
const TEST_PORT_ID: u32 = 73;
const TEST_UID: u32 = 10_321;
const TEST_MARK: u32 = 0x1234_5678;
const TEST_RESPONDER_PORT: u16 = 41_001;
const TEST_TABLE: u32 = 100;

#[test]
fn ipv4_request_is_the_exact_68_byte_iproute2_shape() {
    let destination = Ipv4Addr::new(198, 51, 100, 7);
    let encoded = request(IpAddr::V4(destination));

    let mut expected = request_header(IPV4_ROUTE_LOOKUP_REQUEST_BYTES, TEST_SEQUENCE);
    let mut route = [0_u8; ROUTE_MESSAGE_LENGTH];
    route[0] = AF_INET;
    route[1] = 32;
    route[8..12].copy_from_slice(&RTM_F_LOOKUP_TABLE.to_ne_bytes());
    expected.extend_from_slice(&route);
    append_fixture_attribute(&mut expected, RTA_DST, &destination.octets());
    append_fixture_attribute(&mut expected, RTA_IP_PROTO, &[IPPROTO_TCP]);
    append_fixture_attribute(&mut expected, RTA_DPORT, &TEST_RESPONDER_PORT.to_be_bytes());
    append_fixture_attribute(&mut expected, RTA_UID, &TEST_UID.to_ne_bytes());
    append_fixture_attribute(&mut expected, RTA_MARK, &TEST_MARK.to_ne_bytes());

    assert_eq!(encoded.bytes().len(), IPV4_ROUTE_LOOKUP_REQUEST_BYTES);
    assert_eq!(encoded.bytes(), expected);
    assert_eq!(attribute_types(encoded.bytes()), [1, 27, 29, 25, 16]);
}

#[test]
fn ipv6_request_is_exactly_80_bytes_and_does_not_set_ipv4_lookup_flags() {
    let destination = "2001:db8:1::7".parse::<Ipv6Addr>().unwrap();
    let encoded = request(IpAddr::V6(destination));

    let mut expected = request_header(IPV6_ROUTE_LOOKUP_REQUEST_BYTES, TEST_SEQUENCE);
    let mut route = [0_u8; ROUTE_MESSAGE_LENGTH];
    route[0] = AF_INET6;
    route[1] = 128;
    expected.extend_from_slice(&route);
    append_fixture_attribute(&mut expected, RTA_DST, &destination.octets());
    append_fixture_attribute(&mut expected, RTA_IP_PROTO, &[IPPROTO_TCP]);
    append_fixture_attribute(&mut expected, RTA_DPORT, &TEST_RESPONDER_PORT.to_be_bytes());
    append_fixture_attribute(&mut expected, RTA_UID, &TEST_UID.to_ne_bytes());
    append_fixture_attribute(&mut expected, RTA_MARK, &TEST_MARK.to_ne_bytes());

    assert_eq!(encoded.bytes().len(), IPV6_ROUTE_LOOKUP_REQUEST_BYTES);
    assert_eq!(encoded.bytes(), expected);
    assert_eq!(&encoded.bytes()[24..28], &0_u32.to_ne_bytes());
    assert_eq!(attribute_types(encoded.bytes()), [1, 27, 29, 25, 16]);
}

#[test]
fn request_omits_source_address_and_source_port_and_uses_network_order_dport() {
    let encoded = request(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
    let attributes = encoded_attributes(encoded.bytes());

    assert!(attributes.iter().all(|attribute| attribute.flags() == 0));
    assert!(
        !attributes
            .iter()
            .any(|attribute| attribute.attribute_type() == 2)
    );
    assert!(
        !attributes
            .iter()
            .any(|attribute| attribute.attribute_type() == 28)
    );
    let dport = attributes
        .iter()
        .find(|attribute| attribute.attribute_type() == RTA_DPORT)
        .unwrap();
    assert_eq!(dport.value(), TEST_RESPONDER_PORT.to_be_bytes());
}

#[test]
fn one_matching_kernel_route_resolves_its_nonzero_table() {
    let encoded = request(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
    let datagram = route_response(
        &encoded,
        TEST_TABLE as u8,
        Some(TEST_TABLE),
        true,
        true,
        true,
    );

    let outcome = decode(&datagram, &encoded).unwrap();
    assert_eq!(
        outcome,
        CanaryRouteLookupOutcome::Resolved(CanaryRouteLookupResult {
            table: RouteTableId::from_raw(TEST_TABLE),
        })
    );
}

#[test]
fn extended_tables_must_agree_with_the_compact_table_representation() {
    let encoded = request(IpAddr::V6("2001:db8::7".parse().unwrap()));
    let extended_table = 20_253;
    let valid = route_response(
        &encoded,
        RT_TABLE_COMPAT,
        Some(extended_table),
        true,
        false,
        false,
    );
    let outcome = decode(&valid, &encoded).unwrap();
    assert!(matches!(
        outcome,
        CanaryRouteLookupOutcome::Resolved(result)
            if result.table() == RouteTableId::from_raw(extended_table)
    ));

    let inconsistent = route_response(&encoded, 100, Some(101), true, false, false);
    assert_eq!(
        error_kind(&inconsistent, &encoded),
        RouteLookupDecodeErrorKind::InconsistentTable
    );
}

#[test]
fn table_attribute_is_required_but_uid_and_mark_echoes_are_optional() {
    let encoded = request(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)));
    let missing_table = route_response(&encoded, 255, None, true, false, false);
    assert_eq!(
        error_kind(&missing_table, &encoded),
        RouteLookupDecodeErrorKind::MissingTable
    );

    let datagram = route_response(&encoded, 255, Some(255), true, false, false);

    assert!(matches!(
        decode(&datagram, &encoded).unwrap(),
        CanaryRouteLookupOutcome::Resolved(result) if result.table().get() == 255
    ));
}

#[test]
fn sender_header_family_and_destination_substitutions_are_rejected() {
    let encoded = request(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
    let valid = route_response(
        &encoded,
        TEST_TABLE as u8,
        Some(TEST_TABLE),
        true,
        true,
        true,
    );

    assert_eq!(
        decode_canary_route_lookup(
            &valid,
            PolicyRoutingAckSender::new(12, 16, 1, 0),
            NonZeroU32::new(TEST_PORT_ID).unwrap(),
            &encoded,
        )
        .unwrap_err()
        .kind(),
        RouteLookupDecodeErrorKind::UnexpectedSender
    );

    for (offset, replacement, expected) in [
        (
            8,
            TEST_SEQUENCE.wrapping_add(1),
            RouteLookupDecodeErrorKind::UnexpectedSequence,
        ),
        (
            12,
            TEST_PORT_ID + 1,
            RouteLookupDecodeErrorKind::UnexpectedPortId,
        ),
    ] {
        let mut substituted = valid.clone();
        substituted[offset..offset + 4].copy_from_slice(&replacement.to_ne_bytes());
        assert_eq!(error_kind(&substituted, &encoded), expected);
    }

    let mut wrong_family = valid.clone();
    wrong_family[NETLINK_HEADER_LENGTH] = AF_INET6;
    assert_eq!(
        error_kind(&wrong_family, &encoded),
        RouteLookupDecodeErrorKind::UnexpectedFamily
    );

    let mut wrong_prefix = valid.clone();
    wrong_prefix[NETLINK_HEADER_LENGTH + 1] = 31;
    assert_eq!(
        error_kind(&wrong_prefix, &encoded),
        RouteLookupDecodeErrorKind::UnexpectedDestinationPrefixLength
    );

    let mut wrong_destination = valid;
    let destination = attribute_value_offset(&wrong_destination, RTA_DST);
    wrong_destination[destination] ^= 1;
    assert_eq!(
        error_kind(&wrong_destination, &encoded),
        RouteLookupDecodeErrorKind::UnexpectedDestination
    );
}

#[test]
fn optional_uid_and_mark_echoes_must_match_exactly() {
    let encoded = request(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
    let valid = route_response(
        &encoded,
        TEST_TABLE as u8,
        Some(TEST_TABLE),
        true,
        true,
        true,
    );

    let mut wrong_uid = valid.clone();
    let uid = attribute_value_offset(&wrong_uid, RTA_UID);
    wrong_uid[uid..uid + 4].copy_from_slice(&(TEST_UID + 1).to_ne_bytes());
    assert_eq!(
        error_kind(&wrong_uid, &encoded),
        RouteLookupDecodeErrorKind::UnexpectedUid
    );

    let mut wrong_mark = valid;
    let mark = attribute_value_offset(&wrong_mark, RTA_MARK);
    wrong_mark[mark..mark + 4].copy_from_slice(&(TEST_MARK ^ 1).to_ne_bytes());
    assert_eq!(
        error_kind(&wrong_mark, &encoded),
        RouteLookupDecodeErrorKind::UnexpectedMark
    );
}

#[test]
fn zero_missing_duplicate_flagged_and_malformed_semantic_attributes_are_rejected() {
    let encoded = request(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));

    let zero_table = route_response(&encoded, 0, Some(0), true, false, false);
    assert_eq!(
        error_kind(&zero_table, &encoded),
        RouteLookupDecodeErrorKind::InvalidTable
    );

    let missing_destination = route_response(
        &encoded,
        TEST_TABLE as u8,
        Some(TEST_TABLE),
        false,
        false,
        false,
    );
    assert_eq!(
        error_kind(&missing_destination, &encoded),
        RouteLookupDecodeErrorKind::MissingDestination
    );

    let mut duplicate = route_response(&encoded, TEST_TABLE as u8, None, true, false, false);
    let destination = destination_bytes(encoded.lookup().destination());
    append_to_message(&mut duplicate, RTA_DST, &destination);
    assert_eq!(
        error_kind(&duplicate, &encoded),
        RouteLookupDecodeErrorKind::DuplicateAttribute {
            attribute_type: RTA_DST,
        }
    );

    let mut duplicate_table = route_response(
        &encoded,
        TEST_TABLE as u8,
        Some(TEST_TABLE),
        true,
        false,
        false,
    );
    append_to_message(&mut duplicate_table, RTA_TABLE, &TEST_TABLE.to_ne_bytes());
    assert_eq!(
        error_kind(&duplicate_table, &encoded),
        RouteLookupDecodeErrorKind::DuplicateAttribute {
            attribute_type: RTA_TABLE,
        }
    );

    let mut flagged = route_response(&encoded, TEST_TABLE as u8, None, true, false, false);
    let destination_header = attribute_value_offset(&flagged, RTA_DST) - 4;
    flagged[destination_header + 2..destination_header + 4]
        .copy_from_slice(&(RTA_DST | super::super::NLA_F_NESTED).to_ne_bytes());
    assert_eq!(
        error_kind(&flagged, &encoded),
        RouteLookupDecodeErrorKind::InvalidAttributeFlags {
            attribute_type: RTA_DST,
        }
    );

    let mut malformed = route_response(
        &encoded,
        TEST_TABLE as u8,
        Some(TEST_TABLE),
        true,
        false,
        false,
    );
    let table_header = attribute_value_offset(&malformed, RTA_TABLE) - 4;
    malformed[table_header..table_header + 2].copy_from_slice(&7_u16.to_ne_bytes());
    assert_eq!(
        error_kind(&malformed, &encoded),
        RouteLookupDecodeErrorKind::InvalidTableLength
    );
}

#[test]
fn multipart_extra_control_truncated_and_oversized_datagrams_are_rejected() {
    let encoded = request(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
    let valid = route_response(&encoded, TEST_TABLE as u8, None, true, false, false);

    let mut multipart = valid.clone();
    multipart[6..8].copy_from_slice(&NLM_F_MULTI.to_ne_bytes());
    assert_eq!(
        error_kind(&multipart, &encoded),
        RouteLookupDecodeErrorKind::MultipartResponse
    );

    let mut extra = valid.clone();
    extra.extend_from_slice(&valid);
    assert_eq!(
        error_kind(&extra, &encoded),
        RouteLookupDecodeErrorKind::MultipleMessages
    );

    let control = netlink_message(
        super::super::NLMSG_DONE,
        0,
        TEST_SEQUENCE,
        TEST_PORT_ID,
        &[],
    );
    assert_eq!(
        error_kind(&control, &encoded),
        RouteLookupDecodeErrorKind::UnexpectedControlMessage {
            message_type: super::super::NLMSG_DONE,
        }
    );

    let mut truncated = valid;
    truncated.pop();
    assert!(matches!(
        error_kind(&truncated, &encoded),
        RouteLookupDecodeErrorKind::InvalidFrame(_)
    ));

    let oversized = vec![0; MAX_ROUTE_LOOKUP_RESPONSE_BYTES + 1];
    assert_eq!(
        error_kind(&oversized, &encoded),
        RouteLookupDecodeErrorKind::DatagramTooLarge
    );
}

#[test]
fn bounded_kernel_errno_is_a_typed_rejection_not_a_decode_failure() {
    let encoded = request(IpAddr::V6("2001:db8::7".parse().unwrap()));
    let rejection = rejection_response(&encoded, -13, NLM_F_CAPPED);

    assert_eq!(
        decode(&rejection, &encoded).unwrap(),
        CanaryRouteLookupOutcome::Rejected(CanaryRouteLookupRejection {
            errno: NonZeroI32::new(13).unwrap(),
        })
    );

    for invalid in [0, 1, -4_096, i32::MIN] {
        assert!(matches!(
            error_kind(
                &rejection_response(&encoded, invalid, NLM_F_CAPPED),
                &encoded
            ),
            RouteLookupDecodeErrorKind::InvalidErrno
                | RouteLookupDecodeErrorKind::UnexpectedControlMessage { .. }
        ));
    }
}

#[test]
fn uncapped_rejections_must_echo_the_complete_request() {
    let encoded = request(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
    let rejection = rejection_response(&encoded, -101, 0);
    assert!(matches!(
        decode(&rejection, &encoded).unwrap(),
        CanaryRouteLookupOutcome::Rejected(rejection) if rejection.errno().get() == 101
    ));

    let mut substituted = rejection;
    substituted[NETLINK_HEADER_LENGTH + 4 + NETLINK_HEADER_LENGTH] ^= 1;
    assert_eq!(
        error_kind(&substituted, &encoded),
        RouteLookupDecodeErrorKind::EmbeddedRequestMismatch
    );
}

fn request(destination: IpAddr) -> EncodedCanaryRouteLookupRequest {
    encode_canary_route_lookup(
        CanaryRouteLookupRequest::new(
            destination,
            NonZeroU16::new(TEST_RESPONDER_PORT).unwrap(),
            NonZeroU32::new(TEST_UID).unwrap(),
            TEST_MARK,
        ),
        NonZeroU32::new(TEST_SEQUENCE).unwrap(),
    )
}

fn decode(
    datagram: &[u8],
    request: &EncodedCanaryRouteLookupRequest,
) -> Result<CanaryRouteLookupOutcome, RouteLookupDecodeError> {
    decode_canary_route_lookup(
        datagram,
        PolicyRoutingAckSender::kernel_unicast(),
        NonZeroU32::new(TEST_PORT_ID).unwrap(),
        request,
    )
}

fn error_kind(
    datagram: &[u8],
    request: &EncodedCanaryRouteLookupRequest,
) -> RouteLookupDecodeErrorKind {
    decode(datagram, request).unwrap_err().kind()
}

fn request_header(length: usize, sequence: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(length);
    header.extend_from_slice(&(length as u32).to_ne_bytes());
    header.extend_from_slice(&RTM_GETROUTE.to_ne_bytes());
    header.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    header.extend_from_slice(&sequence.to_ne_bytes());
    header.extend_from_slice(&0_u32.to_ne_bytes());
    header
}

fn route_response(
    request: &EncodedCanaryRouteLookupRequest,
    compact_table: u8,
    extended_table: Option<u32>,
    include_destination: bool,
    echo_uid: bool,
    echo_mark: bool,
) -> Vec<u8> {
    let lookup = request.lookup();
    let mut payload = [0_u8; ROUTE_MESSAGE_LENGTH].to_vec();
    payload[0] = family_byte(lookup.destination());
    payload[1] = maximum_prefix_length(lookup.destination());
    payload[4] = compact_table;
    if let Some(table) = extended_table {
        append_fixture_attribute(&mut payload, RTA_TABLE, &table.to_ne_bytes());
    }
    if include_destination {
        append_fixture_attribute(
            &mut payload,
            RTA_DST,
            &destination_bytes(lookup.destination()),
        );
    }
    if echo_uid {
        append_fixture_attribute(&mut payload, RTA_UID, &lookup.uid().get().to_ne_bytes());
    }
    if echo_mark {
        append_fixture_attribute(&mut payload, RTA_MARK, &lookup.mark().to_ne_bytes());
    }
    netlink_message(
        RTM_NEWROUTE,
        0,
        request.sequence().get(),
        TEST_PORT_ID,
        &payload,
    )
}

fn rejection_response(
    request: &EncodedCanaryRouteLookupRequest,
    raw_errno: i32,
    flags: u16,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&raw_errno.to_ne_bytes());
    if flags & NLM_F_CAPPED != 0 {
        payload.extend_from_slice(&request.bytes()[..NETLINK_HEADER_LENGTH]);
    } else {
        payload.extend_from_slice(request.bytes());
    }
    netlink_message(
        super::super::NLMSG_ERROR,
        flags,
        request.sequence().get(),
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

fn append_to_message(message: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
    let original_length = u32::from_ne_bytes(message[..4].try_into().unwrap()) as usize;
    message.truncate(original_length);
    append_fixture_attribute(message, attribute_type, value);
    let updated_length = message.len() as u32;
    message[..4].copy_from_slice(&updated_length.to_ne_bytes());
}

fn append_fixture_attribute(bytes: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
    let length = NETLINK_ATTRIBUTE_HEADER_LENGTH + value.len();
    bytes.extend_from_slice(&(length as u16).to_ne_bytes());
    bytes.extend_from_slice(&attribute_type.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(align4(bytes.len()), 0);
}

fn encoded_attributes(bytes: &[u8]) -> Vec<super::super::NetlinkAttribute<'_>> {
    NetlinkAttributeIter::new(
        &bytes[NETLINK_HEADER_LENGTH + ROUTE_MESSAGE_LENGTH..],
        NETLINK_HEADER_LENGTH + ROUTE_MESSAGE_LENGTH,
    )
    .map(Result::unwrap)
    .collect()
}

fn attribute_types(bytes: &[u8]) -> Vec<u16> {
    encoded_attributes(bytes)
        .into_iter()
        .map(|attribute| attribute.attribute_type())
        .collect()
}

fn attribute_value_offset(datagram: &[u8], attribute_type: u16) -> usize {
    let length = u32::from_ne_bytes(datagram[..4].try_into().unwrap()) as usize;
    NetlinkAttributeIter::new(
        &datagram[NETLINK_HEADER_LENGTH + ROUTE_MESSAGE_LENGTH..length],
        NETLINK_HEADER_LENGTH + ROUTE_MESSAGE_LENGTH,
    )
    .map(Result::unwrap)
    .find(|attribute| attribute.attribute_type() == attribute_type)
    .unwrap()
    .value_offset()
}
