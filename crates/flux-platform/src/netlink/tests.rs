use super::*;

#[test]
fn message_iterator_preserves_every_header_field_and_payload() {
    let payload = [0xde, 0xad, 0xbe, 0xef];
    let datagram = message(20, NLM_F_DUMP_INTR, 42, 7, &payload);

    let parsed = NetlinkMessageIter::new(&datagram)
        .next()
        .expect("one framed message")
        .expect("valid frame");

    assert_eq!(parsed.offset(), 0);
    assert_eq!(parsed.header().length(), 20);
    assert_eq!(parsed.header().message_type(), 20);
    assert_eq!(parsed.header().flags(), NLM_F_DUMP_INTR);
    assert_eq!(parsed.header().sequence(), 42);
    assert_eq!(parsed.header().port_id(), 7);
    assert_eq!(parsed.payload(), payload);
}

#[test]
fn attribute_iterator_masks_flags_and_preserves_offsets() {
    let mut attributes = Vec::new();
    append_attribute(&mut attributes, 3 | NLA_F_NESTED, b"tun\0");
    append_attribute(&mut attributes, 4, &1_500_u32.to_ne_bytes());

    let parsed = NetlinkAttributeIter::new(&attributes, 32)
        .collect::<Result<Vec<_>, _>>()
        .expect("valid attributes");

    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].attribute_type(), 3);
    assert_eq!(parsed[0].flags(), NLA_F_NESTED);
    assert_eq!(parsed[0].value(), b"tun\0");
    assert_eq!(parsed[0].offset(), 32);
    assert_eq!(parsed[0].value_offset(), 36);
    assert_eq!(parsed[1].attribute_type(), 4);
    assert_eq!(parsed[1].value(), 1_500_u32.to_ne_bytes());
    assert_eq!(parsed[1].offset(), 40);
}

#[test]
fn attribute_iterator_rejects_mutually_exclusive_flags() {
    let mut attributes = Vec::new();
    append_attribute(
        &mut attributes,
        99 | NLA_F_NESTED | NLA_F_NET_BYTEORDER,
        b"future",
    );

    let error = NetlinkAttributeIter::new(&attributes, 48)
        .next()
        .expect("one attribute")
        .expect_err("mutually exclusive flags");

    assert_eq!(
        error.kind(),
        NetlinkAttributeErrorKind::InvalidAttributeFlags
    );
    assert_eq!(error.offset(), 48);
}

fn message(message_type: u16, flags: u16, sequence: u32, port_id: u32, payload: &[u8]) -> Vec<u8> {
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
    let length = NETLINK_ATTRIBUTE_HEADER_LENGTH + value.len();
    message.extend_from_slice(&(length as u16).to_ne_bytes());
    message.extend_from_slice(&attribute_type.to_ne_bytes());
    message.extend_from_slice(value);
    message.resize(align4(message.len()), 0);
}
