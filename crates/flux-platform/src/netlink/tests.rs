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
