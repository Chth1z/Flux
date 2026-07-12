use std::error::Error;
use std::fmt;

pub(crate) const NETLINK_HEADER_LENGTH: usize = 16;
pub(crate) const NETLINK_ATTRIBUTE_HEADER_LENGTH: usize = 4;
pub(crate) const NLMSG_ERROR: u16 = 2;
pub(crate) const NLMSG_DONE: u16 = 3;
pub(crate) const NLMSG_OVERRUN: u16 = 4;
pub(crate) const NLM_F_DUMP_INTR: u16 = 0x10;
pub(crate) const NLM_F_ACK_TLVS: u16 = 0x200;
pub(crate) const NLA_F_NESTED: u16 = 1 << 15;
pub(crate) const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
pub(crate) const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

// Raw link framing stays private behind the combined inventory observer.
#[allow(dead_code)]
pub(crate) mod link;

// Raw route framing stays private to the platform Adapter pending combined-observer integration.
#[allow(dead_code)]
pub(crate) mod route;

// Raw rule framing stays private to the platform Adapter pending combined-observer integration.
#[allow(dead_code)]
pub(crate) mod rule;

// Socket ownership and dump sequencing stay private to the platform Adapter.
#[allow(dead_code)]
pub(crate) mod socket;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetlinkMessageHeader {
    length: u32,
    message_type: u16,
    flags: u16,
    sequence: u32,
    port_id: u32,
}

impl NetlinkMessageHeader {
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn length(self) -> u32 {
        self.length
    }

    #[must_use]
    pub(crate) const fn message_type(self) -> u16 {
        self.message_type
    }

    #[must_use]
    pub(crate) const fn flags(self) -> u16 {
        self.flags
    }

    #[must_use]
    pub(crate) const fn sequence(self) -> u32 {
        self.sequence
    }

    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn port_id(self) -> u32 {
        self.port_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetlinkMessage<'a> {
    header: NetlinkMessageHeader,
    payload: &'a [u8],
    offset: usize,
}

impl<'a> NetlinkMessage<'a> {
    #[must_use]
    pub(crate) const fn header(self) -> NetlinkMessageHeader {
        self.header
    }

    #[must_use]
    pub(crate) const fn payload(self) -> &'a [u8] {
        self.payload
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetlinkAttribute<'a> {
    raw_type: u16,
    value: &'a [u8],
    offset: usize,
}

impl<'a> NetlinkAttribute<'a> {
    #[must_use]
    pub(crate) const fn attribute_type(self) -> u16 {
        self.raw_type & NLA_TYPE_MASK
    }

    #[must_use]
    pub(crate) const fn flags(self) -> u16 {
        self.raw_type & !NLA_TYPE_MASK
    }

    #[must_use]
    pub(crate) const fn value(self) -> &'a [u8] {
        self.value
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }

    #[must_use]
    pub(crate) const fn value_offset(self) -> usize {
        self.offset + NETLINK_ATTRIBUTE_HEADER_LENGTH
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetlinkAttributeErrorKind {
    InvalidAttributeLength,
    MissingAttributePadding,
    InvalidAttributeFlags,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetlinkAttributeError {
    kind: NetlinkAttributeErrorKind,
    offset: usize,
}

impl NetlinkAttributeError {
    const fn new(kind: NetlinkAttributeErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    #[must_use]
    pub(crate) const fn kind(self) -> NetlinkAttributeErrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }
}

impl fmt::Display for NetlinkAttributeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid netlink attribute at byte {}: {}",
            self.offset,
            match self.kind {
                NetlinkAttributeErrorKind::InvalidAttributeLength => "invalid attribute length",
                NetlinkAttributeErrorKind::MissingAttributePadding => {
                    "missing aligned attribute padding"
                }
                NetlinkAttributeErrorKind::InvalidAttributeFlags => {
                    "nested and network-byte-order flags are mutually exclusive"
                }
            }
        )
    }
}

impl Error for NetlinkAttributeError {}

#[derive(Clone, Debug)]
pub(crate) struct NetlinkAttributeIter<'a> {
    attributes: &'a [u8],
    base_offset: usize,
    offset: usize,
    failed: bool,
}

impl<'a> NetlinkAttributeIter<'a> {
    #[must_use]
    pub(crate) const fn new(attributes: &'a [u8], base_offset: usize) -> Self {
        Self {
            attributes,
            base_offset,
            offset: 0,
            failed: false,
        }
    }
}

impl<'a> Iterator for NetlinkAttributeIter<'a> {
    type Item = Result<NetlinkAttribute<'a>, NetlinkAttributeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset == self.attributes.len() {
            return None;
        }

        let remaining = &self.attributes[self.offset..];
        let attribute_offset = self.base_offset + self.offset;
        if remaining.len() < NETLINK_ATTRIBUTE_HEADER_LENGTH {
            self.failed = true;
            return Some(Err(NetlinkAttributeError::new(
                NetlinkAttributeErrorKind::InvalidAttributeLength,
                attribute_offset,
            )));
        }

        let length = read_u16(remaining) as usize;
        if length < NETLINK_ATTRIBUTE_HEADER_LENGTH || length > remaining.len() {
            self.failed = true;
            return Some(Err(NetlinkAttributeError::new(
                NetlinkAttributeErrorKind::InvalidAttributeLength,
                attribute_offset,
            )));
        }
        let aligned_length = align4(length);
        if aligned_length > remaining.len() {
            self.failed = true;
            return Some(Err(NetlinkAttributeError::new(
                NetlinkAttributeErrorKind::MissingAttributePadding,
                attribute_offset,
            )));
        }

        let raw_type = read_u16(&remaining[2..]);
        if raw_type & NLA_F_NESTED != 0 && raw_type & NLA_F_NET_BYTEORDER != 0 {
            self.failed = true;
            return Some(Err(NetlinkAttributeError::new(
                NetlinkAttributeErrorKind::InvalidAttributeFlags,
                attribute_offset,
            )));
        }

        let attribute = NetlinkAttribute {
            raw_type,
            value: &remaining[NETLINK_ATTRIBUTE_HEADER_LENGTH..length],
            offset: attribute_offset,
        };
        self.offset += aligned_length;
        Some(Ok(attribute))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetlinkDoneErrorKind {
    InvalidPayload,
    ErrorStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetlinkDoneError {
    kind: NetlinkDoneErrorKind,
    offset: usize,
}

impl NetlinkDoneError {
    const fn new(kind: NetlinkDoneErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    #[must_use]
    pub(crate) const fn kind(self) -> NetlinkDoneErrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }
}

pub(crate) fn validate_done_payload(
    payload: &[u8],
    flags: u16,
    payload_offset: usize,
) -> Result<(), NetlinkDoneError> {
    if payload.is_empty() {
        return Ok(());
    }
    if payload.len() < std::mem::size_of::<i32>() {
        return Err(NetlinkDoneError::new(
            NetlinkDoneErrorKind::InvalidPayload,
            payload_offset,
        ));
    }

    let status = i32::from_ne_bytes(
        payload[..4]
            .try_into()
            .expect("validated native-endian i32 payload"),
    );
    if status != 0 {
        return Err(NetlinkDoneError::new(
            NetlinkDoneErrorKind::ErrorStatus,
            payload_offset,
        ));
    }

    let attributes = &payload[4..];
    if attributes.is_empty() {
        return Ok(());
    }
    if flags & NLM_F_ACK_TLVS == 0 {
        return Err(NetlinkDoneError::new(
            NetlinkDoneErrorKind::InvalidPayload,
            payload_offset + 4,
        ));
    }
    for attribute in NetlinkAttributeIter::new(attributes, payload_offset + 4) {
        attribute.map_err(|error| {
            NetlinkDoneError::new(NetlinkDoneErrorKind::InvalidPayload, error.offset())
        })?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetlinkFrameErrorKind {
    TruncatedHeader,
    InvalidMessageLength,
    MissingMessagePadding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetlinkFrameError {
    kind: NetlinkFrameErrorKind,
    offset: usize,
}

impl NetlinkFrameError {
    const fn new(kind: NetlinkFrameErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    #[must_use]
    pub(crate) const fn kind(self) -> NetlinkFrameErrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }
}

impl fmt::Display for NetlinkFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid netlink datagram at byte {}: {}",
            self.offset,
            match self.kind {
                NetlinkFrameErrorKind::TruncatedHeader => "truncated netlink header",
                NetlinkFrameErrorKind::InvalidMessageLength => "invalid netlink message length",
                NetlinkFrameErrorKind::MissingMessagePadding => {
                    "missing aligned netlink message padding"
                }
            }
        )
    }
}

impl Error for NetlinkFrameError {}

#[derive(Clone, Debug)]
pub(crate) struct NetlinkMessageIter<'a> {
    datagram: &'a [u8],
    offset: usize,
    failed: bool,
}

impl<'a> NetlinkMessageIter<'a> {
    #[must_use]
    pub(crate) const fn new(datagram: &'a [u8]) -> Self {
        Self {
            datagram,
            offset: 0,
            failed: false,
        }
    }
}

impl<'a> Iterator for NetlinkMessageIter<'a> {
    type Item = Result<NetlinkMessage<'a>, NetlinkFrameError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset == self.datagram.len() {
            return None;
        }

        let remaining = &self.datagram[self.offset..];
        if remaining.len() < NETLINK_HEADER_LENGTH {
            self.failed = true;
            return Some(Err(NetlinkFrameError::new(
                NetlinkFrameErrorKind::TruncatedHeader,
                self.offset,
            )));
        }

        let length = read_u32(remaining) as usize;
        if length < NETLINK_HEADER_LENGTH || length > remaining.len() {
            self.failed = true;
            return Some(Err(NetlinkFrameError::new(
                NetlinkFrameErrorKind::InvalidMessageLength,
                self.offset,
            )));
        }
        let aligned_length = align4(length);
        if aligned_length > remaining.len() {
            self.failed = true;
            return Some(Err(NetlinkFrameError::new(
                NetlinkFrameErrorKind::MissingMessagePadding,
                self.offset,
            )));
        }

        let message = NetlinkMessage {
            header: NetlinkMessageHeader {
                length: length as u32,
                message_type: read_u16(&remaining[4..]),
                flags: read_u16(&remaining[6..]),
                sequence: read_u32(&remaining[8..]),
                port_id: read_u32(&remaining[12..]),
            },
            payload: &remaining[NETLINK_HEADER_LENGTH..length],
            offset: self.offset,
        };
        self.offset += aligned_length;
        Some(Ok(message))
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes[..2].try_into().expect("validated two-byte field"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes[..4].try_into().expect("validated four-byte field"))
}

pub(crate) const fn align4(length: usize) -> usize {
    length.saturating_add(3) & !3
}

#[cfg(test)]
mod tests;
