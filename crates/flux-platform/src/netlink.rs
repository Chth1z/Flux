use std::error::Error;
use std::fmt;

pub(crate) const NETLINK_HEADER_LENGTH: usize = 16;
pub(crate) const NLMSG_ERROR: u16 = 2;
pub(crate) const NLMSG_DONE: u16 = 3;
pub(crate) const NLMSG_OVERRUN: u16 = 4;
pub(crate) const NLM_F_DUMP_INTR: u16 = 0x10;

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
