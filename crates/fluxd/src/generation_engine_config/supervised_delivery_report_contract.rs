use std::num::{NonZeroU8, NonZeroU16};

use sha2::{Digest, Sha256};

use super::compiler::length_bytes;

pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION: u16 = 1;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC: [u8; 8] = *b"FLXDLV1\0";
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_BYTES: u16 = 152;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FRAME_BYTES: u16 = 300;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_FRAME_BYTES: u16 = 280;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_FRAME_BYTES: u16 = 160;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_FRAME_BYTES: u16 =
    ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FRAME_BYTES;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_EVENTS: u8 = 8;

pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_SCHEMA_VERSION: u16 = 1;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_MAGIC: [u8; 8] = *b"FLXHND1\0";
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FRAME_BYTES: u16 = 160;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ATTEMPT_KIND: u8 = 1;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_IPV4_FLAG: u8 = 1 << 0;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_IPV6_FLAG: u8 = 1 << 1;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_TPROXY_BACKEND: u8 = 1;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_IPV4_FLOW_MASK: u8 = 0x0f;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_DUAL_STACK_FLOW_MASK: u8 = 0xff;

pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_MAGIC: usize = 0;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_SCHEMA_VERSION: usize = 8;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_KIND: usize = 10;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_FLAGS: usize = 11;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_FRAME_LENGTH: usize = 12;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_HEADER_LENGTH: usize = 14;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_SEQUENCE: usize = 16;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_CUMULATIVE_LOSS: usize = 24;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_GENERATION: usize = 32;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_ENGINE_PID: usize = 36;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_ENGINE_START_TICKS: usize = 40;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_REPORT_OBJECT: usize = 48;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_PROFILE_REVISION: usize = 80;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_ATTEMPT_NONCE: usize = 112;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_HEADER_RESERVED: usize = 144;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_PAYLOAD: usize = 152;

pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_BYTES: usize = 20;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_IDENTITY_BYTES: usize = 72;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_TRUNCATED_FLAG: u8 = 1 << 0;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CONTROL_TRUNCATED_FLAG: u8 = 1 << 1;
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_TRUNCATION_FLAGS: u8 =
    ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_TRUNCATED_FLAG
        | ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CONTROL_TRUNCATED_FLAG;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EngineSupervisedDeliveryReportWireField {
    offset: usize,
    bytes: usize,
}

impl EngineSupervisedDeliveryReportWireField {
    const fn new(offset: usize, bytes: usize) -> Self {
        Self { offset, bytes }
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }

    #[must_use]
    pub(crate) const fn bytes(self) -> usize {
        self.bytes
    }

    #[must_use]
    pub(crate) const fn end(self) -> usize {
        self.offset + self.bytes
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn at(self, containing_offset: usize) -> Self {
        Self::new(containing_offset + self.offset, self.bytes)
    }
}

pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC_FIELD:
    EngineSupervisedDeliveryReportWireField =
    EngineSupervisedDeliveryReportWireField::new(ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_MAGIC, 8);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(
    ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_SCHEMA_VERSION,
    2,
);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_KIND_FIELD:
    EngineSupervisedDeliveryReportWireField =
    EngineSupervisedDeliveryReportWireField::new(ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_KIND, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_FLAGS_FIELD:
    EngineSupervisedDeliveryReportWireField =
    EngineSupervisedDeliveryReportWireField::new(ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_FLAGS, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_FRAME_LENGTH_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(
    ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_FRAME_LENGTH,
    2,
);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_LENGTH_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(
    ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_HEADER_LENGTH,
    2,
);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_SEQUENCE_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(
    ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_SEQUENCE,
    8,
);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_CUMULATIVE_LOSS_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(
    ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_CUMULATIVE_LOSS,
    8,
);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_GENERATION_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(
    ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_GENERATION,
    4,
);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_PID_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(
    ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_ENGINE_PID,
    4,
);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_START_TICKS_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(
    ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_ENGINE_START_TICKS,
    8,
);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_REPORT_OBJECT_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(
    ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_REPORT_OBJECT,
    32,
);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_PROFILE_REVISION_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(
    ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_PROFILE_REVISION,
    32,
);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_ATTEMPT_NONCE_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(
    ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_ATTEMPT_NONCE,
    32,
);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_RESERVED_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(
    ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_HEADER_RESERVED,
    8,
);

pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(0, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_RESERVED_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(1, 3);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LISTENER_COOKIE_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(4, 8);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_FD_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(12, 4);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_RESERVED_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(16, 4);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_INODE_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(20, 8);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_COOKIE_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(28, 8);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LOCAL_ADDRESS_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(36, 20);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PEER_ADDRESS_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(56, 20);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PAYLOAD_IDENTITY_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(76, 72);

pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_FLOW_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(0, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_COUNT_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(1, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_FAMILY_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(2, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_TRUNCATION_FLAGS_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(3, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_LENGTH_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(4, 2);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_RESERVED_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(6, 2);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_LISTENER_COOKIE_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(8, 8);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CLIENT_ADDRESS_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(16, 20);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_ORIGINAL_DESTINATION_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(36, 20);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_IDENTITY_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(56, 72);

pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_EVENT_COUNT_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(0, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_RESERVED_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(1, 7);

pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_HIGH_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(0, 4);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_LOW_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(4, 4);

pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_FAMILY_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(0, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_RESERVED_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(1, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_PORT_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(2, 2);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(4, 16);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_IPV4_ADDRESS_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(16, 4);

pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_KIND_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(0, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_RESERVED_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(1, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_LENGTH_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(2, 2);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_DIGEST_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(4, 32);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TRANSACTION_ID_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(36, 2);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TCP_LENGTH_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(38, 2);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_QUESTION_DIGEST_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(40, 32);

pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_MAGIC_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(0, 8);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_SCHEMA_VERSION_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(8, 2);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_KIND_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(10, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FLAGS_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(11, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FRAME_LENGTH_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(12, 2);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_HEADER_LENGTH_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(14, 2);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REQUEST_SCHEMA_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(16, 2);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REPORT_SCHEMA_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(18, 2);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FAMILIES_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(20, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REQUIRED_FLOWS_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(21, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_BACKEND_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(22, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_PREFIX_RESERVED_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(23, 1);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_GENERATION_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(24, 4);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ENGINE_PID_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(28, 4);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ENGINE_START_TICKS_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(32, 8);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ENGINE_SNAPSHOT_REVISION_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(40, 8);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REPORT_OBJECT_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(48, 32);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_PROFILE_REVISION_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(80, 32);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ATTEMPT_NONCE_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(112, 32);
pub(crate) const ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_RESERVED_FIELD:
    EngineSupervisedDeliveryReportWireField = EngineSupervisedDeliveryReportWireField::new(144, 16);

const _: () = {
    let fields = [
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_MAGIC_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_SCHEMA_VERSION_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_KIND_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FLAGS_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FRAME_LENGTH_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_HEADER_LENGTH_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REQUEST_SCHEMA_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REPORT_SCHEMA_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FAMILIES_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REQUIRED_FLOWS_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_BACKEND_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_PREFIX_RESERVED_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_GENERATION_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ENGINE_PID_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ENGINE_START_TICKS_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ENGINE_SNAPSHOT_REVISION_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REPORT_OBJECT_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_PROFILE_REVISION_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ATTEMPT_NONCE_FIELD,
        ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_RESERVED_FIELD,
    ];
    let mut index = 1;
    while index < fields.len() {
        assert!(fields[index - 1].end() == fields[index].offset());
        index += 1;
    }
    assert!(fields[0].offset() == 0);
    assert!(
        fields[fields.len() - 1].end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FRAME_BYTES as usize
    );
};

const ENGINE_SUPERVISED_DELIVERY_REPORT_REVISION_DOMAIN: &[u8] =
    b"Flux Engine Supervised Delivery Report Contract\0schema-v1\0";

const _: () = {
    assert!(ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC_FIELD.offset() == 0);
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_KIND_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_KIND_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_FLAGS_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_FLAGS_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_FRAME_LENGTH_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_FRAME_LENGTH_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_LENGTH_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_LENGTH_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_SEQUENCE_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_SEQUENCE_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_CUMULATIVE_LOSS_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_CUMULATIVE_LOSS_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_GENERATION_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_GENERATION_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_PID_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_PID_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_START_TICKS_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_START_TICKS_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_REPORT_OBJECT_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_REPORT_OBJECT_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_PROFILE_REVISION_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_PROFILE_REVISION_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_ATTEMPT_NONCE_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_ATTEMPT_NONCE_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_RESERVED_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_PAYLOAD
            == ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_RESERVED_FIELD.end()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_PAYLOAD
            == ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_BYTES as usize
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FRAME_BYTES as usize
            == ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_PAYLOAD
                + ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PAYLOAD_IDENTITY_FIELD.end()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_FRAME_BYTES as usize
            == ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_PAYLOAD
                + ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_IDENTITY_FIELD.end()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_FRAME_BYTES as usize
            == ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_PAYLOAD + 8
    );
    assert!(ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_BYTES == 20);
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_RESERVED_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_RESERVED_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LISTENER_COOKIE_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LISTENER_COOKIE_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_FD_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_FD_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_RESERVED_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_RESERVED_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_INODE_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_INODE_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_COOKIE_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_COOKIE_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LOCAL_ADDRESS_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LOCAL_ADDRESS_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PEER_ADDRESS_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PEER_ADDRESS_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PAYLOAD_IDENTITY_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PAYLOAD_IDENTITY_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FRAME_BYTES as usize
                - ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_PAYLOAD
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_FLOW_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_COUNT_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_COUNT_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_FAMILY_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_FAMILY_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_TRUNCATION_FLAGS_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_TRUNCATION_FLAGS_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_LENGTH_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_LENGTH_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_RESERVED_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_RESERVED_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_LISTENER_COOKIE_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_LISTENER_COOKIE_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CLIENT_ADDRESS_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CLIENT_ADDRESS_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_ORIGINAL_DESTINATION_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_ORIGINAL_DESTINATION_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_IDENTITY_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_IDENTITY_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_FRAME_BYTES as usize
                - ENGINE_SUPERVISED_DELIVERY_REPORT_OFFSET_PAYLOAD
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_EVENT_COUNT_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_RESERVED_FIELD.offset()
    );
    assert!(ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_RESERVED_FIELD.end() == 8);
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_HIGH_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_LOW_FIELD.offset()
    );
    assert!(ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_LOW_FIELD.end() == 8);
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_FAMILY_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_RESERVED_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_RESERVED_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_PORT_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_PORT_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_BYTES
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_IPV4_ADDRESS_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_BYTES
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_KIND_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_RESERVED_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_RESERVED_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_LENGTH_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_LENGTH_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_DIGEST_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_DIGEST_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TRANSACTION_ID_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TRANSACTION_ID_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TCP_LENGTH_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TCP_LENGTH_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_QUESTION_DIGEST_FIELD.offset()
    );
    assert!(
        ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_QUESTION_DIGEST_FIELD.end()
            == ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_IDENTITY_BYTES
    );
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum EngineSupervisedDeliveryReportEndianness {
    Big = 1,
}

pub(crate) struct EngineSupervisedDeliveryReportWireCodec;

impl EngineSupervisedDeliveryReportWireCodec {
    #[must_use]
    pub(crate) const fn decode_u16(bytes: [u8; 2]) -> u16 {
        u16::from_be_bytes(bytes)
    }

    #[must_use]
    pub(crate) const fn decode_u32(bytes: [u8; 4]) -> u32 {
        u32::from_be_bytes(bytes)
    }

    #[must_use]
    pub(crate) const fn decode_u64(bytes: [u8; 8]) -> u64 {
        u64::from_be_bytes(bytes)
    }

    #[must_use]
    pub(crate) const fn encode_u16(value: u16) -> [u8; 2] {
        value.to_be_bytes()
    }

    #[must_use]
    pub(crate) const fn encode_u32(value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }

    #[must_use]
    pub(crate) const fn encode_u64(value: u64) -> [u8; 8] {
        value.to_be_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EngineSupervisedDeliveryReportFrameKind {
    TcpDelivery = 1,
    UdpDelivery = 2,
    Terminal = 3,
}

impl EngineSupervisedDeliveryReportFrameKind {
    #[must_use]
    pub(crate) const fn from_wire_value(raw: u8) -> Option<Self> {
        match raw {
            value if value == Self::TcpDelivery as u8 => Some(Self::TcpDelivery),
            value if value == Self::UdpDelivery as u8 => Some(Self::UdpDelivery),
            value if value == Self::Terminal as u8 => Some(Self::Terminal),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) const fn wire_value(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub(crate) const fn frame_bytes(self) -> u16 {
        match self {
            Self::TcpDelivery => ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FRAME_BYTES,
            Self::UdpDelivery => ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_FRAME_BYTES,
            Self::Terminal => ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_FRAME_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EngineSupervisedDeliveryReportPayloadKind {
    Echo = 1,
    Dns = 2,
}

impl EngineSupervisedDeliveryReportPayloadKind {
    #[must_use]
    pub(crate) const fn from_wire_value(raw: u8) -> Option<Self> {
        match raw {
            value if value == Self::Echo as u8 => Some(Self::Echo),
            value if value == Self::Dns as u8 => Some(Self::Dns),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) const fn wire_value(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EngineSupervisedDeliveryReportFlowCode {
    Ipv4TcpEcho = 0,
    Ipv4UdpEcho = 1,
    Ipv4DnsUdp = 2,
    Ipv4DnsTcp = 3,
    Ipv6TcpEcho = 4,
    Ipv6UdpEcho = 5,
    Ipv6DnsUdp = 6,
    Ipv6DnsTcp = 7,
}

impl EngineSupervisedDeliveryReportFlowCode {
    #[must_use]
    pub(crate) const fn from_wire_value(raw: u8) -> Option<Self> {
        match raw {
            value if value == Self::Ipv4TcpEcho as u8 => Some(Self::Ipv4TcpEcho),
            value if value == Self::Ipv4UdpEcho as u8 => Some(Self::Ipv4UdpEcho),
            value if value == Self::Ipv4DnsUdp as u8 => Some(Self::Ipv4DnsUdp),
            value if value == Self::Ipv4DnsTcp as u8 => Some(Self::Ipv4DnsTcp),
            value if value == Self::Ipv6TcpEcho as u8 => Some(Self::Ipv6TcpEcho),
            value if value == Self::Ipv6UdpEcho as u8 => Some(Self::Ipv6UdpEcho),
            value if value == Self::Ipv6DnsUdp as u8 => Some(Self::Ipv6DnsUdp),
            value if value == Self::Ipv6DnsTcp as u8 => Some(Self::Ipv6DnsTcp),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) const fn wire_value(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EngineSupervisedDeliveryReportAddressFamilyCode {
    Ipv4 = 4,
    Ipv6 = 6,
}

impl EngineSupervisedDeliveryReportAddressFamilyCode {
    #[must_use]
    pub(crate) const fn from_wire_value(raw: u8) -> Option<Self> {
        match raw {
            value if value == Self::Ipv4 as u8 => Some(Self::Ipv4),
            value if value == Self::Ipv6 as u8 => Some(Self::Ipv6),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) const fn wire_value(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum EngineSupervisedDeliveryReportSource {
    SupervisedEngineInboundHandler = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum EngineSupervisedDeliveryReportTransport {
    AttemptOwnedUnixSeqpacket = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum EngineSupervisedDeliveryReportHandoff {
    ExactPinnedChildLaunchControlScmRights = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum EngineSupervisedDeliveryReportFraming {
    OneCanonicalFramePerDatagram = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum EngineSupervisedDeliveryReportSequence {
    ContiguousFromOneInCanonicalFlowOrder = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum EngineSupervisedDeliveryReportLoss {
    CumulativeZeroForPositiveEvidence = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum EngineSupervisedDeliveryReportObjectLifecycle {
    AttemptOwned = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum EngineSupervisedDeliveryReportShutdown {
    TerminalThenDrainedEofBeforeRetirement = 1,
}

/// Exact producer and wire contract claimed by one immutable engine artifact profile.
///
/// Construction is sealed in this module. Production collection currently leaves the capability
/// absent; only test fixtures can claim the single canonical schema-v1 shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EngineSupervisedDeliveryReportContract {
    schema_version: NonZeroU16,
    handoff_schema_version: NonZeroU16,
    source: EngineSupervisedDeliveryReportSource,
    transport: EngineSupervisedDeliveryReportTransport,
    handoff: EngineSupervisedDeliveryReportHandoff,
    framing: EngineSupervisedDeliveryReportFraming,
    sequence: EngineSupervisedDeliveryReportSequence,
    loss: EngineSupervisedDeliveryReportLoss,
    object_lifecycle: EngineSupervisedDeliveryReportObjectLifecycle,
    shutdown: EngineSupervisedDeliveryReportShutdown,
    max_delivery_events: NonZeroU8,
    max_frame_bytes: NonZeroU16,
    max_handoff_frame_bytes: NonZeroU16,
}

impl EngineSupervisedDeliveryReportContract {
    const fn canonical_schema_v1() -> Self {
        Self {
            schema_version: NonZeroU16::MIN,
            handoff_schema_version: NonZeroU16::MIN,
            source: EngineSupervisedDeliveryReportSource::SupervisedEngineInboundHandler,
            transport: EngineSupervisedDeliveryReportTransport::AttemptOwnedUnixSeqpacket,
            handoff: EngineSupervisedDeliveryReportHandoff::ExactPinnedChildLaunchControlScmRights,
            framing: EngineSupervisedDeliveryReportFraming::OneCanonicalFramePerDatagram,
            sequence: EngineSupervisedDeliveryReportSequence::ContiguousFromOneInCanonicalFlowOrder,
            loss: EngineSupervisedDeliveryReportLoss::CumulativeZeroForPositiveEvidence,
            object_lifecycle: EngineSupervisedDeliveryReportObjectLifecycle::AttemptOwned,
            shutdown:
                EngineSupervisedDeliveryReportShutdown::TerminalThenDrainedEofBeforeRetirement,
            max_delivery_events: match NonZeroU8::new(ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_EVENTS)
            {
                Some(value) => value,
                None => panic!("supervised delivery-report event bound must be nonzero"),
            },
            max_frame_bytes: match NonZeroU16::new(
                ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_FRAME_BYTES,
            ) {
                Some(value) => value,
                None => panic!("supervised delivery-report frame bound must be nonzero"),
            },
            max_handoff_frame_bytes: match NonZeroU16::new(
                ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FRAME_BYTES,
            ) {
                Some(value) => value,
                None => panic!("supervised delivery-report handoff frame bound must be nonzero"),
            },
        }
    }

    #[cfg(test)]
    pub(super) const fn schema_v1_fixture() -> Self {
        Self::canonical_schema_v1()
    }

    #[must_use]
    pub(crate) const fn schema_version(self) -> NonZeroU16 {
        self.schema_version
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn handoff_schema_version(self) -> NonZeroU16 {
        self.handoff_schema_version
    }

    #[must_use]
    pub(crate) fn is_canonical_schema_v1(self) -> bool {
        self == Self::canonical_schema_v1()
    }

    pub(super) fn update_revision_digest(self, digest: &mut Sha256) {
        update_length_prefixed(digest, ENGINE_SUPERVISED_DELIVERY_REPORT_REVISION_DOMAIN);
        update_length_prefixed(digest, &self.schema_version.get().to_be_bytes());
        update_length_prefixed(digest, &self.handoff_schema_version.get().to_be_bytes());
        update_length_prefixed(digest, &[self.source as u8]);
        update_length_prefixed(digest, &[self.transport as u8]);
        update_length_prefixed(digest, &[self.handoff as u8]);
        update_length_prefixed(digest, &[self.framing as u8]);
        update_length_prefixed(digest, &[self.sequence as u8]);
        update_length_prefixed(digest, &[self.loss as u8]);
        update_length_prefixed(digest, &[self.object_lifecycle as u8]);
        update_length_prefixed(digest, &[self.shutdown as u8]);
        update_length_prefixed(digest, &[self.max_delivery_events.get()]);
        update_length_prefixed(digest, &self.max_frame_bytes.get().to_be_bytes());
        update_length_prefixed(digest, &self.max_handoff_frame_bytes.get().to_be_bytes());
        update_length_prefixed(digest, &ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC);
        update_length_prefixed(
            digest,
            &ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_BYTES.to_be_bytes(),
        );
        update_length_prefixed(
            digest,
            &ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FRAME_BYTES.to_be_bytes(),
        );
        update_length_prefixed(
            digest,
            &ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_FRAME_BYTES.to_be_bytes(),
        );
        update_length_prefixed(
            digest,
            &ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_FRAME_BYTES.to_be_bytes(),
        );
        update_length_prefixed(
            digest,
            &ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_SCHEMA_VERSION.to_be_bytes(),
        );
        update_length_prefixed(digest, &ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_MAGIC);
        update_length_prefixed(
            digest,
            &ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FRAME_BYTES.to_be_bytes(),
        );
        for value in [
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ATTEMPT_KIND,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_IPV4_FLAG,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_IPV6_FLAG,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_TPROXY_BACKEND,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_IPV4_FLOW_MASK,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_DUAL_STACK_FLOW_MASK,
        ] {
            update_length_prefixed(digest, &[value]);
        }
        for kind in [
            EngineSupervisedDeliveryReportFrameKind::TcpDelivery,
            EngineSupervisedDeliveryReportFrameKind::UdpDelivery,
            EngineSupervisedDeliveryReportFrameKind::Terminal,
        ] {
            update_length_prefixed(digest, &[kind.wire_value()]);
            update_length_prefixed(digest, &kind.frame_bytes().to_be_bytes());
        }
        for kind in [
            EngineSupervisedDeliveryReportPayloadKind::Echo,
            EngineSupervisedDeliveryReportPayloadKind::Dns,
        ] {
            update_length_prefixed(digest, &[kind.wire_value()]);
        }
        for flow in [
            EngineSupervisedDeliveryReportFlowCode::Ipv4TcpEcho,
            EngineSupervisedDeliveryReportFlowCode::Ipv4UdpEcho,
            EngineSupervisedDeliveryReportFlowCode::Ipv4DnsUdp,
            EngineSupervisedDeliveryReportFlowCode::Ipv4DnsTcp,
            EngineSupervisedDeliveryReportFlowCode::Ipv6TcpEcho,
            EngineSupervisedDeliveryReportFlowCode::Ipv6UdpEcho,
            EngineSupervisedDeliveryReportFlowCode::Ipv6DnsUdp,
            EngineSupervisedDeliveryReportFlowCode::Ipv6DnsTcp,
        ] {
            update_length_prefixed(digest, &[flow.wire_value()]);
        }
        for family in [
            EngineSupervisedDeliveryReportAddressFamilyCode::Ipv4,
            EngineSupervisedDeliveryReportAddressFamilyCode::Ipv6,
        ] {
            update_length_prefixed(digest, &[family.wire_value()]);
        }
        update_length_prefixed(
            digest,
            &[EngineSupervisedDeliveryReportEndianness::Big as u8],
        );
        update_length_prefixed(
            digest,
            &[ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_TRUNCATED_FLAG],
        );
        update_length_prefixed(
            digest,
            &[ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CONTROL_TRUNCATED_FLAG],
        );
        update_length_prefixed(
            digest,
            &[ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_TRUNCATION_FLAGS],
        );
        for field in [
            ENGINE_SUPERVISED_DELIVERY_REPORT_MAGIC_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_KIND_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_FLAGS_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_FRAME_LENGTH_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_LENGTH_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_SEQUENCE_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_CUMULATIVE_LOSS_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_GENERATION_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_PID_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_ENGINE_START_TICKS_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_REPORT_OBJECT_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_PROFILE_REVISION_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_ATTEMPT_NONCE_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HEADER_RESERVED_FIELD,
        ] {
            update_wire_field_digest(digest, field);
        }
        for field in [
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_MAGIC_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_SCHEMA_VERSION_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_KIND_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FLAGS_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FRAME_LENGTH_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_HEADER_LENGTH_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REQUEST_SCHEMA_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REPORT_SCHEMA_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_FAMILIES_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REQUIRED_FLOWS_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_BACKEND_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_PREFIX_RESERVED_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_GENERATION_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ENGINE_PID_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ENGINE_START_TICKS_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ENGINE_SNAPSHOT_REVISION_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_REPORT_OBJECT_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_PROFILE_REVISION_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_ATTEMPT_NONCE_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_RESERVED_FIELD,
        ] {
            update_wire_field_digest(digest, field);
        }
        for field in [
            ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_FLOW_RESERVED_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LISTENER_COOKIE_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_FD_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_RESERVED_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_INODE_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_ACCEPTED_COOKIE_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_LOCAL_ADDRESS_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PEER_ADDRESS_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_TCP_PAYLOAD_IDENTITY_FIELD,
        ] {
            update_wire_field_digest(digest, field);
        }
        for field in [
            ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_FLOW_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_COUNT_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_FAMILY_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_TRUNCATION_FLAGS_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CMSG_LENGTH_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_RESERVED_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_LISTENER_COOKIE_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_CLIENT_ADDRESS_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_ORIGINAL_DESTINATION_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_UDP_PAYLOAD_IDENTITY_FIELD,
        ] {
            update_wire_field_digest(digest, field);
        }
        for field in [
            ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_EVENT_COUNT_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_TERMINAL_RESERVED_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_HIGH_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_COOKIE_LOW_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_FAMILY_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_RESERVED_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_PORT_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_ADDRESS_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_SOCKET_IPV4_ADDRESS_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_KIND_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_RESERVED_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_LENGTH_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_WIRE_DIGEST_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TRANSACTION_ID_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_TCP_LENGTH_FIELD,
            ENGINE_SUPERVISED_DELIVERY_REPORT_PAYLOAD_QUESTION_DIGEST_FIELD,
        ] {
            update_wire_field_digest(digest, field);
        }
    }
}

fn update_wire_field_digest(digest: &mut Sha256, field: EngineSupervisedDeliveryReportWireField) {
    let offset = u16::try_from(field.offset()).expect("schema-v1 wire offset fits u16");
    let bytes = u16::try_from(field.bytes()).expect("schema-v1 wire field size fits u16");
    update_length_prefixed(digest, &offset.to_be_bytes());
    update_length_prefixed(digest, &bytes.to_be_bytes());
}

fn update_length_prefixed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(length_bytes(bytes.len()));
    digest.update(bytes);
}
