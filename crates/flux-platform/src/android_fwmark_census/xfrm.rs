use std::error::Error;
use std::fmt;
use std::time::Duration;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::time::Instant;

use flux_core::{
    FwmarkCensusCoverageRecord, FwmarkCensusCoverageState, FwmarkEvidenceSource, FwmarkPlane,
    FwmarkUseOperation, FwmarkUseRecord, MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
};
use sha2::{Digest, Sha256};

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::read_only_netlink::collect_read_only_netlink_dump;
use super::read_only_netlink::{
    ReadOnlyNetlinkError, ReadOnlyNetlinkErrorKind, ReadOnlyNetlinkMessage, validate_bound,
};
use crate::netlink::NetlinkAttributeIter;

const XFRM_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
    b"Flux privacy-reduced XFRM fwmark snapshot\0canonical-schema-v1\0sha256-v1\0";
const XFRM_MSG_NEWSA: u16 = 0x10;
const XFRM_MSG_GETSA: u16 = 0x12;
const XFRM_MSG_NEWPOLICY: u16 = 0x13;
const XFRM_MSG_GETPOLICY: u16 = 0x15;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_DUMP: u16 = 0x0300;
const NETLINK_HEADER_BYTES: usize = 16;
const XFRM_USERSA_ID_BYTES: usize = 24;
const XFRM_USERPOLICY_ID_BYTES: usize = 64;
const XFRM_USERSA_INFO_BYTES: usize = 224;
const XFRM_USERPOLICY_INFO_BYTES: usize = 168;
const XFRMA_MARK: u16 = 21;
const XFRMA_SET_MARK: u16 = 29;
const XFRMA_SET_MARK_MASK: u16 = 30;
const XFRMA_MAX_MODELED: u16 = 41;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AndroidXfrmSnapshotDigest([u8; 32]);

impl AndroidXfrmSnapshotDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Bounded XFRM evidence that retains counts and mark masks, never selectors or endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidXfrmFwmarkObservation {
    digest: AndroidXfrmSnapshotDigest,
    kernel_supported: bool,
    coverage: [FwmarkCensusCoverageRecord; 3],
    mark_uses: Box<[FwmarkUseRecord]>,
    state_count: usize,
    policy_count: usize,
    mark_attribute_count: usize,
    opaque_attribute_count: usize,
}

impl AndroidXfrmFwmarkObservation {
    #[must_use]
    pub const fn digest(&self) -> AndroidXfrmSnapshotDigest {
        self.digest
    }

    #[must_use]
    pub const fn kernel_supported(&self) -> bool {
        self.kernel_supported
    }

    #[must_use]
    pub fn coverage(&self) -> &[FwmarkCensusCoverageRecord] {
        &self.coverage
    }

    #[must_use]
    pub fn mark_uses(&self) -> &[FwmarkUseRecord] {
        &self.mark_uses
    }

    #[must_use]
    pub const fn state_count(&self) -> usize {
        self.state_count
    }

    #[must_use]
    pub const fn policy_count(&self) -> usize {
        self.policy_count
    }

    #[must_use]
    pub const fn mark_attribute_count(&self) -> usize {
        self.mark_attribute_count
    }

    #[must_use]
    pub const fn opaque_attribute_count(&self) -> usize {
        self.opaque_attribute_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidXfrmFwmarkObservationErrorKind {
    InvalidBound,
    Transport,
    SnapshotDrift,
    InvalidMessageType,
    InvalidMessageLength,
    InvalidAttribute,
    LimitExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidXfrmFwmarkObservationError {
    kind: AndroidXfrmFwmarkObservationErrorKind,
    raw_os_error: Option<i32>,
}

impl AndroidXfrmFwmarkObservationError {
    const fn new(kind: AndroidXfrmFwmarkObservationErrorKind) -> Self {
        Self {
            kind,
            raw_os_error: None,
        }
    }

    const fn transport(source: ReadOnlyNetlinkError) -> Self {
        let kind = match source.kind() {
            ReadOnlyNetlinkErrorKind::InvalidBound => {
                AndroidXfrmFwmarkObservationErrorKind::InvalidBound
            }
            ReadOnlyNetlinkErrorKind::ConcurrentNotification
            | ReadOnlyNetlinkErrorKind::DumpInterrupted => {
                AndroidXfrmFwmarkObservationErrorKind::SnapshotDrift
            }
            ReadOnlyNetlinkErrorKind::LimitExceeded
            | ReadOnlyNetlinkErrorKind::TruncatedDatagram => {
                AndroidXfrmFwmarkObservationErrorKind::LimitExceeded
            }
            ReadOnlyNetlinkErrorKind::SystemCall
            | ReadOnlyNetlinkErrorKind::Timeout
            | ReadOnlyNetlinkErrorKind::ShortWrite
            | ReadOnlyNetlinkErrorKind::UnexpectedSender
            | ReadOnlyNetlinkErrorKind::MalformedDatagram
            | ReadOnlyNetlinkErrorKind::KernelRejected => {
                AndroidXfrmFwmarkObservationErrorKind::Transport
            }
        };
        Self {
            kind,
            raw_os_error: source.raw_os_error(),
        }
    }

    #[must_use]
    pub const fn kind(self) -> AndroidXfrmFwmarkObservationErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn raw_os_error(self) -> Option<i32> {
        self.raw_os_error
    }
}

impl fmt::Display for AndroidXfrmFwmarkObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "XFRM fwmark observation failed: {:?}", self.kind)?;
        if let Some(raw_os_error) = self.raw_os_error {
            write!(formatter, " (errno {raw_os_error})")?;
        }
        Ok(())
    }
}

impl Error for AndroidXfrmFwmarkObservationError {}

/// Collects XFRM state and policy dumps inside one caller-supplied wall-clock bound.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn collect_android_xfrm_fwmarks(
    bound: Duration,
) -> Result<AndroidXfrmFwmarkObservation, AndroidXfrmFwmarkObservationError> {
    validate_bound(bound).map_err(AndroidXfrmFwmarkObservationError::transport)?;
    let started = Instant::now();
    let state_request = dump_request::<XFRM_USERSA_ID_BYTES>(XFRM_MSG_GETSA, 1);
    let states =
        match collect_read_only_netlink_dump(libc::NETLINK_XFRM, 0, &state_request, 1, bound) {
            Ok(messages) => messages,
            Err(error) if is_unsupported(error) => return Ok(absent_observation(false)),
            Err(error) => return Err(AndroidXfrmFwmarkObservationError::transport(error)),
        };
    let remaining = bound.checked_sub(started.elapsed()).ok_or_else(|| {
        AndroidXfrmFwmarkObservationError::new(AndroidXfrmFwmarkObservationErrorKind::Transport)
    })?;
    validate_bound(remaining).map_err(AndroidXfrmFwmarkObservationError::transport)?;
    let policy_request = dump_request::<XFRM_USERPOLICY_ID_BYTES>(XFRM_MSG_GETPOLICY, 1);
    let policies =
        collect_read_only_netlink_dump(libc::NETLINK_XFRM, 0, &policy_request, 1, remaining)
            .map_err(AndroidXfrmFwmarkObservationError::transport)?;
    observe_android_xfrm_messages(&states, &policies, true)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn is_unsupported(error: ReadOnlyNetlinkError) -> bool {
    error.kind() == ReadOnlyNetlinkErrorKind::KernelRejected
        && matches!(
            error.raw_os_error(),
            Some(libc::EOPNOTSUPP) | Some(libc::EPROTONOSUPPORT) | Some(libc::ENOENT)
        )
}

fn dump_request<const PAYLOAD: usize>(message_type: u16, sequence: u32) -> Vec<u8> {
    let mut request = vec![0_u8; NETLINK_HEADER_BYTES + PAYLOAD];
    request[..4].copy_from_slice(&((NETLINK_HEADER_BYTES + PAYLOAD) as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&message_type.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    request
}

fn observe_android_xfrm_messages(
    states: &[ReadOnlyNetlinkMessage],
    policies: &[ReadOnlyNetlinkMessage],
    kernel_supported: bool,
) -> Result<AndroidXfrmFwmarkObservation, AndroidXfrmFwmarkObservationError> {
    let mut digest = Sha256::new();
    digest.update(XFRM_SNAPSHOT_DIGEST_DOMAIN);
    digest.update([u8::from(kernel_supported)]);
    digest_usize(&mut digest, states.len());
    digest_usize(&mut digest, policies.len());
    let mut mark_uses = Vec::new();
    let mut mark_attribute_count = 0_usize;
    let mut opaque_attribute_count = 0_usize;

    for (kind, messages, expected_type, fixed_bytes) in [
        (0_u8, states, XFRM_MSG_NEWSA, XFRM_USERSA_INFO_BYTES),
        (
            1_u8,
            policies,
            XFRM_MSG_NEWPOLICY,
            XFRM_USERPOLICY_INFO_BYTES,
        ),
    ] {
        for (ordinal, message) in messages.iter().enumerate() {
            if message.message_type() != expected_type {
                return Err(AndroidXfrmFwmarkObservationError::new(
                    AndroidXfrmFwmarkObservationErrorKind::InvalidMessageType,
                ));
            }
            if message.payload().len() < fixed_bytes {
                return Err(AndroidXfrmFwmarkObservationError::new(
                    AndroidXfrmFwmarkObservationErrorKind::InvalidMessageLength,
                ));
            }
            digest.update([kind]);
            digest_usize(&mut digest, ordinal);
            let projection = parse_attributes(&message.payload()[fixed_bytes..])?;
            mark_attribute_count = mark_attribute_count
                .checked_add(projection.mark_attribute_count)
                .ok_or_else(limit_error)?;
            opaque_attribute_count = opaque_attribute_count
                .checked_add(projection.opaque_attribute_count)
                .ok_or_else(limit_error)?;
            digest_usize(&mut digest, projection.mark_attribute_count);
            digest_usize(&mut digest, projection.opaque_attribute_count);
            digest.update(projection.opaque_digest);
            for mark_use in projection.mark_uses {
                if mark_uses.len() == MAX_COMPLETE_FWMARK_CENSUS_MARK_USES {
                    return Err(limit_error());
                }
                digest.update([operation_tag(mark_use.operation())]);
                digest.update(mark_use.mask().to_be_bytes());
                mark_uses.push(mark_use);
            }
        }
    }

    let packet_state = if opaque_attribute_count != 0 {
        FwmarkCensusCoverageState::Opaque
    } else if mark_uses.is_empty() {
        FwmarkCensusCoverageState::CompleteAbsent
    } else {
        FwmarkCensusCoverageState::CompletePresent
    };
    let coverage = [
        FwmarkCensusCoverageRecord::new(
            FwmarkEvidenceSource::Xfrm,
            FwmarkPlane::Packet,
            packet_state,
        ),
        FwmarkCensusCoverageRecord::new(
            FwmarkEvidenceSource::Xfrm,
            FwmarkPlane::Socket,
            FwmarkCensusCoverageState::CompleteAbsent,
        ),
        FwmarkCensusCoverageRecord::new(
            FwmarkEvidenceSource::Xfrm,
            FwmarkPlane::Conntrack,
            FwmarkCensusCoverageState::CompleteAbsent,
        ),
    ];
    Ok(AndroidXfrmFwmarkObservation {
        digest: AndroidXfrmSnapshotDigest(digest.finalize().into()),
        kernel_supported,
        coverage,
        mark_uses: mark_uses.into_boxed_slice(),
        state_count: states.len(),
        policy_count: policies.len(),
        mark_attribute_count,
        opaque_attribute_count,
    })
}

fn absent_observation(kernel_supported: bool) -> AndroidXfrmFwmarkObservation {
    observe_android_xfrm_messages(&[], &[], kernel_supported)
        .expect("empty XFRM snapshots are always complete absence")
}

struct AttributeProjection {
    mark_uses: Vec<FwmarkUseRecord>,
    mark_attribute_count: usize,
    opaque_attribute_count: usize,
    opaque_digest: [u8; 32],
}

fn parse_attributes(
    attributes: &[u8],
) -> Result<AttributeProjection, AndroidXfrmFwmarkObservationError> {
    let mut selector = None;
    let mut set_value = None;
    let mut set_mask = None;
    let mut opaque_attribute_count = 0_usize;
    let mut opaque_digest = Sha256::new();
    for attribute in NetlinkAttributeIter::new(attributes, 0) {
        let attribute = attribute.map_err(|_| invalid_attribute())?;
        if attribute.flags() != 0 {
            return Err(invalid_attribute());
        }
        match attribute.attribute_type() {
            XFRMA_MARK => {
                if attribute.value().len() != 8 || selector.is_some() {
                    return Err(invalid_attribute());
                }
                selector = Some((
                    native_u32(&attribute.value()[..4]),
                    native_u32(&attribute.value()[4..]),
                ));
            }
            XFRMA_SET_MARK => {
                if attribute.value().len() != 4 || set_value.is_some() {
                    return Err(invalid_attribute());
                }
                set_value = Some(native_u32(attribute.value()));
            }
            XFRMA_SET_MARK_MASK => {
                if attribute.value().len() != 4 || set_mask.is_some() {
                    return Err(invalid_attribute());
                }
                set_mask = Some(native_u32(attribute.value()));
            }
            kind if kind > XFRMA_MAX_MODELED => {
                opaque_attribute_count = opaque_attribute_count
                    .checked_add(1)
                    .ok_or_else(limit_error)?;
                opaque_digest.update(kind.to_be_bytes());
                digest_usize(&mut opaque_digest, attribute.value().len());
            }
            _ => {}
        }
    }
    if set_mask.is_some() && set_value.is_none() {
        return Err(invalid_attribute());
    }

    let mut mark_uses = Vec::new();
    let mut mark_attribute_count = 0_usize;
    if let Some((_value, mask)) = selector {
        mark_attribute_count += 1;
        if mask != 0 {
            mark_uses.push(mark_use(FwmarkUseOperation::PredicateRead, mask));
        }
    }
    if let Some(value) = set_value {
        mark_attribute_count += 1 + usize::from(set_mask.is_some());
        let effective_mask = set_mask.unwrap_or(u32::MAX) | value;
        if effective_mask != 0 {
            mark_uses.push(mark_use(FwmarkUseOperation::MaskedWrite, effective_mask));
        }
    }
    Ok(AttributeProjection {
        mark_uses,
        mark_attribute_count,
        opaque_attribute_count,
        opaque_digest: opaque_digest.finalize().into(),
    })
}

fn native_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes[..4].try_into().expect("validated native u32"))
}

fn mark_use(operation: FwmarkUseOperation, mask: u32) -> FwmarkUseRecord {
    FwmarkUseRecord::new(
        FwmarkEvidenceSource::Xfrm,
        FwmarkPlane::Packet,
        operation,
        mask,
    )
    .expect("XFRM caller filters zero masks")
}

fn operation_tag(operation: FwmarkUseOperation) -> u8 {
    match operation {
        FwmarkUseOperation::PredicateRead => 0,
        FwmarkUseOperation::MaskedWrite => 1,
        FwmarkUseOperation::TransferRead => 2,
        FwmarkUseOperation::TransferWrite => 3,
    }
}

fn invalid_attribute() -> AndroidXfrmFwmarkObservationError {
    AndroidXfrmFwmarkObservationError::new(AndroidXfrmFwmarkObservationErrorKind::InvalidAttribute)
}

fn limit_error() -> AndroidXfrmFwmarkObservationError {
    AndroidXfrmFwmarkObservationError::new(AndroidXfrmFwmarkObservationErrorKind::LimitExceeded)
}

fn digest_usize(digest: &mut Sha256, value: usize) {
    digest.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires XFRM dump permission in the current network namespace"]
    fn privileged_native_xfrm_dump_smoke() {
        collect_android_xfrm_fwmarks(Duration::from_secs(2)).expect("collect native XFRM state");
    }

    #[test]
    fn privacy_reduced_projection_retains_only_counts_and_mark_masks() {
        let mut state_payload = vec![0x7a; XFRM_USERSA_INFO_BYTES];
        state_payload.extend(nla(XFRMA_MARK, &mark(0x1234, 0xffff)));
        let mut policy_payload = vec![0x5c; XFRM_USERPOLICY_INFO_BYTES];
        policy_payload.extend(nla(XFRMA_SET_MARK, &0x0100_0000_u32.to_ne_bytes()));
        policy_payload.extend(nla(XFRMA_SET_MARK_MASK, &0x0300_0000_u32.to_ne_bytes()));
        let observation = observe_android_xfrm_messages(
            &[ReadOnlyNetlinkMessage::fixture(
                XFRM_MSG_NEWSA,
                0,
                state_payload,
            )],
            &[ReadOnlyNetlinkMessage::fixture(
                XFRM_MSG_NEWPOLICY,
                0,
                policy_payload,
            )],
            true,
        )
        .unwrap();
        assert_eq!(observation.state_count(), 1);
        assert_eq!(observation.policy_count(), 1);
        assert_eq!(observation.mark_attribute_count(), 3);
        assert_eq!(observation.opaque_attribute_count(), 0);
        assert_eq!(
            observation.mark_uses(),
            [
                mark_use(FwmarkUseOperation::PredicateRead, 0xffff),
                mark_use(FwmarkUseOperation::MaskedWrite, 0x0300_0000),
            ]
        );
        assert_eq!(
            observation.coverage()[0].state(),
            FwmarkCensusCoverageState::CompletePresent
        );
        assert!(
            observation.coverage()[1..]
                .iter()
                .all(|record| { record.state() == FwmarkCensusCoverageState::CompleteAbsent })
        );
    }

    #[test]
    fn endpoints_do_not_enter_the_canonical_sanitized_digest() {
        let first = vec![0x11; XFRM_USERSA_INFO_BYTES];
        let second = vec![0xee; XFRM_USERSA_INFO_BYTES];
        let first = observe_android_xfrm_messages(
            &[ReadOnlyNetlinkMessage::fixture(XFRM_MSG_NEWSA, 0, first)],
            &[],
            true,
        )
        .unwrap();
        let second = observe_android_xfrm_messages(
            &[ReadOnlyNetlinkMessage::fixture(XFRM_MSG_NEWSA, 0, second)],
            &[],
            true,
        )
        .unwrap();
        assert_eq!(first.digest(), second.digest());
    }

    #[test]
    fn zero_masks_emit_no_false_use_and_value_bits_expand_write_mask() {
        let mut zero = vec![0; XFRM_USERSA_INFO_BYTES];
        zero.extend(nla(XFRMA_MARK, &mark(0, 0)));
        let observation = observe_android_xfrm_messages(
            &[ReadOnlyNetlinkMessage::fixture(XFRM_MSG_NEWSA, 0, zero)],
            &[],
            true,
        )
        .unwrap();
        assert!(observation.mark_uses().is_empty());
        assert_eq!(
            observation.coverage()[0].state(),
            FwmarkCensusCoverageState::CompleteAbsent
        );

        let mut write = vec![0; XFRM_USERPOLICY_INFO_BYTES];
        write.extend(nla(XFRMA_SET_MARK, &0x30_u32.to_ne_bytes()));
        write.extend(nla(XFRMA_SET_MARK_MASK, &0x0f_u32.to_ne_bytes()));
        let observation = observe_android_xfrm_messages(
            &[],
            &[ReadOnlyNetlinkMessage::fixture(
                XFRM_MSG_NEWPOLICY,
                0,
                write,
            )],
            true,
        )
        .unwrap();
        assert_eq!(observation.mark_uses()[0].mask(), 0x3f);
    }

    #[test]
    fn unknown_attributes_are_opaque_without_exposing_their_payload() {
        let mut payload = vec![0; XFRM_USERSA_INFO_BYTES];
        payload.extend(nla(XFRMA_MAX_MODELED + 1, b"private-endpoint-like-bytes"));
        let observation = observe_android_xfrm_messages(
            &[ReadOnlyNetlinkMessage::fixture(XFRM_MSG_NEWSA, 0, payload)],
            &[],
            true,
        )
        .unwrap();
        assert_eq!(observation.opaque_attribute_count(), 1);
        assert_eq!(
            observation.coverage()[0].state(),
            FwmarkCensusCoverageState::Opaque
        );

        let mut replacement = vec![0; XFRM_USERSA_INFO_BYTES];
        replacement.extend(nla(XFRMA_MAX_MODELED + 1, b"changed-endpoint-like-bytes"));
        let replacement = observe_android_xfrm_messages(
            &[ReadOnlyNetlinkMessage::fixture(
                XFRM_MSG_NEWSA,
                0,
                replacement,
            )],
            &[],
            true,
        )
        .unwrap();
        assert_eq!(observation.digest(), replacement.digest());
    }

    #[test]
    fn malformed_duplicate_and_orphan_mark_attributes_fail_closed() {
        let mut duplicate = vec![0; XFRM_USERSA_INFO_BYTES];
        duplicate.extend(nla(XFRMA_MARK, &mark(1, 1)));
        duplicate.extend(nla(XFRMA_MARK, &mark(2, 2)));
        let mut orphan = vec![0; XFRM_USERPOLICY_INFO_BYTES];
        orphan.extend(nla(XFRMA_SET_MARK_MASK, &1_u32.to_ne_bytes()));
        for (states, policies) in [
            (
                vec![ReadOnlyNetlinkMessage::fixture(
                    XFRM_MSG_NEWSA,
                    0,
                    duplicate,
                )],
                Vec::new(),
            ),
            (
                Vec::new(),
                vec![ReadOnlyNetlinkMessage::fixture(
                    XFRM_MSG_NEWPOLICY,
                    0,
                    orphan,
                )],
            ),
        ] {
            assert_eq!(
                observe_android_xfrm_messages(&states, &policies, true)
                    .unwrap_err()
                    .kind(),
                AndroidXfrmFwmarkObservationErrorKind::InvalidAttribute
            );
        }
    }

    #[test]
    fn request_layout_uses_exact_dump_type_sequence_and_fixed_payload() {
        let state = dump_request::<XFRM_USERSA_ID_BYTES>(XFRM_MSG_GETSA, 7);
        assert_eq!(state.len(), NETLINK_HEADER_BYTES + XFRM_USERSA_ID_BYTES);
        assert_eq!(
            u16::from_ne_bytes(state[4..6].try_into().unwrap()),
            XFRM_MSG_GETSA
        );
        assert_eq!(u32::from_ne_bytes(state[8..12].try_into().unwrap()), 7);
        assert!(state[NETLINK_HEADER_BYTES..].iter().all(|byte| *byte == 0));
    }

    fn mark(value: u32, mask: u32) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&value.to_ne_bytes());
        bytes[4..].copy_from_slice(&mask.to_ne_bytes());
        bytes
    }

    fn nla(attribute_type: u16, value: &[u8]) -> Vec<u8> {
        let length = 4 + value.len();
        let aligned = (length + 3) & !3;
        let mut bytes = vec![0_u8; aligned];
        bytes[..2].copy_from_slice(&(length as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&attribute_type.to_ne_bytes());
        bytes[4..length].copy_from_slice(value);
        bytes
    }
}
