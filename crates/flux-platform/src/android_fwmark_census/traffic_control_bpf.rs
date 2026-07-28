use std::error::Error;
use std::fmt;
use std::time::Duration;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::time::Instant;

use flux_core::{
    FwmarkCensusCoverageRecord, FwmarkCensusCoverageState, FwmarkEvidenceSource, FwmarkPlane,
    FwmarkUseRecord,
};
use sha2::{Digest, Sha256};

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::read_only_netlink::collect_read_only_netlink_dump;
use super::read_only_netlink::{
    ReadOnlyNetlinkError, ReadOnlyNetlinkErrorKind, ReadOnlyNetlinkMessage, validate_bound,
};
use crate::netlink::NetlinkAttributeIter;

const BPF_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
    b"Flux loaded BPF fwmark census\0canonical-schema-v1\0sha256-v1\0";
const BPF_PROGRAM_DIGEST_DOMAIN: &[u8] =
    b"Flux exact xlated BPF program\0canonical-schema-v1\0sha256-v1\0";
const TC_FILTER_IDENTITY_DIGEST_DOMAIN: &[u8] =
    b"Flux TC filter identity\0canonical-schema-v1\0sha256-v1\0";
const BPF_INSTRUCTION_BYTES: usize = 8;
const MAX_BPF_PROGRAMS: usize = 65_536;
const MAX_BPF_PROGRAM_BYTES: usize = 1024 * 1024;
const MAX_BPF_TOTAL_BYTES: usize = 16 * 1024 * 1024;

const BPF_PROG_GET_NEXT_ID: u32 = 11;
const BPF_PROG_GET_FD_BY_ID: u32 = 13;
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;

const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
const BPF_PROG_TYPE_KPROBE: u32 = 2;
const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
const BPF_PROG_TYPE_SCHED_ACT: u32 = 4;
const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;
const BPF_PROG_TYPE_XDP: u32 = 6;
const BPF_PROG_TYPE_PERF_EVENT: u32 = 7;
const BPF_PROG_TYPE_CGROUP_SKB: u32 = 8;
const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
const BPF_PROG_TYPE_LWT_IN: u32 = 10;
const BPF_PROG_TYPE_LWT_OUT: u32 = 11;
const BPF_PROG_TYPE_LWT_XMIT: u32 = 12;
const BPF_PROG_TYPE_SOCK_OPS: u32 = 13;
const BPF_PROG_TYPE_SK_SKB: u32 = 14;
const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
const BPF_PROG_TYPE_SK_MSG: u32 = 16;
const BPF_PROG_TYPE_RAW_TRACEPOINT: u32 = 17;
const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
const BPF_PROG_TYPE_LWT_SEG6LOCAL: u32 = 19;
const BPF_PROG_TYPE_LIRC_MODE2: u32 = 20;
const BPF_PROG_TYPE_SK_REUSEPORT: u32 = 21;
const BPF_PROG_TYPE_FLOW_DISSECTOR: u32 = 22;
const BPF_PROG_TYPE_CGROUP_SYSCTL: u32 = 23;
const BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: u32 = 24;
const BPF_PROG_TYPE_CGROUP_SOCKOPT: u32 = 25;
const BPF_PROG_TYPE_TRACING: u32 = 26;
const BPF_PROG_TYPE_STRUCT_OPS: u32 = 27;
const BPF_PROG_TYPE_EXT: u32 = 28;
const BPF_PROG_TYPE_LSM: u32 = 29;
const BPF_PROG_TYPE_SK_LOOKUP: u32 = 30;
const BPF_PROG_TYPE_SYSCALL: u32 = 31;
const BPF_PROG_TYPE_NETFILTER: u32 = 32;

const RTM_NEWTFILTER: u16 = 44;
const RTM_GETTFILTER: u16 = 46;
const RTMGRP_TC: u32 = 8;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_DUMP: u16 = 0x0300;
const NETLINK_HEADER_BYTES: usize = 16;
const TC_MESSAGE_BYTES: usize = 20;
const TC_FILTER_DUMP_REQUEST_BYTES: usize = NETLINK_HEADER_BYTES + TC_MESSAGE_BYTES;
const TCA_KIND: u16 = 1;

const ALL_PLANES: [FwmarkPlane; 3] = [
    FwmarkPlane::Packet,
    FwmarkPlane::Socket,
    FwmarkPlane::Conntrack,
];

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AndroidTrafficControlBpfSnapshotDigest([u8; 32]);

impl AndroidTrafficControlBpfSnapshotDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Privacy-reduced projection of TC filters and every loaded BPF program in the kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidTrafficControlBpfFwmarkObservation {
    digest: AndroidTrafficControlBpfSnapshotDigest,
    coverage: [FwmarkCensusCoverageRecord; ALL_PLANES.len()],
    mark_uses: Box<[FwmarkUseRecord]>,
    attached_traffic_control_filter_count: usize,
    loaded_program_count: usize,
    relevant_program_count: usize,
    inaccessible_program_count: usize,
    opaque_program_count: usize,
    instruction_count: usize,
}

impl AndroidTrafficControlBpfFwmarkObservation {
    #[must_use]
    pub const fn digest(&self) -> AndroidTrafficControlBpfSnapshotDigest {
        self.digest
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
    pub const fn attached_traffic_control_filter_count(&self) -> usize {
        self.attached_traffic_control_filter_count
    }

    #[must_use]
    pub const fn loaded_program_count(&self) -> usize {
        self.loaded_program_count
    }

    #[must_use]
    pub const fn relevant_program_count(&self) -> usize {
        self.relevant_program_count
    }

    #[must_use]
    pub const fn inaccessible_program_count(&self) -> usize {
        self.inaccessible_program_count
    }

    #[must_use]
    pub const fn opaque_program_count(&self) -> usize {
        self.opaque_program_count
    }

    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instruction_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidTrafficControlBpfFwmarkObservationErrorKind {
    InvalidBound,
    Denied,
    Unsupported,
    Timeout,
    SystemCall,
    SnapshotDrift,
    InvalidTrafficControlInfo,
    InvalidProgramInfo,
    LimitExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidTrafficControlBpfFwmarkObservationError {
    kind: AndroidTrafficControlBpfFwmarkObservationErrorKind,
    raw_os_error: Option<i32>,
}

impl AndroidTrafficControlBpfFwmarkObservationError {
    const fn new(kind: AndroidTrafficControlBpfFwmarkObservationErrorKind) -> Self {
        Self {
            kind,
            raw_os_error: None,
        }
    }

    const fn os(kind: AndroidTrafficControlBpfFwmarkObservationErrorKind, errno: i32) -> Self {
        Self {
            kind,
            raw_os_error: Some(errno),
        }
    }

    #[must_use]
    pub const fn kind(self) -> AndroidTrafficControlBpfFwmarkObservationErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn raw_os_error(self) -> Option<i32> {
        self.raw_os_error
    }
}

impl fmt::Display for AndroidTrafficControlBpfFwmarkObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "TC/BPF fwmark observation failed: {:?}",
            self.kind
        )?;
        if let Some(errno) = self.raw_os_error {
            write!(formatter, " (errno {errno})")?;
        }
        Ok(())
    }
}

impl Error for AndroidTrafficControlBpfFwmarkObservationError {}

impl AndroidTrafficControlBpfFwmarkObservationError {
    const fn transport(source: ReadOnlyNetlinkError) -> Self {
        let kind = match source.kind() {
            ReadOnlyNetlinkErrorKind::InvalidBound => {
                AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidBound
            }
            ReadOnlyNetlinkErrorKind::Timeout => {
                AndroidTrafficControlBpfFwmarkObservationErrorKind::Timeout
            }
            ReadOnlyNetlinkErrorKind::ConcurrentNotification
            | ReadOnlyNetlinkErrorKind::DumpInterrupted => {
                AndroidTrafficControlBpfFwmarkObservationErrorKind::SnapshotDrift
            }
            ReadOnlyNetlinkErrorKind::LimitExceeded
            | ReadOnlyNetlinkErrorKind::TruncatedDatagram => {
                AndroidTrafficControlBpfFwmarkObservationErrorKind::LimitExceeded
            }
            ReadOnlyNetlinkErrorKind::SystemCall
            | ReadOnlyNetlinkErrorKind::ShortWrite
            | ReadOnlyNetlinkErrorKind::UnexpectedSender
            | ReadOnlyNetlinkErrorKind::MalformedDatagram
            | ReadOnlyNetlinkErrorKind::KernelRejected => {
                AndroidTrafficControlBpfFwmarkObservationErrorKind::SystemCall
            }
        };
        Self {
            kind,
            raw_os_error: source.raw_os_error(),
        }
    }
}

/// Collects TC attachment presence and a conservative superset of networking BPF programs.
///
/// The kernel-global loaded-program set covers eBPF attachment mechanisms without trusting program
/// names or filesystem pins. A subscribed TC filter dump separately prevents classic BPF and
/// non-BPF classifiers/actions from creating false absence. Loaded but detached programs can cause
/// conservative false positives. The kernel exports verifier-rewritten, not original, instructions;
/// relevant programs therefore remain opaque until a reviewed exact-artifact interpretation exists.
/// Identical TC identities and program-ID passes around exact instruction retrieval reject relevant
/// endpoint drift.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn collect_android_traffic_control_bpf_fwmarks(
    bound: Duration,
) -> Result<AndroidTrafficControlBpfFwmarkObservation, AndroidTrafficControlBpfFwmarkObservationError>
{
    validate_bound(bound).map_err(|_| {
        AndroidTrafficControlBpfFwmarkObservationError::new(
            AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidBound,
        )
    })?;
    let deadline = Instant::now().checked_add(bound).ok_or_else(|| {
        AndroidTrafficControlBpfFwmarkObservationError::new(
            AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidBound,
        )
    })?;
    let traffic_control_before = implementation::collect_traffic_control_filters(deadline)?;
    let program_ids_before = implementation::enumerate_program_ids(deadline)?;
    let mut programs = Vec::with_capacity(program_ids_before.len());
    let mut program_fds = Vec::with_capacity(program_ids_before.len());
    let mut total_bytes = 0_usize;
    for id in &program_ids_before {
        let (program, program_fd) = implementation::read_program(*id, deadline)?;
        total_bytes = total_bytes
            .checked_add(program.instruction_bytes())
            .ok_or_else(limit_error)?;
        if total_bytes > MAX_BPF_TOTAL_BYTES {
            return Err(limit_error());
        }
        programs.push(program);
        if let Some(program_fd) = program_fd {
            program_fds.push(program_fd);
        }
    }
    let program_ids_after = implementation::enumerate_program_ids(deadline)?;
    let traffic_control_after = implementation::collect_traffic_control_filters(deadline)?;
    if program_ids_before != program_ids_after || traffic_control_before != traffic_control_after {
        return Err(AndroidTrafficControlBpfFwmarkObservationError::new(
            AndroidTrafficControlBpfFwmarkObservationErrorKind::SnapshotDrift,
        ));
    }
    implementation::ensure_before(deadline)?;
    let observation = observe_programs(&programs, &traffic_control_before)?;
    implementation::ensure_before(deadline)?;
    drop(program_fds);
    Ok(observation)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrafficControlFilterSnapshot {
    identities: Box<[Box<[u8]>]>,
}

impl TrafficControlFilterSnapshot {
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            identities: Box::default(),
        }
    }

    fn filter_count(&self) -> usize {
        self.identities.len()
    }

    fn update_digest(&self, digest: &mut Sha256) {
        digest.update(TC_FILTER_IDENTITY_DIGEST_DOMAIN);
        digest_usize(digest, self.identities.len());
        for identity in &self.identities {
            digest_usize(digest, identity.len());
            digest.update(identity);
        }
    }
}

fn observe_traffic_control_messages(
    messages: &[ReadOnlyNetlinkMessage],
) -> Result<TrafficControlFilterSnapshot, AndroidTrafficControlBpfFwmarkObservationError> {
    let mut identities = Vec::with_capacity(messages.len());
    for message in messages {
        if message.message_type() != RTM_NEWTFILTER || message.payload().len() < TC_MESSAGE_BYTES {
            return Err(invalid_traffic_control_info());
        }
        let payload = message.payload();
        let mut kind = None;
        for attribute in NetlinkAttributeIter::new(&payload[TC_MESSAGE_BYTES..], TC_MESSAGE_BYTES) {
            let attribute = attribute.map_err(|_| invalid_traffic_control_info())?;
            if attribute.attribute_type() != TCA_KIND {
                continue;
            }
            if kind.is_some() || attribute.flags() != 0 {
                return Err(invalid_traffic_control_info());
            }
            let Some((&0, bytes)) = attribute.value().split_last() else {
                return Err(invalid_traffic_control_info());
            };
            if bytes.is_empty() || bytes.contains(&0) {
                return Err(invalid_traffic_control_info());
            }
            kind = Some(bytes);
        }
        let kind = kind.ok_or_else(invalid_traffic_control_info)?;
        let mut identity = Vec::with_capacity(TC_MESSAGE_BYTES + 8 + kind.len());
        identity.extend_from_slice(&payload[..TC_MESSAGE_BYTES]);
        identity.extend_from_slice(
            &u64::try_from(kind.len())
                .map_err(|_| limit_error())?
                .to_be_bytes(),
        );
        identity.extend_from_slice(kind);
        identities.push(identity.into_boxed_slice());
    }
    identities.sort_unstable();
    Ok(TrafficControlFilterSnapshot {
        identities: identities.into_boxed_slice(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProgramSnapshot {
    id: u32,
    program_type: Option<u32>,
    tag: Option<[u8; 8]>,
    instructions: Option<Box<[u8]>>,
}

impl ProgramSnapshot {
    fn inaccessible(id: u32) -> Self {
        Self {
            id,
            program_type: None,
            tag: None,
            instructions: None,
        }
    }

    fn exact(id: u32, program_type: u32, tag: [u8; 8], instructions: Vec<u8>) -> Self {
        Self {
            id,
            program_type: Some(program_type),
            tag: Some(tag),
            instructions: Some(instructions.into_boxed_slice()),
        }
    }

    fn instruction_bytes(&self) -> usize {
        self.instructions.as_deref().map_or(0, <[u8]>::len)
    }
}

fn observe_programs(
    programs: &[ProgramSnapshot],
    traffic_control: &TrafficControlFilterSnapshot,
) -> Result<AndroidTrafficControlBpfFwmarkObservation, AndroidTrafficControlBpfFwmarkObservationError>
{
    if programs.len() > MAX_BPF_PROGRAMS {
        return Err(limit_error());
    }
    let mut digest = Sha256::new();
    digest.update(BPF_SNAPSHOT_DIGEST_DOMAIN);
    traffic_control.update_digest(&mut digest);
    digest_usize(&mut digest, programs.len());
    let mut opaque_planes = [false; ALL_PLANES.len()];
    if traffic_control.filter_count() != 0 {
        opaque_planes[plane_index(FwmarkPlane::Packet)] = true;
        opaque_planes[plane_index(FwmarkPlane::Conntrack)] = true;
    }
    let mut relevant_program_count = 0_usize;
    let mut inaccessible_program_count = 0_usize;
    let mut opaque_program_count = 0_usize;
    let mut instruction_count = 0_usize;

    let mut previous_id = None;
    for program in programs {
        if program.id == 0 || previous_id.is_some_and(|previous| previous >= program.id) {
            return Err(AndroidTrafficControlBpfFwmarkObservationError::new(
                AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidProgramInfo,
            ));
        }
        previous_id = Some(program.id);
        digest.update(program.id.to_be_bytes());
        let Some(program_type) = program.program_type else {
            inaccessible_program_count += 1;
            opaque_program_count += 1;
            opaque_planes.fill(true);
            digest.update([0xff]);
            continue;
        };
        let Some(tag) = program.tag else {
            return Err(AndroidTrafficControlBpfFwmarkObservationError::new(
                AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidProgramInfo,
            ));
        };
        let Some(instructions) = program.instructions.as_deref() else {
            return Err(AndroidTrafficControlBpfFwmarkObservationError::new(
                AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidProgramInfo,
            ));
        };
        if instructions.is_empty()
            || instructions.len() > MAX_BPF_PROGRAM_BYTES
            || !instructions.len().is_multiple_of(BPF_INSTRUCTION_BYTES)
        {
            return Err(AndroidTrafficControlBpfFwmarkObservationError::new(
                AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidProgramInfo,
            ));
        }
        instruction_count = instruction_count
            .checked_add(instructions.len() / BPF_INSTRUCTION_BYTES)
            .ok_or_else(limit_error)?;
        digest.update([0]);
        digest.update(program_type.to_be_bytes());
        digest.update(tag);
        let mut program_digest = Sha256::new();
        program_digest.update(BPF_PROGRAM_DIGEST_DOMAIN);
        program_digest.update(instructions);
        digest.update(program_digest.finalize());

        // BPF_OBJ_GET_INFO_BY_FD exposes verifier-rewritten instructions. Context accesses use
        // private kernel-structure offsets and helper calls no longer carry UAPI helper IDs, so
        // these bytes are retained only as a digest and bounded count. Program types that can
        // reach a routing/capture mark plane remain opaque.
        if let Some(program_opaque_planes) = program_opaque_planes(program_type) {
            relevant_program_count += 1;
            opaque_program_count += 1;
            for (index, opaque) in program_opaque_planes.into_iter().enumerate() {
                opaque_planes[index] |= opaque;
            }
        }
    }

    let coverage = ALL_PLANES.map(|plane| {
        let index = plane_index(plane);
        let state = if opaque_planes[index] {
            FwmarkCensusCoverageState::Opaque
        } else {
            FwmarkCensusCoverageState::CompleteAbsent
        };
        FwmarkCensusCoverageRecord::new(FwmarkEvidenceSource::TrafficControlAndBpf, plane, state)
    });
    Ok(AndroidTrafficControlBpfFwmarkObservation {
        digest: AndroidTrafficControlBpfSnapshotDigest(digest.finalize().into()),
        coverage,
        mark_uses: Box::default(),
        attached_traffic_control_filter_count: traffic_control.filter_count(),
        loaded_program_count: programs.len(),
        relevant_program_count,
        inaccessible_program_count,
        opaque_program_count,
        instruction_count,
    })
}

#[cfg(test)]
pub(super) fn test_absent_observation() -> AndroidTrafficControlBpfFwmarkObservation {
    observe_programs(&[], &TrafficControlFilterSnapshot::empty())
        .expect("empty TC and BPF snapshots are complete absence")
}

fn program_opaque_planes(program_type: u32) -> Option<[bool; ALL_PLANES.len()]> {
    match program_type {
        BPF_PROG_TYPE_KPROBE
        | BPF_PROG_TYPE_TRACEPOINT
        | BPF_PROG_TYPE_XDP
        | BPF_PROG_TYPE_PERF_EVENT
        | BPF_PROG_TYPE_CGROUP_DEVICE
        | BPF_PROG_TYPE_RAW_TRACEPOINT
        | BPF_PROG_TYPE_LIRC_MODE2
        | BPF_PROG_TYPE_FLOW_DISSECTOR
        | BPF_PROG_TYPE_CGROUP_SYSCTL
        | BPF_PROG_TYPE_TRACING
        | BPF_PROG_TYPE_STRUCT_OPS
        | BPF_PROG_TYPE_LSM
        | BPF_PROG_TYPE_SYSCALL => None,
        BPF_PROG_TYPE_SCHED_CLS
        | BPF_PROG_TYPE_SCHED_ACT
        | BPF_PROG_TYPE_CGROUP_SKB
        | BPF_PROG_TYPE_LWT_IN
        | BPF_PROG_TYPE_LWT_OUT
        | BPF_PROG_TYPE_LWT_XMIT
        | BPF_PROG_TYPE_LWT_SEG6LOCAL
        | BPF_PROG_TYPE_NETFILTER => Some([true, false, true]),
        BPF_PROG_TYPE_CGROUP_SOCK
        | BPF_PROG_TYPE_SOCK_OPS
        | BPF_PROG_TYPE_SK_MSG
        | BPF_PROG_TYPE_CGROUP_SOCK_ADDR
        | BPF_PROG_TYPE_SK_REUSEPORT
        | BPF_PROG_TYPE_CGROUP_SOCKOPT
        | BPF_PROG_TYPE_SK_LOOKUP => Some([false, true, true]),
        BPF_PROG_TYPE_SOCKET_FILTER
        | BPF_PROG_TYPE_SK_SKB
        | BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
        | BPF_PROG_TYPE_EXT => Some([true; ALL_PLANES.len()]),
        _ => Some([true; ALL_PLANES.len()]),
    }
}

fn plane_index(plane: FwmarkPlane) -> usize {
    match plane {
        FwmarkPlane::Packet => 0,
        FwmarkPlane::Socket => 1,
        FwmarkPlane::Conntrack => 2,
    }
}

fn limit_error() -> AndroidTrafficControlBpfFwmarkObservationError {
    AndroidTrafficControlBpfFwmarkObservationError::new(
        AndroidTrafficControlBpfFwmarkObservationErrorKind::LimitExceeded,
    )
}

fn invalid_traffic_control_info() -> AndroidTrafficControlBpfFwmarkObservationError {
    AndroidTrafficControlBpfFwmarkObservationError::new(
        AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidTrafficControlInfo,
    )
}

fn digest_usize(digest: &mut Sha256, value: usize) {
    digest.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::io;
    use std::mem;
    use std::os::fd::{FromRawFd, OwnedFd};

    use super::*;

    #[derive(Clone, Copy, Debug, Default)]
    #[repr(C)]
    struct BpfGetIdAttr {
        start_or_program_id: u32,
        next_id: u32,
        open_flags: u32,
    }

    #[derive(Clone, Copy, Debug, Default)]
    #[repr(C)]
    struct BpfInfoAttr {
        bpf_fd: u32,
        info_len: u32,
        info: u64,
    }

    #[derive(Clone, Copy, Debug, Default)]
    #[repr(C, align(8))]
    struct BpfProgramInfoPrefix {
        program_type: u32,
        id: u32,
        tag: [u8; 8],
        jited_program_length: u32,
        xlated_program_length: u32,
        jited_program: u64,
        xlated_program: u64,
    }

    const _: () = assert!(mem::size_of::<BpfGetIdAttr>() == 12);
    const _: () = assert!(mem::size_of::<BpfInfoAttr>() == 16);
    const _: () = assert!(mem::size_of::<BpfProgramInfoPrefix>() == 40);

    pub(super) fn collect_traffic_control_filters(
        deadline: Instant,
    ) -> Result<TrafficControlFilterSnapshot, AndroidTrafficControlBpfFwmarkObservationError> {
        let mut request = [0_u8; TC_FILTER_DUMP_REQUEST_BYTES];
        request[..4].copy_from_slice(&(TC_FILTER_DUMP_REQUEST_BYTES as u32).to_ne_bytes());
        request[4..6].copy_from_slice(&RTM_GETTFILTER.to_ne_bytes());
        request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
        let messages = collect_read_only_netlink_dump(
            libc::NETLINK_ROUTE,
            RTMGRP_TC,
            &request,
            1,
            remaining_bound(deadline)?,
        )
        .map_err(AndroidTrafficControlBpfFwmarkObservationError::transport)?;
        ensure_before(deadline)?;
        let snapshot = observe_traffic_control_messages(&messages)?;
        ensure_before(deadline)?;
        Ok(snapshot)
    }

    pub(super) fn enumerate_program_ids(
        deadline: Instant,
    ) -> Result<Vec<u32>, AndroidTrafficControlBpfFwmarkObservationError> {
        let mut ids = Vec::new();
        let mut start_id = 0_u32;
        loop {
            ensure_before(deadline)?;
            let mut attributes = BpfGetIdAttr {
                start_or_program_id: start_id,
                ..BpfGetIdAttr::default()
            };
            match bpf_call(
                BPF_PROG_GET_NEXT_ID,
                std::ptr::from_mut(&mut attributes).cast(),
                mem::size_of::<BpfGetIdAttr>(),
                deadline,
            ) {
                Ok(_) => {}
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => break,
                Err(error)
                    if matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) =>
                {
                    return Err(AndroidTrafficControlBpfFwmarkObservationError::os(
                        AndroidTrafficControlBpfFwmarkObservationErrorKind::Denied,
                        error.raw_os_error().expect("matched access error"),
                    ));
                }
                Err(error) if error.raw_os_error() == Some(libc::ENOSYS) => {
                    return Err(AndroidTrafficControlBpfFwmarkObservationError::os(
                        AndroidTrafficControlBpfFwmarkObservationErrorKind::Unsupported,
                        libc::ENOSYS,
                    ));
                }
                Err(error) => return Err(error),
            }
            if attributes.next_id == 0 || attributes.next_id <= start_id {
                return Err(AndroidTrafficControlBpfFwmarkObservationError::new(
                    AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidProgramInfo,
                ));
            }
            if ids.len() == MAX_BPF_PROGRAMS {
                return Err(limit_error());
            }
            ids.push(attributes.next_id);
            start_id = attributes.next_id;
        }
        Ok(ids)
    }

    pub(super) fn read_program(
        id: u32,
        deadline: Instant,
    ) -> Result<(ProgramSnapshot, Option<OwnedFd>), AndroidTrafficControlBpfFwmarkObservationError>
    {
        let mut attributes = BpfGetIdAttr {
            start_or_program_id: id,
            ..BpfGetIdAttr::default()
        };
        let raw_fd = match bpf_call(
            BPF_PROG_GET_FD_BY_ID,
            std::ptr::from_mut(&mut attributes).cast(),
            mem::size_of::<BpfGetIdAttr>(),
            deadline,
        ) {
            Ok(raw_fd) => raw_fd,
            Err(error) if is_inaccessible(error) => {
                return Ok((ProgramSnapshot::inaccessible(id), None));
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                return Err(AndroidTrafficControlBpfFwmarkObservationError::new(
                    AndroidTrafficControlBpfFwmarkObservationErrorKind::SnapshotDrift,
                ));
            }
            Err(error) => return Err(error),
        };
        let raw_fd = i32::try_from(raw_fd).map_err(|_| invalid_info())?;
        // SAFETY: BPF_PROG_GET_FD_BY_ID returned one new owned descriptor on success.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let first = match read_info(&fd, None, deadline) {
            Ok(info) => info,
            Err(error) if is_inaccessible(error) => {
                return Ok((ProgramSnapshot::inaccessible(id), Some(fd)));
            }
            Err(error) => return Err(error),
        };
        let byte_count = usize::try_from(first.xlated_program_length).map_err(|_| limit_error())?;
        if first.id != id
            || first.program_type == 0
            || byte_count == 0
            || byte_count > MAX_BPF_PROGRAM_BYTES
            || !byte_count.is_multiple_of(BPF_INSTRUCTION_BYTES)
        {
            return Err(invalid_info());
        }
        let mut instructions = vec![0_u8; byte_count];
        let second = match read_info(&fd, Some(&mut instructions), deadline) {
            Ok(info) => info,
            Err(error) if is_inaccessible(error) => {
                return Ok((ProgramSnapshot::inaccessible(id), Some(fd)));
            }
            Err(error) => return Err(error),
        };
        if second.id != first.id
            || second.program_type != first.program_type
            || second.tag != first.tag
            || usize::try_from(second.xlated_program_length).ok() != Some(byte_count)
        {
            return Err(invalid_info());
        }
        Ok((
            ProgramSnapshot::exact(id, first.program_type, first.tag, instructions),
            Some(fd),
        ))
    }

    fn read_info(
        fd: &OwnedFd,
        instructions: Option<&mut [u8]>,
        deadline: Instant,
    ) -> Result<BpfProgramInfoPrefix, AndroidTrafficControlBpfFwmarkObservationError> {
        use std::os::fd::AsRawFd;

        let mut info = BpfProgramInfoPrefix::default();
        if let Some(instructions) = instructions {
            info.xlated_program_length =
                u32::try_from(instructions.len()).map_err(|_| limit_error())?;
            info.xlated_program = instructions.as_mut_ptr() as u64;
        }
        let mut attributes = BpfInfoAttr {
            bpf_fd: u32::try_from(fd.as_raw_fd()).map_err(|_| invalid_info())?,
            info_len: mem::size_of::<BpfProgramInfoPrefix>() as u32,
            info: std::ptr::from_mut(&mut info) as u64,
        };
        bpf_call(
            BPF_OBJ_GET_INFO_BY_FD,
            std::ptr::from_mut(&mut attributes).cast(),
            mem::size_of::<BpfInfoAttr>(),
            deadline,
        )?;
        if attributes.info_len < mem::size_of::<BpfProgramInfoPrefix>() as u32 {
            return Err(invalid_info());
        }
        Ok(info)
    }

    fn bpf_call(
        command: u32,
        attributes: *mut libc::c_void,
        size: usize,
        deadline: Instant,
    ) -> Result<libc::c_long, AndroidTrafficControlBpfFwmarkObservationError> {
        loop {
            ensure_before(deadline)?;
            // SAFETY: every caller supplies a writable command-specific attribute prefix with the
            // exact declared size. The kernel does not retain the pointer after the syscall.
            let result = unsafe { libc::syscall(libc::SYS_bpf, command, attributes, size) };
            if result >= 0 {
                ensure_before(deadline)?;
                return Ok(result);
            }
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(AndroidTrafficControlBpfFwmarkObservationError::os(
                AndroidTrafficControlBpfFwmarkObservationErrorKind::SystemCall,
                source.raw_os_error().unwrap_or(libc::EIO),
            ));
        }
    }

    pub(super) fn ensure_before(
        deadline: Instant,
    ) -> Result<(), AndroidTrafficControlBpfFwmarkObservationError> {
        if Instant::now() >= deadline {
            Err(AndroidTrafficControlBpfFwmarkObservationError::new(
                AndroidTrafficControlBpfFwmarkObservationErrorKind::Timeout,
            ))
        } else {
            Ok(())
        }
    }

    fn remaining_bound(
        deadline: Instant,
    ) -> Result<Duration, AndroidTrafficControlBpfFwmarkObservationError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout_error)?;
        if remaining < Duration::from_millis(1) {
            Err(timeout_error())
        } else {
            Ok(remaining)
        }
    }

    fn timeout_error() -> AndroidTrafficControlBpfFwmarkObservationError {
        AndroidTrafficControlBpfFwmarkObservationError::new(
            AndroidTrafficControlBpfFwmarkObservationErrorKind::Timeout,
        )
    }

    fn is_inaccessible(error: AndroidTrafficControlBpfFwmarkObservationError) -> bool {
        matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES))
    }

    fn invalid_info() -> AndroidTrafficControlBpfFwmarkObservationError {
        AndroidTrafficControlBpfFwmarkObservationError::new(
            AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidProgramInfo,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires permission to enumerate and inspect every loaded BPF program"]
    fn privileged_loaded_program_census_smoke() {
        collect_android_traffic_control_bpf_fwmarks(Duration::from_secs(5))
            .expect("collect the complete loaded-program census");
    }

    #[test]
    fn empty_loaded_program_set_is_complete_absence() {
        let observation = observe_programs(&[], &TrafficControlFilterSnapshot::empty()).unwrap();
        assert_eq!(observation.attached_traffic_control_filter_count(), 0);
        assert_eq!(observation.loaded_program_count(), 0);
        assert!(observation.mark_uses().is_empty());
        assert!(
            observation
                .coverage()
                .iter()
                .all(|record| record.state() == FwmarkCensusCoverageState::CompleteAbsent)
        );
    }

    #[test]
    fn attached_traffic_control_filters_are_bounded_opaque_evidence() {
        let snapshot = observe_traffic_control_messages(&[tc_filter_message(b"bpf\0")]).unwrap();
        let observation = observe_programs(&[], &snapshot).unwrap();
        assert_eq!(observation.attached_traffic_control_filter_count(), 1);
        assert_eq!(
            observation.coverage()[plane_index(FwmarkPlane::Packet)].state(),
            FwmarkCensusCoverageState::Opaque
        );
        assert_eq!(
            observation.coverage()[plane_index(FwmarkPlane::Socket)].state(),
            FwmarkCensusCoverageState::CompleteAbsent
        );
        assert_eq!(
            observation.coverage()[plane_index(FwmarkPlane::Conntrack)].state(),
            FwmarkCensusCoverageState::Opaque
        );

        assert_eq!(
            observe_traffic_control_messages(&[tc_filter_message(b"bpf")])
                .unwrap_err()
                .kind(),
            AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidTrafficControlInfo
        );
    }

    #[test]
    fn rewritten_network_programs_never_create_false_complete_absence() {
        let packet = program(
            1,
            BPF_PROG_TYPE_SCHED_CLS,
            vec![0; 2 * BPF_INSTRUCTION_BYTES],
        );
        let socket = program(2, BPF_PROG_TYPE_CGROUP_SOCK, vec![0; BPF_INSTRUCTION_BYTES]);
        let observation =
            observe_programs(&[packet, socket], &TrafficControlFilterSnapshot::empty()).unwrap();
        assert_eq!(observation.loaded_program_count(), 2);
        assert_eq!(observation.relevant_program_count(), 2);
        assert_eq!(observation.opaque_program_count(), 2);
        assert_eq!(observation.instruction_count(), 3);
        assert!(observation.mark_uses().is_empty());
        assert!(
            observation
                .coverage()
                .iter()
                .all(|record| record.state() == FwmarkCensusCoverageState::Opaque)
        );
    }

    #[test]
    fn program_types_without_a_fwmark_context_remain_complete_absence() {
        let programs = [
            BPF_PROG_TYPE_KPROBE,
            BPF_PROG_TYPE_TRACEPOINT,
            BPF_PROG_TYPE_XDP,
            BPF_PROG_TYPE_PERF_EVENT,
            BPF_PROG_TYPE_CGROUP_DEVICE,
            BPF_PROG_TYPE_RAW_TRACEPOINT,
            BPF_PROG_TYPE_LIRC_MODE2,
            BPF_PROG_TYPE_FLOW_DISSECTOR,
            BPF_PROG_TYPE_CGROUP_SYSCTL,
            BPF_PROG_TYPE_TRACING,
            BPF_PROG_TYPE_STRUCT_OPS,
            BPF_PROG_TYPE_LSM,
            BPF_PROG_TYPE_SYSCALL,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, program_type)| {
            program(
                u32::try_from(index + 1).unwrap(),
                program_type,
                vec![0; BPF_INSTRUCTION_BYTES],
            )
        })
        .collect::<Vec<_>>();
        let observation =
            observe_programs(&programs, &TrafficControlFilterSnapshot::empty()).unwrap();
        assert_eq!(observation.relevant_program_count(), 0);
        assert_eq!(observation.opaque_program_count(), 0);
        assert!(
            observation
                .coverage()
                .iter()
                .all(|record| record.state() == FwmarkCensusCoverageState::CompleteAbsent)
        );
    }
    #[test]
    fn program_type_groups_are_conservatively_opaque() {
        assert_eq!(
            program_opaque_planes(BPF_PROG_TYPE_CGROUP_SKB),
            Some([true, false, true])
        );
        assert_eq!(
            program_opaque_planes(BPF_PROG_TYPE_CGROUP_SOCK),
            Some([false, true, true])
        );
        assert_eq!(
            program_opaque_planes(BPF_PROG_TYPE_NETFILTER),
            Some([true, false, true])
        );
        assert_eq!(
            program_opaque_planes(BPF_PROG_TYPE_SOCKET_FILTER),
            Some([true; ALL_PLANES.len()])
        );
        assert_eq!(
            program_opaque_planes(BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE),
            Some([true; ALL_PLANES.len()])
        );
        assert_eq!(
            program_opaque_planes(u32::MAX),
            Some([true; ALL_PLANES.len()])
        );

        let observation = observe_programs(
            &[
                program(1, u32::MAX, vec![0; BPF_INSTRUCTION_BYTES]),
                ProgramSnapshot::inaccessible(2),
            ],
            &TrafficControlFilterSnapshot::empty(),
        )
        .unwrap();
        assert_eq!(observation.relevant_program_count(), 1);
        assert_eq!(observation.inaccessible_program_count(), 1);
        assert_eq!(observation.opaque_program_count(), 2);
        assert!(
            observation
                .coverage()
                .iter()
                .all(|record| record.state() == FwmarkCensusCoverageState::Opaque)
        );
    }

    #[test]
    fn invalid_program_identity_and_instruction_shape_fail_closed() {
        let duplicate = [
            program(1, BPF_PROG_TYPE_XDP, vec![0; BPF_INSTRUCTION_BYTES]),
            program(1, BPF_PROG_TYPE_XDP, vec![0; BPF_INSTRUCTION_BYTES]),
        ];
        assert_eq!(
            observe_programs(&duplicate, &TrafficControlFilterSnapshot::empty())
                .unwrap_err()
                .kind(),
            AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidProgramInfo
        );

        for instructions in [Vec::new(), vec![0; BPF_INSTRUCTION_BYTES - 1]] {
            assert_eq!(
                observe_programs(
                    &[program(1, BPF_PROG_TYPE_XDP, instructions)],
                    &TrafficControlFilterSnapshot::empty(),
                )
                .unwrap_err()
                .kind(),
                AndroidTrafficControlBpfFwmarkObservationErrorKind::InvalidProgramInfo
            );
        }
    }

    #[test]
    fn rewritten_instruction_bytes_remain_digest_evidence_only() {
        let first = observe_programs(
            &[program(
                1,
                BPF_PROG_TYPE_XDP,
                vec![0; BPF_INSTRUCTION_BYTES],
            )],
            &TrafficControlFilterSnapshot::empty(),
        )
        .unwrap();
        let second = observe_programs(
            &[program(
                1,
                BPF_PROG_TYPE_XDP,
                vec![1; BPF_INSTRUCTION_BYTES],
            )],
            &TrafficControlFilterSnapshot::empty(),
        )
        .unwrap();
        assert_ne!(first.digest(), second.digest());
        assert!(first.mark_uses().is_empty());
        assert!(second.mark_uses().is_empty());
        assert!(
            first
                .coverage()
                .iter()
                .chain(second.coverage())
                .all(|record| record.state() == FwmarkCensusCoverageState::CompleteAbsent)
        );
    }

    fn program(id: u32, program_type: u32, instructions: Vec<u8>) -> ProgramSnapshot {
        ProgramSnapshot::exact(id, program_type, [id as u8; 8], instructions)
    }

    fn tc_filter_message(kind: &[u8]) -> ReadOnlyNetlinkMessage {
        let mut payload = vec![0_u8; TC_MESSAGE_BYTES];
        let length = 4 + kind.len();
        payload.extend_from_slice(&(length as u16).to_ne_bytes());
        payload.extend_from_slice(&TCA_KIND.to_ne_bytes());
        payload.extend_from_slice(kind);
        let aligned_length = (length + 3) & !3;
        payload.resize(TC_MESSAGE_BYTES + aligned_length, 0);
        ReadOnlyNetlinkMessage::fixture(RTM_NEWTFILTER, 0, payload)
    }
}
