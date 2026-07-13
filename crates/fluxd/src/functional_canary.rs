use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use flux_core::{
    BootIdentity, CapabilityProfileRevision, InterfaceIndex, InterfaceName, NetworkEpoch,
    NetworkInventorySnapshotId, NetworkNamespaceIdentity, OwnershipJournalIdentity,
    OwnershipJournalRevision, RouteTableId, RulePriority,
};
use flux_platform::ReadinessEvidence;
use flux_platform::socket_diagnostics::{
    CorrelatedProcessSocket, InetSocketProtocol, ProcessSocketDiagnostics, SocketCorrelationError,
};
use sha2::{Digest, Sha256};

use crate::{EngineArtifactDigest, EngineSpec, OwnedEngineIdentity};

pub(crate) const FUNCTIONAL_CANARY_SCHEMA_VERSION: u16 = 1;
pub(crate) const FUNCTIONAL_CANARY_NONCE_BYTES: usize = 32;
pub(crate) const CAPTURE_PROGRAM_DIGEST_BYTES: usize = 32;
pub(crate) const CANARY_DNS_QUESTION_DIGEST_BYTES: usize = 32;
pub(crate) const CANARY_DNS_WIRE_NAME_BYTES: usize = 83;
pub(crate) const MAX_FUNCTIONAL_CANARY_DURATION: Duration = Duration::from_secs(3);
pub(crate) const MAX_CANARY_FACILITY_OBSERVATION_AGE: Duration = Duration::from_secs(3);
pub(crate) const MAX_FUNCTIONAL_CANARY_DIAGNOSTIC_BYTES: usize = 4 * 1024;
pub(crate) const FUNCTIONAL_CANARY_FLOW_SLOTS: usize = 8;
pub(crate) const CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES: usize = 32;
pub(crate) const CANARY_PEER_SERVER_SLOTS: usize = 3;
pub(crate) const CANARY_NEGATIVE_CONTROL_SLOTS: usize = 2;
pub(crate) const CANARY_FACILITY_AUDIT_DIGEST_BYTES: usize = 32;
pub(crate) const CAPTURE_OWNER_RECORD_DIGEST_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FunctionalCanaryGateMode {
    /// Retain the current Phase 1 structural gate without claiming functional
    /// traffic, DNS, or exact-process loop-escape qualification.
    StructuralOnlyCompatibility,
    /// Require the complete model below while still describing the result as
    /// unqualified until reviewed Android device evidence exists.
    RequiredUnqualified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryAddressFamilies {
    Ipv4Only,
    Ipv4AndIpv6,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct CanaryNonce([u8; FUNCTIONAL_CANARY_NONCE_BYTES]);

impl CanaryNonce {
    /// The caller must obtain these bytes from an operating-system CSPRNG.
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; FUNCTIONAL_CANARY_NONCE_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; FUNCTIONAL_CANARY_NONCE_BYTES] {
        &self.0
    }
}

impl fmt::Debug for CanaryNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanaryNonce(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryDeadlineError {
    ZeroDuration,
    ExceedsMaximum {
        requested: Duration,
        maximum: Duration,
    },
    InstantOverflow,
}

impl fmt::Display for CanaryDeadlineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDuration => formatter.write_str("functional canary duration must be nonzero"),
            Self::ExceedsMaximum { requested, maximum } => write!(
                formatter,
                "functional canary duration {requested:?} exceeds the {maximum:?} maximum"
            ),
            Self::InstantOverflow => {
                formatter.write_str("functional canary absolute deadline overflowed")
            }
        }
    }
}

impl Error for CanaryDeadlineError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryDeadline {
    started_at: Instant,
    expires_at: Instant,
}

impl CanaryDeadline {
    pub(crate) fn new(
        started_at: Instant,
        duration: Duration,
    ) -> Result<Self, CanaryDeadlineError> {
        if duration.is_zero() {
            return Err(CanaryDeadlineError::ZeroDuration);
        }
        if duration > MAX_FUNCTIONAL_CANARY_DURATION {
            return Err(CanaryDeadlineError::ExceedsMaximum {
                requested: duration,
                maximum: MAX_FUNCTIONAL_CANARY_DURATION,
            });
        }
        let expires_at = started_at
            .checked_add(duration)
            .ok_or(CanaryDeadlineError::InstantOverflow)?;
        Ok(Self {
            started_at,
            expires_at,
        })
    }

    #[must_use]
    pub(crate) const fn started_at(self) -> Instant {
        self.started_at
    }

    #[must_use]
    pub(crate) const fn expires_at(self) -> Instant {
        self.expires_at
    }

    #[must_use]
    pub(crate) fn remaining(self, now: Instant) -> Duration {
        self.expires_at.saturating_duration_since(now)
    }

    #[must_use]
    pub(crate) fn has_expired(self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryBindingError {
    TunReadinessUnsupported,
    AllZeroCaptureProgramDigest,
    DuplicateVethIndex,
    DuplicateVethName,
    DuplicateIpv4Address,
    DuplicateIpv6Address,
    ForbiddenIpv4Address,
    ForbiddenIpv6Address,
    SameNetworkNamespace,
    ZeroRpdbTable,
    SameRpdbTable,
    InvalidRpdbPriorityOrder,
    ProxyMarkEmpty,
    ProxyMarkBitsOutsideMask,
    ProbeUidMatchesEngineUid,
    MissingIpv6Facility,
    SameProtocolResponderPortCollision,
    FacilityAdmissionInventoryMismatch,
    FacilityAdmissionAttemptMismatch,
    FacilityAdmissionExpired,
    AllZeroFacilityAuditDigest,
    AllZeroCaptureOwnerRecordDigest,
    CaptureOwnerGenerationMismatch,
    CaptureOwnerBootMismatch,
    AllZeroAttemptObjectIdentity,
    AttemptObjectGenerationMismatch,
    AttemptObjectNonceMismatch,
    InvalidCounterBounds,
}

impl fmt::Display for CanaryBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid functional canary binding: {self:?}")
    }
}

impl Error for CanaryBindingError {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CaptureProgramDigest([u8; CAPTURE_PROGRAM_DIGEST_BYTES]);

impl CaptureProgramDigest {
    pub(crate) fn new(
        bytes: [u8; CAPTURE_PROGRAM_DIGEST_BYTES],
    ) -> Result<Self, CanaryBindingError> {
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0 {
                return Ok(Self(bytes));
            }
            index += 1;
        }
        Err(CanaryBindingError::AllZeroCaptureProgramDigest)
    }

    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; CAPTURE_PROGRAM_DIGEST_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CanaryAttemptObjectIdentity([u8; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES]);

impl CanaryAttemptObjectIdentity {
    pub(crate) const fn new(
        bytes: [u8; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES],
    ) -> Result<Self, CanaryBindingError> {
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0 {
                return Ok(Self(bytes));
            }
            index += 1;
        }
        Err(CanaryBindingError::AllZeroAttemptObjectIdentity)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryAttemptObjectIdentities {
    generation: NonZeroU32,
    nonce: CanaryNonce,
    selector: CanaryAttemptObjectIdentity,
    leak_guard: CanaryAttemptObjectIdentity,
    counters: CanaryAttemptObjectIdentity,
}

impl CanaryAttemptObjectIdentities {
    #[must_use]
    pub(crate) const fn new(
        generation: NonZeroU32,
        nonce: CanaryNonce,
        selector: CanaryAttemptObjectIdentity,
        leak_guard: CanaryAttemptObjectIdentity,
        counters: CanaryAttemptObjectIdentity,
    ) -> Self {
        Self {
            generation,
            nonce,
            selector,
            leak_guard,
            counters,
        }
    }

    #[must_use]
    pub(crate) const fn generation(self) -> NonZeroU32 {
        self.generation
    }

    #[must_use]
    pub(crate) const fn nonce(self) -> CanaryNonce {
        self.nonce
    }

    #[must_use]
    pub(crate) const fn selector(self) -> CanaryAttemptObjectIdentity {
        self.selector
    }

    #[must_use]
    pub(crate) const fn leak_guard(self) -> CanaryAttemptObjectIdentity {
        self.leak_guard
    }

    #[must_use]
    pub(crate) const fn counters(self) -> CanaryAttemptObjectIdentity {
        self.counters
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CanaryFacilityAuditDigest([u8; CANARY_FACILITY_AUDIT_DIGEST_BYTES]);

impl CanaryFacilityAuditDigest {
    pub(crate) const fn new(
        bytes: [u8; CANARY_FACILITY_AUDIT_DIGEST_BYTES],
    ) -> Result<Self, CanaryBindingError> {
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0 {
                return Ok(Self(bytes));
            }
            index += 1;
        }
        Err(CanaryBindingError::AllZeroFacilityAuditDigest)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CaptureOwnerRecordDigest([u8; CAPTURE_OWNER_RECORD_DIGEST_BYTES]);

impl CaptureOwnerRecordDigest {
    pub(crate) const fn new(
        bytes: [u8; CAPTURE_OWNER_RECORD_DIGEST_BYTES],
    ) -> Result<Self, CanaryBindingError> {
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0 {
                return Ok(Self(bytes));
            }
            index += 1;
        }
        Err(CanaryBindingError::AllZeroCaptureOwnerRecordDigest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CaptureOwnerRecordBinding {
    schema_version: NonZeroU16,
    boot_identity: BootIdentity,
    generation: NonZeroU32,
    file_identity: CanaryFileIdentity,
    digest: CaptureOwnerRecordDigest,
}

impl CaptureOwnerRecordBinding {
    #[must_use]
    pub(crate) const fn new(
        schema_version: NonZeroU16,
        boot_identity: BootIdentity,
        generation: NonZeroU32,
        file_identity: CanaryFileIdentity,
        digest: CaptureOwnerRecordDigest,
    ) -> Self {
        Self {
            schema_version,
            boot_identity,
            generation,
            file_identity,
            digest,
        }
    }

    #[must_use]
    pub(crate) const fn schema_version(&self) -> NonZeroU16 {
        self.schema_version
    }

    #[must_use]
    pub(crate) const fn boot_identity(&self) -> &BootIdentity {
        &self.boot_identity
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> NonZeroU32 {
        self.generation
    }

    #[must_use]
    pub(crate) const fn file_identity(&self) -> CanaryFileIdentity {
        self.file_identity
    }

    #[must_use]
    pub(crate) const fn digest(&self) -> CaptureOwnerRecordDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryFileIdentity {
    device: u64,
    inode: NonZeroU64,
}

impl CanaryFileIdentity {
    #[must_use]
    pub(crate) const fn new(device: u64, inode: NonZeroU64) -> Self {
        Self { device, inode }
    }

    #[must_use]
    pub(crate) const fn device(self) -> u64 {
        self.device
    }

    #[must_use]
    pub(crate) const fn inode(self) -> NonZeroU64 {
        self.inode
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanarySocketObserverAuthority {
    ProcFdInetDiag {
        collector_identity: CanaryAttemptObjectIdentity,
        collector_revision: NonZeroU64,
        netlink_port_id: NonZeroU32,
    },
    QualifiedCgroupBpf {
        program_identity: CanaryAttemptObjectIdentity,
        link_id: NonZeroU32,
        event_map_id: NonZeroU32,
        loss_map_id: NonZeroU32,
        cgroup_id: NonZeroU64,
        event_schema_version: NonZeroU16,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryInetDiagCookie {
    high: u32,
    low: u32,
}

impl CanaryInetDiagCookie {
    #[must_use]
    pub(crate) const fn new(high: u32, low: u32) -> Option<Self> {
        if high == u32::MAX && low == u32::MAX {
            None
        } else {
            Some(Self { high, low })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryProcFd(u32);

impl CanaryProcFd {
    #[must_use]
    pub(crate) const fn new(raw: u32) -> Option<Self> {
        if raw <= i32::MAX as u32 {
            Some(Self(raw))
        } else {
            None
        }
    }

    #[must_use]
    pub(crate) const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryInetDiagProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryBpfSocketHook {
    ConnectIpv4,
    ConnectIpv6,
    SendMessageIpv4,
    SendMessageIpv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanarySocketCorrelation {
    ProcFdInetDiag {
        observer: CanarySocketObserverAuthority,
        process: OwnedEngineIdentity,
        proc_fd: CanaryProcFd,
        fd_socket_inode: NonZeroU64,
        diag_socket_inode: NonZeroU64,
        inet_diag_cookie: CanaryInetDiagCookie,
        observer_sequence: NonZeroU64,
        diag_protocol: CanaryInetDiagProtocol,
        diag_tuple: CanaryFlowTuple,
        diag_uid: NonZeroU32,
        diag_socket_mark: u32,
        fd_scan_complete: bool,
        diag_dump_complete: bool,
        snapshot_started_at: Instant,
        snapshot_completed_at: Instant,
        dump_started_at: Instant,
        dump_completed_at: Instant,
    },
    QualifiedCgroupBpf {
        observer: CanarySocketObserverAuthority,
        process: OwnedEngineIdentity,
        socket_cookie: NonZeroU64,
        attempt_nonce: CanaryNonce,
        event_sequence: NonZeroU64,
        hook: CanaryBpfSocketHook,
        lost_events_before: u64,
        lost_events_after: u64,
        observed_at: Instant,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanarySocketCorrelationBuildError {
    WrongObserverAuthority,
    ObserverPortMismatch,
    ProcessIdentityMismatch,
    SnapshotCorrelationRejected(SocketCorrelationError),
    SnapshotCorrelationMismatch,
    InvalidProcFd,
    ZeroDiagnosticInode,
    InvalidInetDiagCookie,
    ZeroDiagnosticUid,
    MissingDiagnosticMark,
    MissingDiagnosticDump,
    AmbiguousDiagnosticDump,
}

impl CanarySocketCorrelation {
    /// Build one correlation exclusively from an exact collector snapshot join.
    ///
    /// The local-OUTPUT executor will call this adapter after selecting the
    /// expected FD, protocol, and tuple through `ProcessSocketDiagnostics::correlate`.
    #[allow(dead_code)]
    pub(crate) fn from_proc_fd_inet_diag_snapshot(
        observer: CanarySocketObserverAuthority,
        process: OwnedEngineIdentity,
        snapshot: &ProcessSocketDiagnostics,
        correlated: CorrelatedProcessSocket,
    ) -> Result<Self, CanarySocketCorrelationBuildError> {
        let CanarySocketObserverAuthority::ProcFdInetDiag {
            netlink_port_id, ..
        } = observer
        else {
            return Err(CanarySocketCorrelationBuildError::WrongObserverAuthority);
        };
        if netlink_port_id != snapshot.netlink_port_id() {
            return Err(CanarySocketCorrelationBuildError::ObserverPortMismatch);
        }
        let observed_process = snapshot.process();
        if observed_process.pid().get() != process.pid()
            || observed_process.start_time_ticks().get() != process.start_time_ticks()
        {
            return Err(CanarySocketCorrelationBuildError::ProcessIdentityMismatch);
        }

        let process_fd = correlated.process_fd();
        let diagnostic = correlated.diagnostic();
        let selected = snapshot
            .correlate(
                process_fd.fd(),
                diagnostic.protocol(),
                diagnostic.local_address(),
                diagnostic.remote_address(),
            )
            .map_err(CanarySocketCorrelationBuildError::SnapshotCorrelationRejected)?;
        if selected != correlated {
            return Err(CanarySocketCorrelationBuildError::SnapshotCorrelationMismatch);
        }

        let proc_fd = CanaryProcFd::new(process_fd.fd())
            .ok_or(CanarySocketCorrelationBuildError::InvalidProcFd)?;
        let diag_socket_inode = NonZeroU64::new(diagnostic.inode())
            .ok_or(CanarySocketCorrelationBuildError::ZeroDiagnosticInode)?;
        let cookie_words = diagnostic.cookie().words();
        let inet_diag_cookie = CanaryInetDiagCookie::new(cookie_words[0], cookie_words[1])
            .ok_or(CanarySocketCorrelationBuildError::InvalidInetDiagCookie)?;
        let diag_uid = NonZeroU32::new(diagnostic.uid())
            .ok_or(CanarySocketCorrelationBuildError::ZeroDiagnosticUid)?;
        let diag_socket_mark = diagnostic
            .mark()
            .ok_or(CanarySocketCorrelationBuildError::MissingDiagnosticMark)?;

        let mut dumps = snapshot.dumps().iter().copied().filter(|dump| {
            dump.sequence() == diagnostic.dump_sequence()
                && dump.address_family() == diagnostic.address_family()
                && dump.protocol() == diagnostic.protocol()
        });
        let dump = dumps
            .next()
            .ok_or(CanarySocketCorrelationBuildError::MissingDiagnosticDump)?;
        if dumps.next().is_some() {
            return Err(CanarySocketCorrelationBuildError::AmbiguousDiagnosticDump);
        }

        Ok(Self::ProcFdInetDiag {
            observer,
            process,
            proc_fd,
            fd_socket_inode: process_fd.inode(),
            diag_socket_inode,
            inet_diag_cookie,
            observer_sequence: NonZeroU64::new(u64::from(diagnostic.dump_sequence().get()))
                .expect("a nonzero u32 remains nonzero as u64"),
            diag_protocol: match diagnostic.protocol() {
                InetSocketProtocol::Tcp => CanaryInetDiagProtocol::Tcp,
                InetSocketProtocol::Udp => CanaryInetDiagProtocol::Udp,
            },
            diag_tuple: CanaryFlowTuple::new(
                diagnostic.local_address(),
                diagnostic.remote_address(),
            ),
            diag_uid,
            diag_socket_mark,
            fd_scan_complete: snapshot.fd_scan_complete(),
            diag_dump_complete: snapshot.diag_dumps_complete(),
            snapshot_started_at: snapshot.started_at(),
            snapshot_completed_at: snapshot.completed_at(),
            dump_started_at: dump.started_at(),
            dump_completed_at: dump.completed_at(),
        })
    }

    const fn process(self) -> OwnedEngineIdentity {
        match self {
            Self::ProcFdInetDiag { process, .. } | Self::QualifiedCgroupBpf { process, .. } => {
                process
            }
        }
    }

    const fn observer(self) -> CanarySocketObserverAuthority {
        match self {
            Self::ProcFdInetDiag { observer, .. } | Self::QualifiedCgroupBpf { observer, .. } => {
                observer
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryArtifactIdentity {
    binary: EngineArtifactDigest,
    config: EngineArtifactDigest,
    launcher: Option<EngineArtifactDigest>,
}

impl CanaryArtifactIdentity {
    #[must_use]
    pub(crate) const fn from_spec(spec: &EngineSpec) -> Self {
        Self {
            binary: spec.binary_digest(),
            config: spec.config_digest(),
            launcher: spec.launcher_digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryListenerIdentity {
    port: NonZeroU16,
    observation_path: PathBuf,
}

impl CanaryListenerIdentity {
    #[must_use]
    pub(crate) const fn port(&self) -> NonZeroU16 {
        self.port
    }

    #[must_use]
    pub(crate) fn observation_path(&self) -> &Path {
        &self.observation_path
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryEngineBinding {
    generation: NonZeroU32,
    engine: OwnedEngineIdentity,
    engine_snapshot_revision: NonZeroU64,
    artifacts: CanaryArtifactIdentity,
    listener: CanaryListenerIdentity,
}

impl CanaryEngineBinding {
    pub(crate) fn from_identity_parts(
        generation: NonZeroU32,
        pid: NonZeroU32,
        start_time_ticks: NonZeroU64,
        engine_snapshot_revision: NonZeroU64,
        spec: &EngineSpec,
        readiness: &ReadinessEvidence,
    ) -> Result<Self, CanaryBindingError> {
        Self::new(
            generation,
            OwnedEngineIdentity::new(pid, start_time_ticks),
            engine_snapshot_revision,
            spec,
            readiness,
        )
    }

    pub(crate) fn new(
        generation: NonZeroU32,
        engine: OwnedEngineIdentity,
        engine_snapshot_revision: NonZeroU64,
        spec: &EngineSpec,
        readiness: &ReadinessEvidence,
    ) -> Result<Self, CanaryBindingError> {
        let listener = match readiness {
            ReadinessEvidence::Listener { port, table } => CanaryListenerIdentity {
                port: *port,
                observation_path: table.clone(),
            },
            ReadinessEvidence::TunInterface { .. } => {
                return Err(CanaryBindingError::TunReadinessUnsupported);
            }
        };
        Ok(Self {
            generation,
            engine,
            engine_snapshot_revision,
            artifacts: CanaryArtifactIdentity::from_spec(spec),
            listener,
        })
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> NonZeroU32 {
        self.generation
    }

    #[must_use]
    pub(crate) const fn engine(&self) -> OwnedEngineIdentity {
        self.engine
    }

    #[must_use]
    pub(crate) const fn engine_snapshot_revision(&self) -> NonZeroU64 {
        self.engine_snapshot_revision
    }

    #[must_use]
    pub(crate) const fn artifacts(&self) -> CanaryArtifactIdentity {
        self.artifacts
    }

    #[must_use]
    pub(crate) const fn listener(&self) -> &CanaryListenerIdentity {
        &self.listener
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryVethIdentity {
    interface_index: InterfaceIndex,
    interface_name: InterfaceName,
}

impl CanaryVethIdentity {
    #[must_use]
    pub(crate) const fn new(
        interface_index: InterfaceIndex,
        interface_name: InterfaceName,
    ) -> Self {
        Self {
            interface_index,
            interface_name,
        }
    }

    #[must_use]
    pub(crate) const fn interface_index(self) -> InterfaceIndex {
        self.interface_index
    }

    #[must_use]
    pub(crate) const fn interface_name(self) -> InterfaceName {
        self.interface_name
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryIpv4AddressPair {
    daemon: Ipv4Addr,
    peer: Ipv4Addr,
}

impl CanaryIpv4AddressPair {
    pub(crate) fn new(daemon: Ipv4Addr, peer: Ipv4Addr) -> Result<Self, CanaryBindingError> {
        if daemon == peer {
            return Err(CanaryBindingError::DuplicateIpv4Address);
        }
        if ipv4_forbidden(daemon) || ipv4_forbidden(peer) {
            return Err(CanaryBindingError::ForbiddenIpv4Address);
        }
        Ok(Self { daemon, peer })
    }

    #[must_use]
    pub(crate) const fn daemon(self) -> Ipv4Addr {
        self.daemon
    }

    #[must_use]
    pub(crate) const fn peer(self) -> Ipv4Addr {
        self.peer
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryIpv6AddressPair {
    daemon: Ipv6Addr,
    peer: Ipv6Addr,
}

impl CanaryIpv6AddressPair {
    pub(crate) fn new(daemon: Ipv6Addr, peer: Ipv6Addr) -> Result<Self, CanaryBindingError> {
        if daemon == peer {
            return Err(CanaryBindingError::DuplicateIpv6Address);
        }
        if ipv6_forbidden(daemon) || ipv6_forbidden(peer) {
            return Err(CanaryBindingError::ForbiddenIpv6Address);
        }
        Ok(Self { daemon, peer })
    }

    #[must_use]
    pub(crate) const fn daemon(self) -> Ipv6Addr {
        self.daemon
    }

    #[must_use]
    pub(crate) const fn peer(self) -> Ipv6Addr {
        self.peer
    }
}

fn ipv4_forbidden(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && matches!(b, 18 | 19))
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
}

fn ipv6_forbidden(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryResponderPorts {
    tcp_echo: NonZeroU16,
    udp_echo: NonZeroU16,
    dns: NonZeroU16,
}

impl CanaryResponderPorts {
    pub(crate) const fn new(
        tcp_echo: NonZeroU16,
        udp_echo: NonZeroU16,
        dns: NonZeroU16,
    ) -> Result<Self, CanaryBindingError> {
        if tcp_echo.get() == dns.get() || udp_echo.get() == dns.get() {
            return Err(CanaryBindingError::SameProtocolResponderPortCollision);
        }
        Ok(Self {
            tcp_echo,
            udp_echo,
            dns,
        })
    }

    #[must_use]
    pub(crate) const fn tcp_echo(self) -> NonZeroU16 {
        self.tcp_echo
    }

    #[must_use]
    pub(crate) const fn udp_echo(self) -> NonZeroU16 {
        self.udp_echo
    }

    #[must_use]
    pub(crate) const fn dns(self) -> NonZeroU16 {
        self.dns
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryFacilityAdmissionScope {
    generation: NonZeroU32,
    nonce: CanaryNonce,
    facility: CanaryFacilityIdentity,
    facility_digest: CanaryFacilityAuditDigest,
    reviewed_pool_identity: CanaryFacilityAuditDigest,
}

impl CanaryFacilityAdmissionScope {
    #[must_use]
    pub(crate) const fn new(
        generation: NonZeroU32,
        nonce: CanaryNonce,
        facility: CanaryFacilityIdentity,
        facility_digest: CanaryFacilityAuditDigest,
        reviewed_pool_identity: CanaryFacilityAuditDigest,
    ) -> Self {
        Self {
            generation,
            nonce,
            facility,
            facility_digest,
            reviewed_pool_identity,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryFacilityAdmissionObservation {
    network_epoch: NetworkEpoch,
    inventory_snapshot_id: NetworkInventorySnapshotId,
    collision_audit_revision: NonZeroU64,
    collision_and_bypass_digest: CanaryFacilityAuditDigest,
    observed_at: Instant,
    fresh_until: Instant,
}

impl CanaryFacilityAdmissionObservation {
    #[must_use]
    pub(crate) const fn new(
        network_epoch: NetworkEpoch,
        inventory_snapshot_id: NetworkInventorySnapshotId,
        collision_audit_revision: NonZeroU64,
        collision_and_bypass_digest: CanaryFacilityAuditDigest,
        observed_at: Instant,
        fresh_until: Instant,
    ) -> Self {
        Self {
            network_epoch,
            inventory_snapshot_id,
            collision_audit_revision,
            collision_and_bypass_digest,
            observed_at,
            fresh_until,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryFacilityAdmissionToken {
    scope: CanaryFacilityAdmissionScope,
    observation: CanaryFacilityAdmissionObservation,
}

impl CanaryFacilityAdmissionToken {
    #[must_use]
    pub(crate) const fn new(
        scope: CanaryFacilityAdmissionScope,
        observation: CanaryFacilityAdmissionObservation,
    ) -> Self {
        Self { scope, observation }
    }

    #[must_use]
    pub(crate) const fn scope(self) -> CanaryFacilityAdmissionScope {
        self.scope
    }

    #[must_use]
    pub(crate) const fn observation(self) -> CanaryFacilityAdmissionObservation {
        self.observation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryFacilityIdentity {
    daemon_veth: CanaryVethIdentity,
    peer_veth: CanaryVethIdentity,
    ipv4: CanaryIpv4AddressPair,
    ipv6: Option<CanaryIpv6AddressPair>,
    ports: CanaryResponderPorts,
}

impl CanaryFacilityIdentity {
    pub(crate) fn new(
        daemon_veth: CanaryVethIdentity,
        peer_veth: CanaryVethIdentity,
        ipv4: CanaryIpv4AddressPair,
        ipv6: Option<CanaryIpv6AddressPair>,
        ports: CanaryResponderPorts,
    ) -> Result<Self, CanaryBindingError> {
        if daemon_veth.interface_index == peer_veth.interface_index {
            return Err(CanaryBindingError::DuplicateVethIndex);
        }
        if daemon_veth.interface_name == peer_veth.interface_name {
            return Err(CanaryBindingError::DuplicateVethName);
        }
        Ok(Self {
            daemon_veth,
            peer_veth,
            ipv4,
            ipv6,
            ports,
        })
    }

    #[must_use]
    pub(crate) const fn daemon_veth(&self) -> CanaryVethIdentity {
        self.daemon_veth
    }

    #[must_use]
    pub(crate) const fn peer_veth(&self) -> CanaryVethIdentity {
        self.peer_veth
    }

    #[must_use]
    pub(crate) const fn ipv4(&self) -> CanaryIpv4AddressPair {
        self.ipv4
    }

    #[must_use]
    pub(crate) const fn ipv6(&self) -> Option<CanaryIpv6AddressPair> {
        self.ipv6
    }

    #[must_use]
    pub(crate) const fn ports(&self) -> CanaryResponderPorts {
        self.ports
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryRpdbIdentity {
    engine_uid: NonZeroU32,
    rule_protocol: NonZeroU8,
    peer_table: RouteTableId,
    proxy_capture_table: RouteTableId,
    peer_rule_priority: RulePriority,
    proxy_mark_rule_priority: RulePriority,
    proxy_mark_value: u32,
    proxy_mark_mask: NonZeroU32,
}

impl CanaryRpdbIdentity {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        engine_uid: NonZeroU32,
        rule_protocol: NonZeroU8,
        peer_table: RouteTableId,
        proxy_capture_table: RouteTableId,
        peer_rule_priority: RulePriority,
        proxy_mark_rule_priority: RulePriority,
        proxy_mark_value: u32,
        proxy_mark_mask: NonZeroU32,
    ) -> Result<Self, CanaryBindingError> {
        if peer_table.get() == 0 || proxy_capture_table.get() == 0 {
            return Err(CanaryBindingError::ZeroRpdbTable);
        }
        if peer_table.get() == proxy_capture_table.get() {
            return Err(CanaryBindingError::SameRpdbTable);
        }
        if proxy_mark_rule_priority.get() >= peer_rule_priority.get() {
            return Err(CanaryBindingError::InvalidRpdbPriorityOrder);
        }
        if proxy_mark_value & proxy_mark_mask.get() == 0 {
            return Err(CanaryBindingError::ProxyMarkEmpty);
        }
        if proxy_mark_value & !proxy_mark_mask.get() != 0 {
            return Err(CanaryBindingError::ProxyMarkBitsOutsideMask);
        }
        Ok(Self {
            engine_uid,
            rule_protocol,
            peer_table,
            proxy_capture_table,
            peer_rule_priority,
            proxy_mark_rule_priority,
            proxy_mark_value,
            proxy_mark_mask,
        })
    }

    #[must_use]
    pub(crate) const fn engine_uid(&self) -> NonZeroU32 {
        self.engine_uid
    }

    #[must_use]
    pub(crate) const fn rule_protocol(&self) -> NonZeroU8 {
        self.rule_protocol
    }

    #[must_use]
    pub(crate) const fn peer_table(&self) -> RouteTableId {
        self.peer_table
    }

    #[must_use]
    pub(crate) const fn proxy_capture_table(&self) -> RouteTableId {
        self.proxy_capture_table
    }

    #[must_use]
    pub(crate) const fn peer_rule_priority(&self) -> RulePriority {
        self.peer_rule_priority
    }

    #[must_use]
    pub(crate) const fn proxy_mark_rule_priority(&self) -> RulePriority {
        self.proxy_mark_rule_priority
    }

    #[must_use]
    pub(crate) const fn proxy_mark_value(&self) -> u32 {
        self.proxy_mark_value
    }

    #[must_use]
    pub(crate) const fn proxy_mark_mask(&self) -> NonZeroU32 {
        self.proxy_mark_mask
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryNetworkObservationBinding {
    daemon_network_namespace: NetworkNamespaceIdentity,
    peer_network_namespace: NetworkNamespaceIdentity,
    network_epoch: NetworkEpoch,
    network_inventory_snapshot_id: NetworkInventorySnapshotId,
}

impl CanaryNetworkObservationBinding {
    pub(crate) fn new(
        daemon_network_namespace: NetworkNamespaceIdentity,
        peer_network_namespace: NetworkNamespaceIdentity,
        network_epoch: NetworkEpoch,
        network_inventory_snapshot_id: NetworkInventorySnapshotId,
    ) -> Result<Self, CanaryBindingError> {
        if daemon_network_namespace == peer_network_namespace {
            return Err(CanaryBindingError::SameNetworkNamespace);
        }
        Ok(Self {
            daemon_network_namespace,
            peer_network_namespace,
            network_epoch,
            network_inventory_snapshot_id,
        })
    }

    #[must_use]
    pub(crate) const fn daemon_network_namespace(&self) -> NetworkNamespaceIdentity {
        self.daemon_network_namespace
    }

    #[must_use]
    pub(crate) const fn peer_network_namespace(&self) -> NetworkNamespaceIdentity {
        self.peer_network_namespace
    }

    #[must_use]
    pub(crate) const fn network_epoch(&self) -> NetworkEpoch {
        self.network_epoch
    }

    #[must_use]
    pub(crate) const fn network_inventory_snapshot_id(&self) -> NetworkInventorySnapshotId {
        self.network_inventory_snapshot_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryOwnershipBinding {
    journal_identity: OwnershipJournalIdentity,
    journal_revision: OwnershipJournalRevision,
    capture_owner: CaptureOwnerRecordBinding,
}

impl CanaryOwnershipBinding {
    #[must_use]
    pub(crate) const fn new(
        journal_identity: OwnershipJournalIdentity,
        journal_revision: OwnershipJournalRevision,
        capture_owner: CaptureOwnerRecordBinding,
    ) -> Self {
        Self {
            journal_identity,
            journal_revision,
            capture_owner,
        }
    }

    #[must_use]
    pub(crate) const fn journal_identity(&self) -> OwnershipJournalIdentity {
        self.journal_identity
    }

    #[must_use]
    pub(crate) const fn journal_revision(&self) -> OwnershipJournalRevision {
        self.journal_revision
    }

    #[must_use]
    pub(crate) const fn capture_owner(&self) -> &CaptureOwnerRecordBinding {
        &self.capture_owner
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryEnvironmentAuthorityBinding {
    boot_identity: BootIdentity,
    capability_profile_revision: CapabilityProfileRevision,
    network: CanaryNetworkObservationBinding,
    capture_program_digest: CaptureProgramDigest,
    ownership: CanaryOwnershipBinding,
    socket_observer: CanarySocketObserverAuthority,
}

impl CanaryEnvironmentAuthorityBinding {
    #[must_use]
    pub(crate) const fn new(
        boot_identity: BootIdentity,
        capability_profile_revision: CapabilityProfileRevision,
        network: CanaryNetworkObservationBinding,
        capture_program_digest: CaptureProgramDigest,
        ownership: CanaryOwnershipBinding,
        socket_observer: CanarySocketObserverAuthority,
    ) -> Self {
        Self {
            boot_identity,
            capability_profile_revision,
            network,
            capture_program_digest,
            ownership,
            socket_observer,
        }
    }

    #[must_use]
    pub(crate) const fn socket_observer(&self) -> CanarySocketObserverAuthority {
        self.socket_observer
    }

    #[must_use]
    pub(crate) const fn boot_identity(&self) -> &BootIdentity {
        &self.boot_identity
    }

    #[must_use]
    pub(crate) const fn capability_profile_revision(&self) -> CapabilityProfileRevision {
        self.capability_profile_revision
    }

    #[must_use]
    pub(crate) const fn network(&self) -> CanaryNetworkObservationBinding {
        self.network
    }

    #[must_use]
    pub(crate) const fn capture_program_digest(&self) -> CaptureProgramDigest {
        self.capture_program_digest
    }

    #[must_use]
    pub(crate) const fn ownership(&self) -> &CanaryOwnershipBinding {
        &self.ownership
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryEnvironmentBinding {
    authority: CanaryEnvironmentAuthorityBinding,
    probe_uid: NonZeroU32,
    facility: CanaryFacilityIdentity,
    facility_admission: CanaryFacilityAdmissionToken,
    rpdb: CanaryRpdbIdentity,
    attempt_objects: CanaryAttemptObjectIdentities,
}

impl CanaryEnvironmentBinding {
    pub(crate) fn new(
        authority: CanaryEnvironmentAuthorityBinding,
        probe_uid: NonZeroU32,
        facility: CanaryFacilityIdentity,
        facility_admission: CanaryFacilityAdmissionToken,
        rpdb: CanaryRpdbIdentity,
        attempt_objects: CanaryAttemptObjectIdentities,
    ) -> Result<Self, CanaryBindingError> {
        if probe_uid.get() == rpdb.engine_uid.get() {
            return Err(CanaryBindingError::ProbeUidMatchesEngineUid);
        }
        if facility_admission.observation.network_epoch != authority.network.network_epoch
            || facility_admission.observation.inventory_snapshot_id
                != authority.network.network_inventory_snapshot_id
        {
            return Err(CanaryBindingError::FacilityAdmissionInventoryMismatch);
        }
        if facility_admission.scope.facility != facility {
            return Err(CanaryBindingError::FacilityAdmissionInventoryMismatch);
        }
        Ok(Self {
            authority,
            probe_uid,
            facility,
            facility_admission,
            rpdb,
            attempt_objects,
        })
    }

    #[must_use]
    pub(crate) const fn authority(&self) -> &CanaryEnvironmentAuthorityBinding {
        &self.authority
    }

    #[must_use]
    pub(crate) const fn probe_uid(&self) -> NonZeroU32 {
        self.probe_uid
    }

    #[must_use]
    pub(crate) const fn facility(&self) -> CanaryFacilityIdentity {
        self.facility
    }

    #[must_use]
    pub(crate) const fn facility_admission(&self) -> CanaryFacilityAdmissionToken {
        self.facility_admission
    }

    #[must_use]
    pub(crate) const fn rpdb(&self) -> CanaryRpdbIdentity {
        self.rpdb
    }

    #[must_use]
    pub(crate) const fn attempt_objects(&self) -> CanaryAttemptObjectIdentities {
        self.attempt_objects
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryAttemptBinding {
    engine: CanaryEngineBinding,
    environment: CanaryEnvironmentBinding,
}

impl CanaryAttemptBinding {
    #[must_use]
    pub(crate) const fn new(
        engine: CanaryEngineBinding,
        environment: CanaryEnvironmentBinding,
    ) -> Self {
        Self {
            engine,
            environment,
        }
    }

    #[must_use]
    pub(crate) const fn engine(&self) -> &CanaryEngineBinding {
        &self.engine
    }

    #[must_use]
    pub(crate) const fn environment(&self) -> &CanaryEnvironmentBinding {
        &self.environment
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryCounterDeltaBounds {
    capture_minimum: NonZeroU64,
    capture_maximum: NonZeroU64,
    bypass_minimum: NonZeroU64,
    bypass_maximum: NonZeroU64,
    recapture_maximum: u64,
}

impl CanaryCounterDeltaBounds {
    pub(crate) const fn new(
        capture_minimum: NonZeroU64,
        capture_maximum: NonZeroU64,
        bypass_minimum: NonZeroU64,
        bypass_maximum: NonZeroU64,
        recapture_maximum: u64,
    ) -> Result<Self, CanaryBindingError> {
        if capture_minimum.get() > capture_maximum.get()
            || bypass_minimum.get() > bypass_maximum.get()
        {
            return Err(CanaryBindingError::InvalidCounterBounds);
        }
        Ok(Self {
            capture_minimum,
            capture_maximum,
            bypass_minimum,
            bypass_maximum,
            recapture_maximum,
        })
    }

    #[must_use]
    pub(crate) const fn capture_minimum(self) -> NonZeroU64 {
        self.capture_minimum
    }

    #[must_use]
    pub(crate) const fn capture_maximum(self) -> NonZeroU64 {
        self.capture_maximum
    }

    #[must_use]
    pub(crate) const fn bypass_minimum(self) -> NonZeroU64 {
        self.bypass_minimum
    }

    #[must_use]
    pub(crate) const fn bypass_maximum(self) -> NonZeroU64 {
        self.bypass_maximum
    }

    #[must_use]
    pub(crate) const fn recapture_maximum(self) -> u64 {
        self.recapture_maximum
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryAttemptRequest {
    schema_version: u16,
    pre_binding: CanaryAttemptBinding,
    nonce: CanaryNonce,
    deadline: CanaryDeadline,
    families: CanaryAddressFamilies,
    dns_expectations: CanaryDnsExpectationSlots,
    counter_bounds: CanaryCounterDeltaBounds,
}

impl CanaryAttemptRequest {
    pub(crate) fn new(
        pre_binding: CanaryAttemptBinding,
        nonce: CanaryNonce,
        deadline: CanaryDeadline,
        families: CanaryAddressFamilies,
        counter_bounds: CanaryCounterDeltaBounds,
    ) -> Result<Self, CanaryBindingError> {
        if families == CanaryAddressFamilies::Ipv4AndIpv6
            && pre_binding.environment.facility.ipv6.is_none()
        {
            return Err(CanaryBindingError::MissingIpv6Facility);
        }
        if pre_binding.environment.attempt_objects.generation != pre_binding.engine.generation() {
            return Err(CanaryBindingError::AttemptObjectGenerationMismatch);
        }
        if pre_binding.environment.attempt_objects.nonce != nonce {
            return Err(CanaryBindingError::AttemptObjectNonceMismatch);
        }
        if pre_binding
            .environment
            .authority
            .ownership
            .capture_owner
            .generation
            != pre_binding.engine.generation()
        {
            return Err(CanaryBindingError::CaptureOwnerGenerationMismatch);
        }
        if pre_binding
            .environment
            .authority
            .ownership
            .capture_owner
            .boot_identity
            != pre_binding.environment.authority.boot_identity
        {
            return Err(CanaryBindingError::CaptureOwnerBootMismatch);
        }
        let admission = pre_binding.environment.facility_admission;
        if admission.scope.generation != pre_binding.engine.generation()
            || admission.scope.nonce != nonce
        {
            return Err(CanaryBindingError::FacilityAdmissionAttemptMismatch);
        }
        if admission.observation.observed_at > deadline.started_at()
            || deadline
                .started_at()
                .saturating_duration_since(admission.observation.observed_at)
                > MAX_CANARY_FACILITY_OBSERVATION_AGE
            || admission.observation.fresh_until < deadline.expires_at()
        {
            return Err(CanaryBindingError::FacilityAdmissionExpired);
        }
        let dns_expectations = CanaryDnsExpectationSlots::derive(families, nonce);
        Ok(Self {
            schema_version: FUNCTIONAL_CANARY_SCHEMA_VERSION,
            pre_binding,
            nonce,
            deadline,
            families,
            dns_expectations,
            counter_bounds,
        })
    }

    #[must_use]
    pub(crate) const fn deadline(&self) -> CanaryDeadline {
        self.deadline
    }

    #[must_use]
    pub(crate) const fn nonce(&self) -> CanaryNonce {
        self.nonce
    }

    #[must_use]
    pub(crate) const fn pre_binding(&self) -> &CanaryAttemptBinding {
        &self.pre_binding
    }

    #[must_use]
    pub(crate) const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub(crate) const fn families(&self) -> CanaryAddressFamilies {
        self.families
    }

    #[must_use]
    pub(crate) const fn expected_dns(&self, flow: CanaryFlow) -> Option<CanaryDnsExpectation> {
        self.dns_expectations.slots[flow.index()]
    }

    #[must_use]
    pub(crate) const fn counter_bounds(&self) -> CanaryCounterDeltaBounds {
        self.counter_bounds
    }

    pub(crate) fn requires_flow(&self, flow: CanaryFlow) -> bool {
        flow.is_ipv4() || self.families == CanaryAddressFamilies::Ipv4AndIpv6
    }

    pub(crate) fn peer_address(&self, flow: CanaryFlow) -> IpAddr {
        if flow.is_ipv4() {
            IpAddr::V4(self.pre_binding.environment.facility.ipv4.peer)
        } else {
            IpAddr::V6(
                self.pre_binding
                    .environment
                    .facility
                    .ipv6
                    .expect("dual-stack request construction requires IPv6 facility")
                    .peer,
            )
        }
    }

    pub(crate) fn daemon_address(&self, flow: CanaryFlow) -> IpAddr {
        if flow.is_ipv4() {
            IpAddr::V4(self.pre_binding.environment.facility.ipv4.daemon)
        } else {
            IpAddr::V6(
                self.pre_binding
                    .environment
                    .facility
                    .ipv6
                    .expect("dual-stack request construction requires IPv6 facility")
                    .daemon,
            )
        }
    }

    pub(crate) const fn responder_port(&self, flow: CanaryFlow) -> NonZeroU16 {
        match flow.kind() {
            CanaryFlowKind::TcpEcho => self.pre_binding.environment.facility.ports.tcp_echo,
            CanaryFlowKind::UdpEcho => self.pre_binding.environment.facility.ports.udp_echo,
            CanaryFlowKind::DnsUdp | CanaryFlowKind::DnsTcp => {
                self.pre_binding.environment.facility.ports.dns
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryFlowKind {
    TcpEcho,
    UdpEcho,
    DnsUdp,
    DnsTcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CanaryFlow {
    Ipv4TcpEcho = 0,
    Ipv4UdpEcho = 1,
    Ipv4DnsUdp = 2,
    Ipv4DnsTcp = 3,
    Ipv6TcpEcho = 4,
    Ipv6UdpEcho = 5,
    Ipv6DnsUdp = 6,
    Ipv6DnsTcp = 7,
}

impl CanaryFlow {
    const ALL: [Self; FUNCTIONAL_CANARY_FLOW_SLOTS] = [
        Self::Ipv4TcpEcho,
        Self::Ipv4UdpEcho,
        Self::Ipv4DnsUdp,
        Self::Ipv4DnsTcp,
        Self::Ipv6TcpEcho,
        Self::Ipv6UdpEcho,
        Self::Ipv6DnsUdp,
        Self::Ipv6DnsTcp,
    ];

    pub(crate) const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn is_ipv4(self) -> bool {
        self.index() < 4
    }

    pub(crate) const fn kind(self) -> CanaryFlowKind {
        match self {
            Self::Ipv4TcpEcho | Self::Ipv6TcpEcho => CanaryFlowKind::TcpEcho,
            Self::Ipv4UdpEcho | Self::Ipv6UdpEcho => CanaryFlowKind::UdpEcho,
            Self::Ipv4DnsUdp | Self::Ipv6DnsUdp => CanaryFlowKind::DnsUdp,
            Self::Ipv4DnsTcp | Self::Ipv6DnsTcp => CanaryFlowKind::DnsTcp,
        }
    }

    const fn is_dns(self) -> bool {
        matches!(self.kind(), CanaryFlowKind::DnsUdp | CanaryFlowKind::DnsTcp)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryFlowTuple {
    source: SocketAddr,
    destination: SocketAddr,
}

impl CanaryFlowTuple {
    #[must_use]
    pub(crate) const fn new(source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            source,
            destination,
        }
    }

    #[must_use]
    pub(crate) const fn source(self) -> SocketAddr {
        self.source
    }

    #[must_use]
    pub(crate) const fn destination(self) -> SocketAddr {
        self.destination
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CanaryDnsQuestionDigest([u8; CANARY_DNS_QUESTION_DIGEST_BYTES]);

impl CanaryDnsQuestionDigest {
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; CANARY_DNS_QUESTION_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryDnsQuestion {
    wire_name: [u8; CANARY_DNS_WIRE_NAME_BYTES],
    record_type: u16,
}

impl CanaryDnsQuestion {
    #[must_use]
    pub(crate) const fn wire_name(&self) -> &[u8; CANARY_DNS_WIRE_NAME_BYTES] {
        &self.wire_name
    }

    #[must_use]
    pub(crate) const fn record_type(self) -> u16 {
        self.record_type
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryDnsExpectation {
    flow: CanaryFlow,
    nonce: CanaryNonce,
    transaction_id: u16,
    question: CanaryDnsQuestion,
    question_digest: CanaryDnsQuestionDigest,
    answer: IpAddr,
}

impl CanaryDnsExpectation {
    const fn derived(
        flow: CanaryFlow,
        nonce: CanaryNonce,
        transaction_id: u16,
        question: CanaryDnsQuestion,
        question_digest: CanaryDnsQuestionDigest,
        answer: IpAddr,
    ) -> Self {
        Self {
            flow,
            nonce,
            transaction_id,
            question,
            question_digest,
            answer,
        }
    }

    #[must_use]
    pub(crate) const fn transaction_id(self) -> u16 {
        self.transaction_id
    }

    #[must_use]
    pub(crate) const fn question(self) -> CanaryDnsQuestion {
        self.question
    }

    #[must_use]
    pub(crate) const fn question_digest(self) -> CanaryDnsQuestionDigest {
        self.question_digest
    }

    #[must_use]
    pub(crate) const fn answer(self) -> IpAddr {
        self.answer
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryDnsExpectationSlots {
    slots: [Option<CanaryDnsExpectation>; FUNCTIONAL_CANARY_FLOW_SLOTS],
}

impl CanaryDnsExpectationSlots {
    fn derive(families: CanaryAddressFamilies, nonce: CanaryNonce) -> Self {
        Self {
            slots: std::array::from_fn(|index| {
                let flow = CanaryFlow::ALL[index];
                let required = flow.is_dns()
                    && (flow.is_ipv4() || families == CanaryAddressFamilies::Ipv4AndIpv6);
                required.then(|| derive_dns_expectation(flow, nonce))
            }),
        }
    }
}

fn derive_dns_expectation(flow: CanaryFlow, nonce: CanaryNonce) -> CanaryDnsExpectation {
    let tag = u8::try_from(flow.index()).expect("canary flow index fits in u8");
    let mut wire_name = [0_u8; CANARY_DNS_WIRE_NAME_BYTES];
    wire_name[0] = 2;
    wire_name[1] = b'f';
    wire_name[2] = hex_nibble(tag);
    wire_name[3] = 32;
    encode_hex(&nonce.as_bytes()[..16], &mut wire_name[4..36]);
    wire_name[36] = 32;
    encode_hex(&nonce.as_bytes()[16..], &mut wire_name[37..69]);
    wire_name[69..74].copy_from_slice(&[4, b'f', b'l', b'u', b'x']);
    wire_name[74..82].copy_from_slice(&[7, b'i', b'n', b'v', b'a', b'l', b'i', b'd']);
    let record_type = if flow.is_ipv4() { 1_u16 } else { 28_u16 };
    let question = CanaryDnsQuestion {
        wire_name,
        record_type,
    };
    let mut hasher = Sha256::new();
    hasher.update(b"flux-functional-canary-dns-question-v1");
    hasher.update(question.wire_name);
    hasher.update(record_type.to_be_bytes());
    hasher.update(1_u16.to_be_bytes());
    let question_bytes: [u8; CANARY_DNS_QUESTION_DIGEST_BYTES] = hasher.finalize().into();
    let transaction_id = u16::from_be_bytes([question_bytes[0], question_bytes[1]]);
    let question_digest = CanaryDnsQuestionDigest::from_bytes(question_bytes);
    let answer = if flow.is_ipv4() {
        IpAddr::V4(Ipv4Addr::new(
            192,
            0,
            2,
            (nonce.as_bytes()[usize::from(tag) % FUNCTIONAL_CANARY_NONCE_BYTES] % 254) + 1,
        ))
    } else {
        let mut octets = [0_u8; 16];
        octets[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        octets[4..].copy_from_slice(&nonce.as_bytes()[..12]);
        octets[15] ^= tag;
        IpAddr::V6(Ipv6Addr::from(octets))
    };
    CanaryDnsExpectation::derived(
        flow,
        nonce,
        transaction_id,
        question,
        question_digest,
        answer,
    )
}

fn encode_hex(input: &[u8], output: &mut [u8]) {
    debug_assert_eq!(output.len(), input.len() * 2);
    for (index, byte) in input.iter().copied().enumerate() {
        output[index * 2] = hex_nibble(byte >> 4);
        output[index * 2 + 1] = hex_nibble(byte & 0x0f);
    }
}

const fn hex_nibble(value: u8) -> u8 {
    match value & 0x0f {
        nibble @ 0..=9 => b'0' + nibble,
        nibble => b'a' + (nibble - 10),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryDnsEvidence {
    sent_transaction_id: u16,
    received_transaction_id: u16,
    peer_transaction_id: u16,
    sent_question: CanaryDnsQuestionDigest,
    received_question: CanaryDnsQuestionDigest,
    peer_question: CanaryDnsQuestionDigest,
    received_answer: IpAddr,
    peer_answer: IpAddr,
}

impl UnqualifiedCanaryDnsEvidence {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) const fn new(
        sent_transaction_id: u16,
        received_transaction_id: u16,
        peer_transaction_id: u16,
        sent_question: CanaryDnsQuestionDigest,
        received_question: CanaryDnsQuestionDigest,
        peer_question: CanaryDnsQuestionDigest,
        received_answer: IpAddr,
        peer_answer: IpAddr,
    ) -> Self {
        Self {
            sent_transaction_id,
            received_transaction_id,
            peer_transaction_id,
            sent_question,
            received_question,
            peer_question,
            received_answer,
            peer_answer,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryFlowEvidence {
    flow: CanaryFlow,
    nonce_sent: CanaryNonce,
    nonce_received: CanaryNonce,
    nonce_peer_observed: CanaryNonce,
    client_tuple: CanaryFlowTuple,
    peer_tuple: CanaryFlowTuple,
    started_at: Instant,
    completed_at: Instant,
    dns: Option<UnqualifiedCanaryDnsEvidence>,
}

impl UnqualifiedCanaryFlowEvidence {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) const fn new(
        flow: CanaryFlow,
        nonce_sent: CanaryNonce,
        nonce_received: CanaryNonce,
        nonce_peer_observed: CanaryNonce,
        client_tuple: CanaryFlowTuple,
        peer_tuple: CanaryFlowTuple,
        started_at: Instant,
        completed_at: Instant,
        dns: Option<UnqualifiedCanaryDnsEvidence>,
    ) -> Self {
        Self {
            flow,
            nonce_sent,
            nonce_received,
            nonce_peer_observed,
            client_tuple,
            peer_tuple,
            started_at,
            completed_at,
            dns,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryFlowEvidenceSlots {
    slots: [Option<UnqualifiedCanaryFlowEvidence>; FUNCTIONAL_CANARY_FLOW_SLOTS],
}

impl UnqualifiedCanaryFlowEvidenceSlots {
    #[must_use]
    pub(crate) const fn new(
        slots: [Option<UnqualifiedCanaryFlowEvidence>; FUNCTIONAL_CANARY_FLOW_SLOTS],
    ) -> Self {
        Self { slots }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryOutboundEvidence {
    flow: CanaryFlow,
    tuple: CanaryFlowTuple,
    socket_correlation: CanarySocketCorrelation,
    observed_uid: NonZeroU32,
    observed_socket_mark: u32,
}

impl UnqualifiedCanaryOutboundEvidence {
    #[must_use]
    pub(crate) const fn new(
        flow: CanaryFlow,
        tuple: CanaryFlowTuple,
        socket_correlation: CanarySocketCorrelation,
        observed_uid: NonZeroU32,
        observed_socket_mark: u32,
    ) -> Self {
        Self {
            flow,
            tuple,
            socket_correlation,
            observed_uid,
            observed_socket_mark,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryOutboundEvidenceSlots {
    slots: [Option<UnqualifiedCanaryOutboundEvidence>; FUNCTIONAL_CANARY_FLOW_SLOTS],
}

impl UnqualifiedCanaryOutboundEvidenceSlots {
    #[must_use]
    pub(crate) const fn new(
        slots: [Option<UnqualifiedCanaryOutboundEvidence>; FUNCTIONAL_CANARY_FLOW_SLOTS],
    ) -> Self {
        Self { slots }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryNegativeRouteControl {
    flow: CanaryFlow,
    tuple: CanaryFlowTuple,
    observed_at: Instant,
    queried_uid: NonZeroU32,
    mark: u32,
    selected_table: RouteTableId,
    peer_observation_count: u8,
}

impl UnqualifiedCanaryNegativeRouteControl {
    #[must_use]
    pub(crate) const fn new(
        flow: CanaryFlow,
        tuple: CanaryFlowTuple,
        observed_at: Instant,
        queried_uid: NonZeroU32,
        mark: u32,
        selected_table: RouteTableId,
        peer_observation_count: u8,
    ) -> Self {
        Self {
            flow,
            tuple,
            observed_at,
            queried_uid,
            mark,
            selected_table,
            peer_observation_count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryNegativeRouteControlSlots {
    slots: [Option<UnqualifiedCanaryNegativeRouteControl>; CANARY_NEGATIVE_CONTROL_SLOTS],
}

impl UnqualifiedCanaryNegativeRouteControlSlots {
    #[must_use]
    pub(crate) const fn new(
        slots: [Option<UnqualifiedCanaryNegativeRouteControl>; CANARY_NEGATIVE_CONTROL_SLOTS],
    ) -> Self {
        Self { slots }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryLoopEvidence {
    outbound: UnqualifiedCanaryOutboundEvidenceSlots,
    negative_route_controls: UnqualifiedCanaryNegativeRouteControlSlots,
}

impl UnqualifiedCanaryLoopEvidence {
    #[must_use]
    pub(crate) const fn new(
        outbound: UnqualifiedCanaryOutboundEvidenceSlots,
        negative_route_controls: UnqualifiedCanaryNegativeRouteControlSlots,
    ) -> Self {
        Self {
            outbound,
            negative_route_controls,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryCleanupStatus {
    NotRequired,
    VerifiedAbsent,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryProcessIdentity {
    pid: NonZeroU32,
    start_time_ticks: NonZeroU64,
}

impl CanaryProcessIdentity {
    #[must_use]
    pub(crate) const fn new(pid: NonZeroU32, start_time_ticks: NonZeroU64) -> Self {
        Self {
            pid,
            start_time_ticks,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryCleanupEvidence {
    nonce: CanaryNonce,
    objects: CanaryAttemptObjectIdentities,
    client: CanaryProcessIdentity,
    client_quiesced: bool,
    client_terminated: bool,
    client_reaped: bool,
    peer_servers: [CanaryProcessIdentity; CANARY_PEER_SERVER_SLOTS],
    peer_servers_stopped: [bool; CANARY_PEER_SERVER_SLOTS],
    peer_servers_reaped: [bool; CANARY_PEER_SERVER_SLOTS],
    selector_absent: bool,
    leak_guard_absent: bool,
    counters_absent: bool,
    retained_facility: CanaryFacilityIdentity,
}

impl UnqualifiedCanaryCleanupEvidence {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) const fn new(
        nonce: CanaryNonce,
        objects: CanaryAttemptObjectIdentities,
        client: CanaryProcessIdentity,
        client_quiesced: bool,
        client_terminated: bool,
        client_reaped: bool,
        peer_servers: [CanaryProcessIdentity; CANARY_PEER_SERVER_SLOTS],
        peer_servers_stopped: [bool; CANARY_PEER_SERVER_SLOTS],
        peer_servers_reaped: [bool; CANARY_PEER_SERVER_SLOTS],
        selector_absent: bool,
        leak_guard_absent: bool,
        counters_absent: bool,
        retained_facility: CanaryFacilityIdentity,
    ) -> Self {
        Self {
            nonce,
            objects,
            client,
            client_quiesced,
            client_terminated,
            client_reaped,
            peer_servers,
            peer_servers_stopped,
            peer_servers_reaped,
            selector_absent,
            leak_guard_absent,
            counters_absent,
            retained_facility,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryCounterSnapshot {
    capture_packets: u64,
    bypass_packets: u64,
    recapture_packets: u64,
}

impl CanaryCounterSnapshot {
    #[must_use]
    pub(crate) const fn new(
        capture_packets: u64,
        bypass_packets: u64,
        recapture_packets: u64,
    ) -> Self {
        Self {
            capture_packets,
            bypass_packets,
            recapture_packets,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryCounterEvidence {
    object: CanaryAttemptObjectIdentity,
    before_observed_at: Instant,
    before: CanaryCounterSnapshot,
    after_observed_at: Instant,
    after: CanaryCounterSnapshot,
}

impl UnqualifiedCanaryCounterEvidence {
    #[must_use]
    pub(crate) const fn new(
        object: CanaryAttemptObjectIdentity,
        before_observed_at: Instant,
        before: CanaryCounterSnapshot,
        after_observed_at: Instant,
        after: CanaryCounterSnapshot,
    ) -> Self {
        Self {
            object,
            before_observed_at,
            before,
            after_observed_at,
            after,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryGateEvidence {
    request: CanaryAttemptRequest,
    completed_at: Instant,
    flows: UnqualifiedCanaryFlowEvidenceSlots,
    unexpected_flow_count: u8,
    loop_escape: UnqualifiedCanaryLoopEvidence,
    counters: UnqualifiedCanaryCounterEvidence,
    cleanup: UnqualifiedCanaryCleanupEvidence,
}

impl UnqualifiedCanaryGateEvidence {
    #[must_use]
    pub(crate) const fn new(
        request: CanaryAttemptRequest,
        completed_at: Instant,
        flows: UnqualifiedCanaryFlowEvidenceSlots,
        unexpected_flow_count: u8,
        loop_escape: UnqualifiedCanaryLoopEvidence,
        counters: UnqualifiedCanaryCounterEvidence,
        cleanup: UnqualifiedCanaryCleanupEvidence,
    ) -> Self {
        Self {
            request,
            completed_at,
            flows,
            unexpected_flow_count,
            loop_escape,
            counters,
            cleanup,
        }
    }

    pub(crate) fn validate_for(
        self,
        expected: &CanaryAttemptRequest,
        post_binding: &CanaryAttemptBinding,
        coordinator_observed_at: Instant,
    ) -> Result<ValidatedUnqualifiedCanaryGateEvidence, CanaryEvidenceError> {
        if &self.request != expected {
            return Err(CanaryEvidenceError::RequestMismatch);
        }
        if expected.pre_binding() != post_binding {
            return Err(CanaryEvidenceError::AttemptBindingChanged);
        }
        let deadline = expected.deadline();
        if self.completed_at < deadline.started_at() {
            return Err(CanaryEvidenceError::CompletionBeforeStart);
        }
        if self.completed_at >= deadline.expires_at() {
            return Err(CanaryEvidenceError::CompletionAtOrAfterDeadline);
        }
        if coordinator_observed_at < self.completed_at {
            return Err(CanaryEvidenceError::CoordinatorObservationBeforeCompletion);
        }
        if coordinator_observed_at >= deadline.expires_at() {
            return Err(CanaryEvidenceError::CoordinatorObservationAtOrAfterDeadline);
        }
        if self.unexpected_flow_count != 0 {
            return Err(CanaryEvidenceError::UnexpectedFlows {
                count: self.unexpected_flow_count,
            });
        }
        validate_flow_evidence(expected, &self.flows, self.completed_at)?;
        validate_loop_evidence(expected, &self.flows, &self.loop_escape)?;
        validate_counter_evidence(expected, &self.flows, self.completed_at, self.counters)?;
        validate_cleanup_evidence(expected, &self.cleanup)?;
        Ok(ValidatedUnqualifiedCanaryGateEvidence(self))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ValidatedUnqualifiedCanaryGateEvidence(UnqualifiedCanaryGateEvidence);

impl ValidatedUnqualifiedCanaryGateEvidence {
    #[must_use]
    pub(crate) const fn evidence(&self) -> &UnqualifiedCanaryGateEvidence {
        &self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FunctionalCanaryDisposition {
    StructuralOnlyCompatibility,
    AttemptPassedUnqualified(Box<ValidatedUnqualifiedCanaryGateEvidence>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryEvidenceError {
    RequestMismatch,
    AttemptBindingChanged,
    CompletionBeforeStart,
    CompletionAtOrAfterDeadline,
    CoordinatorObservationBeforeCompletion,
    CoordinatorObservationAtOrAfterDeadline,
    MissingFlow {
        flow: CanaryFlow,
    },
    UnexpectedFlowSlot {
        flow: CanaryFlow,
    },
    FlowSlotMismatch {
        expected: CanaryFlow,
        observed: CanaryFlow,
    },
    FlowNonceMismatch {
        flow: CanaryFlow,
    },
    FlowTimingInvalid {
        flow: CanaryFlow,
    },
    FlowTupleMismatch {
        flow: CanaryFlow,
    },
    DnsEvidenceMissing {
        flow: CanaryFlow,
    },
    DnsEvidenceUnexpected {
        flow: CanaryFlow,
    },
    DnsEvidenceMismatch {
        flow: CanaryFlow,
    },
    FlowCompletesAfterAttempt {
        flow: CanaryFlow,
    },
    UnexpectedFlows {
        count: u8,
    },
    MissingOutboundLoopEvidence {
        flow: CanaryFlow,
    },
    UnexpectedOutboundLoopEvidence {
        flow: CanaryFlow,
    },
    OutboundLoopFlowMismatch {
        expected: CanaryFlow,
        observed: CanaryFlow,
    },
    OutboundTupleMismatch {
        flow: CanaryFlow,
    },
    OutboundProxyMarkNotClear {
        flow: CanaryFlow,
    },
    OutboundUidMismatch {
        flow: CanaryFlow,
    },
    OutboundEngineMismatch {
        flow: CanaryFlow,
    },
    OutboundSocketObserverMismatch {
        flow: CanaryFlow,
    },
    OutboundSocketCorrelationNonceMismatch {
        flow: CanaryFlow,
    },
    OutboundSocketCorrelationLoss {
        flow: CanaryFlow,
    },
    OutboundSocketCorrelationIdentityMismatch {
        flow: CanaryFlow,
    },
    OutboundSocketCorrelationProtocolMismatch {
        flow: CanaryFlow,
    },
    OutboundSocketCorrelationTupleMismatch {
        flow: CanaryFlow,
    },
    OutboundSocketCorrelationUidMismatch {
        flow: CanaryFlow,
    },
    OutboundSocketCorrelationMarkMismatch {
        flow: CanaryFlow,
    },
    OutboundSocketCorrelationTimingInvalid {
        flow: CanaryFlow,
    },
    MissingNegativeControl {
        ipv6: bool,
    },
    UnexpectedNegativeControl {
        ipv6: bool,
    },
    NegativeControlFlowMismatch {
        expected: CanaryFlow,
        observed: CanaryFlow,
    },
    NegativeControlFlowNotRequired,
    NegativeControlTupleMismatch,
    NegativeControlUidMismatch,
    NegativeControlTimingInvalid,
    NegativeControlMarkMismatch,
    NegativeControlSelectedPeerTable,
    NegativeControlSelectedWrongTable,
    NegativeControlReachedPeer {
        count: u8,
    },
    CounterObjectMismatch,
    CounterTimingInvalid,
    CounterRegressed,
    CaptureCounterDeltaOutOfRange {
        observed: u64,
    },
    BypassCounterDeltaOutOfRange {
        observed: u64,
    },
    RecaptureCounterDeltaOutOfRange {
        observed: u64,
    },
    CleanupNonceMismatch,
    CleanupObjectMismatch,
    CleanupClientNotQuiesced,
    CleanupClientNotTerminated,
    CleanupClientNotReaped,
    CleanupPeerServerNotStopped {
        slot: usize,
    },
    CleanupPeerServerNotReaped {
        slot: usize,
    },
    CleanupProcessIdentityCollision,
    CleanupSelectorPresent,
    CleanupLeakGuardPresent,
    CleanupCountersPresent,
    CleanupFacilityChanged,
}

impl fmt::Display for CanaryEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unqualified functional canary evidence is invalid: {self:?}"
        )
    }
}

impl Error for CanaryEvidenceError {}

fn validate_flow_evidence(
    request: &CanaryAttemptRequest,
    evidence: &UnqualifiedCanaryFlowEvidenceSlots,
    attempt_completed_at: Instant,
) -> Result<(), CanaryEvidenceError> {
    for expected_flow in CanaryFlow::ALL {
        let slot = &evidence.slots[expected_flow.index()];
        if !request.requires_flow(expected_flow) {
            if slot.is_some() {
                return Err(CanaryEvidenceError::UnexpectedFlowSlot {
                    flow: expected_flow,
                });
            }
            continue;
        }
        let observed = slot.as_ref().ok_or(CanaryEvidenceError::MissingFlow {
            flow: expected_flow,
        })?;
        if observed.flow != expected_flow {
            return Err(CanaryEvidenceError::FlowSlotMismatch {
                expected: expected_flow,
                observed: observed.flow,
            });
        }
        if observed.nonce_sent != request.nonce()
            || observed.nonce_received != request.nonce()
            || observed.nonce_peer_observed != request.nonce()
        {
            return Err(CanaryEvidenceError::FlowNonceMismatch {
                flow: expected_flow,
            });
        }
        let deadline = request.deadline();
        if observed.started_at < deadline.started_at()
            || observed.completed_at < observed.started_at
            || observed.completed_at >= deadline.expires_at()
        {
            return Err(CanaryEvidenceError::FlowTimingInvalid {
                flow: expected_flow,
            });
        }
        if observed.completed_at > attempt_completed_at {
            return Err(CanaryEvidenceError::FlowCompletesAfterAttempt {
                flow: expected_flow,
            });
        }
        let peer = SocketAddr::new(
            request.peer_address(expected_flow),
            request.responder_port(expected_flow).get(),
        );
        if observed.client_tuple.destination != peer
            || observed.peer_tuple.destination != peer
            || observed.peer_tuple.source.ip() != request.daemon_address(expected_flow)
            || observed.client_tuple.source.is_ipv4() != expected_flow.is_ipv4()
            || observed.peer_tuple.source.is_ipv4() != expected_flow.is_ipv4()
        {
            return Err(CanaryEvidenceError::FlowTupleMismatch {
                flow: expected_flow,
            });
        }
        match (expected_flow.is_dns(), observed.dns) {
            (true, Some(dns)) => validate_dns(
                expected_flow,
                dns,
                request.dns_expectations.slots[expected_flow.index()]
                    .expect("request construction validates required DNS expectations"),
            )?,
            (true, None) => {
                return Err(CanaryEvidenceError::DnsEvidenceMissing {
                    flow: expected_flow,
                });
            }
            (false, Some(_)) => {
                return Err(CanaryEvidenceError::DnsEvidenceUnexpected {
                    flow: expected_flow,
                });
            }
            (false, None) => {}
        }
    }
    Ok(())
}

fn validate_dns(
    flow: CanaryFlow,
    evidence: UnqualifiedCanaryDnsEvidence,
    expected: CanaryDnsExpectation,
) -> Result<(), CanaryEvidenceError> {
    if evidence.sent_transaction_id != expected.transaction_id
        || evidence.received_transaction_id != expected.transaction_id
        || evidence.peer_transaction_id != expected.transaction_id
        || evidence.sent_question != expected.question_digest
        || evidence.received_question != expected.question_digest
        || evidence.peer_question != expected.question_digest
        || evidence.received_answer != expected.answer
        || evidence.peer_answer != expected.answer
        || expected.answer.is_ipv4() != flow.is_ipv4()
    {
        return Err(CanaryEvidenceError::DnsEvidenceMismatch { flow });
    }
    Ok(())
}

fn validate_loop_evidence(
    request: &CanaryAttemptRequest,
    flows: &UnqualifiedCanaryFlowEvidenceSlots,
    loop_evidence: &UnqualifiedCanaryLoopEvidence,
) -> Result<(), CanaryEvidenceError> {
    let rpdb = request.pre_binding.environment.rpdb;
    let mask = rpdb.proxy_mark_mask.get();
    for expected_flow in CanaryFlow::ALL {
        let outbound = &loop_evidence.outbound.slots[expected_flow.index()];
        if !request.requires_flow(expected_flow) {
            if outbound.is_some() {
                return Err(CanaryEvidenceError::UnexpectedOutboundLoopEvidence {
                    flow: expected_flow,
                });
            }
            continue;
        }
        let outbound =
            outbound
                .as_ref()
                .ok_or(CanaryEvidenceError::MissingOutboundLoopEvidence {
                    flow: expected_flow,
                })?;
        if outbound.flow != expected_flow {
            return Err(CanaryEvidenceError::OutboundLoopFlowMismatch {
                expected: expected_flow,
                observed: outbound.flow,
            });
        }
        let flow = flows.slots[expected_flow.index()]
            .as_ref()
            .expect("flow evidence is validated before loop evidence");
        if outbound.tuple != flow.peer_tuple {
            return Err(CanaryEvidenceError::OutboundTupleMismatch {
                flow: expected_flow,
            });
        }
        if outbound.observed_uid != rpdb.engine_uid {
            return Err(CanaryEvidenceError::OutboundUidMismatch {
                flow: expected_flow,
            });
        }
        validate_socket_correlation(request, expected_flow, flow, outbound)?;
        if outbound.observed_socket_mark & mask != 0 {
            return Err(CanaryEvidenceError::OutboundProxyMarkNotClear {
                flow: expected_flow,
            });
        }
    }

    for slot_index in 0..CANARY_NEGATIVE_CONTROL_SLOTS {
        let ipv6 = slot_index == 1;
        let required = !ipv6 || request.families == CanaryAddressFamilies::Ipv4AndIpv6;
        let negative = loop_evidence.negative_route_controls.slots[slot_index];
        if !required {
            if negative.is_some() {
                return Err(CanaryEvidenceError::UnexpectedNegativeControl { ipv6 });
            }
            continue;
        }
        let negative = negative.ok_or(CanaryEvidenceError::MissingNegativeControl { ipv6 })?;
        let expected_flow = if ipv6 {
            CanaryFlow::Ipv6TcpEcho
        } else {
            CanaryFlow::Ipv4TcpEcho
        };
        if negative.flow != expected_flow {
            return Err(CanaryEvidenceError::NegativeControlFlowMismatch {
                expected: expected_flow,
                observed: negative.flow,
            });
        }
        let flow = flows.slots[expected_flow.index()]
            .as_ref()
            .expect("required flow evidence is validated before loop evidence");
        if negative.tuple != flow.peer_tuple {
            return Err(CanaryEvidenceError::NegativeControlTupleMismatch);
        }
        if negative.queried_uid != rpdb.engine_uid {
            return Err(CanaryEvidenceError::NegativeControlUidMismatch);
        }
        let first_positive_flow = CanaryFlow::ALL
            .iter()
            .filter(|flow| flow.is_ipv4() != ipv6)
            .filter_map(|flow| flows.slots[flow.index()].as_ref())
            .map(|evidence| evidence.started_at)
            .min()
            .expect("the required address family has positive flow evidence");
        if negative.observed_at < request.deadline().started_at()
            || negative.observed_at >= first_positive_flow
        {
            return Err(CanaryEvidenceError::NegativeControlTimingInvalid);
        }
        if negative.mark != rpdb.proxy_mark_value {
            return Err(CanaryEvidenceError::NegativeControlMarkMismatch);
        }
        if negative.selected_table.get() == rpdb.peer_table.get() {
            return Err(CanaryEvidenceError::NegativeControlSelectedPeerTable);
        }
        if negative.selected_table.get() != rpdb.proxy_capture_table.get() {
            return Err(CanaryEvidenceError::NegativeControlSelectedWrongTable);
        }
        if negative.peer_observation_count != 0 {
            return Err(CanaryEvidenceError::NegativeControlReachedPeer {
                count: negative.peer_observation_count,
            });
        }
    }
    Ok(())
}

fn validate_socket_correlation(
    request: &CanaryAttemptRequest,
    flow: CanaryFlow,
    flow_evidence: &UnqualifiedCanaryFlowEvidence,
    outbound: &UnqualifiedCanaryOutboundEvidence,
) -> Result<(), CanaryEvidenceError> {
    let correlation = outbound.socket_correlation;
    if correlation.process() != request.pre_binding.engine.engine() {
        return Err(CanaryEvidenceError::OutboundEngineMismatch { flow });
    }
    let expected_observer = request.pre_binding.environment.authority.socket_observer;
    if correlation.observer() != expected_observer {
        return Err(CanaryEvidenceError::OutboundSocketObserverMismatch { flow });
    }
    match (expected_observer, correlation) {
        (
            CanarySocketObserverAuthority::ProcFdInetDiag { .. },
            CanarySocketCorrelation::ProcFdInetDiag {
                fd_socket_inode,
                diag_socket_inode,
                diag_protocol,
                diag_tuple,
                diag_uid,
                diag_socket_mark,
                fd_scan_complete,
                diag_dump_complete,
                snapshot_started_at,
                snapshot_completed_at,
                dump_started_at,
                dump_completed_at,
                ..
            },
        ) => {
            if snapshot_started_at >= dump_started_at
                || dump_started_at >= dump_completed_at
                || dump_completed_at >= snapshot_completed_at
                || snapshot_started_at < flow_evidence.started_at
                || snapshot_completed_at > flow_evidence.completed_at
            {
                return Err(CanaryEvidenceError::OutboundSocketCorrelationTimingInvalid { flow });
            }
            if !fd_scan_complete || !diag_dump_complete {
                return Err(CanaryEvidenceError::OutboundSocketCorrelationLoss { flow });
            }
            if fd_socket_inode != diag_socket_inode {
                return Err(
                    CanaryEvidenceError::OutboundSocketCorrelationIdentityMismatch { flow },
                );
            }
            let expected_protocol = match flow.kind() {
                CanaryFlowKind::TcpEcho | CanaryFlowKind::DnsTcp => CanaryInetDiagProtocol::Tcp,
                CanaryFlowKind::UdpEcho | CanaryFlowKind::DnsUdp => CanaryInetDiagProtocol::Udp,
            };
            if diag_protocol != expected_protocol {
                return Err(
                    CanaryEvidenceError::OutboundSocketCorrelationProtocolMismatch { flow },
                );
            }
            if diag_tuple != outbound.tuple {
                return Err(CanaryEvidenceError::OutboundSocketCorrelationTupleMismatch { flow });
            }
            if diag_uid != outbound.observed_uid {
                return Err(CanaryEvidenceError::OutboundSocketCorrelationUidMismatch { flow });
            }
            if diag_socket_mark != outbound.observed_socket_mark {
                return Err(CanaryEvidenceError::OutboundSocketCorrelationMarkMismatch { flow });
            }
        }
        (
            CanarySocketObserverAuthority::QualifiedCgroupBpf { .. },
            CanarySocketCorrelation::QualifiedCgroupBpf {
                attempt_nonce,
                hook,
                lost_events_before,
                lost_events_after,
                observed_at,
                ..
            },
        ) => {
            if observed_at < flow_evidence.started_at || observed_at > flow_evidence.completed_at {
                return Err(CanaryEvidenceError::OutboundSocketCorrelationTimingInvalid { flow });
            }
            if attempt_nonce != request.nonce() {
                return Err(CanaryEvidenceError::OutboundSocketCorrelationNonceMismatch { flow });
            }
            if lost_events_before != lost_events_after {
                return Err(CanaryEvidenceError::OutboundSocketCorrelationLoss { flow });
            }
            let expected_hook = match (flow.kind(), flow.is_ipv4()) {
                (CanaryFlowKind::TcpEcho | CanaryFlowKind::DnsTcp, true) => {
                    CanaryBpfSocketHook::ConnectIpv4
                }
                (CanaryFlowKind::TcpEcho | CanaryFlowKind::DnsTcp, false) => {
                    CanaryBpfSocketHook::ConnectIpv6
                }
                (CanaryFlowKind::UdpEcho | CanaryFlowKind::DnsUdp, true) => {
                    CanaryBpfSocketHook::SendMessageIpv4
                }
                (CanaryFlowKind::UdpEcho | CanaryFlowKind::DnsUdp, false) => {
                    CanaryBpfSocketHook::SendMessageIpv6
                }
            };
            if hook != expected_hook {
                return Err(CanaryEvidenceError::OutboundSocketObserverMismatch { flow });
            }
        }
        _ => return Err(CanaryEvidenceError::OutboundSocketObserverMismatch { flow }),
    }
    Ok(())
}

fn validate_counter_evidence(
    request: &CanaryAttemptRequest,
    flows: &UnqualifiedCanaryFlowEvidenceSlots,
    attempt_completed_at: Instant,
    counters: UnqualifiedCanaryCounterEvidence,
) -> Result<(), CanaryEvidenceError> {
    if counters.object != request.pre_binding.environment.attempt_objects.counters {
        return Err(CanaryEvidenceError::CounterObjectMismatch);
    }
    let mut first_flow_started_at = None;
    let mut last_flow_completed_at = None;
    for flow in CanaryFlow::ALL {
        let Some(evidence) = flows.slots[flow.index()].as_ref() else {
            continue;
        };
        first_flow_started_at = Some(match first_flow_started_at {
            Some(current) => std::cmp::min(current, evidence.started_at),
            None => evidence.started_at,
        });
        last_flow_completed_at = Some(match last_flow_completed_at {
            Some(current) => std::cmp::max(current, evidence.completed_at),
            None => evidence.completed_at,
        });
    }
    let first_flow_started_at =
        first_flow_started_at.expect("request validation requires at least IPv4 flow evidence");
    let last_flow_completed_at =
        last_flow_completed_at.expect("request validation requires at least IPv4 flow evidence");
    if counters.before_observed_at < request.deadline().started_at()
        || counters.before_observed_at > first_flow_started_at
        || counters.after_observed_at < last_flow_completed_at
        || counters.after_observed_at > attempt_completed_at
        || counters.after_observed_at < counters.before_observed_at
    {
        return Err(CanaryEvidenceError::CounterTimingInvalid);
    }
    let capture_delta = counters
        .after
        .capture_packets
        .checked_sub(counters.before.capture_packets)
        .ok_or(CanaryEvidenceError::CounterRegressed)?;
    let bypass_delta = counters
        .after
        .bypass_packets
        .checked_sub(counters.before.bypass_packets)
        .ok_or(CanaryEvidenceError::CounterRegressed)?;
    let recapture_delta = counters
        .after
        .recapture_packets
        .checked_sub(counters.before.recapture_packets)
        .ok_or(CanaryEvidenceError::CounterRegressed)?;
    let bounds = request.counter_bounds;
    if capture_delta < bounds.capture_minimum.get() || capture_delta > bounds.capture_maximum.get()
    {
        return Err(CanaryEvidenceError::CaptureCounterDeltaOutOfRange {
            observed: capture_delta,
        });
    }
    if bypass_delta < bounds.bypass_minimum.get() || bypass_delta > bounds.bypass_maximum.get() {
        return Err(CanaryEvidenceError::BypassCounterDeltaOutOfRange {
            observed: bypass_delta,
        });
    }
    if recapture_delta > bounds.recapture_maximum {
        return Err(CanaryEvidenceError::RecaptureCounterDeltaOutOfRange {
            observed: recapture_delta,
        });
    }
    Ok(())
}

fn validate_cleanup_evidence(
    request: &CanaryAttemptRequest,
    cleanup: &UnqualifiedCanaryCleanupEvidence,
) -> Result<(), CanaryEvidenceError> {
    let environment = &request.pre_binding.environment;
    if cleanup.nonce != request.nonce() {
        return Err(CanaryEvidenceError::CleanupNonceMismatch);
    }
    if cleanup.objects != environment.attempt_objects {
        return Err(CanaryEvidenceError::CleanupObjectMismatch);
    }
    if !cleanup.client_quiesced {
        return Err(CanaryEvidenceError::CleanupClientNotQuiesced);
    }
    if !cleanup.client_terminated {
        return Err(CanaryEvidenceError::CleanupClientNotTerminated);
    }
    if !cleanup.client_reaped {
        return Err(CanaryEvidenceError::CleanupClientNotReaped);
    }
    if cleanup.peer_servers.contains(&cleanup.client) {
        return Err(CanaryEvidenceError::CleanupProcessIdentityCollision);
    }
    for first in 0..CANARY_PEER_SERVER_SLOTS {
        if !cleanup.peer_servers_stopped[first] {
            return Err(CanaryEvidenceError::CleanupPeerServerNotStopped { slot: first });
        }
        if !cleanup.peer_servers_reaped[first] {
            return Err(CanaryEvidenceError::CleanupPeerServerNotReaped { slot: first });
        }
        for second in first + 1..CANARY_PEER_SERVER_SLOTS {
            if cleanup.peer_servers[first] == cleanup.peer_servers[second] {
                return Err(CanaryEvidenceError::CleanupProcessIdentityCollision);
            }
        }
    }
    if !cleanup.selector_absent {
        return Err(CanaryEvidenceError::CleanupSelectorPresent);
    }
    if !cleanup.leak_guard_absent {
        return Err(CanaryEvidenceError::CleanupLeakGuardPresent);
    }
    if !cleanup.counters_absent {
        return Err(CanaryEvidenceError::CleanupCountersPresent);
    }
    if cleanup.retained_facility != environment.facility {
        return Err(CanaryEvidenceError::CleanupFacilityChanged);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryAvailability {
    Unsupported,
    Denied,
    Conflicting,
    Broken,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryErrorKind {
    Availability(CanaryAvailability),
    Busy,
    TimedOut,
    IdentityChanged,
    ResponseMismatch,
    UnexpectedFlow,
    LoopEscapeUnproven,
    InvalidEvidence,
    CleanupUncertain,
    AdapterFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FunctionalCanaryError {
    kind: CanaryErrorKind,
    cleanup: CanaryCleanupStatus,
    diagnostic: String,
}

impl FunctionalCanaryError {
    #[must_use]
    pub(crate) fn new(
        kind: CanaryErrorKind,
        cleanup: CanaryCleanupStatus,
        diagnostic: &str,
    ) -> Self {
        Self {
            kind,
            cleanup,
            diagnostic: bounded_prefix(diagnostic),
        }
    }

    #[must_use]
    pub(crate) fn diagnostic(&self) -> &str {
        &self.diagnostic
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> CanaryErrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn cleanup(&self) -> CanaryCleanupStatus {
        self.cleanup
    }
}

impl fmt::Display for FunctionalCanaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "functional canary failed ({:?}, cleanup {:?}): {}",
            self.kind, self.cleanup, self.diagnostic
        )
    }
}

impl Error for FunctionalCanaryError {}

pub(crate) trait UnqualifiedFunctionalCanaryExecutor: Send + 'static {
    fn execute(
        &mut self,
        request: &CanaryAttemptRequest,
    ) -> Result<UnqualifiedCanaryGateEvidence, FunctionalCanaryError>;
}

fn bounded_prefix(diagnostic: &str) -> String {
    let mut end = diagnostic.len().min(MAX_FUNCTIONAL_CANARY_DIAGNOSTIC_BYTES);
    while !diagnostic.is_char_boundary(end) {
        end -= 1;
    }
    diagnostic[..end].to_owned()
}

#[cfg(all(test, target_os = "linux"))]
mod linux_namespace_harness;

#[cfg(test)]
mod linux_tproxy_checkpoint_boundary {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum LinuxTproxyCheckpointHook {
        Output,
        Prerouting,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum LinuxTproxyCheckpointAction {
        SetMark,
        Tproxy,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) struct LinuxTproxyCheckpointRulePlan {
        rules: [(LinuxTproxyCheckpointHook, LinuxTproxyCheckpointAction); 2],
    }

    impl LinuxTproxyCheckpointRulePlan {
        pub(super) fn new(
            rules: [(LinuxTproxyCheckpointHook, LinuxTproxyCheckpointAction); 2],
        ) -> Option<Self> {
            if rules.iter().any(|(hook, action)| {
                matches!(action, LinuxTproxyCheckpointAction::Tproxy)
                    && !matches!(hook, LinuxTproxyCheckpointHook::Prerouting)
            }) {
                return None;
            }
            Some(Self { rules })
        }

        fn has_prerouting_tproxy(self) -> bool {
            self.rules.contains(&(
                LinuxTproxyCheckpointHook::Prerouting,
                LinuxTproxyCheckpointAction::Tproxy,
            ))
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) struct LinuxTproxyCheckpointEvidence {
        output_mark_packets: u64,
        prerouting_tproxy_packets: u64,
        listener_observations: u64,
    }

    impl LinuxTproxyCheckpointEvidence {
        pub(super) const fn new(
            output_mark_packets: u64,
            prerouting_tproxy_packets: u64,
            listener_observations: u64,
        ) -> Self {
            Self {
                output_mark_packets,
                prerouting_tproxy_packets,
                listener_observations,
            }
        }

        pub(super) const fn output_mark_packets(self) -> u64 {
            self.output_mark_packets
        }

        pub(super) fn qualifies_ingress_tproxy(self, plan: LinuxTproxyCheckpointRulePlan) -> bool {
            // OUTPUT marking is diagnostic evidence only. It cannot substitute for observing
            // both the PREROUTING TPROXY action and the transparent listener.
            plan.has_prerouting_tproxy()
                && self.prerouting_tproxy_packets > 0
                && self.listener_observations > 0
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};

    use flux_core::{NetworkInventoryTracker, OWNERSHIP_JOURNAL_IDENTITY_BYTES};
    use flux_platform::{SingBoxLaunchSpec, SingBoxLauncher, SingBoxReadiness};

    use super::linux_tproxy_checkpoint_boundary::{
        LinuxTproxyCheckpointAction, LinuxTproxyCheckpointEvidence, LinuxTproxyCheckpointHook,
        LinuxTproxyCheckpointRulePlan,
    };
    use super::*;
    use crate::RestartPolicy;

    #[test]
    fn linux_tproxy_checkpoint_rejects_output_mark_only_evidence() {
        assert!(
            LinuxTproxyCheckpointRulePlan::new([
                (
                    LinuxTproxyCheckpointHook::Output,
                    LinuxTproxyCheckpointAction::Tproxy,
                ),
                (
                    LinuxTproxyCheckpointHook::Prerouting,
                    LinuxTproxyCheckpointAction::Tproxy,
                ),
            ])
            .is_none()
        );

        let plan = LinuxTproxyCheckpointRulePlan::new([
            (
                LinuxTproxyCheckpointHook::Output,
                LinuxTproxyCheckpointAction::SetMark,
            ),
            (
                LinuxTproxyCheckpointHook::Prerouting,
                LinuxTproxyCheckpointAction::Tproxy,
            ),
        ])
        .expect("TPROXY is confined to PREROUTING");
        let output_mark_only = LinuxTproxyCheckpointEvidence::new(8, 0, 0);
        assert_eq!(output_mark_only.output_mark_packets(), 8);
        assert!(!output_mark_only.qualifies_ingress_tproxy(plan));
        assert!(!LinuxTproxyCheckpointEvidence::new(8, 8, 0).qualifies_ingress_tproxy(plan));
        assert!(!LinuxTproxyCheckpointEvidence::new(8, 0, 8).qualifies_ingress_tproxy(plan));
        assert!(LinuxTproxyCheckpointEvidence::new(0, 8, 8).qualifies_ingress_tproxy(plan));
    }

    #[test]
    fn deadline_is_absolute_nonzero_capped_and_exclusive() {
        let started_at = Instant::now();
        assert_eq!(
            CanaryDeadline::new(started_at, Duration::ZERO),
            Err(CanaryDeadlineError::ZeroDuration)
        );
        assert!(matches!(
            CanaryDeadline::new(started_at, Duration::from_secs(3) + Duration::from_nanos(1)),
            Err(CanaryDeadlineError::ExceedsMaximum { .. })
        ));
        let deadline = CanaryDeadline::new(started_at, Duration::from_secs(3))
            .expect("maximum deadline is accepted");
        assert_eq!(
            deadline.remaining(started_at + Duration::from_secs(1)),
            Duration::from_secs(2)
        );
        assert!(deadline.has_expired(deadline.expires_at()));
    }

    #[test]
    fn environment_binding_is_exact_and_rejects_ambiguous_authority() {
        assert_eq!(
            CaptureProgramDigest::new([0; CAPTURE_PROGRAM_DIGEST_BYTES]),
            Err(CanaryBindingError::AllZeroCaptureProgramDigest)
        );
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4AndIpv6);
        assert_eq!(
            fixture
                .request
                .pre_binding
                .environment
                .authority
                .boot_identity
                .as_str(),
            BOOT_ID
        );
        assert_eq!(
            fixture.request.pre_binding.environment.probe_uid.get(),
            20_002
        );
        assert_eq!(fixture.request.pre_binding.engine.engine().pid(), 4242);
        assert_eq!(
            fixture
                .request
                .pre_binding
                .engine
                .engine()
                .start_time_ticks(),
            98_765
        );
        assert_eq!(
            fixture
                .request
                .pre_binding
                .engine
                .engine_snapshot_revision()
                .get(),
            23
        );
        assert_eq!(
            fixture.request.pre_binding.engine.artifacts.binary,
            fixture
                ._engine
                .as_ref()
                .expect("fixture owns its engine")
                .spec
                .binary_digest()
        );
        assert_eq!(
            fixture.request.pre_binding.engine.artifacts.config,
            fixture
                ._engine
                .as_ref()
                .expect("fixture owns its engine")
                .spec
                .config_digest()
        );
        assert_eq!(
            fixture.request.pre_binding.engine.listener.port().get(),
            1536
        );
        assert_eq!(
            fixture
                .request
                .pre_binding
                .engine
                .listener
                .observation_path(),
            Path::new("/proc/4242/net/tcp")
        );
        assert_eq!(
            fixture
                .request
                .pre_binding
                .environment
                .authority
                .capture_program_digest
                .as_bytes(),
            &[3; CAPTURE_PROGRAM_DIGEST_BYTES]
        );
    }

    #[test]
    fn post_environment_must_equal_the_request_pre_binding() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let evidence = fixture.successful_evidence();
        let mut changed = fixture.request.pre_binding.clone();
        changed.environment.authority.ownership.journal_revision =
            OwnershipJournalRevision::new(2).expect("revision two");
        assert_eq!(
            evidence
                .validate_for(&fixture.request, &changed, fixture.observed_at())
                .expect_err("post-binding drift invalidates the attempt"),
            CanaryEvidenceError::AttemptBindingChanged
        );
    }

    #[test]
    fn fixed_ipv4_and_dual_stack_flow_slots_validate() {
        for families in [
            CanaryAddressFamilies::Ipv4Only,
            CanaryAddressFamilies::Ipv4AndIpv6,
        ] {
            let fixture = Fixture::new(families);
            let evidence = fixture.successful_evidence();
            let validated = evidence
                .validate_for(
                    &fixture.request,
                    fixture.request.pre_binding(),
                    fixture.observed_at(),
                )
                .expect("complete fixed-slot evidence validates");
            assert_eq!(validated.evidence().request, fixture.request);
        }
    }

    #[test]
    fn flow_nonce_slot_tuple_timing_and_dns_mismatches_are_rejected() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);

        let mut missing = fixture.successful_evidence();
        missing.flows.slots[CanaryFlow::Ipv4UdpEcho.index()] = None;
        assert_eq!(
            validate(&fixture, missing).expect_err("missing fixed slot cannot pass"),
            CanaryEvidenceError::MissingFlow {
                flow: CanaryFlow::Ipv4UdpEcho,
            }
        );

        let mut nonce = fixture.successful_evidence();
        nonce.flows.slots[0]
            .as_mut()
            .expect("IPv4 TCP evidence")
            .nonce_received = CanaryNonce::from_bytes([99; FUNCTIONAL_CANARY_NONCE_BYTES]);
        assert_eq!(
            validate(&fixture, nonce).expect_err("nonce mismatch cannot pass"),
            CanaryEvidenceError::FlowNonceMismatch {
                flow: CanaryFlow::Ipv4TcpEcho,
            }
        );

        let mut dns = fixture.successful_evidence();
        dns.flows.slots[CanaryFlow::Ipv4DnsUdp.index()]
            .as_mut()
            .expect("DNS evidence")
            .dns
            .as_mut()
            .expect("DNS detail")
            .received_transaction_id ^= 1;
        assert_eq!(
            validate(&fixture, dns).expect_err("DNS mismatch cannot pass"),
            CanaryEvidenceError::DnsEvidenceMismatch {
                flow: CanaryFlow::Ipv4DnsUdp,
            }
        );

        let other = request_with_nonce(
            &fixture
                ._engine
                .as_ref()
                .expect("fixture owns its engine")
                .spec,
            CanaryAddressFamilies::Ipv4Only,
            fixture.request.deadline().started_at() + Duration::from_secs(4),
            CanaryNonce::from_bytes([8; FUNCTIONAL_CANARY_NONCE_BYTES]),
        );
        assert_ne!(
            fixture.request.expected_dns(CanaryFlow::Ipv4DnsUdp),
            other.expected_dns(CanaryFlow::Ipv4DnsUdp),
            "a fresh nonce must derive a distinct DNS transaction"
        );
    }

    #[test]
    fn structured_loop_evidence_requires_clear_marks_and_negative_route_isolation() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let mut marked = fixture.successful_evidence();
        let proxy_mark = fixture
            .request
            .pre_binding
            .environment
            .rpdb
            .proxy_mark_value;
        let outbound = marked.loop_escape.outbound.slots[0]
            .as_mut()
            .expect("outbound evidence");
        outbound.observed_socket_mark = proxy_mark;
        let CanarySocketCorrelation::ProcFdInetDiag {
            diag_socket_mark, ..
        } = &mut outbound.socket_correlation
        else {
            panic!("fixture uses proc/INET_DIAG correlation");
        };
        *diag_socket_mark = proxy_mark;
        assert_eq!(
            validate(&fixture, marked).expect_err("masked outbound socket cannot pass"),
            CanaryEvidenceError::OutboundProxyMarkNotClear {
                flow: CanaryFlow::Ipv4TcpEcho,
            }
        );

        let mut peer_table = fixture.successful_evidence();
        peer_table.loop_escape.negative_route_controls.slots[0]
            .as_mut()
            .expect("IPv4 negative control")
            .selected_table = fixture.request.pre_binding.environment.rpdb.peer_table;
        assert_eq!(
            validate(&fixture, peer_table).expect_err("negative control selected peer table"),
            CanaryEvidenceError::NegativeControlSelectedPeerTable
        );

        let mut observed = fixture.successful_evidence();
        observed.loop_escape.negative_route_controls.slots[0]
            .as_mut()
            .expect("IPv4 negative control")
            .peer_observation_count = 1;
        assert_eq!(
            validate(&fixture, observed).expect_err("negative packet reached peer"),
            CanaryEvidenceError::NegativeControlReachedPeer { count: 1 }
        );

        let dual = Fixture::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let mut missing_ipv6 = dual.successful_evidence();
        missing_ipv6.loop_escape.negative_route_controls.slots[1] = None;
        assert_eq!(
            validate(&dual, missing_ipv6).expect_err("IPv6 needs its own negative control"),
            CanaryEvidenceError::MissingNegativeControl { ipv6: true }
        );

        let mut incomplete_observer = fixture.successful_evidence();
        let outbound = incomplete_observer.loop_escape.outbound.slots[0]
            .as_mut()
            .expect("IPv4 TCP outbound evidence");
        let CanarySocketCorrelation::ProcFdInetDiag {
            diag_dump_complete, ..
        } = &mut outbound.socket_correlation
        else {
            panic!("fixture uses proc/INET_DIAG correlation");
        };
        *diag_dump_complete = false;
        assert_eq!(
            validate(&fixture, incomplete_observer)
                .expect_err("an incomplete socket dump cannot prove ownership"),
            CanaryEvidenceError::OutboundSocketCorrelationLoss {
                flow: CanaryFlow::Ipv4TcpEcho,
            }
        );
    }

    #[test]
    fn proc_fd_inet_diag_correlation_requires_the_exact_outbound_socket() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);

        let mut unrelated_tuple = fixture.successful_evidence();
        let flow = unrelated_tuple.flows.slots[CanaryFlow::Ipv4TcpEcho.index()]
            .as_ref()
            .expect("IPv4 TCP flow evidence");
        let outbound = unrelated_tuple.loop_escape.outbound.slots[CanaryFlow::Ipv4TcpEcho.index()]
            .as_mut()
            .expect("IPv4 TCP outbound evidence");
        let CanarySocketCorrelation::ProcFdInetDiag { diag_tuple, .. } =
            &mut outbound.socket_correlation
        else {
            panic!("fixture uses proc/INET_DIAG correlation");
        };
        *diag_tuple = flow.client_tuple;
        assert_eq!(
            validate(&fixture, unrelated_tuple)
                .expect_err("an unrelated INET_DIAG tuple cannot prove socket ownership"),
            CanaryEvidenceError::OutboundSocketCorrelationTupleMismatch {
                flow: CanaryFlow::Ipv4TcpEcho,
            }
        );

        let mut wrong_protocol = fixture.successful_evidence();
        let outbound = wrong_protocol.loop_escape.outbound.slots[CanaryFlow::Ipv4TcpEcho.index()]
            .as_mut()
            .expect("IPv4 TCP outbound evidence");
        let CanarySocketCorrelation::ProcFdInetDiag { diag_protocol, .. } =
            &mut outbound.socket_correlation
        else {
            panic!("fixture uses proc/INET_DIAG correlation");
        };
        *diag_protocol = CanaryInetDiagProtocol::Udp;
        assert_eq!(
            validate(&fixture, wrong_protocol)
                .expect_err("a UDP INET_DIAG row cannot prove a TCP socket"),
            CanaryEvidenceError::OutboundSocketCorrelationProtocolMismatch {
                flow: CanaryFlow::Ipv4TcpEcho,
            }
        );

        let mut wrong_uid = fixture.successful_evidence();
        let outbound = wrong_uid.loop_escape.outbound.slots[CanaryFlow::Ipv4TcpEcho.index()]
            .as_mut()
            .expect("IPv4 TCP outbound evidence");
        let CanarySocketCorrelation::ProcFdInetDiag { diag_uid, .. } =
            &mut outbound.socket_correlation
        else {
            panic!("fixture uses proc/INET_DIAG correlation");
        };
        *diag_uid = NonZeroU32::new(20_003).expect("unrelated UID");
        assert_eq!(
            validate(&fixture, wrong_uid)
                .expect_err("an unrelated INET_DIAG UID cannot prove socket ownership"),
            CanaryEvidenceError::OutboundSocketCorrelationUidMismatch {
                flow: CanaryFlow::Ipv4TcpEcho,
            }
        );

        let mut wrong_mark = fixture.successful_evidence();
        let outbound = wrong_mark.loop_escape.outbound.slots[CanaryFlow::Ipv4TcpEcho.index()]
            .as_mut()
            .expect("IPv4 TCP outbound evidence");
        let CanarySocketCorrelation::ProcFdInetDiag {
            diag_socket_mark, ..
        } = &mut outbound.socket_correlation
        else {
            panic!("fixture uses proc/INET_DIAG correlation");
        };
        *diag_socket_mark = 1;
        assert_eq!(
            validate(&fixture, wrong_mark)
                .expect_err("a mismatched INET_DIAG mark cannot prove socket ownership"),
            CanaryEvidenceError::OutboundSocketCorrelationMarkMismatch {
                flow: CanaryFlow::Ipv4TcpEcho,
            }
        );
    }

    #[test]
    fn proc_fd_inet_diag_identity_types_reject_invalid_values() {
        assert_eq!(
            CanaryProcFd::new(0).map(CanaryProcFd::get),
            Some(0),
            "fd zero remains a valid Linux file descriptor"
        );
        assert_eq!(
            CanaryProcFd::new(i32::MAX as u32).map(CanaryProcFd::get),
            Some(i32::MAX as u32)
        );
        assert_eq!(CanaryProcFd::new(i32::MAX as u32 + 1), None);
        assert_eq!(
            CanaryInetDiagCookie::new(u32::MAX, u32::MAX),
            None,
            "INET_DIAG_NOCOOKIE is request syntax, not observed identity"
        );
        assert!(
            CanaryInetDiagCookie::new(0, 0).is_some(),
            "the ABI does not reserve the zero cookie"
        );
        assert_eq!(NonZeroU64::new(0), None);
    }

    #[test]
    fn proc_fd_inet_diag_intervals_are_strict_and_inside_the_flow_window() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);

        let mut reversed_dump = fixture.successful_evidence();
        let outbound = reversed_dump.loop_escape.outbound.slots[CanaryFlow::Ipv4TcpEcho.index()]
            .as_mut()
            .expect("IPv4 TCP outbound evidence");
        let CanarySocketCorrelation::ProcFdInetDiag {
            dump_started_at,
            dump_completed_at,
            ..
        } = &mut outbound.socket_correlation
        else {
            panic!("fixture uses proc/INET_DIAG correlation");
        };
        std::mem::swap(dump_started_at, dump_completed_at);
        assert_eq!(
            validate(&fixture, reversed_dump)
                .expect_err("a reversed diagnostic dump interval cannot pass"),
            CanaryEvidenceError::OutboundSocketCorrelationTimingInvalid {
                flow: CanaryFlow::Ipv4TcpEcho,
            }
        );

        let mut starts_before_flow = fixture.successful_evidence();
        let flow_started_at = starts_before_flow.flows.slots[CanaryFlow::Ipv4TcpEcho.index()]
            .as_ref()
            .expect("IPv4 TCP flow evidence")
            .started_at;
        let outbound = starts_before_flow.loop_escape.outbound.slots
            [CanaryFlow::Ipv4TcpEcho.index()]
        .as_mut()
        .expect("IPv4 TCP outbound evidence");
        let CanarySocketCorrelation::ProcFdInetDiag {
            snapshot_started_at,
            ..
        } = &mut outbound.socket_correlation
        else {
            panic!("fixture uses proc/INET_DIAG correlation");
        };
        *snapshot_started_at = flow_started_at - Duration::from_nanos(1);
        assert_eq!(
            validate(&fixture, starts_before_flow)
                .expect_err("a snapshot beginning before its flow cannot pass"),
            CanaryEvidenceError::OutboundSocketCorrelationTimingInvalid {
                flow: CanaryFlow::Ipv4TcpEcho,
            }
        );

        let mut completes_after_flow = fixture.successful_evidence();
        let flow_completed_at = completes_after_flow.flows.slots[CanaryFlow::Ipv4TcpEcho.index()]
            .as_ref()
            .expect("IPv4 TCP flow evidence")
            .completed_at;
        let outbound = completes_after_flow.loop_escape.outbound.slots
            [CanaryFlow::Ipv4TcpEcho.index()]
        .as_mut()
        .expect("IPv4 TCP outbound evidence");
        let CanarySocketCorrelation::ProcFdInetDiag {
            snapshot_completed_at,
            ..
        } = &mut outbound.socket_correlation
        else {
            panic!("fixture uses proc/INET_DIAG correlation");
        };
        *snapshot_completed_at = flow_completed_at + Duration::from_nanos(1);
        assert_eq!(
            validate(&fixture, completes_after_flow)
                .expect_err("a snapshot completing after its flow cannot pass"),
            CanaryEvidenceError::OutboundSocketCorrelationTimingInvalid {
                flow: CanaryFlow::Ipv4TcpEcho,
            }
        );
    }

    #[test]
    fn one_complete_inet_diag_dump_may_correlate_multiple_sockets() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let mut evidence = fixture.successful_evidence();
        let shared_sequence = match evidence.loop_escape.outbound.slots
            [CanaryFlow::Ipv4TcpEcho.index()]
        .as_ref()
        .expect("IPv4 TCP outbound evidence")
        .socket_correlation
        {
            CanarySocketCorrelation::ProcFdInetDiag {
                observer_sequence, ..
            } => observer_sequence,
            CanarySocketCorrelation::QualifiedCgroupBpf { .. } => {
                panic!("fixture uses proc/INET_DIAG correlation")
            }
        };
        let outbound = evidence.loop_escape.outbound.slots[CanaryFlow::Ipv4UdpEcho.index()]
            .as_mut()
            .expect("IPv4 UDP outbound evidence");
        let CanarySocketCorrelation::ProcFdInetDiag {
            observer_sequence, ..
        } = &mut outbound.socket_correlation
        else {
            panic!("fixture uses proc/INET_DIAG correlation");
        };
        *observer_sequence = shared_sequence;

        validate(&fixture, evidence)
            .expect("one complete dump sequence may contain multiple exact socket rows");
    }

    #[test]
    fn completion_at_deadline_and_uncertain_cleanup_are_rejected() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let mut late = fixture.successful_evidence();
        late.completed_at = fixture.request.deadline().expires_at();
        assert_eq!(
            validate(&fixture, late).expect_err("deadline is exclusive"),
            CanaryEvidenceError::CompletionAtOrAfterDeadline
        );

        let mut uncertain = fixture.successful_evidence();
        uncertain.cleanup.client_reaped = false;
        assert_eq!(
            validate(&fixture, uncertain).expect_err("cleanup uncertainty cannot pass"),
            CanaryEvidenceError::CleanupClientNotReaped
        );

        let mut recursion = fixture.successful_evidence();
        recursion.counters.after.recapture_packets = 1;
        assert_eq!(
            validate(&fixture, recursion).expect_err("recapture delta cannot pass"),
            CanaryEvidenceError::RecaptureCounterDeltaOutOfRange { observed: 1 }
        );
    }

    #[test]
    fn error_constructor_copies_only_a_bounded_utf8_prefix() {
        let diagnostic = "界".repeat(MAX_FUNCTIONAL_CANARY_DIAGNOSTIC_BYTES);
        let error = FunctionalCanaryError::new(
            CanaryErrorKind::AdapterFailure,
            CanaryCleanupStatus::Uncertain,
            &diagnostic,
        );
        assert!(error.diagnostic().len() <= MAX_FUNCTIONAL_CANARY_DIAGNOSTIC_BYTES);
        assert!(
            error
                .diagnostic()
                .is_char_boundary(error.diagnostic().len())
        );
        assert!(diagnostic.len() > error.diagnostic().len());
        assert_eq!(error.kind(), CanaryErrorKind::AdapterFailure);
        assert_eq!(error.cleanup(), CanaryCleanupStatus::Uncertain);
    }

    #[test]
    fn forbidden_facility_addresses_and_port_collisions_are_rejected() {
        assert_eq!(
            CanaryIpv4AddressPair::new(Ipv4Addr::LOCALHOST, Ipv4Addr::new(11, 0, 0, 2)),
            Err(CanaryBindingError::ForbiddenIpv4Address)
        );
        assert_eq!(
            CanaryIpv6AddressPair::new(
                Ipv6Addr::LOCALHOST,
                "2001:4860::2".parse().expect("global IPv6 address"),
            ),
            Err(CanaryBindingError::ForbiddenIpv6Address)
        );
        let dns = NonZeroU16::new(41_003).expect("DNS port");
        assert_eq!(
            CanaryResponderPorts::new(dns, NonZeroU16::new(41_002).expect("UDP echo port"), dns,),
            Err(CanaryBindingError::SameProtocolResponderPortCollision)
        );
    }

    fn validate(
        fixture: &Fixture,
        evidence: UnqualifiedCanaryGateEvidence,
    ) -> Result<ValidatedUnqualifiedCanaryGateEvidence, CanaryEvidenceError> {
        evidence.validate_for(
            &fixture.request,
            fixture.request.pre_binding(),
            fixture.observed_at(),
        )
    }

    const BOOT_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";

    pub(crate) struct Fixture {
        request: CanaryAttemptRequest,
        _engine: Option<EngineFixture>,
    }

    impl Fixture {
        pub(crate) fn new(families: CanaryAddressFamilies) -> Self {
            let engine = EngineFixture::new();
            let started_at = Instant::now();
            let request = request(&engine.spec, families, started_at);
            Self {
                request,
                _engine: Some(engine),
            }
        }

        pub(crate) fn from_request(request: CanaryAttemptRequest) -> Self {
            Self {
                request,
                _engine: None,
            }
        }

        pub(crate) const fn request(&self) -> &CanaryAttemptRequest {
            &self.request
        }

        pub(crate) fn successful_evidence(&self) -> UnqualifiedCanaryGateEvidence {
            let flows = flow_slots(&self.request);
            let outbound = std::array::from_fn(|index| {
                let flow = CanaryFlow::ALL[index];
                flows.slots[index].as_ref().map(|evidence| {
                    let socket_inode = NonZeroU64::new(
                        80_000 + u64::try_from(index).expect("slot index fits u64"),
                    )
                    .expect("socket inode");
                    UnqualifiedCanaryOutboundEvidence::new(
                        flow,
                        evidence.peer_tuple,
                        CanarySocketCorrelation::ProcFdInetDiag {
                            observer: self
                                .request
                                .pre_binding
                                .environment
                                .authority
                                .socket_observer,
                            process: self.request.pre_binding.engine.engine(),
                            proc_fd: CanaryProcFd::new(
                                100 + u32::try_from(index).expect("slot index fits u32"),
                            )
                            .expect("engine socket fd"),
                            fd_socket_inode: socket_inode,
                            diag_socket_inode: socket_inode,
                            inet_diag_cookie: CanaryInetDiagCookie::new(
                                1,
                                u32::try_from(index + 1).expect("slot cookie"),
                            )
                            .expect("nonzero INET_DIAG cookie"),
                            observer_sequence: NonZeroU64::new(
                                90_000 + u64::try_from(index).expect("slot sequence"),
                            )
                            .expect("observer sequence"),
                            diag_protocol: match flow.kind() {
                                CanaryFlowKind::TcpEcho | CanaryFlowKind::DnsTcp => {
                                    CanaryInetDiagProtocol::Tcp
                                }
                                CanaryFlowKind::UdpEcho | CanaryFlowKind::DnsUdp => {
                                    CanaryInetDiagProtocol::Udp
                                }
                            },
                            diag_tuple: evidence.peer_tuple,
                            diag_uid: self.request.pre_binding.environment.rpdb.engine_uid,
                            diag_socket_mark: 0,
                            fd_scan_complete: true,
                            diag_dump_complete: true,
                            snapshot_started_at: evidence.started_at + Duration::from_millis(1),
                            dump_started_at: evidence.started_at + Duration::from_millis(2),
                            dump_completed_at: evidence.started_at + Duration::from_millis(3),
                            snapshot_completed_at: evidence.started_at + Duration::from_millis(4),
                        },
                        self.request.pre_binding.environment.rpdb.engine_uid,
                        0,
                    )
                })
            });
            let negative_route_controls = std::array::from_fn(|slot| {
                let flow = if slot == 0 {
                    CanaryFlow::Ipv4TcpEcho
                } else {
                    CanaryFlow::Ipv6TcpEcho
                };
                self.request.requires_flow(flow).then(|| {
                    let tuple = flows.slots[flow.index()]
                        .as_ref()
                        .expect("required TCP flow evidence")
                        .peer_tuple;
                    UnqualifiedCanaryNegativeRouteControl::new(
                        flow,
                        tuple,
                        self.request.deadline().started_at() + Duration::from_millis(1),
                        self.request.pre_binding.environment.rpdb.engine_uid,
                        self.request.pre_binding.environment.rpdb.proxy_mark_value,
                        self.request
                            .pre_binding
                            .environment
                            .rpdb
                            .proxy_capture_table,
                        0,
                    )
                })
            });
            let loop_escape = UnqualifiedCanaryLoopEvidence::new(
                UnqualifiedCanaryOutboundEvidenceSlots::new(outbound),
                UnqualifiedCanaryNegativeRouteControlSlots::new(negative_route_controls),
            );
            let counters = counter_evidence(&self.request);
            let cleanup = cleanup_evidence(&self.request);
            UnqualifiedCanaryGateEvidence::new(
                self.request.clone(),
                self.request.deadline().started_at() + Duration::from_millis(200),
                flows,
                0,
                loop_escape,
                counters,
                cleanup,
            )
        }

        pub(crate) fn observed_at(&self) -> Instant {
            self.request.deadline().started_at() + Duration::from_millis(210)
        }
    }

    fn request(
        spec: &EngineSpec,
        families: CanaryAddressFamilies,
        started_at: Instant,
    ) -> CanaryAttemptRequest {
        request_with_nonce(
            spec,
            families,
            started_at,
            CanaryNonce::from_bytes([7; FUNCTIONAL_CANARY_NONCE_BYTES]),
        )
    }

    pub(crate) fn request_with_nonce(
        spec: &EngineSpec,
        families: CanaryAddressFamilies,
        started_at: Instant,
        nonce: CanaryNonce,
    ) -> CanaryAttemptRequest {
        request_with_engine_identity(
            spec,
            families,
            started_at,
            nonce,
            NonZeroU32::new(17).expect("nonzero generation"),
            NonZeroU32::new(4242).expect("nonzero pid"),
            NonZeroU64::new(98_765).expect("nonzero start ticks"),
            NonZeroU64::new(23).expect("nonzero snapshot revision"),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn request_with_engine_identity(
        spec: &EngineSpec,
        families: CanaryAddressFamilies,
        started_at: Instant,
        nonce: CanaryNonce,
        generation: NonZeroU32,
        pid: NonZeroU32,
        start_time_ticks: NonZeroU64,
        engine_snapshot_revision: NonZeroU64,
    ) -> CanaryAttemptRequest {
        let readiness = ReadinessEvidence::Listener {
            port: NonZeroU16::new(1536).expect("nonzero listener port"),
            table: PathBuf::from(format!("/proc/{}/net/tcp", pid.get())),
        };
        let engine = CanaryEngineBinding::from_identity_parts(
            generation,
            pid,
            start_time_ticks,
            engine_snapshot_revision,
            spec,
            &readiness,
        )
        .expect("exact engine binding");
        let environment = environment(generation, nonce, started_at);
        CanaryAttemptRequest::new(
            CanaryAttemptBinding::new(engine, environment),
            nonce,
            CanaryDeadline::new(started_at, Duration::from_secs(2)).expect("valid deadline"),
            families,
            counter_bounds(families),
        )
        .expect("valid request")
    }

    fn counter_bounds(families: CanaryAddressFamilies) -> CanaryCounterDeltaBounds {
        let minimum = match families {
            CanaryAddressFamilies::Ipv4Only => 4,
            CanaryAddressFamilies::Ipv4AndIpv6 => 8,
        };
        CanaryCounterDeltaBounds::new(
            NonZeroU64::new(minimum).expect("positive capture minimum"),
            NonZeroU64::new(128).expect("capture maximum"),
            NonZeroU64::new(minimum).expect("positive bypass minimum"),
            NonZeroU64::new(128).expect("bypass maximum"),
            0,
        )
        .expect("ordered canary counter bounds")
    }

    fn environment(
        generation: NonZeroU32,
        nonce: CanaryNonce,
        attempt_started_at: Instant,
    ) -> CanaryEnvironmentBinding {
        let mut tracker = NetworkInventoryTracker::new();
        let inventory = tracker
            .publish_complete([], [])
            .expect("publish empty complete inventory");
        let daemon_veth = CanaryVethIdentity::new(
            InterfaceIndex::new(101).expect("daemon ifindex"),
            InterfaceName::new(b"fluxc0").expect("daemon interface name"),
        );
        let peer_veth = CanaryVethIdentity::new(
            InterfaceIndex::new(102).expect("peer ifindex"),
            InterfaceName::new(b"fluxp0").expect("peer interface name"),
        );
        let facility = CanaryFacilityIdentity::new(
            daemon_veth,
            peer_veth,
            CanaryIpv4AddressPair::new(Ipv4Addr::new(11, 0, 0, 1), Ipv4Addr::new(11, 0, 0, 2))
                .expect("distinct IPv4 addresses"),
            Some(
                CanaryIpv6AddressPair::new(
                    "2001:4860::1".parse().expect("daemon IPv6"),
                    "2001:4860::2".parse().expect("peer IPv6"),
                )
                .expect("distinct IPv6 addresses"),
            ),
            CanaryResponderPorts::new(
                NonZeroU16::new(41_001).expect("TCP responder port"),
                NonZeroU16::new(41_002).expect("UDP responder port"),
                NonZeroU16::new(41_003).expect("DNS responder port"),
            )
            .expect("same-protocol responder ports are distinct"),
        )
        .expect("valid facility");
        let admission = CanaryFacilityAdmissionToken::new(
            CanaryFacilityAdmissionScope::new(
                generation,
                nonce,
                facility,
                CanaryFacilityAuditDigest::new([8; CANARY_FACILITY_AUDIT_DIGEST_BYTES])
                    .expect("facility identity digest"),
                CanaryFacilityAuditDigest::new([10; CANARY_FACILITY_AUDIT_DIGEST_BYTES])
                    .expect("reviewed pool identity"),
            ),
            CanaryFacilityAdmissionObservation::new(
                inventory.epoch(),
                inventory.snapshot_id(),
                NonZeroU64::new(33).expect("collision audit revision"),
                CanaryFacilityAuditDigest::new([11; CANARY_FACILITY_AUDIT_DIGEST_BYTES])
                    .expect("collision and bypass digest"),
                attempt_started_at,
                attempt_started_at + MAX_FUNCTIONAL_CANARY_DURATION,
            ),
        );
        let rpdb = CanaryRpdbIdentity::new(
            NonZeroU32::new(20_001).expect("engine UID"),
            NonZeroU8::new(0xfd).expect("owned RPDB protocol"),
            RouteTableId::from_raw(10_101),
            RouteTableId::from_raw(10_102),
            RulePriority::from_raw(12_100),
            RulePriority::from_raw(12_000),
            0x1200,
            NonZeroU32::new(0xff00).expect("proxy mark mask"),
        )
        .expect("valid RPDB identity");
        let attempt_objects = CanaryAttemptObjectIdentities::new(
            generation,
            nonce,
            CanaryAttemptObjectIdentity::new([5; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES])
                .expect("selector identity"),
            CanaryAttemptObjectIdentity::new([6; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES])
                .expect("guard identity"),
            CanaryAttemptObjectIdentity::new([7; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES])
                .expect("counter identity"),
        );
        let network = CanaryNetworkObservationBinding::new(
            NetworkNamespaceIdentity::new(1, 101).expect("daemon namespace"),
            NetworkNamespaceIdentity::new(1, 102).expect("peer namespace"),
            inventory.epoch(),
            inventory.snapshot_id(),
        )
        .expect("distinct network namespaces");
        let boot_identity = BootIdentity::parse(BOOT_ID).expect("canonical boot ID");
        let capture_owner = CaptureOwnerRecordBinding::new(
            NonZeroU16::new(1).expect("capture owner schema"),
            boot_identity.clone(),
            generation,
            CanaryFileIdentity::new(55, NonZeroU64::new(56).expect("capture owner inode")),
            CaptureOwnerRecordDigest::new([9; CAPTURE_OWNER_RECORD_DIGEST_BYTES])
                .expect("capture owner digest"),
        );
        let ownership = CanaryOwnershipBinding::new(
            OwnershipJournalIdentity::new([4; OWNERSHIP_JOURNAL_IDENTITY_BYTES])
                .expect("journal identity"),
            OwnershipJournalRevision::INITIAL,
            capture_owner,
        );
        let authority = CanaryEnvironmentAuthorityBinding::new(
            boot_identity,
            CapabilityProfileRevision::new(9).expect("profile revision"),
            network,
            CaptureProgramDigest::new([3; CAPTURE_PROGRAM_DIGEST_BYTES]).expect("capture digest"),
            ownership,
            CanarySocketObserverAuthority::ProcFdInetDiag {
                collector_identity: CanaryAttemptObjectIdentity::new(
                    [12; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES],
                )
                .expect("socket observer identity"),
                collector_revision: NonZeroU64::new(13).expect("collector revision"),
                netlink_port_id: NonZeroU32::new(14).expect("netlink port ID"),
            },
        );
        CanaryEnvironmentBinding::new(
            authority,
            NonZeroU32::new(20_002).expect("probe UID"),
            facility,
            admission,
            rpdb,
            attempt_objects,
        )
        .expect("valid environment")
    }

    fn cleanup_evidence(request: &CanaryAttemptRequest) -> UnqualifiedCanaryCleanupEvidence {
        let process = |pid, ticks| {
            CanaryProcessIdentity::new(
                NonZeroU32::new(pid).expect("nonzero canary process PID"),
                NonZeroU64::new(ticks).expect("nonzero canary process start ticks"),
            )
        };
        UnqualifiedCanaryCleanupEvidence::new(
            request.nonce(),
            request.pre_binding.environment.attempt_objects,
            process(60_001, 70_001),
            true,
            true,
            true,
            [
                process(60_002, 70_002),
                process(60_003, 70_003),
                process(60_004, 70_004),
            ],
            [true; CANARY_PEER_SERVER_SLOTS],
            [true; CANARY_PEER_SERVER_SLOTS],
            true,
            true,
            true,
            request.pre_binding.environment.facility,
        )
    }

    fn counter_evidence(request: &CanaryAttemptRequest) -> UnqualifiedCanaryCounterEvidence {
        let packet_delta = match request.families() {
            CanaryAddressFamilies::Ipv4Only => 4,
            CanaryAddressFamilies::Ipv4AndIpv6 => 8,
        };
        UnqualifiedCanaryCounterEvidence::new(
            request.pre_binding.environment.attempt_objects.counters,
            request.deadline().started_at() + Duration::from_millis(2),
            CanaryCounterSnapshot::new(100, 200, 0),
            request.deadline().started_at() + Duration::from_millis(100),
            CanaryCounterSnapshot::new(100 + packet_delta, 200 + packet_delta, 0),
        )
    }

    fn flow_slots(request: &CanaryAttemptRequest) -> UnqualifiedCanaryFlowEvidenceSlots {
        UnqualifiedCanaryFlowEvidenceSlots::new(std::array::from_fn(|index| {
            let flow = CanaryFlow::ALL[index];
            request
                .requires_flow(flow)
                .then(|| flow_evidence(request, flow, index))
        }))
    }

    fn flow_evidence(
        request: &CanaryAttemptRequest,
        flow: CanaryFlow,
        index: usize,
    ) -> UnqualifiedCanaryFlowEvidence {
        let peer = SocketAddr::new(
            request.peer_address(flow),
            request.responder_port(flow).get(),
        );
        let client_source_ip = if flow.is_ipv4() {
            IpAddr::V4(Ipv4Addr::new(11, 0, 0, 10))
        } else {
            IpAddr::V6("2001:4860::10".parse().expect("client IPv6"))
        };
        let client_tuple = CanaryFlowTuple::new(
            SocketAddr::new(
                client_source_ip,
                50_000 + u16::try_from(index).expect("slot index"),
            ),
            peer,
        );
        let peer_tuple = CanaryFlowTuple::new(
            SocketAddr::new(
                request.daemon_address(flow),
                51_000 + u16::try_from(index).expect("slot index"),
            ),
            peer,
        );
        let dns = flow.is_dns().then(|| {
            let expected = request.dns_expectations.slots[index]
                .expect("request contains each required DNS expectation");
            UnqualifiedCanaryDnsEvidence::new(
                expected.transaction_id,
                expected.transaction_id,
                expected.transaction_id,
                expected.question_digest,
                expected.question_digest,
                expected.question_digest,
                expected.answer,
                expected.answer,
            )
        });
        let started_at = request.deadline().started_at()
            + Duration::from_millis(10 * u64::try_from(index + 1).expect("slot index"));
        UnqualifiedCanaryFlowEvidence::new(
            flow,
            request.nonce(),
            request.nonce(),
            request.nonce(),
            client_tuple,
            peer_tuple,
            started_at,
            started_at + Duration::from_millis(5),
            dns,
        )
    }

    struct EngineFixture {
        spec: EngineSpec,
        _directory: tempfile::TempDir,
    }

    impl EngineFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("create engine fixture");
            let binary = directory.path().join("sing-box");
            let config = directory.path().join("config.json");
            fs::write(&binary, b"sing-box").expect("write binary");
            fs::write(&config, b"{}").expect("write config");
            let restart = RestartPolicy::new(
                3,
                Duration::from_secs(60),
                Duration::from_secs(1),
                Duration::from_secs(8),
                Duration::from_secs(10),
            )
            .expect("valid restart policy");
            let spec = EngineSpec::new(
                SingBoxLaunchSpec {
                    binary,
                    config,
                    working_directory: directory.path().to_path_buf(),
                    log: directory.path().join("sing-box.log"),
                    launcher: SingBoxLauncher::Direct,
                    readiness: SingBoxReadiness::Listener {
                        port: NonZeroU16::new(1536).expect("nonzero port"),
                    },
                    startup_timeout: Duration::from_secs(1),
                    stop_timeout: Duration::from_secs(1),
                },
                restart,
            )
            .expect("inspect engine spec");
            Self {
                spec,
                _directory: directory,
            }
        }
    }
}
