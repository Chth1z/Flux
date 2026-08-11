use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use flux_core::{
    BootIdentity, CapabilityProfileRevision, GenerationId, InterfaceAddressFlags, InterfaceIndex,
    InterfaceLinkReference, InterfaceName, NetworkAddressFamily, NetworkEpoch, NetworkInventory,
    NetworkInventorySnapshotId, NetworkNamespaceIdentity, NetworkRouteRecord, NetworkRuleRecord,
    OwnershipJournalIdentity, OwnershipJournalRevision, RouteFlags, RoutePath, RoutePreference,
    RoutePrefix, RouteProperties, RouteProtocol, RouteScope, RouteTableId, RouteType, RuleAction,
    RuleFlags, RuleFwMark, RuleIpProtocol, RulePortRange, RulePrefix, RulePriority, RuleProperties,
    RuleProtocol, RuleTableId, RuleUidRange,
};
use flux_platform::socket_diagnostics::{
    CorrelatedProcessSocket, InetSocketAddressFamily, InetSocketProtocol, ListenerConflictSnapshot,
    ListenerConflictTarget, ProcessSocketDiagnostics, SocketCorrelationError,
    SocketDiagnosticsError, SocketDiagnosticsErrorKind, SystemSocketDiagnosticsSession,
    SystemSocketDiagnosticsSource,
};
use flux_platform::{
    NativeCaptureOwnershipObservation, NativeCaptureTargetIdentity, ReadinessEvidence,
};
use sha2::{Digest, Sha256};

use crate::engine_supervisor::EngineChildAuthority;
use crate::generation_engine_config::{
    ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION, EngineCapabilityProfileRevision,
};
use crate::runtime_coordinator::CanaryAttemptObservationAuthority;
use crate::{EngineArtifactSetIdentity, EngineSpec, OwnedEngineIdentity};

pub(crate) const FUNCTIONAL_CANARY_SCHEMA_VERSION: u16 = 2;
pub(crate) const FUNCTIONAL_CANARY_NONCE_BYTES: usize = 32;
pub(crate) const CAPTURE_PROGRAM_DIGEST_BYTES: usize = 32;
pub(crate) const CANARY_DNS_QUESTION_DIGEST_BYTES: usize = 32;
pub(crate) const CANARY_INBOUND_PAYLOAD_DIGEST_BYTES: usize = 32;
pub(crate) const CANARY_DNS_WIRE_NAME_BYTES: usize = 83;
pub(crate) const MAX_FUNCTIONAL_CANARY_DURATION: Duration = Duration::from_secs(3);
pub(crate) const MAX_CANARY_FACILITY_OBSERVATION_AGE: Duration = Duration::from_secs(3);
pub(crate) const MAX_FUNCTIONAL_CANARY_DIAGNOSTIC_BYTES: usize = 4 * 1024;
pub(crate) const FUNCTIONAL_CANARY_FLOW_SLOTS: usize = 8;
pub(crate) const CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES: usize = 32;
pub(crate) const CANARY_PEER_SERVER_SLOTS: usize = 3;
pub(crate) const CANARY_NEGATIVE_CONTROL_SLOTS: usize = 2;
pub(crate) const CANARY_LISTENER_ROLE_SLOTS: usize = 4;
pub(crate) const CANARY_FACILITY_AUDIT_DIGEST_BYTES: usize = 32;
pub(crate) const CAPTURE_OWNER_RECORD_DIGEST_BYTES: usize = 32;
pub(crate) const CANARY_CREDENTIAL_MAP_DIGEST_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FunctionalCanaryGateMode {
    /// Retain the current Phase 1 structural gate without claiming functional
    /// traffic, DNS, or exact-process loop-escape qualification.
    StructuralVerificationOnly,
    /// Require the complete model below while still describing the result as
    /// unqualified until reviewed Android device evidence exists.
    RequiredUnqualified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryAddressFamilies {
    Ipv4Only,
    Ipv4AndIpv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryCaptureBackend {
    Tproxy,
    Redirect,
    Dnat,
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
    InvalidIpv4VethPrefixLength,
    InvalidIpv6VethPrefixLength,
    MismatchedVethTopologyFamily,
    FacilityIpv6TopologyMismatch,
    ZeroCanaryRouteTable,
    ZeroCanaryRouteProtocol,
    SameNetworkNamespace,
    ZeroRpdbTable,
    SameRpdbTable,
    UnrepresentableRpdbEngineUid,
    CanaryPeerRouteTableMismatch,
    InvalidRpdbPriorityOrder,
    ProxyMarkEmpty,
    ProxyMarkBitsOutsideMask,
    ProbeUidMatchesEngineUid,
    ProbeGidMatchesEngineGid,
    EngineCredentialUidMismatch,
    AllZeroCredentialMapDigest,
    CredentialNamespaceCollision,
    MissingIpv6Facility,
    SameProtocolResponderPortCollision,
    UnrepresentableResponderPort,
    FacilityAdmissionInventoryMismatch,
    FacilityAdmissionScopeMismatch,
    FacilityAdmissionAttemptMismatch,
    FacilityAdmissionExpired,
    AllZeroFacilityAuditDigest,
    AllZeroCaptureOwnerRecordDigest,
    CaptureOwnerGenerationMismatch,
    CaptureOwnerBootMismatch,
    ActiveCaptureTargetMismatch,
    ActiveCaptureBootMismatch,
    ActiveCaptureNetworkNamespaceMismatch,
    ActiveCaptureJournalIdentityMismatch,
    ActiveCaptureJournalRevisionNotAdvanced,
    AllZeroAttemptObjectIdentity,
    AttemptObjectIdentityCollision,
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

    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryAttemptObjectIdentities {
    generation: GenerationId,
    nonce: CanaryNonce,
    selector: CanaryAttemptObjectIdentity,
    counters: CanaryAttemptObjectIdentity,
    listener_delivery_report: CanaryAttemptObjectIdentity,
}

impl CanaryAttemptObjectIdentities {
    pub(crate) fn new(
        generation: GenerationId,
        nonce: CanaryNonce,
        selector: CanaryAttemptObjectIdentity,
        counters: CanaryAttemptObjectIdentity,
        listener_delivery_report: CanaryAttemptObjectIdentity,
    ) -> Result<Self, CanaryBindingError> {
        let identities = [selector, counters, listener_delivery_report];
        for (index, identity) in identities.iter().enumerate() {
            if identities[index + 1..].contains(identity) {
                return Err(CanaryBindingError::AttemptObjectIdentityCollision);
            }
        }
        Ok(Self {
            generation,
            nonce,
            selector,
            counters,
            listener_delivery_report,
        })
    }

    #[must_use]
    pub(crate) const fn generation(self) -> GenerationId {
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
    pub(crate) const fn counters(self) -> CanaryAttemptObjectIdentity {
        self.counters
    }

    #[must_use]
    pub(crate) const fn listener_delivery_report(self) -> CanaryAttemptObjectIdentity {
        self.listener_delivery_report
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

    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; CANARY_FACILITY_AUDIT_DIGEST_BYTES] {
        &self.0
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
    generation: GenerationId,
    file_identity: CanaryFileIdentity,
    digest: CaptureOwnerRecordDigest,
}

impl CaptureOwnerRecordBinding {
    #[must_use]
    pub(crate) const fn new(
        schema_version: NonZeroU16,
        boot_identity: BootIdentity,
        generation: GenerationId,
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
    pub(crate) const fn generation(&self) -> GenerationId {
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CanaryCredentialMapDigest([u8; CANARY_CREDENTIAL_MAP_DIGEST_BYTES]);

impl CanaryCredentialMapDigest {
    pub(crate) const fn new(
        bytes: [u8; CANARY_CREDENTIAL_MAP_DIGEST_BYTES],
    ) -> Result<Self, CanaryBindingError> {
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0 {
                return Ok(Self(bytes));
            }
            index += 1;
        }
        Err(CanaryBindingError::AllZeroCredentialMapDigest)
    }

    #[must_use]
    pub(crate) const fn as_bytes(self) -> [u8; CANARY_CREDENTIAL_MAP_DIGEST_BYTES] {
        self.0
    }
}

/// User-namespace and credential-map domain bound to one immutable attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryUserNamespaceBinding {
    Unsupported,
    Observed {
        namespace: CanaryFileIdentity,
        uid_map_digest: CanaryCredentialMapDigest,
        gid_map_digest: CanaryCredentialMapDigest,
    },
}

/// Namespace domain in which process credentials are interpreted for one
/// immutable attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryCredentialDomainBinding {
    user_namespace: CanaryUserNamespaceBinding,
    mount_namespace: CanaryFileIdentity,
}

impl CanaryCredentialDomainBinding {
    pub(crate) fn observed(
        user_namespace: CanaryFileIdentity,
        mount_namespace: CanaryFileIdentity,
        uid_map_digest: CanaryCredentialMapDigest,
        gid_map_digest: CanaryCredentialMapDigest,
    ) -> Result<Self, CanaryBindingError> {
        if user_namespace == mount_namespace {
            return Err(CanaryBindingError::CredentialNamespaceCollision);
        }
        Ok(Self {
            user_namespace: CanaryUserNamespaceBinding::Observed {
                namespace: user_namespace,
                uid_map_digest,
                gid_map_digest,
            },
            mount_namespace,
        })
    }

    #[must_use]
    pub(crate) const fn unsupported(mount_namespace: CanaryFileIdentity) -> Self {
        Self {
            user_namespace: CanaryUserNamespaceBinding::Unsupported,
            mount_namespace,
        }
    }

    #[must_use]
    pub(crate) const fn user_namespace(self) -> CanaryUserNamespaceBinding {
        self.user_namespace
    }

    #[must_use]
    pub(crate) const fn mount_namespace(self) -> CanaryFileIdentity {
        self.mount_namespace
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryProcessCredentialIdentity {
    uid: NonZeroU32,
    gid: NonZeroU32,
}

impl CanaryProcessCredentialIdentity {
    #[must_use]
    pub(crate) const fn new(uid: NonZeroU32, gid: NonZeroU32) -> Self {
        Self { uid, gid }
    }

    #[must_use]
    pub(crate) const fn uid(self) -> NonZeroU32 {
        self.uid
    }

    #[must_use]
    pub(crate) const fn gid(self) -> NonZeroU32 {
        self.gid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryAttemptCredentialBinding {
    probe: CanaryProcessCredentialIdentity,
    engine: CanaryProcessCredentialIdentity,
    domain: CanaryCredentialDomainBinding,
}

impl CanaryAttemptCredentialBinding {
    pub(crate) fn new(
        probe: CanaryProcessCredentialIdentity,
        engine: CanaryProcessCredentialIdentity,
        domain: CanaryCredentialDomainBinding,
    ) -> Result<Self, CanaryBindingError> {
        if probe.uid() == engine.uid() {
            return Err(CanaryBindingError::ProbeUidMatchesEngineUid);
        }
        if probe.gid() == engine.gid() {
            return Err(CanaryBindingError::ProbeGidMatchesEngineGid);
        }
        Ok(Self {
            probe,
            engine,
            domain,
        })
    }

    #[must_use]
    pub(crate) const fn probe(self) -> CanaryProcessCredentialIdentity {
        self.probe
    }

    #[must_use]
    pub(crate) const fn engine(self) -> CanaryProcessCredentialIdentity {
        self.engine
    }

    #[must_use]
    pub(crate) const fn domain(self) -> CanaryCredentialDomainBinding {
        self.domain
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

/// Pure request-side binding for one live observer opening.
///
/// The private process-local opening identity prevents a later socket that
/// receives the same recycled netlink port number from matching the original
/// attempt resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanarySocketObserverBinding {
    authority: CanarySocketObserverAuthority,
    opening_id: CanarySocketObserverOpeningId,
}

impl CanarySocketObserverBinding {
    #[cfg(test)]
    pub(crate) const fn scripted(
        authority: CanarySocketObserverAuthority,
        opening_id: NonZeroU64,
    ) -> Self {
        Self {
            authority,
            opening_id: CanarySocketObserverOpeningId(opening_id),
        }
    }

    #[must_use]
    pub(crate) const fn authority(self) -> CanarySocketObserverAuthority {
        self.authority
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CanarySocketObserverOpeningId(NonZeroU64);

static NEXT_CANARY_SOCKET_OBSERVER_OPENING_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) enum CanaryAttemptSocketObserverOpenError {
    SocketDiagnostics(SocketDiagnosticsError),
    OpeningIdentityExhausted,
}

impl fmt::Display for CanaryAttemptSocketObserverOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketDiagnostics(error) => error.fmt(formatter),
            Self::OpeningIdentityExhausted => {
                formatter.write_str("functional-canary socket-observer opening identity exhausted")
            }
        }
    }
}

impl Error for CanaryAttemptSocketObserverOpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SocketDiagnostics(error) => Some(error),
            Self::OpeningIdentityExhausted => None,
        }
    }
}

impl From<SocketDiagnosticsError> for CanaryAttemptSocketObserverOpenError {
    fn from(error: SocketDiagnosticsError) -> Self {
        Self::SocketDiagnostics(error)
    }
}

/// Attempt-owned transport for the socket observer named by the request.
///
/// Production construction derives the authority port and a private opening
/// identity from the exact live prebound session. The value is neither
/// cloneable nor separable from that session, so a copied or recycled port ID
/// cannot substitute for the observer handed from preparation to execution.
pub(crate) struct CanaryAttemptSocketObserverSession {
    binding: CanarySocketObserverBinding,
    deadline: CanaryDeadline,
    transport: CanaryAttemptSocketObserverTransport,
}

const _: fn() = || {
    fn assert_send_static<T: Send + 'static>() {}
    assert_send_static::<CanaryAttemptSocketObserverSession>();
};

enum CanaryAttemptSocketObserverTransport {
    ProcFdInetDiag(SystemSocketDiagnosticsSession),
    #[cfg(test)]
    Scripted,
}

impl CanaryAttemptSocketObserverSession {
    /// Open the real observer in the caller's current network namespace under
    /// the attempt's immutable deadline and derive its request authority.
    #[allow(dead_code)]
    pub(crate) fn open_proc_fd_inet_diag(
        collector_identity: CanaryAttemptObjectIdentity,
        collector_revision: NonZeroU64,
        deadline: CanaryDeadline,
    ) -> Result<Self, CanaryAttemptSocketObserverOpenError> {
        let session = SystemSocketDiagnosticsSource.open_until(deadline.expires_at())?;
        let opening_id = next_socket_observer_opening_id()?;
        Ok(Self {
            binding: CanarySocketObserverBinding {
                authority: CanarySocketObserverAuthority::ProcFdInetDiag {
                    collector_identity,
                    collector_revision,
                    netlink_port_id: session.netlink_port_id(),
                },
                opening_id,
            },
            deadline,
            transport: CanaryAttemptSocketObserverTransport::ProcFdInetDiag(session),
        })
    }

    #[cfg(test)]
    pub(crate) const fn scripted(
        binding: CanarySocketObserverBinding,
        deadline: CanaryDeadline,
    ) -> Self {
        Self {
            binding,
            deadline,
            transport: CanaryAttemptSocketObserverTransport::Scripted,
        }
    }

    #[must_use]
    pub(crate) const fn authority(&self) -> CanarySocketObserverAuthority {
        self.binding.authority()
    }

    #[must_use]
    pub(crate) const fn binding(&self) -> CanarySocketObserverBinding {
        self.binding
    }

    #[must_use]
    pub(crate) const fn deadline(&self) -> CanaryDeadline {
        self.deadline
    }

    /// Collect one identity-bound process snapshot while retaining the exact
    /// prebound diagnostic session.
    ///
    /// The session is consumed on entry and returned only after a complete,
    /// all-or-nothing collection. Any platform error consumes the session so
    /// unread netlink datagrams cannot satisfy a later attempt.
    pub(crate) fn collect_process_until(
        self,
        process: OwnedEngineIdentity,
    ) -> Result<(Self, ProcessSocketDiagnostics), FunctionalCanaryError> {
        match self.transport {
            CanaryAttemptSocketObserverTransport::ProcFdInetDiag(session) => {
                let expected =
                    flux_platform::socket_diagnostics::SocketDiagnosticsProcessIdentity::new(
                        NonZeroU32::new(process.pid()).expect("engine PID is nonzero"),
                        NonZeroU64::new(process.start_time_ticks())
                            .expect("engine start ticks are nonzero"),
                    );
                let (session, snapshot) = session
                    .collect_process_until(expected, self.deadline.expires_at())
                    .map_err(|error| {
                        let kind = match error.kind() {
                            SocketDiagnosticsErrorKind::DeadlineExpired => {
                                CanaryErrorKind::TimedOut
                            }
                            SocketDiagnosticsErrorKind::ProcessIdentityMismatch
                            | SocketDiagnosticsErrorKind::ProcessSocketFdsChanged => {
                                CanaryErrorKind::IdentityChanged
                            }
                            _ => CanaryErrorKind::InvalidEvidence,
                        };
                        let diagnostic = format!(
                            "authoritative process socket observation failed ({:?}): {error}",
                            error.kind(),
                        );
                        FunctionalCanaryError::new(
                            kind,
                            CanaryCleanupStatus::Uncertain,
                            &diagnostic,
                        )
                    })?;
                Ok((
                    Self {
                        binding: self.binding,
                        deadline: self.deadline,
                        transport: CanaryAttemptSocketObserverTransport::ProcFdInetDiag(session),
                    },
                    snapshot,
                ))
            }
            #[cfg(test)]
            CanaryAttemptSocketObserverTransport::Scripted => Err(FunctionalCanaryError::new(
                CanaryErrorKind::InvalidEvidence,
                CanaryCleanupStatus::NotRequired,
                "the attempt-owned socket observer cannot collect a production process snapshot",
            )),
        }
    }

    /// Collect one identity-bound process snapshot plus the two targeted UDP
    /// listener dumps while retaining the exact prebound diagnostic session.
    ///
    /// The session is consumed on entry and returned only after a complete,
    /// all-or-nothing collection. Any platform error consumes the session so
    /// unread netlink datagrams cannot satisfy a later attempt.
    pub(crate) fn collect_process_and_listeners_until(
        self,
        process: OwnedEngineIdentity,
        listener_port: NonZeroU16,
    ) -> Result<(Self, ProcessSocketDiagnostics), FunctionalCanaryError> {
        match self.transport {
            CanaryAttemptSocketObserverTransport::ProcFdInetDiag(session) => {
                let expected =
                    flux_platform::socket_diagnostics::SocketDiagnosticsProcessIdentity::new(
                        NonZeroU32::new(process.pid()).expect("engine PID is nonzero"),
                        NonZeroU64::new(process.start_time_ticks())
                            .expect("engine start ticks are nonzero"),
                    );
                let (session, snapshot) = session
                    .collect_process_and_listeners_until(
                        expected,
                        listener_port,
                        self.deadline.expires_at(),
                    )
                    .map_err(|error| {
                        let kind = match error.kind() {
                            SocketDiagnosticsErrorKind::DeadlineExpired => {
                                CanaryErrorKind::TimedOut
                            }
                            SocketDiagnosticsErrorKind::ProcessIdentityMismatch
                            | SocketDiagnosticsErrorKind::ProcessSocketFdsChanged => {
                                CanaryErrorKind::IdentityChanged
                            }
                            _ => CanaryErrorKind::InvalidEvidence,
                        };
                        let diagnostic = format!(
                            "authoritative process/listener socket observation failed ({:?}): {error}",
                            error.kind(),
                        );
                        FunctionalCanaryError::new(
                            kind,
                            CanaryCleanupStatus::Uncertain,
                            &diagnostic,
                        )
                    })?;
                Ok((
                    Self {
                        binding: self.binding,
                        deadline: self.deadline,
                        transport: CanaryAttemptSocketObserverTransport::ProcFdInetDiag(session),
                    },
                    snapshot,
                ))
            }
            #[cfg(test)]
            CanaryAttemptSocketObserverTransport::Scripted => Err(FunctionalCanaryError::new(
                CanaryErrorKind::InvalidEvidence,
                CanaryCleanupStatus::NotRequired,
                "the attempt-owned socket observer cannot collect a production listener snapshot",
            )),
        }
    }
}

fn next_socket_observer_opening_id()
-> Result<CanarySocketObserverOpeningId, CanaryAttemptSocketObserverOpenError> {
    let raw = NEXT_CANARY_SOCKET_OBSERVER_OPENING_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| CanaryAttemptSocketObserverOpenError::OpeningIdentityExhausted)?;
    Ok(CanarySocketObserverOpeningId(
        NonZeroU64::new(raw).expect("socket-observer opening IDs start at one"),
    ))
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
    generation: GenerationId,
    engine: OwnedEngineIdentity,
    engine_snapshot_revision: NonZeroU64,
    engine_profile_revision: EngineCapabilityProfileRevision,
    artifacts: EngineArtifactSetIdentity,
    listener: CanaryListenerIdentity,
}

impl CanaryEngineBinding {
    pub(crate) fn from_identity_parts(
        generation: GenerationId,
        pid: NonZeroU32,
        start_time_ticks: NonZeroU64,
        engine_snapshot_revision: NonZeroU64,
        engine_profile_revision: EngineCapabilityProfileRevision,
        spec: &EngineSpec,
        readiness: &ReadinessEvidence,
    ) -> Result<Self, CanaryBindingError> {
        Self::new(
            generation,
            OwnedEngineIdentity::new(pid, start_time_ticks),
            engine_snapshot_revision,
            engine_profile_revision,
            spec,
            readiness,
        )
    }

    pub(crate) fn new(
        generation: GenerationId,
        engine: OwnedEngineIdentity,
        engine_snapshot_revision: NonZeroU64,
        engine_profile_revision: EngineCapabilityProfileRevision,
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
            engine_profile_revision,
            artifacts: spec.artifacts(),
            listener,
        })
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> GenerationId {
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
    pub(crate) const fn engine_profile_revision(&self) -> EngineCapabilityProfileRevision {
        self.engine_profile_revision
    }

    #[must_use]
    pub(crate) const fn artifacts(&self) -> EngineArtifactSetIdentity {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryRouteShape {
    table: RouteTableId,
    protocol: RouteProtocol,
    scope: RouteScope,
    route_type: RouteType,
    metric: NonZeroU32,
}

impl CanaryRouteShape {
    pub(crate) const fn new(
        table: RouteTableId,
        protocol: RouteProtocol,
        scope: RouteScope,
        metric: NonZeroU32,
    ) -> Result<Self, CanaryBindingError> {
        if table.get() == 0 {
            return Err(CanaryBindingError::ZeroCanaryRouteTable);
        }
        if protocol.raw() == 0 {
            return Err(CanaryBindingError::ZeroCanaryRouteProtocol);
        }
        Ok(Self {
            table,
            protocol,
            scope,
            route_type: RouteType::from_raw(1),
            metric,
        })
    }

    #[must_use]
    pub(crate) const fn table(self) -> RouteTableId {
        self.table
    }

    #[must_use]
    pub(crate) const fn protocol(self) -> RouteProtocol {
        self.protocol
    }

    #[must_use]
    pub(crate) const fn scope(self) -> RouteScope {
        self.scope
    }

    #[must_use]
    pub(crate) const fn route_type(self) -> RouteType {
        self.route_type
    }

    #[must_use]
    pub(crate) const fn metric(self) -> NonZeroU32 {
        self.metric
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CanaryVethAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryVethFamilyTopology {
    family: CanaryVethAddressFamily,
    daemon_prefix_length: u8,
    peer_prefix_length: u8,
    daemon_to_peer_route: CanaryRouteShape,
    peer_to_daemon_route: CanaryRouteShape,
}

impl CanaryVethFamilyTopology {
    pub(crate) const fn ipv4(
        daemon_prefix_length: u8,
        peer_prefix_length: u8,
        daemon_to_peer_route: CanaryRouteShape,
        peer_to_daemon_route: CanaryRouteShape,
    ) -> Result<Self, CanaryBindingError> {
        Self::new(
            CanaryVethAddressFamily::Ipv4,
            32,
            CanaryBindingError::InvalidIpv4VethPrefixLength,
            daemon_prefix_length,
            peer_prefix_length,
            daemon_to_peer_route,
            peer_to_daemon_route,
        )
    }

    pub(crate) const fn ipv6(
        daemon_prefix_length: u8,
        peer_prefix_length: u8,
        daemon_to_peer_route: CanaryRouteShape,
        peer_to_daemon_route: CanaryRouteShape,
    ) -> Result<Self, CanaryBindingError> {
        Self::new(
            CanaryVethAddressFamily::Ipv6,
            128,
            CanaryBindingError::InvalidIpv6VethPrefixLength,
            daemon_prefix_length,
            peer_prefix_length,
            daemon_to_peer_route,
            peer_to_daemon_route,
        )
    }

    #[allow(clippy::too_many_arguments)]
    const fn new(
        family: CanaryVethAddressFamily,
        maximum_prefix_length: u8,
        invalid_prefix_error: CanaryBindingError,
        daemon_prefix_length: u8,
        peer_prefix_length: u8,
        daemon_to_peer_route: CanaryRouteShape,
        peer_to_daemon_route: CanaryRouteShape,
    ) -> Result<Self, CanaryBindingError> {
        if daemon_prefix_length == 0
            || daemon_prefix_length > maximum_prefix_length
            || peer_prefix_length == 0
            || peer_prefix_length > maximum_prefix_length
        {
            return Err(invalid_prefix_error);
        }
        Ok(Self {
            family,
            daemon_prefix_length,
            peer_prefix_length,
            daemon_to_peer_route,
            peer_to_daemon_route,
        })
    }

    #[must_use]
    pub(crate) const fn daemon_prefix_length(self) -> u8 {
        self.daemon_prefix_length
    }

    #[must_use]
    pub(crate) const fn peer_prefix_length(self) -> u8 {
        self.peer_prefix_length
    }

    #[must_use]
    pub(crate) const fn daemon_to_peer_route(self) -> CanaryRouteShape {
        self.daemon_to_peer_route
    }

    #[must_use]
    pub(crate) const fn peer_to_daemon_route(self) -> CanaryRouteShape {
        self.peer_to_daemon_route
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryPeerVethTopology {
    ipv4: CanaryVethFamilyTopology,
    ipv6: Option<CanaryVethFamilyTopology>,
}

impl CanaryPeerVethTopology {
    pub(crate) const fn new(
        ipv4: CanaryVethFamilyTopology,
        ipv6: Option<CanaryVethFamilyTopology>,
    ) -> Result<Self, CanaryBindingError> {
        let ipv4_matches = matches!(ipv4.family, CanaryVethAddressFamily::Ipv4);
        let ipv6_matches = match ipv6 {
            Some(ipv6) => matches!(ipv6.family, CanaryVethAddressFamily::Ipv6),
            None => true,
        };
        if !ipv4_matches || !ipv6_matches {
            return Err(CanaryBindingError::MismatchedVethTopologyFamily);
        }
        Ok(Self { ipv4, ipv6 })
    }

    #[must_use]
    pub(crate) const fn ipv4(self) -> CanaryVethFamilyTopology {
        self.ipv4
    }

    #[must_use]
    pub(crate) const fn ipv6(self) -> Option<CanaryVethFamilyTopology> {
        self.ipv6
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
        if tcp_echo.get() == u16::MAX || udp_echo.get() == u16::MAX || dns.get() == u16::MAX {
            return Err(CanaryBindingError::UnrepresentableResponderPort);
        }
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
    generation: GenerationId,
    nonce: CanaryNonce,
    facility: CanaryFacilityIdentity,
    facility_digest: CanaryFacilityAuditDigest,
    reviewed_pool_identity: CanaryFacilityAuditDigest,
}

impl CanaryFacilityAdmissionScope {
    #[must_use]
    pub(crate) const fn new(
        generation: GenerationId,
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

    #[must_use]
    pub(crate) const fn facility_digest(self) -> CanaryFacilityAuditDigest {
        self.facility_digest
    }

    #[must_use]
    pub(crate) const fn facility(self) -> CanaryFacilityIdentity {
        self.facility
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
    peer_veth_topology: CanaryPeerVethTopology,
    ports: CanaryResponderPorts,
}

impl CanaryFacilityIdentity {
    pub(crate) fn new(
        daemon_veth: CanaryVethIdentity,
        peer_veth: CanaryVethIdentity,
        ipv4: CanaryIpv4AddressPair,
        ipv6: Option<CanaryIpv6AddressPair>,
        peer_veth_topology: CanaryPeerVethTopology,
        ports: CanaryResponderPorts,
    ) -> Result<Self, CanaryBindingError> {
        if daemon_veth.interface_index == peer_veth.interface_index {
            return Err(CanaryBindingError::DuplicateVethIndex);
        }
        if daemon_veth.interface_name == peer_veth.interface_name {
            return Err(CanaryBindingError::DuplicateVethName);
        }
        if ipv6.is_some() != peer_veth_topology.ipv6.is_some() {
            return Err(CanaryBindingError::FacilityIpv6TopologyMismatch);
        }
        Ok(Self {
            daemon_veth,
            peer_veth,
            ipv4,
            ipv6,
            peer_veth_topology,
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
    pub(crate) const fn peer_veth_topology(&self) -> CanaryPeerVethTopology {
        self.peer_veth_topology
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
        if engine_uid.get() == u32::MAX {
            return Err(CanaryBindingError::UnrepresentableRpdbEngineUid);
        }
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

/// Private provenance supplied to the pure retained-facility validator.
///
/// The two inventories come from separate loss-aware one-shot observers. Their
/// epochs are deliberately not compared: a first publication is `INITIAL` for
/// both observers and is not a continuity token.
#[allow(
    dead_code,
    reason = "the packaged attempt remains uninhabited until its evidence transaction lands"
)]
pub(crate) struct RetainedCanaryFacilityObservation {
    daemon_namespace_before: NetworkNamespaceIdentity,
    daemon_namespace_after: NetworkNamespaceIdentity,
    peer_namespace: NetworkNamespaceIdentity,
    daemon_inventory: Arc<NetworkInventory>,
    peer_inventory: Arc<NetworkInventory>,
    daemon_started_at: Instant,
    daemon_completed_at: Instant,
    peer_started_at: Instant,
    peer_inventory_completed_at: Instant,
    listener_started_at: Instant,
    listener_completed_at: Instant,
    listener_netlink_port_id: NonZeroU32,
    listener_dumps: Box<[RetainedCanaryListenerDump]>,
    listener_conflict_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedCanaryListenerDump {
    sequence: NonZeroU32,
    target: ListenerConflictTarget,
    started_at: Instant,
    completed_at: Instant,
}

#[allow(
    dead_code,
    reason = "the packaged attempt remains uninhabited until its evidence transaction lands"
)]
impl RetainedCanaryFacilityObservation {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) fn new(
        daemon_namespace_before: NetworkNamespaceIdentity,
        daemon_namespace_after: NetworkNamespaceIdentity,
        peer_namespace: NetworkNamespaceIdentity,
        daemon_inventory: Arc<NetworkInventory>,
        peer_inventory: Arc<NetworkInventory>,
        daemon_started_at: Instant,
        daemon_completed_at: Instant,
        peer_started_at: Instant,
        peer_inventory_completed_at: Instant,
        listener: &ListenerConflictSnapshot,
    ) -> Self {
        Self {
            daemon_namespace_before,
            daemon_namespace_after,
            peer_namespace,
            daemon_inventory,
            peer_inventory,
            daemon_started_at,
            daemon_completed_at,
            peer_started_at,
            peer_inventory_completed_at,
            listener_started_at: listener.started_at(),
            listener_completed_at: listener.completed_at(),
            listener_netlink_port_id: listener.netlink_port_id(),
            listener_dumps: listener
                .dumps()
                .iter()
                .map(|dump| RetainedCanaryListenerDump {
                    sequence: dump.sequence(),
                    target: dump.target(),
                    started_at: dump.started_at(),
                    completed_at: dump.completed_at(),
                })
                .collect(),
            listener_conflict_count: listener.conflicts().len(),
        }
    }

    fn listener_dumps_complete(&self) -> bool {
        !self.listener_dumps.is_empty()
            && self
                .listener_dumps
                .windows(2)
                .all(|pair| pair[0].sequence.get().checked_add(1) == Some(pair[1].sequence.get()))
            && self.listener_dumps.iter().enumerate().all(|(index, dump)| {
                self.listener_dumps[..index]
                    .iter()
                    .all(|prior| prior.target != dump.target)
                    && dump.started_at >= self.listener_started_at
                    && dump.completed_at >= dump.started_at
                    && dump.completed_at <= self.listener_completed_at
            })
    }
}

/// Minimal successful readback. Observer epochs, snapshot identities, and
/// sequential intervals remain validation-local and cannot become authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the packaged attempt remains uninhabited until its evidence transaction lands"
)]
pub(crate) struct RetainedCanaryFacilityReadback {
    facility: CanaryFacilityIdentity,
    observed_at: Instant,
}

#[allow(
    dead_code,
    reason = "the packaged attempt remains uninhabited until its evidence transaction lands"
)]
impl RetainedCanaryFacilityReadback {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn fixture(facility: CanaryFacilityIdentity, observed_at: Instant) -> Self {
        Self {
            facility,
            observed_at,
        }
    }

    #[must_use]
    pub(crate) const fn facility(self) -> CanaryFacilityIdentity {
        self.facility
    }

    #[must_use]
    pub(crate) const fn observed_at(self) -> Instant {
        self.observed_at
    }

    /// Finalize the validated facility with the completion time sampled by the
    /// live observer after semantic validation has succeeded.
    pub(crate) fn finalize_at(
        self,
        observed_at: Instant,
    ) -> Result<Self, RetainedCanaryFacilityValidationError> {
        if observed_at < self.observed_at {
            return Err(RetainedCanaryFacilityValidationError::InvalidObservationChronology);
        }
        Ok(Self {
            facility: self.facility,
            observed_at,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetainedCanaryFacilityValidationError {
    RequestMismatch,
    InvalidPeerRetirementChronology,
    NetworkNamespaceMismatch,
    InventoryProvenanceMismatch,
    InvalidObservationChronology,
    IncompleteListenerObservation,
    ListenerTargetMismatch,
    ListenerConflict,
    DaemonVethMismatch,
    PeerVethMismatch,
    AddressMismatch,
    RouteMismatch,
    PeerRuleMismatch,
}

impl fmt::Display for RetainedCanaryFacilityValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RequestMismatch => {
                "peer-reaped authority belongs to another functional-canary request"
            }
            Self::InvalidPeerRetirementChronology => "peer-server retirement chronology is invalid",
            Self::NetworkNamespaceMismatch => {
                "retained facility was observed under a different network namespace"
            }
            Self::InventoryProvenanceMismatch => {
                "retained facility inventories do not have fresh distinct snapshot provenance"
            }
            Self::InvalidObservationChronology => {
                "retained facility observation falls outside the immutable sequential chronology"
            }
            Self::IncompleteListenerObservation => {
                "retained facility listener-conflict observation is incomplete"
            }
            Self::ListenerTargetMismatch => {
                "retained facility listener-conflict targets are not canonical"
            }
            Self::ListenerConflict => {
                "retained facility responder port has a namespace listener conflict"
            }
            Self::DaemonVethMismatch => "daemon retained-facility veth endpoint changed",
            Self::PeerVethMismatch => "peer retained-facility veth endpoint changed",
            Self::AddressMismatch => "retained-facility address or prefix changed",
            Self::RouteMismatch => "retained-facility canonical host route changed",
            Self::PeerRuleMismatch => "daemon retained-facility peer-selection policy rule changed",
        })
    }
}

impl Error for RetainedCanaryFacilityValidationError {}

/// Validate one sequential post-reap observation without performing I/O.
///
/// Listener dumps are complete negative evidence for the exact ordered states
/// and ports only. They are sequential rather than atomic and do not claim
/// total immediate bindability.
pub(crate) fn validate_retained_canary_facility_observation(
    request: &CanaryAttemptRequest,
    peer_reaped: &PeerReapedCanaryAttemptAuthority,
    observation: &RetainedCanaryFacilityObservation,
) -> Result<RetainedCanaryFacilityReadback, RetainedCanaryFacilityValidationError> {
    if peer_reaped.request() != request {
        return Err(RetainedCanaryFacilityValidationError::RequestMismatch);
    }
    let deadline = request.deadline();
    let peer_retirements = peer_reaped.peer_servers();
    if peer_retirements.iter().any(|retirement| {
        retirement.quiesced_at > retirement.terminated_at
            || retirement.terminated_at > retirement.reaped_at
            || retirement.quiesced_at < deadline.started_at()
            || retirement.reaped_at >= deadline.expires_at()
    }) || peer_retirements
        .iter()
        .map(|retirement| retirement.reaped_at)
        .max()
        != Some(peer_reaped.latest_peer_reaped_at())
    {
        return Err(RetainedCanaryFacilityValidationError::InvalidPeerRetirementChronology);
    }

    let expected_network = request.pre_binding().environment().authority().network();
    if observation.daemon_namespace_before != expected_network.daemon_network_namespace()
        || observation.daemon_namespace_after != expected_network.daemon_network_namespace()
        || observation.peer_namespace != expected_network.peer_network_namespace()
    {
        return Err(RetainedCanaryFacilityValidationError::NetworkNamespaceMismatch);
    }
    let admission_snapshot = expected_network.network_inventory_snapshot_id();
    if observation.daemon_inventory.snapshot_id() == admission_snapshot
        || observation.peer_inventory.snapshot_id() == admission_snapshot
        || observation.daemon_inventory.snapshot_id() == observation.peer_inventory.snapshot_id()
    {
        return Err(RetainedCanaryFacilityValidationError::InventoryProvenanceMismatch);
    }
    if peer_reaped.latest_peer_reaped_at() >= observation.daemon_started_at
        || observation.daemon_started_at > observation.daemon_completed_at
        || observation.daemon_completed_at > observation.peer_started_at
        || observation.peer_started_at > observation.peer_inventory_completed_at
        || observation.peer_inventory_completed_at > observation.listener_started_at
        || observation.listener_started_at > observation.listener_completed_at
        || observation.listener_completed_at >= deadline.expires_at()
    {
        return Err(RetainedCanaryFacilityValidationError::InvalidObservationChronology);
    }
    if !observation.listener_dumps_complete() {
        return Err(RetainedCanaryFacilityValidationError::IncompleteListenerObservation);
    }
    if observation
        .listener_dumps
        .iter()
        .map(|dump| dump.target)
        .ne(canonical_listener_conflict_targets(request))
    {
        return Err(RetainedCanaryFacilityValidationError::ListenerTargetMismatch);
    }
    if observation.listener_conflict_count != 0 {
        return Err(RetainedCanaryFacilityValidationError::ListenerConflict);
    }

    let environment = request.pre_binding().environment();
    let facility = environment.facility();
    validate_veth_endpoint(
        observation.daemon_inventory.as_ref(),
        facility.daemon_veth(),
        facility.peer_veth().interface_index(),
    )
    .map_err(|()| RetainedCanaryFacilityValidationError::DaemonVethMismatch)?;
    validate_veth_endpoint(
        observation.peer_inventory.as_ref(),
        facility.peer_veth(),
        facility.daemon_veth().interface_index(),
    )
    .map_err(|()| RetainedCanaryFacilityValidationError::PeerVethMismatch)?;

    let topology = facility.peer_veth_topology();
    let ipv6 = facility.ipv6().zip(topology.ipv6());
    validate_exact_endpoint_addresses(
        observation.daemon_inventory.as_ref(),
        observation.peer_inventory.as_ref(),
        facility.daemon_veth().interface_index(),
        IpAddr::V4(facility.ipv4().daemon()),
        topology.ipv4().daemon_prefix_length(),
        ipv6.map(|(addresses, topology)| {
            (
                IpAddr::V6(addresses.daemon()),
                topology.daemon_prefix_length(),
            )
        }),
    )?;
    validate_exact_endpoint_addresses(
        observation.peer_inventory.as_ref(),
        observation.daemon_inventory.as_ref(),
        facility.peer_veth().interface_index(),
        IpAddr::V4(facility.ipv4().peer()),
        topology.ipv4().peer_prefix_length(),
        ipv6.map(|(addresses, topology)| {
            (IpAddr::V6(addresses.peer()), topology.peer_prefix_length())
        }),
    )?;
    let mut daemon_routes = vec![
        expected_host_route(
            IpAddr::V4(facility.ipv4().peer()),
            facility.daemon_veth().interface_index(),
            topology.ipv4().daemon_to_peer_route(),
        )
        .ok_or(RetainedCanaryFacilityValidationError::RouteMismatch)?,
    ];
    let mut peer_routes = vec![
        expected_host_route(
            IpAddr::V4(facility.ipv4().daemon()),
            facility.peer_veth().interface_index(),
            topology.ipv4().peer_to_daemon_route(),
        )
        .ok_or(RetainedCanaryFacilityValidationError::RouteMismatch)?,
    ];
    if let Some((addresses, ipv6_topology)) = ipv6 {
        daemon_routes.push(
            expected_host_route(
                IpAddr::V6(addresses.peer()),
                facility.daemon_veth().interface_index(),
                ipv6_topology.daemon_to_peer_route(),
            )
            .ok_or(RetainedCanaryFacilityValidationError::RouteMismatch)?,
        );
        peer_routes.push(
            expected_host_route(
                IpAddr::V6(addresses.daemon()),
                facility.peer_veth().interface_index(),
                ipv6_topology.peer_to_daemon_route(),
            )
            .ok_or(RetainedCanaryFacilityValidationError::RouteMismatch)?,
        );
    }
    validate_exact_owned_route_cohort(observation.daemon_inventory.as_ref(), &daemon_routes)?;
    validate_exact_owned_route_cohort(observation.peer_inventory.as_ref(), &peer_routes)?;
    validate_peer_selection_rules(request, observation.daemon_inventory.as_ref())?;

    // The listener completion is the lower bound for the writer's final live
    // observation timestamp. The writer samples the clock only after this pure
    // semantic validation returns successfully.
    Ok(RetainedCanaryFacilityReadback {
        facility,
        observed_at: observation.listener_completed_at,
    })
}

fn validate_exact_owned_route_cohort(
    inventory: &NetworkInventory,
    expected: &[NetworkRouteRecord],
) -> Result<(), RetainedCanaryFacilityValidationError> {
    let actual = inventory
        .routes()
        .iter()
        .filter(|route| {
            expected.iter().any(|candidate| {
                route.properties().table() == candidate.properties().table()
                    && route.properties().protocol() == candidate.properties().protocol()
            })
        })
        .collect::<Vec<_>>();
    if actual.len() != expected.len()
        || expected
            .iter()
            .any(|candidate| actual.iter().filter(|route| **route == candidate).count() != 1)
        || actual
            .iter()
            .any(|route| !expected.iter().any(|candidate| **route == *candidate))
    {
        return Err(RetainedCanaryFacilityValidationError::RouteMismatch);
    }
    Ok(())
}

pub(crate) fn canonical_listener_conflict_targets(
    request: &CanaryAttemptRequest,
) -> Vec<ListenerConflictTarget> {
    CanaryFlow::ALL
        .iter()
        .copied()
        .filter(|flow| request.requires_flow(*flow))
        .map(|flow| {
            ListenerConflictTarget::new(
                match flow.address_family() {
                    CanaryFlowAddressFamily::Ipv4 => InetSocketAddressFamily::Ipv4,
                    CanaryFlowAddressFamily::Ipv6 => InetSocketAddressFamily::Ipv6,
                },
                match flow.protocol() {
                    CanaryFlowProtocol::Tcp => InetSocketProtocol::Tcp,
                    CanaryFlowProtocol::Udp => InetSocketProtocol::Udp,
                },
                request.responder_port(flow),
            )
        })
        .collect()
}

fn validate_veth_endpoint(
    inventory: &NetworkInventory,
    expected: CanaryVethIdentity,
    expected_peer_index: InterfaceIndex,
) -> Result<(), ()> {
    let mut endpoints = inventory.links().iter().filter(|link| {
        link.interface_index() == expected.interface_index()
            || link.name() == &expected.interface_name()
    });
    let endpoint = endpoints.next().ok_or(())?;
    if endpoints.next().is_some()
        || endpoint.interface_index() != expected.interface_index()
        || endpoint.name() != &expected.interface_name()
        || endpoint.kind().map(|kind| kind.as_bytes()) != Some(b"veth".as_slice())
        || endpoint.link_reference() != Some(InterfaceLinkReference::Interface(expected_peer_index))
    {
        return Err(());
    }
    Ok(())
}

fn validate_exact_endpoint_addresses(
    inventory: &NetworkInventory,
    other_inventory: &NetworkInventory,
    expected_interface: InterfaceIndex,
    expected_ipv4: IpAddr,
    expected_ipv4_prefix_length: u8,
    expected_ipv6: Option<(IpAddr, u8)>,
) -> Result<(), RetainedCanaryFacilityValidationError> {
    for (expected_address, expected_prefix_length) in
        std::iter::once((expected_ipv4, expected_ipv4_prefix_length)).chain(expected_ipv6)
    {
        let matching = inventory
            .addresses()
            .iter()
            .filter(|address| address.address() == expected_address)
            .collect::<Vec<_>>();
        if matching.len() != 1
            || matching[0].interface_index() != expected_interface
            || matching[0].prefix_length() != expected_prefix_length
            || has_unhealthy_address_flags(matching[0].flags())
            || other_inventory
                .addresses()
                .iter()
                .any(|address| address.address() == expected_address)
        {
            return Err(RetainedCanaryFacilityValidationError::AddressMismatch);
        }
    }
    let extras = inventory.addresses().iter().filter(|address| {
        address.interface_index() == expected_interface
            && address.address() != expected_ipv4
            && expected_ipv6.is_none_or(|(expected, _)| address.address() != expected)
    });
    let mut link_local_count = 0_usize;
    for address in extras {
        if !is_healthy_ipv6_link_local(address.address(), address.prefix_length(), address.flags())
        {
            return Err(RetainedCanaryFacilityValidationError::AddressMismatch);
        }
        link_local_count += 1;
    }
    // Linux may synthesize one link-local endpoint unless the future facility
    // creator pins addrgenmode. Its concrete address is not an authority, but
    // multiple, unhealthy, non-/64, or global extras remain drift.
    if link_local_count > 1 {
        return Err(RetainedCanaryFacilityValidationError::AddressMismatch);
    }
    Ok(())
}

fn expected_host_route(
    destination: IpAddr,
    output_interface: InterfaceIndex,
    shape: CanaryRouteShape,
) -> Option<NetworkRouteRecord> {
    let family = match destination {
        IpAddr::V4(_) => NetworkAddressFamily::Ipv4,
        IpAddr::V6(_) => NetworkAddressFamily::Ipv6,
    };
    let prefix_length = match family {
        NetworkAddressFamily::Ipv4 => 32,
        NetworkAddressFamily::Ipv6 => 128,
    };
    let route = NetworkRouteRecord::new(
        RoutePrefix::new(destination, prefix_length).ok()?,
        RoutePrefix::unspecified(family),
        RouteProperties::new(
            0,
            shape.table(),
            shape.protocol(),
            shape.scope(),
            shape.route_type(),
            RouteFlags::from_raw(0),
        ),
        shape.metric().get(),
        RoutePath::Single {
            output_interface: Some(output_interface),
            gateway: None,
        },
    )
    .ok()?;
    match family {
        NetworkAddressFamily::Ipv4 => Some(route),
        NetworkAddressFamily::Ipv6 => route.with_preference(RoutePreference::from_raw(0)).ok(),
    }
}

fn has_unhealthy_address_flags(flags: InterfaceAddressFlags) -> bool {
    flags.intersects(
        InterfaceAddressFlags::TENTATIVE
            | InterfaceAddressFlags::DAD_FAILED
            | InterfaceAddressFlags::DEPRECATED,
    )
}

fn is_healthy_ipv6_link_local(
    address: IpAddr,
    prefix_length: u8,
    flags: InterfaceAddressFlags,
) -> bool {
    matches!(address, IpAddr::V6(address) if address.segments()[0] & 0xffc0 == 0xfe80)
        && prefix_length == 64
        && !has_unhealthy_address_flags(flags)
}

fn validate_peer_selection_rules(
    request: &CanaryAttemptRequest,
    daemon_inventory: &NetworkInventory,
) -> Result<(), RetainedCanaryFacilityValidationError> {
    let expected = CanaryFlow::ALL
        .iter()
        .copied()
        .filter(|flow| request.requires_flow(*flow))
        .map(|flow| {
            expected_peer_selection_rule(request, flow)
                .ok_or(RetainedCanaryFacilityValidationError::PeerRuleMismatch)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let rpdb = request.pre_binding().environment().rpdb();
    let peer_table = RuleTableId::from_raw(rpdb.peer_table().get());
    let actual = daemon_inventory
        .rules()
        .iter()
        .filter(|rule| {
            rule.priority() == rpdb.peer_rule_priority() || rule.properties().table() == peer_table
        })
        .collect::<Vec<_>>();
    if actual.len() != expected.len()
        || expected
            .iter()
            .any(|candidate| actual.iter().filter(|rule| **rule == candidate).count() != 1)
        || actual
            .iter()
            .any(|rule| !expected.iter().any(|candidate| **rule == *candidate))
    {
        return Err(RetainedCanaryFacilityValidationError::PeerRuleMismatch);
    }
    Ok(())
}

fn expected_peer_selection_rule(
    request: &CanaryAttemptRequest,
    flow: CanaryFlow,
) -> Option<NetworkRuleRecord> {
    let environment = request.pre_binding().environment();
    let rpdb = environment.rpdb();
    let destination = request.peer_address(flow);
    let family = match destination {
        IpAddr::V4(_) => NetworkAddressFamily::Ipv4,
        IpAddr::V6(_) => NetworkAddressFamily::Ipv6,
    };
    let prefix_length = match family {
        NetworkAddressFamily::Ipv4 => 32,
        NetworkAddressFamily::Ipv6 => 128,
    };
    let mut rule = NetworkRuleRecord::new(
        RulePrefix::new(destination, prefix_length).ok()?,
        RulePrefix::unspecified(family),
        RuleProperties::new(
            0,
            RuleTableId::from_raw(rpdb.peer_table().get()),
            RuleAction::TO_TABLE,
            RuleProtocol::from_raw(rpdb.rule_protocol().get()),
            RuleFlags::from_raw(0),
        ),
        rpdb.peer_rule_priority(),
        None,
    )
    .ok()?;
    rule = rule
        .with_fwmark(RuleFwMark::new(0, rpdb.proxy_mark_mask().get())?)
        .with_uid_range(RuleUidRange::new(rpdb.engine_uid().get(), rpdb.engine_uid().get()).ok()?)
        .with_ip_protocol(RuleIpProtocol::new(match flow.protocol() {
            CanaryFlowProtocol::Tcp => 6,
            CanaryFlowProtocol::Udp => 17,
        })?)
        .with_destination_port_range(
            RulePortRange::new(
                request.responder_port(flow).get(),
                request.responder_port(flow).get(),
            )
            .ok()?,
        );
    rule.has_complete_attribute_coverage().then_some(rule)
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
    socket_observer_opening: CanarySocketObserverOpeningId,
}

impl CanaryEnvironmentAuthorityBinding {
    #[must_use]
    pub(crate) const fn new(
        boot_identity: BootIdentity,
        capability_profile_revision: CapabilityProfileRevision,
        network: CanaryNetworkObservationBinding,
        capture_program_digest: CaptureProgramDigest,
        ownership: CanaryOwnershipBinding,
        socket_observer: CanarySocketObserverBinding,
    ) -> Self {
        Self {
            boot_identity,
            capability_profile_revision,
            network,
            capture_program_digest,
            ownership,
            socket_observer: socket_observer.authority,
            socket_observer_opening: socket_observer.opening_id,
        }
    }

    #[must_use]
    pub(crate) const fn socket_observer(&self) -> CanarySocketObserverAuthority {
        self.socket_observer
    }

    #[must_use]
    pub(crate) const fn socket_observer_binding(&self) -> CanarySocketObserverBinding {
        CanarySocketObserverBinding {
            authority: self.socket_observer,
            opening_id: self.socket_observer_opening,
        }
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

/// Immutable native facts retained when a Generation is admitted.
///
/// This value is planning evidence only. It cannot become canary authority until the native writer
/// combines it with a fresh exact active-ownership observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedCanaryGenerationBinding {
    generation: GenerationId,
    boot_identity: BootIdentity,
    capability_profile_revision: CapabilityProfileRevision,
    daemon_network_namespace: NetworkNamespaceIdentity,
    network_epoch: NetworkEpoch,
    network_inventory_snapshot_id: NetworkInventorySnapshotId,
    capture_program_digest: CaptureProgramDigest,
    journal_identity: OwnershipJournalIdentity,
    planning_journal_revision: OwnershipJournalRevision,
}

impl PreparedCanaryGenerationBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        generation: GenerationId,
        boot_identity: BootIdentity,
        capability_profile_revision: CapabilityProfileRevision,
        daemon_network_namespace: NetworkNamespaceIdentity,
        network_epoch: NetworkEpoch,
        network_inventory_snapshot_id: NetworkInventorySnapshotId,
        capture_program_digest: [u8; CAPTURE_PROGRAM_DIGEST_BYTES],
        journal_identity: OwnershipJournalIdentity,
        planning_journal_revision: OwnershipJournalRevision,
    ) -> Result<Self, CanaryBindingError> {
        Ok(Self {
            generation,
            boot_identity,
            capability_profile_revision,
            daemon_network_namespace,
            network_epoch,
            network_inventory_snapshot_id,
            capture_program_digest: CaptureProgramDigest::new(capture_program_digest)?,
            journal_identity,
            planning_journal_revision,
        })
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> GenerationId {
        self.generation
    }

    pub(crate) fn bind_active_ownership(
        &self,
        expected_target: NativeCaptureTargetIdentity,
        observation: &NativeCaptureOwnershipObservation,
        retained_facility: CanaryFacilityIdentity,
    ) -> Result<ActiveCanaryGenerationBinding, CanaryBindingError> {
        if expected_target.generation() != self.generation
            || observation.target() != expected_target
        {
            return Err(CanaryBindingError::ActiveCaptureTargetMismatch);
        }
        if observation.boot_identity() != &self.boot_identity {
            return Err(CanaryBindingError::ActiveCaptureBootMismatch);
        }
        if observation.network_namespace() != self.daemon_network_namespace {
            return Err(CanaryBindingError::ActiveCaptureNetworkNamespaceMismatch);
        }
        if observation.journal_identity() != self.journal_identity {
            return Err(CanaryBindingError::ActiveCaptureJournalIdentityMismatch);
        }
        if observation.journal_revision() <= self.planning_journal_revision {
            return Err(CanaryBindingError::ActiveCaptureJournalRevisionNotAdvanced);
        }
        let capture_owner = CaptureOwnerRecordBinding::new(
            observation.record_schema_version(),
            observation.boot_identity().clone(),
            self.generation,
            CanaryFileIdentity::new(observation.record_device(), observation.record_inode()),
            CaptureOwnerRecordDigest::new(observation.record_digest())?,
        );
        Ok(ActiveCanaryGenerationBinding {
            generation: self.generation,
            boot_identity: self.boot_identity.clone(),
            capability_profile_revision: self.capability_profile_revision,
            daemon_network_namespace: self.daemon_network_namespace,
            network_epoch: self.network_epoch,
            network_inventory_snapshot_id: self.network_inventory_snapshot_id,
            capture_program_digest: self.capture_program_digest,
            retained_facility,
            ownership: CanaryOwnershipBinding::new(
                observation.journal_identity(),
                observation.journal_revision(),
                capture_owner,
            ),
        })
    }
}

/// Fresh active native ownership combined with the immutable admitted Generation facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActiveCanaryGenerationBinding {
    generation: GenerationId,
    boot_identity: BootIdentity,
    capability_profile_revision: CapabilityProfileRevision,
    daemon_network_namespace: NetworkNamespaceIdentity,
    network_epoch: NetworkEpoch,
    network_inventory_snapshot_id: NetworkInventorySnapshotId,
    capture_program_digest: CaptureProgramDigest,
    retained_facility: CanaryFacilityIdentity,
    ownership: CanaryOwnershipBinding,
}

impl ActiveCanaryGenerationBinding {
    #[must_use]
    pub(crate) const fn generation(&self) -> GenerationId {
        self.generation
    }

    #[must_use]
    pub(crate) const fn retained_facility(&self) -> CanaryFacilityIdentity {
        self.retained_facility
    }

    #[must_use]
    pub(crate) const fn network_epoch(&self) -> NetworkEpoch {
        self.network_epoch
    }

    #[must_use]
    pub(crate) const fn network_inventory_snapshot_id(&self) -> NetworkInventorySnapshotId {
        self.network_inventory_snapshot_id
    }

    pub(crate) fn bind_environment_authority(
        &self,
        peer_network_namespace: NetworkNamespaceIdentity,
        socket_observer: CanarySocketObserverBinding,
    ) -> Result<CanaryEnvironmentAuthorityBinding, CanaryBindingError> {
        let network = CanaryNetworkObservationBinding::new(
            self.daemon_network_namespace,
            peer_network_namespace,
            self.network_epoch,
            self.network_inventory_snapshot_id,
        )?;
        Ok(CanaryEnvironmentAuthorityBinding::new(
            self.boot_identity.clone(),
            self.capability_profile_revision,
            network,
            self.capture_program_digest,
            self.ownership.clone(),
            socket_observer,
        ))
    }

    #[must_use]
    pub(crate) fn matches_environment(&self, environment: &CanaryEnvironmentBinding) -> bool {
        let authority = environment.authority();
        self.boot_identity == authority.boot_identity
            && self.capability_profile_revision == authority.capability_profile_revision
            && self.daemon_network_namespace == authority.network.daemon_network_namespace
            && self.network_epoch == authority.network.network_epoch
            && self.network_inventory_snapshot_id == authority.network.network_inventory_snapshot_id
            && self.capture_program_digest == authority.capture_program_digest
            && self.retained_facility == environment.facility
            && self.ownership == authority.ownership
            && self.generation == authority.ownership.capture_owner.generation
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_environment_fixture(environment: &CanaryEnvironmentBinding) -> Self {
        let authority = environment.authority();
        Self {
            generation: authority.ownership.capture_owner.generation,
            boot_identity: authority.boot_identity.clone(),
            capability_profile_revision: authority.capability_profile_revision,
            daemon_network_namespace: authority.network.daemon_network_namespace,
            network_epoch: authority.network.network_epoch,
            network_inventory_snapshot_id: authority.network.network_inventory_snapshot_id,
            capture_program_digest: authority.capture_program_digest,
            retained_facility: environment.facility,
            ownership: authority.ownership.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryEnvironmentBinding {
    authority: CanaryEnvironmentAuthorityBinding,
    credentials: CanaryAttemptCredentialBinding,
    facility: CanaryFacilityIdentity,
    facility_admission: CanaryFacilityAdmissionToken,
    rpdb: CanaryRpdbIdentity,
    attempt_objects: CanaryAttemptObjectIdentities,
}

impl CanaryEnvironmentBinding {
    pub(crate) fn new(
        authority: CanaryEnvironmentAuthorityBinding,
        credentials: CanaryAttemptCredentialBinding,
        facility: CanaryFacilityIdentity,
        facility_admission: CanaryFacilityAdmissionToken,
        rpdb: CanaryRpdbIdentity,
        attempt_objects: CanaryAttemptObjectIdentities,
    ) -> Result<Self, CanaryBindingError> {
        if credentials.engine.uid() != rpdb.engine_uid {
            return Err(CanaryBindingError::EngineCredentialUidMismatch);
        }
        if facility_admission.observation.network_epoch != authority.network.network_epoch
            || facility_admission.observation.inventory_snapshot_id
                != authority.network.network_inventory_snapshot_id
        {
            return Err(CanaryBindingError::FacilityAdmissionInventoryMismatch);
        }
        if facility_admission.scope.facility != facility {
            return Err(CanaryBindingError::FacilityAdmissionScopeMismatch);
        }
        let topology = facility.peer_veth_topology();
        if topology.ipv4().daemon_to_peer_route().table() != rpdb.peer_table()
            || topology
                .ipv6()
                .is_some_and(|ipv6| ipv6.daemon_to_peer_route().table() != rpdb.peer_table())
        {
            return Err(CanaryBindingError::CanaryPeerRouteTableMismatch);
        }
        Ok(Self {
            authority,
            credentials,
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
        self.credentials.probe.uid()
    }

    #[must_use]
    pub(crate) const fn probe_credentials(&self) -> CanaryProcessCredentialIdentity {
        self.credentials.probe
    }

    #[must_use]
    pub(crate) const fn engine_credentials(&self) -> CanaryProcessCredentialIdentity {
        self.credentials.engine
    }

    #[must_use]
    pub(crate) const fn credential_domain(&self) -> CanaryCredentialDomainBinding {
        self.credentials.domain
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
    capture_backend: CanaryCaptureBackend,
    nonce: CanaryNonce,
    deadline: CanaryDeadline,
    families: CanaryAddressFamilies,
    dns_expectations: CanaryDnsExpectationSlots,
    counter_bounds: CanaryCounterDeltaBounds,
}

/// Linear proof that the exact request-driving client was parent-reaped while
/// its peer servers remained owned and live.
///
/// Production construction is private to the local-OUTPUT child typestate. The
/// writer-bound attempt consumes this proof before its final counter snapshot,
/// preventing namespace handoff alone from claiming traffic completion.
#[derive(Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the packaged attempt remains uninhabited until its evidence transaction lands"
)]
pub(crate) struct ClientReapedCanaryAttemptAuthority {
    request: CanaryAttemptRequest,
}

/// Linear proof that every exact peer-server role was parent-reaped after the
/// report and counter objects retired.
///
/// Production construction is private to the local-OUTPUT child typestate.
/// The ordered retirement slots remain available for later process receipt
/// projection; the latest reap time is only a chronology convenience.
#[derive(Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the packaged attempt remains uninhabited until its evidence transaction lands"
)]
pub(crate) struct PeerReapedCanaryAttemptAuthority {
    request: CanaryAttemptRequest,
    peer_servers: [CanaryProcessRetirementEvidence; CANARY_PEER_SERVER_SLOTS],
    latest_peer_reaped_at: Instant,
}

#[allow(
    dead_code,
    reason = "the packaged attempt remains uninhabited until its evidence transaction lands"
)]
impl PeerReapedCanaryAttemptAuthority {
    fn from_reaped_peers(
        request: &CanaryAttemptRequest,
        peer_servers: [CanaryProcessRetirementEvidence; CANARY_PEER_SERVER_SLOTS],
    ) -> Self {
        let latest_peer_reaped_at = peer_servers
            .iter()
            .map(|retirement| retirement.reaped_at)
            .max()
            .expect("the fixed peer-server retirement set is nonempty");
        Self {
            request: request.clone(),
            peer_servers,
            latest_peer_reaped_at,
        }
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &CanaryAttemptRequest {
        &self.request
    }

    #[must_use]
    pub(crate) const fn peer_servers(
        &self,
    ) -> &[CanaryProcessRetirementEvidence; CANARY_PEER_SERVER_SLOTS] {
        &self.peer_servers
    }

    #[must_use]
    pub(crate) const fn latest_peer_reaped_at(&self) -> Instant {
        self.latest_peer_reaped_at
    }

    #[cfg(test)]
    pub(crate) fn fixture(
        request: &CanaryAttemptRequest,
        peer_servers: [CanaryProcessRetirementEvidence; CANARY_PEER_SERVER_SLOTS],
    ) -> Self {
        Self::from_reaped_peers(request, peer_servers)
    }
}

#[allow(
    dead_code,
    reason = "the packaged attempt remains uninhabited until its evidence transaction lands"
)]
impl ClientReapedCanaryAttemptAuthority {
    fn from_request(request: &CanaryAttemptRequest) -> Self {
        Self {
            request: request.clone(),
        }
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &CanaryAttemptRequest {
        &self.request
    }

    #[cfg(test)]
    pub(crate) fn fixture(request: &CanaryAttemptRequest) -> Self {
        Self::from_request(request)
    }
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
        if admission.observation.observed_at < deadline.started_at()
            || admission
                .observation
                .observed_at
                .saturating_duration_since(deadline.started_at())
                > MAX_CANARY_FACILITY_OBSERVATION_AGE
            || admission.observation.observed_at >= deadline.expires_at()
            || admission.observation.fresh_until < deadline.expires_at()
        {
            return Err(CanaryBindingError::FacilityAdmissionExpired);
        }
        let dns_expectations = CanaryDnsExpectationSlots::derive(families, nonce);
        Ok(Self {
            schema_version: FUNCTIONAL_CANARY_SCHEMA_VERSION,
            pre_binding,
            capture_backend: CanaryCaptureBackend::Tproxy,
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
    pub(crate) const fn capture_backend(&self) -> CanaryCaptureBackend {
        self.capture_backend
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
pub(crate) enum CanaryFlowProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryFlowAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CanaryListenerRole {
    Ipv4Tcp = 0,
    Ipv4Udp = 1,
    Ipv6Tcp = 2,
    Ipv6Udp = 3,
}

impl CanaryListenerRole {
    pub(crate) const ALL: [Self; CANARY_LISTENER_ROLE_SLOTS] =
        [Self::Ipv4Tcp, Self::Ipv4Udp, Self::Ipv6Tcp, Self::Ipv6Udp];

    pub(crate) const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn address_family(self) -> CanaryFlowAddressFamily {
        match self {
            Self::Ipv4Tcp | Self::Ipv4Udp => CanaryFlowAddressFamily::Ipv4,
            Self::Ipv6Tcp | Self::Ipv6Udp => CanaryFlowAddressFamily::Ipv6,
        }
    }

    pub(crate) const fn protocol(self) -> CanaryFlowProtocol {
        match self {
            Self::Ipv4Tcp | Self::Ipv6Tcp => CanaryFlowProtocol::Tcp,
            Self::Ipv4Udp | Self::Ipv6Udp => CanaryFlowProtocol::Udp,
        }
    }
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

    pub(crate) const fn protocol(self) -> CanaryFlowProtocol {
        match self.kind() {
            CanaryFlowKind::TcpEcho | CanaryFlowKind::DnsTcp => CanaryFlowProtocol::Tcp,
            CanaryFlowKind::UdpEcho | CanaryFlowKind::DnsUdp => CanaryFlowProtocol::Udp,
        }
    }

    pub(crate) const fn address_family(self) -> CanaryFlowAddressFamily {
        if self.is_ipv4() {
            CanaryFlowAddressFamily::Ipv4
        } else {
            CanaryFlowAddressFamily::Ipv6
        }
    }

    pub(crate) const fn listener_role(self) -> CanaryListenerRole {
        match (self.address_family(), self.protocol()) {
            (CanaryFlowAddressFamily::Ipv4, CanaryFlowProtocol::Tcp) => CanaryListenerRole::Ipv4Tcp,
            (CanaryFlowAddressFamily::Ipv4, CanaryFlowProtocol::Udp) => CanaryListenerRole::Ipv4Udp,
            (CanaryFlowAddressFamily::Ipv6, CanaryFlowProtocol::Tcp) => CanaryListenerRole::Ipv6Tcp,
            (CanaryFlowAddressFamily::Ipv6, CanaryFlowProtocol::Udp) => CanaryListenerRole::Ipv6Udp,
        }
    }

    const fn inbound_listener_slot(self) -> usize {
        self.listener_role().index()
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CanaryInboundPayloadDigest([u8; CANARY_INBOUND_PAYLOAD_DIGEST_BYTES]);

impl CanaryInboundPayloadDigest {
    #[must_use]
    const fn from_bytes(bytes: [u8; CANARY_INBOUND_PAYLOAD_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryInboundPayloadIdentity {
    Echo {
        nonce: CanaryNonce,
        wire_length: NonZeroU16,
        wire_digest: CanaryInboundPayloadDigest,
    },
    Dns {
        nonce: CanaryNonce,
        transaction_id: u16,
        question: CanaryDnsQuestionDigest,
        wire_length: NonZeroU16,
        wire_digest: CanaryInboundPayloadDigest,
        tcp_length_prefix: Option<u16>,
    },
}

fn expected_inbound_payload_identity(
    request: &CanaryAttemptRequest,
    flow: CanaryFlow,
) -> CanaryInboundPayloadIdentity {
    let Some(dns) = request.expected_dns(flow) else {
        let mut hasher = Sha256::new();
        hasher.update(request.nonce().as_bytes());
        let wire_digest = CanaryInboundPayloadDigest::from_bytes(hasher.finalize().into());
        return CanaryInboundPayloadIdentity::Echo {
            nonce: request.nonce(),
            wire_length: NonZeroU16::new(
                u16::try_from(FUNCTIONAL_CANARY_NONCE_BYTES)
                    .expect("the fixed nonce length fits u16"),
            )
            .expect("the fixed nonce length is nonzero"),
            wire_digest,
        };
    };

    const DNS_HEADER_BYTES: u16 = 12;
    const DNS_QUESTION_FOOTER_BYTES: u16 = 4;
    let wire_length = DNS_HEADER_BYTES
        + u16::try_from(CANARY_DNS_WIRE_NAME_BYTES).expect("DNS wire-name length fits u16")
        + DNS_QUESTION_FOOTER_BYTES;
    let mut hasher = Sha256::new();
    hasher.update(dns.transaction_id.to_be_bytes());
    hasher.update(0x0100_u16.to_be_bytes());
    hasher.update(1_u16.to_be_bytes());
    hasher.update(0_u16.to_be_bytes());
    hasher.update(0_u16.to_be_bytes());
    hasher.update(0_u16.to_be_bytes());
    hasher.update(dns.question.wire_name);
    hasher.update(dns.question.record_type.to_be_bytes());
    hasher.update(1_u16.to_be_bytes());
    let wire_digest = CanaryInboundPayloadDigest::from_bytes(hasher.finalize().into());
    CanaryInboundPayloadIdentity::Dns {
        nonce: request.nonce(),
        transaction_id: dns.transaction_id,
        question: dns.question_digest,
        wire_length: NonZeroU16::new(wire_length).expect("DNS query wire length is nonzero"),
        wire_digest,
        tcp_length_prefix: (flow.kind() == CanaryFlowKind::DnsTcp).then_some(wire_length),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryInetDiagListenerSnapshot {
    observer: CanarySocketObserverBinding,
    process: OwnedEngineIdentity,
    listener_port: NonZeroU16,
    started_at: Instant,
    completed_at: Instant,
    first_sequence: NonZeroU64,
    last_sequence: NonZeroU64,
    role_sequences: [NonZeroU64; CANARY_LISTENER_ROLE_SLOTS],
}

impl CanaryInetDiagListenerSnapshot {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    const fn new(
        observer: CanarySocketObserverBinding,
        process: OwnedEngineIdentity,
        listener_port: NonZeroU16,
        started_at: Instant,
        completed_at: Instant,
        first_sequence: NonZeroU64,
        last_sequence: NonZeroU64,
        role_sequences: [NonZeroU64; CANARY_LISTENER_ROLE_SLOTS],
    ) -> Self {
        Self {
            observer,
            process,
            listener_port,
            started_at,
            completed_at,
            first_sequence,
            last_sequence,
            role_sequences,
        }
    }

    #[must_use]
    fn role_sequence(self, flow: CanaryFlow) -> NonZeroU64 {
        self.role_sequence_for(flow.listener_role())
    }

    #[must_use]
    fn role_sequence_for(self, role: CanaryListenerRole) -> NonZeroU64 {
        self.role_sequences[role.index()]
    }

    fn has_exact_sequence_map(self) -> bool {
        let first = self.first_sequence.get();
        let Some(last) = first.checked_add(5) else {
            return false;
        };
        self.last_sequence.get() == last
            && self.role_sequences.map(NonZeroU64::get) == [first, first + 4, first + 2, first + 5]
    }
}

/// Loss contract for one listener observation.
///
/// Event observers retain their exact before/after counter. The INET_DIAG
/// path instead binds one all-or-nothing snapshot: interrupted or incomplete
/// dumps never construct the snapshot value, so it does not fabricate an
/// event-counter baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CanaryListenerObservationLoss {
    Counter { before: u64, after: u64 },
    CompleteInetDiagSnapshot(CanaryInetDiagListenerSnapshot),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryListenerSocketObservation {
    authority: CanarySocketObserverAuthority,
    sequence: NonZeroU64,
    loss: CanaryListenerObservationLoss,
    observed_at: Instant,
}

impl CanaryListenerSocketObservation {
    #[cfg(test)]
    #[must_use]
    const fn from_event_counter(
        authority: CanarySocketObserverAuthority,
        sequence: NonZeroU64,
        lost_events_before: u64,
        lost_events_after: u64,
        observed_at: Instant,
    ) -> Self {
        Self {
            authority,
            sequence,
            loss: CanaryListenerObservationLoss::Counter {
                before: lost_events_before,
                after: lost_events_after,
            },
            observed_at,
        }
    }

    #[must_use]
    const fn from_complete_inet_diag_snapshot(
        authority: CanarySocketObserverAuthority,
        sequence: NonZeroU64,
        snapshot: CanaryInetDiagListenerSnapshot,
    ) -> Self {
        Self {
            authority,
            sequence,
            loss: CanaryListenerObservationLoss::CompleteInetDiagSnapshot(snapshot),
            observed_at: snapshot.completed_at,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryInboundDeliveryAuthority {
    SupervisedEngineReport {
        engine: OwnedEngineIdentity,
        engine_profile_revision: EngineCapabilityProfileRevision,
        report_object: CanaryAttemptObjectIdentity,
        schema_version: NonZeroU16,
    },
    QualifiedCgroupBpf {
        observer: CanarySocketObserverAuthority,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryInboundDeliveryEvent {
    authority: CanaryInboundDeliveryAuthority,
    sequence: NonZeroU64,
    lost_events_before: u64,
    lost_events_after: u64,
    observed_at: Instant,
}

impl CanaryInboundDeliveryEvent {
    #[cfg(test)]
    #[must_use]
    const fn new(
        authority: CanaryInboundDeliveryAuthority,
        sequence: NonZeroU64,
        lost_events_before: u64,
        lost_events_after: u64,
        observed_at: Instant,
    ) -> Self {
        Self {
            authority,
            sequence,
            lost_events_before,
            lost_events_after,
            observed_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryTproxyListenerSocketIdentity {
    generation: GenerationId,
    engine: OwnedEngineIdentity,
    listener: CanaryListenerIdentity,
    daemon_network_namespace: NetworkNamespaceIdentity,
    capture_program_digest: CaptureProgramDigest,
    selector: CanaryAttemptObjectIdentity,
    protocol: CanaryFlowProtocol,
    address_family: CanaryFlowAddressFamily,
    listener_fd: CanaryProcFd,
    listener_inode: NonZeroU64,
    listener_cookie: CanaryInetDiagCookie,
    bind: SocketAddr,
    transparent: bool,
    ipv6_only: Option<bool>,
    observation: CanaryListenerSocketObservation,
}

impl CanaryTproxyListenerSocketIdentity {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    const fn new(
        generation: GenerationId,
        engine: OwnedEngineIdentity,
        listener: CanaryListenerIdentity,
        daemon_network_namespace: NetworkNamespaceIdentity,
        capture_program_digest: CaptureProgramDigest,
        selector: CanaryAttemptObjectIdentity,
        protocol: CanaryFlowProtocol,
        address_family: CanaryFlowAddressFamily,
        listener_fd: CanaryProcFd,
        listener_inode: NonZeroU64,
        listener_cookie: CanaryInetDiagCookie,
        bind: SocketAddr,
        transparent: bool,
        ipv6_only: Option<bool>,
        observation: CanaryListenerSocketObservation,
    ) -> Self {
        Self {
            generation,
            engine,
            listener,
            daemon_network_namespace,
            capture_program_digest,
            selector,
            protocol,
            address_family,
            listener_fd,
            listener_inode,
            listener_cookie,
            bind,
            transparent,
            ipv6_only,
            observation,
        }
    }

    fn same_socket_as(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.engine == other.engine
            && self.listener == other.listener
            && self.daemon_network_namespace == other.daemon_network_namespace
            && self.capture_program_digest == other.capture_program_digest
            && self.selector == other.selector
            && self.protocol == other.protocol
            && self.address_family == other.address_family
            && self.listener_fd == other.listener_fd
            && self.listener_inode == other.listener_inode
            && self.listener_cookie == other.listener_cookie
            && self.bind == other.bind
            && self.transparent == other.transparent
            && self.ipv6_only == other.ipv6_only
    }

    fn physical_identity_collides_with(&self, other: &Self) -> bool {
        self.listener_fd == other.listener_fd
            || self.listener_inode == other.listener_inode
            || self.listener_cookie == other.listener_cookie
    }

    fn physical_identity_collides_with_socket(
        &self,
        fd: CanaryProcFd,
        inode: NonZeroU64,
        cookie: CanaryInetDiagCookie,
    ) -> bool {
        self.listener_fd == fd || self.listener_inode == inode || self.listener_cookie == cookie
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryTproxyAcceptedSocketDelivery {
    flow: CanaryFlow,
    engine: OwnedEngineIdentity,
    listener_cookie: CanaryInetDiagCookie,
    accepted_fd: CanaryProcFd,
    accepted_inode: NonZeroU64,
    accepted_cookie: CanaryInetDiagCookie,
    local: SocketAddr,
    peer: SocketAddr,
    event: CanaryInboundDeliveryEvent,
    payload: CanaryInboundPayloadIdentity,
}

impl CanaryTproxyAcceptedSocketDelivery {
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    #[must_use]
    const fn new(
        flow: CanaryFlow,
        engine: OwnedEngineIdentity,
        listener_cookie: CanaryInetDiagCookie,
        accepted_fd: CanaryProcFd,
        accepted_inode: NonZeroU64,
        accepted_cookie: CanaryInetDiagCookie,
        local: SocketAddr,
        peer: SocketAddr,
        event: CanaryInboundDeliveryEvent,
        payload: CanaryInboundPayloadIdentity,
    ) -> Self {
        Self {
            flow,
            engine,
            listener_cookie,
            accepted_fd,
            accepted_inode,
            accepted_cookie,
            local,
            peer,
            event,
            payload,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CanaryOriginalDestinationCmsg {
    Ipv4 { payload_length: u16 },
    Ipv6 { payload_length: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryTproxyUdpRecvmsgDelivery {
    flow: CanaryFlow,
    listener_cookie: CanaryInetDiagCookie,
    client_source: SocketAddr,
    original_destination: SocketAddr,
    payload_truncated: bool,
    control_truncated: bool,
    original_destination_cmsg_count: u8,
    original_destination_cmsg: CanaryOriginalDestinationCmsg,
    event: CanaryInboundDeliveryEvent,
    payload: CanaryInboundPayloadIdentity,
}

impl CanaryTproxyUdpRecvmsgDelivery {
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    #[must_use]
    const fn new(
        flow: CanaryFlow,
        listener_cookie: CanaryInetDiagCookie,
        client_source: SocketAddr,
        original_destination: SocketAddr,
        payload_truncated: bool,
        control_truncated: bool,
        original_destination_cmsg_count: u8,
        original_destination_cmsg: CanaryOriginalDestinationCmsg,
        event: CanaryInboundDeliveryEvent,
        payload: CanaryInboundPayloadIdentity,
    ) -> Self {
        Self {
            flow,
            listener_cookie,
            client_source,
            original_destination,
            payload_truncated,
            control_truncated,
            original_destination_cmsg_count,
            original_destination_cmsg,
            event,
            payload,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UnqualifiedCanaryInboundListenerDeliveryEvidence {
    TproxyTcp {
        listener: CanaryTproxyListenerSocketIdentity,
        accepted: CanaryTproxyAcceptedSocketDelivery,
    },
    TproxyUdp {
        listener: CanaryTproxyListenerSocketIdentity,
        datagram: CanaryTproxyUdpRecvmsgDelivery,
    },
    Redirect,
    Dnat,
}

impl UnqualifiedCanaryInboundListenerDeliveryEvidence {
    #[must_use]
    pub(crate) const fn capture_backend(&self) -> CanaryCaptureBackend {
        match self {
            Self::TproxyTcp { .. } | Self::TproxyUdp { .. } => CanaryCaptureBackend::Tproxy,
            Self::Redirect => CanaryCaptureBackend::Redirect,
            Self::Dnat => CanaryCaptureBackend::Dnat,
        }
    }

    #[must_use]
    const fn delivery_event(&self) -> Option<CanaryInboundDeliveryEvent> {
        match self {
            Self::TproxyTcp { accepted, .. } => Some(accepted.event),
            Self::TproxyUdp { datagram, .. } => Some(datagram.event),
            Self::Redirect | Self::Dnat => None,
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
    inbound_listener_delivery: Option<UnqualifiedCanaryInboundListenerDeliveryEvidence>,
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
        inbound_listener_delivery: Option<UnqualifiedCanaryInboundListenerDeliveryEvidence>,
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
            inbound_listener_delivery,
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
    destination: SocketAddr,
    observed_at: Instant,
    queried_uid: NonZeroU32,
    mark: u32,
    selected_table: RouteTableId,
    injected_peer_observation_count: Option<u8>,
}

impl UnqualifiedCanaryNegativeRouteControl {
    #[must_use]
    pub(crate) const fn new(
        flow: CanaryFlow,
        destination: SocketAddr,
        observed_at: Instant,
        queried_uid: NonZeroU32,
        mark: u32,
        selected_table: RouteTableId,
        injected_peer_observation_count: Option<u8>,
    ) -> Self {
        Self {
            flow,
            destination,
            observed_at,
            queried_uid,
            mark,
            selected_table,
            injected_peer_observation_count,
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

    #[must_use]
    pub(crate) const fn pid(self) -> NonZeroU32 {
        self.pid
    }

    #[must_use]
    pub(crate) const fn start_time_ticks(self) -> NonZeroU64 {
        self.start_time_ticks
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryProcessRetirementEvidence {
    process: CanaryProcessIdentity,
    quiesced_at: Instant,
    terminated_at: Instant,
    reaped_at: Instant,
}

impl CanaryProcessRetirementEvidence {
    #[must_use]
    pub(crate) const fn new(
        process: CanaryProcessIdentity,
        quiesced_at: Instant,
        terminated_at: Instant,
        reaped_at: Instant,
    ) -> Self {
        Self {
            process,
            quiesced_at,
            terminated_at,
            reaped_at,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryAttemptObjectRetirementEvidence {
    object: CanaryAttemptObjectIdentity,
    retired_at: Instant,
    absent_observed_at: Instant,
}

impl CanaryAttemptObjectRetirementEvidence {
    #[must_use]
    pub(crate) const fn new(
        object: CanaryAttemptObjectIdentity,
        retired_at: Instant,
        absent_observed_at: Instant,
    ) -> Self {
        Self {
            object,
            retired_at,
            absent_observed_at,
        }
    }

    #[must_use]
    pub(crate) const fn object(self) -> CanaryAttemptObjectIdentity {
        self.object
    }

    #[must_use]
    pub(crate) const fn retired_at(self) -> Instant {
        self.retired_at
    }

    #[must_use]
    pub(crate) const fn absent_observed_at(self) -> Instant {
        self.absent_observed_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanaryCleanupObjectRole {
    Selector,
    Counters,
    ListenerDeliveryReport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryCleanupEvidence {
    nonce: CanaryNonce,
    client: CanaryProcessRetirementEvidence,
    peer_servers: [CanaryProcessRetirementEvidence; CANARY_PEER_SERVER_SLOTS],
    selector_retirement: Option<CanaryAttemptObjectRetirementEvidence>,
    counters_retirement: CanaryAttemptObjectRetirementEvidence,
    listener_delivery_report: CanaryListenerDeliveryReportCleanupEvidence,
    retained_facility: CanaryFacilityIdentity,
    retained_facility_observed_at: Instant,
}

impl UnqualifiedCanaryCleanupEvidence {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) const fn new(
        nonce: CanaryNonce,
        client: CanaryProcessRetirementEvidence,
        peer_servers: [CanaryProcessRetirementEvidence; CANARY_PEER_SERVER_SLOTS],
        selector_retirement: Option<CanaryAttemptObjectRetirementEvidence>,
        counters_retirement: CanaryAttemptObjectRetirementEvidence,
        listener_delivery_report: CanaryListenerDeliveryReportCleanupEvidence,
        retained_facility: CanaryFacilityIdentity,
        retained_facility_observed_at: Instant,
    ) -> Self {
        Self {
            nonce,
            client,
            peer_servers,
            selector_retirement,
            counters_retirement,
            listener_delivery_report,
            retained_facility,
            retained_facility_observed_at,
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

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct UnqualifiedCanaryGateEvidence {
    request: CanaryAttemptRequest,
    local_output_capture_receipt: local_output::TproxyLocalOutputCaptureReceipt,
    local_output_process_ownership_receipt: local_output::TproxyLocalOutputProcessOwnershipReceipt,
    completed_at: Instant,
    flows: UnqualifiedCanaryFlowEvidenceSlots,
    unexpected_flow_count: u8,
    loop_escape: UnqualifiedCanaryLoopEvidence,
    counters: UnqualifiedCanaryCounterEvidence,
    cleanup: UnqualifiedCanaryCleanupEvidence,
}

impl UnqualifiedCanaryGateEvidence {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(in crate::functional_canary) const fn new(
        request: CanaryAttemptRequest,
        local_output_capture_receipt: local_output::TproxyLocalOutputCaptureReceipt,
        local_output_process_ownership_receipt:
            local_output::TproxyLocalOutputProcessOwnershipReceipt,
        completed_at: Instant,
        flows: UnqualifiedCanaryFlowEvidenceSlots,
        unexpected_flow_count: u8,
        loop_escape: UnqualifiedCanaryLoopEvidence,
        counters: UnqualifiedCanaryCounterEvidence,
        cleanup: UnqualifiedCanaryCleanupEvidence,
    ) -> Self {
        Self {
            request,
            local_output_capture_receipt,
            local_output_process_ownership_receipt,
            completed_at,
            flows,
            unexpected_flow_count,
            loop_escape,
            counters,
            cleanup,
        }
    }

    /// Complete executor-local evidence with the serialized writer's outer selector receipt.
    pub(crate) fn bind_selector_retirement(
        &mut self,
        selector_retirement: CanaryAttemptObjectRetirementEvidence,
    ) -> Result<(), CanaryEvidenceError> {
        if self.cleanup.selector_retirement.is_some() {
            return Err(CanaryEvidenceError::CleanupSelectorRetirementConflict);
        }
        if selector_retirement.object
            != self
                .request
                .pre_binding()
                .environment()
                .attempt_objects()
                .selector()
        {
            return Err(CanaryEvidenceError::CleanupObjectMismatch {
                object: CanaryCleanupObjectRole::Selector,
            });
        }
        if selector_retirement.retired_at > selector_retirement.absent_observed_at {
            return Err(CanaryEvidenceError::CleanupObjectRetirementTimingInvalid {
                object: CanaryCleanupObjectRole::Selector,
            });
        }
        if selector_retirement.retired_at < self.completed_at {
            return Err(CanaryEvidenceError::CleanupSelectorRetiredBeforeAttemptSettlement);
        }

        self.completed_at = selector_retirement.absent_observed_at;
        self.cleanup.selector_retirement = Some(selector_retirement);
        Ok(())
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
        self.local_output_capture_receipt
            .validate_for(
                expected,
                &self.flows,
                self.completed_at,
                self.cleanup.client.quiesced_at,
            )
            .map_err(|_| CanaryEvidenceError::LocalOutputCaptureReceiptInvalid)?;
        validate_loop_evidence(expected, &self.flows, &self.loop_escape)?;
        validate_counter_evidence(expected, &self.flows, self.completed_at, self.counters)?;
        validate_cleanup_evidence(
            expected,
            &self.flows,
            self.counters,
            self.completed_at,
            &self.cleanup,
        )?;
        self.local_output_process_ownership_receipt
            .validate_for(expected, &self.flows, &self.cleanup, self.completed_at)
            .map_err(|_| CanaryEvidenceError::LocalOutputProcessOwnershipReceiptInvalid)?;
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
    StructuralVerificationOnly,
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
    MissingInboundListenerDelivery {
        flow: CanaryFlow,
    },
    InboundListenerBackendMismatch {
        flow: CanaryFlow,
        expected: CanaryCaptureBackend,
        observed: CanaryCaptureBackend,
    },
    InboundListenerBackendUnsupported {
        flow: CanaryFlow,
        backend: CanaryCaptureBackend,
    },
    InboundListenerGenerationMismatch {
        flow: CanaryFlow,
    },
    InboundListenerEngineMismatch {
        flow: CanaryFlow,
    },
    InboundListenerIdentityMismatch {
        flow: CanaryFlow,
    },
    InboundListenerObserverMismatch {
        flow: CanaryFlow,
    },
    InboundListenerDeliveryAuthorityMismatch {
        flow: CanaryFlow,
    },
    InboundListenerNetworkNamespaceMismatch {
        flow: CanaryFlow,
    },
    InboundListenerCaptureProgramMismatch {
        flow: CanaryFlow,
    },
    InboundListenerSelectorMismatch {
        flow: CanaryFlow,
    },
    InboundListenerFlowMismatch {
        expected: CanaryFlow,
        observed: CanaryFlow,
    },
    InboundListenerProtocolMismatch {
        flow: CanaryFlow,
    },
    InboundListenerAddressFamilyMismatch {
        flow: CanaryFlow,
    },
    InboundListenerBindMismatch {
        flow: CanaryFlow,
    },
    InboundListenerTransparentSocketRequired {
        flow: CanaryFlow,
    },
    InboundListenerIpv6OnlyStateInvalid {
        flow: CanaryFlow,
    },
    InboundListenerObservationLoss {
        flow: CanaryFlow,
    },
    InboundListenerObservationAuthorityMismatch {
        flow: CanaryFlow,
    },
    InboundListenerSnapshotAuthorityMismatch {
        flow: CanaryFlow,
    },
    InboundListenerObservationLossBaselineChanged {
        first: CanaryFlow,
        second: CanaryFlow,
    },
    InboundListenerSocketObservationTimingInvalid {
        flow: CanaryFlow,
    },
    InboundListenerTransportEvidenceMismatch {
        flow: CanaryFlow,
    },
    InboundListenerAcceptedEngineMismatch {
        flow: CanaryFlow,
    },
    InboundListenerSocketLinkMismatch {
        flow: CanaryFlow,
    },
    InboundListenerAcceptedSocketIdentityCollision {
        flow: CanaryFlow,
    },
    InboundListenerClientSourceMismatch {
        flow: CanaryFlow,
    },
    InboundListenerOriginalDestinationMismatch {
        flow: CanaryFlow,
    },
    InboundListenerTimingInvalid {
        flow: CanaryFlow,
    },
    InboundListenerEventLoss {
        flow: CanaryFlow,
    },
    InboundListenerEventSequenceReused {
        first: CanaryFlow,
        second: CanaryFlow,
    },
    InboundListenerEventLossBaselineChanged {
        first: CanaryFlow,
        second: CanaryFlow,
    },
    InboundListenerDeliveryAuthorityChanged {
        first: CanaryFlow,
        second: CanaryFlow,
    },
    InboundListenerAcceptedSocketIdentityReused {
        first: CanaryFlow,
        second: CanaryFlow,
    },
    InboundListenerSocketIdentityReused {
        first: CanaryFlow,
        second: CanaryFlow,
    },
    InboundListenerAcceptedSocketConflictsWithListener {
        listener: CanaryFlow,
        accepted: CanaryFlow,
    },
    InboundListenerSocketIdentityChanged {
        first: CanaryFlow,
        second: CanaryFlow,
    },
    InboundListenerUdpMessageTruncated {
        flow: CanaryFlow,
    },
    InboundListenerUdpOriginalDestinationInvalid {
        flow: CanaryFlow,
    },
    InboundListenerPayloadMismatch {
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
    LocalOutputCaptureReceiptInvalid,
    LocalOutputProcessOwnershipReceiptInvalid,
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
    NegativeControlDestinationMismatch,
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
    CleanupSelectorRetirementMissing,
    CleanupSelectorRetirementConflict,
    CleanupSelectorRetiredBeforeAttemptSettlement,
    CleanupObjectMismatch {
        object: CanaryCleanupObjectRole,
    },
    CleanupObjectRetirementTimingInvalid {
        object: CanaryCleanupObjectRole,
    },
    CleanupClientRetirementTimingInvalid,
    CleanupClientQuiescedBeforeFlowCompletion,
    CleanupPeerServerRetirementTimingInvalid {
        slot: usize,
    },
    CleanupObjectRetiredBeforeClientReap {
        object: CanaryCleanupObjectRole,
    },
    CleanupObjectAbsenceObservedBeforeClientReap {
        object: CanaryCleanupObjectRole,
    },
    CleanupCountersRetiredBeforeFinalObservation,
    CleanupListenerDeliveryReportRetiredBeforeFinalDelivery,
    CleanupListenerDeliveryReportNeverCreatedObservedBeforeFinalDelivery,
    CleanupListenerDeliveryReportDispositionMismatch,
    CleanupPeerServerQuiescedBeforeObjectAbsence {
        slot: usize,
    },
    CleanupProcessIdentityCollision,
    CleanupFacilityChanged,
    CleanupFacilityObservedBeforeSettlement,
    CleanupTimingAfterGateCompletion,
    CleanupTimingAtOrAfterDeadline,
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
    let mut listener_sockets: [Option<(CanaryFlow, &CanaryTproxyListenerSocketIdentity)>; 4] =
        [None; 4];
    let mut delivery_sequences: [Option<(CanaryFlow, NonZeroU64)>; FUNCTIONAL_CANARY_FLOW_SLOTS] =
        [None; FUNCTIONAL_CANARY_FLOW_SLOTS];
    let mut delivery_loss_baseline: Option<(CanaryFlow, u64)> = None;
    let mut listener_observation_loss_baseline: Option<(
        CanaryFlow,
        CanaryListenerObservationLoss,
    )> = None;
    let mut delivery_authority: Option<(CanaryFlow, CanaryInboundDeliveryAuthority)> = None;
    let mut accepted_socket_identities: [Option<(
        CanaryFlow,
        CanaryProcFd,
        NonZeroU64,
        CanaryInetDiagCookie,
    )>; FUNCTIONAL_CANARY_FLOW_SLOTS] = [None; FUNCTIONAL_CANARY_FLOW_SLOTS];
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
        let validated_delivery =
            validate_inbound_listener_delivery(request, expected_flow, observed)?;
        let listener_slot = expected_flow.inbound_listener_slot();
        if let Some((first_flow, first_listener)) = listener_sockets[listener_slot] {
            if !first_listener.same_socket_as(validated_delivery.listener) {
                return Err(CanaryEvidenceError::InboundListenerSocketIdentityChanged {
                    first: first_flow,
                    second: expected_flow,
                });
            }
        } else {
            for (first_flow, first_listener) in listener_sockets.iter().flatten().copied() {
                if first_listener.physical_identity_collides_with(validated_delivery.listener) {
                    return Err(CanaryEvidenceError::InboundListenerSocketIdentityReused {
                        first: first_flow,
                        second: expected_flow,
                    });
                }
            }
            for (accepted_flow, accepted_fd, accepted_inode, accepted_cookie) in
                accepted_socket_identities.iter().flatten().copied()
            {
                if validated_delivery
                    .listener
                    .physical_identity_collides_with_socket(
                        accepted_fd,
                        accepted_inode,
                        accepted_cookie,
                    )
                {
                    return Err(
                        CanaryEvidenceError::InboundListenerAcceptedSocketConflictsWithListener {
                            listener: expected_flow,
                            accepted: accepted_flow,
                        },
                    );
                }
            }
            listener_sockets[listener_slot] = Some((expected_flow, validated_delivery.listener));
        }
        let listener_loss_baseline = validated_delivery.listener.observation.loss;
        if let Some((first_flow, first_loss_baseline)) = listener_observation_loss_baseline {
            if first_loss_baseline != listener_loss_baseline {
                return Err(
                    CanaryEvidenceError::InboundListenerObservationLossBaselineChanged {
                        first: first_flow,
                        second: expected_flow,
                    },
                );
            }
        } else {
            listener_observation_loss_baseline = Some((expected_flow, listener_loss_baseline));
        }
        for (first_flow, first_sequence) in delivery_sequences.iter().flatten().copied() {
            if first_sequence == validated_delivery.event.sequence {
                return Err(CanaryEvidenceError::InboundListenerEventSequenceReused {
                    first: first_flow,
                    second: expected_flow,
                });
            }
        }
        delivery_sequences[expected_flow.index()] =
            Some((expected_flow, validated_delivery.event.sequence));
        if let Some((first_flow, first_authority)) = delivery_authority {
            if first_authority != validated_delivery.event.authority {
                return Err(
                    CanaryEvidenceError::InboundListenerDeliveryAuthorityChanged {
                        first: first_flow,
                        second: expected_flow,
                    },
                );
            }
        } else {
            delivery_authority = Some((expected_flow, validated_delivery.event.authority));
        }
        if let Some((first_flow, first_loss_baseline)) = delivery_loss_baseline {
            if first_loss_baseline != validated_delivery.event.lost_events_before {
                return Err(
                    CanaryEvidenceError::InboundListenerEventLossBaselineChanged {
                        first: first_flow,
                        second: expected_flow,
                    },
                );
            }
        } else {
            delivery_loss_baseline =
                Some((expected_flow, validated_delivery.event.lost_events_before));
        }
        if let Some((accepted_fd, accepted_inode, accepted_cookie)) =
            validated_delivery.accepted_socket
        {
            for (listener_flow, listener) in listener_sockets.iter().flatten().copied() {
                if listener.physical_identity_collides_with_socket(
                    accepted_fd,
                    accepted_inode,
                    accepted_cookie,
                ) {
                    return Err(
                        CanaryEvidenceError::InboundListenerAcceptedSocketConflictsWithListener {
                            listener: listener_flow,
                            accepted: expected_flow,
                        },
                    );
                }
            }
            for (first_flow, _, first_inode, first_cookie) in
                accepted_socket_identities.iter().flatten().copied()
            {
                if first_inode == accepted_inode || first_cookie == accepted_cookie {
                    return Err(
                        CanaryEvidenceError::InboundListenerAcceptedSocketIdentityReused {
                            first: first_flow,
                            second: expected_flow,
                        },
                    );
                }
            }
            accepted_socket_identities[expected_flow.index()] =
                Some((expected_flow, accepted_fd, accepted_inode, accepted_cookie));
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

struct ValidatedInboundListenerDelivery<'a> {
    listener: &'a CanaryTproxyListenerSocketIdentity,
    event: CanaryInboundDeliveryEvent,
    accepted_socket: Option<(CanaryProcFd, NonZeroU64, CanaryInetDiagCookie)>,
}

fn validate_inbound_listener_delivery<'a>(
    request: &CanaryAttemptRequest,
    flow: CanaryFlow,
    flow_evidence: &'a UnqualifiedCanaryFlowEvidence,
) -> Result<ValidatedInboundListenerDelivery<'a>, CanaryEvidenceError> {
    let delivery = flow_evidence
        .inbound_listener_delivery
        .as_ref()
        .ok_or(CanaryEvidenceError::MissingInboundListenerDelivery { flow })?;
    let expected_backend = request.capture_backend();
    let observed_backend = delivery.capture_backend();
    if observed_backend != expected_backend {
        return Err(CanaryEvidenceError::InboundListenerBackendMismatch {
            flow,
            expected: expected_backend,
            observed: observed_backend,
        });
    }
    if expected_backend != CanaryCaptureBackend::Tproxy {
        return Err(CanaryEvidenceError::InboundListenerBackendUnsupported {
            flow,
            backend: expected_backend,
        });
    }
    let (listener, event, payload, accepted_socket) = match (flow.protocol(), delivery) {
        (
            CanaryFlowProtocol::Tcp,
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyTcp { listener, accepted },
        ) => {
            if accepted.flow != flow {
                return Err(CanaryEvidenceError::InboundListenerFlowMismatch {
                    expected: flow,
                    observed: accepted.flow,
                });
            }
            if accepted.engine != request.pre_binding.engine.engine() {
                return Err(CanaryEvidenceError::InboundListenerAcceptedEngineMismatch { flow });
            }
            if accepted.listener_cookie != listener.listener_cookie {
                return Err(CanaryEvidenceError::InboundListenerSocketLinkMismatch { flow });
            }
            if accepted.accepted_fd == listener.listener_fd
                || accepted.accepted_inode == listener.listener_inode
                || accepted.accepted_cookie == listener.listener_cookie
            {
                return Err(
                    CanaryEvidenceError::InboundListenerAcceptedSocketIdentityCollision { flow },
                );
            }
            if accepted.peer != flow_evidence.client_tuple.source() {
                return Err(CanaryEvidenceError::InboundListenerClientSourceMismatch { flow });
            }
            if accepted.local != flow_evidence.client_tuple.destination() {
                return Err(
                    CanaryEvidenceError::InboundListenerOriginalDestinationMismatch { flow },
                );
            }
            (
                listener,
                accepted.event,
                accepted.payload,
                Some((
                    accepted.accepted_fd,
                    accepted.accepted_inode,
                    accepted.accepted_cookie,
                )),
            )
        }
        (
            CanaryFlowProtocol::Udp,
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyUdp { listener, datagram },
        ) => {
            if datagram.flow != flow {
                return Err(CanaryEvidenceError::InboundListenerFlowMismatch {
                    expected: flow,
                    observed: datagram.flow,
                });
            }
            if datagram.listener_cookie != listener.listener_cookie {
                return Err(CanaryEvidenceError::InboundListenerSocketLinkMismatch { flow });
            }
            if datagram.client_source != flow_evidence.client_tuple.source() {
                return Err(CanaryEvidenceError::InboundListenerClientSourceMismatch { flow });
            }
            if datagram.original_destination != flow_evidence.client_tuple.destination() {
                return Err(
                    CanaryEvidenceError::InboundListenerOriginalDestinationMismatch { flow },
                );
            }
            if datagram.payload_truncated || datagram.control_truncated {
                return Err(CanaryEvidenceError::InboundListenerUdpMessageTruncated { flow });
            }
            let cmsg_matches = matches!(
                (flow.address_family(), &datagram.original_destination_cmsg),
                (
                    CanaryFlowAddressFamily::Ipv4,
                    CanaryOriginalDestinationCmsg::Ipv4 { payload_length: 16 }
                ) | (
                    CanaryFlowAddressFamily::Ipv6,
                    CanaryOriginalDestinationCmsg::Ipv6 { payload_length: 28 }
                )
            );
            if datagram.original_destination_cmsg_count != 1 || !cmsg_matches {
                return Err(
                    CanaryEvidenceError::InboundListenerUdpOriginalDestinationInvalid { flow },
                );
            }
            (listener, datagram.event, datagram.payload, None)
        }
        _ => {
            return Err(CanaryEvidenceError::InboundListenerTransportEvidenceMismatch { flow });
        }
    };
    validate_tproxy_listener_socket(request, flow, flow_evidence, listener, event)?;
    let expected_payload = expected_inbound_payload_identity(request, flow);
    if payload != expected_payload {
        return Err(CanaryEvidenceError::InboundListenerPayloadMismatch { flow });
    }
    Ok(ValidatedInboundListenerDelivery {
        listener,
        event,
        accepted_socket,
    })
}

fn validate_tproxy_listener_socket(
    request: &CanaryAttemptRequest,
    flow: CanaryFlow,
    flow_evidence: &UnqualifiedCanaryFlowEvidence,
    listener: &CanaryTproxyListenerSocketIdentity,
    delivery_event: CanaryInboundDeliveryEvent,
) -> Result<(), CanaryEvidenceError> {
    let engine = &request.pre_binding.engine;
    if listener.generation != engine.generation() {
        return Err(CanaryEvidenceError::InboundListenerGenerationMismatch { flow });
    }
    if listener.engine != engine.engine() {
        return Err(CanaryEvidenceError::InboundListenerEngineMismatch { flow });
    }
    if &listener.listener != engine.listener() {
        return Err(CanaryEvidenceError::InboundListenerIdentityMismatch { flow });
    }
    let authority = &request.pre_binding.environment.authority;
    let expected_observer = authority.socket_observer;
    if listener.observation.authority != expected_observer {
        return Err(CanaryEvidenceError::InboundListenerObserverMismatch { flow });
    }
    let delivery_authority_valid = match delivery_event.authority {
        CanaryInboundDeliveryAuthority::SupervisedEngineReport {
            engine: observed_engine,
            engine_profile_revision,
            report_object,
            schema_version,
        } => {
            observed_engine == engine.engine()
                && engine_profile_revision == engine.engine_profile_revision()
                && report_object
                    == request
                        .pre_binding
                        .environment
                        .attempt_objects
                        .listener_delivery_report
                && schema_version.get() == ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION
        }
        CanaryInboundDeliveryAuthority::QualifiedCgroupBpf { observer } => {
            observer == expected_observer
                && matches!(
                    observer,
                    CanarySocketObserverAuthority::QualifiedCgroupBpf { .. }
                )
        }
    };
    if !delivery_authority_valid {
        return Err(CanaryEvidenceError::InboundListenerDeliveryAuthorityMismatch { flow });
    }
    if listener.daemon_network_namespace != authority.network.daemon_network_namespace {
        return Err(CanaryEvidenceError::InboundListenerNetworkNamespaceMismatch { flow });
    }
    if listener.capture_program_digest != authority.capture_program_digest {
        return Err(CanaryEvidenceError::InboundListenerCaptureProgramMismatch { flow });
    }
    if listener.selector != request.pre_binding.environment.attempt_objects.selector {
        return Err(CanaryEvidenceError::InboundListenerSelectorMismatch { flow });
    }
    if listener.protocol != flow.protocol() {
        return Err(CanaryEvidenceError::InboundListenerProtocolMismatch { flow });
    }
    if listener.address_family != flow.address_family() {
        return Err(CanaryEvidenceError::InboundListenerAddressFamilyMismatch { flow });
    }
    if listener.bind.port() != engine.listener().port().get()
        || !listener.bind.ip().is_unspecified()
        || listener.bind.is_ipv4() != flow.is_ipv4()
    {
        return Err(CanaryEvidenceError::InboundListenerBindMismatch { flow });
    }
    if !listener.transparent {
        return Err(CanaryEvidenceError::InboundListenerTransparentSocketRequired { flow });
    }
    match (listener.address_family, listener.ipv6_only) {
        (CanaryFlowAddressFamily::Ipv4, None) | (CanaryFlowAddressFamily::Ipv6, Some(true)) => {}
        _ => return Err(CanaryEvidenceError::InboundListenerIpv6OnlyStateInvalid { flow }),
    }
    match (expected_observer, listener.observation.loss) {
        (
            CanarySocketObserverAuthority::ProcFdInetDiag { .. },
            CanaryListenerObservationLoss::CompleteInetDiagSnapshot(snapshot),
        ) => {
            if snapshot.observer != authority.socket_observer_binding()
                || snapshot.process != engine.engine()
                || snapshot.listener_port != engine.listener().port()
                || snapshot.started_at < request.deadline().started_at()
                || snapshot.completed_at != listener.observation.observed_at
                || snapshot.completed_at < snapshot.started_at
                || snapshot.completed_at >= request.deadline().expires_at()
                || !snapshot.has_exact_sequence_map()
                || snapshot.role_sequence(flow) != listener.observation.sequence
            {
                return Err(CanaryEvidenceError::InboundListenerSnapshotAuthorityMismatch { flow });
            }
        }
        (
            CanarySocketObserverAuthority::QualifiedCgroupBpf { .. },
            CanaryListenerObservationLoss::Counter { before, after },
        ) => {
            if before != after {
                return Err(CanaryEvidenceError::InboundListenerObservationLoss { flow });
            }
        }
        _ => {
            return Err(CanaryEvidenceError::InboundListenerObservationAuthorityMismatch { flow });
        }
    }
    if delivery_event.lost_events_before != delivery_event.lost_events_after {
        return Err(CanaryEvidenceError::InboundListenerEventLoss { flow });
    }
    if listener.observation.observed_at < request.deadline().started_at()
        || listener.observation.observed_at > delivery_event.observed_at
    {
        return Err(CanaryEvidenceError::InboundListenerSocketObservationTimingInvalid { flow });
    }
    if delivery_event.observed_at < flow_evidence.started_at
        || delivery_event.observed_at > flow_evidence.completed_at
    {
        return Err(CanaryEvidenceError::InboundListenerTimingInvalid { flow });
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
        let expected_destination = SocketAddr::new(
            request.peer_address(expected_flow),
            request.responder_port(expected_flow).get(),
        );
        if negative.destination != expected_destination {
            return Err(CanaryEvidenceError::NegativeControlDestinationMismatch);
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
        if let Some(count) = negative.injected_peer_observation_count
            && count != 0
        {
            return Err(CanaryEvidenceError::NegativeControlReachedPeer { count });
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
    flows: &UnqualifiedCanaryFlowEvidenceSlots,
    counters: UnqualifiedCanaryCounterEvidence,
    attempt_completed_at: Instant,
    cleanup: &UnqualifiedCanaryCleanupEvidence,
) -> Result<(), CanaryEvidenceError> {
    let environment = &request.pre_binding.environment;
    if cleanup.nonce != request.nonce() {
        return Err(CanaryEvidenceError::CleanupNonceMismatch);
    }

    let deadline = request.deadline();
    let client = cleanup.client;
    if !retirement_timing_is_ordered(client) {
        return Err(CanaryEvidenceError::CleanupClientRetirementTimingInvalid);
    }
    validate_cleanup_timestamp(client.quiesced_at, attempt_completed_at, deadline)?;
    validate_cleanup_timestamp(client.terminated_at, attempt_completed_at, deadline)?;
    validate_cleanup_timestamp(client.reaped_at, attempt_completed_at, deadline)?;

    let mut last_flow_completed_at = deadline.started_at();
    let mut last_delivery_observed_at = deadline.started_at();
    let mut delivery_authority = None;
    for flow in flows.slots.iter().flatten() {
        last_flow_completed_at = std::cmp::max(last_flow_completed_at, flow.completed_at);
        let delivery = flow
            .inbound_listener_delivery
            .as_ref()
            .and_then(UnqualifiedCanaryInboundListenerDeliveryEvidence::delivery_event)
            .ok_or(CanaryEvidenceError::MissingInboundListenerDelivery { flow: flow.flow })?;
        last_delivery_observed_at = std::cmp::max(last_delivery_observed_at, delivery.observed_at);
        delivery_authority.get_or_insert(delivery.authority);
    }
    if client.quiesced_at < last_flow_completed_at {
        return Err(CanaryEvidenceError::CleanupClientQuiescedBeforeFlowCompletion);
    }

    let engine = request.pre_binding.engine.engine();
    let matches_engine = |process: CanaryProcessIdentity| {
        process.pid.get() == engine.pid()
            && process.start_time_ticks.get() == engine.start_time_ticks()
    };
    if matches_engine(client.process) {
        return Err(CanaryEvidenceError::CleanupProcessIdentityCollision);
    }
    if cleanup
        .peer_servers
        .iter()
        .any(|peer| peer.process == client.process || matches_engine(peer.process))
    {
        return Err(CanaryEvidenceError::CleanupProcessIdentityCollision);
    }
    for first in 0..CANARY_PEER_SERVER_SLOTS {
        let peer = cleanup.peer_servers[first];
        if !retirement_timing_is_ordered(peer) {
            return Err(
                CanaryEvidenceError::CleanupPeerServerRetirementTimingInvalid { slot: first },
            );
        }
        validate_cleanup_timestamp(peer.quiesced_at, attempt_completed_at, deadline)?;
        validate_cleanup_timestamp(peer.terminated_at, attempt_completed_at, deadline)?;
        validate_cleanup_timestamp(peer.reaped_at, attempt_completed_at, deadline)?;
        for second in first + 1..CANARY_PEER_SERVER_SLOTS {
            if peer.process == cleanup.peer_servers[second].process {
                return Err(CanaryEvidenceError::CleanupProcessIdentityCollision);
            }
        }
    }

    let expected_objects = environment.attempt_objects;
    let object_retirements = [(
        CanaryCleanupObjectRole::Counters,
        cleanup.counters_retirement,
        expected_objects.counters(),
    )];
    let mut last_object_absence_observed_at = client.reaped_at;
    for (object, retirement, expected_identity) in object_retirements {
        if retirement.object != expected_identity {
            return Err(CanaryEvidenceError::CleanupObjectMismatch { object });
        }
        if retirement.retired_at > retirement.absent_observed_at {
            return Err(CanaryEvidenceError::CleanupObjectRetirementTimingInvalid { object });
        }
        validate_cleanup_timestamp(retirement.retired_at, attempt_completed_at, deadline)?;
        validate_cleanup_timestamp(
            retirement.absent_observed_at,
            attempt_completed_at,
            deadline,
        )?;
        match object {
            CanaryCleanupObjectRole::Counters
                if retirement.retired_at < counters.after_observed_at =>
            {
                return Err(CanaryEvidenceError::CleanupCountersRetiredBeforeFinalObservation);
            }
            _ => {}
        }
        if retirement.retired_at < client.reaped_at {
            return Err(CanaryEvidenceError::CleanupObjectRetiredBeforeClientReap { object });
        }
        last_object_absence_observed_at = std::cmp::max(
            last_object_absence_observed_at,
            retirement.absent_observed_at,
        );
    }

    let delivery_authority =
        delivery_authority.ok_or(CanaryEvidenceError::MissingInboundListenerDelivery {
            flow: CanaryFlow::Ipv4TcpEcho,
        })?;
    match (
        delivery_authority,
        cleanup.listener_delivery_report.disposition(),
    ) {
        (
            CanaryInboundDeliveryAuthority::SupervisedEngineReport { .. },
            CanaryListenerDeliveryReportCleanupDisposition::Retired(retirement),
        ) => {
            let object = CanaryCleanupObjectRole::ListenerDeliveryReport;
            if retirement.object != expected_objects.listener_delivery_report() {
                return Err(CanaryEvidenceError::CleanupObjectMismatch { object });
            }
            if retirement.retired_at > retirement.absent_observed_at {
                return Err(CanaryEvidenceError::CleanupObjectRetirementTimingInvalid { object });
            }
            validate_cleanup_timestamp(retirement.retired_at, attempt_completed_at, deadline)?;
            validate_cleanup_timestamp(
                retirement.absent_observed_at,
                attempt_completed_at,
                deadline,
            )?;
            if retirement.retired_at < last_delivery_observed_at {
                return Err(
                    CanaryEvidenceError::CleanupListenerDeliveryReportRetiredBeforeFinalDelivery,
                );
            }
            if retirement.retired_at < client.reaped_at {
                return Err(CanaryEvidenceError::CleanupObjectRetiredBeforeClientReap { object });
            }
            last_object_absence_observed_at = std::cmp::max(
                last_object_absence_observed_at,
                retirement.absent_observed_at,
            );
        }
        (
            CanaryInboundDeliveryAuthority::QualifiedCgroupBpf { .. },
            CanaryListenerDeliveryReportCleanupDisposition::VerifiedNeverCreated {
                object,
                absent_observed_at,
            },
        ) => {
            let role = CanaryCleanupObjectRole::ListenerDeliveryReport;
            if object != expected_objects.listener_delivery_report() {
                return Err(CanaryEvidenceError::CleanupObjectMismatch { object: role });
            }
            validate_cleanup_timestamp(absent_observed_at, attempt_completed_at, deadline)?;
            if absent_observed_at < last_delivery_observed_at {
                return Err(
                    CanaryEvidenceError::CleanupListenerDeliveryReportNeverCreatedObservedBeforeFinalDelivery,
                );
            }
            if absent_observed_at < client.reaped_at {
                return Err(
                    CanaryEvidenceError::CleanupObjectAbsenceObservedBeforeClientReap {
                        object: role,
                    },
                );
            }
            last_object_absence_observed_at =
                std::cmp::max(last_object_absence_observed_at, absent_observed_at);
        }
        _ => return Err(CanaryEvidenceError::CleanupListenerDeliveryReportDispositionMismatch),
    }

    let mut cleanup_settled_at = last_object_absence_observed_at;
    for (slot, peer) in cleanup.peer_servers.iter().copied().enumerate() {
        if peer.quiesced_at < last_object_absence_observed_at {
            return Err(CanaryEvidenceError::CleanupPeerServerQuiescedBeforeObjectAbsence { slot });
        }
        cleanup_settled_at = std::cmp::max(cleanup_settled_at, peer.reaped_at);
    }

    if cleanup.retained_facility != environment.facility {
        return Err(CanaryEvidenceError::CleanupFacilityChanged);
    }
    validate_cleanup_timestamp(
        cleanup.retained_facility_observed_at,
        attempt_completed_at,
        deadline,
    )?;
    if cleanup.retained_facility_observed_at < cleanup_settled_at {
        return Err(CanaryEvidenceError::CleanupFacilityObservedBeforeSettlement);
    }

    let selector_retirement = cleanup
        .selector_retirement
        .ok_or(CanaryEvidenceError::CleanupSelectorRetirementMissing)?;
    let object = CanaryCleanupObjectRole::Selector;
    if selector_retirement.object != expected_objects.selector() {
        return Err(CanaryEvidenceError::CleanupObjectMismatch { object });
    }
    if selector_retirement.retired_at > selector_retirement.absent_observed_at {
        return Err(CanaryEvidenceError::CleanupObjectRetirementTimingInvalid { object });
    }
    validate_cleanup_timestamp(
        selector_retirement.retired_at,
        attempt_completed_at,
        deadline,
    )?;
    validate_cleanup_timestamp(
        selector_retirement.absent_observed_at,
        attempt_completed_at,
        deadline,
    )?;
    if selector_retirement.retired_at < client.reaped_at {
        return Err(CanaryEvidenceError::CleanupObjectRetiredBeforeClientReap { object });
    }
    if selector_retirement.retired_at < cleanup.retained_facility_observed_at {
        return Err(CanaryEvidenceError::CleanupSelectorRetiredBeforeAttemptSettlement);
    }
    Ok(())
}

fn retirement_timing_is_ordered(evidence: CanaryProcessRetirementEvidence) -> bool {
    evidence.quiesced_at <= evidence.terminated_at && evidence.terminated_at <= evidence.reaped_at
}

fn validate_cleanup_timestamp(
    observed_at: Instant,
    attempt_completed_at: Instant,
    deadline: CanaryDeadline,
) -> Result<(), CanaryEvidenceError> {
    if observed_at >= deadline.expires_at() {
        return Err(CanaryEvidenceError::CleanupTimingAtOrAfterDeadline);
    }
    if observed_at > attempt_completed_at {
        return Err(CanaryEvidenceError::CleanupTimingAfterGateCompletion);
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

type SupervisedReportInstaller<'a> = Box<
    dyn FnOnce(
            SupervisedDeliveryReportEngineHandoff,
        ) -> Result<InstalledSupervisedDeliveryReportProducer, FunctionalCanaryError>
        + 'a,
>;

pub(crate) struct UnqualifiedFunctionalCanaryExecution<'a> {
    request: &'a CanaryAttemptRequest,
    socket_observer: CanaryAttemptSocketObserverSession,
    supervised_report_prebind:
        Option<supervised_delivery_report::collector::SupervisedDeliveryReportPrebindAuthority>,
    supervised_report_prebound: bool,
    install_supervised_report: Option<SupervisedReportInstaller<'a>>,
    supervised_report_installed: bool,
    open_engine_child:
        Box<dyn FnOnce() -> Result<EngineChildAuthority, FunctionalCanaryError> + 'a>,
}

impl<'a> UnqualifiedFunctionalCanaryExecution<'a> {
    pub(crate) fn new(
        request: &'a CanaryAttemptRequest,
        socket_observer: CanaryAttemptSocketObserverSession,
        supervised_report: AdmittedSupervisedDeliveryReportBinding,
        install_supervised_report: SupervisedReportInstaller<'a>,
        open_engine_child: Box<
            dyn FnOnce() -> Result<EngineChildAuthority, FunctionalCanaryError> + 'a,
        >,
    ) -> Result<Self, FunctionalCanaryError> {
        if request
            .pre_binding()
            .environment()
            .authority()
            .socket_observer_binding()
            != socket_observer.binding()
        {
            return Err(FunctionalCanaryError::new(
                CanaryErrorKind::IdentityChanged,
                CanaryCleanupStatus::NotRequired,
                "attempt-owned socket observer does not match the immutable request authority",
            ));
        }
        if request.deadline() != socket_observer.deadline() {
            return Err(FunctionalCanaryError::new(
                CanaryErrorKind::IdentityChanged,
                CanaryCleanupStatus::NotRequired,
                "attempt-owned socket observer deadline does not match the immutable request deadline",
            ));
        }
        let supervised_report_prebind =
            supervised_delivery_report::collector::SupervisedDeliveryReportPrebindAuthority::admitted(
                supervised_report,
                request,
            )
            .map_err(supervised_delivery_report_bind_error)?;
        Ok(Self {
            request,
            socket_observer,
            supervised_report_prebind: Some(supervised_report_prebind),
            supervised_report_prebound: false,
            install_supervised_report: Some(install_supervised_report),
            supervised_report_installed: false,
            open_engine_child,
        })
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &'a CanaryAttemptRequest {
        self.request
    }

    #[must_use]
    pub(crate) const fn socket_observer_authority(&self) -> CanarySocketObserverAuthority {
        self.socket_observer.authority()
    }

    pub(crate) fn install_supervised_delivery_report(
        &mut self,
        handoff: SupervisedDeliveryReportEngineHandoff,
    ) -> Result<InstalledSupervisedDeliveryReportProducer, FunctionalCanaryError> {
        let installer = self.install_supervised_report.take().ok_or_else(|| {
            if self.supervised_report_installed {
                FunctionalCanaryError::new(
                    CanaryErrorKind::CleanupUncertain,
                    CanaryCleanupStatus::Uncertain,
                    "functional canary execution already installed its supervised-report producer",
                )
            } else {
                FunctionalCanaryError::new(
                    CanaryErrorKind::AdapterFailure,
                    CanaryCleanupStatus::NotRequired,
                    "functional canary execution has no unused supervised-report installer",
                )
            }
        })?;
        if handoff.request() != self.request {
            return Err(FunctionalCanaryError::new(
                CanaryErrorKind::IdentityChanged,
                CanaryCleanupStatus::NotRequired,
                "supervised-report handoff does not match the immutable canary request",
            ));
        }
        let installed = installer(handoff)?;
        let expected_engine = self.request.pre_binding().engine();
        let expected_report = self
            .request
            .pre_binding()
            .environment()
            .attempt_objects()
            .listener_delivery_report();
        if installed.child() != expected_engine.engine()
            || installed.report_object() != expected_report
            || installed.profile_revision() != expected_engine.engine_profile_revision()
        {
            return Err(FunctionalCanaryError::new(
                CanaryErrorKind::CleanupUncertain,
                CanaryCleanupStatus::Uncertain,
                "installed supervised-report producer does not match the immutable canary request",
            ));
        }
        self.supervised_report_installed = true;
        Ok(installed)
    }

    pub(in crate::functional_canary) fn prebind_supervised_delivery_report<C>(
        &mut self,
        clock: C,
    ) -> Result<
        (
            supervised_delivery_report::collector::SupervisedDeliveryReportProducer,
            supervised_delivery_report::collector::SupervisedDeliveryReportCollector<C>,
        ),
        FunctionalCanaryError,
    >
    where
        C: FnMut() -> Instant,
    {
        let authority = self.supervised_report_prebind.take().ok_or_else(|| {
            FunctionalCanaryError::new(
                if self.supervised_report_prebound {
                    CanaryErrorKind::CleanupUncertain
                } else {
                    CanaryErrorKind::AdapterFailure
                },
                if self.supervised_report_prebound {
                    CanaryCleanupStatus::Uncertain
                } else {
                    CanaryCleanupStatus::NotRequired
                },
                "functional canary execution has no unused supervised-report prebind authority",
            )
        })?;
        self.supervised_report_prebound = true;
        supervised_delivery_report::collector::prebind(authority, clock)
            .map_err(supervised_delivery_report_collector_error)
    }

    pub(crate) fn into_parts(
        self,
    ) -> Result<
        (
            &'a CanaryAttemptRequest,
            CanaryAttemptSocketObserverSession,
            EngineChildAuthority,
        ),
        FunctionalCanaryError,
    > {
        if self.supervised_report_prebound && !self.supervised_report_installed {
            return Err(FunctionalCanaryError::new(
                CanaryErrorKind::CleanupUncertain,
                CanaryCleanupStatus::Uncertain,
                "functional canary execution prebound a supervised report but did not install its producer",
            ));
        }
        let engine_child = (self.open_engine_child)()?;
        debug_assert_ne!(engine_child.opening_id().get(), 0);
        let expected_engine = self.request.pre_binding().engine();
        if expected_engine.engine() != engine_child.identity() {
            return Err(FunctionalCanaryError::new(
                CanaryErrorKind::IdentityChanged,
                CanaryCleanupStatus::NotRequired,
                "attempt-owned engine child authority does not match the immutable request identity",
            ));
        }
        if expected_engine.engine_snapshot_revision() != engine_child.engine_snapshot_revision() {
            return Err(FunctionalCanaryError::new(
                CanaryErrorKind::IdentityChanged,
                CanaryCleanupStatus::NotRequired,
                "attempt-owned engine child authority does not match the immutable engine snapshot revision",
            ));
        }
        let deadline = self.request.deadline();
        if engine_child.opened_at() < deadline.started_at()
            || engine_child.opened_at() >= deadline.expires_at()
        {
            return Err(FunctionalCanaryError::new(
                CanaryErrorKind::IdentityChanged,
                CanaryCleanupStatus::NotRequired,
                "attempt-owned engine child authority was not opened within the immutable request deadline",
            ));
        }
        Ok((self.request, self.socket_observer, engine_child))
    }

    /// Consume the attempt authorities only after the report handoff and selector identity agree.
    pub(crate) fn into_selector_ready_parts(
        self,
        attempt: &dyn CanaryAttemptObservationAuthority,
    ) -> Result<
        (
            &'a CanaryAttemptRequest,
            CanaryAttemptSocketObserverSession,
            EngineChildAuthority,
        ),
        FunctionalCanaryError,
    > {
        if attempt.request() != self.request {
            return Err(FunctionalCanaryError::new(
                CanaryErrorKind::IdentityChanged,
                CanaryCleanupStatus::Uncertain,
                "selector session does not match the immutable canary request",
            ));
        }
        if !self.supervised_report_prebound || !self.supervised_report_installed {
            return Err(FunctionalCanaryError::new(
                CanaryErrorKind::CleanupUncertain,
                CanaryCleanupStatus::Uncertain,
                "selector session cannot enter execution before supervised-report prebind and installation",
            ));
        }
        self.into_parts()
    }
}

fn supervised_delivery_report_bind_error(
    source: SupervisedDeliveryReportBindError,
) -> FunctionalCanaryError {
    let kind = match source {
        SupervisedDeliveryReportBindError::CapabilityUnavailable
        | SupervisedDeliveryReportBindError::NonCanonicalContract => {
            CanaryErrorKind::InvalidEvidence
        }
        SupervisedDeliveryReportBindError::ArtifactSetMismatch
        | SupervisedDeliveryReportBindError::ProfileRevisionMismatch => {
            CanaryErrorKind::IdentityChanged
        }
    };
    FunctionalCanaryError::new(kind, CanaryCleanupStatus::NotRequired, &source.to_string())
}

fn supervised_delivery_report_collector_error(
    source: supervised_delivery_report::collector::SupervisedDeliveryReportCollectorError,
) -> FunctionalCanaryError {
    use supervised_delivery_report::collector::SupervisedDeliveryReportCollectorError as Error;

    let (kind, cleanup) = match &source {
        Error::Bind(error) => return supervised_delivery_report_bind_error(*error),
        Error::Transport(flux_platform::PlatformError::UnsupportedPlatform(_)) => (
            CanaryErrorKind::Availability(CanaryAvailability::Unsupported),
            CanaryCleanupStatus::NotRequired,
        ),
        Error::Transport(flux_platform::PlatformError::SystemCall { source, .. })
            if source.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            (
                CanaryErrorKind::Availability(CanaryAvailability::Denied),
                CanaryCleanupStatus::NotRequired,
            )
        }
        Error::Transport(_) | Error::OpeningIdentityExhausted => (
            CanaryErrorKind::AdapterFailure,
            CanaryCleanupStatus::NotRequired,
        ),
        Error::DeadlineExpired => (CanaryErrorKind::TimedOut, CanaryCleanupStatus::Uncertain),
        Error::InvalidReport(_) => (
            CanaryErrorKind::InvalidEvidence,
            CanaryCleanupStatus::Uncertain,
        ),
        Error::ProducerCredentialsMismatch { .. } => (
            CanaryErrorKind::IdentityChanged,
            CanaryCleanupStatus::Uncertain,
        ),
        Error::ClientRetirementAuthorityMismatch
        | Error::InvalidClientRetirement
        | Error::InvalidReceiverRetirement => (
            CanaryErrorKind::CleanupUncertain,
            CanaryCleanupStatus::Uncertain,
        ),
    };
    FunctionalCanaryError::new(kind, cleanup, &source.to_string())
}

pub(crate) trait UnqualifiedFunctionalCanaryExecutor: Send + 'static {
    fn execute(
        &mut self,
        execution: UnqualifiedFunctionalCanaryExecution<'_>,
        attempt: &mut dyn CanaryAttemptObservationAuthority,
    ) -> Result<UnqualifiedCanaryGateEvidence, FunctionalCanaryError>;
}

fn bounded_prefix(diagnostic: &str) -> String {
    let mut end = diagnostic.len().min(MAX_FUNCTIONAL_CANARY_DIAGNOSTIC_BYTES);
    while !diagnostic.is_char_boundary(end) {
        end -= 1;
    }
    diagnostic[..end].to_owned()
}

pub(crate) mod local_output;
mod supervised_delivery_report;

pub(crate) fn try_run_internal_driver_child(args: &[String]) -> Option<i32> {
    local_output::try_run_internal_child(args)
}
use supervised_delivery_report::CanaryListenerDeliveryReportCleanupDisposition;
pub(crate) use supervised_delivery_report::{
    AdmittedSupervisedDeliveryReportBinding, CanaryListenerDeliveryReportCleanupEvidence,
    InstalledSupervisedDeliveryReportProducer, SupervisedDeliveryReportBindError,
    SupervisedDeliveryReportEngineHandoff, SupervisedDeliveryReportHandoffError,
};

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
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

    use flux_core::{
        InterfaceAddressRecord, InterfaceHardwareType, InterfaceLinkFlags, InterfaceLinkKind,
        InterfaceLinkRecord, NetworkInventoryTracker, OWNERSHIP_JOURNAL_IDENTITY_BYTES,
        OpaqueRuleAttribute, RuleAttributeOpacity, RuleOpaqueAttributeFingerprint,
    };
    use flux_platform::{SingBoxLaunchSpec, SingBoxPrivilege, SingBoxReadiness};

    use super::linux_tproxy_checkpoint_boundary::{
        LinuxTproxyCheckpointAction, LinuxTproxyCheckpointEvidence, LinuxTproxyCheckpointHook,
        LinuxTproxyCheckpointRulePlan,
    };
    use super::*;
    use crate::RestartPolicy;

    #[derive(Clone, Copy)]
    enum RetainedFacilityDrift {
        None,
        MissingDaemonLinkReference,
        UnknownDaemonLinkReference,
        WrongPeerLinkReference,
        NonVethPeer,
        TentativeDaemonAddress,
        ExtraDaemonGlobalIpv6,
        InvalidDaemonLinkLocal,
        WrongPeerIpv4Prefix,
        MissingDaemonRoute,
        DuplicateDaemonRoute,
        AlteredDaemonRoute,
        ResidualDaemonRoute,
        MissingPeerRule,
        DuplicatePeerRule,
        AlteredPeerRule,
        ResidualPeerRule,
        DisabledIpv6PeerRule,
        OpaquePeerRule,
    }

    #[test]
    fn facility_admission_observation_must_follow_start_and_precede_expiry() {
        let engine = EngineFixture::new();
        let started_at = Instant::now();
        let valid = request(&engine.spec, CanaryAddressFamilies::Ipv4Only, started_at);
        let rebuild = |observed_at| {
            let mut environment = valid.pre_binding.environment.clone();
            environment.facility_admission.observation.observed_at = observed_at;
            CanaryAttemptRequest::new(
                CanaryAttemptBinding::new(valid.pre_binding.engine.clone(), environment),
                valid.nonce,
                valid.deadline,
                valid.families,
                valid.counter_bounds,
            )
        };

        rebuild(started_at + Duration::from_millis(1))
            .expect("completed admission audit occurs inside the immutable deadline");
        assert_eq!(
            rebuild(started_at - Duration::from_nanos(1)),
            Err(CanaryBindingError::FacilityAdmissionExpired)
        );
        assert_eq!(
            rebuild(valid.deadline.expires_at()),
            Err(CanaryBindingError::FacilityAdmissionExpired)
        );
    }

    fn retained_peer_reaped_authority(
        request: &CanaryAttemptRequest,
    ) -> PeerReapedCanaryAttemptAuthority {
        let started_at = request.deadline().started_at();
        let retirement = |slot: u32, offset: u64| {
            CanaryProcessRetirementEvidence::new(
                CanaryProcessIdentity::new(
                    NonZeroU32::new(70_000 + slot).expect("peer PID"),
                    NonZeroU64::new(80_000 + u64::from(slot)).expect("peer start ticks"),
                ),
                started_at + Duration::from_millis(offset),
                started_at + Duration::from_millis(offset + 1),
                started_at + Duration::from_millis(offset + 2),
            )
        };
        PeerReapedCanaryAttemptAuthority::fixture(
            request,
            [retirement(1, 100), retirement(2, 110), retirement(3, 120)],
        )
    }

    fn retained_facility_fixture(families: CanaryAddressFamilies) -> Fixture {
        let engine = EngineFixture::new();
        Fixture::from_request(request(
            &engine.spec,
            families,
            Instant::now() - Duration::from_millis(500),
        ))
    }

    fn retained_facility_observation_fixture(
        request: &CanaryAttemptRequest,
        drift: RetainedFacilityDrift,
    ) -> RetainedCanaryFacilityObservation {
        let facility = request.pre_binding().environment().facility();
        let topology = facility.peer_veth_topology();
        let daemon_veth = facility.daemon_veth();
        let peer_veth = facility.peer_veth();
        let veth_kind = InterfaceLinkKind::new(b"veth").expect("veth kind");
        let daemon_link = InterfaceLinkRecord::new(
            daemon_veth.interface_index(),
            daemon_veth.interface_name(),
            InterfaceHardwareType::from_raw(1),
            InterfaceLinkFlags::from_bits(0),
        )
        .with_kind(veth_kind.clone());
        let daemon_link = match drift {
            RetainedFacilityDrift::MissingDaemonLinkReference => daemon_link,
            RetainedFacilityDrift::UnknownDaemonLinkReference => {
                daemon_link.with_link_reference(InterfaceLinkReference::UnknownMedia)
            }
            _ => daemon_link.with_link_reference(InterfaceLinkReference::Interface(
                peer_veth.interface_index(),
            )),
        };
        let peer_kind = if matches!(drift, RetainedFacilityDrift::NonVethPeer) {
            InterfaceLinkKind::new(b"bridge").expect("non-veth kind")
        } else {
            veth_kind
        };
        let peer_reference = if matches!(drift, RetainedFacilityDrift::WrongPeerLinkReference) {
            InterfaceLinkReference::Interface(peer_veth.interface_index())
        } else {
            InterfaceLinkReference::Interface(daemon_veth.interface_index())
        };
        let peer_link = InterfaceLinkRecord::new(
            peer_veth.interface_index(),
            peer_veth.interface_name(),
            InterfaceHardwareType::from_raw(1),
            InterfaceLinkFlags::from_bits(0),
        )
        .with_kind(peer_kind)
        .with_link_reference(peer_reference);

        let daemon_ipv4_flags = if matches!(drift, RetainedFacilityDrift::TentativeDaemonAddress) {
            InterfaceAddressFlags::PERMANENT | InterfaceAddressFlags::TENTATIVE
        } else {
            InterfaceAddressFlags::PERMANENT
        };
        let mut daemon_addresses = vec![
            InterfaceAddressRecord::new(
                daemon_veth.interface_index(),
                IpAddr::V4(facility.ipv4().daemon()),
                topology.ipv4().daemon_prefix_length(),
                daemon_ipv4_flags,
            )
            .expect("daemon IPv4 address"),
        ];
        let peer_ipv4_prefix = if matches!(drift, RetainedFacilityDrift::WrongPeerIpv4Prefix) {
            topology.ipv4().peer_prefix_length().saturating_sub(1)
        } else {
            topology.ipv4().peer_prefix_length()
        };
        let mut peer_addresses = vec![
            InterfaceAddressRecord::new(
                peer_veth.interface_index(),
                IpAddr::V4(facility.ipv4().peer()),
                peer_ipv4_prefix,
                InterfaceAddressFlags::PERMANENT,
            )
            .expect("peer IPv4 address"),
        ];
        let mut daemon_routes = Vec::new();
        let mut peer_routes = Vec::new();
        if !matches!(drift, RetainedFacilityDrift::MissingDaemonRoute) {
            daemon_routes.push(
                expected_host_route(
                    IpAddr::V4(facility.ipv4().peer()),
                    daemon_veth.interface_index(),
                    topology.ipv4().daemon_to_peer_route(),
                )
                .expect("daemon IPv4 route"),
            );
        }
        peer_routes.push(
            expected_host_route(
                IpAddr::V4(facility.ipv4().daemon()),
                peer_veth.interface_index(),
                topology.ipv4().peer_to_daemon_route(),
            )
            .expect("peer IPv4 route"),
        );
        if matches!(drift, RetainedFacilityDrift::ResidualDaemonRoute) {
            daemon_routes.push(
                expected_host_route(
                    IpAddr::V4(Ipv4Addr::new(11, 0, 0, 99)),
                    daemon_veth.interface_index(),
                    topology.ipv4().daemon_to_peer_route(),
                )
                .expect("residual daemon route"),
            );
        }
        if matches!(drift, RetainedFacilityDrift::DuplicateDaemonRoute) {
            daemon_routes.push(daemon_routes[0].clone());
        }
        if matches!(drift, RetainedFacilityDrift::AlteredDaemonRoute) {
            daemon_routes[0] = daemon_routes[0]
                .clone()
                .with_preferred_source(IpAddr::V4(facility.ipv4().daemon()))
                .expect("same-family preferred source");
        }
        if matches!(drift, RetainedFacilityDrift::ExtraDaemonGlobalIpv6) {
            daemon_addresses.push(
                InterfaceAddressRecord::new(
                    daemon_veth.interface_index(),
                    "2001:4860::99".parse().expect("extra global IPv6 address"),
                    64,
                    InterfaceAddressFlags::PERMANENT,
                )
                .expect("extra daemon global IPv6 address"),
            );
        }
        if let (Some(ipv6), Some(ipv6_topology)) = (facility.ipv6(), topology.ipv6()) {
            daemon_addresses.extend([
                InterfaceAddressRecord::new(
                    daemon_veth.interface_index(),
                    IpAddr::V6(ipv6.daemon()),
                    ipv6_topology.daemon_prefix_length(),
                    InterfaceAddressFlags::PERMANENT,
                )
                .expect("daemon IPv6 address"),
                InterfaceAddressRecord::new(
                    daemon_veth.interface_index(),
                    "fe80::1".parse().expect("daemon link-local address"),
                    if matches!(drift, RetainedFacilityDrift::InvalidDaemonLinkLocal) {
                        63
                    } else {
                        64
                    },
                    InterfaceAddressFlags::PERMANENT,
                )
                .expect("daemon IPv6 link-local address"),
            ]);
            peer_addresses.extend([
                InterfaceAddressRecord::new(
                    peer_veth.interface_index(),
                    IpAddr::V6(ipv6.peer()),
                    ipv6_topology.peer_prefix_length(),
                    InterfaceAddressFlags::PERMANENT,
                )
                .expect("peer IPv6 address"),
                InterfaceAddressRecord::new(
                    peer_veth.interface_index(),
                    "fe80::2".parse().expect("peer link-local address"),
                    64,
                    InterfaceAddressFlags::PERMANENT,
                )
                .expect("peer IPv6 link-local address"),
            ]);
            if !matches!(drift, RetainedFacilityDrift::MissingDaemonRoute) {
                daemon_routes.push(
                    expected_host_route(
                        IpAddr::V6(ipv6.peer()),
                        daemon_veth.interface_index(),
                        ipv6_topology.daemon_to_peer_route(),
                    )
                    .expect("daemon IPv6 route"),
                );
            }
            peer_routes.push(
                expected_host_route(
                    IpAddr::V6(ipv6.daemon()),
                    peer_veth.interface_index(),
                    ipv6_topology.peer_to_daemon_route(),
                )
                .expect("peer IPv6 route"),
            );
        }
        let mut daemon_rules = CanaryFlow::ALL
            .iter()
            .copied()
            .filter(|flow| request.requires_flow(*flow))
            .enumerate()
            .filter_map(|(index, flow)| {
                if matches!(drift, RetainedFacilityDrift::MissingPeerRule) && index == 0 {
                    None
                } else {
                    Some(expected_peer_selection_rule(request, flow).expect("canonical peer rule"))
                }
            })
            .collect::<Vec<_>>();
        if matches!(drift, RetainedFacilityDrift::ResidualPeerRule) {
            let port = request
                .responder_port(CanaryFlow::Ipv4TcpEcho)
                .get()
                .checked_add(1)
                .expect("admission rejects maximum responder ports");
            daemon_rules.push(
                expected_peer_selection_rule(request, CanaryFlow::Ipv4TcpEcho)
                    .expect("canonical IPv4 TCP rule")
                    .with_destination_port_range(
                        RulePortRange::new(port, port).expect("residual singleton port"),
                    ),
            );
        }
        if matches!(drift, RetainedFacilityDrift::DuplicatePeerRule) {
            daemon_rules.push(daemon_rules[0].clone());
        }
        if matches!(drift, RetainedFacilityDrift::AlteredPeerRule) {
            let port = request
                .responder_port(CanaryFlow::Ipv4TcpEcho)
                .get()
                .checked_add(1)
                .expect("admission rejects maximum responder ports");
            daemon_rules[0] = daemon_rules[0].clone().with_destination_port_range(
                RulePortRange::new(port, port).expect("altered singleton port"),
            );
        }
        if matches!(drift, RetainedFacilityDrift::DisabledIpv6PeerRule) {
            daemon_rules.push(
                expected_peer_selection_rule(request, CanaryFlow::Ipv6TcpEcho)
                    .expect("disabled-family rule still has a retained facility endpoint"),
            );
        }
        if matches!(drift, RetainedFacilityDrift::OpaquePeerRule) {
            let opacity = RuleAttributeOpacity::new(
                [OpaqueRuleAttribute::new(0x7fff, 0, 4)],
                0,
                RuleOpaqueAttributeFingerprint::from_bytes([0x55; 32]),
            )
            .expect("opaque rule evidence");
            daemon_rules[0] = daemon_rules[0].clone().with_attribute_opacity(opacity);
        }

        let mut daemon_tracker = NetworkInventoryTracker::new();
        let daemon_inventory = daemon_tracker
            .publish_complete_with_routing(
                [daemon_link],
                daemon_addresses,
                daemon_routes,
                daemon_rules,
            )
            .expect("daemon retained facility inventory")
            .clone();
        let mut peer_tracker = NetworkInventoryTracker::new();
        let peer_inventory = peer_tracker
            .publish_complete_with_routing(
                [peer_link],
                peer_addresses,
                peer_routes,
                std::iter::empty(),
            )
            .expect("peer retained facility inventory")
            .clone();
        let started_at = request.deadline().started_at();
        let network = request.pre_binding().environment().authority().network();
        let listener_started_at = started_at + Duration::from_millis(260);
        let listener_completed_at = started_at + Duration::from_millis(280);
        let listener_dumps = canonical_listener_conflict_targets(request)
            .into_iter()
            .enumerate()
            .map(|(index, target)| RetainedCanaryListenerDump {
                sequence: NonZeroU32::new(u32::try_from(index + 1).expect("bounded dump index"))
                    .expect("listener sequence is nonzero"),
                target,
                started_at: listener_started_at,
                completed_at: listener_completed_at,
            })
            .collect();
        RetainedCanaryFacilityObservation {
            daemon_namespace_before: network.daemon_network_namespace(),
            daemon_namespace_after: network.daemon_network_namespace(),
            peer_namespace: network.peer_network_namespace(),
            daemon_inventory: Arc::new(daemon_inventory),
            peer_inventory: Arc::new(peer_inventory),
            daemon_started_at: started_at + Duration::from_millis(200),
            daemon_completed_at: started_at + Duration::from_millis(220),
            peer_started_at: started_at + Duration::from_millis(230),
            peer_inventory_completed_at: started_at + Duration::from_millis(250),
            listener_started_at,
            listener_completed_at,
            listener_netlink_port_id: NonZeroU32::new(65_001).expect("netlink port ID"),
            listener_dumps,
            listener_conflict_count: 0,
        }
    }

    #[test]
    fn retained_facility_validator_accepts_exact_dual_stack_observation() {
        let fixture = retained_facility_fixture(CanaryAddressFamilies::Ipv4AndIpv6);
        let request = fixture.request().clone();
        let peer_reaped = retained_peer_reaped_authority(&request);
        let observation =
            retained_facility_observation_fixture(&request, RetainedFacilityDrift::None);

        let readback =
            validate_retained_canary_facility_observation(&request, &peer_reaped, &observation)
                .expect("exact retained facility remains valid");

        assert_eq!(
            readback.facility(),
            request.pre_binding().environment().facility()
        );
        assert!(readback.observed_at() >= observation.listener_completed_at);
        assert!(readback.observed_at() < request.deadline().expires_at());
    }

    #[test]
    fn retained_facility_validator_accepts_ipv4_and_checks_a_retained_dual_stack_facility() {
        let ipv4 = retained_facility_fixture(CanaryAddressFamilies::Ipv4Only);
        let ipv4_request = ipv4.request().clone();
        let ipv4_peer_reaped = retained_peer_reaped_authority(&ipv4_request);
        validate_retained_canary_facility_observation(
            &ipv4_request,
            &ipv4_peer_reaped,
            &retained_facility_observation_fixture(&ipv4_request, RetainedFacilityDrift::None),
        )
        .expect("exact IPv4 retained facility remains valid");

        let dual = retained_facility_fixture(CanaryAddressFamilies::Ipv4AndIpv6);
        let mut request = dual.request().clone();
        request.families = CanaryAddressFamilies::Ipv4Only;
        let peer_reaped = retained_peer_reaped_authority(&request);
        validate_retained_canary_facility_observation(
            &request,
            &peer_reaped,
            &retained_facility_observation_fixture(&request, RetainedFacilityDrift::None),
        )
        .expect("IPv4 attempt still validates every family retained by its facility");
        assert_eq!(
            validate_retained_canary_facility_observation(
                &request,
                &peer_reaped,
                &retained_facility_observation_fixture(
                    &request,
                    RetainedFacilityDrift::DisabledIpv6PeerRule,
                ),
            ),
            Err(RetainedCanaryFacilityValidationError::PeerRuleMismatch),
        );
    }

    #[test]
    fn retained_facility_validator_rejects_topology_address_route_and_rule_drift() {
        let fixture = retained_facility_fixture(CanaryAddressFamilies::Ipv4AndIpv6);
        let request = fixture.request().clone();
        let peer_reaped = retained_peer_reaped_authority(&request);
        for (drift, expected) in [
            (
                RetainedFacilityDrift::MissingDaemonLinkReference,
                RetainedCanaryFacilityValidationError::DaemonVethMismatch,
            ),
            (
                RetainedFacilityDrift::UnknownDaemonLinkReference,
                RetainedCanaryFacilityValidationError::DaemonVethMismatch,
            ),
            (
                RetainedFacilityDrift::WrongPeerLinkReference,
                RetainedCanaryFacilityValidationError::PeerVethMismatch,
            ),
            (
                RetainedFacilityDrift::NonVethPeer,
                RetainedCanaryFacilityValidationError::PeerVethMismatch,
            ),
            (
                RetainedFacilityDrift::TentativeDaemonAddress,
                RetainedCanaryFacilityValidationError::AddressMismatch,
            ),
            (
                RetainedFacilityDrift::ExtraDaemonGlobalIpv6,
                RetainedCanaryFacilityValidationError::AddressMismatch,
            ),
            (
                RetainedFacilityDrift::InvalidDaemonLinkLocal,
                RetainedCanaryFacilityValidationError::AddressMismatch,
            ),
            (
                RetainedFacilityDrift::WrongPeerIpv4Prefix,
                RetainedCanaryFacilityValidationError::AddressMismatch,
            ),
            (
                RetainedFacilityDrift::MissingDaemonRoute,
                RetainedCanaryFacilityValidationError::RouteMismatch,
            ),
            (
                RetainedFacilityDrift::DuplicateDaemonRoute,
                RetainedCanaryFacilityValidationError::RouteMismatch,
            ),
            (
                RetainedFacilityDrift::AlteredDaemonRoute,
                RetainedCanaryFacilityValidationError::RouteMismatch,
            ),
            (
                RetainedFacilityDrift::ResidualDaemonRoute,
                RetainedCanaryFacilityValidationError::RouteMismatch,
            ),
            (
                RetainedFacilityDrift::MissingPeerRule,
                RetainedCanaryFacilityValidationError::PeerRuleMismatch,
            ),
            (
                RetainedFacilityDrift::DuplicatePeerRule,
                RetainedCanaryFacilityValidationError::PeerRuleMismatch,
            ),
            (
                RetainedFacilityDrift::AlteredPeerRule,
                RetainedCanaryFacilityValidationError::PeerRuleMismatch,
            ),
            (
                RetainedFacilityDrift::ResidualPeerRule,
                RetainedCanaryFacilityValidationError::PeerRuleMismatch,
            ),
            (
                RetainedFacilityDrift::OpaquePeerRule,
                RetainedCanaryFacilityValidationError::PeerRuleMismatch,
            ),
        ] {
            let observation = retained_facility_observation_fixture(&request, drift);
            assert_eq!(
                validate_retained_canary_facility_observation(&request, &peer_reaped, &observation,),
                Err(expected),
            );
        }
    }

    #[test]
    fn retained_facility_validator_requires_strict_post_reap_complete_empty_listener_interval() {
        let fixture = retained_facility_fixture(CanaryAddressFamilies::Ipv4Only);
        let request = fixture.request().clone();
        let peer_reaped = retained_peer_reaped_authority(&request);
        let mut observation =
            retained_facility_observation_fixture(&request, RetainedFacilityDrift::None);
        observation.daemon_started_at = peer_reaped.latest_peer_reaped_at();
        assert_eq!(
            validate_retained_canary_facility_observation(&request, &peer_reaped, &observation),
            Err(RetainedCanaryFacilityValidationError::InvalidObservationChronology),
        );

        let mut observation =
            retained_facility_observation_fixture(&request, RetainedFacilityDrift::None);
        observation.listener_dumps[1].sequence = observation.listener_dumps[0].sequence;
        assert_eq!(
            validate_retained_canary_facility_observation(&request, &peer_reaped, &observation),
            Err(RetainedCanaryFacilityValidationError::IncompleteListenerObservation),
        );

        let mut observation =
            retained_facility_observation_fixture(&request, RetainedFacilityDrift::None);
        observation.listener_conflict_count = 1;
        assert_eq!(
            validate_retained_canary_facility_observation(&request, &peer_reaped, &observation),
            Err(RetainedCanaryFacilityValidationError::ListenerConflict),
        );

        let mut observation =
            retained_facility_observation_fixture(&request, RetainedFacilityDrift::None);
        let first = observation.listener_dumps[0].target;
        observation.listener_dumps[0].target = observation.listener_dumps[1].target;
        observation.listener_dumps[1].target = first;
        assert_eq!(
            validate_retained_canary_facility_observation(&request, &peer_reaped, &observation),
            Err(RetainedCanaryFacilityValidationError::ListenerTargetMismatch),
        );

        let mut observation =
            retained_facility_observation_fixture(&request, RetainedFacilityDrift::None);
        observation.listener_completed_at = request.deadline().expires_at();
        assert_eq!(
            validate_retained_canary_facility_observation(&request, &peer_reaped, &observation),
            Err(RetainedCanaryFacilityValidationError::InvalidObservationChronology),
        );
    }

    #[test]
    fn retained_facility_validator_rejects_namespace_request_and_retirement_substitution() {
        let fixture = retained_facility_fixture(CanaryAddressFamilies::Ipv4Only);
        let request = fixture.request().clone();
        let peer_reaped = retained_peer_reaped_authority(&request);
        let mut observation =
            retained_facility_observation_fixture(&request, RetainedFacilityDrift::None);
        observation.daemon_namespace_after = request
            .pre_binding()
            .environment()
            .authority()
            .network()
            .peer_network_namespace();
        assert_eq!(
            validate_retained_canary_facility_observation(&request, &peer_reaped, &observation),
            Err(RetainedCanaryFacilityValidationError::NetworkNamespaceMismatch),
        );

        let mut substituted_request = request.clone();
        substituted_request.nonce = CanaryNonce::from_bytes([0x99; FUNCTIONAL_CANARY_NONCE_BYTES]);
        let substituted = retained_peer_reaped_authority(&substituted_request);
        let observation =
            retained_facility_observation_fixture(&request, RetainedFacilityDrift::None);
        assert_eq!(
            validate_retained_canary_facility_observation(&request, &substituted, &observation),
            Err(RetainedCanaryFacilityValidationError::RequestMismatch),
        );

        let mut invalid_retirement = retained_peer_reaped_authority(&request);
        invalid_retirement.peer_servers[0].terminated_at =
            invalid_retirement.peer_servers[0].reaped_at + Duration::from_nanos(1);
        assert_eq!(
            validate_retained_canary_facility_observation(
                &request,
                &invalid_retirement,
                &observation,
            ),
            Err(RetainedCanaryFacilityValidationError::InvalidPeerRetirementChronology),
        );
    }

    #[test]
    fn retained_facility_bindings_reject_unrepresentable_rule_singletons() {
        let ports = CanaryResponderPorts::new(
            NonZeroU16::new(u16::MAX).expect("maximum port is nonzero"),
            NonZeroU16::new(41_002).expect("UDP responder port"),
            NonZeroU16::new(41_003).expect("DNS responder port"),
        );
        assert_eq!(ports, Err(CanaryBindingError::UnrepresentableResponderPort));
        let rpdb = CanaryRpdbIdentity::new(
            NonZeroU32::new(u32::MAX).expect("maximum UID is nonzero"),
            NonZeroU8::new(99).expect("rule protocol"),
            RouteTableId::from_raw(10_101),
            RouteTableId::from_raw(10_102),
            RulePriority::from_raw(12_100),
            RulePriority::from_raw(12_000),
            0x1200,
            NonZeroU32::new(0xff00).expect("proxy mask"),
        );
        assert_eq!(rpdb, Err(CanaryBindingError::UnrepresentableRpdbEngineUid));
    }

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
        assert_eq!(
            CanaryCredentialMapDigest::new([0; CANARY_CREDENTIAL_MAP_DIGEST_BYTES]),
            Err(CanaryBindingError::AllZeroCredentialMapDigest)
        );
        let namespace = CanaryFileIdentity::new(60, NonZeroU64::new(70).expect("namespace inode"));
        assert_eq!(
            CanaryCredentialDomainBinding::observed(
                namespace,
                namespace,
                CanaryCredentialMapDigest::new([1; CANARY_CREDENTIAL_MAP_DIGEST_BYTES])
                    .expect("UID map digest"),
                CanaryCredentialMapDigest::new([2; CANARY_CREDENTIAL_MAP_DIGEST_BYTES])
                    .expect("GID map digest"),
            ),
            Err(CanaryBindingError::CredentialNamespaceCollision)
        );
        let mount_namespace =
            CanaryFileIdentity::new(60, NonZeroU64::new(71).expect("mount namespace inode"));
        let unsupported_domain = CanaryCredentialDomainBinding::unsupported(mount_namespace);
        assert_eq!(
            unsupported_domain.user_namespace(),
            CanaryUserNamespaceBinding::Unsupported
        );
        assert_eq!(unsupported_domain.mount_namespace(), mount_namespace);
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let environment = &fixture.request.pre_binding.environment;
        let probe = environment.probe_credentials();
        let engine = environment.engine_credentials();
        assert_eq!(
            CanaryAttemptCredentialBinding::new(
                CanaryProcessCredentialIdentity::new(engine.uid(), probe.gid()),
                engine,
                environment.credential_domain(),
            ),
            Err(CanaryBindingError::ProbeUidMatchesEngineUid)
        );
        assert_eq!(
            CanaryAttemptCredentialBinding::new(
                CanaryProcessCredentialIdentity::new(probe.uid(), engine.gid()),
                engine,
                environment.credential_domain(),
            ),
            Err(CanaryBindingError::ProbeGidMatchesEngineGid)
        );
        let mut mismatched_credentials = environment.credentials;
        mismatched_credentials.engine.uid =
            NonZeroU32::new(65_500).expect("mismatched engine credential UID");
        assert_eq!(
            CanaryEnvironmentBinding::new(
                environment.authority.clone(),
                mismatched_credentials,
                environment.facility,
                environment.facility_admission,
                environment.rpdb,
                environment.attempt_objects,
            ),
            Err(CanaryBindingError::EngineCredentialUidMismatch)
        );
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
            fixture.request.pre_binding.environment.probe_uid().get(),
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
            fixture.request.pre_binding.engine.artifacts.binary(),
            fixture
                ._engine
                .as_ref()
                .expect("fixture owns its engine")
                .spec
                .binary_digest()
        );
        assert_eq!(
            fixture.request.pre_binding.engine.artifacts.config(),
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
    fn active_generation_binding_matches_only_exact_environment_authority() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let environment = fixture.request.pre_binding().environment();
        let binding = ActiveCanaryGenerationBinding::from_environment_fixture(environment);
        assert!(binding.matches_environment(environment));

        let mut generation = binding.clone();
        generation.generation = GenerationId::new(18).expect("alternate Generation");

        let mut boot = binding.clone();
        boot.boot_identity =
            BootIdentity::parse("00000000-0000-0000-0000-000000000002").expect("alternate boot");

        let mut profile = binding.clone();
        profile.capability_profile_revision =
            CapabilityProfileRevision::new(10).expect("alternate profile revision");

        let mut namespace = binding.clone();
        namespace.daemon_network_namespace =
            NetworkNamespaceIdentity::new(2, 101).expect("alternate daemon namespace");

        let mut epoch = binding.clone();
        epoch.network_epoch = NetworkEpoch::new(2).expect("alternate network epoch");

        let other_binding = active_generation_binding(binding.generation());
        let mut inventory = binding.clone();
        inventory.network_inventory_snapshot_id = other_binding.network_inventory_snapshot_id;

        let mut capture_program = binding.clone();
        capture_program.capture_program_digest =
            CaptureProgramDigest::new([13; CAPTURE_PROGRAM_DIGEST_BYTES])
                .expect("alternate capture program");

        let mut journal = binding.clone();
        journal.ownership.journal_identity =
            OwnershipJournalIdentity::new([14; OWNERSHIP_JOURNAL_IDENTITY_BYTES])
                .expect("alternate journal identity");

        let mut revision = binding.clone();
        revision.ownership.journal_revision =
            OwnershipJournalRevision::new(2).expect("alternate journal revision");

        let mut facility = binding.clone();
        facility.retained_facility.ipv4.peer = Ipv4Addr::new(11, 0, 0, 3);

        let mut capture_owner = binding;
        capture_owner.ownership.capture_owner.digest =
            CaptureOwnerRecordDigest::new([15; CAPTURE_OWNER_RECORD_DIGEST_BYTES])
                .expect("alternate capture owner record");

        for (name, substituted) in [
            ("Generation", generation),
            ("boot", boot),
            ("Capability Profile revision", profile),
            ("daemon network namespace", namespace),
            ("Network Epoch", epoch),
            ("Network Inventory snapshot", inventory),
            ("Capture Program", capture_program),
            ("ownership journal", journal),
            ("ownership journal revision", revision),
            ("retained canary facility", facility),
            ("capture owner record", capture_owner),
        ] {
            assert!(
                !substituted.matches_environment(environment),
                "{name} substitution must not match the attempt environment"
            );
        }
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
    fn selector_retirement_requires_the_writer_receipt_before_validation() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let mut evidence = fixture.successful_evidence_without_selector_retirement();
        assert_eq!(
            validate(&fixture, evidence)
                .expect_err("an executor cannot self-complete writer-owned selector cleanup"),
            CanaryEvidenceError::CleanupSelectorRetirementMissing
        );

        evidence = fixture.successful_evidence_without_selector_retirement();
        let executor_completed_at = evidence.completed_at;
        assert_eq!(
            evidence
                .bind_selector_retirement(CanaryAttemptObjectRetirementEvidence::new(
                    fixture
                        .request
                        .pre_binding()
                        .environment()
                        .attempt_objects()
                        .counters(),
                    executor_completed_at + Duration::from_nanos(1),
                    executor_completed_at + Duration::from_nanos(2),
                ))
                .expect_err("the writer receipt must carry the exact selector object"),
            CanaryEvidenceError::CleanupObjectMismatch {
                object: CanaryCleanupObjectRole::Selector,
            }
        );

        evidence = fixture.successful_evidence_without_selector_retirement();
        let executor_completed_at = evidence.completed_at;
        assert_eq!(
            evidence
                .bind_selector_retirement(CanaryAttemptObjectRetirementEvidence::new(
                    fixture
                        .request
                        .pre_binding()
                        .environment()
                        .attempt_objects()
                        .selector(),
                    executor_completed_at - Duration::from_nanos(1),
                    executor_completed_at,
                ))
                .expect_err("writer retirement cannot predate executor settlement"),
            CanaryEvidenceError::CleanupSelectorRetiredBeforeAttemptSettlement
        );

        evidence = fixture.successful_evidence_without_selector_retirement();
        let executor_completed_at = evidence.completed_at;
        let retired_at = executor_completed_at + Duration::from_nanos(1);
        let absent_observed_at = retired_at + Duration::from_nanos(1);
        evidence
            .bind_selector_retirement(CanaryAttemptObjectRetirementEvidence::new(
                fixture
                    .request
                    .pre_binding()
                    .environment()
                    .attempt_objects()
                    .selector(),
                retired_at,
                absent_observed_at,
            ))
            .expect("the exact writer receipt completes raw evidence");
        assert_eq!(evidence.completed_at, absent_observed_at);
        validate(&fixture, evidence).expect("writer-bound selector cleanup validates");
    }

    #[test]
    fn gate_rejects_a_local_output_capture_receipt_from_another_attempt() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let other = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let other_flows = flow_slots(&other.request);
        let mut evidence = fixture.successful_evidence();
        evidence.local_output_capture_receipt =
            local_output::TproxyLocalOutputCaptureReceipt::scripted(&other.request, &other_flows);

        assert_eq!(
            validate(&fixture, evidence)
                .expect_err("a capture receipt cannot be replayed across attempts"),
            CanaryEvidenceError::LocalOutputCaptureReceiptInvalid
        );
    }

    #[test]
    fn gate_rejects_a_process_ownership_receipt_from_another_attempt() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let other = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let mut evidence = fixture.successful_evidence();
        let other_evidence = other.successful_evidence();
        evidence.local_output_process_ownership_receipt =
            other_evidence.local_output_process_ownership_receipt;

        assert_eq!(
            validate(&fixture, evidence)
                .expect_err("a process receipt cannot be replayed across attempts"),
            CanaryEvidenceError::LocalOutputProcessOwnershipReceiptInvalid
        );
    }

    #[test]
    fn inbound_listener_delivery_is_required_and_backend_specific() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let flow = CanaryFlow::Ipv4TcpEcho;

        let mut missing = fixture.successful_evidence();
        missing.flows.slots[flow.index()]
            .as_mut()
            .expect("IPv4 TCP evidence")
            .inbound_listener_delivery = None;
        assert_eq!(
            validate(&fixture, missing).expect_err("listener delivery is mandatory"),
            CanaryEvidenceError::MissingInboundListenerDelivery { flow }
        );

        let mut redirected = fixture.successful_evidence();
        let flow_evidence = redirected.flows.slots[flow.index()]
            .as_mut()
            .expect("IPv4 TCP evidence");
        flow_evidence.inbound_listener_delivery =
            Some(UnqualifiedCanaryInboundListenerDeliveryEvidence::Redirect);
        assert_eq!(
            validate(&fixture, redirected).expect_err("REDIRECT delivery cannot qualify TPROXY"),
            CanaryEvidenceError::InboundListenerBackendMismatch {
                flow,
                expected: CanaryCaptureBackend::Tproxy,
                observed: CanaryCaptureBackend::Redirect,
            }
        );

        let mut dnat = fixture.successful_evidence();
        let flow_evidence = dnat.flows.slots[flow.index()]
            .as_mut()
            .expect("IPv4 TCP evidence");
        flow_evidence.inbound_listener_delivery =
            Some(UnqualifiedCanaryInboundListenerDeliveryEvidence::Dnat);
        assert_eq!(
            validate(&fixture, dnat).expect_err("DNAT delivery cannot qualify TPROXY"),
            CanaryEvidenceError::InboundListenerBackendMismatch {
                flow,
                expected: CanaryCaptureBackend::Tproxy,
                observed: CanaryCaptureBackend::Dnat,
            }
        );
    }

    #[test]
    fn tproxy_listener_delivery_binds_generation_engine_listener_and_flow_shape() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let flow = CanaryFlow::Ipv4TcpEcho;

        let mut generation = fixture.successful_evidence();
        tproxy_listener_mut(&mut generation, flow).generation =
            GenerationId::new(18).expect("different generation");
        assert_eq!(
            validate(&fixture, generation).expect_err("generation drift cannot pass"),
            CanaryEvidenceError::InboundListenerGenerationMismatch { flow }
        );

        let mut engine = fixture.successful_evidence();
        tproxy_listener_mut(&mut engine, flow).engine = OwnedEngineIdentity::new(
            NonZeroU32::new(4243).expect("different pid"),
            NonZeroU64::new(98_766).expect("different start ticks"),
        );
        assert_eq!(
            validate(&fixture, engine).expect_err("another process cannot satisfy delivery"),
            CanaryEvidenceError::InboundListenerEngineMismatch { flow }
        );

        let mut listener = fixture.successful_evidence();
        tproxy_listener_mut(&mut listener, flow).listener.port =
            NonZeroU16::new(1537).expect("different listener port");
        assert_eq!(
            validate(&fixture, listener).expect_err("another listener cannot satisfy delivery"),
            CanaryEvidenceError::InboundListenerIdentityMismatch { flow }
        );

        let mut wrong_flow = fixture.successful_evidence();
        tproxy_tcp_delivery_mut(&mut wrong_flow, flow).flow = CanaryFlow::Ipv4UdpEcho;
        assert_eq!(
            validate(&fixture, wrong_flow).expect_err("another flow cannot satisfy delivery"),
            CanaryEvidenceError::InboundListenerFlowMismatch {
                expected: flow,
                observed: CanaryFlow::Ipv4UdpEcho,
            }
        );

        let mut protocol = fixture.successful_evidence();
        tproxy_listener_mut(&mut protocol, flow).protocol = CanaryFlowProtocol::Udp;
        assert_eq!(
            validate(&fixture, protocol).expect_err("UDP cannot prove TCP listener delivery"),
            CanaryEvidenceError::InboundListenerProtocolMismatch { flow }
        );

        let mut family = fixture.successful_evidence();
        tproxy_listener_mut(&mut family, flow).address_family = CanaryFlowAddressFamily::Ipv6;
        assert_eq!(
            validate(&fixture, family).expect_err("IPv6 cannot prove IPv4 listener delivery"),
            CanaryEvidenceError::InboundListenerAddressFamilyMismatch { flow }
        );
    }

    #[test]
    fn tproxy_listener_delivery_binds_tuple_timing_and_attempt_payload() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let flow = CanaryFlow::Ipv4TcpEcho;

        let mut client_source = fixture.successful_evidence();
        let accepted = tproxy_tcp_delivery_mut(&mut client_source, flow);
        accepted.peer.set_port(accepted.peer.port() + 1);
        assert_eq!(
            validate(&fixture, client_source).expect_err("another client cannot satisfy delivery"),
            CanaryEvidenceError::InboundListenerClientSourceMismatch { flow }
        );

        let mut destination = fixture.successful_evidence();
        let accepted = tproxy_tcp_delivery_mut(&mut destination, flow);
        accepted.local.set_port(accepted.local.port() + 1);
        assert_eq!(
            validate(&fixture, destination)
                .expect_err("a rewritten destination cannot satisfy TPROXY delivery"),
            CanaryEvidenceError::InboundListenerOriginalDestinationMismatch { flow }
        );

        let mut timing = fixture.successful_evidence();
        let started_at = timing.flows.slots[flow.index()]
            .as_ref()
            .expect("IPv4 TCP evidence")
            .started_at;
        tproxy_delivery_event_mut(&mut timing, flow).observed_at =
            started_at - Duration::from_nanos(1);
        assert_eq!(
            validate(&fixture, timing).expect_err("out-of-flow delivery cannot pass"),
            CanaryEvidenceError::InboundListenerTimingInvalid { flow }
        );

        let mut echo_payload = fixture.successful_evidence();
        let CanaryInboundPayloadIdentity::Echo { nonce, .. } =
            tproxy_payload_mut(&mut echo_payload, flow)
        else {
            panic!("echo flow carries echo payload identity");
        };
        *nonce = CanaryNonce::from_bytes([8; FUNCTIONAL_CANARY_NONCE_BYTES]);
        assert_eq!(
            validate(&fixture, echo_payload).expect_err("another echo nonce cannot pass"),
            CanaryEvidenceError::InboundListenerPayloadMismatch { flow }
        );

        let dns_flow = CanaryFlow::Ipv4DnsUdp;
        let mut dns_payload = fixture.successful_evidence();
        let CanaryInboundPayloadIdentity::Dns { transaction_id, .. } =
            tproxy_payload_mut(&mut dns_payload, dns_flow)
        else {
            panic!("DNS flow carries DNS listener payload identity");
        };
        *transaction_id ^= 1;
        assert_eq!(
            validate(&fixture, dns_payload)
                .expect_err("another nonce-derived DNS transaction cannot pass"),
            CanaryEvidenceError::InboundListenerPayloadMismatch { flow: dns_flow }
        );
    }

    #[test]
    fn tproxy_listener_socket_is_bound_to_authority_attempt_and_socket_state() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let flow = CanaryFlow::Ipv4TcpEcho;

        let mut observer = fixture.successful_evidence();
        tproxy_listener_mut(&mut observer, flow)
            .observation
            .authority = CanarySocketObserverAuthority::ProcFdInetDiag {
            collector_identity: CanaryAttemptObjectIdentity::new(
                [12; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES],
            )
            .expect("observer identity"),
            collector_revision: NonZeroU64::new(13).expect("observer revision"),
            netlink_port_id: NonZeroU32::new(15).expect("different port ID"),
        };
        assert_eq!(
            validate(&fixture, observer).expect_err("another socket observer cannot pass"),
            CanaryEvidenceError::InboundListenerObserverMismatch { flow }
        );

        let mut network_namespace = fixture.successful_evidence();
        tproxy_listener_mut(&mut network_namespace, flow).daemon_network_namespace = fixture
            .request
            .pre_binding
            .environment
            .authority
            .network
            .peer_network_namespace;
        assert_eq!(
            validate(&fixture, network_namespace)
                .expect_err("another network namespace cannot pass"),
            CanaryEvidenceError::InboundListenerNetworkNamespaceMismatch { flow }
        );

        let mut capture_program = fixture.successful_evidence();
        tproxy_listener_mut(&mut capture_program, flow).capture_program_digest =
            CaptureProgramDigest::new([4; CAPTURE_PROGRAM_DIGEST_BYTES])
                .expect("different capture program");
        assert_eq!(
            validate(&fixture, capture_program).expect_err("another capture program cannot pass"),
            CanaryEvidenceError::InboundListenerCaptureProgramMismatch { flow }
        );

        let mut selector = fixture.successful_evidence();
        tproxy_listener_mut(&mut selector, flow).selector =
            CanaryAttemptObjectIdentity::new([16; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES])
                .expect("different selector");
        assert_eq!(
            validate(&fixture, selector).expect_err("another attempt selector cannot pass"),
            CanaryEvidenceError::InboundListenerSelectorMismatch { flow }
        );

        let mut bind = fixture.successful_evidence();
        let listener = tproxy_listener_mut(&mut bind, flow);
        listener.bind.set_port(listener.bind.port() + 1);
        assert_eq!(
            validate(&fixture, bind).expect_err("another bind tuple cannot pass"),
            CanaryEvidenceError::InboundListenerBindMismatch { flow }
        );

        let mut non_wildcard = fixture.successful_evidence();
        tproxy_listener_mut(&mut non_wildcard, flow)
            .bind
            .set_ip(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1)));
        assert_eq!(
            validate(&fixture, non_wildcard)
                .expect_err("a non-wildcard listener cannot satisfy this TPROXY contract"),
            CanaryEvidenceError::InboundListenerBindMismatch { flow }
        );

        let mut wrong_bind_family = fixture.successful_evidence();
        tproxy_listener_mut(&mut wrong_bind_family, flow).bind =
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1536);
        assert_eq!(
            validate(&fixture, wrong_bind_family)
                .expect_err("an IPv6 bind cannot prove an IPv4 listener"),
            CanaryEvidenceError::InboundListenerBindMismatch { flow }
        );

        let mut transparent = fixture.successful_evidence();
        tproxy_listener_mut(&mut transparent, flow).transparent = false;
        assert_eq!(
            validate(&fixture, transparent)
                .expect_err("a conventional listener cannot qualify TPROXY"),
            CanaryEvidenceError::InboundListenerTransparentSocketRequired { flow }
        );

        let mut ipv4_v6only = fixture.successful_evidence();
        tproxy_listener_mut(&mut ipv4_v6only, flow).ipv6_only = Some(true);
        assert_eq!(
            validate(&fixture, ipv4_v6only).expect_err("IPv4 has no IPV6_V6ONLY state"),
            CanaryEvidenceError::InboundListenerIpv6OnlyStateInvalid { flow }
        );

        let mut observation_loss = fixture.successful_evidence();
        tproxy_listener_mut(&mut observation_loss, flow)
            .observation
            .loss = CanaryListenerObservationLoss::Counter {
            before: 4,
            after: 4,
        };
        assert_eq!(
            validate(&fixture, observation_loss)
                .expect_err("an event counter cannot replace the INET_DIAG snapshot"),
            CanaryEvidenceError::InboundListenerObservationAuthorityMismatch { flow }
        );

        let mut bpf_fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        bpf_fixture
            .request
            .pre_binding
            .environment
            .authority
            .socket_observer = qualified_cgroup_bpf_observer();
        let mut bpf_loss = bpf_fixture.successful_evidence();
        let CanaryListenerObservationLoss::Counter { after, .. } =
            &mut tproxy_listener_mut(&mut bpf_loss, flow).observation.loss
        else {
            panic!("BPF fixture uses event-counter loss authority")
        };
        *after = 5;
        assert_eq!(
            validate(&bpf_fixture, bpf_loss)
                .expect_err("a lossy BPF listener observation cannot pass"),
            CanaryEvidenceError::InboundListenerObservationLoss { flow }
        );

        let mut observation_timing = fixture.successful_evidence();
        let delivery_observed_at =
            tproxy_delivery_event_mut(&mut observation_timing, flow).observed_at;
        let late_observation = delivery_observed_at + Duration::from_nanos(1);
        let observation = &mut tproxy_listener_mut(&mut observation_timing, flow).observation;
        observation.observed_at = late_observation;
        let CanaryListenerObservationLoss::CompleteInetDiagSnapshot(snapshot) =
            &mut observation.loss
        else {
            panic!("INET_DIAG fixture uses snapshot loss authority")
        };
        snapshot.completed_at = late_observation;
        assert_eq!(
            validate(&fixture, observation_timing)
                .expect_err("a listener observed after delivery cannot pass"),
            CanaryEvidenceError::InboundListenerSocketObservationTimingInvalid { flow }
        );

        let dual = Fixture::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let ipv6_flow = CanaryFlow::Ipv6TcpEcho;
        let mut ipv6_v6only = dual.successful_evidence();
        tproxy_listener_mut(&mut ipv6_v6only, ipv6_flow).ipv6_only = Some(false);
        assert_eq!(
            validate(&dual, ipv6_v6only).expect_err("the separate IPv6 listener must be v6-only"),
            CanaryEvidenceError::InboundListenerIpv6OnlyStateInvalid { flow: ipv6_flow }
        );
    }

    #[test]
    fn complete_inet_diag_listener_snapshot_is_lossless_and_authority_bound() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let observer_binding = fixture
            .request
            .pre_binding
            .environment
            .authority
            .socket_observer_binding();
        let observer = observer_binding.authority();
        let role_sequences = [1, 5, 3, 6]
            .map(|sequence| NonZeroU64::new(sequence).expect("listener role dump sequence"));
        let snapshot = CanaryInetDiagListenerSnapshot::new(
            observer_binding,
            fixture.request.pre_binding.engine.engine(),
            fixture.request.pre_binding.engine.listener.port,
            fixture.request.deadline().started_at(),
            fixture.request.deadline().started_at() + Duration::from_millis(5),
            NonZeroU64::new(1).expect("first listener dump sequence"),
            NonZeroU64::new(6).expect("last listener dump sequence"),
            role_sequences,
        );
        let bind_snapshot = |evidence: &mut UnqualifiedCanaryGateEvidence,
                             snapshot: CanaryInetDiagListenerSnapshot| {
            for flow in CanaryFlow::ALL {
                if fixture.request.requires_flow(flow) {
                    tproxy_listener_mut(evidence, flow).observation =
                        CanaryListenerSocketObservation::from_complete_inet_diag_snapshot(
                            observer,
                            snapshot.role_sequence(flow),
                            snapshot,
                        );
                }
            }
        };
        let mut evidence = fixture.successful_evidence();
        bind_snapshot(&mut evidence, snapshot);
        assert!(validate(&fixture, evidence).is_ok());

        let mut wrong_role = fixture.successful_evidence();
        bind_snapshot(&mut wrong_role, snapshot);
        tproxy_listener_mut(&mut wrong_role, CanaryFlow::Ipv4TcpEcho)
            .observation
            .sequence = snapshot.role_sequence(CanaryFlow::Ipv4UdpEcho);
        assert_eq!(
            validate(&fixture, wrong_role).expect_err("another role's dump cannot pass"),
            CanaryEvidenceError::InboundListenerSnapshotAuthorityMismatch {
                flow: CanaryFlow::Ipv4TcpEcho
            }
        );

        let mut bpf_fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let bpf_observer = qualified_cgroup_bpf_observer();
        bpf_fixture
            .request
            .pre_binding
            .environment
            .authority
            .socket_observer = bpf_observer;
        let mut bpf_snapshot = bpf_fixture.successful_evidence();
        for flow in CanaryFlow::ALL {
            if bpf_fixture.request.requires_flow(flow) {
                tproxy_listener_mut(&mut bpf_snapshot, flow).observation =
                    CanaryListenerSocketObservation::from_complete_inet_diag_snapshot(
                        bpf_observer,
                        snapshot.role_sequence(flow),
                        snapshot,
                    );
            }
        }
        assert_eq!(
            validate(&bpf_fixture, bpf_snapshot)
                .expect_err("an INET_DIAG snapshot cannot replace the BPF loss counter"),
            CanaryEvidenceError::InboundListenerObservationAuthorityMismatch {
                flow: CanaryFlow::Ipv4TcpEcho
            }
        );

        let wrong_authority = match observer {
            CanarySocketObserverAuthority::ProcFdInetDiag {
                collector_identity,
                collector_revision,
                netlink_port_id,
            } => CanarySocketObserverAuthority::ProcFdInetDiag {
                collector_identity,
                collector_revision,
                netlink_port_id: NonZeroU32::new(netlink_port_id.get() + 1)
                    .expect("mismatched netlink port"),
            },
            CanarySocketObserverAuthority::QualifiedCgroupBpf { .. } => {
                panic!("fixture uses the INET_DIAG observer")
            }
        };
        let wrong_snapshot = CanaryInetDiagListenerSnapshot::new(
            CanarySocketObserverBinding::scripted(
                wrong_authority,
                NonZeroU64::new(999).expect("mismatched opening"),
            ),
            fixture.request.pre_binding.engine.engine(),
            fixture.request.pre_binding.engine.listener.port,
            fixture.request.deadline().started_at(),
            fixture.request.deadline().started_at() + Duration::from_millis(5),
            NonZeroU64::new(1).expect("first listener dump sequence"),
            NonZeroU64::new(6).expect("last listener dump sequence"),
            role_sequences,
        );
        let mut mismatched = fixture.successful_evidence();
        bind_snapshot(&mut mismatched, wrong_snapshot);
        assert_eq!(
            validate(&fixture, mismatched).expect_err("replaced snapshot authority cannot pass"),
            CanaryEvidenceError::InboundListenerSnapshotAuthorityMismatch {
                flow: CanaryFlow::Ipv4TcpEcho
            }
        );
    }

    #[test]
    fn scripted_attempt_socket_observer_cannot_collect_a_process_snapshot() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let observer = CanaryAttemptSocketObserverSession::scripted(
            fixture
                .request
                .pre_binding
                .environment
                .authority
                .socket_observer_binding(),
            fixture.request.deadline(),
        );
        let result = observer.collect_process_until(fixture.request.pre_binding.engine.engine());
        let error = match result {
            Ok(_) => panic!("scripted observer must not collect production socket state"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), CanaryErrorKind::InvalidEvidence);
        assert_eq!(error.cleanup(), CanaryCleanupStatus::NotRequired);
    }

    #[test]
    fn transport_specific_tproxy_delivery_rejects_unlinked_or_lossy_socket_events() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let tcp_flow = CanaryFlow::Ipv4TcpEcho;

        let mut accepted_engine = fixture.successful_evidence();
        tproxy_tcp_delivery_mut(&mut accepted_engine, tcp_flow).engine = OwnedEngineIdentity::new(
            NonZeroU32::new(4243).expect("different PID"),
            NonZeroU64::new(98_766).expect("different start ticks"),
        );
        assert_eq!(
            validate(&fixture, accepted_engine)
                .expect_err("an accepted socket from another process cannot pass"),
            CanaryEvidenceError::InboundListenerAcceptedEngineMismatch { flow: tcp_flow }
        );

        let mut unlinked = fixture.successful_evidence();
        tproxy_tcp_delivery_mut(&mut unlinked, tcp_flow).listener_cookie =
            CanaryInetDiagCookie::new(99, 1).expect("different listener cookie");
        assert_eq!(
            validate(&fixture, unlinked).expect_err("an unlinked accepted socket cannot pass"),
            CanaryEvidenceError::InboundListenerSocketLinkMismatch { flow: tcp_flow }
        );

        let mut collision = fixture.successful_evidence();
        let listener_inode = tproxy_listener_mut(&mut collision, tcp_flow).listener_inode;
        tproxy_tcp_delivery_mut(&mut collision, tcp_flow).accepted_inode = listener_inode;
        assert_eq!(
            validate(&fixture, collision)
                .expect_err("the listener cannot masquerade as its accepted child"),
            CanaryEvidenceError::InboundListenerAcceptedSocketIdentityCollision { flow: tcp_flow }
        );

        let mut fd_collision = fixture.successful_evidence();
        let listener_fd = tproxy_listener_mut(&mut fd_collision, tcp_flow).listener_fd;
        tproxy_tcp_delivery_mut(&mut fd_collision, tcp_flow).accepted_fd = listener_fd;
        assert_eq!(
            validate(&fixture, fd_collision)
                .expect_err("the accepted child cannot reuse the live listener FD"),
            CanaryEvidenceError::InboundListenerAcceptedSocketIdentityCollision { flow: tcp_flow }
        );

        let mut cookie_collision = fixture.successful_evidence();
        let listener_cookie = tproxy_listener_mut(&mut cookie_collision, tcp_flow).listener_cookie;
        tproxy_tcp_delivery_mut(&mut cookie_collision, tcp_flow).accepted_cookie = listener_cookie;
        assert_eq!(
            validate(&fixture, cookie_collision)
                .expect_err("the accepted child cannot reuse the listener cookie"),
            CanaryEvidenceError::InboundListenerAcceptedSocketIdentityCollision { flow: tcp_flow }
        );

        let udp_flow = CanaryFlow::Ipv4UdpEcho;
        let mut truncated = fixture.successful_evidence();
        tproxy_udp_delivery_mut(&mut truncated, udp_flow).control_truncated = true;
        assert_eq!(
            validate(&fixture, truncated).expect_err("MSG_CTRUNC cannot pass"),
            CanaryEvidenceError::InboundListenerUdpMessageTruncated { flow: udp_flow }
        );

        let mut payload_truncated = fixture.successful_evidence();
        tproxy_udp_delivery_mut(&mut payload_truncated, udp_flow).payload_truncated = true;
        assert_eq!(
            validate(&fixture, payload_truncated).expect_err("MSG_TRUNC cannot pass"),
            CanaryEvidenceError::InboundListenerUdpMessageTruncated { flow: udp_flow }
        );

        let mut udp_unlinked = fixture.successful_evidence();
        tproxy_udp_delivery_mut(&mut udp_unlinked, udp_flow).listener_cookie =
            CanaryInetDiagCookie::new(99, 2).expect("different listener cookie");
        assert_eq!(
            validate(&fixture, udp_unlinked)
                .expect_err("a datagram from another listener cannot pass"),
            CanaryEvidenceError::InboundListenerSocketLinkMismatch { flow: udp_flow }
        );

        let mut missing_cmsg = fixture.successful_evidence();
        tproxy_udp_delivery_mut(&mut missing_cmsg, udp_flow).original_destination_cmsg_count = 0;
        assert_eq!(
            validate(&fixture, missing_cmsg)
                .expect_err("a missing original-destination cmsg cannot pass"),
            CanaryEvidenceError::InboundListenerUdpOriginalDestinationInvalid { flow: udp_flow }
        );

        let mut duplicate_cmsg = fixture.successful_evidence();
        tproxy_udp_delivery_mut(&mut duplicate_cmsg, udp_flow).original_destination_cmsg_count = 2;
        assert_eq!(
            validate(&fixture, duplicate_cmsg)
                .expect_err("duplicate original-destination cmsgs cannot pass"),
            CanaryEvidenceError::InboundListenerUdpOriginalDestinationInvalid { flow: udp_flow }
        );

        let mut wrong_cmsg_family = fixture.successful_evidence();
        tproxy_udp_delivery_mut(&mut wrong_cmsg_family, udp_flow).original_destination_cmsg =
            CanaryOriginalDestinationCmsg::Ipv6 { payload_length: 28 };
        assert_eq!(
            validate(&fixture, wrong_cmsg_family)
                .expect_err("an IPv6 cmsg cannot prove an IPv4 datagram"),
            CanaryEvidenceError::InboundListenerUdpOriginalDestinationInvalid { flow: udp_flow }
        );

        let mut wrong_cmsg_length = fixture.successful_evidence();
        tproxy_udp_delivery_mut(&mut wrong_cmsg_length, udp_flow).original_destination_cmsg =
            CanaryOriginalDestinationCmsg::Ipv4 { payload_length: 15 };
        assert_eq!(
            validate(&fixture, wrong_cmsg_length)
                .expect_err("a malformed sockaddr_in cmsg cannot pass"),
            CanaryEvidenceError::InboundListenerUdpOriginalDestinationInvalid { flow: udp_flow }
        );

        let dual = Fixture::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let ipv6_udp = CanaryFlow::Ipv6UdpEcho;
        let mut wrong_ipv6_cmsg_length = dual.successful_evidence();
        tproxy_udp_delivery_mut(&mut wrong_ipv6_cmsg_length, ipv6_udp).original_destination_cmsg =
            CanaryOriginalDestinationCmsg::Ipv6 { payload_length: 27 };
        assert_eq!(
            validate(&dual, wrong_ipv6_cmsg_length)
                .expect_err("a malformed sockaddr_in6 cmsg cannot pass"),
            CanaryEvidenceError::InboundListenerUdpOriginalDestinationInvalid { flow: ipv6_udp }
        );

        let mut wrong_transport = fixture.successful_evidence();
        let udp_delivery = wrong_transport.flows.slots[udp_flow.index()]
            .as_ref()
            .expect("IPv4 UDP evidence")
            .inbound_listener_delivery
            .as_ref()
            .expect("UDP listener delivery")
            .clone();
        wrong_transport.flows.slots[tcp_flow.index()]
            .as_mut()
            .expect("IPv4 TCP evidence")
            .inbound_listener_delivery = Some(udp_delivery);
        assert_eq!(
            validate(&fixture, wrong_transport)
                .expect_err("UDP recvmsg evidence cannot prove TCP acceptance"),
            CanaryEvidenceError::InboundListenerTransportEvidenceMismatch { flow: tcp_flow }
        );
    }

    #[test]
    fn inbound_delivery_events_are_unique_stable_and_single_authority() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let first = CanaryFlow::Ipv4TcpEcho;
        let second = CanaryFlow::Ipv4UdpEcho;

        let mut independent_sequences = fixture.successful_evidence();
        tproxy_delivery_event_mut(&mut independent_sequences, first).sequence =
            NonZeroU64::new(1).expect("independent delivery sequence");
        independent_sequences.local_output_capture_receipt =
            local_output::TproxyLocalOutputCaptureReceipt::scripted(
                &fixture.request,
                &independent_sequences.flows,
            );
        validate(&fixture, independent_sequences)
            .expect("listener-observer and delivery-authority sequence domains are independent");

        let same_listener_role = CanaryFlow::Ipv4DnsTcp;
        let mut shared_listener_snapshot = fixture.successful_evidence();
        let listener_sequence = tproxy_listener_mut(&mut shared_listener_snapshot, first)
            .observation
            .sequence;
        assert_eq!(
            tproxy_listener_mut(&mut shared_listener_snapshot, same_listener_role)
                .observation
                .sequence,
            listener_sequence
        );
        validate(&fixture, shared_listener_snapshot)
            .expect("one complete listener snapshot may cover multiple sockets and flows");

        let mut reused_sequence = fixture.successful_evidence();
        let first_sequence = tproxy_delivery_event_mut(&mut reused_sequence, first).sequence;
        tproxy_delivery_event_mut(&mut reused_sequence, second).sequence = first_sequence;
        assert_eq!(
            validate(&fixture, reused_sequence)
                .expect_err("one delivery event cannot satisfy two flows"),
            CanaryEvidenceError::InboundListenerEventSequenceReused { first, second }
        );

        let mut event_loss = fixture.successful_evidence();
        tproxy_delivery_event_mut(&mut event_loss, first).lost_events_after = 5;
        assert_eq!(
            validate(&fixture, event_loss).expect_err("delivery event loss cannot pass"),
            CanaryEvidenceError::InboundListenerEventLoss { flow: first }
        );

        let mut baseline = fixture.successful_evidence();
        let event = tproxy_delivery_event_mut(&mut baseline, second);
        event.lost_events_before = 5;
        event.lost_events_after = 5;
        assert_eq!(
            validate(&fixture, baseline).expect_err("loss baseline drift cannot pass"),
            CanaryEvidenceError::InboundListenerEventLossBaselineChanged { first, second }
        );

        let mut listener_fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        listener_fixture
            .request
            .pre_binding
            .environment
            .authority
            .socket_observer = qualified_cgroup_bpf_observer();
        let mut listener_baseline = listener_fixture.successful_evidence();
        let observation = &mut tproxy_listener_mut(&mut listener_baseline, second).observation;
        observation.loss = CanaryListenerObservationLoss::Counter {
            before: 5,
            after: 5,
        };
        assert_eq!(
            validate(&listener_fixture, listener_baseline)
                .expect_err("listener-observer loss baseline drift cannot pass"),
            CanaryEvidenceError::InboundListenerObservationLossBaselineChanged { first, second }
        );

        let mut listener_fd_reused = fixture.successful_evidence();
        let first_listener_fd = tproxy_listener_mut(&mut listener_fd_reused, first).listener_fd;
        tproxy_listener_mut(&mut listener_fd_reused, second).listener_fd = first_listener_fd;
        assert_eq!(
            validate(&fixture, listener_fd_reused)
                .expect_err("TCP and UDP listener roles cannot reuse one FD"),
            CanaryEvidenceError::InboundListenerSocketIdentityReused { first, second }
        );

        let mut listener_inode_reused = fixture.successful_evidence();
        let first_listener_inode =
            tproxy_listener_mut(&mut listener_inode_reused, first).listener_inode;
        tproxy_listener_mut(&mut listener_inode_reused, second).listener_inode =
            first_listener_inode;
        assert_eq!(
            validate(&fixture, listener_inode_reused)
                .expect_err("TCP and UDP listener roles cannot reuse one inode"),
            CanaryEvidenceError::InboundListenerSocketIdentityReused { first, second }
        );

        let mut listener_cookie_reused = fixture.successful_evidence();
        let first_listener_cookie =
            tproxy_listener_mut(&mut listener_cookie_reused, first).listener_cookie;
        tproxy_listener_mut(&mut listener_cookie_reused, second).listener_cookie =
            first_listener_cookie;
        tproxy_udp_delivery_mut(&mut listener_cookie_reused, second).listener_cookie =
            first_listener_cookie;
        assert_eq!(
            validate(&fixture, listener_cookie_reused)
                .expect_err("TCP and UDP listener roles cannot reuse one socket cookie"),
            CanaryEvidenceError::InboundListenerSocketIdentityReused { first, second }
        );

        let mut accepted_conflicts_with_later_listener = fixture.successful_evidence();
        let udp_listener_cookie =
            tproxy_listener_mut(&mut accepted_conflicts_with_later_listener, second)
                .listener_cookie;
        tproxy_tcp_delivery_mut(&mut accepted_conflicts_with_later_listener, first)
            .accepted_cookie = udp_listener_cookie;
        assert_eq!(
            validate(&fixture, accepted_conflicts_with_later_listener)
                .expect_err("an accepted child cannot collide with a later listener role"),
            CanaryEvidenceError::InboundListenerAcceptedSocketConflictsWithListener {
                listener: second,
                accepted: first,
            }
        );

        let dns_tcp = CanaryFlow::Ipv4DnsTcp;
        let mut listener_changed = fixture.successful_evidence();
        tproxy_listener_mut(&mut listener_changed, dns_tcp).listener_inode =
            NonZeroU64::new(71_000).expect("different listener inode");
        assert_eq!(
            validate(&fixture, listener_changed)
                .expect_err("one transport cannot switch listener sockets mid-attempt"),
            CanaryEvidenceError::InboundListenerSocketIdentityChanged {
                first,
                second: dns_tcp,
            }
        );

        let dns_udp = CanaryFlow::Ipv4DnsUdp;
        let mut udp_listener_changed = fixture.successful_evidence();
        tproxy_listener_mut(&mut udp_listener_changed, dns_udp).listener_inode =
            NonZeroU64::new(71_001).expect("different UDP listener inode");
        assert_eq!(
            validate(&fixture, udp_listener_changed)
                .expect_err("UDP echo and DNS must share one stable listener socket"),
            CanaryEvidenceError::InboundListenerSocketIdentityChanged {
                first: second,
                second: dns_udp,
            }
        );

        let mut accepted_conflicts_with_existing_listener = fixture.successful_evidence();
        let udp_listener_inode =
            tproxy_listener_mut(&mut accepted_conflicts_with_existing_listener, second)
                .listener_inode;
        tproxy_tcp_delivery_mut(&mut accepted_conflicts_with_existing_listener, dns_tcp)
            .accepted_inode = udp_listener_inode;
        assert_eq!(
            validate(&fixture, accepted_conflicts_with_existing_listener)
                .expect_err("an accepted child cannot collide with an existing listener role"),
            CanaryEvidenceError::InboundListenerAcceptedSocketConflictsWithListener {
                listener: second,
                accepted: dns_tcp,
            }
        );

        let mut accepted_reused = fixture.successful_evidence();
        let first_inode = tproxy_tcp_delivery_mut(&mut accepted_reused, first).accepted_inode;
        tproxy_tcp_delivery_mut(&mut accepted_reused, dns_tcp).accepted_inode = first_inode;
        assert_eq!(
            validate(&fixture, accepted_reused)
                .expect_err("two TCP flows cannot reuse an accepted socket identity"),
            CanaryEvidenceError::InboundListenerAcceptedSocketIdentityReused {
                first,
                second: dns_tcp,
            }
        );

        let mut accepted_cookie_reused = fixture.successful_evidence();
        let first_cookie =
            tproxy_tcp_delivery_mut(&mut accepted_cookie_reused, first).accepted_cookie;
        tproxy_tcp_delivery_mut(&mut accepted_cookie_reused, dns_tcp).accepted_cookie =
            first_cookie;
        assert_eq!(
            validate(&fixture, accepted_cookie_reused)
                .expect_err("two TCP flows cannot reuse an accepted socket cookie"),
            CanaryEvidenceError::InboundListenerAcceptedSocketIdentityReused {
                first,
                second: dns_tcp,
            }
        );

        let mut mixed_fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let qualified_observer = qualified_cgroup_bpf_observer();
        mixed_fixture
            .request
            .pre_binding
            .environment
            .authority
            .socket_observer = qualified_observer;
        let qualified_evidence = || {
            let mut evidence = mixed_fixture.successful_evidence();
            for flow in CanaryFlow::ALL {
                if mixed_fixture.request.requires_flow(flow) {
                    tproxy_delivery_event_mut(&mut evidence, flow).authority =
                        CanaryInboundDeliveryAuthority::QualifiedCgroupBpf {
                            observer: qualified_observer,
                        };
                }
            }
            evidence.local_output_capture_receipt =
                local_output::TproxyLocalOutputCaptureReceipt::scripted(
                    &mixed_fixture.request,
                    &evidence.flows,
                );
            evidence
        };
        assert_eq!(
            validate(&mixed_fixture, qualified_evidence())
                .expect_err("BPF authority cannot fabricate report-object retirement"),
            CanaryEvidenceError::CleanupListenerDeliveryReportDispositionMismatch
        );
        let mut qualified = qualified_evidence();
        qualified.cleanup.listener_delivery_report =
            CanaryListenerDeliveryReportCleanupEvidence::verified_never_created(
                mixed_fixture
                    .request
                    .pre_binding
                    .environment
                    .attempt_objects
                    .listener_delivery_report(),
                mixed_fixture.request.deadline().started_at() + Duration::from_millis(123),
            );
        let mut premature_never_created_readback = qualified_evidence();
        premature_never_created_readback
            .cleanup
            .listener_delivery_report =
            CanaryListenerDeliveryReportCleanupEvidence::verified_never_created(
                mixed_fixture
                    .request
                    .pre_binding
                    .environment
                    .attempt_objects
                    .listener_delivery_report(),
                mixed_fixture.request.deadline().started_at() + Duration::from_millis(123),
            );
        let absent_observed_at = premature_never_created_readback
            .cleanup
            .listener_delivery_report
            .never_created_absence_mut()
            .expect("qualified BPF fixture verifies the report object was never created");
        *absent_observed_at = mixed_fixture.request.deadline().started_at();
        assert_eq!(
            validate(&mixed_fixture, premature_never_created_readback)
                .expect_err("BPF report-object absence must follow the final delivery"),
            CanaryEvidenceError::CleanupListenerDeliveryReportNeverCreatedObservedBeforeFinalDelivery
        );
        validate(&mixed_fixture, qualified)
            .expect("one exact qualified cgroup-BPF authority may prove every delivery");

        let mut mixed = mixed_fixture.successful_evidence();
        tproxy_delivery_event_mut(&mut mixed, second).authority =
            CanaryInboundDeliveryAuthority::QualifiedCgroupBpf {
                observer: qualified_observer,
            };
        assert_eq!(
            validate(&mixed_fixture, mixed)
                .expect_err("one attempt cannot mix report and BPF delivery authority"),
            CanaryEvidenceError::InboundListenerDeliveryAuthorityChanged { first, second }
        );
    }

    #[test]
    fn dns_wire_identity_matches_the_producer_golden_vector() {
        let mut nonce = [0_u8; FUNCTIONAL_CANARY_NONCE_BYTES];
        nonce[0] = 0x5a;
        let expected =
            derive_dns_expectation(CanaryFlow::Ipv4DnsUdp, CanaryNonce::from_bytes(nonce));
        assert_eq!(expected.transaction_id, 0xc897);
        assert_eq!(expected.question.wire_name.len(), 83);
        assert_eq!(expected.question.wire_name[82], 0);
        assert_eq!(
            expected.question_digest,
            CanaryDnsQuestionDigest::from_bytes([
                0xc8, 0x97, 0xbf, 0x07, 0xaa, 0xdf, 0xc9, 0x63, 0xfe, 0x73, 0xea, 0xd8, 0x78, 0xb0,
                0xd4, 0x9f, 0x78, 0x29, 0x01, 0xf0, 0x14, 0x8e, 0x33, 0x0f, 0xb1, 0xc6, 0x82, 0xe5,
                0x19, 0x03, 0xad, 0xaf,
            ])
        );

        let mut query = Vec::with_capacity(99);
        query.extend_from_slice(&expected.transaction_id.to_be_bytes());
        query.extend_from_slice(&0x0100_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&[0; 6]);
        query.extend_from_slice(&expected.question.wire_name);
        query.extend_from_slice(&expected.question.record_type.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        assert_eq!(query.len(), 99);
        let wire_digest: [u8; 32] = Sha256::digest(&query).into();
        assert_eq!(
            wire_digest,
            [
                0x58, 0xfb, 0xbb, 0x24, 0x21, 0xf3, 0xf3, 0x6b, 0xab, 0x46, 0x2b, 0xce, 0x83, 0xeb,
                0xb4, 0xcf, 0xa1, 0x67, 0x8f, 0xa8, 0x98, 0x48, 0xf3, 0xda, 0x43, 0x17, 0x29, 0x00,
                0xa3, 0x8f, 0x43, 0x2e,
            ]
        );
    }

    #[test]
    fn supervised_delivery_report_and_exact_wire_identity_are_attempt_bound() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let flow = CanaryFlow::Ipv4TcpEcho;

        let mut exact_lengths = fixture.successful_evidence();
        let CanaryInboundPayloadIdentity::Echo {
            wire_length,
            wire_digest,
            ..
        } = *tproxy_payload_mut(&mut exact_lengths, flow)
        else {
            panic!("echo flow carries echo payload identity");
        };
        assert_eq!(
            wire_length.get(),
            u16::try_from(FUNCTIONAL_CANARY_NONCE_BYTES).expect("nonce length fits u16")
        );
        let mut echo_hasher = Sha256::new();
        echo_hasher.update(fixture.request.nonce().as_bytes());
        assert_eq!(
            wire_digest,
            CanaryInboundPayloadDigest::from_bytes(echo_hasher.finalize().into())
        );
        let dns_udp = CanaryFlow::Ipv4DnsUdp;
        let CanaryInboundPayloadIdentity::Dns {
            wire_length,
            tcp_length_prefix,
            ..
        } = *tproxy_payload_mut(&mut exact_lengths, dns_udp)
        else {
            panic!("DNS/UDP flow carries DNS payload identity");
        };
        assert_eq!(wire_length.get(), 99);
        assert_eq!(tcp_length_prefix, None);
        let dns_tcp = CanaryFlow::Ipv4DnsTcp;
        let CanaryInboundPayloadIdentity::Dns {
            wire_length,
            tcp_length_prefix,
            ..
        } = *tproxy_payload_mut(&mut exact_lengths, dns_tcp)
        else {
            panic!("DNS/TCP flow carries DNS payload identity");
        };
        assert_eq!(wire_length.get(), 99);
        assert_eq!(tcp_length_prefix, Some(99));

        let mut report_engine = fixture.successful_evidence();
        let CanaryInboundDeliveryAuthority::SupervisedEngineReport { engine, .. } =
            &mut tproxy_delivery_event_mut(&mut report_engine, flow).authority
        else {
            panic!("fixture uses supervised engine reports");
        };
        *engine = OwnedEngineIdentity::new(
            NonZeroU32::new(4243).expect("different report PID"),
            NonZeroU64::new(98_766).expect("different report start ticks"),
        );
        assert_eq!(
            validate(&fixture, report_engine)
                .expect_err("another engine cannot own the delivery report"),
            CanaryEvidenceError::InboundListenerDeliveryAuthorityMismatch { flow }
        );

        let mut profile_revision = fixture.successful_evidence();
        let CanaryInboundDeliveryAuthority::SupervisedEngineReport {
            engine_profile_revision,
            ..
        } = &mut tproxy_delivery_event_mut(&mut profile_revision, flow).authority
        else {
            panic!("fixture uses supervised engine reports");
        };
        *engine_profile_revision = EngineCapabilityProfileRevision::from_fixture_bytes([0x52; 32]);
        assert_eq!(
            validate(&fixture, profile_revision)
                .expect_err("another engine profile cannot own the delivery report"),
            CanaryEvidenceError::InboundListenerDeliveryAuthorityMismatch { flow }
        );

        let mut report_object = fixture.successful_evidence();
        let CanaryInboundDeliveryAuthority::SupervisedEngineReport {
            report_object: observed_object,
            ..
        } = &mut tproxy_delivery_event_mut(&mut report_object, flow).authority
        else {
            panic!("fixture uses supervised engine reports");
        };
        *observed_object =
            CanaryAttemptObjectIdentity::new([16; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES])
                .expect("different report object");
        assert_eq!(
            validate(&fixture, report_object)
                .expect_err("another report object cannot satisfy delivery"),
            CanaryEvidenceError::InboundListenerDeliveryAuthorityMismatch { flow }
        );

        let mut schema = fixture.successful_evidence();
        let CanaryInboundDeliveryAuthority::SupervisedEngineReport { schema_version, .. } =
            &mut tproxy_delivery_event_mut(&mut schema, flow).authority
        else {
            panic!("fixture uses supervised engine reports");
        };
        *schema_version = NonZeroU16::new(2).expect("different schema");
        assert_eq!(
            validate(&fixture, schema).expect_err("another report schema cannot pass"),
            CanaryEvidenceError::InboundListenerDeliveryAuthorityMismatch { flow }
        );

        let mut invalid_bpf = fixture.successful_evidence();
        tproxy_delivery_event_mut(&mut invalid_bpf, flow).authority =
            CanaryInboundDeliveryAuthority::QualifiedCgroupBpf {
                observer: qualified_cgroup_bpf_observer(),
            };
        assert_eq!(
            validate(&fixture, invalid_bpf)
                .expect_err("an unbound BPF observer cannot satisfy delivery"),
            CanaryEvidenceError::InboundListenerDeliveryAuthorityMismatch { flow }
        );

        let mut non_bpf_authority = fixture.successful_evidence();
        let proc_fd_observer = fixture
            .request
            .pre_binding
            .environment
            .authority
            .socket_observer;
        tproxy_delivery_event_mut(&mut non_bpf_authority, flow).authority =
            CanaryInboundDeliveryAuthority::QualifiedCgroupBpf {
                observer: proc_fd_observer,
            };
        assert_eq!(
            validate(&fixture, non_bpf_authority)
                .expect_err("a proc/diag observer cannot masquerade as cgroup-BPF authority"),
            CanaryEvidenceError::InboundListenerDeliveryAuthorityMismatch { flow }
        );

        let mut echo_length = fixture.successful_evidence();
        let CanaryInboundPayloadIdentity::Echo { wire_length, .. } =
            tproxy_payload_mut(&mut echo_length, flow)
        else {
            panic!("echo flow carries echo payload identity");
        };
        *wire_length = NonZeroU16::new(31).expect("different echo wire length");
        assert_eq!(
            validate(&fixture, echo_length).expect_err("a partial echo payload cannot pass"),
            CanaryEvidenceError::InboundListenerPayloadMismatch { flow }
        );

        let mut wire_digest = fixture.successful_evidence();
        let CanaryInboundPayloadIdentity::Echo {
            wire_digest: observed_digest,
            ..
        } = tproxy_payload_mut(&mut wire_digest, flow)
        else {
            panic!("echo flow carries echo payload identity");
        };
        observed_digest.0[0] ^= 1;
        assert_eq!(
            validate(&fixture, wire_digest).expect_err("another wire payload cannot pass"),
            CanaryEvidenceError::InboundListenerPayloadMismatch { flow }
        );

        let mut framing = fixture.successful_evidence();
        let CanaryInboundPayloadIdentity::Dns {
            tcp_length_prefix, ..
        } = tproxy_payload_mut(&mut framing, dns_tcp)
        else {
            panic!("DNS/TCP flow carries DNS payload identity");
        };
        *tcp_length_prefix = None;
        assert_eq!(
            validate(&fixture, framing)
                .expect_err("DNS/TCP without its two-byte length prefix cannot pass"),
            CanaryEvidenceError::InboundListenerPayloadMismatch { flow: dns_tcp }
        );

        let mut dns_udp_length = fixture.successful_evidence();
        let CanaryInboundPayloadIdentity::Dns { wire_length, .. } =
            tproxy_payload_mut(&mut dns_udp_length, dns_udp)
        else {
            panic!("DNS/UDP flow carries DNS payload identity");
        };
        *wire_length = NonZeroU16::new(98).expect("different DNS wire length");
        assert_eq!(
            validate(&fixture, dns_udp_length).expect_err("an incomplete DNS datagram cannot pass"),
            CanaryEvidenceError::InboundListenerPayloadMismatch { flow: dns_udp }
        );

        let mut dns_udp_digest = fixture.successful_evidence();
        let CanaryInboundPayloadIdentity::Dns { wire_digest, .. } =
            tproxy_payload_mut(&mut dns_udp_digest, dns_udp)
        else {
            panic!("DNS/UDP flow carries DNS payload identity");
        };
        wire_digest.0[0] ^= 1;
        assert_eq!(
            validate(&fixture, dns_udp_digest)
                .expect_err("another canonical DNS datagram cannot pass"),
            CanaryEvidenceError::InboundListenerPayloadMismatch { flow: dns_udp }
        );

        let mut dns_nonce = fixture.successful_evidence();
        let CanaryInboundPayloadIdentity::Dns { nonce, .. } =
            tproxy_payload_mut(&mut dns_nonce, dns_udp)
        else {
            panic!("DNS/UDP flow carries DNS payload identity");
        };
        *nonce = CanaryNonce::from_bytes([8; FUNCTIONAL_CANARY_NONCE_BYTES]);
        assert_eq!(
            validate(&fixture, dns_nonce)
                .expect_err("a DNS payload from another attempt cannot pass"),
            CanaryEvidenceError::InboundListenerPayloadMismatch { flow: dns_udp }
        );

        let mut dns_question = fixture.successful_evidence();
        let CanaryInboundPayloadIdentity::Dns { question, .. } =
            tproxy_payload_mut(&mut dns_question, dns_udp)
        else {
            panic!("DNS/UDP flow carries DNS payload identity");
        };
        question.0[0] ^= 1;
        assert_eq!(
            validate(&fixture, dns_question).expect_err("another DNS question digest cannot pass"),
            CanaryEvidenceError::InboundListenerPayloadMismatch { flow: dns_udp }
        );

        let mut wrong_framing = fixture.successful_evidence();
        let CanaryInboundPayloadIdentity::Dns {
            tcp_length_prefix, ..
        } = tproxy_payload_mut(&mut wrong_framing, dns_tcp)
        else {
            panic!("DNS/TCP flow carries DNS payload identity");
        };
        *tcp_length_prefix = Some(98);
        assert_eq!(
            validate(&fixture, wrong_framing)
                .expect_err("an incorrect DNS/TCP length prefix cannot pass"),
            CanaryEvidenceError::InboundListenerPayloadMismatch { flow: dns_tcp }
        );
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

        let mut wrong_destination = fixture.successful_evidence();
        let negative = wrong_destination.loop_escape.negative_route_controls.slots[0]
            .as_mut()
            .expect("IPv4 negative control");
        negative.destination =
            SocketAddr::new(negative.destination.ip(), negative.destination.port() + 1);
        assert_eq!(
            validate(&fixture, wrong_destination)
                .expect_err("negative route lookup destination cannot change"),
            CanaryEvidenceError::NegativeControlDestinationMismatch
        );

        let mut wrong_uid = fixture.successful_evidence();
        wrong_uid.loop_escape.negative_route_controls.slots[0]
            .as_mut()
            .expect("IPv4 negative control")
            .queried_uid = NonZeroU32::new(20_002).expect("alternate UID");
        assert_eq!(
            validate(&fixture, wrong_uid).expect_err("negative route lookup UID cannot change"),
            CanaryEvidenceError::NegativeControlUidMismatch
        );

        let mut wrong_mark = fixture.successful_evidence();
        wrong_mark.loop_escape.negative_route_controls.slots[0]
            .as_mut()
            .expect("IPv4 negative control")
            .mark ^= 1;
        assert_eq!(
            validate(&fixture, wrong_mark).expect_err("negative route lookup mark cannot change"),
            CanaryEvidenceError::NegativeControlMarkMismatch
        );

        let mut wrong_table = fixture.successful_evidence();
        wrong_table.loop_escape.negative_route_controls.slots[0]
            .as_mut()
            .expect("IPv4 negative control")
            .selected_table = RouteTableId::from_raw(10_103);
        assert_eq!(
            validate(&fixture, wrong_table)
                .expect_err("negative route lookup must select the capture table"),
            CanaryEvidenceError::NegativeControlSelectedWrongTable
        );

        let mut late = fixture.successful_evidence();
        late.loop_escape.negative_route_controls.slots[0]
            .as_mut()
            .expect("IPv4 negative control")
            .observed_at = fixture.request.deadline().started_at() + Duration::from_millis(10);
        assert_eq!(
            validate(&fixture, late).expect_err("negative route lookup must precede traffic"),
            CanaryEvidenceError::NegativeControlTimingInvalid
        );

        let mut injected_zero = fixture.successful_evidence();
        injected_zero.loop_escape.negative_route_controls.slots[0]
            .as_mut()
            .expect("IPv4 negative control")
            .injected_peer_observation_count = Some(0);
        validate(&fixture, injected_zero)
            .expect("an armed injection window with zero peer packets remains isolated");

        let mut observed = fixture.successful_evidence();
        observed.loop_escape.negative_route_controls.slots[0]
            .as_mut()
            .expect("IPv4 negative control")
            .injected_peer_observation_count = Some(1);
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
    fn completion_at_deadline_and_invalid_cleanup_are_rejected() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let mut late = fixture.successful_evidence();
        late.completed_at = fixture.request.deadline().expires_at();
        assert_eq!(
            validate(&fixture, late).expect_err("deadline is exclusive"),
            CanaryEvidenceError::CompletionAtOrAfterDeadline
        );

        let mut uncertain = fixture.successful_evidence();
        uncertain.cleanup.client.reaped_at =
            uncertain.cleanup.client.quiesced_at - Duration::from_nanos(1);
        assert_eq!(
            validate(&fixture, uncertain).expect_err("cleanup uncertainty cannot pass"),
            CanaryEvidenceError::CleanupClientRetirementTimingInvalid
        );

        let mut recursion = fixture.successful_evidence();
        recursion.counters.after.recapture_packets = 1;
        assert_eq!(
            validate(&fixture, recursion).expect_err("recapture delta cannot pass"),
            CanaryEvidenceError::RecaptureCounterDeltaOutOfRange { observed: 1 }
        );
    }

    #[test]
    fn cleanup_evidence_binds_exact_objects_and_documented_chronology() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4AndIpv6);

        let mut before_flow_completion = fixture.successful_evidence();
        let last_flow_completed_at = before_flow_completion
            .flows
            .slots
            .iter()
            .flatten()
            .map(|flow| flow.completed_at)
            .max()
            .expect("dual-stack fixture has required flows");
        before_flow_completion.cleanup.client.quiesced_at =
            last_flow_completed_at - Duration::from_nanos(1);
        assert_eq!(
            validate(&fixture, before_flow_completion)
                .expect_err("the client must remain live through the final flow"),
            CanaryEvidenceError::LocalOutputCaptureReceiptInvalid
        );

        let mut wrong_report_object = fixture.successful_evidence();
        supervised_report_retirement_mut(&mut wrong_report_object).object = fixture
            .request
            .pre_binding
            .environment
            .attempt_objects
            .selector();
        assert_eq!(
            validate(&fixture, wrong_report_object)
                .expect_err("a copied selector identity cannot retire the report object"),
            CanaryEvidenceError::CleanupObjectMismatch {
                object: CanaryCleanupObjectRole::ListenerDeliveryReport,
            }
        );

        let mut supervised_report_claimed_never_created = fixture.successful_evidence();
        supervised_report_claimed_never_created
            .cleanup
            .listener_delivery_report =
            CanaryListenerDeliveryReportCleanupEvidence::verified_never_created(
                fixture
                    .request
                    .pre_binding
                    .environment
                    .attempt_objects
                    .listener_delivery_report(),
                fixture.request.deadline().started_at() + Duration::from_millis(123),
            );
        assert_eq!(
            validate(&fixture, supervised_report_claimed_never_created)
                .expect_err("a supervised report must carry retirement evidence"),
            CanaryEvidenceError::CleanupListenerDeliveryReportDispositionMismatch
        );

        let mut absence_before_retirement = fixture.successful_evidence();
        let selector_absent_observed_at =
            selector_retirement_mut(&mut absence_before_retirement).absent_observed_at;
        selector_retirement_mut(&mut absence_before_retirement).retired_at =
            selector_absent_observed_at + Duration::from_nanos(1);
        assert_eq!(
            validate(&fixture, absence_before_retirement)
                .expect_err("absence readback cannot precede object retirement"),
            CanaryEvidenceError::CleanupObjectRetirementTimingInvalid {
                object: CanaryCleanupObjectRole::Selector,
            }
        );

        let mut report_removed_before_delivery = fixture.successful_evidence();
        let final_delivery_observed_at = report_removed_before_delivery
            .flows
            .slots
            .iter()
            .flatten()
            .filter_map(|flow| {
                flow.inbound_listener_delivery
                    .as_ref()
                    .and_then(UnqualifiedCanaryInboundListenerDeliveryEvidence::delivery_event)
                    .map(|event| event.observed_at)
            })
            .max()
            .expect("dual-stack fixture has authoritative delivery events");
        supervised_report_retirement_mut(&mut report_removed_before_delivery).retired_at =
            final_delivery_observed_at - Duration::from_nanos(1);
        assert_eq!(
            validate(&fixture, report_removed_before_delivery)
                .expect_err("the report object must survive the final delivery event"),
            CanaryEvidenceError::CleanupListenerDeliveryReportRetiredBeforeFinalDelivery
        );

        let mut counters_removed_before_readback = fixture.successful_evidence();
        counters_removed_before_readback
            .cleanup
            .counters_retirement
            .retired_at =
            counters_removed_before_readback.counters.after_observed_at - Duration::from_nanos(1);
        assert_eq!(
            validate(&fixture, counters_removed_before_readback)
                .expect_err("counter removal cannot precede final readback"),
            CanaryEvidenceError::CleanupCountersRetiredBeforeFinalObservation
        );

        let mut object_removed_before_client_reap = fixture.successful_evidence();
        let client_reaped_at = object_removed_before_client_reap.cleanup.client.reaped_at;
        selector_retirement_mut(&mut object_removed_before_client_reap).retired_at =
            client_reaped_at - Duration::from_nanos(1);
        assert_eq!(
            validate(&fixture, object_removed_before_client_reap)
                .expect_err("attempt objects remain until the client is reaped"),
            CanaryEvidenceError::CleanupObjectRetiredBeforeClientReap {
                object: CanaryCleanupObjectRole::Selector,
            }
        );

        let mut selector_removed_before_attempt_settlement = fixture.successful_evidence();
        let retained_facility_observed_at = selector_removed_before_attempt_settlement
            .cleanup
            .retained_facility_observed_at;
        let selector = selector_retirement_mut(&mut selector_removed_before_attempt_settlement);
        selector.retired_at = retained_facility_observed_at - Duration::from_nanos(1);
        selector.absent_observed_at = retained_facility_observed_at;
        assert_eq!(
            validate(&fixture, selector_removed_before_attempt_settlement)
                .expect_err("the outer selector guard remains through attempt-local cleanup"),
            CanaryEvidenceError::CleanupSelectorRetiredBeforeAttemptSettlement
        );

        let mut peer_stopped_before_object_removal = fixture.successful_evidence();
        let report_absent_observed_at =
            supervised_report_retirement_mut(&mut peer_stopped_before_object_removal)
                .absent_observed_at;
        peer_stopped_before_object_removal.cleanup.peer_servers[0].quiesced_at =
            report_absent_observed_at - Duration::from_nanos(1);
        assert_eq!(
            validate(&fixture, peer_stopped_before_object_removal)
                .expect_err("peer servers remain live until attempt objects are absent"),
            CanaryEvidenceError::CleanupPeerServerQuiescedBeforeObjectAbsence { slot: 0 }
        );

        let mut engine_process_reused = fixture.successful_evidence();
        let engine = fixture.request.pre_binding.engine.engine();
        engine_process_reused.cleanup.client.process = CanaryProcessIdentity::new(
            NonZeroU32::new(engine.pid()).expect("engine PID is nonzero"),
            NonZeroU64::new(engine.start_time_ticks()).expect("engine start ticks are nonzero"),
        );
        assert_eq!(
            validate(&fixture, engine_process_reused)
                .expect_err("cleanup roles cannot reuse the supervised engine identity"),
            CanaryEvidenceError::CleanupProcessIdentityCollision
        );

        let mut facility_observed_before_settlement = fixture.successful_evidence();
        facility_observed_before_settlement
            .cleanup
            .retained_facility_observed_at =
            facility_observed_before_settlement.cleanup.peer_servers[CANARY_PEER_SERVER_SLOTS - 1]
                .reaped_at
                - Duration::from_nanos(1);
        assert_eq!(
            validate(&fixture, facility_observed_before_settlement)
                .expect_err("facility readback must follow complete attempt cleanup"),
            CanaryEvidenceError::CleanupFacilityObservedBeforeSettlement
        );

        let mut cleanup_after_gate = fixture.successful_evidence();
        cleanup_after_gate.cleanup.retained_facility_observed_at =
            cleanup_after_gate.completed_at + Duration::from_nanos(1);
        assert_eq!(
            validate(&fixture, cleanup_after_gate)
                .expect_err("cleanup evidence cannot postdate gate completion"),
            CanaryEvidenceError::CleanupTimingAfterGateCompletion
        );

        let mut cleanup_at_deadline = fixture.successful_evidence();
        cleanup_at_deadline.cleanup.retained_facility_observed_at =
            fixture.request.deadline().expires_at();
        assert_eq!(
            validate(&fixture, cleanup_at_deadline).expect_err("the cleanup deadline is exclusive"),
            CanaryEvidenceError::CleanupTimingAtOrAfterDeadline
        );
    }

    #[test]
    fn attempt_object_roles_must_have_distinct_identities() {
        let identity = CanaryAttemptObjectIdentity::new([1; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES])
            .expect("nonzero attempt object identity");
        assert_eq!(
            CanaryAttemptObjectIdentities::new(
                GenerationId::INITIAL,
                CanaryNonce::from_bytes([2; FUNCTIONAL_CANARY_NONCE_BYTES]),
                identity,
                identity,
                CanaryAttemptObjectIdentity::new([4; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES])
                    .expect("report identity"),
            ),
            Err(CanaryBindingError::AttemptObjectIdentityCollision)
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

    #[test]
    fn route_shape_rejects_zero_identity_fields_but_allows_universe_scope() {
        let table = RouteTableId::from_raw(10_201);
        let protocol = RouteProtocol::from_raw(99);
        let scope = RouteScope::from_raw(0);
        let metric = NonZeroU32::new(100).expect("nonzero route metric");
        assert_eq!(
            CanaryRouteShape::new(RouteTableId::from_raw(0), protocol, scope, metric),
            Err(CanaryBindingError::ZeroCanaryRouteTable)
        );
        assert_eq!(
            CanaryRouteShape::new(table, RouteProtocol::from_raw(0), scope, metric),
            Err(CanaryBindingError::ZeroCanaryRouteProtocol)
        );

        let shape = CanaryRouteShape::new(table, protocol, scope, metric)
            .expect("zero is the valid universe scope");
        assert_eq!(shape.table(), table);
        assert_eq!(shape.protocol(), protocol);
        assert_eq!(shape.scope(), scope);
        assert_eq!(shape.route_type(), RouteType::from_raw(1));
        assert_eq!(shape.metric(), metric);
    }

    #[test]
    fn peer_veth_topology_enforces_family_widths_and_preserves_exact_shape() {
        let daemon_to_peer = fixture_route_shape(10_201, 100);
        let peer_to_daemon = fixture_route_shape(10_202, 101);
        assert_eq!(
            CanaryVethFamilyTopology::ipv4(0, 32, daemon_to_peer, peer_to_daemon),
            Err(CanaryBindingError::InvalidIpv4VethPrefixLength)
        );
        assert_eq!(
            CanaryVethFamilyTopology::ipv4(33, 32, daemon_to_peer, peer_to_daemon),
            Err(CanaryBindingError::InvalidIpv4VethPrefixLength)
        );

        let ipv4 = CanaryVethFamilyTopology::ipv4(32, 31, daemon_to_peer, peer_to_daemon)
            .expect("nonzero family prefixes");
        assert_eq!(
            CanaryVethFamilyTopology::ipv6(
                128,
                129,
                fixture_route_shape(10_203, 102),
                fixture_route_shape(10_204, 103),
            ),
            Err(CanaryBindingError::InvalidIpv6VethPrefixLength)
        );

        let ipv6 = fixture_ipv6_family_topology(10_201, 10_204);
        assert_eq!(
            CanaryPeerVethTopology::new(ipv6, Some(ipv4)),
            Err(CanaryBindingError::MismatchedVethTopologyFamily)
        );
        let topology = CanaryPeerVethTopology::new(ipv4, Some(ipv6))
            .expect("point-to-point host prefixes remain valid");
        assert_eq!(topology.ipv4(), ipv4);
        assert_eq!(topology.ipv6(), Some(ipv6));
        assert_eq!(ipv4.daemon_prefix_length(), 32);
        assert_eq!(ipv4.peer_prefix_length(), 31);
        assert_eq!(ipv4.daemon_to_peer_route(), daemon_to_peer);
        assert_eq!(ipv4.peer_to_daemon_route(), peer_to_daemon);
        assert_eq!(
            topology,
            CanaryPeerVethTopology::new(ipv4, Some(ipv6)).unwrap()
        );
    }

    #[test]
    fn facility_requires_matching_ipv6_topology_and_admission_rejects_substitution() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let environment = &fixture.request.pre_binding.environment;
        let facility = environment.facility();
        let ipv4_only_topology =
            CanaryPeerVethTopology::new(facility.peer_veth_topology().ipv4(), None)
                .expect("valid IPv4-only topology");
        assert_eq!(
            CanaryFacilityIdentity::new(
                facility.daemon_veth(),
                facility.peer_veth(),
                facility.ipv4(),
                facility.ipv6(),
                ipv4_only_topology,
                facility.ports(),
            ),
            Err(CanaryBindingError::FacilityIpv6TopologyMismatch)
        );
        assert_eq!(
            CanaryFacilityIdentity::new(
                facility.daemon_veth(),
                facility.peer_veth(),
                facility.ipv4(),
                None,
                facility.peer_veth_topology(),
                facility.ports(),
            ),
            Err(CanaryBindingError::FacilityIpv6TopologyMismatch)
        );

        let substituted_facility = CanaryFacilityIdentity::new(
            facility.daemon_veth(),
            facility.peer_veth(),
            facility.ipv4(),
            facility.ipv6(),
            fixture_peer_veth_topology(10_101, 10_300),
            facility.ports(),
        )
        .expect("valid substituted topology");
        assert_ne!(substituted_facility, facility);
        assert_eq!(
            CanaryEnvironmentBinding::new(
                environment.authority().clone(),
                CanaryAttemptCredentialBinding::new(
                    environment.probe_credentials(),
                    environment.engine_credentials(),
                    environment.credential_domain(),
                )
                .expect("fixture credential binding"),
                substituted_facility,
                environment.facility_admission(),
                environment.rpdb(),
                environment.attempt_objects(),
            ),
            Err(CanaryBindingError::FacilityAdmissionScopeMismatch)
        );
    }

    #[test]
    fn environment_rejects_ipv4_daemon_to_peer_route_outside_the_peer_table() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let environment = &fixture.request.pre_binding.environment;
        let facility = environment.facility();
        let topology = facility.peer_veth_topology();
        let ipv4 = topology.ipv4();
        let substituted_ipv4 = CanaryVethFamilyTopology::ipv4(
            ipv4.daemon_prefix_length(),
            ipv4.peer_prefix_length(),
            route_shape_with_table(ipv4.daemon_to_peer_route(), 10_999),
            ipv4.peer_to_daemon_route(),
        )
        .expect("valid substituted IPv4 route shape");
        let substituted_topology = CanaryPeerVethTopology::new(substituted_ipv4, topology.ipv6())
            .expect("valid dual-stack topology");
        let substituted_facility = facility_with_topology(facility, substituted_topology);

        assert_eq!(
            environment_with_admitted_facility(environment, substituted_facility),
            Err(CanaryBindingError::CanaryPeerRouteTableMismatch)
        );
    }

    #[test]
    fn environment_rejects_ipv6_daemon_to_peer_route_outside_the_peer_table() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let environment = &fixture.request.pre_binding.environment;
        let facility = environment.facility();
        let topology = facility.peer_veth_topology();
        let ipv6 = topology.ipv6().expect("dual-stack fixture topology");
        let substituted_ipv6 = CanaryVethFamilyTopology::ipv6(
            ipv6.daemon_prefix_length(),
            ipv6.peer_prefix_length(),
            route_shape_with_table(ipv6.daemon_to_peer_route(), 10_999),
            ipv6.peer_to_daemon_route(),
        )
        .expect("valid substituted IPv6 route shape");
        let substituted_topology =
            CanaryPeerVethTopology::new(topology.ipv4(), Some(substituted_ipv6))
                .expect("valid dual-stack topology");
        let substituted_facility = facility_with_topology(facility, substituted_topology);

        assert_eq!(
            environment_with_admitted_facility(environment, substituted_facility),
            Err(CanaryBindingError::CanaryPeerRouteTableMismatch)
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

    fn inbound_listener_delivery_mut(
        evidence: &mut UnqualifiedCanaryGateEvidence,
        flow: CanaryFlow,
    ) -> &mut UnqualifiedCanaryInboundListenerDeliveryEvidence {
        evidence.flows.slots[flow.index()]
            .as_mut()
            .expect("required flow evidence")
            .inbound_listener_delivery
            .as_mut()
            .expect("inbound listener delivery evidence")
    }

    fn tproxy_listener_mut(
        evidence: &mut UnqualifiedCanaryGateEvidence,
        flow: CanaryFlow,
    ) -> &mut CanaryTproxyListenerSocketIdentity {
        match inbound_listener_delivery_mut(evidence, flow) {
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyTcp { listener, .. }
            | UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyUdp { listener, .. } => {
                listener
            }
            UnqualifiedCanaryInboundListenerDeliveryEvidence::Redirect
            | UnqualifiedCanaryInboundListenerDeliveryEvidence::Dnat => {
                panic!("fixture uses TPROXY delivery evidence")
            }
        }
    }

    fn tproxy_tcp_delivery_mut(
        evidence: &mut UnqualifiedCanaryGateEvidence,
        flow: CanaryFlow,
    ) -> &mut CanaryTproxyAcceptedSocketDelivery {
        match inbound_listener_delivery_mut(evidence, flow) {
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyTcp { accepted, .. } => {
                accepted
            }
            _ => panic!("fixture flow uses TPROXY TCP delivery evidence"),
        }
    }

    fn tproxy_udp_delivery_mut(
        evidence: &mut UnqualifiedCanaryGateEvidence,
        flow: CanaryFlow,
    ) -> &mut CanaryTproxyUdpRecvmsgDelivery {
        match inbound_listener_delivery_mut(evidence, flow) {
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyUdp { datagram, .. } => {
                datagram
            }
            _ => panic!("fixture flow uses TPROXY UDP delivery evidence"),
        }
    }

    fn tproxy_delivery_event_mut(
        evidence: &mut UnqualifiedCanaryGateEvidence,
        flow: CanaryFlow,
    ) -> &mut CanaryInboundDeliveryEvent {
        match inbound_listener_delivery_mut(evidence, flow) {
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyTcp { accepted, .. } => {
                &mut accepted.event
            }
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyUdp { datagram, .. } => {
                &mut datagram.event
            }
            _ => panic!("fixture uses TPROXY delivery evidence"),
        }
    }

    fn tproxy_payload_mut(
        evidence: &mut UnqualifiedCanaryGateEvidence,
        flow: CanaryFlow,
    ) -> &mut CanaryInboundPayloadIdentity {
        match inbound_listener_delivery_mut(evidence, flow) {
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyTcp { accepted, .. } => {
                &mut accepted.payload
            }
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyUdp { datagram, .. } => {
                &mut datagram.payload
            }
            _ => panic!("fixture uses TPROXY delivery evidence"),
        }
    }

    fn supervised_report_retirement_mut(
        evidence: &mut UnqualifiedCanaryGateEvidence,
    ) -> &mut CanaryAttemptObjectRetirementEvidence {
        evidence
            .cleanup
            .listener_delivery_report
            .retired_mut()
            .expect("fixture uses supervised delivery-report cleanup")
    }

    fn selector_retirement_mut(
        evidence: &mut UnqualifiedCanaryGateEvidence,
    ) -> &mut CanaryAttemptObjectRetirementEvidence {
        evidence
            .cleanup
            .selector_retirement
            .as_mut()
            .expect("fixture carries selector retirement evidence")
    }

    fn qualified_cgroup_bpf_observer() -> CanarySocketObserverAuthority {
        CanarySocketObserverAuthority::QualifiedCgroupBpf {
            program_identity: CanaryAttemptObjectIdentity::new(
                [17; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES],
            )
            .expect("BPF program identity"),
            link_id: NonZeroU32::new(18).expect("BPF link ID"),
            event_map_id: NonZeroU32::new(19).expect("BPF event map ID"),
            loss_map_id: NonZeroU32::new(20).expect("BPF loss map ID"),
            cgroup_id: NonZeroU64::new(21).expect("cgroup ID"),
            event_schema_version: NonZeroU16::new(1).expect("BPF event schema"),
        }
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
                    let observer = self
                        .request
                        .pre_binding
                        .environment
                        .authority
                        .socket_observer;
                    let socket_correlation = match observer {
                        CanarySocketObserverAuthority::ProcFdInetDiag { .. } => {
                            CanarySocketCorrelation::ProcFdInetDiag {
                                observer,
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
                                diag_protocol: match flow.protocol() {
                                    CanaryFlowProtocol::Tcp => CanaryInetDiagProtocol::Tcp,
                                    CanaryFlowProtocol::Udp => CanaryInetDiagProtocol::Udp,
                                },
                                diag_tuple: evidence.peer_tuple,
                                diag_uid: self.request.pre_binding.environment.rpdb.engine_uid,
                                diag_socket_mark: 0,
                                fd_scan_complete: true,
                                diag_dump_complete: true,
                                snapshot_started_at: evidence.started_at + Duration::from_millis(1),
                                dump_started_at: evidence.started_at + Duration::from_millis(2),
                                dump_completed_at: evidence.started_at + Duration::from_millis(3),
                                snapshot_completed_at: evidence.started_at
                                    + Duration::from_millis(4),
                            }
                        }
                        CanarySocketObserverAuthority::QualifiedCgroupBpf { .. } => {
                            CanarySocketCorrelation::QualifiedCgroupBpf {
                                observer,
                                process: self.request.pre_binding.engine.engine(),
                                socket_cookie: NonZeroU64::new(
                                    80_000 + u64::try_from(index).expect("slot index fits u64"),
                                )
                                .expect("socket cookie"),
                                attempt_nonce: self.request.nonce(),
                                event_sequence: NonZeroU64::new(
                                    90_000 + u64::try_from(index).expect("slot sequence"),
                                )
                                .expect("event sequence"),
                                hook: match (flow.protocol(), flow.is_ipv4()) {
                                    (CanaryFlowProtocol::Tcp, true) => {
                                        CanaryBpfSocketHook::ConnectIpv4
                                    }
                                    (CanaryFlowProtocol::Tcp, false) => {
                                        CanaryBpfSocketHook::ConnectIpv6
                                    }
                                    (CanaryFlowProtocol::Udp, true) => {
                                        CanaryBpfSocketHook::SendMessageIpv4
                                    }
                                    (CanaryFlowProtocol::Udp, false) => {
                                        CanaryBpfSocketHook::SendMessageIpv6
                                    }
                                },
                                lost_events_before: 0,
                                lost_events_after: 0,
                                observed_at: evidence.started_at + Duration::from_millis(2),
                            }
                        }
                    };
                    UnqualifiedCanaryOutboundEvidence::new(
                        flow,
                        evidence.peer_tuple,
                        socket_correlation,
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
                    UnqualifiedCanaryNegativeRouteControl::new(
                        flow,
                        SocketAddr::new(
                            self.request.peer_address(flow),
                            self.request.responder_port(flow).get(),
                        ),
                        self.request.deadline().started_at() + Duration::from_millis(1),
                        self.request.pre_binding.environment.rpdb.engine_uid,
                        self.request.pre_binding.environment.rpdb.proxy_mark_value,
                        self.request
                            .pre_binding
                            .environment
                            .rpdb
                            .proxy_capture_table,
                        None,
                    )
                })
            });
            let loop_escape = UnqualifiedCanaryLoopEvidence::new(
                UnqualifiedCanaryOutboundEvidenceSlots::new(outbound),
                UnqualifiedCanaryNegativeRouteControlSlots::new(negative_route_controls),
            );
            let counters = counter_evidence(&self.request);
            let cleanup = cleanup_evidence(&self.request);
            let completed_at = self.request.deadline().started_at() + Duration::from_millis(205);
            let local_output_capture_receipt =
                local_output::TproxyLocalOutputCaptureReceipt::scripted(&self.request, &flows);
            let local_output_process_ownership_receipt =
                local_output::TproxyLocalOutputProcessOwnershipReceipt::scripted(
                    &self.request,
                    &flows,
                    &cleanup,
                    completed_at,
                );
            UnqualifiedCanaryGateEvidence::new(
                self.request.clone(),
                local_output_capture_receipt,
                local_output_process_ownership_receipt,
                completed_at,
                flows,
                0,
                loop_escape,
                counters,
                cleanup,
            )
        }

        pub(crate) fn successful_evidence_without_selector_retirement(
            &self,
        ) -> UnqualifiedCanaryGateEvidence {
            let mut evidence = self.successful_evidence();
            evidence.cleanup.selector_retirement = None;
            evidence
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
            GenerationId::new(17).expect("nonzero generation"),
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
        generation: GenerationId,
        pid: NonZeroU32,
        start_time_ticks: NonZeroU64,
        engine_snapshot_revision: NonZeroU64,
    ) -> CanaryAttemptRequest {
        request_with_engine_profile_revision(
            spec,
            families,
            started_at,
            nonce,
            generation,
            pid,
            start_time_ticks,
            engine_snapshot_revision,
            EngineCapabilityProfileRevision::from_fixture_bytes([0x51; 32]),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn request_with_engine_identity_and_network_namespaces(
        spec: &EngineSpec,
        families: CanaryAddressFamilies,
        started_at: Instant,
        nonce: CanaryNonce,
        generation: GenerationId,
        pid: NonZeroU32,
        start_time_ticks: NonZeroU64,
        engine_snapshot_revision: NonZeroU64,
        daemon_network_namespace: NetworkNamespaceIdentity,
        peer_network_namespace: NetworkNamespaceIdentity,
    ) -> CanaryAttemptRequest {
        request_with_engine_profile_revision_and_duration_and_network_namespaces(
            spec,
            families,
            started_at,
            nonce,
            generation,
            pid,
            start_time_ticks,
            engine_snapshot_revision,
            EngineCapabilityProfileRevision::from_fixture_bytes([0x51; 32]),
            Duration::from_secs(2),
            daemon_network_namespace,
            peer_network_namespace,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn request_with_engine_profile_revision(
        spec: &EngineSpec,
        families: CanaryAddressFamilies,
        started_at: Instant,
        nonce: CanaryNonce,
        generation: GenerationId,
        pid: NonZeroU32,
        start_time_ticks: NonZeroU64,
        engine_snapshot_revision: NonZeroU64,
        engine_profile_revision: EngineCapabilityProfileRevision,
    ) -> CanaryAttemptRequest {
        request_with_engine_profile_revision_and_duration(
            spec,
            families,
            started_at,
            nonce,
            generation,
            pid,
            start_time_ticks,
            engine_snapshot_revision,
            engine_profile_revision,
            Duration::from_secs(2),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn request_with_engine_profile_revision_and_duration(
        spec: &EngineSpec,
        families: CanaryAddressFamilies,
        started_at: Instant,
        nonce: CanaryNonce,
        generation: GenerationId,
        pid: NonZeroU32,
        start_time_ticks: NonZeroU64,
        engine_snapshot_revision: NonZeroU64,
        engine_profile_revision: EngineCapabilityProfileRevision,
        duration: Duration,
    ) -> CanaryAttemptRequest {
        request_with_engine_profile_revision_and_duration_and_network_namespaces(
            spec,
            families,
            started_at,
            nonce,
            generation,
            pid,
            start_time_ticks,
            engine_snapshot_revision,
            engine_profile_revision,
            duration,
            NetworkNamespaceIdentity::new(1, 101).expect("daemon namespace"),
            NetworkNamespaceIdentity::new(1, 102).expect("peer namespace"),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn request_with_engine_profile_revision_and_duration_and_network_namespaces(
        spec: &EngineSpec,
        families: CanaryAddressFamilies,
        started_at: Instant,
        nonce: CanaryNonce,
        generation: GenerationId,
        pid: NonZeroU32,
        start_time_ticks: NonZeroU64,
        engine_snapshot_revision: NonZeroU64,
        engine_profile_revision: EngineCapabilityProfileRevision,
        duration: Duration,
        daemon_network_namespace: NetworkNamespaceIdentity,
        peer_network_namespace: NetworkNamespaceIdentity,
    ) -> CanaryAttemptRequest {
        let listener_port = match spec.process().readiness {
            SingBoxReadiness::Listener { port } => port,
            SingBoxReadiness::TunInterface { .. } => {
                panic!("functional canary fixture requires listener readiness")
            }
        };
        let readiness = ReadinessEvidence::Listener {
            port: listener_port,
            table: PathBuf::from(format!("/proc/{}/net/tcp", pid.get())),
        };
        let engine = CanaryEngineBinding::from_identity_parts(
            generation,
            pid,
            start_time_ticks,
            engine_snapshot_revision,
            engine_profile_revision,
            spec,
            &readiness,
        )
        .expect("exact engine binding");
        let environment = environment_with_network_namespaces(
            generation,
            nonce,
            started_at,
            daemon_network_namespace,
            peer_network_namespace,
        );
        CanaryAttemptRequest::new(
            CanaryAttemptBinding::new(engine, environment),
            nonce,
            CanaryDeadline::new(started_at, duration).expect("valid deadline"),
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

    fn fixture_route_shape(table: u32, metric: u32) -> CanaryRouteShape {
        CanaryRouteShape::new(
            RouteTableId::from_raw(table),
            RouteProtocol::from_raw(99),
            RouteScope::from_raw(0),
            NonZeroU32::new(metric).expect("nonzero fixture route metric"),
        )
        .expect("valid fixture route shape")
    }

    fn route_shape_with_table(shape: CanaryRouteShape, table: u32) -> CanaryRouteShape {
        CanaryRouteShape::new(
            RouteTableId::from_raw(table),
            shape.protocol(),
            shape.scope(),
            shape.metric(),
        )
        .expect("valid substituted route table")
    }

    fn facility_with_topology(
        facility: CanaryFacilityIdentity,
        topology: CanaryPeerVethTopology,
    ) -> CanaryFacilityIdentity {
        CanaryFacilityIdentity::new(
            facility.daemon_veth(),
            facility.peer_veth(),
            facility.ipv4(),
            facility.ipv6(),
            topology,
            facility.ports(),
        )
        .expect("valid substituted facility topology")
    }

    fn environment_with_admitted_facility(
        environment: &CanaryEnvironmentBinding,
        facility: CanaryFacilityIdentity,
    ) -> Result<CanaryEnvironmentBinding, CanaryBindingError> {
        let mut admission = environment.facility_admission();
        admission.scope.facility = facility;
        CanaryEnvironmentBinding::new(
            environment.authority().clone(),
            CanaryAttemptCredentialBinding::new(
                environment.probe_credentials(),
                environment.engine_credentials(),
                environment.credential_domain(),
            )
            .expect("fixture credential binding"),
            facility,
            admission,
            environment.rpdb(),
            environment.attempt_objects(),
        )
    }

    fn fixture_ipv4_family_topology(
        peer_table: u32,
        reverse_table: u32,
    ) -> CanaryVethFamilyTopology {
        CanaryVethFamilyTopology::ipv4(
            32,
            32,
            fixture_route_shape(peer_table, 100),
            fixture_route_shape(reverse_table, 101),
        )
        .expect("valid fixture IPv4 topology")
    }

    fn fixture_ipv6_family_topology(
        peer_table: u32,
        reverse_table: u32,
    ) -> CanaryVethFamilyTopology {
        CanaryVethFamilyTopology::ipv6(
            128,
            128,
            fixture_route_shape(peer_table, 102),
            fixture_route_shape(reverse_table, 103),
        )
        .expect("valid fixture IPv6 topology")
    }

    fn fixture_peer_veth_topology(
        peer_table: u32,
        first_reverse_table: u32,
    ) -> CanaryPeerVethTopology {
        CanaryPeerVethTopology::new(
            fixture_ipv4_family_topology(peer_table, first_reverse_table),
            Some(fixture_ipv6_family_topology(
                peer_table,
                first_reverse_table + 1,
            )),
        )
        .expect("valid dual-stack fixture topology")
    }

    pub(crate) fn fixture_responder_ports() -> CanaryResponderPorts {
        CanaryResponderPorts::new(
            NonZeroU16::new(41_001).expect("TCP responder port"),
            NonZeroU16::new(41_002).expect("UDP responder port"),
            NonZeroU16::new(41_003).expect("DNS responder port"),
        )
        .expect("same-protocol responder ports are distinct")
    }

    pub(crate) fn active_generation_binding(
        generation: GenerationId,
    ) -> ActiveCanaryGenerationBinding {
        let environment = environment(
            generation,
            CanaryNonce::from_bytes([7; FUNCTIONAL_CANARY_NONCE_BYTES]),
            Instant::now(),
        );
        ActiveCanaryGenerationBinding::from_environment_fixture(&environment)
    }

    fn environment(
        generation: GenerationId,
        nonce: CanaryNonce,
        attempt_started_at: Instant,
    ) -> CanaryEnvironmentBinding {
        environment_with_network_namespaces(
            generation,
            nonce,
            attempt_started_at,
            NetworkNamespaceIdentity::new(1, 101).expect("daemon namespace"),
            NetworkNamespaceIdentity::new(1, 102).expect("peer namespace"),
        )
    }

    fn environment_with_network_namespaces(
        generation: GenerationId,
        nonce: CanaryNonce,
        attempt_started_at: Instant,
        daemon_network_namespace: NetworkNamespaceIdentity,
        peer_network_namespace: NetworkNamespaceIdentity,
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
            fixture_peer_veth_topology(10_101, 10_200),
            fixture_responder_ports(),
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
            CanaryAttemptObjectIdentity::new([7; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES])
                .expect("counter identity"),
            CanaryAttemptObjectIdentity::new([15; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES])
                .expect("listener delivery report identity"),
        )
        .expect("distinct attempt object identities");
        let network = CanaryNetworkObservationBinding::new(
            daemon_network_namespace,
            peer_network_namespace,
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
            CanarySocketObserverBinding::scripted(
                CanarySocketObserverAuthority::ProcFdInetDiag {
                    collector_identity: CanaryAttemptObjectIdentity::new(
                        [12; CANARY_ATTEMPT_OBJECT_IDENTITY_BYTES],
                    )
                    .expect("socket observer identity"),
                    collector_revision: NonZeroU64::new(13).expect("collector revision"),
                    netlink_port_id: NonZeroU32::new(14).expect("netlink port ID"),
                },
                NonZeroU64::new(15).expect("socket observer opening ID"),
            ),
        );
        CanaryEnvironmentBinding::new(
            authority,
            CanaryAttemptCredentialBinding::new(
                CanaryProcessCredentialIdentity::new(
                    NonZeroU32::new(20_002).expect("probe UID"),
                    NonZeroU32::new(20_002).expect("probe GID"),
                ),
                CanaryProcessCredentialIdentity::new(
                    rpdb.engine_uid,
                    NonZeroU32::new(20_001).expect("engine GID"),
                ),
                CanaryCredentialDomainBinding::observed(
                    CanaryFileIdentity::new(60, NonZeroU64::new(61).expect("user namespace inode")),
                    CanaryFileIdentity::new(
                        60,
                        NonZeroU64::new(62).expect("mount namespace inode"),
                    ),
                    CanaryCredentialMapDigest::new([16; CANARY_CREDENTIAL_MAP_DIGEST_BYTES])
                        .expect("UID map digest"),
                    CanaryCredentialMapDigest::new([17; CANARY_CREDENTIAL_MAP_DIGEST_BYTES])
                        .expect("GID map digest"),
                )
                .expect("distinct credential namespace identities"),
            )
            .expect("distinct role credentials"),
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
        let started_at = request.deadline().started_at();
        UnqualifiedCanaryCleanupEvidence::new(
            request.nonce(),
            CanaryProcessRetirementEvidence::new(
                process(60_001, 70_001),
                started_at + Duration::from_millis(110),
                started_at + Duration::from_millis(111),
                started_at + Duration::from_millis(112),
            ),
            [
                CanaryProcessRetirementEvidence::new(
                    process(60_002, 70_002),
                    started_at + Duration::from_millis(130),
                    started_at + Duration::from_millis(131),
                    started_at + Duration::from_millis(132),
                ),
                CanaryProcessRetirementEvidence::new(
                    process(60_003, 70_003),
                    started_at + Duration::from_millis(133),
                    started_at + Duration::from_millis(134),
                    started_at + Duration::from_millis(135),
                ),
                CanaryProcessRetirementEvidence::new(
                    process(60_004, 70_004),
                    started_at + Duration::from_millis(136),
                    started_at + Duration::from_millis(137),
                    started_at + Duration::from_millis(138),
                ),
            ],
            Some(CanaryAttemptObjectRetirementEvidence::new(
                request.pre_binding.environment.attempt_objects.selector(),
                started_at + Duration::from_millis(201),
                started_at + Duration::from_millis(202),
            )),
            CanaryAttemptObjectRetirementEvidence::new(
                request.pre_binding.environment.attempt_objects.counters(),
                started_at + Duration::from_millis(118),
                started_at + Duration::from_millis(122),
            ),
            CanaryListenerDeliveryReportCleanupEvidence::retired(
                CanaryAttemptObjectRetirementEvidence::new(
                    request
                        .pre_binding
                        .environment
                        .attempt_objects
                        .listener_delivery_report(),
                    started_at + Duration::from_millis(119),
                    started_at + Duration::from_millis(123),
                ),
            ),
            request.pre_binding.environment.facility,
            started_at + Duration::from_millis(150),
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
        let payload = expected_inbound_payload_identity(request, flow);
        let listener_slot = flow.inbound_listener_slot();
        let listener_slot_u32 = u32::try_from(listener_slot).expect("listener slot fits u32");
        let listener_slot_u64 = u64::try_from(listener_slot).expect("listener slot fits u64");
        let flow_index_u32 = u32::try_from(index).expect("flow index fits u32");
        let flow_index_u64 = u64::try_from(index).expect("flow index fits u64");
        let listener_cookie =
            CanaryInetDiagCookie::new(10, listener_slot_u32 + 1).expect("fixture listener cookie");
        let listener_port = request.pre_binding.engine.listener().port().get();
        let bind = if flow.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listener_port)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), listener_port)
        };
        let observer = request.pre_binding.environment.authority.socket_observer;
        let observation = match observer {
            CanarySocketObserverAuthority::ProcFdInetDiag { .. } => {
                let role_sequences = [1, 5, 3, 6].map(|sequence| {
                    NonZeroU64::new(sequence).expect("listener role dump sequence")
                });
                let snapshot = CanaryInetDiagListenerSnapshot::new(
                    request
                        .pre_binding
                        .environment
                        .authority
                        .socket_observer_binding(),
                    request.pre_binding.engine.engine(),
                    request.pre_binding.engine.listener.port,
                    request.deadline().started_at(),
                    request.deadline().started_at() + Duration::from_millis(1),
                    NonZeroU64::new(1).expect("first listener dump sequence"),
                    NonZeroU64::new(6).expect("last listener dump sequence"),
                    role_sequences,
                );
                CanaryListenerSocketObservation::from_complete_inet_diag_snapshot(
                    observer,
                    snapshot.role_sequence(flow),
                    snapshot,
                )
            }
            CanarySocketObserverAuthority::QualifiedCgroupBpf { .. } => {
                CanaryListenerSocketObservation::from_event_counter(
                    observer,
                    NonZeroU64::new(100 + listener_slot_u64)
                        .expect("listener observation sequence"),
                    4,
                    4,
                    request.deadline().started_at() + Duration::from_millis(1),
                )
            }
        };
        let listener = CanaryTproxyListenerSocketIdentity::new(
            request.pre_binding.engine.generation(),
            request.pre_binding.engine.engine(),
            request.pre_binding.engine.listener().clone(),
            request
                .pre_binding
                .environment
                .authority
                .network
                .daemon_network_namespace,
            request
                .pre_binding
                .environment
                .authority
                .capture_program_digest,
            request.pre_binding.environment.attempt_objects.selector,
            flow.protocol(),
            flow.address_family(),
            CanaryProcFd::new(10 + listener_slot_u32).expect("fixture listener fd"),
            NonZeroU64::new(70_000 + listener_slot_u64).expect("fixture listener inode"),
            listener_cookie,
            bind,
            true,
            (!flow.is_ipv4()).then_some(true),
            observation,
        );
        let delivery_event = CanaryInboundDeliveryEvent::new(
            CanaryInboundDeliveryAuthority::SupervisedEngineReport {
                engine: request.pre_binding.engine.engine(),
                engine_profile_revision: request.pre_binding.engine.engine_profile_revision(),
                report_object: request
                    .pre_binding
                    .environment
                    .attempt_objects
                    .listener_delivery_report,
                schema_version: NonZeroU16::new(ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION)
                    .expect("listener delivery report schema is nonzero"),
            },
            NonZeroU64::new(1_000 + flow_index_u64).expect("delivery event sequence"),
            4,
            4,
            started_at + Duration::from_millis(1),
        );
        let inbound_listener_delivery = match flow.protocol() {
            CanaryFlowProtocol::Tcp => {
                UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyTcp {
                    listener,
                    accepted: CanaryTproxyAcceptedSocketDelivery::new(
                        flow,
                        request.pre_binding.engine.engine(),
                        listener_cookie,
                        CanaryProcFd::new(100 + flow_index_u32).expect("accepted socket fd"),
                        NonZeroU64::new(80_000 + flow_index_u64).expect("accepted socket inode"),
                        CanaryInetDiagCookie::new(20, flow_index_u32 + 1)
                            .expect("accepted socket cookie"),
                        client_tuple.destination(),
                        client_tuple.source(),
                        delivery_event,
                        payload,
                    ),
                }
            }
            CanaryFlowProtocol::Udp => {
                let original_destination_cmsg = if flow.is_ipv4() {
                    CanaryOriginalDestinationCmsg::Ipv4 { payload_length: 16 }
                } else {
                    CanaryOriginalDestinationCmsg::Ipv6 { payload_length: 28 }
                };
                UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyUdp {
                    listener,
                    datagram: CanaryTproxyUdpRecvmsgDelivery::new(
                        flow,
                        listener_cookie,
                        client_tuple.source(),
                        client_tuple.destination(),
                        false,
                        false,
                        1,
                        original_destination_cmsg,
                        delivery_event,
                        payload,
                    ),
                }
            }
        };
        UnqualifiedCanaryFlowEvidence::new(
            flow,
            request.nonce(),
            request.nonce(),
            request.nonce(),
            client_tuple,
            peer_tuple,
            started_at,
            started_at + Duration::from_millis(5),
            Some(inbound_listener_delivery),
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
                    privilege: SingBoxPrivilege::Inherit,
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
