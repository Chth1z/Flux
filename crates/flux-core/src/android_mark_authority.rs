use std::error::Error;
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};
use std::ops::{BitOr, BitOrAssign};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::android_rpdb::AndroidRpdbClassificationReport;
use crate::android_tproxy_topology::{
    AndroidTproxyRoutingShape, AndroidTproxyTopologyScopeReport,
    AndroidTproxyTopologyScopeStructuralFeasibility, DeferredAndroidTproxyPrerequisite,
    StaleAndroidTproxyTopologyScopeReport,
};
use crate::capability::{
    BootIdentity, CapabilityProfile, CapabilityProfileRevision, NetworkNamespaceIdentity,
    ObservationKind,
};
use crate::fwmark_audit::{
    FwmarkCandidate, FwmarkEvidenceSource, FwmarkEvidenceState, FwmarkPartialAudit,
    FwmarkPartialAuditOutcome, audit_fwmark_candidate_partial,
};
use crate::network_inventory::{NetworkEpoch, NetworkInventory, NetworkInventorySnapshotId};

/// Device-policy mark bits that are structurally eligible for this checkpoint.
///
/// This is the inclusive bit range 21 through 30. Membership in this range is only a structural
/// syntactic prerequisite. It does not claim that generic AOSP or any vendor reserves these bits
/// for Flux; a positive exact device policy, partial audit, and complete live census remain
/// mandatory and can still reject the field.
pub const ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK: u32 = 0x7fe0_0000;
/// Maximum UTF-8 bytes accepted for a device-qualified policy name.
pub const MAX_ANDROID_MARK_DEVICE_POLICY_NAME_BYTES: usize = 128;
/// Exact byte length of a SHA-256 device-policy artifact digest.
pub const ANDROID_MARK_DEVICE_POLICY_ARTIFACT_DIGEST_BYTES: usize = 32;
/// Exact byte length of a durable ownership-journal identity.
pub const OWNERSHIP_JOURNAL_IDENTITY_BYTES: usize = 32;
/// Maximum raw mark-use records accepted by one complete point-in-time census.
pub const MAX_COMPLETE_FWMARK_CENSUS_MARK_USES: usize = 512;

const ALL_FWMARK_EVIDENCE_SOURCES: [FwmarkEvidenceSource; 9] = [
    FwmarkEvidenceSource::AndroidNetId,
    FwmarkEvidenceSource::Rpdb,
    FwmarkEvidenceSource::DeviceMarkPolicy,
    FwmarkEvidenceSource::LegacyXtables,
    FwmarkEvidenceSource::Nftables,
    FwmarkEvidenceSource::TrafficControlAndBpf,
    FwmarkEvidenceSource::Xfrm,
    FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
    FwmarkEvidenceSource::ExistingFluxOwnership,
];

const ALL_FWMARK_PLANES: [FwmarkPlane; 3] = [
    FwmarkPlane::Packet,
    FwmarkPlane::Socket,
    FwmarkPlane::Conntrack,
];

/// Exact number of source-plane coverage records required by a complete census.
pub const COMPLETE_FWMARK_CENSUS_COVERAGE_RECORDS: usize =
    ALL_FWMARK_EVIDENCE_SOURCES.len() * ALL_FWMARK_PLANES.len();

const DEFERRED_ANDROID_MARK_ACTIVATION_PREREQUISITES: [DeferredAndroidMarkActivationPrerequisite;
    3] = [
    DeferredAndroidMarkActivationPrerequisite::ExactWriterSemantics,
    DeferredAndroidMarkActivationPrerequisite::ObserverContinuity,
    DeferredAndroidMarkActivationPrerequisite::MarkPreservationCanary,
];

const REMAINING_COMMON_ANDROID_TPROXY_PREREQUISITES: [DeferredAndroidTproxyPrerequisite; 8] = [
    DeferredAndroidTproxyPrerequisite::ExactCaptureOrdering,
    DeferredAndroidTproxyPrerequisite::DomainIdentityHandoff,
    DeferredAndroidTproxyPrerequisite::NetworkSelectionHandoff,
    DeferredAndroidTproxyPrerequisite::RouteReachabilityCanary,
    DeferredAndroidTproxyPrerequisite::ObserverContinuity,
    DeferredAndroidTproxyPrerequisite::DurableOwnershipJournal,
    DeferredAndroidTproxyPrerequisite::ExactMutationIdentity,
    DeferredAndroidTproxyPrerequisite::EngineLoopEscape,
];

const REMAINING_PRE_MARK_ANDROID_TPROXY_PREREQUISITES: [DeferredAndroidTproxyPrerequisite; 9] = [
    DeferredAndroidTproxyPrerequisite::OneRuleAddressHandling,
    DeferredAndroidTproxyPrerequisite::ExactCaptureOrdering,
    DeferredAndroidTproxyPrerequisite::DomainIdentityHandoff,
    DeferredAndroidTproxyPrerequisite::NetworkSelectionHandoff,
    DeferredAndroidTproxyPrerequisite::RouteReachabilityCanary,
    DeferredAndroidTproxyPrerequisite::ObserverContinuity,
    DeferredAndroidTproxyPrerequisite::DurableOwnershipJournal,
    DeferredAndroidTproxyPrerequisite::ExactMutationIdentity,
    DeferredAndroidTproxyPrerequisite::EngineLoopEscape,
];

static NEXT_COMPLETE_FWMARK_CENSUS_OBSERVATION_ID: AtomicU64 = AtomicU64::new(1);

/// Exact nonzero identity of the durable Flux ownership-journal artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OwnershipJournalIdentity([u8; OWNERSHIP_JOURNAL_IDENTITY_BYTES]);

impl OwnershipJournalIdentity {
    pub const fn new(
        bytes: [u8; OWNERSHIP_JOURNAL_IDENTITY_BYTES],
    ) -> Result<Self, OwnershipJournalIdentityError> {
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0 {
                return Ok(Self(bytes));
            }
            index += 1;
        }
        Err(OwnershipJournalIdentityError::AllZero)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; OWNERSHIP_JOURNAL_IDENTITY_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipJournalIdentityError {
    AllZero,
}

impl fmt::Display for OwnershipJournalIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ownership-journal identity is all zero")
    }
}

impl Error for OwnershipJournalIdentityError {}

/// Monotonic revision of the exact durable Flux ownership journal observed by a collector.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OwnershipJournalRevision(NonZeroU64);

impl OwnershipJournalRevision {
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Revision of the bounded collector grammar that produced a complete fwmark census.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FwmarkCensusCollectorRevision(NonZeroU64);

impl FwmarkCensusCollectorRevision {
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Revision of one explicitly selected Android device mark policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AndroidMarkDevicePolicyRevision(NonZeroU64);

impl AndroidMarkDevicePolicyRevision {
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Validated device-qualified cooperative policy name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AndroidMarkDevicePolicyName(Box<str>);

impl AndroidMarkDevicePolicyName {
    pub fn new(value: &str) -> Result<Self, AndroidMarkDevicePolicyNameError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(AndroidMarkDevicePolicyNameError::Empty);
        }
        if value.len() > MAX_ANDROID_MARK_DEVICE_POLICY_NAME_BYTES {
            return Err(AndroidMarkDevicePolicyNameError::TooLong {
                maximum: MAX_ANDROID_MARK_DEVICE_POLICY_NAME_BYTES,
                actual: value.len(),
            });
        }
        if value.chars().any(char::is_control) {
            return Err(AndroidMarkDevicePolicyNameError::ControlCharacter);
        }
        Ok(Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidMarkDevicePolicyNameError {
    Empty,
    TooLong { maximum: usize, actual: usize },
    ControlCharacter,
}

impl fmt::Display for AndroidMarkDevicePolicyNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("Android mark device policy name is empty"),
            Self::TooLong { maximum, actual } => write!(
                formatter,
                "Android mark device policy name is {actual} bytes but its limit is {maximum}"
            ),
            Self::ControlCharacter => {
                formatter.write_str("Android mark device policy name contains a control character")
            }
        }
    }
}

impl Error for AndroidMarkDevicePolicyNameError {}

/// Exact nonzero SHA-256 digest of the reviewed device-policy artifact that asserts cooperation
/// with Flux.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AndroidMarkDevicePolicyArtifactDigest(
    [u8; ANDROID_MARK_DEVICE_POLICY_ARTIFACT_DIGEST_BYTES],
);

impl AndroidMarkDevicePolicyArtifactDigest {
    pub const fn new(
        bytes: [u8; ANDROID_MARK_DEVICE_POLICY_ARTIFACT_DIGEST_BYTES],
    ) -> Result<Self, AndroidMarkDevicePolicyArtifactDigestError> {
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0 {
                return Ok(Self(bytes));
            }
            index += 1;
        }
        Err(AndroidMarkDevicePolicyArtifactDigestError::AllZero)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ANDROID_MARK_DEVICE_POLICY_ARTIFACT_DIGEST_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidMarkDevicePolicyArtifactDigestError {
    AllZero,
}

impl fmt::Display for AndroidMarkDevicePolicyArtifactDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Android mark device-policy artifact digest is all zero")
    }
}

impl Error for AndroidMarkDevicePolicyArtifactDigestError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidMarkDevicePolicyKind {
    /// Generic AOSP supplies no public mark allocator and therefore grants no field.
    GenericAospNoGrant,
    /// An explicitly named, device-qualified integration cooperates with Flux.
    DeviceQualifiedCooperative,
}

/// Stable identity of the exact policy whose evidence was observed.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AndroidMarkDevicePolicyIdentity {
    kind: AndroidMarkDevicePolicyKind,
    name: Option<AndroidMarkDevicePolicyName>,
    artifact_digest: Option<AndroidMarkDevicePolicyArtifactDigest>,
}

impl AndroidMarkDevicePolicyIdentity {
    const fn generic_aosp() -> Self {
        Self {
            kind: AndroidMarkDevicePolicyKind::GenericAospNoGrant,
            name: None,
            artifact_digest: None,
        }
    }

    fn device_qualified_cooperative(
        name: AndroidMarkDevicePolicyName,
        artifact_digest: AndroidMarkDevicePolicyArtifactDigest,
    ) -> Self {
        Self {
            kind: AndroidMarkDevicePolicyKind::DeviceQualifiedCooperative,
            name: Some(name),
            artifact_digest: Some(artifact_digest),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> AndroidMarkDevicePolicyKind {
        self.kind
    }

    #[must_use]
    pub const fn name(&self) -> Option<&AndroidMarkDevicePolicyName> {
        self.name.as_ref()
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> Option<AndroidMarkDevicePolicyArtifactDigest> {
        self.artifact_digest
    }
}

/// Kernel mark storage plane covered by grants and complete census evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum FwmarkPlane {
    Packet = 1 << 0,
    Socket = 1 << 1,
    Conntrack = 1 << 2,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FwmarkPlaneSet(u8);

impl FwmarkPlaneSet {
    pub const NONE: Self = Self(0);
    pub const PACKET: Self = Self(FwmarkPlane::Packet as u8);
    pub const SOCKET: Self = Self(FwmarkPlane::Socket as u8);
    pub const CONNTRACK: Self = Self(FwmarkPlane::Conntrack as u8);
    pub const ALL: Self = Self(Self::PACKET.0 | Self::SOCKET.0 | Self::CONNTRACK.0);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, plane: FwmarkPlane) -> bool {
        self.0 & plane as u8 != 0
    }

    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl From<FwmarkPlane> for FwmarkPlaneSet {
    fn from(value: FwmarkPlane) -> Self {
        Self(value as u8)
    }
}

impl BitOr for FwmarkPlaneSet {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for FwmarkPlaneSet {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidMarkCandidateEligibilityError {
    mask: u32,
    eligible_mask: u32,
}

impl AndroidMarkCandidateEligibilityError {
    #[must_use]
    pub const fn mask(self) -> u32 {
        self.mask
    }

    #[must_use]
    pub const fn eligible_mask(self) -> u32 {
        self.eligible_mask
    }
}

impl fmt::Display for AndroidMarkCandidateEligibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "fwmark candidate mask {:#010x} is not confined to eligible Android device-policy field {:#010x}",
            self.mask, self.eligible_mask
        )
    }
}

impl Error for AndroidMarkCandidateEligibilityError {}

/// Exact positive assertion made by a device-qualified cooperative policy.
///
/// There is deliberately no public constructor. Callers can obtain this evidence only from the
/// explicitly named `AndroidMarkDevicePolicy::device_qualified_cooperative` factory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidMarkPositiveGrant {
    candidate: FwmarkCandidate,
    topology_scope: AndroidTproxyTopologyScopeReport,
    capability_profile: CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    policy_identity: AndroidMarkDevicePolicyIdentity,
    policy_revision: AndroidMarkDevicePolicyRevision,
    planes: FwmarkPlaneSet,
}

impl AndroidMarkPositiveGrant {
    #[must_use]
    pub const fn candidate(&self) -> FwmarkCandidate {
        self.candidate
    }

    #[must_use]
    pub const fn topology_scope(&self) -> &AndroidTproxyTopologyScopeReport {
        &self.topology_scope
    }

    #[must_use]
    pub fn boot_identity(&self) -> &BootIdentity {
        self.capability_profile
            .boot_identity()
            .verified()
            .expect("positive Android mark grant retains a verified boot identity")
    }

    #[must_use]
    pub const fn network_namespace(&self) -> NetworkNamespaceIdentity {
        self.network_namespace
    }

    #[must_use]
    pub const fn capability_profile(&self) -> &CapabilityProfile {
        &self.capability_profile
    }

    #[must_use]
    pub const fn capability_revision(&self) -> CapabilityProfileRevision {
        self.capability_profile.revision()
    }

    #[must_use]
    pub const fn policy_identity(&self) -> &AndroidMarkDevicePolicyIdentity {
        &self.policy_identity
    }

    #[must_use]
    pub const fn policy_revision(&self) -> AndroidMarkDevicePolicyRevision {
        self.policy_revision
    }

    #[must_use]
    pub const fn planes(&self) -> FwmarkPlaneSet {
        self.planes
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidMarkDeviceGrantKind {
    NoGrant,
    Positive,
}

/// Device-specific mark allocation policy.
///
/// The generic AOSP profile is explicitly zero-grant. A positive assertion exists only behind the
/// device-qualified cooperative factory and remains subject to complete live reauthorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidMarkDevicePolicy {
    identity: AndroidMarkDevicePolicyIdentity,
    revision: AndroidMarkDevicePolicyRevision,
    positive_grant: Option<AndroidMarkPositiveGrant>,
}

impl AndroidMarkDevicePolicy {
    #[must_use]
    pub const fn generic_aosp() -> Self {
        Self {
            identity: AndroidMarkDevicePolicyIdentity::generic_aosp(),
            revision: AndroidMarkDevicePolicyRevision::INITIAL,
            positive_grant: None,
        }
    }

    /// Records an externally established cooperative device-policy assertion.
    ///
    /// This factory does not inspect a device-policy artifact or prove vendor cooperation. The
    /// caller crosses a trust boundary by supplying the reviewed artifact identity and exact
    /// evidence bindings; live authorization still rechecks topology, inventory, policy, profile,
    /// namespace, ownership-journal, and complete census evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn device_qualified_cooperative(
        name: AndroidMarkDevicePolicyName,
        revision: AndroidMarkDevicePolicyRevision,
        artifact_digest: AndroidMarkDevicePolicyArtifactDigest,
        candidate: FwmarkCandidate,
        topology_scope: &AndroidTproxyTopologyScopeReport,
        capability_profile: &CapabilityProfile,
        network_namespace: NetworkNamespaceIdentity,
        planes: FwmarkPlaneSet,
    ) -> Result<Self, AndroidMarkDevicePolicyError> {
        ensure_candidate_eligible(candidate)
            .map_err(AndroidMarkDevicePolicyError::IneligibleCandidate)?;
        if planes.is_empty() {
            return Err(AndroidMarkDevicePolicyError::EmptyPlaneGrant);
        }
        if capability_profile.boot_identity().verified().is_none() {
            return Err(AndroidMarkDevicePolicyError::UnverifiedBootIdentity {
                observation: capability_profile.boot_identity().kind(),
            });
        }
        let device_identity = capability_profile.device_identity().verified().ok_or(
            AndroidMarkDevicePolicyError::UnverifiedDeviceIdentity {
                observation: capability_profile.device_identity().kind(),
            },
        )?;
        if device_identity.network_namespace() != network_namespace {
            return Err(AndroidMarkDevicePolicyError::NetworkNamespaceMismatch {
                profile: device_identity.network_namespace(),
                observed: network_namespace,
            });
        }

        let identity =
            AndroidMarkDevicePolicyIdentity::device_qualified_cooperative(name, artifact_digest);
        let positive_grant = AndroidMarkPositiveGrant {
            candidate,
            topology_scope: topology_scope.clone(),
            capability_profile: capability_profile.clone(),
            network_namespace,
            policy_identity: identity.clone(),
            policy_revision: revision,
            planes,
        };
        Ok(Self {
            identity,
            revision,
            positive_grant: Some(positive_grant),
        })
    }

    #[must_use]
    pub const fn identity(&self) -> &AndroidMarkDevicePolicyIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn revision(&self) -> AndroidMarkDevicePolicyRevision {
        self.revision
    }

    #[must_use]
    pub const fn grant_kind(&self) -> AndroidMarkDeviceGrantKind {
        if self.positive_grant.is_some() {
            AndroidMarkDeviceGrantKind::Positive
        } else {
            AndroidMarkDeviceGrantKind::NoGrant
        }
    }

    #[must_use]
    pub const fn positive_grant(&self) -> Option<&AndroidMarkPositiveGrant> {
        self.positive_grant.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidMarkDevicePolicyError {
    IneligibleCandidate(AndroidMarkCandidateEligibilityError),
    EmptyPlaneGrant,
    UnverifiedBootIdentity {
        observation: ObservationKind,
    },
    UnverifiedDeviceIdentity {
        observation: ObservationKind,
    },
    NetworkNamespaceMismatch {
        profile: NetworkNamespaceIdentity,
        observed: NetworkNamespaceIdentity,
    },
}

impl fmt::Display for AndroidMarkDevicePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IneligibleCandidate(error) => error.fmt(formatter),
            Self::EmptyPlaneGrant => {
                formatter.write_str("device-qualified Android mark policy grants no mark plane")
            }
            Self::UnverifiedBootIdentity { observation } => write!(
                formatter,
                "device-qualified Android mark policy requires a verified boot identity, not {observation:?}"
            ),
            Self::UnverifiedDeviceIdentity { observation } => write!(
                formatter,
                "device-qualified Android mark policy requires a verified exact device identity, not {observation:?}"
            ),
            Self::NetworkNamespaceMismatch { profile, observed } => write!(
                formatter,
                "device-qualified Android mark policy observed network namespace {}:{} but the capability profile binds {}:{}",
                observed.device(),
                observed.inode(),
                profile.device(),
                profile.inode()
            ),
        }
    }
}

impl Error for AndroidMarkDevicePolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::IneligibleCandidate(error) => Some(error),
            Self::EmptyPlaneGrant
            | Self::UnverifiedBootIdentity { .. }
            | Self::UnverifiedDeviceIdentity { .. }
            | Self::NetworkNamespaceMismatch { .. } => None,
        }
    }
}

/// Complete/absent state asserted for one source-plane pair.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FwmarkCensusCoverageState {
    CompletePresent,
    CompleteAbsent,
    Incomplete,
    Opaque,
    Denied,
    Transient,
    Unavailable,
}

impl FwmarkCensusCoverageState {
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::CompletePresent | Self::CompleteAbsent)
    }
}

/// Coverage assertion for one exact evidence source and storage plane.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FwmarkCensusCoverageRecord {
    source: FwmarkEvidenceSource,
    plane: FwmarkPlane,
    state: FwmarkCensusCoverageState,
}

impl FwmarkCensusCoverageRecord {
    #[must_use]
    pub const fn new(
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
        state: FwmarkCensusCoverageState,
    ) -> Self {
        Self {
            source,
            plane,
            state,
        }
    }

    #[must_use]
    pub const fn source(self) -> FwmarkEvidenceSource {
        self.source
    }

    #[must_use]
    pub const fn plane(self) -> FwmarkPlane {
        self.plane
    }

    #[must_use]
    pub const fn state(self) -> FwmarkCensusCoverageState {
        self.state
    }
}

/// Semantics of one observed mark use.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FwmarkUseOperation {
    PredicateRead,
    MaskedWrite,
    TransferRead,
    TransferWrite,
}

/// Canonical mark-use evidence retained by a complete census.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FwmarkUseRecord {
    source: FwmarkEvidenceSource,
    plane: FwmarkPlane,
    operation: FwmarkUseOperation,
    mask: NonZeroU32,
}

impl FwmarkUseRecord {
    pub fn new(
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
        operation: FwmarkUseOperation,
        mask: u32,
    ) -> Result<Self, FwmarkUseRecordError> {
        let mask = NonZeroU32::new(mask).ok_or(FwmarkUseRecordError::EmptyMask)?;
        Ok(Self {
            source,
            plane,
            operation,
            mask,
        })
    }

    #[must_use]
    pub const fn source(self) -> FwmarkEvidenceSource {
        self.source
    }

    #[must_use]
    pub const fn plane(self) -> FwmarkPlane {
        self.plane
    }

    #[must_use]
    pub const fn operation(self) -> FwmarkUseOperation {
        self.operation
    }

    #[must_use]
    pub const fn mask(self) -> u32 {
        self.mask.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FwmarkUseRecordError {
    EmptyMask,
}

impl fmt::Display for FwmarkUseRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fwmark use record has an empty mask")
    }
}

impl Error for FwmarkUseRecordError {}

/// Opaque process-local identity of one consumed point-in-time census observation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CompleteFwmarkCensusObservationId(NonZeroU64);

impl CompleteFwmarkCensusObservationId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Bounded, complete, point-in-time fwmark census.
///
/// This is intentionally not a tracker and does not implement `Clone`. Authorization consumes it,
/// so reauthorization requires a newly collected replacement observation.
#[derive(Debug, Eq, PartialEq)]
pub struct CompleteFwmarkCensus {
    observation_id: CompleteFwmarkCensusObservationId,
    snapshot_id: NetworkInventorySnapshotId,
    epoch: NetworkEpoch,
    capability_profile: CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    device_policy_identity: AndroidMarkDevicePolicyIdentity,
    device_policy_revision: AndroidMarkDevicePolicyRevision,
    collector_revision: FwmarkCensusCollectorRevision,
    ownership_journal_identity: OwnershipJournalIdentity,
    ownership_journal_revision: OwnershipJournalRevision,
    coverage: Box<[FwmarkCensusCoverageRecord]>,
    mark_uses: Box<[FwmarkUseRecord]>,
}

impl CompleteFwmarkCensus {
    /// Validates one externally collected, point-in-time completeness assertion.
    ///
    /// This constructor is a trust boundary for a platform collector, not a kernel observer. The
    /// collector revision, complete source-plane matrix, canonical uses, and all bound identities
    /// are retained so authorization can reject stale or differently interpreted evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn from_complete_observation(
        inventory: &NetworkInventory,
        capability_profile: &CapabilityProfile,
        network_namespace: NetworkNamespaceIdentity,
        device_policy_identity: &AndroidMarkDevicePolicyIdentity,
        device_policy_revision: AndroidMarkDevicePolicyRevision,
        collector_revision: FwmarkCensusCollectorRevision,
        ownership_journal_identity: OwnershipJournalIdentity,
        ownership_journal_revision: OwnershipJournalRevision,
        coverage: impl IntoIterator<Item = FwmarkCensusCoverageRecord>,
        mark_uses: impl IntoIterator<Item = FwmarkUseRecord>,
    ) -> Result<Self, CompleteFwmarkCensusError> {
        if capability_profile.boot_identity().verified().is_none() {
            return Err(CompleteFwmarkCensusError::UnverifiedBootIdentity {
                observation: capability_profile.boot_identity().kind(),
            });
        }
        let device_identity = capability_profile.device_identity().verified().ok_or(
            CompleteFwmarkCensusError::UnverifiedDeviceIdentity {
                observation: capability_profile.device_identity().kind(),
            },
        )?;
        if device_identity.network_namespace() != network_namespace {
            return Err(CompleteFwmarkCensusError::NetworkNamespaceMismatch {
                profile: device_identity.network_namespace(),
                observed: network_namespace,
            });
        }
        let mut canonical_coverage = Vec::with_capacity(COMPLETE_FWMARK_CENSUS_COVERAGE_RECORDS);
        for record in coverage {
            if canonical_coverage.len() == COMPLETE_FWMARK_CENSUS_COVERAGE_RECORDS {
                return Err(CompleteFwmarkCensusError::TooManyCoverageRecords {
                    maximum: COMPLETE_FWMARK_CENSUS_COVERAGE_RECORDS,
                    required_at_least: COMPLETE_FWMARK_CENSUS_COVERAGE_RECORDS + 1,
                });
            }
            canonical_coverage.push(record);
        }
        canonical_coverage.sort_unstable_by_key(|record| (record.source, record.plane));
        if let Some(pair) = canonical_coverage
            .windows(2)
            .find(|pair| pair[0].source == pair[1].source && pair[0].plane == pair[1].plane)
        {
            return Err(CompleteFwmarkCensusError::DuplicateCoverage {
                source: pair[0].source,
                plane: pair[0].plane,
            });
        }
        if let Some(record) = canonical_coverage
            .iter()
            .find(|record| !record.state.is_complete())
        {
            return Err(CompleteFwmarkCensusError::NonCompleteCoverage {
                source: record.source,
                plane: record.plane,
                state: record.state,
            });
        }
        for source in ALL_FWMARK_EVIDENCE_SOURCES {
            for plane in ALL_FWMARK_PLANES {
                if !canonical_coverage
                    .iter()
                    .any(|record| record.source == source && record.plane == plane)
                {
                    return Err(CompleteFwmarkCensusError::MissingCoverage { source, plane });
                }
            }
        }

        let mut canonical_mark_uses = Vec::new();
        for record in mark_uses {
            if canonical_mark_uses.len() == MAX_COMPLETE_FWMARK_CENSUS_MARK_USES {
                return Err(CompleteFwmarkCensusError::TooManyMarkUseRecords {
                    maximum: MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
                    required_at_least: MAX_COMPLETE_FWMARK_CENSUS_MARK_USES + 1,
                });
            }
            canonical_mark_uses.push(record);
        }
        canonical_mark_uses.sort_unstable();
        canonical_mark_uses.dedup();

        for coverage in &canonical_coverage {
            let has_mark_use = canonical_mark_uses
                .iter()
                .any(|record| record.source == coverage.source && record.plane == coverage.plane);
            match (coverage.state, has_mark_use) {
                (FwmarkCensusCoverageState::CompletePresent, false) => {
                    return Err(CompleteFwmarkCensusError::PresentCoverageHasNoMarkUse {
                        source: coverage.source,
                        plane: coverage.plane,
                    });
                }
                (FwmarkCensusCoverageState::CompleteAbsent, true) => {
                    return Err(CompleteFwmarkCensusError::AbsentCoverageHasMarkUse {
                        source: coverage.source,
                        plane: coverage.plane,
                    });
                }
                (FwmarkCensusCoverageState::CompletePresent, true)
                | (FwmarkCensusCoverageState::CompleteAbsent, false) => {}
                (
                    FwmarkCensusCoverageState::Incomplete
                    | FwmarkCensusCoverageState::Opaque
                    | FwmarkCensusCoverageState::Denied
                    | FwmarkCensusCoverageState::Transient
                    | FwmarkCensusCoverageState::Unavailable,
                    _,
                ) => unreachable!("noncomplete coverage was rejected before use validation"),
            }
        }

        let observation_id = allocate_complete_fwmark_census_observation_id()?;
        Ok(Self {
            observation_id,
            snapshot_id: inventory.snapshot_id(),
            epoch: inventory.epoch(),
            capability_profile: capability_profile.clone(),
            network_namespace,
            device_policy_identity: device_policy_identity.clone(),
            device_policy_revision,
            collector_revision,
            ownership_journal_identity,
            ownership_journal_revision,
            coverage: canonical_coverage.into_boxed_slice(),
            mark_uses: canonical_mark_uses.into_boxed_slice(),
        })
    }

    #[must_use]
    pub const fn observation_id(&self) -> CompleteFwmarkCensusObservationId {
        self.observation_id
    }

    #[must_use]
    pub const fn snapshot_id(&self) -> NetworkInventorySnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub const fn epoch(&self) -> NetworkEpoch {
        self.epoch
    }

    #[must_use]
    pub fn boot_identity(&self) -> &BootIdentity {
        self.capability_profile
            .boot_identity()
            .verified()
            .expect("complete fwmark census retains a verified boot identity")
    }

    #[must_use]
    pub const fn network_namespace(&self) -> NetworkNamespaceIdentity {
        self.network_namespace
    }

    #[must_use]
    pub const fn capability_profile(&self) -> &CapabilityProfile {
        &self.capability_profile
    }

    #[must_use]
    pub const fn capability_revision(&self) -> CapabilityProfileRevision {
        self.capability_profile.revision()
    }

    #[must_use]
    pub const fn device_policy_identity(&self) -> &AndroidMarkDevicePolicyIdentity {
        &self.device_policy_identity
    }

    #[must_use]
    pub const fn device_policy_revision(&self) -> AndroidMarkDevicePolicyRevision {
        self.device_policy_revision
    }

    #[must_use]
    pub const fn collector_revision(&self) -> FwmarkCensusCollectorRevision {
        self.collector_revision
    }

    #[must_use]
    pub const fn ownership_journal_identity(&self) -> OwnershipJournalIdentity {
        self.ownership_journal_identity
    }

    #[must_use]
    pub const fn ownership_journal_revision(&self) -> OwnershipJournalRevision {
        self.ownership_journal_revision
    }

    #[must_use]
    pub fn coverage(&self) -> &[FwmarkCensusCoverageRecord] {
        &self.coverage
    }

    #[must_use]
    pub fn mark_uses(&self) -> &[FwmarkUseRecord] {
        &self.mark_uses
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompleteFwmarkCensusError {
    UnverifiedBootIdentity {
        observation: ObservationKind,
    },
    UnverifiedDeviceIdentity {
        observation: ObservationKind,
    },
    NetworkNamespaceMismatch {
        profile: NetworkNamespaceIdentity,
        observed: NetworkNamespaceIdentity,
    },
    TooManyCoverageRecords {
        maximum: usize,
        required_at_least: usize,
    },
    DuplicateCoverage {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
    },
    MissingCoverage {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
    },
    NonCompleteCoverage {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
        state: FwmarkCensusCoverageState,
    },
    TooManyMarkUseRecords {
        maximum: usize,
        required_at_least: usize,
    },
    PresentCoverageHasNoMarkUse {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
    },
    AbsentCoverageHasMarkUse {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
    },
    ObservationIdExhausted,
}

impl fmt::Display for CompleteFwmarkCensusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnverifiedBootIdentity { observation } => write!(
                formatter,
                "complete fwmark census requires a verified boot identity, not {observation:?}"
            ),
            Self::UnverifiedDeviceIdentity { observation } => write!(
                formatter,
                "complete fwmark census requires a verified exact device identity, not {observation:?}"
            ),
            Self::NetworkNamespaceMismatch { profile, observed } => write!(
                formatter,
                "complete fwmark census observed network namespace {}:{} but the capability profile binds {}:{}",
                observed.device(),
                observed.inode(),
                profile.device(),
                profile.inode()
            ),
            Self::TooManyCoverageRecords {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "complete fwmark census has at least {required_at_least} coverage records but its exact limit is {maximum}"
            ),
            Self::DuplicateCoverage { source, plane } => write!(
                formatter,
                "complete fwmark census repeats {source:?} coverage for the {plane:?} plane"
            ),
            Self::MissingCoverage { source, plane } => write!(
                formatter,
                "complete fwmark census omits {source:?} coverage for the {plane:?} plane"
            ),
            Self::NonCompleteCoverage {
                source,
                plane,
                state,
            } => write!(
                formatter,
                "complete fwmark census has noncomplete {state:?} evidence for {source:?} on the {plane:?} plane"
            ),
            Self::TooManyMarkUseRecords {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "complete fwmark census has at least {required_at_least} mark-use records but its limit is {maximum}"
            ),
            Self::PresentCoverageHasNoMarkUse { source, plane } => write!(
                formatter,
                "complete fwmark census declares {source:?} present on the {plane:?} plane without a canonical mark-use record"
            ),
            Self::AbsentCoverageHasMarkUse { source, plane } => write!(
                formatter,
                "complete fwmark census declares {source:?} absent on the {plane:?} plane but retains a canonical mark-use record"
            ),
            Self::ObservationIdExhausted => {
                formatter.write_str("complete fwmark census observation identity is exhausted")
            }
        }
    }
}

impl Error for CompleteFwmarkCensusError {}

fn allocate_complete_fwmark_census_observation_id()
-> Result<CompleteFwmarkCensusObservationId, CompleteFwmarkCensusError> {
    let value = NEXT_COMPLETE_FWMARK_CENSUS_OBSERVATION_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| CompleteFwmarkCensusError::ObservationIdExhausted)?;
    Ok(CompleteFwmarkCensusObservationId(
        NonZeroU64::new(value).expect("census observation counter starts nonzero"),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FwmarkCensusConflict {
    mark_use: FwmarkUseRecord,
    overlap: u32,
}

impl FwmarkCensusConflict {
    #[must_use]
    pub const fn mark_use(self) -> FwmarkUseRecord {
        self.mark_use
    }

    #[must_use]
    pub const fn overlap(self) -> u32 {
        self.overlap
    }
}

/// Activation evidence deliberately left outside this read-only planning authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DeferredAndroidMarkActivationPrerequisite {
    ExactWriterSemantics,
    ObserverContinuity,
    MarkPreservationCanary,
}

/// Read-only positive authority to continue pure Android mark planning.
///
/// This type has no public constructor and exposes no priority, table, route, mutation intent,
/// encoder, apply operation, lease, or activation conversion.
#[derive(Debug, Eq, PartialEq)]
pub struct AndroidMarkPlanningAuthority {
    candidate: FwmarkCandidate,
    topology_scope: AndroidTproxyTopologyScopeReport,
    capability_profile: CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    policy_identity: AndroidMarkDevicePolicyIdentity,
    policy_revision: AndroidMarkDevicePolicyRevision,
    planes: FwmarkPlaneSet,
    census: CompleteFwmarkCensus,
    partial_audit: FwmarkPartialAudit,
}

impl AndroidMarkPlanningAuthority {
    #[must_use]
    pub const fn candidate(&self) -> FwmarkCandidate {
        self.candidate
    }

    #[must_use]
    pub const fn topology_scope(&self) -> &AndroidTproxyTopologyScopeReport {
        &self.topology_scope
    }

    #[must_use]
    pub fn boot_identity(&self) -> &BootIdentity {
        self.capability_profile
            .boot_identity()
            .verified()
            .expect("Android mark planning authority retains a verified boot identity")
    }

    #[must_use]
    pub const fn network_namespace(&self) -> NetworkNamespaceIdentity {
        self.network_namespace
    }

    #[must_use]
    pub const fn capability_profile(&self) -> &CapabilityProfile {
        &self.capability_profile
    }

    #[must_use]
    pub const fn capability_revision(&self) -> CapabilityProfileRevision {
        self.capability_profile.revision()
    }

    #[must_use]
    pub const fn policy_identity(&self) -> &AndroidMarkDevicePolicyIdentity {
        &self.policy_identity
    }

    #[must_use]
    pub const fn policy_revision(&self) -> AndroidMarkDevicePolicyRevision {
        self.policy_revision
    }

    #[must_use]
    pub const fn planes(&self) -> FwmarkPlaneSet {
        self.planes
    }

    #[must_use]
    pub const fn census(&self) -> &CompleteFwmarkCensus {
        &self.census
    }

    #[must_use]
    pub const fn census_collector_revision(&self) -> FwmarkCensusCollectorRevision {
        self.census.collector_revision
    }

    #[must_use]
    pub const fn ownership_journal_identity(&self) -> OwnershipJournalIdentity {
        self.census.ownership_journal_identity
    }

    #[must_use]
    pub const fn ownership_journal_revision(&self) -> OwnershipJournalRevision {
        self.census.ownership_journal_revision
    }

    #[must_use]
    pub const fn partial_audit(&self) -> &FwmarkPartialAudit {
        &self.partial_audit
    }

    #[must_use]
    /// Returns only the mark-authority-specific activation gaps.
    ///
    /// The topology scope retains its separate capture-ordering, domain/network handoff, route,
    /// ownership, mutation-identity, and engine-loop prerequisites. Neither list is an activation
    /// conversion.
    pub fn deferred_mark_activation_prerequisites(
        &self,
    ) -> &[DeferredAndroidMarkActivationPrerequisite] {
        &DEFERRED_ANDROID_MARK_ACTIVATION_PREREQUISITES
    }

    #[must_use]
    /// Returns the topology activation gaps that remain after this authority has supplied positive
    /// mark authority plus verified boot and network-namespace binding.
    ///
    /// `DurableOwnershipJournal` remains deferred: binding the census to an exact journal identity
    /// and revision is freshness evidence, not an ownership claim or mutation lease.
    pub const fn topology_deferred_prerequisites(
        &self,
    ) -> &'static [DeferredAndroidTproxyPrerequisite] {
        match self.topology_scope.request().shape() {
            AndroidTproxyRoutingShape::DedicatedAddressBypassRule => {
                &REMAINING_COMMON_ANDROID_TPROXY_PREREQUISITES
            }
            AndroidTproxyRoutingShape::PreMarkAddressHostSet => {
                &REMAINING_PRE_MARK_ANDROID_TPROXY_PREREQUISITES
            }
        }
    }

    /// Consumes this point-in-time authority and reauthorizes the same candidate from fresh
    /// current evidence and a newly collected replacement census.
    #[allow(clippy::too_many_arguments)]
    pub fn reauthorize(
        self,
        inventory: &NetworkInventory,
        classification: &AndroidRpdbClassificationReport,
        topology_scope: &AndroidTproxyTopologyScopeReport,
        capability_profile: &CapabilityProfile,
        network_namespace: NetworkNamespaceIdentity,
        ownership_journal_identity: OwnershipJournalIdentity,
        ownership_journal_revision: OwnershipJournalRevision,
        census_collector_revision: FwmarkCensusCollectorRevision,
        policy: &AndroidMarkDevicePolicy,
        replacement_census: CompleteFwmarkCensus,
    ) -> Result<Self, AndroidMarkPlanningAuthorizationError> {
        let previous_observation_id = self.census.observation_id;
        let replacement_observation_id = replacement_census.observation_id;
        let candidate = self.candidate;
        if replacement_observation_id <= previous_observation_id {
            return Err(
                AndroidMarkPlanningAuthorizationError::NonFreshCensusObservation {
                    previous_observation_id,
                    replacement_observation_id,
                },
            );
        }
        authorize_android_mark_planning(
            inventory,
            classification,
            topology_scope,
            capability_profile,
            network_namespace,
            ownership_journal_identity,
            ownership_journal_revision,
            census_collector_revision,
            policy,
            candidate,
            replacement_census,
        )
    }
}

/// Revalidates all current evidence and authorizes only further pure mark planning.
#[allow(clippy::too_many_arguments)]
pub fn authorize_android_mark_planning(
    inventory: &NetworkInventory,
    classification: &AndroidRpdbClassificationReport,
    topology_scope: &AndroidTproxyTopologyScopeReport,
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    ownership_journal_identity: OwnershipJournalIdentity,
    ownership_journal_revision: OwnershipJournalRevision,
    census_collector_revision: FwmarkCensusCollectorRevision,
    policy: &AndroidMarkDevicePolicy,
    candidate: FwmarkCandidate,
    census: CompleteFwmarkCensus,
) -> Result<AndroidMarkPlanningAuthority, AndroidMarkPlanningAuthorizationError> {
    let grant = policy.positive_grant().ok_or(
        AndroidMarkPlanningAuthorizationError::NoPositiveDeviceGrant {
            policy_kind: policy.identity.kind,
        },
    )?;

    ensure_candidate_eligible(candidate)
        .map_err(AndroidMarkPlanningAuthorizationError::IneligibleCandidate)?;

    let boot_identity = capability_profile.boot_identity().verified().ok_or(
        AndroidMarkPlanningAuthorizationError::UnverifiedBootIdentity {
            observation: capability_profile.boot_identity().kind(),
        },
    )?;

    topology_scope
        .ensure_current(inventory, classification)
        .map_err(AndroidMarkPlanningAuthorizationError::StaleTopologyScope)?;

    if grant.policy_identity != policy.identity || grant.policy_revision != policy.revision {
        return Err(AndroidMarkPlanningAuthorizationError::MalformedPositiveGrant);
    }
    if grant.candidate != candidate {
        return Err(
            AndroidMarkPlanningAuthorizationError::GrantCandidateMismatch {
                granted: grant.candidate,
                requested: candidate,
            },
        );
    }
    if &grant.topology_scope != topology_scope {
        return Err(AndroidMarkPlanningAuthorizationError::GrantTopologyScopeMismatch);
    }
    if grant.boot_identity() != boot_identity {
        return Err(AndroidMarkPlanningAuthorizationError::GrantBootIdentityMismatch);
    }
    if grant.network_namespace != network_namespace {
        return Err(
            AndroidMarkPlanningAuthorizationError::GrantNetworkNamespaceMismatch {
                granted: grant.network_namespace,
                current: network_namespace,
            },
        );
    }
    if &grant.capability_profile != capability_profile {
        return Err(
            AndroidMarkPlanningAuthorizationError::GrantCapabilityProfileMismatch {
                granted_revision: grant.capability_profile.revision(),
                current: capability_profile.revision(),
            },
        );
    }
    if !grant.planes.contains_all(FwmarkPlaneSet::ALL) {
        return Err(AndroidMarkPlanningAuthorizationError::GrantMissingPlanes {
            granted: grant.planes,
            required: FwmarkPlaneSet::ALL,
        });
    }

    ensure_census_bindings(
        &census,
        inventory,
        capability_profile,
        network_namespace,
        policy.identity(),
        policy.revision(),
        census_collector_revision,
        ownership_journal_identity,
        ownership_journal_revision,
    )?;

    let topology_feasibility = topology_scope.structural_feasibility();
    if matches!(
        topology_feasibility,
        AndroidTproxyTopologyScopeStructuralFeasibility::DefiniteStructuralRejection { .. }
    ) {
        return Err(
            AndroidMarkPlanningAuthorizationError::TopologyScopeNotAllResidual {
                feasibility: topology_feasibility,
            },
        );
    }

    let partial_audit = audit_fwmark_candidate_partial(inventory, candidate);
    if partial_audit.outcome() == FwmarkPartialAuditOutcome::Conflicting {
        return Err(
            AndroidMarkPlanningAuthorizationError::PartialAuditConflict {
                audit: partial_audit,
            },
        );
    }

    let census_conflicts: Vec<_> = census
        .mark_uses
        .iter()
        .filter_map(|mark_use| {
            let overlap = candidate.mask() & mark_use.mask();
            (overlap != 0).then_some(FwmarkCensusConflict {
                mark_use: *mark_use,
                overlap,
            })
        })
        .collect();
    if !census_conflicts.is_empty() {
        return Err(AndroidMarkPlanningAuthorizationError::CensusConflict {
            conflicts: census_conflicts.into_boxed_slice(),
        });
    }

    let incomplete_partial_source = [
        FwmarkEvidenceSource::AndroidNetId,
        FwmarkEvidenceSource::Rpdb,
    ]
    .into_iter()
    .find_map(|source| {
        let state = partial_audit
            .sources()
            .iter()
            .find(|status| status.source() == source)
            .map(|status| status.state());
        (state != Some(FwmarkEvidenceState::Available)).then_some((source, state))
    });
    if let Some((source, state)) = incomplete_partial_source {
        return Err(
            AndroidMarkPlanningAuthorizationError::PartialAuditEvidenceNotAvailable {
                audit: partial_audit,
                source,
                state,
            },
        );
    }

    if matches!(
        topology_feasibility,
        AndroidTproxyTopologyScopeStructuralFeasibility::IncompleteEvidence { .. }
    ) {
        return Err(
            AndroidMarkPlanningAuthorizationError::TopologyScopeNotAllResidual {
                feasibility: topology_feasibility,
            },
        );
    }
    debug_assert!(matches!(
        topology_feasibility,
        AndroidTproxyTopologyScopeStructuralFeasibility::AllMatchedAnchorsHaveResidualCandidateWindows { .. }
    ));

    Ok(AndroidMarkPlanningAuthority {
        candidate,
        topology_scope: topology_scope.clone(),
        capability_profile: capability_profile.clone(),
        network_namespace,
        policy_identity: policy.identity.clone(),
        policy_revision: policy.revision,
        planes: grant.planes,
        census,
        partial_audit,
    })
}

fn ensure_candidate_eligible(
    candidate: FwmarkCandidate,
) -> Result<(), AndroidMarkCandidateEligibilityError> {
    if candidate.mask() & !ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK == 0 {
        Ok(())
    } else {
        Err(AndroidMarkCandidateEligibilityError {
            mask: candidate.mask(),
            eligible_mask: ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn ensure_census_bindings(
    census: &CompleteFwmarkCensus,
    inventory: &NetworkInventory,
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    policy_identity: &AndroidMarkDevicePolicyIdentity,
    policy_revision: AndroidMarkDevicePolicyRevision,
    collector_revision: FwmarkCensusCollectorRevision,
    ownership_journal_identity: OwnershipJournalIdentity,
    ownership_journal_revision: OwnershipJournalRevision,
) -> Result<(), AndroidMarkPlanningAuthorizationError> {
    if census.snapshot_id != inventory.snapshot_id() || census.epoch != inventory.epoch() {
        return Err(
            AndroidMarkPlanningAuthorizationError::CensusInventoryMismatch {
                observed_snapshot_id: census.snapshot_id,
                current_snapshot_id: inventory.snapshot_id(),
                observed_epoch: census.epoch,
                current_epoch: inventory.epoch(),
            },
        );
    }
    if census.boot_identity()
        != capability_profile
            .boot_identity()
            .verified()
            .expect("authorization verifies current boot identity before census bindings")
    {
        return Err(AndroidMarkPlanningAuthorizationError::CensusBootIdentityMismatch);
    }
    if census.network_namespace != network_namespace {
        return Err(
            AndroidMarkPlanningAuthorizationError::CensusNetworkNamespaceMismatch {
                observed: census.network_namespace,
                current: network_namespace,
            },
        );
    }
    if &census.capability_profile != capability_profile {
        return Err(
            AndroidMarkPlanningAuthorizationError::CensusCapabilityProfileMismatch {
                observed_revision: census.capability_profile.revision(),
                current_revision: capability_profile.revision(),
            },
        );
    }
    if &census.device_policy_identity != policy_identity {
        return Err(AndroidMarkPlanningAuthorizationError::CensusDevicePolicyIdentityMismatch);
    }
    if census.device_policy_revision != policy_revision {
        return Err(
            AndroidMarkPlanningAuthorizationError::CensusDevicePolicyRevisionMismatch {
                observed: census.device_policy_revision,
                current: policy_revision,
            },
        );
    }
    if census.collector_revision != collector_revision {
        return Err(
            AndroidMarkPlanningAuthorizationError::CensusCollectorRevisionMismatch {
                observed: census.collector_revision,
                current: collector_revision,
            },
        );
    }
    if census.ownership_journal_identity != ownership_journal_identity {
        return Err(
            AndroidMarkPlanningAuthorizationError::CensusOwnershipJournalIdentityMismatch {
                observed: census.ownership_journal_identity,
                current: ownership_journal_identity,
            },
        );
    }
    if census.ownership_journal_revision != ownership_journal_revision {
        return Err(
            AndroidMarkPlanningAuthorizationError::CensusOwnershipJournalRevisionMismatch {
                observed: census.ownership_journal_revision,
                current: ownership_journal_revision,
            },
        );
    }
    debug_assert_eq!(
        census.coverage.len(),
        COMPLETE_FWMARK_CENSUS_COVERAGE_RECORDS
    );
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
pub enum AndroidMarkPlanningAuthorizationError {
    NoPositiveDeviceGrant {
        policy_kind: AndroidMarkDevicePolicyKind,
    },
    IneligibleCandidate(AndroidMarkCandidateEligibilityError),
    UnverifiedBootIdentity {
        observation: ObservationKind,
    },
    StaleTopologyScope(StaleAndroidTproxyTopologyScopeReport),
    TopologyScopeNotAllResidual {
        feasibility: AndroidTproxyTopologyScopeStructuralFeasibility,
    },
    MalformedPositiveGrant,
    GrantCandidateMismatch {
        granted: FwmarkCandidate,
        requested: FwmarkCandidate,
    },
    GrantTopologyScopeMismatch,
    GrantBootIdentityMismatch,
    GrantNetworkNamespaceMismatch {
        granted: NetworkNamespaceIdentity,
        current: NetworkNamespaceIdentity,
    },
    GrantCapabilityProfileMismatch {
        granted_revision: CapabilityProfileRevision,
        current: CapabilityProfileRevision,
    },
    GrantMissingPlanes {
        granted: FwmarkPlaneSet,
        required: FwmarkPlaneSet,
    },
    CensusInventoryMismatch {
        observed_snapshot_id: NetworkInventorySnapshotId,
        current_snapshot_id: NetworkInventorySnapshotId,
        observed_epoch: NetworkEpoch,
        current_epoch: NetworkEpoch,
    },
    CensusBootIdentityMismatch,
    CensusNetworkNamespaceMismatch {
        observed: NetworkNamespaceIdentity,
        current: NetworkNamespaceIdentity,
    },
    CensusCapabilityProfileMismatch {
        observed_revision: CapabilityProfileRevision,
        current_revision: CapabilityProfileRevision,
    },
    CensusDevicePolicyIdentityMismatch,
    CensusDevicePolicyRevisionMismatch {
        observed: AndroidMarkDevicePolicyRevision,
        current: AndroidMarkDevicePolicyRevision,
    },
    CensusCollectorRevisionMismatch {
        observed: FwmarkCensusCollectorRevision,
        current: FwmarkCensusCollectorRevision,
    },
    CensusOwnershipJournalIdentityMismatch {
        observed: OwnershipJournalIdentity,
        current: OwnershipJournalIdentity,
    },
    CensusOwnershipJournalRevisionMismatch {
        observed: OwnershipJournalRevision,
        current: OwnershipJournalRevision,
    },
    PartialAuditConflict {
        audit: FwmarkPartialAudit,
    },
    PartialAuditEvidenceNotAvailable {
        audit: FwmarkPartialAudit,
        source: FwmarkEvidenceSource,
        state: Option<FwmarkEvidenceState>,
    },
    CensusConflict {
        conflicts: Box<[FwmarkCensusConflict]>,
    },
    NonFreshCensusObservation {
        previous_observation_id: CompleteFwmarkCensusObservationId,
        replacement_observation_id: CompleteFwmarkCensusObservationId,
    },
}

impl AndroidMarkPlanningAuthorizationError {
    #[must_use]
    pub fn partial_audit(&self) -> Option<&FwmarkPartialAudit> {
        match self {
            Self::PartialAuditConflict { audit }
            | Self::PartialAuditEvidenceNotAvailable { audit, .. } => Some(audit),
            _ => None,
        }
    }

    #[must_use]
    pub fn census_conflicts(&self) -> &[FwmarkCensusConflict] {
        match self {
            Self::CensusConflict { conflicts } => conflicts,
            _ => &[],
        }
    }
}

impl fmt::Display for AndroidMarkPlanningAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPositiveDeviceGrant { policy_kind } => write!(
                formatter,
                "Android mark device policy {policy_kind:?} provides no positive grant"
            ),
            Self::IneligibleCandidate(error) => error.fmt(formatter),
            Self::UnverifiedBootIdentity { observation } => write!(
                formatter,
                "Android mark planning requires a verified boot identity, not {observation:?}"
            ),
            Self::StaleTopologyScope(error) => error.fmt(formatter),
            Self::TopologyScopeNotAllResidual { feasibility } => write!(
                formatter,
                "Android mark planning requires all topology anchors to have residual candidate windows, not {feasibility:?}"
            ),
            Self::MalformedPositiveGrant => formatter.write_str(
                "device-qualified Android mark policy contains an internally inconsistent positive grant",
            ),
            Self::GrantCandidateMismatch { granted, requested } => write!(
                formatter,
                "device-qualified Android mark grant binds candidate mask {:#010x} but authorization requests {:#010x}",
                granted.mask(),
                requested.mask()
            ),
            Self::GrantTopologyScopeMismatch => formatter.write_str(
                "device-qualified Android mark grant does not bind the exact current topology scope report",
            ),
            Self::GrantBootIdentityMismatch => formatter.write_str(
                "device-qualified Android mark grant does not bind the verified current boot identity",
            ),
            Self::GrantNetworkNamespaceMismatch { granted, current } => write!(
                formatter,
                "device-qualified Android mark grant binds network namespace {}:{} rather than current {}:{}",
                granted.device(),
                granted.inode(),
                current.device(),
                current.inode()
            ),
            Self::GrantCapabilityProfileMismatch {
                granted_revision,
                current,
            } => write!(
                formatter,
                "device-qualified Android mark grant binds a different capability profile (grant revision {}, current revision {})",
                granted_revision.get(),
                current.get()
            ),
            Self::GrantMissingPlanes { granted, required } => write!(
                formatter,
                "device-qualified Android mark grant covers plane bits {:#05b} but authorization requires {:#05b}",
                granted.bits(),
                required.bits()
            ),
            Self::CensusInventoryMismatch {
                observed_snapshot_id,
                current_snapshot_id,
                observed_epoch,
                current_epoch,
            } => write!(
                formatter,
                "complete fwmark census snapshot {} at epoch {} does not match current snapshot {} at epoch {}",
                observed_snapshot_id.get(),
                observed_epoch.get(),
                current_snapshot_id.get(),
                current_epoch.get()
            ),
            Self::CensusBootIdentityMismatch => formatter.write_str(
                "complete fwmark census does not bind the verified current boot identity",
            ),
            Self::CensusNetworkNamespaceMismatch { observed, current } => write!(
                formatter,
                "complete fwmark census binds network namespace {}:{} rather than current {}:{}",
                observed.device(),
                observed.inode(),
                current.device(),
                current.inode()
            ),
            Self::CensusCapabilityProfileMismatch {
                observed_revision,
                current_revision,
            } => write!(
                formatter,
                "complete fwmark census binds a different capability profile (observed revision {}, current revision {})",
                observed_revision.get(),
                current_revision.get()
            ),
            Self::CensusDevicePolicyIdentityMismatch => formatter.write_str(
                "complete fwmark census does not bind the current device-policy identity",
            ),
            Self::CensusDevicePolicyRevisionMismatch { observed, current } => write!(
                formatter,
                "complete fwmark census binds device-policy revision {} rather than current {}",
                observed.get(),
                current.get()
            ),
            Self::CensusCollectorRevisionMismatch { observed, current } => write!(
                formatter,
                "complete fwmark census binds collector revision {} rather than current {}",
                observed.get(),
                current.get()
            ),
            Self::CensusOwnershipJournalIdentityMismatch { .. } => formatter.write_str(
                "complete fwmark census does not bind the exact current ownership-journal identity",
            ),
            Self::CensusOwnershipJournalRevisionMismatch { observed, current } => write!(
                formatter,
                "complete fwmark census binds ownership-journal revision {} rather than current {}",
                observed.get(),
                current.get()
            ),
            Self::PartialAuditConflict { audit } => write!(
                formatter,
                "partial fwmark audit found {} retained conflicts and {} omitted conflicts",
                audit.conflicts().len(),
                audit.omitted_conflicts()
            ),
            Self::PartialAuditEvidenceNotAvailable { source, state, .. } => write!(
                formatter,
                "partial fwmark audit requires trusted {source:?} evidence but observed {state:?}"
            ),
            Self::CensusConflict { conflicts } => write!(
                formatter,
                "complete fwmark census found {} candidate-mask conflicts",
                conflicts.len()
            ),
            Self::NonFreshCensusObservation {
                previous_observation_id,
                replacement_observation_id,
            } => write!(
                formatter,
                "Android mark reauthorization requires a census newer than observation {}, not observation {}",
                previous_observation_id.get(),
                replacement_observation_id.get()
            ),
        }
    }
}

impl Error for AndroidMarkPlanningAuthorizationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::IneligibleCandidate(error) => Some(error),
            Self::StaleTopologyScope(error) => Some(error),
            _ => None,
        }
    }
}
