use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;

use crate::canonical_evidence::CanonicalEvidenceDigest;

pub const CAPABILITY_PROFILE_SCHEMA_VERSION: u16 = 2;
pub const CAPABILITY_PROFILE_DIGEST_BYTES: usize = 32;
pub const MIN_SUPPORTED_KERNEL: KernelVersion = KernelVersion::new(5, 10, 0);
pub const MAX_BOOT_IDENTITY_BYTES: usize = 128;
pub const MAX_KERNEL_RELEASE_BYTES: usize = 256;
pub const MAX_DEVICE_IDENTITY_TEXT_BYTES: usize = 1_024;
pub const MAX_TOOL_ID_BYTES: usize = 128;
pub const MAX_DEVICE_TOOL_IDENTITIES: usize = 32;
pub const SHA256_DIGEST_BYTES: usize = 32;

const CAPABILITY_PROFILE_DIGEST_DOMAIN: &[u8] =
    b"Flux complete Capability Profile\0canonical-schema-v2\0sha256-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationKind {
    Verified,
    Absent,
    Denied,
    Malformed,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Observation<T> {
    Verified(T),
    Absent,
    Denied,
    Malformed,
    Unavailable,
}

impl<T> Observation<T> {
    #[must_use]
    pub const fn kind(&self) -> ObservationKind {
        match self {
            Self::Verified(_) => ObservationKind::Verified,
            Self::Absent => ObservationKind::Absent,
            Self::Denied => ObservationKind::Denied,
            Self::Malformed => ObservationKind::Malformed,
            Self::Unavailable => ObservationKind::Unavailable,
        }
    }

    #[must_use]
    pub const fn verified(&self) -> Option<&T> {
        match self {
            Self::Verified(value) => Some(value),
            Self::Absent | Self::Denied | Self::Malformed | Self::Unavailable => None,
        }
    }

    #[must_use]
    pub fn map_ref<U>(&self, map: impl FnOnce(&T) -> U) -> Observation<U> {
        match self {
            Self::Verified(value) => Observation::Verified(map(value)),
            Self::Absent => Observation::Absent,
            Self::Denied => Observation::Denied,
            Self::Malformed => Observation::Malformed,
            Self::Unavailable => Observation::Unavailable,
        }
    }

    #[must_use]
    pub fn and_then<U>(self, map: impl FnOnce(T) -> Observation<U>) -> Observation<U> {
        match self {
            Self::Verified(value) => map(value),
            Self::Absent => Observation::Absent,
            Self::Denied => Observation::Denied,
            Self::Malformed => Observation::Malformed,
            Self::Unavailable => Observation::Unavailable,
        }
    }
}

pub trait CapabilityProfileSource {
    fn collect_capability_profile(&self) -> CapabilityProfile;
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilityProfileRevision(u64);

impl CapabilityProfileRevision {
    pub const INITIAL: Self = Self(1);

    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Domain-separated SHA-256 identity of every retained Capability Profile field.
///
/// The monotonic revision remains useful for freshness checks, but it is not globally unique.
/// This digest prevents independent profiles with the same revision from sharing an identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CapabilityProfileDigest([u8; CAPABILITY_PROFILE_DIGEST_BYTES]);

impl CapabilityProfileDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CAPABILITY_PROFILE_DIGEST_BYTES] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityProfile {
    schema_version: u16,
    revision: CapabilityProfileRevision,
    boot_identity: Observation<BootIdentity>,
    device_identity: Observation<DeviceIdentity>,
    kernel: KernelFacts,
    selinux: Observation<SelinuxMode>,
    legacy_bridge: LegacyBridgeFacts,
}

impl CapabilityProfile {
    #[must_use]
    pub const fn initial(
        boot_identity: Observation<BootIdentity>,
        device_identity: Observation<DeviceIdentity>,
        kernel: KernelFacts,
        selinux: Observation<SelinuxMode>,
        legacy_bridge: LegacyBridgeFacts,
    ) -> Self {
        Self::new(
            CapabilityProfileRevision::INITIAL,
            boot_identity,
            device_identity,
            kernel,
            selinux,
            legacy_bridge,
        )
    }

    #[must_use]
    pub const fn new(
        revision: CapabilityProfileRevision,
        boot_identity: Observation<BootIdentity>,
        device_identity: Observation<DeviceIdentity>,
        kernel: KernelFacts,
        selinux: Observation<SelinuxMode>,
        legacy_bridge: LegacyBridgeFacts,
    ) -> Self {
        Self {
            schema_version: CAPABILITY_PROFILE_SCHEMA_VERSION,
            revision,
            boot_identity,
            device_identity,
            kernel,
            selinux,
            legacy_bridge,
        }
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn revision(&self) -> CapabilityProfileRevision {
        self.revision
    }

    /// Returns the canonical identity of this complete point-in-time profile.
    #[must_use]
    pub fn digest(&self) -> CapabilityProfileDigest {
        let mut digest = CanonicalEvidenceDigest::new(CAPABILITY_PROFILE_DIGEST_DOMAIN);
        digest.u16(self.schema_version);
        digest.u64(self.revision.get());
        digest_observation(&mut digest, &self.boot_identity, |digest, identity| {
            digest.bytes(identity.as_str().as_bytes());
        });
        digest_observation(&mut digest, &self.device_identity, digest_device_identity);
        digest_observation(&mut digest, self.kernel.release(), |digest, release| {
            digest.bytes(release.as_str().as_bytes());
        });
        digest_observation(&mut digest, self.kernel.version(), |digest, version| {
            digest_kernel_version(digest, *version);
        });
        digest_observation(&mut digest, &self.selinux, |digest, mode| {
            digest.tag(match mode {
                SelinuxMode::Enforcing => 0,
                SelinuxMode::Permissive => 1,
            });
        });
        digest_legacy_bridge(&mut digest, &self.legacy_bridge);
        CapabilityProfileDigest(digest.finish())
    }

    #[must_use]
    pub const fn boot_identity(&self) -> &Observation<BootIdentity> {
        &self.boot_identity
    }

    #[must_use]
    pub const fn device_identity(&self) -> &Observation<DeviceIdentity> {
        &self.device_identity
    }

    #[must_use]
    pub const fn kernel(&self) -> &KernelFacts {
        &self.kernel
    }

    #[must_use]
    pub const fn selinux(&self) -> &Observation<SelinuxMode> {
        &self.selinux
    }

    #[must_use]
    pub const fn legacy_bridge(&self) -> &LegacyBridgeFacts {
        &self.legacy_bridge
    }

    #[must_use]
    pub fn kernel_support(&self) -> Option<KernelSupport> {
        self.kernel.support()
    }

    #[must_use]
    pub fn mutation_gate(&self) -> MutationGate {
        let kernel = match self.kernel_support() {
            Some(KernelSupport::Supported(_)) => KernelMutationStatus::Eligible,
            Some(KernelSupport::Unsupported { found, minimum }) => {
                KernelMutationStatus::Unsupported { found, minimum }
            }
            None => KernelMutationStatus::Unverified,
        };
        let boot_identity = match self.boot_identity {
            Observation::Verified(_) => BootIdentityMutationStatus::Verified,
            Observation::Absent
            | Observation::Denied
            | Observation::Malformed
            | Observation::Unavailable => BootIdentityMutationStatus::Unverified,
        };

        if matches!(kernel, KernelMutationStatus::Eligible)
            && matches!(boot_identity, BootIdentityMutationStatus::Verified)
        {
            MutationGate::Allowed
        } else {
            MutationGate::ReadOnly {
                kernel,
                boot_identity,
            }
        }
    }
}

fn digest_observation<T>(
    digest: &mut CanonicalEvidenceDigest,
    observation: &Observation<T>,
    encode: impl FnOnce(&mut CanonicalEvidenceDigest, &T),
) {
    match observation {
        Observation::Verified(value) => {
            digest.tag(0);
            encode(digest, value);
        }
        Observation::Absent => digest.tag(1),
        Observation::Denied => digest.tag(2),
        Observation::Malformed => digest.tag(3),
        Observation::Unavailable => digest.tag(4),
    }
}

fn digest_device_identity(digest: &mut CanonicalEvidenceDigest, identity: &DeviceIdentity) {
    digest.bytes(identity.android_product.as_str().as_bytes());
    digest.bytes(identity.android_build.as_str().as_bytes());
    digest.bytes(identity.vendor_build.as_str().as_bytes());
    digest.bytes(identity.security_patch.as_str().as_bytes());

    let verified_boot = identity.verified_boot;
    digest.tag(match verified_boot.state() {
        VerifiedBootState::Green => 0,
        VerifiedBootState::Yellow => 1,
        VerifiedBootState::Orange => 2,
        VerifiedBootState::Red => 3,
    });
    digest.boolean(verified_boot.device_locked());
    digest.bytes(verified_boot.vbmeta_digest().as_bytes());

    digest.bytes(identity.kernel_build.as_str().as_bytes());
    digest_artifact(digest, identity.selinux_policy.artifact());
    digest_artifact(digest, identity.netd);
    digest_artifact(digest, identity.connectivity);
    digest.usize(identity.tools.len());
    for (tool, artifact) in &identity.tools {
        digest.bytes(tool.as_str().as_bytes());
        digest_artifact(digest, *artifact);
    }
    digest_network_namespace(digest, identity.network_namespace);
}

fn digest_artifact(digest: &mut CanonicalEvidenceDigest, identity: ArtifactIdentity) {
    digest.bytes(identity.digest().as_bytes());
    digest.u64(identity.size());
}

fn digest_network_namespace(
    digest: &mut CanonicalEvidenceDigest,
    identity: NetworkNamespaceIdentity,
) {
    digest.u64(identity.device());
    digest.u64(identity.inode());
}

fn digest_kernel_version(digest: &mut CanonicalEvidenceDigest, version: KernelVersion) {
    digest.u16(version.major());
    digest.u16(version.minor());
    digest.u16(version.patch());
}

fn digest_legacy_bridge(digest: &mut CanonicalEvidenceDigest, bridge: &LegacyBridgeFacts) {
    for observation in [&bridge.shell, &bridge.dispatcher, &bridge.addrsync] {
        digest_observation(digest, observation, |digest, readiness| {
            digest.tag(match readiness.resolution() {
                LegacyArtifactResolution::Direct => 0,
                LegacyArtifactResolution::SymbolicLink => 1,
            });
            digest.boolean(readiness.is_ready());
        });
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationGate {
    Allowed,
    ReadOnly {
        kernel: KernelMutationStatus,
        boot_identity: BootIdentityMutationStatus,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelMutationStatus {
    Eligible,
    Unsupported {
        found: KernelVersion,
        minimum: KernelVersion,
    },
    Unverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootIdentityMutationStatus {
    Verified,
    Unverified,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BootIdentity(String);

impl BootIdentity {
    pub fn parse(value: &str) -> Result<Self, ParseBootIdentityError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(ParseBootIdentityError::new(
                ParseBootIdentityErrorKind::Empty,
            ));
        }
        if value.len() > MAX_BOOT_IDENTITY_BYTES {
            return Err(ParseBootIdentityError::new(
                ParseBootIdentityErrorKind::TooLong,
            ));
        }
        let bytes = value.as_bytes();
        let canonical = bytes.len() == 36
            && bytes.iter().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    *byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            });
        if !canonical {
            return Err(ParseBootIdentityError::new(
                ParseBootIdentityErrorKind::InvalidFormat,
            ));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BootIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseBootIdentityErrorKind {
    Empty,
    TooLong,
    InvalidFormat,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseBootIdentityError {
    kind: ParseBootIdentityErrorKind,
}

impl ParseBootIdentityError {
    const fn new(kind: ParseBootIdentityErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(&self) -> ParseBootIdentityErrorKind {
        self.kind
    }
}

impl fmt::Display for ParseBootIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ParseBootIdentityErrorKind::Empty => "boot identity is empty",
            ParseBootIdentityErrorKind::TooLong => "boot identity is too long",
            ParseBootIdentityErrorKind::InvalidFormat => "boot identity is not a canonical UUID",
        })
    }
}

impl Error for ParseBootIdentityError {}

macro_rules! bounded_identity_text {
    ($name:ident, $label:literal, $maximum:expr) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Box<str>);

        impl $name {
            pub fn new(value: &str) -> Result<Self, IdentityTextError> {
                if value.is_empty() {
                    return Err(IdentityTextError::new($label, IdentityTextErrorKind::Empty));
                }
                if value.len() > $maximum {
                    return Err(IdentityTextError::new(
                        $label,
                        IdentityTextErrorKind::TooLong {
                            maximum: $maximum,
                            actual: value.len(),
                        },
                    ));
                }
                if value.trim() != value {
                    return Err(IdentityTextError::new(
                        $label,
                        IdentityTextErrorKind::InvalidFormat,
                    ));
                }
                if value.chars().any(char::is_control) {
                    return Err(IdentityTextError::new(
                        $label,
                        IdentityTextErrorKind::ControlCharacter,
                    ));
                }
                if !value.is_ascii() {
                    return Err(IdentityTextError::new(
                        $label,
                        IdentityTextErrorKind::InvalidFormat,
                    ));
                }
                Ok(Self(value.into()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_identity_text!(
    AndroidProductIdentity,
    "Android product identity",
    MAX_DEVICE_IDENTITY_TEXT_BYTES
);
bounded_identity_text!(
    AndroidBuildIdentity,
    "Android build identity",
    MAX_DEVICE_IDENTITY_TEXT_BYTES
);
bounded_identity_text!(
    VendorBuildIdentity,
    "vendor build identity",
    MAX_DEVICE_IDENTITY_TEXT_BYTES
);
bounded_identity_text!(
    KernelBuildIdentity,
    "kernel build identity",
    MAX_DEVICE_IDENTITY_TEXT_BYTES
);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ToolId(Box<str>);

impl ToolId {
    pub fn new(value: &str) -> Result<Self, IdentityTextError> {
        if value.is_empty() {
            return Err(IdentityTextError::new(
                "tool identity",
                IdentityTextErrorKind::Empty,
            ));
        }
        if value.len() > MAX_TOOL_ID_BYTES {
            return Err(IdentityTextError::new(
                "tool identity",
                IdentityTextErrorKind::TooLong {
                    maximum: MAX_TOOL_ID_BYTES,
                    actual: value.len(),
                },
            ));
        }
        let mut bytes = value.bytes();
        if !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !bytes.all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(IdentityTextError::new(
                "tool identity",
                IdentityTextErrorKind::InvalidFormat,
            ));
        }
        Ok(Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ToolId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecurityPatchLevel(Box<str>);

impl SecurityPatchLevel {
    pub fn new(value: &str) -> Result<Self, IdentityTextError> {
        if value.is_empty() {
            return Err(IdentityTextError::new(
                "Android security patch level",
                IdentityTextErrorKind::Empty,
            ));
        }
        if !is_valid_security_patch_level(value) {
            return Err(IdentityTextError::new(
                "Android security patch level",
                IdentityTextErrorKind::InvalidFormat,
            ));
        }
        Ok(Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecurityPatchLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn is_valid_security_patch_level(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return false;
    }
    let year = parse_decimal(&bytes[0..4]);
    let month = parse_decimal(&bytes[5..7]);
    let day = parse_decimal(&bytes[8..10]);
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    year != 0 && (1..=maximum_day).contains(&day)
}

fn parse_decimal(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0'))
}

const fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityTextErrorKind {
    Empty,
    TooLong { maximum: usize, actual: usize },
    ControlCharacter,
    InvalidFormat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityTextError {
    field: &'static str,
    kind: IdentityTextErrorKind,
}

impl IdentityTextError {
    const fn new(field: &'static str, kind: IdentityTextErrorKind) -> Self {
        Self { field, kind }
    }

    #[must_use]
    pub const fn field(self) -> &'static str {
        self.field
    }

    #[must_use]
    pub const fn kind(self) -> IdentityTextErrorKind {
        self.kind
    }
}

impl fmt::Display for IdentityTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            IdentityTextErrorKind::Empty => write!(formatter, "{} is empty", self.field),
            IdentityTextErrorKind::TooLong { maximum, actual } => write!(
                formatter,
                "{} is {actual} bytes but its limit is {maximum}",
                self.field
            ),
            IdentityTextErrorKind::ControlCharacter => {
                write!(formatter, "{} contains a control character", self.field)
            }
            IdentityTextErrorKind::InvalidFormat => {
                write!(formatter, "{} has an invalid format", self.field)
            }
        }
    }
}

impl Error for IdentityTextError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; SHA256_DIGEST_BYTES]);

impl Sha256Digest {
    pub const fn new(bytes: [u8; SHA256_DIGEST_BYTES]) -> Result<Self, Sha256DigestError> {
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0 {
                return Ok(Self(bytes));
            }
            index += 1;
        }
        Err(Sha256DigestError::AllZero)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_DIGEST_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sha256DigestError {
    AllZero,
}

impl fmt::Display for Sha256DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SHA-256 identity digest is all zero")
    }
}

impl Error for Sha256DigestError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactIdentity {
    digest: Sha256Digest,
    size: NonZeroU64,
}

impl ArtifactIdentity {
    pub const fn new(digest: Sha256Digest, size: u64) -> Result<Self, ArtifactIdentityError> {
        match NonZeroU64::new(size) {
            Some(size) => Ok(Self { digest, size }),
            None => Err(ArtifactIdentityError::EmptyArtifact),
        }
    }

    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub const fn size(self) -> u64 {
        self.size.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactIdentityError {
    EmptyArtifact,
}

impl fmt::Display for ArtifactIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("artifact identity has zero size")
    }
}

impl Error for ArtifactIdentityError {}

/// Exact identity of the loaded SELinux policy artifact.
///
/// This remains a distinct domain type so a netd or Connectivity artifact cannot be passed in its
/// place accidentally at a reviewed-policy boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SelinuxPolicyIdentity(ArtifactIdentity);

impl SelinuxPolicyIdentity {
    pub const fn new(digest: Sha256Digest, size: u64) -> Result<Self, ArtifactIdentityError> {
        match ArtifactIdentity::new(digest, size) {
            Ok(identity) => Ok(Self(identity)),
            Err(error) => Err(error),
        }
    }

    #[must_use]
    pub const fn artifact(self) -> ArtifactIdentity {
        self.0
    }

    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.0.digest()
    }

    #[must_use]
    pub const fn size(self) -> u64 {
        self.0.size()
    }
}

impl From<ArtifactIdentity> for SelinuxPolicyIdentity {
    fn from(identity: ArtifactIdentity) -> Self {
        Self(identity)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum VerifiedBootState {
    Green,
    Yellow,
    Orange,
    Red,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VerifiedBootIdentity {
    state: VerifiedBootState,
    device_locked: bool,
    vbmeta_digest: Sha256Digest,
}

impl VerifiedBootIdentity {
    #[must_use]
    pub const fn new(
        state: VerifiedBootState,
        device_locked: bool,
        vbmeta_digest: Sha256Digest,
    ) -> Self {
        Self {
            state,
            device_locked,
            vbmeta_digest,
        }
    }

    #[must_use]
    pub const fn state(self) -> VerifiedBootState {
        self.state
    }

    #[must_use]
    pub const fn device_locked(self) -> bool {
        self.device_locked
    }

    #[must_use]
    pub const fn vbmeta_digest(self) -> Sha256Digest {
        self.vbmeta_digest
    }
}

/// Kernel object identity for one observed network namespace.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkNamespaceIdentity {
    device: u64,
    inode: NonZeroU64,
}

impl NetworkNamespaceIdentity {
    #[must_use]
    pub const fn new(device: u64, inode: u64) -> Option<Self> {
        match NonZeroU64::new(inode) {
            Some(inode) => Some(Self { device, inode }),
            None => None,
        }
    }

    #[must_use]
    pub const fn device(self) -> u64 {
        self.device
    }

    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode.get()
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceIdentity {
    android_product: AndroidProductIdentity,
    android_build: AndroidBuildIdentity,
    vendor_build: VendorBuildIdentity,
    security_patch: SecurityPatchLevel,
    verified_boot: VerifiedBootIdentity,
    kernel_build: KernelBuildIdentity,
    selinux_policy: SelinuxPolicyIdentity,
    netd: ArtifactIdentity,
    connectivity: ArtifactIdentity,
    tools: BTreeMap<ToolId, ArtifactIdentity>,
    network_namespace: NetworkNamespaceIdentity,
}

impl DeviceIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        android_product: AndroidProductIdentity,
        android_build: AndroidBuildIdentity,
        vendor_build: VendorBuildIdentity,
        security_patch: SecurityPatchLevel,
        verified_boot: VerifiedBootIdentity,
        kernel_build: KernelBuildIdentity,
        selinux_policy: SelinuxPolicyIdentity,
        netd: ArtifactIdentity,
        connectivity: ArtifactIdentity,
        tools: impl IntoIterator<Item = (ToolId, ArtifactIdentity)>,
        network_namespace: NetworkNamespaceIdentity,
    ) -> Result<Self, DeviceIdentityError> {
        let mut canonical_tools = BTreeMap::new();
        for (tool, identity) in tools {
            if canonical_tools.contains_key(&tool) {
                return Err(DeviceIdentityError::DuplicateTool { tool });
            }
            if canonical_tools.len() == MAX_DEVICE_TOOL_IDENTITIES {
                return Err(DeviceIdentityError::TooManyTools {
                    maximum: MAX_DEVICE_TOOL_IDENTITIES,
                    required_at_least: MAX_DEVICE_TOOL_IDENTITIES + 1,
                });
            }
            canonical_tools.insert(tool, identity);
        }
        if canonical_tools.is_empty() {
            return Err(DeviceIdentityError::NoTools);
        }
        Ok(Self {
            android_product,
            android_build,
            vendor_build,
            security_patch,
            verified_boot,
            kernel_build,
            selinux_policy,
            netd,
            connectivity,
            tools: canonical_tools,
            network_namespace,
        })
    }

    #[must_use]
    pub const fn android_product(&self) -> &AndroidProductIdentity {
        &self.android_product
    }

    #[must_use]
    pub const fn android_build(&self) -> &AndroidBuildIdentity {
        &self.android_build
    }

    #[must_use]
    pub const fn vendor_build(&self) -> &VendorBuildIdentity {
        &self.vendor_build
    }

    #[must_use]
    pub const fn security_patch(&self) -> &SecurityPatchLevel {
        &self.security_patch
    }

    #[must_use]
    pub const fn verified_boot(&self) -> VerifiedBootIdentity {
        self.verified_boot
    }

    #[must_use]
    pub const fn kernel_build(&self) -> &KernelBuildIdentity {
        &self.kernel_build
    }

    #[must_use]
    pub const fn selinux_policy(&self) -> SelinuxPolicyIdentity {
        self.selinux_policy
    }

    #[must_use]
    pub const fn netd(&self) -> ArtifactIdentity {
        self.netd
    }

    #[must_use]
    pub const fn connectivity(&self) -> ArtifactIdentity {
        self.connectivity
    }

    #[must_use]
    pub const fn tools(&self) -> &BTreeMap<ToolId, ArtifactIdentity> {
        &self.tools
    }

    #[must_use]
    pub const fn network_namespace(&self) -> NetworkNamespaceIdentity {
        self.network_namespace
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceIdentityError {
    NoTools,
    TooManyTools {
        maximum: usize,
        required_at_least: usize,
    },
    DuplicateTool {
        tool: ToolId,
    },
}

impl fmt::Display for DeviceIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTools => formatter.write_str("device identity contains no tool artifacts"),
            Self::TooManyTools {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "device identity contains at least {required_at_least} tool artifacts but its limit is {maximum}"
            ),
            Self::DuplicateTool { tool } => {
                write!(formatter, "device identity repeats tool {tool}")
            }
        }
    }
}

impl Error for DeviceIdentityError {}

/// Stable catalog key derived from an exact device identity.
///
/// Boot state, network namespace, and executing-tool artifacts are deliberately excluded. They
/// freshness-bind selected evidence, but an executable cannot contain its own full-file digest as
/// a compile-time catalog key without creating a self-referential build.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReviewedPolicySelector {
    android_product: AndroidProductIdentity,
    android_build: AndroidBuildIdentity,
    vendor_build: VendorBuildIdentity,
    security_patch: SecurityPatchLevel,
    kernel_build: KernelBuildIdentity,
    selinux_policy: SelinuxPolicyIdentity,
    netd: ArtifactIdentity,
    connectivity: ArtifactIdentity,
}

impl ReviewedPolicySelector {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_exact_parts(
        android_product: AndroidProductIdentity,
        android_build: AndroidBuildIdentity,
        vendor_build: VendorBuildIdentity,
        security_patch: SecurityPatchLevel,
        kernel_build: KernelBuildIdentity,
        selinux_policy: SelinuxPolicyIdentity,
        netd: ArtifactIdentity,
        connectivity: ArtifactIdentity,
    ) -> Self {
        Self {
            android_product,
            android_build,
            vendor_build,
            security_patch,
            kernel_build,
            selinux_policy,
            netd,
            connectivity,
        }
    }

    #[must_use]
    pub fn from_device_identity(identity: &DeviceIdentity) -> Self {
        Self {
            android_product: identity.android_product.clone(),
            android_build: identity.android_build.clone(),
            vendor_build: identity.vendor_build.clone(),
            security_patch: identity.security_patch.clone(),
            kernel_build: identity.kernel_build.clone(),
            selinux_policy: identity.selinux_policy,
            netd: identity.netd,
            connectivity: identity.connectivity,
        }
    }

    #[must_use]
    pub const fn android_product(&self) -> &AndroidProductIdentity {
        &self.android_product
    }

    #[must_use]
    pub const fn android_build(&self) -> &AndroidBuildIdentity {
        &self.android_build
    }

    #[must_use]
    pub const fn vendor_build(&self) -> &VendorBuildIdentity {
        &self.vendor_build
    }

    #[must_use]
    pub const fn security_patch(&self) -> &SecurityPatchLevel {
        &self.security_patch
    }

    #[must_use]
    pub const fn kernel_build(&self) -> &KernelBuildIdentity {
        &self.kernel_build
    }

    #[must_use]
    pub const fn selinux_policy(&self) -> SelinuxPolicyIdentity {
        self.selinux_policy
    }

    #[must_use]
    pub const fn netd(&self) -> ArtifactIdentity {
        self.netd
    }

    #[must_use]
    pub const fn connectivity(&self) -> ArtifactIdentity {
        self.connectivity
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KernelRelease(String);

impl KernelRelease {
    pub fn new(value: impl Into<String>) -> Result<Self, KernelReleaseError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_KERNEL_RELEASE_BYTES || value.contains('\0') {
            return Err(KernelReleaseError);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KernelRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelReleaseError;

impl fmt::Display for KernelReleaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("kernel release is empty, oversized, or contains NUL")
    }
}

impl Error for KernelReleaseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelFacts {
    release: Observation<KernelRelease>,
    version: Observation<KernelVersion>,
}

impl KernelFacts {
    #[must_use]
    pub fn from_release(release: Observation<KernelRelease>) -> Self {
        let version = match &release {
            Observation::Verified(release) => KernelVersion::parse_release(release.as_str())
                .map_or(Observation::Malformed, Observation::Verified),
            Observation::Absent => Observation::Absent,
            Observation::Denied => Observation::Denied,
            Observation::Malformed => Observation::Malformed,
            Observation::Unavailable => Observation::Unavailable,
        };
        Self { release, version }
    }

    #[must_use]
    pub const fn release(&self) -> &Observation<KernelRelease> {
        &self.release
    }

    #[must_use]
    pub const fn version(&self) -> &Observation<KernelVersion> {
        &self.version
    }

    #[must_use]
    pub fn support(&self) -> Option<KernelSupport> {
        match self.version {
            Observation::Verified(found) if found >= MIN_SUPPORTED_KERNEL => {
                Some(KernelSupport::Supported(found))
            }
            Observation::Verified(found) => Some(KernelSupport::Unsupported {
                found,
                minimum: MIN_SUPPORTED_KERNEL,
            }),
            Observation::Absent
            | Observation::Denied
            | Observation::Malformed
            | Observation::Unavailable => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KernelVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl KernelVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn parse_release(release: &str) -> Result<Self, ParseKernelVersionError> {
        let numeric_end = release
            .find(|character: char| !(character.is_ascii_digit() || character == '.'))
            .unwrap_or(release.len());
        let numeric = &release[..numeric_end];
        let mut components = numeric.split('.');
        let major = parse_required_component(components.next(), release)?;
        let minor = parse_required_component(components.next(), release)?;
        let patch = match components.next() {
            Some(value) if !value.is_empty() => value.parse::<u16>().map_err(|_| {
                ParseKernelVersionError::new(release, "expected numeric patch component")
            })?,
            _ => 0,
        };
        Ok(Self::new(major, minor, patch))
    }

    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }

    #[must_use]
    pub const fn patch(self) -> u16 {
        self.patch
    }
}

impl fmt::Display for KernelVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelSupport {
    Supported(KernelVersion),
    Unsupported {
        found: KernelVersion,
        minimum: KernelVersion,
    },
}

impl KernelSupport {
    pub fn evaluate(release: &str) -> Result<Self, ParseKernelVersionError> {
        let found = KernelVersion::parse_release(release)?;
        if found < MIN_SUPPORTED_KERNEL {
            return Ok(Self::Unsupported {
                found,
                minimum: MIN_SUPPORTED_KERNEL,
            });
        }
        Ok(Self::Supported(found))
    }

    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseKernelVersionError {
    release: String,
    reason: &'static str,
}

impl ParseKernelVersionError {
    fn new(release: &str, reason: &'static str) -> Self {
        Self {
            release: release.to_owned(),
            reason,
        }
    }
}

impl fmt::Display for ParseKernelVersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid kernel release '{}': {}",
            self.release, self.reason
        )
    }
}

impl Error for ParseKernelVersionError {}

fn parse_required_component(
    component: Option<&str>,
    release: &str,
) -> Result<u16, ParseKernelVersionError> {
    component
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| ParseKernelVersionError::new(release, "expected numeric major.minor"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelinuxMode {
    Enforcing,
    Permissive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyMutationWriter {
    Dispatcher,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyRuleBackend {
    IptablesRestore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyAddressSynchronization {
    StandaloneAddrsyncdViaScript,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyArtifactResolution {
    Direct,
    SymbolicLink,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyArtifactReadiness {
    resolution: LegacyArtifactResolution,
    executable: bool,
}

impl LegacyArtifactReadiness {
    #[must_use]
    pub const fn new(resolution: LegacyArtifactResolution, executable: bool) -> Self {
        Self {
            resolution,
            executable,
        }
    }

    #[must_use]
    pub const fn resolution(self) -> LegacyArtifactResolution {
        self.resolution
    }

    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.executable
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyBridgeFacts {
    shell: Observation<LegacyArtifactReadiness>,
    dispatcher: Observation<LegacyArtifactReadiness>,
    addrsync: Observation<LegacyArtifactReadiness>,
}

impl LegacyBridgeFacts {
    #[must_use]
    pub const fn new(
        shell: Observation<LegacyArtifactReadiness>,
        dispatcher: Observation<LegacyArtifactReadiness>,
        addrsync: Observation<LegacyArtifactReadiness>,
    ) -> Self {
        Self {
            shell,
            dispatcher,
            addrsync,
        }
    }

    #[must_use]
    pub const fn mutation_writer(&self) -> LegacyMutationWriter {
        LegacyMutationWriter::Dispatcher
    }

    #[must_use]
    pub const fn rule_backend(&self) -> LegacyRuleBackend {
        LegacyRuleBackend::IptablesRestore
    }

    #[must_use]
    pub const fn address_synchronization(&self) -> LegacyAddressSynchronization {
        LegacyAddressSynchronization::StandaloneAddrsyncdViaScript
    }

    #[must_use]
    pub const fn shell(&self) -> &Observation<LegacyArtifactReadiness> {
        &self.shell
    }

    #[must_use]
    pub const fn dispatcher(&self) -> &Observation<LegacyArtifactReadiness> {
        &self.dispatcher
    }

    #[must_use]
    pub const fn addrsync(&self) -> &Observation<LegacyArtifactReadiness> {
        &self.addrsync
    }
}
