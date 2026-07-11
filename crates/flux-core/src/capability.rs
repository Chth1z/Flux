use std::error::Error;
use std::fmt;

pub const CAPABILITY_PROFILE_SCHEMA_VERSION: u16 = 1;
pub const MIN_SUPPORTED_KERNEL: KernelVersion = KernelVersion::new(5, 10, 0);
pub const MAX_BOOT_IDENTITY_BYTES: usize = 128;
pub const MAX_KERNEL_RELEASE_BYTES: usize = 256;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityProfile {
    schema_version: u16,
    revision: CapabilityProfileRevision,
    boot_identity: Observation<BootIdentity>,
    kernel: KernelFacts,
    selinux: Observation<SelinuxMode>,
    legacy_bridge: LegacyBridgeFacts,
}

impl CapabilityProfile {
    #[must_use]
    pub const fn initial(
        boot_identity: Observation<BootIdentity>,
        kernel: KernelFacts,
        selinux: Observation<SelinuxMode>,
        legacy_bridge: LegacyBridgeFacts,
    ) -> Self {
        Self::new(
            CapabilityProfileRevision::INITIAL,
            boot_identity,
            kernel,
            selinux,
            legacy_bridge,
        )
    }

    #[must_use]
    pub const fn new(
        revision: CapabilityProfileRevision,
        boot_identity: Observation<BootIdentity>,
        kernel: KernelFacts,
        selinux: Observation<SelinuxMode>,
        legacy_bridge: LegacyBridgeFacts,
    ) -> Self {
        Self {
            schema_version: CAPABILITY_PROFILE_SCHEMA_VERSION,
            revision,
            boot_identity,
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

    #[must_use]
    pub const fn boot_identity(&self) -> &Observation<BootIdentity> {
        &self.boot_identity
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
    pub fn legacy_mutation_gate(&self) -> LegacyMutationGate {
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
            LegacyMutationGate::Allowed
        } else {
            LegacyMutationGate::ReadOnly {
                kernel,
                boot_identity,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyMutationGate {
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
