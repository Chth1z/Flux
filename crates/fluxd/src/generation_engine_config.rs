use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::num::NonZeroU16;

use serde::Deserialize;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use flux_core::{
    CapabilityProfile, KernelSupport, NetworkEpoch, NetworkInventory, NetworkInventorySnapshotId,
    ObservationKind,
};
use flux_platform::SingBoxReadiness;

use crate::engine_supervisor::{EngineCapabilityProbeError, EngineCapabilityProbeErrorKind};
use crate::{EngineArtifactDigest, EngineArtifactSetIdentity, EngineSpec, MAX_ENGINE_CONFIG_BYTES};

pub(crate) const GENERATION_ENGINE_CONFIG_SCHEMA_VERSION: u16 = 1;
pub(crate) const ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION: u16 = 1;
pub(crate) const ENGINE_CAPABILITY_PROFILE_SCHEMA_VERSION: u16 = 1;
pub(crate) const TPROXY_GENERATION_CANDIDATE_SCHEMA_VERSION: u16 = 1;
pub(crate) const MAX_GENERATION_ENGINE_CONFIG_INBOUNDS: usize = 256;

const ENGINE_CONFIG_DIGEST_BYTES: usize = 32;
const TEMPLATE_DIGEST_DOMAIN: &[u8] =
    b"Flux Generation Sing-Box template\0semantic-json\0sha256-v1\0";
const ARTIFACT_DIGEST_DOMAIN: &[u8] =
    b"Flux Generation Sing-Box engine config artifact\0sha256-v1\0";
const LAUNCH_BINDING_DIGEST_DOMAIN: &[u8] =
    b"Flux Generation Sing-Box engine config launch binding\0sha256-v1\0";
const ENGINE_CAPABILITY_PROFILE_DIGEST_DOMAIN: &[u8] =
    b"Flux Sing-Box Engine Capability Profile\0sha256-v1\0";
const SING_BOX_VERSION_PREFIX: &str = "sing-box version ";
const MAX_SING_BOX_RELEASE_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct EngineConfigArtifactDigest([u8; ENGINE_CONFIG_DIGEST_BYTES]);

impl EngineConfigArtifactDigest {
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; ENGINE_CONFIG_DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Display for EngineConfigArtifactDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TproxyEngineConfigRequest<'a> {
    template: &'a [u8],
    listener_port: NonZeroU16,
}

impl<'a> TproxyEngineConfigRequest<'a> {
    #[must_use]
    pub(crate) const fn new(template: &'a [u8], listener_port: NonZeroU16) -> Self {
        Self {
            template,
            listener_port,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EngineConfigResourceUsage {
    input_bytes: usize,
    output_bytes: usize,
    input_inbounds: usize,
    output_inbounds: usize,
}

impl EngineConfigResourceUsage {
    #[must_use]
    pub(crate) const fn input_bytes(self) -> usize {
        self.input_bytes
    }

    #[must_use]
    pub(crate) const fn output_bytes(self) -> usize {
        self.output_bytes
    }

    #[must_use]
    pub(crate) const fn input_inbounds(self) -> usize {
        self.input_inbounds
    }

    #[must_use]
    pub(crate) const fn output_inbounds(self) -> usize {
        self.output_inbounds
    }
}

/// Deterministic, non-authorizing Sing-Box configuration for one TPROXY candidate.
///
/// The artifact is a future member of a complete `GenerationArtifact`. It carries no Generation
/// ID, engine capability lease, process authority, writer token, or activation conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EngineConfigArtifact {
    listener_port: NonZeroU16,
    template_digest: [u8; ENGINE_CONFIG_DIGEST_BYTES],
    content_sha256: [u8; ENGINE_CONFIG_DIGEST_BYTES],
    digest: EngineConfigArtifactDigest,
    usage: EngineConfigResourceUsage,
    bytes: Box<[u8]>,
}

impl EngineConfigArtifact {
    #[must_use]
    pub(crate) const fn schema_version(&self) -> u16 {
        GENERATION_ENGINE_CONFIG_SCHEMA_VERSION
    }

    #[must_use]
    pub(crate) const fn listener_port(&self) -> NonZeroU16 {
        self.listener_port
    }

    #[must_use]
    pub(crate) const fn template_digest(&self) -> &[u8; ENGINE_CONFIG_DIGEST_BYTES] {
        &self.template_digest
    }

    /// Plain SHA-256 of `bytes`, suitable for exact comparison with `EngineSpec::config_digest`.
    #[must_use]
    pub(crate) const fn content_sha256(&self) -> &[u8; ENGINE_CONFIG_DIGEST_BYTES] {
        &self.content_sha256
    }

    #[must_use]
    pub(crate) const fn digest(&self) -> EngineConfigArtifactDigest {
        self.digest
    }

    #[must_use]
    pub(crate) const fn usage(&self) -> EngineConfigResourceUsage {
        self.usage
    }

    #[must_use]
    pub(crate) const fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct EngineConfigLaunchBindingDigest([u8; ENGINE_CONFIG_DIGEST_BYTES]);

impl EngineConfigLaunchBindingDigest {
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; ENGINE_CONFIG_DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Display for EngineConfigLaunchBindingDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Canonical configuration bound to one exact inspected launch-artifact set.
///
/// This is not an Engine Capability Profile, runtime readiness observation, process identity,
/// Generation, or activation token. It records only immutable artifact identities and the
/// pre-launch listener shape already declared by `EngineSpec`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EngineConfigLaunchBinding {
    artifact: EngineConfigArtifact,
    artifacts: EngineArtifactSetIdentity,
    digest: EngineConfigLaunchBindingDigest,
}

impl EngineConfigLaunchBinding {
    #[must_use]
    pub(crate) const fn schema_version(&self) -> u16 {
        ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION
    }

    #[must_use]
    pub(crate) const fn artifact(&self) -> &EngineConfigArtifact {
        &self.artifact
    }

    #[must_use]
    pub(crate) const fn artifacts(&self) -> EngineArtifactSetIdentity {
        self.artifacts
    }

    #[must_use]
    pub(crate) const fn binary_digest(&self) -> EngineArtifactDigest {
        self.artifacts.binary()
    }

    #[must_use]
    pub(crate) const fn config_digest(&self) -> EngineArtifactDigest {
        self.artifacts.config()
    }

    #[must_use]
    pub(crate) const fn launcher_digest(&self) -> Option<EngineArtifactDigest> {
        self.artifacts.launcher()
    }

    #[must_use]
    pub(crate) const fn digest(&self) -> EngineConfigLaunchBindingDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct EngineCapabilityProfileRevision([u8; ENGINE_CONFIG_DIGEST_BYTES]);

impl EngineCapabilityProfileRevision {
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; ENGINE_CONFIG_DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Display for EngineCapabilityProfileRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SingBoxVersionIdentity {
    release: Box<str>,
    major: u16,
    minor: u16,
    patch: u16,
}

impl SingBoxVersionIdentity {
    #[must_use]
    pub(crate) fn release(&self) -> &str {
        &self.release
    }

    #[must_use]
    pub(crate) const fn major(&self) -> u16 {
        self.major
    }

    #[must_use]
    pub(crate) const fn minor(&self) -> u16 {
        self.minor
    }

    #[must_use]
    pub(crate) const fn patch(&self) -> u16 {
        self.patch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SingBoxBuildIdentity {
    stdout: Box<str>,
    stderr: Box<str>,
}

impl SingBoxBuildIdentity {
    #[must_use]
    pub(crate) fn stdout(&self) -> &str {
        &self.stdout
    }

    #[must_use]
    pub(crate) fn stderr(&self) -> &str {
        &self.stderr
    }
}

/// Minimal immutable profile for the first canonical TPROXY Generation candidate.
///
/// Schema 1 proves only parsed exact-build identity and descriptor-pinned acceptance of the exact
/// config binding. Every other engine feature remains unclaimed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EngineCapabilityProfile {
    artifacts: EngineArtifactSetIdentity,
    validated_binding: EngineConfigLaunchBindingDigest,
    version: SingBoxVersionIdentity,
    build: SingBoxBuildIdentity,
    revision: EngineCapabilityProfileRevision,
}

impl EngineCapabilityProfile {
    #[must_use]
    pub(crate) const fn schema_version(&self) -> u16 {
        ENGINE_CAPABILITY_PROFILE_SCHEMA_VERSION
    }

    #[must_use]
    pub(crate) const fn artifacts(&self) -> EngineArtifactSetIdentity {
        self.artifacts
    }

    #[must_use]
    pub(crate) const fn validated_binding(&self) -> EngineConfigLaunchBindingDigest {
        self.validated_binding
    }

    #[must_use]
    pub(crate) const fn version(&self) -> &SingBoxVersionIdentity {
        &self.version
    }

    #[must_use]
    pub(crate) const fn build(&self) -> &SingBoxBuildIdentity {
        &self.build
    }

    #[must_use]
    pub(crate) const fn revision(&self) -> EngineCapabilityProfileRevision {
        self.revision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EngineVersionOutputErrorKind {
    InvalidUtf8 { stream: &'static str },
    UnsafeText { stream: &'static str },
    MissingVersionHeader,
    AmbiguousVersionHeader,
    InvalidRelease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EngineCapabilityProfileErrorKind {
    ArtifactSetMismatch,
    Probe(EngineCapabilityProbeErrorKind),
    VersionOutput(EngineVersionOutputErrorKind),
}

#[derive(Debug)]
pub(crate) struct EngineCapabilityProfileError {
    kind: EngineCapabilityProfileErrorKind,
    source: Option<Box<EngineCapabilityProbeError>>,
}

impl EngineCapabilityProfileError {
    #[must_use]
    pub(crate) const fn kind(&self) -> EngineCapabilityProfileErrorKind {
        self.kind
    }

    const fn without_source(kind: EngineCapabilityProfileErrorKind) -> Self {
        Self { kind, source: None }
    }
}

impl fmt::Display for EngineCapabilityProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            EngineCapabilityProfileErrorKind::ArtifactSetMismatch => formatter.write_str(
                "engine config binding and EngineSpec identify different launch artifacts",
            ),
            EngineCapabilityProfileErrorKind::Probe(_) => {
                formatter.write_str("exact Proxy Engine capability probe failed")
            }
            EngineCapabilityProfileErrorKind::VersionOutput(kind) => {
                write!(
                    formatter,
                    "invalid exact Proxy Engine version output: {kind:?}"
                )
            }
        }
    }
}

impl Error for EngineCapabilityProfileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

pub(crate) fn collect_tproxy_engine_capability_profile(
    binding: &EngineConfigLaunchBinding,
    spec: &EngineSpec,
) -> Result<EngineCapabilityProfile, EngineCapabilityProfileError> {
    if binding.artifacts() != spec.artifacts() {
        return Err(EngineCapabilityProfileError::without_source(
            EngineCapabilityProfileErrorKind::ArtifactSetMismatch,
        ));
    }

    let probe = spec.probe_capabilities().map_err(|source| {
        let kind = EngineCapabilityProfileErrorKind::Probe(source.kind());
        EngineCapabilityProfileError {
            kind,
            source: Some(Box::new(source)),
        }
    })?;
    debug_assert_eq!(probe.artifacts(), binding.artifacts());
    let (version, build) =
        parse_sing_box_version_output(probe.version_stdout(), probe.version_stderr())?;
    let revision = EngineCapabilityProfileRevision(digest_engine_capability_profile(
        binding, &version, &build,
    ));
    Ok(EngineCapabilityProfile {
        artifacts: probe.artifacts(),
        validated_binding: binding.digest(),
        version,
        build,
        revision,
    })
}

/// Deterministic, non-authorizing input bundle for later complete Generation compilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TproxyGenerationCandidate {
    device_profile: CapabilityProfile,
    inventory_snapshot: NetworkInventorySnapshotId,
    inventory_epoch: NetworkEpoch,
    engine_profile: EngineCapabilityProfile,
    engine_config: EngineConfigLaunchBinding,
}

impl TproxyGenerationCandidate {
    #[must_use]
    pub(crate) const fn schema_version(&self) -> u16 {
        TPROXY_GENERATION_CANDIDATE_SCHEMA_VERSION
    }

    #[must_use]
    pub(crate) const fn device_profile(&self) -> &CapabilityProfile {
        &self.device_profile
    }

    #[must_use]
    pub(crate) const fn inventory_snapshot(&self) -> NetworkInventorySnapshotId {
        self.inventory_snapshot
    }

    #[must_use]
    pub(crate) const fn inventory_epoch(&self) -> NetworkEpoch {
        self.inventory_epoch
    }

    #[must_use]
    pub(crate) const fn engine_profile(&self) -> &EngineCapabilityProfile {
        &self.engine_profile
    }

    #[must_use]
    pub(crate) const fn engine_config(&self) -> &EngineConfigLaunchBinding {
        &self.engine_config
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TproxyGenerationCandidateErrorKind {
    EngineArtifactSetMismatch,
    EngineBindingMismatch,
    BootIdentityNotVerified { observation: ObservationKind },
    DeviceIdentityNotVerified { observation: ObservationKind },
    KernelNotSupported { support: Option<KernelSupport> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TproxyGenerationCandidateError {
    kind: TproxyGenerationCandidateErrorKind,
}

impl TproxyGenerationCandidateError {
    #[must_use]
    pub(crate) const fn kind(self) -> TproxyGenerationCandidateErrorKind {
        self.kind
    }
}

impl fmt::Display for TproxyGenerationCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            TproxyGenerationCandidateErrorKind::EngineArtifactSetMismatch => formatter.write_str(
                "Engine Capability Profile and config binding identify different artifacts",
            ),
            TproxyGenerationCandidateErrorKind::EngineBindingMismatch => formatter
                .write_str("Engine Capability Profile did not validate this exact config binding"),
            TproxyGenerationCandidateErrorKind::BootIdentityNotVerified { .. } => {
                formatter.write_str("device boot identity is not verified")
            }
            TproxyGenerationCandidateErrorKind::DeviceIdentityNotVerified { .. } => {
                formatter.write_str("exact device identity is not verified")
            }
            TproxyGenerationCandidateErrorKind::KernelNotSupported { .. } => {
                formatter.write_str("device kernel is not verified at the supported floor")
            }
        }
    }
}

impl Error for TproxyGenerationCandidateError {}

pub(crate) fn compile_tproxy_generation_candidate(
    device_profile: CapabilityProfile,
    inventory: &NetworkInventory,
    engine_profile: EngineCapabilityProfile,
    engine_config: EngineConfigLaunchBinding,
) -> Result<TproxyGenerationCandidate, TproxyGenerationCandidateError> {
    if engine_profile.artifacts() != engine_config.artifacts() {
        return Err(TproxyGenerationCandidateError {
            kind: TproxyGenerationCandidateErrorKind::EngineArtifactSetMismatch,
        });
    }
    if engine_profile.validated_binding() != engine_config.digest() {
        return Err(TproxyGenerationCandidateError {
            kind: TproxyGenerationCandidateErrorKind::EngineBindingMismatch,
        });
    }
    if device_profile.boot_identity().verified().is_none() {
        return Err(TproxyGenerationCandidateError {
            kind: TproxyGenerationCandidateErrorKind::BootIdentityNotVerified {
                observation: device_profile.boot_identity().kind(),
            },
        });
    }
    if device_profile.device_identity().verified().is_none() {
        return Err(TproxyGenerationCandidateError {
            kind: TproxyGenerationCandidateErrorKind::DeviceIdentityNotVerified {
                observation: device_profile.device_identity().kind(),
            },
        });
    }
    let support = device_profile.kernel_support();
    if !support.is_some_and(KernelSupport::is_supported) {
        return Err(TproxyGenerationCandidateError {
            kind: TproxyGenerationCandidateErrorKind::KernelNotSupported { support },
        });
    }

    Ok(TproxyGenerationCandidate {
        device_profile,
        inventory_snapshot: inventory.snapshot_id(),
        inventory_epoch: inventory.epoch(),
        engine_profile,
        engine_config,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EngineConfigBindingErrorKind {
    ConfigDigestMismatch {
        artifact: [u8; ENGINE_CONFIG_DIGEST_BYTES],
        engine_spec: EngineArtifactDigest,
    },
    ListenerPortMismatch {
        artifact: NonZeroU16,
        engine_spec: NonZeroU16,
    },
    TunReadinessUnsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EngineConfigBindingError {
    kind: EngineConfigBindingErrorKind,
}

impl EngineConfigBindingError {
    #[must_use]
    pub(crate) const fn kind(self) -> EngineConfigBindingErrorKind {
        self.kind
    }
}

impl fmt::Display for EngineConfigBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            EngineConfigBindingErrorKind::ConfigDigestMismatch { .. } => formatter.write_str(
                "canonical engine configuration does not match the inspected EngineSpec config digest",
            ),
            EngineConfigBindingErrorKind::ListenerPortMismatch {
                artifact,
                engine_spec,
            } => write!(
                formatter,
                "canonical TPROXY listener port {artifact} does not match EngineSpec listener port {engine_spec}"
            ),
            EngineConfigBindingErrorKind::TunReadinessUnsupported => formatter.write_str(
                "canonical TPROXY engine configuration cannot bind to EngineSpec TUN readiness",
            ),
        }
    }
}

impl Error for EngineConfigBindingError {}

/// Bind a canonical config to one already inspected launch request without I/O or runtime claims.
pub(crate) fn bind_engine_config_to_spec(
    artifact: EngineConfigArtifact,
    spec: &EngineSpec,
) -> Result<EngineConfigLaunchBinding, EngineConfigBindingError> {
    let config_digest = spec.config_digest();
    if artifact.content_sha256() != config_digest.as_bytes() {
        return Err(EngineConfigBindingError {
            kind: EngineConfigBindingErrorKind::ConfigDigestMismatch {
                artifact: *artifact.content_sha256(),
                engine_spec: config_digest,
            },
        });
    }

    match &spec.process().readiness {
        SingBoxReadiness::Listener { port } if *port == artifact.listener_port() => {}
        SingBoxReadiness::Listener { port } => {
            return Err(EngineConfigBindingError {
                kind: EngineConfigBindingErrorKind::ListenerPortMismatch {
                    artifact: artifact.listener_port(),
                    engine_spec: *port,
                },
            });
        }
        SingBoxReadiness::TunInterface { .. } => {
            return Err(EngineConfigBindingError {
                kind: EngineConfigBindingErrorKind::TunReadinessUnsupported,
            });
        }
    }

    let artifacts = spec.artifacts();
    let digest = EngineConfigLaunchBindingDigest(digest_engine_config_launch_binding(
        artifact.digest(),
        artifacts,
    ));
    Ok(EngineConfigLaunchBinding {
        artifact,
        artifacts,
        digest,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EngineConfigCompileErrorKind {
    TemplateTooLarge { actual: usize, maximum: u64 },
    InvalidJson,
    RootNotObject,
    InboundsNotArray,
    TooManyInbounds { actual: usize, maximum: usize },
    InboundNotObject { index: usize },
    InboundTypeMissing { index: usize },
    InboundTypeNotString { index: usize },
    MultipleTproxyInbounds,
    OutputTooLarge { actual: usize, maximum: u64 },
    Encode,
}

#[derive(Debug)]
pub(crate) struct EngineConfigCompileError {
    kind: EngineConfigCompileErrorKind,
    source: Option<serde_json::Error>,
}

impl EngineConfigCompileError {
    #[must_use]
    pub(crate) const fn kind(&self) -> EngineConfigCompileErrorKind {
        self.kind
    }

    const fn without_source(kind: EngineConfigCompileErrorKind) -> Self {
        Self { kind, source: None }
    }

    const fn with_source(kind: EngineConfigCompileErrorKind, source: serde_json::Error) -> Self {
        Self {
            kind,
            source: Some(source),
        }
    }
}

impl fmt::Display for EngineConfigCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            EngineConfigCompileErrorKind::TemplateTooLarge { actual, maximum } => write!(
                formatter,
                "Sing-Box template is {actual} bytes, exceeding the {maximum}-byte Generation budget"
            ),
            EngineConfigCompileErrorKind::InvalidJson => match &self.source {
                Some(source) => write!(formatter, "invalid Sing-Box template JSON: {source}"),
                None => formatter.write_str("invalid Sing-Box template JSON"),
            },
            EngineConfigCompileErrorKind::RootNotObject => {
                formatter.write_str("Sing-Box template root must be a JSON object")
            }
            EngineConfigCompileErrorKind::InboundsNotArray => {
                formatter.write_str("Sing-Box template field 'inbounds' must be a JSON array")
            }
            EngineConfigCompileErrorKind::TooManyInbounds { actual, maximum } => write!(
                formatter,
                "Sing-Box template contains {actual} inbounds, exceeding the Generation budget of {maximum}"
            ),
            EngineConfigCompileErrorKind::InboundNotObject { index } => write!(
                formatter,
                "Sing-Box template inbound {index} must be a JSON object"
            ),
            EngineConfigCompileErrorKind::InboundTypeMissing { index } => write!(
                formatter,
                "Sing-Box template inbound {index} is missing string field 'type'"
            ),
            EngineConfigCompileErrorKind::InboundTypeNotString { index } => write!(
                formatter,
                "Sing-Box template inbound {index} field 'type' must be a string"
            ),
            EngineConfigCompileErrorKind::MultipleTproxyInbounds => formatter.write_str(
                "Sing-Box template contains multiple TPROXY inbounds; one canonical listener is required",
            ),
            EngineConfigCompileErrorKind::OutputTooLarge { actual, maximum } => write!(
                formatter,
                "compiled Sing-Box configuration is {actual} bytes, exceeding the {maximum}-byte Generation budget"
            ),
            EngineConfigCompileErrorKind::Encode => match &self.source {
                Some(source) => write!(
                    formatter,
                    "cannot encode the canonical Sing-Box Generation configuration: {source}"
                ),
                None => formatter
                    .write_str("cannot encode the canonical Sing-Box Generation configuration"),
            },
        }
    }
}

impl Error for EngineConfigCompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// Compile one bounded, deterministic TCP/UDP TPROXY engine configuration without I/O.
pub(crate) fn compile_tproxy_engine_config(
    request: TproxyEngineConfigRequest<'_>,
) -> Result<EngineConfigArtifact, EngineConfigCompileError> {
    if bytes_exceed_limit(request.template.len(), MAX_ENGINE_CONFIG_BYTES) {
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::TemplateTooLarge {
                actual: request.template.len(),
                maximum: MAX_ENGINE_CONFIG_BYTES,
            },
        ));
    }

    let parsed = parse_strict_json(request.template)?;
    let parsed = canonicalize_json(parsed);
    let canonical_template = serde_json::to_vec(&parsed).map_err(|source| {
        EngineConfigCompileError::with_source(EngineConfigCompileErrorKind::Encode, source)
    })?;
    let template_digest = digest_with_domain(TEMPLATE_DIGEST_DOMAIN, &canonical_template);

    let Value::Object(mut document) = parsed else {
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::RootNotObject,
        ));
    };
    let raw_inbounds = document
        .remove("inbounds")
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let Value::Array(inbounds) = raw_inbounds else {
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::InboundsNotArray,
        ));
    };
    if inbounds.len() > MAX_GENERATION_ENGINE_CONFIG_INBOUNDS {
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::TooManyInbounds {
                actual: inbounds.len(),
                maximum: MAX_GENERATION_ENGINE_CONFIG_INBOUNDS,
            },
        ));
    }

    let input_inbounds = inbounds.len();
    let mut output_inbounds = Vec::with_capacity(input_inbounds.saturating_add(1));
    let mut found_tproxy = false;
    for (index, inbound) in inbounds.into_iter().enumerate() {
        let Value::Object(mut inbound) = inbound else {
            return Err(EngineConfigCompileError::without_source(
                EngineConfigCompileErrorKind::InboundNotObject { index },
            ));
        };
        let inbound_type = match inbound.get("type") {
            Some(Value::String(value)) => value.as_str(),
            Some(_) => {
                return Err(EngineConfigCompileError::without_source(
                    EngineConfigCompileErrorKind::InboundTypeNotString { index },
                ));
            }
            None => {
                return Err(EngineConfigCompileError::without_source(
                    EngineConfigCompileErrorKind::InboundTypeMissing { index },
                ));
            }
        };
        match inbound_type {
            "tun" => continue,
            "tproxy" => {
                if found_tproxy {
                    return Err(EngineConfigCompileError::without_source(
                        EngineConfigCompileErrorKind::MultipleTproxyInbounds,
                    ));
                }
                found_tproxy = true;
                normalize_tproxy_inbound(&mut inbound, request.listener_port);
            }
            _ => {}
        }
        output_inbounds.push(Value::Object(inbound));
    }
    if !found_tproxy {
        output_inbounds.push(Value::Object(default_tproxy_inbound(request.listener_port)));
    }
    let output_inbound_count = output_inbounds.len();
    document.insert("inbounds".to_owned(), Value::Array(output_inbounds));

    let output = canonicalize_json(Value::Object(document));
    let mut bytes = serde_json::to_vec(&output).map_err(|source| {
        EngineConfigCompileError::with_source(EngineConfigCompileErrorKind::Encode, source)
    })?;
    bytes.push(b'\n');
    if bytes_exceed_limit(bytes.len(), MAX_ENGINE_CONFIG_BYTES) {
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::OutputTooLarge {
                actual: bytes.len(),
                maximum: MAX_ENGINE_CONFIG_BYTES,
            },
        ));
    }

    let content_sha256 = sha256(&bytes);
    let digest = EngineConfigArtifactDigest(digest_engine_config_artifact(
        request.listener_port,
        template_digest,
        content_sha256,
        input_inbounds,
        output_inbound_count,
    ));
    Ok(EngineConfigArtifact {
        listener_port: request.listener_port,
        template_digest,
        content_sha256,
        digest,
        usage: EngineConfigResourceUsage {
            input_bytes: request.template.len(),
            output_bytes: bytes.len(),
            input_inbounds,
            output_inbounds: output_inbound_count,
        },
        bytes: bytes.into_boxed_slice(),
    })
}

fn normalize_tproxy_inbound(inbound: &mut Map<String, Value>, port: NonZeroU16) {
    inbound.insert("listen".to_owned(), Value::String("::".to_owned()));
    inbound.insert(
        "listen_port".to_owned(),
        Value::Number(Number::from(port.get())),
    );
    // Absence is Sing-Box's exact TCP+UDP selection. A narrower inherited value must not silently
    // weaken the first canonical Capture Path.
    inbound.remove("network");
}

fn default_tproxy_inbound(port: NonZeroU16) -> Map<String, Value> {
    let mut inbound = Map::new();
    inbound.insert("type".to_owned(), Value::String("tproxy".to_owned()));
    inbound.insert("tag".to_owned(), Value::String("tproxy-in".to_owned()));
    normalize_tproxy_inbound(&mut inbound, port);
    inbound
}

fn bytes_exceed_limit(actual: usize, maximum: u64) -> bool {
    u64::try_from(actual).map_or(true, |actual| actual > maximum)
}

fn parse_sing_box_version_output(
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(SingBoxVersionIdentity, SingBoxBuildIdentity), EngineCapabilityProfileError> {
    let stdout = exact_safe_version_text(stdout, "stdout")?;
    let stderr = exact_safe_version_text(stderr, "stderr")?;
    let mut release = None;
    for line in stdout.lines().chain(stderr.lines()) {
        let Some(candidate) = line.strip_prefix(SING_BOX_VERSION_PREFIX) else {
            continue;
        };
        if release.replace(candidate).is_some() {
            return Err(engine_version_output_error(
                EngineVersionOutputErrorKind::AmbiguousVersionHeader,
            ));
        }
    }
    let release = release.ok_or_else(|| {
        engine_version_output_error(EngineVersionOutputErrorKind::MissingVersionHeader)
    })?;
    let (major, minor, patch) = parse_sing_box_release(release)
        .ok_or_else(|| engine_version_output_error(EngineVersionOutputErrorKind::InvalidRelease))?;

    Ok((
        SingBoxVersionIdentity {
            release: release.into(),
            major,
            minor,
            patch,
        },
        SingBoxBuildIdentity {
            stdout: stdout.into(),
            stderr: stderr.into(),
        },
    ))
}

fn exact_safe_version_text<'a>(
    bytes: &'a [u8],
    stream: &'static str,
) -> Result<&'a str, EngineCapabilityProfileError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        engine_version_output_error(EngineVersionOutputErrorKind::InvalidUtf8 { stream })
    })?;
    let unsafe_control = text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'));
    let bare_carriage_return = bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'));
    if unsafe_control || bare_carriage_return {
        return Err(engine_version_output_error(
            EngineVersionOutputErrorKind::UnsafeText { stream },
        ));
    }
    Ok(text)
}

fn parse_sing_box_release(release: &str) -> Option<(u16, u16, u16)> {
    if release.is_empty() || release.len() > MAX_SING_BOX_RELEASE_BYTES || !release.is_ascii() {
        return None;
    }

    let (without_build, build) = match release.split_once('+') {
        Some((version, build)) if valid_semver_identifiers(build, false) => (version, Some(build)),
        Some(_) => return None,
        None => (release, None),
    };
    debug_assert!(build.is_none_or(|value| !value.is_empty()));
    let (core, prerelease) = match without_build.split_once('-') {
        Some((core, prerelease)) if valid_semver_identifiers(prerelease, true) => {
            (core, Some(prerelease))
        }
        Some(_) => return None,
        None => (without_build, None),
    };
    debug_assert!(prerelease.is_none_or(|value| !value.is_empty()));

    let mut components = core.split('.');
    let major = parse_semver_component(components.next()?)?;
    let minor = parse_semver_component(components.next()?)?;
    let patch = parse_semver_component(components.next()?)?;
    if components.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn parse_semver_component(component: &str) -> Option<u16> {
    if component.is_empty()
        || !component.bytes().all(|byte| byte.is_ascii_digit())
        || (component.len() > 1 && component.starts_with('0'))
    {
        return None;
    }
    component.parse().ok()
}

fn valid_semver_identifiers(value: &str, reject_numeric_leading_zero: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!reject_numeric_leading_zero
                    || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || identifier.len() == 1
                    || !identifier.starts_with('0'))
        })
}

fn engine_version_output_error(kind: EngineVersionOutputErrorKind) -> EngineCapabilityProfileError {
    EngineCapabilityProfileError::without_source(EngineCapabilityProfileErrorKind::VersionOutput(
        kind,
    ))
}

fn digest_engine_config_artifact(
    listener_port: NonZeroU16,
    template_digest: [u8; ENGINE_CONFIG_DIGEST_BYTES],
    content_sha256: [u8; ENGINE_CONFIG_DIGEST_BYTES],
    input_inbound_count: usize,
    output_inbound_count: usize,
) -> [u8; ENGINE_CONFIG_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(ARTIFACT_DIGEST_DOMAIN);
    digest.update(GENERATION_ENGINE_CONFIG_SCHEMA_VERSION.to_be_bytes());
    digest.update(listener_port.get().to_be_bytes());
    digest.update(template_digest);
    digest.update(content_sha256);
    digest.update(length_bytes(input_inbound_count));
    digest.update(length_bytes(output_inbound_count));
    digest.finalize().into()
}

fn digest_engine_config_launch_binding(
    artifact_digest: EngineConfigArtifactDigest,
    artifacts: EngineArtifactSetIdentity,
) -> [u8; ENGINE_CONFIG_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(LAUNCH_BINDING_DIGEST_DOMAIN);
    digest.update(ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION.to_be_bytes());
    digest.update(artifact_digest.as_bytes());
    digest.update(artifacts.binary().as_bytes());
    digest.update(artifacts.config().as_bytes());
    match artifacts.launcher() {
        Some(launcher_digest) => {
            digest.update([1]);
            digest.update(launcher_digest.as_bytes());
        }
        None => digest.update([0]),
    }
    digest.finalize().into()
}

fn digest_engine_capability_profile(
    binding: &EngineConfigLaunchBinding,
    version: &SingBoxVersionIdentity,
    build: &SingBoxBuildIdentity,
) -> [u8; ENGINE_CONFIG_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(ENGINE_CAPABILITY_PROFILE_DIGEST_DOMAIN);
    update_length_prefixed(
        &mut digest,
        &ENGINE_CAPABILITY_PROFILE_SCHEMA_VERSION.to_be_bytes(),
    );
    update_length_prefixed(&mut digest, binding.digest().as_bytes());
    let artifacts = binding.artifacts();
    update_length_prefixed(&mut digest, artifacts.binary().as_bytes());
    update_length_prefixed(&mut digest, artifacts.config().as_bytes());
    match artifacts.launcher() {
        Some(launcher) => {
            update_length_prefixed(&mut digest, &[1]);
            update_length_prefixed(&mut digest, launcher.as_bytes());
        }
        None => update_length_prefixed(&mut digest, &[0]),
    }
    update_length_prefixed(&mut digest, version.release().as_bytes());
    update_length_prefixed(&mut digest, &version.major().to_be_bytes());
    update_length_prefixed(&mut digest, &version.minor().to_be_bytes());
    update_length_prefixed(&mut digest, &version.patch().to_be_bytes());
    update_length_prefixed(&mut digest, build.stdout().as_bytes());
    update_length_prefixed(&mut digest, build.stderr().as_bytes());
    digest.finalize().into()
}

fn update_length_prefixed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(length_bytes(bytes.len()));
    digest.update(bytes);
}

fn digest_with_domain(domain: &[u8], bytes: &[u8]) -> [u8; ENGINE_CONFIG_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(length_bytes(bytes.len()));
    digest.update(bytes);
    digest.finalize().into()
}

fn sha256(bytes: &[u8]) -> [u8; ENGINE_CONFIG_DIGEST_BYTES] {
    Sha256::digest(bytes).into()
}

fn length_bytes(value: usize) -> [u8; 8] {
    u64::try_from(value)
        .expect("supported Flux targets represent bounded configuration lengths in u64")
        .to_be_bytes()
}

fn parse_strict_json(bytes: &[u8]) -> Result<Value, EngineConfigCompileError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|source| {
            EngineConfigCompileError::with_source(EngineConfigCompileErrorKind::InvalidJson, source)
        })?
        .0;
    deserializer.end().map_err(|source| {
        EngineConfigCompileError::with_source(EngineConfigCompileErrorKind::InvalidJson, source)
    })?;
    Ok(value)
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar,
    }
}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some((key, value)) = map.next_entry::<String, StrictJsonValue>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(format_args!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            values.insert(key, value.0);
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::num::NonZeroU16;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use flux_core::{
        CapabilityProfile, InterfaceAddressRecord, InterfaceLinkRecord, KernelSupport,
        NetworkInventoryTracker, ObservationKind,
    };
    use flux_platform::internal::SingBoxProcessError;
    use flux_platform::{SingBoxLaunchSpec, SingBoxLauncher, SingBoxReadiness};
    use flux_testkit::CapabilityProfileFixture;

    use super::{
        ENGINE_CAPABILITY_PROFILE_SCHEMA_VERSION, ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION,
        EngineCapabilityProfileErrorKind, EngineConfigBindingErrorKind,
        EngineConfigCompileErrorKind, EngineVersionOutputErrorKind,
        GENERATION_ENGINE_CONFIG_SCHEMA_VERSION, MAX_GENERATION_ENGINE_CONFIG_INBOUNDS,
        TPROXY_GENERATION_CANDIDATE_SCHEMA_VERSION, TproxyEngineConfigRequest,
        TproxyGenerationCandidateErrorKind, bind_engine_config_to_spec,
        collect_tproxy_engine_capability_profile, compile_tproxy_engine_config,
        compile_tproxy_generation_candidate, parse_sing_box_version_output,
    };
    use crate::engine_supervisor::EngineCapabilityProbeError;
    use crate::{EngineSpec, MAX_ENGINE_CONFIG_BYTES, RestartPolicy};

    const PORT: u16 = 1536;

    #[test]
    fn compiles_one_canonical_tcp_udp_tproxy_inbound() {
        let template = br#"{
            "route": {"rules": []},
            "inbounds": [
                {"type": "mixed", "tag": "mixed-in"},
                {
                    "type": "tproxy",
                    "tag": "existing-tproxy",
                    "listen": "127.0.0.1",
                    "listen_port": 1,
                    "network": "udp",
                    "sniff": true
                },
                {"type": "tun", "tag": "old-tun"}
            ]
        }"#;

        let artifact = compile(template, PORT).expect("canonical TPROXY configuration");

        assert_eq!(
            artifact.bytes(),
            concat!(
                "{\"inbounds\":[",
                "{\"tag\":\"mixed-in\",\"type\":\"mixed\"},",
                "{\"listen\":\"::\",\"listen_port\":1536,\"sniff\":true,",
                "\"tag\":\"existing-tproxy\",\"type\":\"tproxy\"}",
                "],\"route\":{\"rules\":[]}}\n"
            )
            .as_bytes()
        );
        assert_eq!(
            artifact.schema_version(),
            GENERATION_ENGINE_CONFIG_SCHEMA_VERSION
        );
        assert_eq!(artifact.listener_port().get(), PORT);
        assert_eq!(artifact.usage().input_inbounds(), 3);
        assert_eq!(artifact.usage().output_inbounds(), 2);
        assert_eq!(artifact.usage().input_bytes(), template.len());
        assert_eq!(artifact.usage().output_bytes(), artifact.bytes().len());
        assert_eq!(
            hex(artifact.content_sha256()),
            "d06fd8595a4a85897ad2c5fe68a4ab42ce126afad4570546142c3bc7bf489470"
        );
        assert_eq!(
            artifact.digest().to_string(),
            "fa4d5069c6bb6d889bbf1edb4ea0459f0697c7a6b82f17fda83c87e9774d033f"
        );
        assert_eq!(artifact.digest().as_bytes().len(), 32);
    }

    #[test]
    fn adds_the_default_listener_when_the_template_has_none() {
        let artifact = compile(br#"{"inbounds":[],"log":{"level":"info"}}"#, PORT)
            .expect("missing TPROXY listener is generated");

        assert_eq!(
            artifact.bytes(),
            concat!(
                "{\"inbounds\":[{\"listen\":\"::\",\"listen_port\":1536,",
                "\"tag\":\"tproxy-in\",\"type\":\"tproxy\"}],",
                "\"log\":{\"level\":\"info\"}}\n"
            )
            .as_bytes()
        );
    }

    #[test]
    fn semantic_template_key_order_does_not_change_identities_or_output() {
        let first = compile(
            br#"{"route":{"final":"proxy"},"inbounds":[],"log":{"level":"warn"}}"#,
            PORT,
        )
        .unwrap();
        let second = compile(
            br#" { "log" : { "level" : "warn" }, "inbounds" : [ ], "route" : { "final" : "proxy" } } "#,
            PORT,
        )
        .unwrap();

        assert_eq!(first.bytes(), second.bytes());
        assert_eq!(first.template_digest(), second.template_digest());
        assert_eq!(first.content_sha256(), second.content_sha256());
        assert_eq!(first.digest(), second.digest());
    }

    #[test]
    fn listener_port_changes_only_the_compiled_identity_not_the_template_identity() {
        let template = br#"{"inbounds":[]}"#;
        let first = compile(template, PORT).unwrap();
        let second = compile(template, PORT + 1).unwrap();

        assert_eq!(first.template_digest(), second.template_digest());
        assert_ne!(first.content_sha256(), second.content_sha256());
        assert_ne!(first.digest(), second.digest());
    }

    #[test]
    fn binds_exact_config_listener_and_launch_artifact_identities() {
        let artifact =
            compile(br#"{"inbounds":[{"type":"tproxy","network":"udp"}]}"#, PORT).unwrap();
        let artifact_digest = artifact.digest();
        let fixture = EngineSpecFixture::new(
            artifact.bytes(),
            b"sing-box-v1",
            SingBoxReadiness::Listener {
                port: NonZeroU16::new(PORT).unwrap(),
            },
        );

        let binding = bind_engine_config_to_spec(artifact, &fixture.spec).unwrap();

        assert_eq!(
            binding.schema_version(),
            ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION
        );
        assert_eq!(binding.artifact().digest(), artifact_digest);
        assert_eq!(binding.binary_digest(), fixture.spec.binary_digest());
        assert_eq!(binding.config_digest(), fixture.spec.config_digest());
        assert_eq!(binding.launcher_digest(), None);
        assert_eq!(binding.digest().as_bytes().len(), 32);
        assert_eq!(
            binding.digest().to_string(),
            "fdacd3c8d087371e5c7f51c879298a3aa42e4369c559dde4fe9337ba97630f5f"
        );
    }

    #[test]
    fn rejects_config_content_or_listener_shape_drift() {
        let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
        let mismatched_config = EngineSpecFixture::new(
            b"{}\n",
            b"sing-box",
            SingBoxReadiness::Listener {
                port: NonZeroU16::new(PORT).unwrap(),
            },
        );
        let expected_artifact = *artifact.content_sha256();
        let expected_spec = mismatched_config.spec.config_digest();
        let error = bind_engine_config_to_spec(artifact, &mismatched_config.spec).unwrap_err();
        assert_eq!(
            error.kind(),
            EngineConfigBindingErrorKind::ConfigDigestMismatch {
                artifact: expected_artifact,
                engine_spec: expected_spec,
            }
        );

        let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
        let mismatched_port = EngineSpecFixture::new(
            artifact.bytes(),
            b"sing-box",
            SingBoxReadiness::Listener {
                port: NonZeroU16::new(PORT + 1).unwrap(),
            },
        );
        let error = bind_engine_config_to_spec(artifact, &mismatched_port.spec).unwrap_err();
        assert_eq!(
            error.kind(),
            EngineConfigBindingErrorKind::ListenerPortMismatch {
                artifact: NonZeroU16::new(PORT).unwrap(),
                engine_spec: NonZeroU16::new(PORT + 1).unwrap(),
            }
        );

        let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
        let tun = EngineSpecFixture::new(
            artifact.bytes(),
            b"sing-box",
            SingBoxReadiness::TunInterface {
                name: "tun0".to_owned(),
            },
        );
        let error = bind_engine_config_to_spec(artifact, &tun.spec).unwrap_err();
        assert_eq!(
            error.kind(),
            EngineConfigBindingErrorKind::TunReadinessUnsupported
        );
    }

    #[test]
    fn binding_identity_retains_binary_and_removed_template_provenance() {
        let empty = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
        let old_tun = compile(br#"{"inbounds":[{"type":"tun","tag":"old-tun"}]}"#, PORT).unwrap();
        assert_eq!(empty.bytes(), old_tun.bytes());

        let first_engine = EngineSpecFixture::new(
            empty.bytes(),
            b"sing-box-v1",
            SingBoxReadiness::Listener {
                port: NonZeroU16::new(PORT).unwrap(),
            },
        );
        let second_engine = EngineSpecFixture::new(
            empty.bytes(),
            b"sing-box-v2",
            SingBoxReadiness::Listener {
                port: NonZeroU16::new(PORT).unwrap(),
            },
        );
        let launcher_engine = EngineSpecFixture::new_with_busybox(
            empty.bytes(),
            b"sing-box-v1",
            b"busybox-v1",
            SingBoxReadiness::Listener {
                port: NonZeroU16::new(PORT).unwrap(),
            },
        );

        let first = bind_engine_config_to_spec(empty.clone(), &first_engine.spec).unwrap();
        let binary_drift = bind_engine_config_to_spec(empty.clone(), &second_engine.spec).unwrap();
        let launcher_drift = bind_engine_config_to_spec(empty, &launcher_engine.spec).unwrap();
        let source_drift = bind_engine_config_to_spec(old_tun, &first_engine.spec).unwrap();

        assert_ne!(first.digest(), binary_drift.digest());
        assert_ne!(first.digest(), launcher_drift.digest());
        assert_eq!(
            launcher_drift.launcher_digest(),
            launcher_engine.spec.launcher_digest()
        );
        assert_ne!(first.digest(), source_drift.digest());
    }

    #[test]
    fn collects_exact_binary_profile_and_pins_its_revision() {
        let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
        let fixture = EngineSpecFixture::new_executable(
            artifact.bytes(),
            PROFILE_SCRIPT,
            listener_readiness(),
        );
        let binding = bind_engine_config_to_spec(artifact, &fixture.spec).unwrap();

        let profile = collect_tproxy_engine_capability_profile(&binding, &fixture.spec)
            .expect("exact binary accepts its exact canonical config");

        assert_eq!(
            profile.schema_version(),
            ENGINE_CAPABILITY_PROFILE_SCHEMA_VERSION
        );
        assert_eq!(profile.artifacts(), binding.artifacts());
        assert_eq!(profile.validated_binding(), binding.digest());
        assert_eq!(profile.version().release(), "1.13.14-rc.1+flux.2");
        assert_eq!(profile.version().major(), 1);
        assert_eq!(profile.version().minor(), 13);
        assert_eq!(profile.version().patch(), 14);
        assert_eq!(
            profile.build().stdout(),
            "sing-box version 1.13.14-rc.1+flux.2\n\nEnvironment: go1.24.5 linux/amd64\n"
        );
        assert_eq!(profile.build().stderr(), "Tags: with_quic,with_wireguard\n");
        assert_eq!(
            profile.revision().to_string(),
            "d129642ba9e1ac385d42a36a7d125b240514d477268a63fdcda448b42edc02ec"
        );
        assert_eq!(profile.revision().as_bytes().len(), 32);
    }

    #[test]
    fn profile_collection_rejects_artifact_mismatch_before_execution() {
        let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
        let fixture = EngineSpecFixture::new_executable(
            artifact.bytes(),
            PROFILE_SCRIPT,
            listener_readiness(),
        );
        let binding = bind_engine_config_to_spec(artifact, &fixture.spec).unwrap();
        let marker_directory = tempfile::tempdir().expect("create probe marker directory");
        let marker = marker_directory.path().join("probe-invoked");
        let mismatched_script = format!(
            "#!/bin/sh\nprintf invoked > \"{}\"\n{}",
            marker.display(),
            std::str::from_utf8(PROFILE_SCRIPT)
                .unwrap()
                .trim_start_matches("#!/bin/sh\n")
        );
        let mismatched = EngineSpecFixture::new_executable(
            binding.artifact().bytes(),
            mismatched_script.as_bytes(),
            listener_readiness(),
        );

        let error = collect_tproxy_engine_capability_profile(&binding, &mismatched.spec)
            .expect_err("artifact-set mismatch must fail before probing");

        assert!(matches!(
            error.kind(),
            EngineCapabilityProfileErrorKind::ArtifactSetMismatch
        ));
        assert!(!marker.exists());
    }

    #[test]
    fn version_output_requires_one_valid_safe_header_across_both_streams() {
        let cases: &[(&[u8], &[u8], EngineVersionOutputErrorKind)] = &[
            (
                b"Environment: go1.24.5 linux/amd64\n",
                b"",
                EngineVersionOutputErrorKind::MissingVersionHeader,
            ),
            (
                b"sing-box version 1.13.14\n",
                b"sing-box version 1.13.14\n",
                EngineVersionOutputErrorKind::AmbiguousVersionHeader,
            ),
            (
                b"sing-box version 1.13\n",
                b"",
                EngineVersionOutputErrorKind::InvalidRelease,
            ),
            (
                b"sing-box version 01.13.14\n",
                b"",
                EngineVersionOutputErrorKind::InvalidRelease,
            ),
            (
                b"sing-box version 1.13.14-rc..1\n",
                b"",
                EngineVersionOutputErrorKind::InvalidRelease,
            ),
        ];

        for (stdout, stderr, expected) in cases {
            let error = parse_sing_box_version_output(stdout, stderr)
                .expect_err("invalid version output must fail closed");
            assert_eq!(
                error.kind(),
                EngineCapabilityProfileErrorKind::VersionOutput(*expected)
            );
        }

        let invalid_utf8 = parse_sing_box_version_output(b"sing-box version 1.13.14\n\xff", b"")
            .expect_err("version output must be exact UTF-8");
        assert_eq!(
            invalid_utf8.kind(),
            EngineCapabilityProfileErrorKind::VersionOutput(
                EngineVersionOutputErrorKind::InvalidUtf8 { stream: "stdout" }
            )
        );

        let unsafe_text = parse_sing_box_version_output(b"sing-box version 1.13.14\n\x1b[31m", b"")
            .expect_err("terminal control output must fail closed");
        assert_eq!(
            unsafe_text.kind(),
            EngineCapabilityProfileErrorKind::VersionOutput(
                EngineVersionOutputErrorKind::UnsafeText { stream: "stdout" }
            )
        );
    }

    #[test]
    fn profile_collection_propagates_exact_configuration_check_failure() {
        let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
        let fixture = EngineSpecFixture::new_executable(
            artifact.bytes(),
            PROFILE_CHECK_FAILURE_SCRIPT,
            listener_readiness(),
        );
        let binding = bind_engine_config_to_spec(artifact, &fixture.spec).unwrap();

        let error = collect_tproxy_engine_capability_profile(&binding, &fixture.spec)
            .expect_err("configuration rejection must fail profile collection");

        assert_eq!(
            error.kind(),
            EngineCapabilityProfileErrorKind::Probe(
                crate::engine_supervisor::EngineCapabilityProbeErrorKind::Process
            )
        );
        assert!(matches!(
            error.source.as_deref(),
            Some(EngineCapabilityProbeError::Process {
                source: SingBoxProcessError::CheckFailed { .. }
            })
        ));
    }

    #[test]
    fn compiles_the_same_non_authorizing_candidate_for_identical_inputs() {
        let (binding, profile, _fixture) = collected_profile();
        let mut tracker = NetworkInventoryTracker::new();
        let inventory = empty_inventory(&mut tracker);
        let device_profile = CapabilityProfileFixture::device_qualified();

        let first = compile_tproxy_generation_candidate(
            device_profile.clone(),
            inventory,
            profile.clone(),
            binding.clone(),
        )
        .expect("verified inputs compile");
        let second = compile_tproxy_generation_candidate(
            device_profile.clone(),
            inventory,
            profile,
            binding,
        )
        .expect("identical verified inputs compile");

        assert_eq!(first, second);
        assert_eq!(
            first.schema_version(),
            TPROXY_GENERATION_CANDIDATE_SCHEMA_VERSION
        );
        assert_eq!(first.device_profile(), &device_profile);
        assert_eq!(first.inventory_snapshot(), inventory.snapshot_id());
        assert_eq!(first.inventory_epoch(), inventory.epoch());
        assert_eq!(
            first.engine_profile().validated_binding(),
            first.engine_config().digest()
        );
    }

    #[test]
    fn candidate_rejects_mismatched_engine_binding_or_artifact_set() {
        let (binding, profile, fixture) = collected_profile();
        let mut tracker = NetworkInventoryTracker::new();
        let inventory = empty_inventory(&mut tracker);
        let device_profile = CapabilityProfileFixture::device_qualified();
        let source_drift =
            compile(br#"{"inbounds":[{"type":"tun","tag":"removed"}]}"#, PORT).unwrap();
        assert_eq!(source_drift.bytes(), binding.artifact().bytes());
        let different_binding = bind_engine_config_to_spec(source_drift, &fixture.spec).unwrap();

        let error = compile_tproxy_generation_candidate(
            device_profile.clone(),
            inventory,
            profile.clone(),
            different_binding,
        )
        .expect_err("profile must validate the exact binding");
        assert_eq!(
            error.kind(),
            TproxyGenerationCandidateErrorKind::EngineBindingMismatch
        );

        let other_fixture = EngineSpecFixture::new_executable(
            binding.artifact().bytes(),
            PROFILE_ALTERNATE_BINARY_SCRIPT,
            listener_readiness(),
        );
        let other_artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
        let other_binding =
            bind_engine_config_to_spec(other_artifact, &other_fixture.spec).unwrap();
        let error =
            compile_tproxy_generation_candidate(device_profile, inventory, profile, other_binding)
                .expect_err("profile and binding artifact sets must agree");
        assert_eq!(
            error.kind(),
            TproxyGenerationCandidateErrorKind::EngineArtifactSetMismatch
        );
    }

    #[test]
    fn candidate_requires_verified_device_identity_and_supported_kernel() {
        let (binding, profile, _fixture) = collected_profile();
        let mut tracker = NetworkInventoryTracker::new();
        let inventory = empty_inventory(&mut tracker);

        let error = compile_tproxy_generation_candidate(
            CapabilityProfileFixture::unverified_boot(),
            inventory,
            profile.clone(),
            binding.clone(),
        )
        .expect_err("boot identity must be verified");
        assert_eq!(
            error.kind(),
            TproxyGenerationCandidateErrorKind::BootIdentityNotVerified {
                observation: ObservationKind::Unavailable,
            }
        );

        let error = compile_tproxy_generation_candidate(
            CapabilityProfileFixture::supported(),
            inventory,
            profile.clone(),
            binding.clone(),
        )
        .expect_err("exact device identity must be verified");
        assert_eq!(
            error.kind(),
            TproxyGenerationCandidateErrorKind::DeviceIdentityNotVerified {
                observation: ObservationKind::Unavailable,
            }
        );

        let qualified = CapabilityProfileFixture::device_qualified();
        let unsupported = CapabilityProfileFixture::unsupported_kernel();
        let unsupported = CapabilityProfile::new(
            qualified.revision(),
            qualified.boot_identity().clone(),
            qualified.device_identity().clone(),
            unsupported.kernel().clone(),
            qualified.selinux().clone(),
            qualified.legacy_bridge().clone(),
        );
        let error = compile_tproxy_generation_candidate(unsupported, inventory, profile, binding)
            .expect_err("unsupported kernel must fail closed");
        assert!(matches!(
            error.kind(),
            TproxyGenerationCandidateErrorKind::KernelNotSupported {
                support: Some(KernelSupport::Unsupported { .. })
            }
        ));
    }

    #[test]
    fn rejects_duplicate_or_ambiguous_json_before_compilation() {
        for template in [
            br#"{"inbounds":[],"inbounds":[]}"#.as_slice(),
            br#"{"inbounds":[{"type":"tproxy","type":"tun"}]}"#.as_slice(),
            br#"{"inbounds":[]} trailing"#.as_slice(),
        ] {
            let error = compile(template, PORT).expect_err("ambiguous JSON must fail closed");
            assert_eq!(error.kind(), EngineConfigCompileErrorKind::InvalidJson);
            assert!(error.source.is_some());
        }
    }

    #[test]
    fn rejects_invalid_or_multiple_inbound_shapes() {
        let cases: &[(&[u8], EngineConfigCompileErrorKind)] = &[
            (b"[]", EngineConfigCompileErrorKind::RootNotObject),
            (
                br#"{"inbounds":{}}"#,
                EngineConfigCompileErrorKind::InboundsNotArray,
            ),
            (
                br#"{"inbounds":[false]}"#,
                EngineConfigCompileErrorKind::InboundNotObject { index: 0 },
            ),
            (
                br#"{"inbounds":[{}]}"#,
                EngineConfigCompileErrorKind::InboundTypeMissing { index: 0 },
            ),
            (
                br#"{"inbounds":[{"type":7}]}"#,
                EngineConfigCompileErrorKind::InboundTypeNotString { index: 0 },
            ),
            (
                br#"{"inbounds":[{"type":"tproxy"},{"type":"tproxy"}]}"#,
                EngineConfigCompileErrorKind::MultipleTproxyInbounds,
            ),
        ];

        for (template, expected) in cases {
            let error = compile(template, PORT).expect_err("invalid inbound shape must fail");
            assert_eq!(error.kind(), *expected);
        }
    }

    #[test]
    fn removed_template_input_remains_bound_to_the_artifact_identity() {
        let empty = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
        let old_tun = compile(br#"{"inbounds":[{"type":"tun","tag":"old-tun"}]}"#, PORT).unwrap();

        assert_eq!(empty.bytes(), old_tun.bytes());
        assert_eq!(empty.content_sha256(), old_tun.content_sha256());
        assert_ne!(empty.template_digest(), old_tun.template_digest());
        assert_ne!(empty.digest(), old_tun.digest());
    }

    #[test]
    fn enforces_document_and_inbound_resource_budgets() {
        let oversized = vec![b' '; usize::try_from(MAX_ENGINE_CONFIG_BYTES).unwrap() + 1];
        let error = compile(&oversized, PORT).expect_err("oversized template must fail early");
        assert_eq!(
            error.kind(),
            EngineConfigCompileErrorKind::TemplateTooLarge {
                actual: oversized.len(),
                maximum: MAX_ENGINE_CONFIG_BYTES,
            }
        );

        let inbounds = std::iter::repeat_n("{}", MAX_GENERATION_ENGINE_CONFIG_INBOUNDS + 1)
            .collect::<Vec<_>>()
            .join(",");
        let template = format!("{{\"inbounds\":[{inbounds}]}}");
        let error = compile(template.as_bytes(), PORT).expect_err("inbound count must be bounded");
        assert_eq!(
            error.kind(),
            EngineConfigCompileErrorKind::TooManyInbounds {
                actual: MAX_GENERATION_ENGINE_CONFIG_INBOUNDS + 1,
                maximum: MAX_GENERATION_ENGINE_CONFIG_INBOUNDS,
            }
        );
    }

    fn compile(
        template: &[u8],
        port: u16,
    ) -> Result<super::EngineConfigArtifact, super::EngineConfigCompileError> {
        compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
            template,
            NonZeroU16::new(port).unwrap(),
        ))
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn listener_readiness() -> SingBoxReadiness {
        SingBoxReadiness::Listener {
            port: NonZeroU16::new(PORT).unwrap(),
        }
    }

    fn collected_profile() -> (
        super::EngineConfigLaunchBinding,
        super::EngineCapabilityProfile,
        EngineSpecFixture,
    ) {
        let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
        let fixture = EngineSpecFixture::new_executable(
            artifact.bytes(),
            PROFILE_SCRIPT,
            listener_readiness(),
        );
        let binding = bind_engine_config_to_spec(artifact, &fixture.spec).unwrap();
        let profile = collect_tproxy_engine_capability_profile(&binding, &fixture.spec).unwrap();
        (binding, profile, fixture)
    }

    fn empty_inventory(tracker: &mut NetworkInventoryTracker) -> &flux_core::NetworkInventory {
        tracker
            .publish_complete(
                Vec::<InterfaceLinkRecord>::new(),
                Vec::<InterfaceAddressRecord>::new(),
            )
            .expect("publish complete empty inventory")
    }

    const PROFILE_SCRIPT: &[u8] = br#"#!/bin/sh
case "$1" in
    version)
        printf '%s\n\n%s\n' 'sing-box version 1.13.14-rc.1+flux.2' 'Environment: go1.24.5 linux/amd64'
        printf '%s\n' 'Tags: with_quic,with_wireguard' >&2
        ;;
    check)
        exit 0
        ;;
    *)
        exit 64
        ;;
esac
"#;

    const PROFILE_CHECK_FAILURE_SCRIPT: &[u8] = br#"#!/bin/sh
case "$1" in
    version)
        printf '%s\n' 'sing-box version 1.13.14'
        ;;
    check)
        printf '%s\n' 'configuration rejected' >&2
        exit 42
        ;;
    *)
        exit 64
        ;;
esac
"#;

    const PROFILE_ALTERNATE_BINARY_SCRIPT: &[u8] = br#"#!/bin/sh
case "$1" in
    version)
        printf '%s\n' 'sing-box version 1.13.15'
        ;;
    check)
        exit 0
        ;;
    *)
        exit 64
        ;;
esac
"#;

    struct EngineSpecFixture {
        spec: EngineSpec,
        _directory: tempfile::TempDir,
    }

    impl EngineSpecFixture {
        fn new(config: &[u8], binary: &[u8], readiness: SingBoxReadiness) -> Self {
            Self::build(config, binary, None, readiness)
        }

        fn new_with_busybox(
            config: &[u8],
            binary: &[u8],
            busybox: &[u8],
            readiness: SingBoxReadiness,
        ) -> Self {
            Self::build(config, binary, Some(busybox), readiness)
        }

        fn new_executable(config: &[u8], binary: &[u8], readiness: SingBoxReadiness) -> Self {
            let fixture = Self::new(config, binary, readiness);
            let path = &fixture.spec.process().binary;
            let mut permissions = fs::metadata(path).expect("read fixture mode").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).expect("make engine fixture executable");
            fixture
        }

        fn build(
            config: &[u8],
            binary: &[u8],
            busybox: Option<&[u8]>,
            readiness: SingBoxReadiness,
        ) -> Self {
            let directory = tempfile::tempdir().expect("create engine config binding fixture");
            let binary_path = directory.path().join("sing-box");
            let config_path = directory.path().join("config.json");
            fs::write(&binary_path, binary).expect("write engine binary fixture");
            fs::write(&config_path, config).expect("write engine config fixture");
            let launcher = match busybox {
                Some(bytes) => {
                    let path = directory.path().join("busybox");
                    fs::write(&path, bytes).expect("write engine launcher fixture");
                    SingBoxLauncher::BusyBoxSetuidgid {
                        busybox: path,
                        identity: "1000:1000".into(),
                    }
                }
                None => SingBoxLauncher::Direct,
            };
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
                    binary: binary_path,
                    config: config_path,
                    working_directory: directory.path().to_path_buf(),
                    log: directory.path().join("sing-box.log"),
                    launcher,
                    readiness,
                    startup_timeout: Duration::from_secs(1),
                    stop_timeout: Duration::from_secs(1),
                },
                restart,
            )
            .expect("inspect engine config binding fixture");
            Self {
                spec,
                _directory: directory,
            }
        }
    }
}
