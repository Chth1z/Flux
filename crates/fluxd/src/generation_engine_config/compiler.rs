use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::path::Path;

use serde::Deserialize;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use flux_core::AddressHostFamilySelection;
use flux_platform::{SingBoxPrivilege, SingBoxReadiness};

use crate::intent_store::{IntentStoreError, record_io};
use crate::{EngineArtifactDigest, EngineArtifactSetIdentity, EngineSpec, MAX_ENGINE_CONFIG_BYTES};

pub(crate) const GENERATION_ENGINE_CONFIG_SCHEMA_VERSION: u16 = 2;
pub(crate) const ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION: u16 = 2;
pub(crate) const MAX_GENERATION_ENGINE_CONFIG_INBOUNDS: usize = 256;

pub(super) const ENGINE_CONFIG_DIGEST_BYTES: usize = 32;
const TEMPLATE_DIGEST_DOMAIN: &[u8] =
    b"Flux Generation Sing-Box template\0semantic-json\0sha256-v1\0";
const ARTIFACT_DIGEST_DOMAIN: &[u8] =
    b"Flux Generation Sing-Box engine config artifact\0sha256-v1\0";
const LAUNCH_BINDING_DIGEST_DOMAIN: &[u8] =
    b"Flux Generation Sing-Box engine config launch binding\0sha256-v2\0";
const TPROXY_CANARY_DIRECT_OUTBOUND_TAG: &str = "flux-canary-direct-v1";
const LEGACY_TPROXY_INBOUND_TAG: &str = "tproxy-in";
const TPROXY_IPV4_INBOUND_TAG: &str = "tproxy-in-ipv4";
const TPROXY_IPV6_INBOUND_TAG: &str = "tproxy-in-ipv6";

pub(crate) fn read_bounded_regular_file(path: &Path) -> io::Result<Vec<u8>> {
    let maximum = usize::try_from(MAX_ENGINE_CONFIG_BYTES).unwrap_or(usize::MAX);
    match record_io::read(path, maximum) {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("engine template {} is missing", path.display()),
        )),
        Err(source) => {
            let kind = match source {
                IntentStoreError::Symlink(_) | IntentStoreError::NotRegularFile(_) => {
                    io::ErrorKind::InvalidInput
                }
                IntentStoreError::RecordTooLarge { .. } => io::ErrorKind::InvalidData,
                _ => io::ErrorKind::Other,
            };
            Err(io::Error::new(kind, source))
        }
    }
}

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
    listener_families: AddressHostFamilySelection,
    canary_route: Option<TproxyCanaryEngineRoute>,
}

impl<'a> TproxyEngineConfigRequest<'a> {
    #[must_use]
    pub(crate) const fn new(
        template: &'a [u8],
        listener_port: NonZeroU16,
        listener_families: AddressHostFamilySelection,
    ) -> Self {
        Self {
            template,
            listener_port,
            listener_families,
            canary_route: None,
        }
    }

    #[allow(
        dead_code,
        reason = "the serialized native facility supplies this route in the next canary checkpoint"
    )]
    #[must_use]
    pub(crate) const fn with_canary_route(mut self, canary_route: TproxyCanaryEngineRoute) -> Self {
        self.canary_route = Some(canary_route);
        self
    }
}

/// Immutable, already-admitted peer endpoints for one Generation's private Sing-Box route.
///
/// Address selection and collision checks belong to the serialized native facility owner. This
/// value grants no facility creation, route mutation, or traffic authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct TproxyCanaryEngineRoute {
    ipv4_peer: Ipv4Addr,
    ipv6_peer: Option<Ipv6Addr>,
    tcp_echo_port: NonZeroU16,
    udp_echo_port: NonZeroU16,
    dns_port: NonZeroU16,
}

impl TproxyCanaryEngineRoute {
    #[allow(
        dead_code,
        reason = "the serialized native facility supplies admitted endpoints in the next canary checkpoint"
    )]
    #[must_use]
    pub(crate) const fn new(
        ipv4_peer: Ipv4Addr,
        ipv6_peer: Option<Ipv6Addr>,
        tcp_echo_port: NonZeroU16,
        udp_echo_port: NonZeroU16,
        dns_port: NonZeroU16,
    ) -> Self {
        Self {
            ipv4_peer,
            ipv6_peer,
            tcp_echo_port,
            udp_echo_port,
            dns_port,
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
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn input_bytes(self) -> usize {
        self.input_bytes
    }

    #[must_use]
    pub(crate) const fn output_bytes(self) -> usize {
        self.output_bytes
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn input_inbounds(self) -> usize {
        self.input_inbounds
    }

    #[cfg(test)]
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
    listener_families: AddressHostFamilySelection,
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
    pub(crate) const fn listener_families(&self) -> AddressHostFamilySelection {
        self.listener_families
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

/// Canonical configuration bound to one exact inspected launch request.
///
/// This is not an Engine Capability Profile, runtime readiness observation, process identity,
/// Generation, or activation token. It records immutable artifact identities, privilege policy,
/// and the pre-launch listener shape already declared by `EngineSpec`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EngineConfigLaunchBinding {
    artifact: EngineConfigArtifact,
    artifacts: EngineArtifactSetIdentity,
    privilege: SingBoxPrivilege,
    digest: EngineConfigLaunchBindingDigest,
}

impl EngineConfigLaunchBinding {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn schema_version(&self) -> u16 {
        ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn artifact(&self) -> &EngineConfigArtifact {
        &self.artifact
    }

    #[must_use]
    pub(crate) const fn artifacts(&self) -> EngineArtifactSetIdentity {
        self.artifacts
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn binary_digest(&self) -> EngineArtifactDigest {
        self.artifacts.binary()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn config_digest(&self) -> EngineArtifactDigest {
        self.artifacts.config()
    }

    #[must_use]
    pub(crate) const fn privilege(&self) -> SingBoxPrivilege {
        self.privilege
    }

    #[must_use]
    pub(crate) const fn digest(&self) -> EngineConfigLaunchBindingDigest {
        self.digest
    }
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
    #[cfg(test)]
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
    let privilege = spec.process().privilege;
    let digest = EngineConfigLaunchBindingDigest(digest_engine_config_launch_binding(
        artifact.digest(),
        artifacts,
        privilege,
    ));
    Ok(EngineConfigLaunchBinding {
        artifact,
        artifacts,
        privilege,
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
    InboundTagNotString { index: usize },
    CanonicalTproxyInboundTagCollision { index: usize },
    CanonicalTproxyInboundReferenceCollision,
    InheritedTproxyInboundTagCollision { index: usize },
    InvalidTproxyInboundReference,
    MultipleTproxyInbounds,
    OutboundsNotArray,
    OutboundNotObject { index: usize },
    OutboundTagNotString { index: usize },
    RouteNotObject,
    RouteRulesNotArray,
    RouteRuleNotObject { index: usize },
    RouteRuleOutboundNotString { index: usize },
    CanaryRouteReservedTagCollision,
    CanaryRouteListenerFamilyMismatch,
    OutputTooLarge { actual: usize, maximum: u64 },
    NonCanonical,
    ContentDigestMismatch,
    Encode,
}

#[derive(Debug)]
pub(crate) struct EngineConfigCompileError {
    kind: EngineConfigCompileErrorKind,
    source: Option<serde_json::Error>,
}

impl EngineConfigCompileError {
    #[cfg(test)]
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

    pub(crate) const fn content_digest_mismatch() -> Self {
        Self::without_source(EngineConfigCompileErrorKind::ContentDigestMismatch)
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
            EngineConfigCompileErrorKind::InboundTagNotString { index } => write!(
                formatter,
                "Sing-Box template TPROXY inbound {index} field 'tag' must be a string"
            ),
            EngineConfigCompileErrorKind::CanonicalTproxyInboundTagCollision { index } => write!(
                formatter,
                "Sing-Box template inbound {index} reuses a compiler-owned family-specific TPROXY tag"
            ),
            EngineConfigCompileErrorKind::CanonicalTproxyInboundReferenceCollision => formatter
                .write_str(
                    "Sing-Box template references a compiler-owned family-specific TPROXY tag without the exact canonical listener bundle",
                ),
            EngineConfigCompileErrorKind::InheritedTproxyInboundTagCollision { index } => write!(
                formatter,
                "Sing-Box template inbound {index} reuses the inherited TPROXY tag"
            ),
            EngineConfigCompileErrorKind::InvalidTproxyInboundReference => formatter.write_str(
                "Sing-Box route or DNS rule field 'inbound' must be a string or an array of strings",
            ),
            EngineConfigCompileErrorKind::MultipleTproxyInbounds => formatter.write_str(
                "Sing-Box template contains multiple inherited TPROXY inbounds; one canonical source inbound is required",
            ),
            EngineConfigCompileErrorKind::OutboundsNotArray => {
                formatter.write_str("Sing-Box template field 'outbounds' must be a JSON array")
            }
            EngineConfigCompileErrorKind::OutboundNotObject { index } => write!(
                formatter,
                "Sing-Box template outbound {index} must be a JSON object"
            ),
            EngineConfigCompileErrorKind::OutboundTagNotString { index } => write!(
                formatter,
                "Sing-Box template outbound {index} field 'tag' must be a string"
            ),
            EngineConfigCompileErrorKind::RouteNotObject => {
                formatter.write_str("Sing-Box template field 'route' must be a JSON object")
            }
            EngineConfigCompileErrorKind::RouteRulesNotArray => formatter
                .write_str("Sing-Box template field 'route.rules' must be a JSON array"),
            EngineConfigCompileErrorKind::RouteRuleNotObject { index } => write!(
                formatter,
                "Sing-Box template route rule {index} must be a JSON object"
            ),
            EngineConfigCompileErrorKind::RouteRuleOutboundNotString { index } => write!(
                formatter,
                "Sing-Box template route rule {index} field 'outbound' must be a string"
            ),
            EngineConfigCompileErrorKind::CanaryRouteReservedTagCollision => write!(
                formatter,
                "Sing-Box template substitutes or reuses reserved canary outbound tag '{TPROXY_CANARY_DIRECT_OUTBOUND_TAG}'"
            ),
            EngineConfigCompileErrorKind::CanaryRouteListenerFamilyMismatch => formatter
                .write_str(
                    "the admitted canary route families do not exactly match the canonical TPROXY listener families",
                ),
            EngineConfigCompileErrorKind::OutputTooLarge { actual, maximum } => write!(
                formatter,
                "compiled Sing-Box configuration is {actual} bytes, exceeding the {maximum}-byte Generation budget"
            ),
            EngineConfigCompileErrorKind::NonCanonical => formatter.write_str(
                "prepared Sing-Box configuration is not the exact canonical TPROXY artifact",
            ),
            EngineConfigCompileErrorKind::ContentDigestMismatch => formatter.write_str(
                "prepared Sing-Box configuration does not match its validated content digest",
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
    let canonical_listener_count = canonical_tproxy_listener_count(request.listener_families);
    let exact_canonical_listener_bundle = is_exact_canonical_tproxy_bundle(
        &inbounds,
        request.listener_port,
        request.listener_families,
    );
    let alternate_canonical_listener_bundle = [
        AddressHostFamilySelection::Ipv4,
        AddressHostFamilySelection::Ipv6,
        AddressHostFamilySelection::DualStack,
    ]
    .into_iter()
    .any(|families| {
        families != request.listener_families
            && is_exact_canonical_tproxy_bundle(&inbounds, request.listener_port, families)
    });
    if !exact_canonical_listener_bundle && alternate_canonical_listener_bundle {
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::NonCanonical,
        ));
    }
    let mut output_inbounds =
        Vec::with_capacity(input_inbounds.saturating_add(canonical_listener_count));
    let mut found_tproxy = false;
    let mut inherited_tproxy_tag = None;
    let mut non_tproxy_tags = Vec::new();
    for (index, inbound) in inbounds.into_iter().enumerate() {
        let Value::Object(inbound) = inbound else {
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
        if inbound_type != "tproxy"
            && let Some(Value::String(tag)) = inbound.get("tag")
        {
            if is_canonical_tproxy_inbound_tag(tag) {
                return Err(EngineConfigCompileError::without_source(
                    EngineConfigCompileErrorKind::CanonicalTproxyInboundTagCollision { index },
                ));
            }
            non_tproxy_tags.push((index, tag.clone()));
        }
        match inbound_type {
            "tun" => continue,
            "tproxy" => {
                if exact_canonical_listener_bundle {
                    found_tproxy = true;
                    output_inbounds.push(Value::Object(inbound));
                    continue;
                }
                if found_tproxy {
                    return Err(EngineConfigCompileError::without_source(
                        EngineConfigCompileErrorKind::MultipleTproxyInbounds,
                    ));
                }
                found_tproxy = true;
                inherited_tproxy_tag = match inbound.get("tag") {
                    Some(Value::String(tag)) if is_canonical_tproxy_inbound_tag(tag) => {
                        return Err(EngineConfigCompileError::without_source(
                            EngineConfigCompileErrorKind::CanonicalTproxyInboundTagCollision {
                                index,
                            },
                        ));
                    }
                    Some(Value::String(tag)) => Some(tag.clone()),
                    Some(_) => {
                        return Err(EngineConfigCompileError::without_source(
                            EngineConfigCompileErrorKind::InboundTagNotString { index },
                        ));
                    }
                    None => None,
                };
                output_inbounds.extend(canonical_tproxy_inbounds(
                    inbound,
                    request.listener_port,
                    request.listener_families,
                ));
            }
            _ => output_inbounds.push(Value::Object(inbound)),
        }
    }
    let inherited_reference_tag = if exact_canonical_listener_bundle {
        None
    } else if found_tproxy {
        inherited_tproxy_tag.as_deref()
    } else {
        Some(LEGACY_TPROXY_INBOUND_TAG)
    };
    if let Some(inherited_reference_tag) = inherited_reference_tag
        && let Some((index, _)) = non_tproxy_tags
            .iter()
            .find(|(_, tag)| tag == inherited_reference_tag)
    {
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::InheritedTproxyInboundTagCollision { index: *index },
        ));
    }
    if !found_tproxy {
        output_inbounds.extend(canonical_tproxy_inbounds(
            default_tproxy_inbound(),
            request.listener_port,
            request.listener_families,
        ));
    }
    let output_inbound_count = output_inbounds.len();
    document.insert("inbounds".to_owned(), Value::Array(output_inbounds));
    rewrite_inbound_tag_references(
        &mut document,
        inherited_reference_tag,
        request.listener_families,
        exact_canonical_listener_bundle,
    )?;
    if let Some(canary_route) = request.canary_route {
        if !canary_route_matches_listener_families(canary_route, request.listener_families) {
            return Err(EngineConfigCompileError::without_source(
                EngineConfigCompileErrorKind::CanaryRouteListenerFamilyMismatch,
            ));
        }
        install_tproxy_canary_route(&mut document, canary_route)?;
    }

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
        request.listener_families,
        template_digest,
        content_sha256,
        input_inbounds,
        output_inbound_count,
    ));
    Ok(EngineConfigArtifact {
        listener_port: request.listener_port,
        listener_families: request.listener_families,
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

/// Reconstruct an artifact only when the supplied bytes are already its exact canonical encoding.
pub(crate) fn reconstruct_canonical_tproxy_engine_config(
    bytes: &[u8],
    listener_port: NonZeroU16,
    listener_families: AddressHostFamilySelection,
) -> Result<EngineConfigArtifact, EngineConfigCompileError> {
    let artifact = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
        bytes,
        listener_port,
        listener_families,
    ))?;
    if artifact.bytes() != bytes {
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::NonCanonical,
        ));
    }
    Ok(artifact)
}

fn install_tproxy_canary_route(
    document: &mut Map<String, Value>,
    route_plan: TproxyCanaryEngineRoute,
) -> Result<(), EngineConfigCompileError> {
    validate_canary_route_containers(document)?;

    let direct_outbound = canary_direct_outbound();
    let tcp_rule = canary_route_rule(route_plan, "tcp", route_plan.tcp_echo_port);
    let udp_rule = canary_route_rule(route_plan, "udp", route_plan.udp_echo_port);
    let exact_bundle = document
        .get("outbounds")
        .and_then(Value::as_array)
        .and_then(|outbounds| outbounds.first())
        == Some(&direct_outbound)
        && document
            .get("route")
            .and_then(Value::as_object)
            .and_then(|route| route.get("rules"))
            .and_then(Value::as_array)
            .is_some_and(|rules| {
                rules.first() == Some(&tcp_rule) && rules.get(1) == Some(&udp_rule)
            });
    let reserved_tag_occurrences = document
        .values()
        .map(count_reserved_canary_tag)
        .sum::<usize>();
    if reserved_tag_occurrences != 0 {
        if exact_bundle && reserved_tag_occurrences == 3 {
            return Ok(());
        }
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::CanaryRouteReservedTagCollision,
        ));
    }

    let outbounds = document
        .entry("outbounds".to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(outbounds) = outbounds else {
        unreachable!("canary route containers were validated before mutation");
    };
    outbounds.insert(0, direct_outbound);

    let route = document
        .entry("route".to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(route) = route else {
        unreachable!("canary route containers were validated before mutation");
    };
    let rules = route
        .entry("rules".to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(rules) = rules else {
        unreachable!("canary route containers were validated before mutation");
    };
    rules.splice(0..0, [tcp_rule, udp_rule]);
    Ok(())
}

fn validate_canary_route_containers(
    document: &Map<String, Value>,
) -> Result<(), EngineConfigCompileError> {
    if let Some(outbounds) = document.get("outbounds") {
        let Value::Array(outbounds) = outbounds else {
            return Err(EngineConfigCompileError::without_source(
                EngineConfigCompileErrorKind::OutboundsNotArray,
            ));
        };
        for (index, outbound) in outbounds.iter().enumerate() {
            let Value::Object(outbound) = outbound else {
                return Err(EngineConfigCompileError::without_source(
                    EngineConfigCompileErrorKind::OutboundNotObject { index },
                ));
            };
            if outbound.get("tag").is_some_and(|tag| !tag.is_string()) {
                return Err(EngineConfigCompileError::without_source(
                    EngineConfigCompileErrorKind::OutboundTagNotString { index },
                ));
            }
        }
    }

    let Some(route) = document.get("route") else {
        return Ok(());
    };
    let Value::Object(route) = route else {
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::RouteNotObject,
        ));
    };
    let Some(rules) = route.get("rules") else {
        return Ok(());
    };
    let Value::Array(rules) = rules else {
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::RouteRulesNotArray,
        ));
    };
    for (index, rule) in rules.iter().enumerate() {
        let Value::Object(rule) = rule else {
            return Err(EngineConfigCompileError::without_source(
                EngineConfigCompileErrorKind::RouteRuleNotObject { index },
            ));
        };
        if rule
            .get("outbound")
            .is_some_and(|outbound| !outbound.is_string())
        {
            return Err(EngineConfigCompileError::without_source(
                EngineConfigCompileErrorKind::RouteRuleOutboundNotString { index },
            ));
        }
    }
    Ok(())
}

fn canary_direct_outbound() -> Value {
    let mut outbound = Map::new();
    outbound.insert("type".to_owned(), Value::String("direct".to_owned()));
    outbound.insert(
        "tag".to_owned(),
        Value::String(TPROXY_CANARY_DIRECT_OUTBOUND_TAG.to_owned()),
    );
    Value::Object(outbound)
}

fn canary_route_rule(
    route_plan: TproxyCanaryEngineRoute,
    network: &'static str,
    echo_port: NonZeroU16,
) -> Value {
    let mut cidrs = vec![Value::String(format!("{}/32", route_plan.ipv4_peer))];
    if let Some(ipv6_peer) = route_plan.ipv6_peer {
        cidrs.push(Value::String(format!("{ipv6_peer}/128")));
    }

    let mut rule = Map::new();
    rule.insert("action".to_owned(), Value::String("route".to_owned()));
    rule.insert("ip_cidr".to_owned(), Value::Array(cidrs));
    rule.insert("network".to_owned(), Value::String(network.to_owned()));
    rule.insert(
        "port".to_owned(),
        Value::Array(vec![
            Value::Number(Number::from(echo_port.get())),
            Value::Number(Number::from(route_plan.dns_port.get())),
        ]),
    );
    rule.insert(
        "outbound".to_owned(),
        Value::String(TPROXY_CANARY_DIRECT_OUTBOUND_TAG.to_owned()),
    );
    Value::Object(rule)
}

fn count_reserved_canary_tag(value: &Value) -> usize {
    match value {
        Value::String(value) => usize::from(value == TPROXY_CANARY_DIRECT_OUTBOUND_TAG),
        Value::Array(values) => values.iter().map(count_reserved_canary_tag).sum(),
        Value::Object(values) => values.values().map(count_reserved_canary_tag).sum(),
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
    }
}

fn normalize_tproxy_inbound(
    inbound: &mut Map<String, Value>,
    port: NonZeroU16,
    listen: &'static str,
    tag: &'static str,
) {
    inbound.insert("listen".to_owned(), Value::String(listen.to_owned()));
    inbound.insert(
        "listen_port".to_owned(),
        Value::Number(Number::from(port.get())),
    );
    inbound.insert("tag".to_owned(), Value::String(tag.to_owned()));
    // Absence is Sing-Box's exact TCP+UDP selection. A narrower inherited value must not silently
    // weaken the first canonical Capture Path.
    inbound.remove("network");
}

fn default_tproxy_inbound() -> Map<String, Value> {
    let mut inbound = Map::new();
    inbound.insert("type".to_owned(), Value::String("tproxy".to_owned()));
    inbound
}

fn canonical_tproxy_inbounds(
    inbound: Map<String, Value>,
    port: NonZeroU16,
    families: AddressHostFamilySelection,
) -> Vec<Value> {
    let mut canonical = Vec::with_capacity(canonical_tproxy_listener_count(families));
    if matches!(
        families,
        AddressHostFamilySelection::Ipv4 | AddressHostFamilySelection::DualStack
    ) {
        let mut ipv4 = inbound.clone();
        normalize_tproxy_inbound(&mut ipv4, port, "0.0.0.0", TPROXY_IPV4_INBOUND_TAG);
        canonical.push(Value::Object(ipv4));
    }
    if matches!(
        families,
        AddressHostFamilySelection::Ipv6 | AddressHostFamilySelection::DualStack
    ) {
        let mut ipv6 = inbound;
        normalize_tproxy_inbound(&mut ipv6, port, "::", TPROXY_IPV6_INBOUND_TAG);
        canonical.push(Value::Object(ipv6));
    }
    canonical
}

const fn canonical_tproxy_listener_count(families: AddressHostFamilySelection) -> usize {
    match families {
        AddressHostFamilySelection::Ipv4 | AddressHostFamilySelection::Ipv6 => 1,
        AddressHostFamilySelection::DualStack => 2,
    }
}

fn is_canonical_tproxy_inbound_tag(tag: &str) -> bool {
    matches!(tag, TPROXY_IPV4_INBOUND_TAG | TPROXY_IPV6_INBOUND_TAG)
}

fn is_exact_canonical_tproxy_bundle(
    inbounds: &[Value],
    port: NonZeroU16,
    families: AddressHostFamilySelection,
) -> bool {
    let expected_tags = canonical_tproxy_inbound_tags(families);
    let candidates = inbounds
        .iter()
        .enumerate()
        .filter_map(|(index, inbound)| {
            let inbound = inbound.as_object()?;
            (inbound.get("type").and_then(Value::as_str) == Some("tproxy"))
                .then_some((index, inbound))
        })
        .collect::<Vec<_>>();
    if candidates.len() != expected_tags.len()
        || candidates
            .windows(2)
            .any(|pair| pair[1].0 != pair[0].0.saturating_add(1))
    {
        return false;
    }

    let expected_listens = canonical_tproxy_listen_addresses(families);
    let mut shared_options = None;
    for (((_, inbound), tag), listen) in candidates.iter().zip(expected_tags).zip(expected_listens)
    {
        if inbound.get("tag").and_then(Value::as_str) != Some(tag)
            || inbound.get("listen").and_then(Value::as_str) != Some(listen)
            || inbound.get("listen_port").and_then(Value::as_u64) != Some(u64::from(port.get()))
            || inbound.contains_key("network")
        {
            return false;
        }
        let mut options = (*inbound).clone();
        options.remove("tag");
        options.remove("listen");
        options.remove("listen_port");
        if shared_options
            .as_ref()
            .is_some_and(|previous| previous != &options)
        {
            return false;
        }
        shared_options = Some(options);
    }
    true
}

fn canonical_tproxy_listen_addresses(families: AddressHostFamilySelection) -> Vec<&'static str> {
    match families {
        AddressHostFamilySelection::Ipv4 => vec!["0.0.0.0"],
        AddressHostFamilySelection::Ipv6 => vec!["::"],
        AddressHostFamilySelection::DualStack => vec!["0.0.0.0", "::"],
    }
}

fn rewrite_inbound_tag_references(
    document: &mut Map<String, Value>,
    inherited: Option<&str>,
    families: AddressHostFamilySelection,
    exact_canonical_bundle: bool,
) -> Result<(), EngineConfigCompileError> {
    for root in ["route", "dns"] {
        let Some(Value::Object(container)) = document.get_mut(root) else {
            continue;
        };
        let Some(Value::Array(rules)) = container.get_mut("rules") else {
            continue;
        };
        for rule in rules {
            rewrite_inbound_tag_references_in_rule(
                rule,
                inherited,
                families,
                exact_canonical_bundle,
            )?;
        }
    }
    Ok(())
}

fn rewrite_inbound_tag_references_in_rule(
    value: &mut Value,
    inherited: Option<&str>,
    families: AddressHostFamilySelection,
    exact_canonical_bundle: bool,
) -> Result<(), EngineConfigCompileError> {
    let Value::Object(rule) = value else {
        return Ok(());
    };
    if let Some(inbound) = rule.get_mut("inbound") {
        rewrite_inbound_tag_reference(inbound, inherited, families, exact_canonical_bundle)?;
    }
    if let Some(Value::Array(nested)) = rule.get_mut("rules") {
        for rule in nested {
            rewrite_inbound_tag_references_in_rule(
                rule,
                inherited,
                families,
                exact_canonical_bundle,
            )?;
        }
    }
    Ok(())
}

fn rewrite_inbound_tag_reference(
    value: &mut Value,
    inherited: Option<&str>,
    families: AddressHostFamilySelection,
    exact_canonical_bundle: bool,
) -> Result<(), EngineConfigCompileError> {
    let replacement = canonical_tproxy_inbound_tags(families);
    match value {
        Value::String(tag) => {
            validate_inbound_reference_tag(tag, inherited, &replacement, exact_canonical_bundle)?;
            if inherited == Some(tag.as_str()) {
                if replacement.len() == 1 {
                    *tag = replacement[0].to_owned();
                } else {
                    *value = Value::Array(
                        replacement
                            .into_iter()
                            .map(|tag| Value::String(tag.to_owned()))
                            .collect(),
                    );
                }
            }
        }
        Value::Array(tags) => {
            let mut rewritten = Vec::with_capacity(tags.len().saturating_add(1));
            for tag in tags.drain(..) {
                let Some(tag_text) = tag.as_str() else {
                    return Err(EngineConfigCompileError::without_source(
                        EngineConfigCompileErrorKind::InvalidTproxyInboundReference,
                    ));
                };
                validate_inbound_reference_tag(
                    tag_text,
                    inherited,
                    &replacement,
                    exact_canonical_bundle,
                )?;
                if inherited == Some(tag_text) {
                    for replacement in &replacement {
                        let replacement = Value::String((*replacement).to_owned());
                        if !rewritten.contains(&replacement) {
                            rewritten.push(replacement);
                        }
                    }
                } else {
                    let duplicates_replacement = tag.as_str().is_some_and(|candidate| {
                        replacement.contains(&candidate)
                            && rewritten
                                .iter()
                                .any(|existing| existing.as_str() == Some(candidate))
                    });
                    if !duplicates_replacement {
                        rewritten.push(tag);
                    }
                }
            }
            *tags = rewritten;
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => {
            return Err(EngineConfigCompileError::without_source(
                EngineConfigCompileErrorKind::InvalidTproxyInboundReference,
            ));
        }
    }
    Ok(())
}

fn validate_inbound_reference_tag(
    tag: &str,
    inherited: Option<&str>,
    requested_canonical_tags: &[&str],
    exact_canonical_bundle: bool,
) -> Result<(), EngineConfigCompileError> {
    let canonical_reference = is_canonical_tproxy_inbound_tag(tag);
    let requested_canonical_reference = requested_canonical_tags.contains(&tag);
    let legacy_reference = tag == LEGACY_TPROXY_INBOUND_TAG;
    let owned_reference = inherited == Some(tag);
    if (canonical_reference
        && (!exact_canonical_bundle || !requested_canonical_reference)
        && !owned_reference)
        || (legacy_reference && exact_canonical_bundle)
    {
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::CanonicalTproxyInboundReferenceCollision,
        ));
    }
    Ok(())
}

fn canonical_tproxy_inbound_tags(families: AddressHostFamilySelection) -> Vec<&'static str> {
    match families {
        AddressHostFamilySelection::Ipv4 => vec![TPROXY_IPV4_INBOUND_TAG],
        AddressHostFamilySelection::Ipv6 => vec![TPROXY_IPV6_INBOUND_TAG],
        AddressHostFamilySelection::DualStack => {
            vec![TPROXY_IPV4_INBOUND_TAG, TPROXY_IPV6_INBOUND_TAG]
        }
    }
}

fn canary_route_matches_listener_families(
    route: TproxyCanaryEngineRoute,
    families: AddressHostFamilySelection,
) -> bool {
    match families {
        AddressHostFamilySelection::Ipv4 => route.ipv6_peer.is_none(),
        AddressHostFamilySelection::Ipv6 => false,
        AddressHostFamilySelection::DualStack => route.ipv6_peer.is_some(),
    }
}

fn bytes_exceed_limit(actual: usize, maximum: u64) -> bool {
    u64::try_from(actual).map_or(true, |actual| actual > maximum)
}

fn digest_engine_config_artifact(
    listener_port: NonZeroU16,
    listener_families: AddressHostFamilySelection,
    template_digest: [u8; ENGINE_CONFIG_DIGEST_BYTES],
    content_sha256: [u8; ENGINE_CONFIG_DIGEST_BYTES],
    input_inbound_count: usize,
    output_inbound_count: usize,
) -> [u8; ENGINE_CONFIG_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(ARTIFACT_DIGEST_DOMAIN);
    digest.update(GENERATION_ENGINE_CONFIG_SCHEMA_VERSION.to_be_bytes());
    digest.update(listener_port.get().to_be_bytes());
    digest.update([listener_family_selection_tag(listener_families)]);
    digest.update(template_digest);
    digest.update(content_sha256);
    digest.update(length_bytes(input_inbound_count));
    digest.update(length_bytes(output_inbound_count));
    digest.finalize().into()
}

const fn listener_family_selection_tag(families: AddressHostFamilySelection) -> u8 {
    match families {
        AddressHostFamilySelection::Ipv4 => 4,
        AddressHostFamilySelection::Ipv6 => 6,
        AddressHostFamilySelection::DualStack => 10,
    }
}

fn digest_engine_config_launch_binding(
    artifact_digest: EngineConfigArtifactDigest,
    artifacts: EngineArtifactSetIdentity,
    privilege: SingBoxPrivilege,
) -> [u8; ENGINE_CONFIG_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(LAUNCH_BINDING_DIGEST_DOMAIN);
    digest.update(ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION.to_be_bytes());
    digest.update(artifact_digest.as_bytes());
    digest.update(artifacts.binary().as_bytes());
    digest.update(artifacts.config().as_bytes());
    match privilege {
        SingBoxPrivilege::Inherit => digest.update([0]),
        SingBoxPrivilege::TransparentProxy(credentials) => {
            digest.update([1]);
            digest.update(credentials.uid().get().to_be_bytes());
            digest.update(credentials.gid().get().to_be_bytes());
        }
    }
    digest.finalize().into()
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

pub(super) fn length_bytes(value: usize) -> [u8; 8] {
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
