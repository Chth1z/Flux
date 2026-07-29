use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io;
use std::num::NonZeroU16;
use std::path::Path;

use serde::Deserialize;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use flux_platform::{SingBoxPrivilege, SingBoxReadiness};

use crate::intent_store::{IntentStoreError, record_io};
use crate::{EngineArtifactDigest, EngineArtifactSetIdentity, EngineSpec, MAX_ENGINE_CONFIG_BYTES};

pub(crate) const GENERATION_ENGINE_CONFIG_SCHEMA_VERSION: u16 = 1;
pub(crate) const ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION: u16 = 2;
pub(crate) const MAX_GENERATION_ENGINE_CONFIG_INBOUNDS: usize = 256;

pub(super) const ENGINE_CONFIG_DIGEST_BYTES: usize = 32;
const TEMPLATE_DIGEST_DOMAIN: &[u8] =
    b"Flux Generation Sing-Box template\0semantic-json\0sha256-v1\0";
const ARTIFACT_DIGEST_DOMAIN: &[u8] =
    b"Flux Generation Sing-Box engine config artifact\0sha256-v1\0";
const LAUNCH_BINDING_DIGEST_DOMAIN: &[u8] =
    b"Flux Generation Sing-Box engine config launch binding\0sha256-v2\0";

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
    MultipleTproxyInbounds,
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
            EngineConfigCompileErrorKind::MultipleTproxyInbounds => formatter.write_str(
                "Sing-Box template contains multiple TPROXY inbounds; one canonical listener is required",
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

/// Reconstruct an artifact only when the supplied bytes are already its exact canonical encoding.
pub(crate) fn reconstruct_canonical_tproxy_engine_config(
    bytes: &[u8],
    listener_port: NonZeroU16,
) -> Result<EngineConfigArtifact, EngineConfigCompileError> {
    let artifact =
        compile_tproxy_engine_config(TproxyEngineConfigRequest::new(bytes, listener_port))?;
    if artifact.bytes() != bytes {
        return Err(EngineConfigCompileError::without_source(
            EngineConfigCompileErrorKind::NonCanonical,
        ));
    }
    Ok(artifact)
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
