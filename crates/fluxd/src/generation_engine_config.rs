use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::num::NonZeroU16;

use serde::Deserialize;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use flux_platform::SingBoxReadiness;

use crate::{EngineArtifactDigest, EngineSpec, MAX_ENGINE_CONFIG_BYTES};

pub(crate) const GENERATION_ENGINE_CONFIG_SCHEMA_VERSION: u16 = 1;
pub(crate) const ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION: u16 = 1;
pub(crate) const MAX_GENERATION_ENGINE_CONFIG_INBOUNDS: usize = 256;

const ENGINE_CONFIG_DIGEST_BYTES: usize = 32;
const TEMPLATE_DIGEST_DOMAIN: &[u8] =
    b"Flux Generation Sing-Box template\0semantic-json\0sha256-v1\0";
const ARTIFACT_DIGEST_DOMAIN: &[u8] =
    b"Flux Generation Sing-Box engine config artifact\0sha256-v1\0";
const LAUNCH_BINDING_DIGEST_DOMAIN: &[u8] =
    b"Flux Generation Sing-Box engine config launch binding\0sha256-v1\0";

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
    binary_digest: EngineArtifactDigest,
    config_digest: EngineArtifactDigest,
    launcher_digest: Option<EngineArtifactDigest>,
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
    pub(crate) const fn binary_digest(&self) -> EngineArtifactDigest {
        self.binary_digest
    }

    #[must_use]
    pub(crate) const fn config_digest(&self) -> EngineArtifactDigest {
        self.config_digest
    }

    #[must_use]
    pub(crate) const fn launcher_digest(&self) -> Option<EngineArtifactDigest> {
        self.launcher_digest
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

    let binary_digest = spec.binary_digest();
    let launcher_digest = spec.launcher_digest();
    let digest = EngineConfigLaunchBindingDigest(digest_engine_config_launch_binding(
        artifact.digest(),
        binary_digest,
        config_digest,
        launcher_digest,
    ));
    Ok(EngineConfigLaunchBinding {
        artifact,
        binary_digest,
        config_digest,
        launcher_digest,
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
    binary_digest: EngineArtifactDigest,
    config_digest: EngineArtifactDigest,
    launcher_digest: Option<EngineArtifactDigest>,
) -> [u8; ENGINE_CONFIG_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(LAUNCH_BINDING_DIGEST_DOMAIN);
    digest.update(ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION.to_be_bytes());
    digest.update(artifact_digest.as_bytes());
    digest.update(binary_digest.as_bytes());
    digest.update(config_digest.as_bytes());
    match launcher_digest {
        Some(launcher_digest) => {
            digest.update([1]);
            digest.update(launcher_digest.as_bytes());
        }
        None => digest.update([0]),
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
    use std::time::Duration;

    use flux_platform::{SingBoxLaunchSpec, SingBoxLauncher, SingBoxReadiness};

    use super::{
        ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION, EngineConfigBindingErrorKind,
        EngineConfigCompileErrorKind, GENERATION_ENGINE_CONFIG_SCHEMA_VERSION,
        MAX_GENERATION_ENGINE_CONFIG_INBOUNDS, TproxyEngineConfigRequest,
        bind_engine_config_to_spec, compile_tproxy_engine_config,
    };
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
