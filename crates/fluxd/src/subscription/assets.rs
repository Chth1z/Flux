use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::num::NonZeroU16;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::MAX_ENGINE_CONFIG_BYTES;
use crate::generation_engine_config::{
    EngineConfigCompileError, TproxyEngineConfigRequest, compile_tproxy_engine_config,
};

use super::compiler::{
    CompiledSubscriptionTemplate, SubscriptionCompileError, SubscriptionCompileRequest,
    compile_subscription_template,
};
use super::fetch::{
    FetchAdapter, FetchError, FetchPurpose, FetchRequest, FetchedResource, validate_request,
};

const PREPARED_SUBSCRIPTION_DIGEST_DOMAIN: &[u8] =
    b"Flux prepared subscription snapshot\0sha256-v1\0";
const REDACTED_SOURCE_DIGEST_DOMAIN: &[u8] = b"Flux redacted subscription source\0sha256-v1\0";
pub(super) const MAX_REMOTE_RULE_SETS: usize = 64;
pub(super) const MAX_RULE_SET_TAG_BYTES: usize = 128;
const MAX_RULE_SET_UPDATE_INTERVAL_BYTES: usize = 128;
const MAX_ASSET_PATH_BYTES: usize = 4_096;

#[derive(Clone, Copy)]
pub(super) struct PrepareSubscriptionRequest<'a> {
    template: &'a [u8],
    subscription_url: &'a Url,
    asset_root: &'a Path,
    listener_port: NonZeroU16,
    limits: SubscriptionRefreshLimits,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SubscriptionRefreshLimits {
    timeout: Duration,
    maximum_download_bytes: u32,
    maximum_decoded_bytes: u32,
    maximum_nodes: u32,
}

impl SubscriptionRefreshLimits {
    pub(super) const fn new(
        timeout: Duration,
        maximum_download_bytes: u32,
        maximum_decoded_bytes: u32,
        maximum_nodes: u32,
    ) -> Self {
        Self {
            timeout,
            maximum_download_bytes,
            maximum_decoded_bytes,
            maximum_nodes,
        }
    }
}

impl fmt::Debug for PrepareSubscriptionRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrepareSubscriptionRequest")
            .field("template_bytes", &self.template.len())
            .field("subscription_url", &"<redacted>")
            .field("asset_root", &self.asset_root)
            .field("listener_port", &self.listener_port)
            .field("limits", &self.limits)
            .finish()
    }
}

impl<'a> PrepareSubscriptionRequest<'a> {
    pub(super) const fn new(
        template: &'a [u8],
        subscription_url: &'a Url,
        asset_root: &'a Path,
        listener_port: NonZeroU16,
        limits: SubscriptionRefreshLimits,
    ) -> Self {
        Self {
            template,
            subscription_url,
            asset_root,
            listener_port,
            limits,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct RedactedSourceId([u8; 32]);

impl RedactedSourceId {
    pub(super) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(super) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct PreparedRuleSetAsset {
    path: PathBuf,
    bytes: Box<[u8]>,
    content_sha256: [u8; 32],
}

impl fmt::Debug for PreparedRuleSetAsset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRuleSetAsset")
            .field("path", &self.path)
            .field("byte_len", &self.bytes.len())
            .field("content_sha256", &hex_digest(&self.content_sha256))
            .finish()
    }
}

impl PreparedRuleSetAsset {
    pub(super) fn restore(path: PathBuf, bytes: Vec<u8>, content_sha256: [u8; 32]) -> Option<Self> {
        let asset = Self {
            path,
            bytes: bytes.into_boxed_slice(),
            content_sha256,
        };
        asset.verify().then_some(asset)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) const fn content_sha256(&self) -> &[u8; 32] {
        &self.content_sha256
    }

    pub(super) fn verify(&self) -> bool {
        let expected_name = format!("{}.srs", hex_digest(&self.content_sha256));
        Sha256::digest(&self.bytes)[..] == self.content_sha256
            && self.path.file_name().and_then(|name| name.to_str()) == Some(&expected_name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PreparedRuleSetBinding {
    tag: Box<str>,
    source: RedactedSourceId,
    content_sha256: [u8; 32],
}

impl PreparedRuleSetBinding {
    pub(super) fn restore(
        tag: String,
        source: RedactedSourceId,
        content_sha256: [u8; 32],
    ) -> Option<Self> {
        if tag.is_empty() || tag.len() > MAX_RULE_SET_TAG_BYTES {
            return None;
        }
        Some(Self {
            tag: tag.into_boxed_str(),
            source,
            content_sha256,
        })
    }

    pub(super) fn tag(&self) -> &str {
        &self.tag
    }

    pub(super) const fn source(&self) -> RedactedSourceId {
        self.source
    }

    pub(super) const fn content_sha256(&self) -> &[u8; 32] {
        &self.content_sha256
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct PreparedSubscriptionRefresh {
    bytes: Box<[u8]>,
    content_sha256: [u8; 32],
    digest: [u8; 32],
    subscription_source: RedactedSourceId,
    subscription_content_sha256: [u8; 32],
    compiled_digest: [u8; 32],
    node_count: u32,
    assets: Box<[PreparedRuleSetAsset]>,
    bindings: Box<[PreparedRuleSetBinding]>,
}

impl fmt::Debug for PreparedSubscriptionRefresh {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSubscriptionRefresh")
            .field("byte_len", &self.bytes.len())
            .field("content_sha256", &hex_digest(&self.content_sha256))
            .field("digest", &hex_digest(&self.digest))
            .field("subscription_source", &self.subscription_source)
            .field(
                "subscription_content_sha256",
                &hex_digest(&self.subscription_content_sha256),
            )
            .field("compiled_digest", &hex_digest(&self.compiled_digest))
            .field("node_count", &self.node_count)
            .field("assets", &self.assets)
            .field("bindings", &self.bindings)
            .finish()
    }
}

impl PreparedSubscriptionRefresh {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn restore(
        bytes: Vec<u8>,
        content_sha256: [u8; 32],
        digest: [u8; 32],
        subscription_source: RedactedSourceId,
        subscription_content_sha256: [u8; 32],
        compiled_digest: [u8; 32],
        node_count: u32,
        assets: Vec<PreparedRuleSetAsset>,
        bindings: Vec<PreparedRuleSetBinding>,
    ) -> Option<Self> {
        let prepared = Self {
            bytes: bytes.into_boxed_slice(),
            content_sha256,
            digest,
            subscription_source,
            subscription_content_sha256,
            compiled_digest,
            node_count,
            assets: assets.into_boxed_slice(),
            bindings: bindings.into_boxed_slice(),
        };
        prepared.verify().then_some(prepared)
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) const fn content_sha256(&self) -> &[u8; 32] {
        &self.content_sha256
    }

    pub(super) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(super) const fn subscription_source(&self) -> RedactedSourceId {
        self.subscription_source
    }

    pub(super) const fn subscription_content_sha256(&self) -> &[u8; 32] {
        &self.subscription_content_sha256
    }

    pub(super) const fn compiled_digest(&self) -> &[u8; 32] {
        &self.compiled_digest
    }

    pub(super) const fn node_count(&self) -> u32 {
        self.node_count
    }

    pub(super) fn assets(&self) -> &[PreparedRuleSetAsset] {
        &self.assets
    }

    pub(super) fn bindings(&self) -> &[PreparedRuleSetBinding] {
        &self.bindings
    }

    pub(super) fn verify_assets(&self) -> bool {
        let mut asset_digests = BTreeSet::new();
        let mut asset_paths = BTreeSet::new();
        let mut binding_tags = BTreeSet::new();
        self.assets.iter().all(|asset| {
            asset.verify()
                && asset_digests.insert(asset.content_sha256)
                && asset_paths.insert(asset.path.as_path())
        }) && self.bindings.iter().all(|binding| {
            !binding.tag.is_empty()
                && binding.tag.len() <= MAX_RULE_SET_TAG_BYTES
                && binding_tags.insert(binding.tag.as_ref())
                && self
                    .assets
                    .iter()
                    .any(|asset| asset.content_sha256 == binding.content_sha256)
        }) && verify_local_rule_set_bindings(&self.bytes, &self.assets, &self.bindings)
    }

    pub(super) fn verify(&self) -> bool {
        self.node_count > 0
            && Sha256::digest(&self.bytes)[..] == self.content_sha256
            && self.verify_assets()
            && prepared_digest(
                self.content_sha256,
                self.subscription_source,
                self.subscription_content_sha256,
                self.compiled_digest,
                self.node_count,
                &self.assets,
                &self.bindings,
            ) == self.digest
    }
}

fn verify_local_rule_set_bindings(
    bytes: &[u8],
    assets: &[PreparedRuleSetAsset],
    bindings: &[PreparedRuleSetBinding],
) -> bool {
    let Ok(document) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    let Some(document) = document.as_object() else {
        return false;
    };
    let Some(route) = document.get("route") else {
        return bindings.is_empty();
    };
    let Some(route) = route.as_object() else {
        return false;
    };
    let Some(rule_sets) = route.get("rule_set") else {
        return bindings.is_empty();
    };
    let Some(rule_sets) = rule_sets.as_array() else {
        return false;
    };
    rule_sets.len() == bindings.len()
        && rule_sets.iter().zip(bindings).all(|(entry, binding)| {
            let Some(object) = entry.as_object() else {
                return false;
            };
            if object.len() != 4
                || object.get("type").and_then(Value::as_str) != Some("local")
                || object.get("tag").and_then(Value::as_str) != Some(binding.tag())
                || object.get("format").and_then(Value::as_str) != Some("binary")
            {
                return false;
            }
            let Some(path) = object.get("path").and_then(Value::as_str) else {
                return false;
            };
            assets.iter().any(|asset| {
                asset.content_sha256 == binding.content_sha256 && asset.path.to_str() == Some(path)
            })
        })
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrepareSubscriptionErrorKind {
    InvalidAssetRoot,
    InvalidTemplate,
    UnmanagedExternalDownload,
    TooManyRuleSets,
    InvalidRuleSet,
    DuplicateRuleSetTag,
    UnsupportedRuleSet,
    InvalidRuleSetUrl,
    SubscriptionFetch,
    SubscriptionCompile,
    CanonicalEngineConfig,
    RuleSetFetch,
    AssetBytesTooLarge,
    OutputTooLarge,
    Serialize,
}

#[derive(Debug)]
pub(super) enum PrepareSubscriptionError {
    InvalidAssetRoot(&'static str),
    InvalidTemplate(serde_json::Error),
    UnmanagedExternalDownload,
    TooManyRuleSets { actual: usize, maximum: usize },
    InvalidRuleSet { index: usize, detail: &'static str },
    DuplicateRuleSetTag { index: usize },
    UnsupportedRuleSet { index: usize },
    InvalidRuleSetUrl { index: usize },
    SubscriptionFetch(FetchError),
    SubscriptionCompile(SubscriptionCompileError),
    CanonicalEngineConfig(EngineConfigCompileError),
    RuleSetFetch { index: usize, source: FetchError },
    AssetBytesTooLarge { actual: usize, maximum: usize },
    OutputTooLarge { actual: usize, maximum: u64 },
    Serialize(serde_json::Error),
}

impl PrepareSubscriptionError {
    #[cfg(test)]
    pub(super) const fn kind(&self) -> PrepareSubscriptionErrorKind {
        match self {
            Self::InvalidAssetRoot(_) => PrepareSubscriptionErrorKind::InvalidAssetRoot,
            Self::InvalidTemplate(_) => PrepareSubscriptionErrorKind::InvalidTemplate,
            Self::UnmanagedExternalDownload => {
                PrepareSubscriptionErrorKind::UnmanagedExternalDownload
            }
            Self::TooManyRuleSets { .. } => PrepareSubscriptionErrorKind::TooManyRuleSets,
            Self::InvalidRuleSet { .. } => PrepareSubscriptionErrorKind::InvalidRuleSet,
            Self::DuplicateRuleSetTag { .. } => PrepareSubscriptionErrorKind::DuplicateRuleSetTag,
            Self::UnsupportedRuleSet { .. } => PrepareSubscriptionErrorKind::UnsupportedRuleSet,
            Self::InvalidRuleSetUrl { .. } => PrepareSubscriptionErrorKind::InvalidRuleSetUrl,
            Self::SubscriptionFetch(_) => PrepareSubscriptionErrorKind::SubscriptionFetch,
            Self::SubscriptionCompile(_) => PrepareSubscriptionErrorKind::SubscriptionCompile,
            Self::CanonicalEngineConfig(_) => PrepareSubscriptionErrorKind::CanonicalEngineConfig,
            Self::RuleSetFetch { .. } => PrepareSubscriptionErrorKind::RuleSetFetch,
            Self::AssetBytesTooLarge { .. } => PrepareSubscriptionErrorKind::AssetBytesTooLarge,
            Self::OutputTooLarge { .. } => PrepareSubscriptionErrorKind::OutputTooLarge,
            Self::Serialize(_) => PrepareSubscriptionErrorKind::Serialize,
        }
    }
}

impl fmt::Display for PrepareSubscriptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAssetRoot(detail) => write!(formatter, "invalid asset root: {detail}"),
            Self::InvalidTemplate(source) => {
                write!(formatter, "invalid subscription template: {source}")
            }
            Self::UnmanagedExternalDownload => formatter
                .write_str("subscription template contains an unmanaged external-UI download"),
            Self::TooManyRuleSets { actual, maximum } => write!(
                formatter,
                "template contains {actual} rule sets, exceeding the limit of {maximum}"
            ),
            Self::InvalidRuleSet { index, detail } => {
                write!(formatter, "invalid rule set {index}: {detail}")
            }
            Self::DuplicateRuleSetTag { index } => {
                write!(formatter, "rule set {index} has a duplicate tag")
            }
            Self::UnsupportedRuleSet { index } => write!(
                formatter,
                "rule set {index} is not a remote binary rule set owned by Flux"
            ),
            Self::InvalidRuleSetUrl { index } => {
                write!(formatter, "rule set {index} has an invalid URL")
            }
            Self::SubscriptionFetch(source) => {
                write!(formatter, "cannot fetch subscription: {source}")
            }
            Self::SubscriptionCompile(source) => {
                write!(formatter, "cannot compile subscription: {source}")
            }
            Self::CanonicalEngineConfig(source) => {
                write!(
                    formatter,
                    "cannot canonicalize subscription engine config: {source}"
                )
            }
            Self::RuleSetFetch { index, source } => {
                write!(formatter, "cannot fetch rule set {index}: {source}")
            }
            Self::AssetBytesTooLarge { actual, maximum } => write!(
                formatter,
                "rule-set assets use {actual} bytes, exceeding the aggregate limit of {maximum}"
            ),
            Self::OutputTooLarge { actual, maximum } => write!(
                formatter,
                "asset-rewritten configuration uses {actual} bytes, exceeding the limit of {maximum}"
            ),
            Self::Serialize(source) => {
                write!(
                    formatter,
                    "cannot serialize asset-rewritten template: {source}"
                )
            }
        }
    }
}

impl Error for PrepareSubscriptionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidTemplate(source) | Self::Serialize(source) => Some(source),
            Self::SubscriptionFetch(source) => Some(source),
            Self::SubscriptionCompile(source) => Some(source),
            Self::CanonicalEngineConfig(source) => Some(source),
            Self::RuleSetFetch { source, .. } => Some(source),
            Self::InvalidAssetRoot(_)
            | Self::UnmanagedExternalDownload
            | Self::TooManyRuleSets { .. }
            | Self::InvalidRuleSet { .. }
            | Self::DuplicateRuleSetTag { .. }
            | Self::UnsupportedRuleSet { .. }
            | Self::InvalidRuleSetUrl { .. }
            | Self::AssetBytesTooLarge { .. }
            | Self::OutputTooLarge { .. } => None,
        }
    }
}

pub(super) fn prepare_subscription_refresh<A: FetchAdapter>(
    adapter: &A,
    request: PrepareSubscriptionRequest<'_>,
) -> Result<PreparedSubscriptionRefresh, PrepareSubscriptionError> {
    validate_asset_root(request.asset_root)?;
    preflight_template(request)?;

    let fetch_request = FetchRequest::new(
        request.subscription_url,
        request.limits.timeout,
        u64::from(request.limits.maximum_download_bytes),
        u64::from(request.limits.maximum_decoded_bytes),
        FetchPurpose::Subscription,
    );
    validate_request(fetch_request).map_err(PrepareSubscriptionError::SubscriptionFetch)?;
    let subscription = adapter
        .fetch(fetch_request)
        .map_err(PrepareSubscriptionError::SubscriptionFetch)?;
    validate_adapter_resource(&subscription, request.limits.maximum_decoded_bytes)
        .map_err(PrepareSubscriptionError::SubscriptionFetch)?;
    let compiled = compile_subscription_template(SubscriptionCompileRequest::new(
        request.template,
        subscription.bytes(),
        request.limits.maximum_nodes,
        request.limits.maximum_decoded_bytes,
    ))
    .map_err(PrepareSubscriptionError::SubscriptionCompile)?;

    materialize_rule_sets(adapter, request, subscription, compiled)
}

fn materialize_rule_sets<A: FetchAdapter>(
    adapter: &A,
    request: PrepareSubscriptionRequest<'_>,
    subscription: FetchedResource,
    compiled: CompiledSubscriptionTemplate,
) -> Result<PreparedSubscriptionRefresh, PrepareSubscriptionError> {
    let mut document = serde_json::from_slice::<Value>(compiled.bytes())
        .map_err(PrepareSubscriptionError::InvalidTemplate)?;
    reject_unmanaged_external_download(&document)?;
    let mut empty_rule_sets = Vec::new();
    let rule_sets = mutable_rule_sets(&mut document)?.unwrap_or(&mut empty_rule_sets);

    let mut tags = BTreeSet::new();
    let mut unique_assets = BTreeMap::<[u8; 32], usize>::new();
    let mut assets = Vec::<PreparedRuleSetAsset>::new();
    let mut bindings = Vec::<PreparedRuleSetBinding>::with_capacity(rule_sets.len());
    let mut total_asset_bytes = 0usize;
    let aggregate_limit = usize::try_from(request.limits.maximum_decoded_bytes).map_err(|_| {
        PrepareSubscriptionError::InvalidAssetRoot("decoded byte limit does not fit this target")
    })?;

    for (index, entry) in rule_sets.iter_mut().enumerate() {
        let (tag, url) = remote_rule_set_fields(entry, index)?;
        if !tags.insert(tag.clone()) {
            return Err(PrepareSubscriptionError::DuplicateRuleSetTag { index });
        }
        let url =
            Url::parse(&url).map_err(|_| PrepareSubscriptionError::InvalidRuleSetUrl { index })?;
        let fetch_request = FetchRequest::new(
            &url,
            request.limits.timeout,
            u64::from(request.limits.maximum_download_bytes),
            u64::from(request.limits.maximum_decoded_bytes),
            FetchPurpose::BinaryRuleSet,
        );
        validate_request(fetch_request)
            .map_err(|source| PrepareSubscriptionError::RuleSetFetch { index, source })?;
        let fetched = adapter
            .fetch(fetch_request)
            .map_err(|source| PrepareSubscriptionError::RuleSetFetch { index, source })?;
        validate_adapter_resource(&fetched, request.limits.maximum_decoded_bytes)
            .map_err(|source| PrepareSubscriptionError::RuleSetFetch { index, source })?;
        total_asset_bytes = total_asset_bytes.checked_add(fetched.bytes().len()).ok_or(
            PrepareSubscriptionError::AssetBytesTooLarge {
                actual: usize::MAX,
                maximum: aggregate_limit,
            },
        )?;
        if total_asset_bytes > aggregate_limit {
            return Err(PrepareSubscriptionError::AssetBytesTooLarge {
                actual: total_asset_bytes,
                maximum: aggregate_limit,
            });
        }

        let content_sha256 = *fetched.content_sha256();
        let path = content_addressed_path(request.asset_root, content_sha256)?;
        if let Some(existing) = unique_assets.get(&content_sha256).copied() {
            if assets[existing].bytes() != fetched.bytes() {
                return Err(PrepareSubscriptionError::InvalidRuleSet {
                    index,
                    detail: "content digest collision",
                });
            }
        } else {
            unique_assets.insert(content_sha256, assets.len());
            assets.push(PreparedRuleSetAsset {
                path: path.clone(),
                bytes: fetched.bytes().to_vec().into_boxed_slice(),
                content_sha256,
            });
        }

        bindings.push(PreparedRuleSetBinding {
            tag: tag.clone().into_boxed_str(),
            source: redacted_source_id(&url),
            content_sha256,
        });
        *entry = local_rule_set(tag, &path, index)?;
    }

    let merged = serde_json::to_vec(&document).map_err(PrepareSubscriptionError::Serialize)?;
    if u64::try_from(merged.len()).map_or(true, |actual| actual > MAX_ENGINE_CONFIG_BYTES) {
        return Err(PrepareSubscriptionError::OutputTooLarge {
            actual: merged.len(),
            maximum: MAX_ENGINE_CONFIG_BYTES,
        });
    }
    let engine_config = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
        &merged,
        request.listener_port,
    ))
    .map_err(PrepareSubscriptionError::CanonicalEngineConfig)?;
    let bytes = engine_config.bytes().to_vec();
    let content_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    let subscription_source = redacted_source_id(request.subscription_url);
    let digest = prepared_digest(
        content_sha256,
        subscription_source,
        *subscription.content_sha256(),
        *compiled.digest(),
        compiled.node_count(),
        &assets,
        &bindings,
    );
    Ok(PreparedSubscriptionRefresh {
        bytes: bytes.into_boxed_slice(),
        content_sha256,
        digest,
        subscription_source,
        subscription_content_sha256: *subscription.content_sha256(),
        compiled_digest: *compiled.digest(),
        node_count: compiled.node_count(),
        assets: assets.into_boxed_slice(),
        bindings: bindings.into_boxed_slice(),
    })
}

fn preflight_template(
    request: PrepareSubscriptionRequest<'_>,
) -> Result<(), PrepareSubscriptionError> {
    if u64::try_from(request.template.len()).map_or(true, |actual| actual > MAX_ENGINE_CONFIG_BYTES)
    {
        return Err(PrepareSubscriptionError::OutputTooLarge {
            actual: request.template.len(),
            maximum: MAX_ENGINE_CONFIG_BYTES,
        });
    }
    let document = serde_json::from_slice::<Value>(request.template)
        .map_err(PrepareSubscriptionError::InvalidTemplate)?;
    if !document.is_object() {
        return Err(PrepareSubscriptionError::InvalidRuleSet {
            index: 0,
            detail: "template root must be an object",
        });
    }
    reject_unmanaged_external_download(&document)?;
    let Some(rule_sets) = immutable_rule_sets(&document)? else {
        return Ok(());
    };
    let mut tags = BTreeSet::new();
    for (index, entry) in rule_sets.iter().enumerate() {
        let (tag, url) = remote_rule_set_fields(entry, index)?;
        if !tags.insert(tag) {
            return Err(PrepareSubscriptionError::DuplicateRuleSetTag { index });
        }
        let url =
            Url::parse(&url).map_err(|_| PrepareSubscriptionError::InvalidRuleSetUrl { index })?;
        validate_request(FetchRequest::new(
            &url,
            request.limits.timeout,
            u64::from(request.limits.maximum_download_bytes),
            u64::from(request.limits.maximum_decoded_bytes),
            FetchPurpose::BinaryRuleSet,
        ))
        .map_err(|source| PrepareSubscriptionError::RuleSetFetch { index, source })?;
    }
    Ok(())
}

fn immutable_rule_sets(document: &Value) -> Result<Option<&[Value]>, PrepareSubscriptionError> {
    let Some(route) = document.get("route") else {
        return Ok(None);
    };
    let route = route
        .as_object()
        .ok_or(PrepareSubscriptionError::InvalidRuleSet {
            index: 0,
            detail: "route must be an object",
        })?;
    let Some(rule_sets) = route.get("rule_set") else {
        return Ok(None);
    };
    let rule_sets = rule_sets
        .as_array()
        .ok_or(PrepareSubscriptionError::InvalidRuleSet {
            index: 0,
            detail: "route.rule_set must be an array",
        })?;
    enforce_rule_set_count(rule_sets.len())?;
    Ok(Some(rule_sets))
}

fn mutable_rule_sets(
    document: &mut Value,
) -> Result<Option<&mut Vec<Value>>, PrepareSubscriptionError> {
    let Some(route) = document.get_mut("route") else {
        return Ok(None);
    };
    let route = route
        .as_object_mut()
        .ok_or(PrepareSubscriptionError::InvalidRuleSet {
            index: 0,
            detail: "route must be an object",
        })?;
    let Some(rule_sets) = route.get_mut("rule_set") else {
        return Ok(None);
    };
    let rule_sets = rule_sets
        .as_array_mut()
        .ok_or(PrepareSubscriptionError::InvalidRuleSet {
            index: 0,
            detail: "route.rule_set must be an array",
        })?;
    enforce_rule_set_count(rule_sets.len())?;
    Ok(Some(rule_sets))
}

fn enforce_rule_set_count(actual: usize) -> Result<(), PrepareSubscriptionError> {
    if actual > MAX_REMOTE_RULE_SETS {
        Err(PrepareSubscriptionError::TooManyRuleSets {
            actual,
            maximum: MAX_REMOTE_RULE_SETS,
        })
    } else {
        Ok(())
    }
}

fn remote_rule_set_fields(
    entry: &Value,
    index: usize,
) -> Result<(String, String), PrepareSubscriptionError> {
    let object = entry
        .as_object()
        .ok_or(PrepareSubscriptionError::InvalidRuleSet {
            index,
            detail: "entry must be an object",
        })?;
    if object.get("type").and_then(Value::as_str) != Some("remote")
        || object.get("format").and_then(Value::as_str) != Some("binary")
    {
        return Err(PrepareSubscriptionError::UnsupportedRuleSet { index });
    }
    if object.keys().any(|field| {
        !matches!(
            field.as_str(),
            "type" | "tag" | "format" | "url" | "update_interval"
        )
    }) {
        return Err(PrepareSubscriptionError::InvalidRuleSet {
            index,
            detail: "entry contains an unsupported field",
        });
    }
    let tag = required_text(object, "tag", index)?;
    if tag.len() > MAX_RULE_SET_TAG_BYTES {
        return Err(PrepareSubscriptionError::InvalidRuleSet {
            index,
            detail: "tag is too long",
        });
    }
    let url = required_text(object, "url", index)?;
    if let Some(update_interval) = object.get("update_interval") {
        let valid = update_interval.as_str().is_some_and(|value| {
            !value.is_empty() && value.len() <= MAX_RULE_SET_UPDATE_INTERVAL_BYTES
        });
        if !valid {
            return Err(PrepareSubscriptionError::InvalidRuleSet {
                index,
                detail: "update_interval must be bounded nonempty text",
            });
        }
    }
    Ok((tag.to_owned(), url.to_owned()))
}

fn required_text<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<&'a str, PrepareSubscriptionError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(PrepareSubscriptionError::InvalidRuleSet {
            index,
            detail: "required text field is missing",
        })
}

fn local_rule_set(
    tag: String,
    path: &Path,
    index: usize,
) -> Result<Value, PrepareSubscriptionError> {
    let path = path
        .to_str()
        .ok_or(PrepareSubscriptionError::InvalidRuleSet {
            index,
            detail: "asset path is not UTF-8",
        })?;
    Ok(serde_json::json!({
        "type": "local",
        "tag": tag,
        "format": "binary",
        "path": path,
    }))
}

fn reject_unmanaged_external_download(document: &Value) -> Result<(), PrepareSubscriptionError> {
    let Some(clash_api) = document
        .get("experimental")
        .and_then(|value| value.get("clash_api"))
        .and_then(Value::as_object)
    else {
        return Ok(());
    };
    if clash_api.contains_key("external_ui_download_url")
        || clash_api.contains_key("external_ui_download_detour")
    {
        Err(PrepareSubscriptionError::UnmanagedExternalDownload)
    } else {
        Ok(())
    }
}

fn validate_asset_root(root: &Path) -> Result<(), PrepareSubscriptionError> {
    if !root.is_absolute() {
        return Err(PrepareSubscriptionError::InvalidAssetRoot(
            "path must be absolute",
        ));
    }
    if root
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(PrepareSubscriptionError::InvalidAssetRoot(
            "path must be lexically normalized",
        ));
    }
    let path = root
        .to_str()
        .ok_or(PrepareSubscriptionError::InvalidAssetRoot(
            "path must be UTF-8",
        ))?;
    if path.len() > MAX_ASSET_PATH_BYTES.saturating_sub(69) {
        return Err(PrepareSubscriptionError::InvalidAssetRoot(
            "path is too long",
        ));
    }
    Ok(())
}

fn content_addressed_path(
    root: &Path,
    content_sha256: [u8; 32],
) -> Result<PathBuf, PrepareSubscriptionError> {
    let path = root.join(format!("{}.srs", hex_digest(&content_sha256)));
    if path.as_os_str().len() > MAX_ASSET_PATH_BYTES {
        return Err(PrepareSubscriptionError::InvalidAssetRoot(
            "content-addressed path is too long",
        ));
    }
    Ok(path)
}

fn validate_adapter_resource(resource: &FetchedResource, maximum: u32) -> Result<(), FetchError> {
    if resource.bytes().is_empty() {
        return Err(FetchError::EmptyBody);
    }
    let maximum_u64 = u64::from(maximum);
    let maximum = usize::try_from(maximum)
        .map_err(|_| FetchError::InvalidPolicy("decoded limit does not fit this target"))?;
    if resource.bytes().len() > maximum {
        Err(FetchError::DecodedBodyTooLarge {
            maximum: maximum_u64,
        })
    } else {
        Ok(())
    }
}

fn redacted_source_id(url: &Url) -> RedactedSourceId {
    let mut digest = Sha256::new();
    digest.update(REDACTED_SOURCE_DIGEST_DOMAIN);
    digest.update(url.as_str().as_bytes());
    RedactedSourceId(digest.finalize().into())
}

fn prepared_digest(
    content_sha256: [u8; 32],
    subscription_source: RedactedSourceId,
    subscription_content_sha256: [u8; 32],
    compiled_digest: [u8; 32],
    node_count: u32,
    assets: &[PreparedRuleSetAsset],
    bindings: &[PreparedRuleSetBinding],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(PREPARED_SUBSCRIPTION_DIGEST_DOMAIN);
    digest.update(content_sha256);
    digest.update(subscription_source.as_bytes());
    digest.update(subscription_content_sha256);
    digest.update(compiled_digest);
    digest.update(node_count.to_be_bytes());
    digest.update(assets.len().to_be_bytes());
    for asset in assets {
        digest.update(asset.content_sha256);
        update_field(&mut digest, asset.path.as_os_str().as_encoded_bytes());
        update_field(&mut digest, &asset.bytes);
    }
    digest.update(bindings.len().to_be_bytes());
    for binding in bindings {
        update_field(&mut digest, binding.tag.as_bytes());
        digest.update(binding.source.as_bytes());
        digest.update(binding.content_sha256);
    }
    digest.finalize().into()
}

fn update_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(bytes.len().to_be_bytes());
    digest.update(bytes);
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut value = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;
    use crate::subscription::fetch::FetchErrorKind;

    const ASSET_ROOT: &str = "/data/adb/flux/state/subscriptions/assets";
    const SUBSCRIPTION_URL: &str = "https://provider.example/sub?token=secret";
    const RULE_ONE_URL: &str = "https://assets.example/one.srs";
    const RULE_TWO_URL: &str = "https://assets.example/two.srs";
    const MAX_BYTES: u32 = 4_096;
    const LISTENER_PORT: NonZeroU16 = NonZeroU16::new(1_536).unwrap();
    const PACKAGED_TEMPLATE: &[u8] = include_bytes!("../../../../conf/template.json");
    const TEMPLATE: &[u8] = br#"{
        "outbounds":[
            {"type":"direct","tag":"DIRECT"},
            {"type":"selector","tag":"PROXY","outbounds":[]}
        ],
        "route":{"rule_set":[
            {"type":"remote","tag":"one","format":"binary","url":"https://assets.example/one.srs","update_interval":"1d"},
            {"type":"remote","tag":"two","format":"binary","url":"https://assets.example/two.srs","update_interval":"1d"}
        ]},
        "experimental":{"clash_api":{"external_ui":"./zashboard"}}
    }"#;
    const SUBSCRIPTION: &[u8] =
        br#"[{"type":"vless","tag":"Node","server":"node.example","server_port":443,"uuid":"id"}]"#;

    struct ExpectedFetch {
        url: &'static str,
        purpose: FetchPurpose,
        result: Result<Vec<u8>, FetchError>,
    }

    struct DeterministicAdapter {
        expected: RefCell<VecDeque<ExpectedFetch>>,
    }

    impl DeterministicAdapter {
        fn new(expected: impl IntoIterator<Item = ExpectedFetch>) -> Self {
            Self {
                expected: RefCell::new(expected.into_iter().collect()),
            }
        }

        fn assert_exhausted(&self) {
            assert!(self.expected.borrow().is_empty());
        }
    }

    impl FetchAdapter for DeterministicAdapter {
        fn fetch(&self, request: FetchRequest<'_>) -> Result<FetchedResource, FetchError> {
            let expected = self
                .expected
                .borrow_mut()
                .pop_front()
                .expect("unexpected fetch");
            assert_eq!(request.url().as_str(), expected.url);
            assert_eq!(request.purpose(), expected.purpose);
            assert_eq!(request.maximum_encoded_bytes(), u64::from(MAX_BYTES));
            assert_eq!(request.maximum_decoded_bytes(), u64::from(MAX_BYTES));
            expected.result.map(FetchedResource::from_bytes)
        }
    }

    fn expected_successes(asset: &[u8]) -> [ExpectedFetch; 3] {
        [
            ExpectedFetch {
                url: SUBSCRIPTION_URL,
                purpose: FetchPurpose::Subscription,
                result: Ok(SUBSCRIPTION.to_vec()),
            },
            ExpectedFetch {
                url: RULE_ONE_URL,
                purpose: FetchPurpose::BinaryRuleSet,
                result: Ok(asset.to_vec()),
            },
            ExpectedFetch {
                url: RULE_TWO_URL,
                purpose: FetchPurpose::BinaryRuleSet,
                result: Ok(asset.to_vec()),
            },
        ]
    }

    fn subscription_success() -> [ExpectedFetch; 1] {
        [ExpectedFetch {
            url: SUBSCRIPTION_URL,
            purpose: FetchPurpose::Subscription,
            result: Ok(SUBSCRIPTION.to_vec()),
        }]
    }

    fn request<'a>(template: &'a [u8], url: &'a Url) -> PrepareSubscriptionRequest<'a> {
        PrepareSubscriptionRequest::new(
            template,
            url,
            Path::new(ASSET_ROOT),
            LISTENER_PORT,
            SubscriptionRefreshLimits::new(Duration::from_secs(10), MAX_BYTES, MAX_BYTES, 100),
        )
    }

    #[test]
    fn refresh_fetches_rewrites_deduplicates_and_binds_assets_deterministically() {
        let url = Url::parse(SUBSCRIPTION_URL).unwrap();
        let adapter = DeterministicAdapter::new(expected_successes(b"same-srs-content"));
        let first = prepare_subscription_refresh(&adapter, request(TEMPLATE, &url)).unwrap();
        adapter.assert_exhausted();

        let adapter = DeterministicAdapter::new(expected_successes(b"same-srs-content"));
        let second = prepare_subscription_refresh(&adapter, request(TEMPLATE, &url)).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.node_count(), 1);
        assert_eq!(first.assets().len(), 1);
        assert_eq!(first.bindings().len(), 2);
        assert!(first.verify_assets());
        assert_eq!(first.content_sha256(), &Sha256::digest(first.bytes())[..]);
        assert_ne!(first.digest(), first.content_sha256());
        assert_eq!(first.bytes().last(), Some(&b'\n'));

        let document: Value = serde_json::from_slice(first.bytes()).unwrap();
        let tproxy = document["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|inbound| inbound["type"] == "tproxy")
            .expect("canonical TPROXY inbound");
        assert_eq!(tproxy["listen"], "::");
        assert_eq!(tproxy["listen_port"], LISTENER_PORT.get());
        assert!(tproxy.get("network").is_none());
        let rule_sets = document["route"]["rule_set"].as_array().unwrap();
        assert_eq!(rule_sets[0]["type"], "local");
        assert_eq!(rule_sets[1]["type"], "local");
        assert_eq!(rule_sets[0]["format"], "binary");
        assert_eq!(rule_sets[0]["path"], rule_sets[1]["path"]);
        assert_eq!(
            rule_sets[0]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["format", "path", "tag", "type"])
        );
        assert!(rule_sets.iter().all(|entry| entry.get("url").is_none()));
        assert!(
            rule_sets
                .iter()
                .all(|entry| entry.get("update_interval").is_none())
        );
        assert!(first.assets()[0].path().starts_with(Path::new(ASSET_ROOT)));
        assert_eq!(first.assets()[0].bytes(), b"same-srs-content");
        assert_eq!(first.bindings()[0].tag(), "one");
        assert_ne!(
            first.subscription_source().as_bytes(),
            first.bindings()[0].source().as_bytes()
        );
        assert_eq!(
            first.bindings()[0].content_sha256(),
            first.assets()[0].content_sha256()
        );
        assert_eq!(
            first.subscription_content_sha256(),
            &Sha256::digest(SUBSCRIPTION)[..]
        );
        assert_ne!(first.compiled_digest(), first.content_sha256());

        let debug = format!("{first:?}");
        assert!(!debug.contains("provider.example"));
        assert!(!debug.contains("token=secret"));
        assert!(!debug.contains("node.example"));
    }

    #[test]
    fn templates_without_rule_sets_fetch_only_the_subscription() {
        let url = Url::parse(SUBSCRIPTION_URL).unwrap();
        for template in [
            br#"{"outbounds":[{"type":"selector","tag":"PROXY","outbounds":[]}]}"#.as_slice(),
            br#"{"outbounds":[{"type":"selector","tag":"PROXY","outbounds":[]}],"route":{"rule_set":[]}}"#.as_slice(),
        ] {
            let adapter = DeterministicAdapter::new(subscription_success());
            let prepared = prepare_subscription_refresh(&adapter, request(template, &url)).unwrap();
            adapter.assert_exhausted();
            assert!(prepared.assets().is_empty());
            assert!(prepared.bindings().is_empty());
            assert!(prepared.verify_assets());
        }
    }

    #[test]
    fn packaged_template_has_only_managed_remote_asset_inputs() {
        let url = Url::parse(SUBSCRIPTION_URL).unwrap();
        preflight_template(request(PACKAGED_TEMPLATE, &url))
            .expect("packaged template asset ownership");
        let document: Value = serde_json::from_slice(PACKAGED_TEMPLATE).unwrap();
        assert_eq!(document["route"]["rule_set"].as_array().unwrap().len(), 3);
        assert!(
            document
                .pointer("/experimental/clash_api/external_ui_download_url")
                .is_none()
        );
    }

    #[test]
    fn template_preflight_rejects_unmanaged_downloads_and_local_assets_before_fetch() {
        let url = Url::parse(SUBSCRIPTION_URL).unwrap();
        let adapter = DeterministicAdapter::new([]);
        let unmanaged_ui = br#"{
            "outbounds":[],
            "experimental":{"clash_api":{"external_ui_download_url":"https://ui.example/ui.zip"}}
        }"#;
        let error =
            prepare_subscription_refresh(&adapter, request(unmanaged_ui, &url)).unwrap_err();
        assert_eq!(
            error.kind(),
            PrepareSubscriptionErrorKind::UnmanagedExternalDownload
        );

        let local = br#"{
            "outbounds":[],
            "route":{"rule_set":[{"type":"local","tag":"one","format":"binary","path":"one.srs"}]}
        }"#;
        let error = prepare_subscription_refresh(&adapter, request(local, &url)).unwrap_err();
        assert_eq!(
            error.kind(),
            PrepareSubscriptionErrorKind::UnsupportedRuleSet
        );

        let unmanaged_http_client = br#"{
            "outbounds":[],
            "route":{"rule_set":[{
                "type":"remote","tag":"one","format":"binary",
                "url":"https://assets.example/one.srs","http_client":"custom"
            }]}
        }"#;
        let error = prepare_subscription_refresh(&adapter, request(unmanaged_http_client, &url))
            .unwrap_err();
        assert_eq!(error.kind(), PrepareSubscriptionErrorKind::InvalidRuleSet);

        let insecure_asset = br#"{
            "outbounds":[],
            "route":{"rule_set":[{
                "type":"remote","tag":"one","format":"binary",
                "url":"http://assets.example/one.srs"
            }]}
        }"#;
        let error =
            prepare_subscription_refresh(&adapter, request(insecure_asset, &url)).unwrap_err();
        assert_eq!(error.kind(), PrepareSubscriptionErrorKind::RuleSetFetch);
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<FetchError>()
                .unwrap()
                .kind(),
            FetchErrorKind::InsecureUrl
        );
        adapter.assert_exhausted();
    }

    #[test]
    fn aggregate_asset_budget_and_fetch_failures_fail_closed() {
        let url = Url::parse(SUBSCRIPTION_URL).unwrap();
        let large = vec![b'x'; usize::try_from(MAX_BYTES / 2 + 1).unwrap()];
        let adapter = DeterministicAdapter::new(expected_successes(&large));
        let error = prepare_subscription_refresh(&adapter, request(TEMPLATE, &url)).unwrap_err();
        assert_eq!(
            error.kind(),
            PrepareSubscriptionErrorKind::AssetBytesTooLarge
        );
        adapter.assert_exhausted();

        let adapter = DeterministicAdapter::new([
            ExpectedFetch {
                url: SUBSCRIPTION_URL,
                purpose: FetchPurpose::Subscription,
                result: Ok(SUBSCRIPTION.to_vec()),
            },
            ExpectedFetch {
                url: RULE_ONE_URL,
                purpose: FetchPurpose::BinaryRuleSet,
                result: Err(FetchError::EmptyBody),
            },
        ]);
        let error = prepare_subscription_refresh(&adapter, request(TEMPLATE, &url)).unwrap_err();
        assert_eq!(error.kind(), PrepareSubscriptionErrorKind::RuleSetFetch);
        let source = error
            .source()
            .unwrap()
            .downcast_ref::<FetchError>()
            .unwrap();
        assert_eq!(source.kind(), FetchErrorKind::EmptyBody);
    }

    #[test]
    fn deterministic_adapter_contract_violations_keep_fetch_error_categories() {
        let url = Url::parse(SUBSCRIPTION_URL).unwrap();
        let oversized = vec![b'x'; usize::try_from(MAX_BYTES + 1).unwrap()];
        let adapter = DeterministicAdapter::new([ExpectedFetch {
            url: SUBSCRIPTION_URL,
            purpose: FetchPurpose::Subscription,
            result: Ok(oversized),
        }]);
        let error = prepare_subscription_refresh(&adapter, request(TEMPLATE, &url)).unwrap_err();
        assert_eq!(
            error.kind(),
            PrepareSubscriptionErrorKind::SubscriptionFetch
        );
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<FetchError>()
                .unwrap()
                .kind(),
            FetchErrorKind::DecodedBodyTooLarge
        );

        let adapter = DeterministicAdapter::new([
            subscription_success().into_iter().next().unwrap(),
            ExpectedFetch {
                url: RULE_ONE_URL,
                purpose: FetchPurpose::BinaryRuleSet,
                result: Ok(Vec::new()),
            },
        ]);
        let error = prepare_subscription_refresh(&adapter, request(TEMPLATE, &url)).unwrap_err();
        assert_eq!(error.kind(), PrepareSubscriptionErrorKind::RuleSetFetch);
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<FetchError>()
                .unwrap()
                .kind(),
            FetchErrorKind::EmptyBody
        );
    }

    #[test]
    fn asset_root_and_duplicate_tags_are_rejected_without_requests() {
        let url = Url::parse(SUBSCRIPTION_URL).unwrap();
        let adapter = DeterministicAdapter::new([]);
        let invalid_root = PrepareSubscriptionRequest::new(
            TEMPLATE,
            &url,
            Path::new("relative/assets"),
            LISTENER_PORT,
            SubscriptionRefreshLimits::new(Duration::from_secs(10), MAX_BYTES, MAX_BYTES, 100),
        );
        assert_eq!(
            prepare_subscription_refresh(&adapter, invalid_root)
                .unwrap_err()
                .kind(),
            PrepareSubscriptionErrorKind::InvalidAssetRoot
        );

        let duplicates = String::from_utf8(TEMPLATE.to_vec())
            .unwrap()
            .replace("\"tag\":\"two\"", "\"tag\":\"one\"");
        assert_eq!(
            prepare_subscription_refresh(&adapter, request(duplicates.as_bytes(), &url))
                .unwrap_err()
                .kind(),
            PrepareSubscriptionErrorKind::DuplicateRuleSetTag
        );
        adapter.assert_exhausted();
    }
}
