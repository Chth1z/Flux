use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::MAX_ENGINE_CONFIG_BYTES;

const SUBSCRIPTION_DIGEST_DOMAIN: &[u8] = b"Flux subscription merged engine template\0sha256-v1\0";
const MAX_SOURCE_LINE_BYTES: usize = 16 * 1024;
const MAX_NODE_BYTES: usize = 64 * 1024;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_OBJECT_FIELDS: usize = 256;
const MAX_JSON_ARRAY_ITEMS: usize = 100_000;
const MAX_JSON_STRING_BYTES: usize = 16 * 1024;
const MAX_TAG_CHARS: usize = 32;

const INFRASTRUCTURE_TYPES: &[&str] = &["selector", "urltest", "direct", "block", "dns"];
const SELECTION_TYPES: &[&str] = &["selector", "urltest"];
const EXCLUDED_ASCII_TAG_FRAGMENTS: &[&str] = &[
    "expire", "traffic", "reset", "contact", "group", "notice", "platform", "website", "time",
    "suggest", "feedback", "version", "update",
];
const EXCLUDED_UNICODE_TAG_FRAGMENTS: &[&str] = &[
    "\u{5b98}\u{7f51}",
    "\u{5230}\u{671f}",
    "\u{6d41}\u{91cf}",
    "\u{5269}\u{4f59}",
    "\u{5957}\u{9910}",
    "\u{91cd}\u{7f6e}",
    "\u{8054}\u{7cfb}",
    "\u{7fa4}\u{7ec4}",
    "\u{901a}\u{77e5}",
    "\u{5e73}\u{53f0}",
    "\u{7f51}\u{7ad9}",
    "\u{65f6}\u{95f4}",
    "\u{5efa}\u{8bae}",
    "\u{53cd}\u{9988}",
    "\u{7248}\u{672c}",
    "\u{66f4}\u{65b0}",
];

#[derive(Clone, Copy)]
pub(crate) struct SubscriptionCompileRequest<'a> {
    template: &'a [u8],
    source: &'a [u8],
    maximum_nodes: u32,
    maximum_decoded_bytes: u32,
}

impl<'a> SubscriptionCompileRequest<'a> {
    #[must_use]
    pub(crate) const fn new(
        template: &'a [u8],
        source: &'a [u8],
        maximum_nodes: u32,
        maximum_decoded_bytes: u32,
    ) -> Self {
        Self {
            template,
            source,
            maximum_nodes,
            maximum_decoded_bytes,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CompiledSubscriptionTemplate {
    bytes: Box<[u8]>,
    content_sha256: [u8; 32],
    digest: [u8; 32],
    node_count: u32,
}

impl fmt::Debug for CompiledSubscriptionTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledSubscriptionTemplate")
            .field("byte_len", &self.bytes.len())
            .field("content_sha256", &self.content_sha256)
            .field("digest", &self.digest)
            .field("node_count", &self.node_count)
            .finish()
    }
}

impl CompiledSubscriptionTemplate {
    #[must_use]
    pub(crate) const fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn content_sha256(&self) -> &[u8; 32] {
        &self.content_sha256
    }

    #[must_use]
    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[must_use]
    pub(crate) const fn node_count(&self) -> u32 {
        self.node_count
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SubscriptionCompileErrorKind {
    EmptySource,
    InvalidUtf8,
    InvalidJson,
    InvalidShape,
    InvalidBase64,
    InvalidUri,
    UnsupportedProtocol,
    ResourceLimit,
    NoUsableNodes,
    Serialize,
}

#[derive(Debug)]
pub(crate) enum SubscriptionCompileError {
    EmptySource,
    InvalidUtf8,
    InvalidJson(serde_json::Error),
    InvalidShape(&'static str),
    InvalidBase64,
    InvalidUri {
        line: usize,
        protocol: &'static str,
        detail: &'static str,
    },
    UnsupportedProtocol {
        line: usize,
        protocol: String,
    },
    ResourceLimit {
        resource: &'static str,
        actual: usize,
        maximum: usize,
    },
    NoUsableNodes,
    Serialize(serde_json::Error),
}

impl SubscriptionCompileError {
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn kind(&self) -> SubscriptionCompileErrorKind {
        match self {
            Self::EmptySource => SubscriptionCompileErrorKind::EmptySource,
            Self::InvalidUtf8 => SubscriptionCompileErrorKind::InvalidUtf8,
            Self::InvalidJson(_) => SubscriptionCompileErrorKind::InvalidJson,
            Self::InvalidShape(_) => SubscriptionCompileErrorKind::InvalidShape,
            Self::InvalidBase64 => SubscriptionCompileErrorKind::InvalidBase64,
            Self::InvalidUri { .. } => SubscriptionCompileErrorKind::InvalidUri,
            Self::UnsupportedProtocol { .. } => SubscriptionCompileErrorKind::UnsupportedProtocol,
            Self::ResourceLimit { .. } => SubscriptionCompileErrorKind::ResourceLimit,
            Self::NoUsableNodes => SubscriptionCompileErrorKind::NoUsableNodes,
            Self::Serialize(_) => SubscriptionCompileErrorKind::Serialize,
        }
    }
}

impl fmt::Display for SubscriptionCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySource => formatter.write_str("subscription source is empty"),
            Self::InvalidUtf8 => formatter.write_str("subscription source is not valid UTF-8"),
            Self::InvalidJson(source) => write!(formatter, "invalid subscription JSON: {source}"),
            Self::InvalidShape(detail) => write!(formatter, "invalid subscription shape: {detail}"),
            Self::InvalidBase64 => formatter
                .write_str("subscription is neither a supported document nor strict Base64"),
            Self::InvalidUri {
                line,
                protocol,
                detail,
            } => write!(
                formatter,
                "invalid {protocol} subscription URI on line {line}: {detail}"
            ),
            Self::UnsupportedProtocol { line, protocol } => write!(
                formatter,
                "unsupported subscription URI protocol '{protocol}' on line {line}"
            ),
            Self::ResourceLimit {
                resource,
                actual,
                maximum,
            } => write!(
                formatter,
                "subscription {resource} uses {actual}, exceeding the limit of {maximum}"
            ),
            Self::NoUsableNodes => {
                formatter.write_str("subscription contains no usable proxy nodes")
            }
            Self::Serialize(source) => {
                write!(
                    formatter,
                    "cannot serialize merged subscription template: {source}"
                )
            }
        }
    }
}

impl Error for SubscriptionCompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidJson(source) | Self::Serialize(source) => Some(source),
            Self::EmptySource
            | Self::InvalidUtf8
            | Self::InvalidShape(_)
            | Self::InvalidBase64
            | Self::InvalidUri { .. }
            | Self::UnsupportedProtocol { .. }
            | Self::ResourceLimit { .. }
            | Self::NoUsableNodes => None,
        }
    }
}

/// Compile one bounded subscription and base template without I/O or process authority.
pub(crate) fn compile_subscription_template(
    request: SubscriptionCompileRequest<'_>,
) -> Result<CompiledSubscriptionTemplate, SubscriptionCompileError> {
    if request.source.is_empty() {
        return Err(SubscriptionCompileError::EmptySource);
    }
    let maximum_engine_config_bytes = usize::try_from(MAX_ENGINE_CONFIG_BYTES).map_err(|_| {
        SubscriptionCompileError::InvalidShape(
            "engine configuration limit does not fit this target",
        )
    })?;
    if request.template.len() > maximum_engine_config_bytes {
        return Err(resource_limit(
            "template bytes",
            request.template.len(),
            maximum_engine_config_bytes,
        ));
    }
    let maximum_nodes = usize::try_from(request.maximum_nodes).map_err(|_| {
        SubscriptionCompileError::InvalidShape("maximum node count does not fit this target")
    })?;
    if maximum_nodes == 0 || maximum_nodes > MAX_JSON_ARRAY_ITEMS {
        return Err(resource_limit(
            "node limit",
            maximum_nodes,
            MAX_JSON_ARRAY_ITEMS,
        ));
    }
    let maximum_decoded_bytes = usize::try_from(request.maximum_decoded_bytes).map_err(|_| {
        SubscriptionCompileError::InvalidShape("decoded byte limit does not fit this target")
    })?;
    if maximum_decoded_bytes == 0 || maximum_decoded_bytes > maximum_engine_config_bytes {
        return Err(resource_limit(
            "decoded byte limit",
            maximum_decoded_bytes,
            maximum_engine_config_bytes,
        ));
    }

    let mut nodes = parse_source(request.source, maximum_nodes, maximum_decoded_bytes)?;
    normalize_nodes(&mut nodes, maximum_nodes)?;
    if nodes.is_empty() {
        return Err(SubscriptionCompileError::NoUsableNodes);
    }

    let mut template = serde_json::from_slice::<Value>(request.template)
        .map_err(SubscriptionCompileError::InvalidJson)?;
    validate_json_shape(&template, 0)?;
    merge_nodes(&mut template, nodes)?;
    remove_nulls(&mut template);
    let bytes = serde_json::to_vec(&template).map_err(SubscriptionCompileError::Serialize)?;
    if bytes.len() > maximum_engine_config_bytes {
        return Err(resource_limit(
            "merged configuration bytes",
            bytes.len(),
            maximum_engine_config_bytes,
        ));
    }
    let node_count = count_proxy_nodes(&template)?;
    let node_count = u32::try_from(node_count).map_err(|_| {
        SubscriptionCompileError::InvalidShape("compiled node count does not fit u32")
    })?;
    let content_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    let mut digest = Sha256::new();
    digest.update(SUBSCRIPTION_DIGEST_DOMAIN);
    digest.update(content_sha256);
    digest.update(node_count.to_be_bytes());
    Ok(CompiledSubscriptionTemplate {
        bytes: bytes.into_boxed_slice(),
        content_sha256,
        digest: digest.finalize().into(),
        node_count,
    })
}

fn parse_source(
    source: &[u8],
    maximum_nodes: usize,
    maximum_decoded_bytes: usize,
) -> Result<Vec<Map<String, Value>>, SubscriptionCompileError> {
    let text = std::str::from_utf8(source).map_err(|_| SubscriptionCompileError::InvalidUtf8)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(SubscriptionCompileError::EmptySource);
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        enforce_decoded_limit(trimmed.len(), maximum_decoded_bytes)?;
        return parse_json_nodes(trimmed.as_bytes(), maximum_nodes);
    }
    if trimmed.contains("://") {
        enforce_decoded_limit(trimmed.len(), maximum_decoded_bytes)?;
        return parse_uri_lines(trimmed, maximum_nodes);
    }

    let compact: String = trimmed
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let decoded =
        decode_base64(compact.as_bytes()).ok_or(SubscriptionCompileError::InvalidBase64)?;
    enforce_decoded_limit(decoded.len(), maximum_decoded_bytes)?;
    let decoded =
        std::str::from_utf8(&decoded).map_err(|_| SubscriptionCompileError::InvalidUtf8)?;
    let decoded = decoded.trim();
    if decoded.starts_with('{') || decoded.starts_with('[') {
        parse_json_nodes(decoded.as_bytes(), maximum_nodes)
    } else if decoded.contains("://") {
        parse_uri_lines(decoded, maximum_nodes)
    } else {
        Err(SubscriptionCompileError::InvalidBase64)
    }
}

fn enforce_decoded_limit(actual: usize, maximum: usize) -> Result<(), SubscriptionCompileError> {
    if actual > maximum {
        Err(resource_limit("decoded source bytes", actual, maximum))
    } else {
        Ok(())
    }
}

fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    STANDARD
        .decode(input)
        .or_else(|_| STANDARD_NO_PAD.decode(input))
        .or_else(|_| URL_SAFE.decode(input))
        .or_else(|_| URL_SAFE_NO_PAD.decode(input))
        .ok()
}

fn parse_json_nodes(
    source: &[u8],
    maximum_nodes: usize,
) -> Result<Vec<Map<String, Value>>, SubscriptionCompileError> {
    let parsed =
        serde_json::from_slice::<Value>(source).map_err(SubscriptionCompileError::InvalidJson)?;
    validate_json_shape(&parsed, 0)?;
    let values = match parsed {
        Value::Array(values) => values,
        Value::Object(mut object) => match object.remove("outbounds") {
            Some(Value::Array(values)) => values,
            Some(_) => {
                return Err(SubscriptionCompileError::InvalidShape(
                    "subscription outbounds must be an array",
                ));
            }
            None => {
                return Err(SubscriptionCompileError::InvalidShape(
                    "subscription JSON must be an array or contain outbounds",
                ));
            }
        },
        _ => {
            return Err(SubscriptionCompileError::InvalidShape(
                "subscription JSON root must be an object or array",
            ));
        }
    };
    if values.len() > maximum_nodes {
        return Err(resource_limit("nodes", values.len(), maximum_nodes));
    }
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| match value {
            Value::Object(object) => {
                let encoded =
                    serde_json::to_vec(&object).map_err(SubscriptionCompileError::Serialize)?;
                if encoded.len() > MAX_NODE_BYTES {
                    return Err(resource_limit("node bytes", encoded.len(), MAX_NODE_BYTES));
                }
                Ok(object)
            }
            _ => Err(SubscriptionCompileError::InvalidShape(match index {
                0 => "subscription node 0 must be an object",
                _ => "every subscription node must be an object",
            })),
        })
        .collect()
}

fn parse_uri_lines(
    source: &str,
    maximum_nodes: usize,
) -> Result<Vec<Map<String, Value>>, SubscriptionCompileError> {
    let mut nodes = Vec::new();
    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > MAX_SOURCE_LINE_BYTES {
            return Err(resource_limit(
                "URI line bytes",
                line.len(),
                MAX_SOURCE_LINE_BYTES,
            ));
        }
        if nodes.len() >= maximum_nodes {
            return Err(resource_limit("nodes", nodes.len() + 1, maximum_nodes));
        }
        let scheme = line
            .split_once("://")
            .map(|(scheme, _)| scheme.to_ascii_lowercase())
            .ok_or(SubscriptionCompileError::InvalidUri {
                line: line_number,
                protocol: "unknown",
                detail: "missing scheme delimiter",
            })?;
        let node = match scheme.as_str() {
            "vmess" => parse_vmess_uri(line, line_number)?,
            "ss" => parse_shadowsocks_uri(line, line_number)?,
            "vless" | "trojan" | "hysteria" | "hysteria2" | "tuic" | "socks" | "http" | "snell" => {
                parse_structured_uri(line, line_number, &scheme)?
            }
            _ => {
                return Err(SubscriptionCompileError::UnsupportedProtocol {
                    line: line_number,
                    protocol: scheme,
                });
            }
        };
        nodes.push(node);
    }
    Ok(nodes)
}

fn parse_vmess_uri(
    line: &str,
    line_number: usize,
) -> Result<Map<String, Value>, SubscriptionCompileError> {
    let encoded = line
        .strip_prefix("vmess://")
        .or_else(|| line.strip_prefix("VMESS://"))
        .ok_or_else(|| invalid_uri(line_number, "vmess", "invalid scheme"))?;
    let encoded = encoded.split('#').next().unwrap_or(encoded);
    let decoded = decode_base64(encoded.as_bytes())
        .ok_or_else(|| invalid_uri(line_number, "vmess", "invalid Base64 payload"))?;
    if decoded.len() > MAX_NODE_BYTES {
        return Err(resource_limit(
            "VMess payload bytes",
            decoded.len(),
            MAX_NODE_BYTES,
        ));
    }
    let value =
        serde_json::from_slice::<Value>(&decoded).map_err(SubscriptionCompileError::InvalidJson)?;
    validate_json_shape(&value, 0)?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid_uri(line_number, "vmess", "payload must be a JSON object"))?;
    let server = json_scalar_text(object, "add")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_uri(line_number, "vmess", "missing server"))?;
    let port = json_u16(object, "port")
        .ok_or_else(|| invalid_uri(line_number, "vmess", "invalid server port"))?;
    let uuid = json_scalar_text(object, "id")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_uri(line_number, "vmess", "missing UUID"))?;
    let tag = json_scalar_text(object, "ps").unwrap_or_else(|| "VMess".to_owned());

    let mut node = Map::new();
    insert_string(&mut node, "type", "vmess");
    insert_string(&mut node, "tag", tag);
    insert_string(&mut node, "server", server);
    node.insert("server_port".to_owned(), Value::from(port));
    insert_string(&mut node, "uuid", uuid);
    insert_string(
        &mut node,
        "security",
        json_scalar_text(object, "scy").unwrap_or_else(|| "auto".to_owned()),
    );
    if let Some(alter_id) = json_u64(object, "aid").filter(|value| *value != 0) {
        node.insert("alter_id".to_owned(), Value::from(alter_id));
    }

    let network = json_scalar_text(object, "net").unwrap_or_default();
    if network == "ws" {
        let mut transport = Map::new();
        insert_string(&mut transport, "type", "ws");
        if let Some(path) = json_scalar_text(object, "path").filter(|value| !value.is_empty()) {
            insert_string(&mut transport, "path", path);
        }
        if let Some(host) = json_scalar_text(object, "host").filter(|value| !value.is_empty()) {
            let mut headers = Map::new();
            insert_string(&mut headers, "Host", host);
            transport.insert("headers".to_owned(), Value::Object(headers));
        }
        node.insert("transport".to_owned(), Value::Object(transport));
    } else if network == "grpc" {
        let mut transport = Map::new();
        insert_string(&mut transport, "type", "grpc");
        if let Some(service) = json_scalar_text(object, "path").filter(|value| !value.is_empty()) {
            insert_string(&mut transport, "service_name", service);
        }
        node.insert("transport".to_owned(), Value::Object(transport));
    }
    if json_scalar_text(object, "tls").is_some_and(|value| value == "tls") {
        let server_name = json_scalar_text(object, "sni")
            .or_else(|| json_scalar_text(object, "host"))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| node["server"].as_str().unwrap_or_default().to_owned());
        node.insert(
            "tls".to_owned(),
            Value::Object(tls_object(server_name, false)),
        );
    }
    Ok(node)
}

fn parse_shadowsocks_uri(
    line: &str,
    line_number: usize,
) -> Result<Map<String, Value>, SubscriptionCompileError> {
    let remainder = line
        .split_once("://")
        .map(|(_, value)| value)
        .ok_or_else(|| invalid_uri(line_number, "ss", "missing URI payload"))?;
    let (without_fragment, fragment) = split_fragment(remainder);
    let (authority, query) = without_fragment
        .split_once('?')
        .map_or((without_fragment, None), |(authority, query)| {
            (authority, Some(query))
        });
    let expanded = if authority.contains('@') {
        authority.to_owned()
    } else {
        let decoded = decode_base64(authority.as_bytes())
            .ok_or_else(|| invalid_uri(line_number, "ss", "invalid Base64 authority"))?;
        String::from_utf8(decoded)
            .map_err(|_| invalid_uri(line_number, "ss", "authority is not UTF-8"))?
    };
    let (userinfo, host_port) = expanded
        .rsplit_once('@')
        .ok_or_else(|| invalid_uri(line_number, "ss", "missing user information"))?;
    let userinfo = if userinfo.contains(':') {
        userinfo.to_owned()
    } else {
        let decoded = decode_base64(userinfo.as_bytes())
            .ok_or_else(|| invalid_uri(line_number, "ss", "invalid Base64 user information"))?;
        String::from_utf8(decoded)
            .map_err(|_| invalid_uri(line_number, "ss", "user information is not UTF-8"))?
    };
    let (method, password) = userinfo
        .split_once(':')
        .ok_or_else(|| invalid_uri(line_number, "ss", "missing method or password"))?;
    let endpoint = Url::parse(&format!("ss://x@{host_port}"))
        .map_err(|_| invalid_uri(line_number, "ss", "invalid server endpoint"))?;
    let server = endpoint
        .host_str()
        .ok_or_else(|| invalid_uri(line_number, "ss", "missing server"))?;
    let port = endpoint
        .port()
        .ok_or_else(|| invalid_uri(line_number, "ss", "missing server port"))?;

    let mut node = Map::new();
    insert_string(&mut node, "type", "shadowsocks");
    insert_string(
        &mut node,
        "tag",
        fragment
            .map(|value| percent_decode(value, line_number, "ss"))
            .transpose()?
            .unwrap_or_else(|| "shadowsocks".to_owned()),
    );
    insert_string(&mut node, "server", server);
    node.insert("server_port".to_owned(), Value::from(port));
    insert_string(
        &mut node,
        "method",
        percent_decode(method, line_number, "ss")?,
    );
    insert_string(
        &mut node,
        "password",
        percent_decode(password, line_number, "ss")?,
    );
    if let Some(query) = query {
        let query = query_pairs(query);
        if let Some(plugin) = query.get("plugin").filter(|value| !value.is_empty()) {
            let (name, options) = plugin
                .split_once(';')
                .map_or((plugin.as_str(), None), |(name, options)| {
                    (name, Some(options))
                });
            insert_string(&mut node, "plugin", name);
            if let Some(options) = options {
                insert_string(&mut node, "plugin_opts", options);
            }
        }
    }
    Ok(node)
}

fn parse_structured_uri(
    line: &str,
    line_number: usize,
    scheme: &str,
) -> Result<Map<String, Value>, SubscriptionCompileError> {
    let parsed = Url::parse(line)
        .map_err(|_| invalid_uri(line_number, protocol_token(scheme), "URL parse failed"))?;
    let protocol = protocol_token(scheme);
    let server = parsed
        .host_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_uri(line_number, protocol, "missing server"))?;
    let port = parsed.port().unwrap_or(443);
    let username = percent_decode(parsed.username(), line_number, protocol)?;
    let password = parsed
        .password()
        .map(|value| percent_decode(value, line_number, protocol))
        .transpose()?;
    let tag = parsed
        .fragment()
        .map(|value| percent_decode(value, line_number, protocol))
        .transpose()?
        .unwrap_or_else(|| scheme.to_owned());
    let query: BTreeMap<String, String> = parsed.query_pairs().into_owned().collect();

    let mut node = Map::new();
    let sing_box_type = if scheme == "socks" { "socks" } else { scheme };
    insert_string(&mut node, "type", sing_box_type);
    insert_string(&mut node, "tag", tag);
    insert_string(&mut node, "server", server);
    node.insert("server_port".to_owned(), Value::from(port));

    match scheme {
        "vless" => {
            require_credential(&username, line_number, protocol, "UUID")?;
            insert_string(&mut node, "uuid", username);
            insert_query_string(&mut node, "flow", &query, &["flow"]);
        }
        "trojan" => {
            require_credential(&username, line_number, protocol, "password")?;
            insert_string(&mut node, "password", username);
        }
        "hysteria" => {
            require_credential(&username, line_number, protocol, "authentication")?;
            insert_string(&mut node, "auth_str", username);
            insert_query_u64(&mut node, "up_mbps", &query, &["upmbps", "up"])?;
            insert_query_u64(&mut node, "down_mbps", &query, &["downmbps", "down"])?;
            insert_query_string(&mut node, "obfs", &query, &["obfs"]);
        }
        "hysteria2" => {
            require_credential(&username, line_number, protocol, "password")?;
            insert_string(&mut node, "password", username);
            if let Some(obfs_password) =
                query.get("obfs-password").filter(|value| !value.is_empty())
            {
                let mut obfs = Map::new();
                insert_string(
                    &mut obfs,
                    "type",
                    query.get("obfs").map_or("salamander", String::as_str),
                );
                insert_string(&mut obfs, "password", obfs_password);
                node.insert("obfs".to_owned(), Value::Object(obfs));
            }
        }
        "tuic" => {
            require_credential(&username, line_number, protocol, "UUID")?;
            let password = password
                .or_else(|| query.get("password").cloned())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid_uri(line_number, protocol, "missing password"))?;
            insert_string(&mut node, "uuid", username);
            insert_string(&mut node, "password", password);
            insert_query_string(
                &mut node,
                "congestion_control",
                &query,
                &["congestion_control", "congestion-controller"],
            );
            insert_query_string(
                &mut node,
                "udp_relay_mode",
                &query,
                &["udp_relay_mode", "udp-relay-mode"],
            );
        }
        "socks" | "http" => {
            if !username.is_empty() {
                insert_string(&mut node, "username", username);
            }
            if let Some(password) = password.filter(|value| !value.is_empty()) {
                insert_string(&mut node, "password", password);
            }
        }
        "snell" => {
            require_credential(&username, line_number, protocol, "pre-shared key")?;
            insert_string(&mut node, "psk", username);
            insert_query_u64(&mut node, "version", &query, &["version"])?;
        }
        _ => unreachable!("caller admits only supported structured protocols"),
    }

    add_transport(&mut node, &query);
    let tls_default = matches!(scheme, "trojan" | "hysteria" | "hysteria2" | "tuic");
    add_tls(&mut node, &query, server, tls_default);
    Ok(node)
}

fn protocol_token(scheme: &str) -> &'static str {
    match scheme {
        "vless" => "vless",
        "trojan" => "trojan",
        "hysteria" => "hysteria",
        "hysteria2" => "hysteria2",
        "tuic" => "tuic",
        "socks" => "socks",
        "http" => "http",
        "snell" => "snell",
        _ => "unknown",
    }
}

fn normalize_nodes(
    nodes: &mut Vec<Map<String, Value>>,
    maximum_nodes: usize,
) -> Result<(), SubscriptionCompileError> {
    let mut normalized = Vec::with_capacity(nodes.len());
    let mut names = BTreeMap::<String, usize>::new();
    for mut node in nodes.drain(..) {
        validate_json_shape(&Value::Object(node.clone()), 0)?;
        let node_type = required_string(&node, "type", "node type must be a nonempty string")?;
        if INFRASTRUCTURE_TYPES.contains(&node_type) {
            continue;
        }
        let source_tag = required_string(&node, "tag", "node tag must be a nonempty string")?;
        if excluded_tag(source_tag) {
            continue;
        }
        let base = normalize_tag(source_tag, node_type);
        let occurrence = names.entry(base.clone()).or_default();
        *occurrence += 1;
        let stable = if *occurrence == 1 {
            base
        } else {
            tag_with_suffix(&base, *occurrence)
        };
        node.insert("tag".to_owned(), Value::String(stable));
        let encoded = serde_json::to_vec(&node).map_err(SubscriptionCompileError::Serialize)?;
        if encoded.len() > MAX_NODE_BYTES {
            return Err(resource_limit(
                "normalized node bytes",
                encoded.len(),
                MAX_NODE_BYTES,
            ));
        }
        normalized.push(node);
        if normalized.len() > maximum_nodes {
            return Err(resource_limit("nodes", normalized.len(), maximum_nodes));
        }
    }
    *nodes = normalized;
    Ok(())
}

fn merge_nodes(
    template: &mut Value,
    nodes: Vec<Map<String, Value>>,
) -> Result<(), SubscriptionCompileError> {
    let root = template
        .as_object_mut()
        .ok_or(SubscriptionCompileError::InvalidShape(
            "engine template root must be an object",
        ))?;
    let outbounds = root
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .ok_or(SubscriptionCompileError::InvalidShape(
            "engine template outbounds must be an array",
        ))?;
    outbounds.retain(|outbound| {
        outbound
            .as_object()
            .and_then(|object| object.get("type"))
            .and_then(Value::as_str)
            .is_some_and(|node_type| INFRASTRUCTURE_TYPES.contains(&node_type))
    });

    let all_tags: Vec<String> = nodes
        .iter()
        .filter_map(|node| node.get("tag").and_then(Value::as_str).map(str::to_owned))
        .collect();
    for outbound in outbounds.iter_mut() {
        let Some(group) = outbound.as_object_mut() else {
            return Err(SubscriptionCompileError::InvalidShape(
                "engine template outbound must be an object",
            ));
        };
        if !group
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| SELECTION_TYPES.contains(&kind))
        {
            continue;
        }
        let group_tag = required_string(
            group,
            "tag",
            "selection-group tag must be a nonempty string",
        )?
        .to_owned();
        let members = group
            .get_mut("outbounds")
            .and_then(Value::as_array_mut)
            .ok_or(SubscriptionCompileError::InvalidShape(
                "selection-group outbounds must be an array",
            ))?;
        if !members.is_empty() {
            continue;
        }
        let selected = if matches!(group_tag.as_str(), "PROXY" | "AUTO") {
            all_tags.clone()
        } else {
            all_tags
                .iter()
                .filter(|tag| tag_matches_country(tag, &group_tag))
                .cloned()
                .collect()
        };
        *members = selected.into_iter().map(Value::String).collect();
    }

    prune_empty_country_groups(outbounds, &all_tags);
    outbounds.extend(nodes.into_iter().map(Value::Object));
    validate_selection_graph(outbounds)?;
    Ok(())
}

fn prune_empty_country_groups(outbounds: &mut Vec<Value>, proxy_tags: &[String]) {
    let empty_country_tags: BTreeSet<String> = outbounds
        .iter()
        .filter_map(Value::as_object)
        .filter(|object| {
            object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| SELECTION_TYPES.contains(&kind))
        })
        .filter_map(|object| {
            object
                .get("outbounds")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
                .then(|| object.get("tag").and_then(Value::as_str))
                .flatten()
                .filter(|tag| !country_aliases(tag).is_empty())
                .map(str::to_owned)
        })
        .collect();

    outbounds.retain(|outbound| {
        outbound
            .as_object()
            .and_then(|object| object.get("tag"))
            .and_then(Value::as_str)
            .is_none_or(|tag| !empty_country_tags.contains(tag))
    });
    for outbound in outbounds.iter_mut() {
        let Some(object) = outbound.as_object_mut() else {
            continue;
        };
        if !object
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| SELECTION_TYPES.contains(&kind))
        {
            continue;
        }
        let tag = object
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let Some(members) = object.get_mut("outbounds").and_then(Value::as_array_mut) else {
            continue;
        };
        members.retain(|member| {
            member
                .as_str()
                .is_none_or(|tag| !empty_country_tags.contains(tag))
        });
        if members.is_empty() && matches!(tag.as_str(), "PROXY" | "AUTO") {
            members.extend(proxy_tags.iter().cloned().map(Value::String));
        }
    }
}

fn validate_selection_graph(outbounds: &[Value]) -> Result<(), SubscriptionCompileError> {
    let mut known_tags = BTreeSet::new();
    let mut proxy_tags = BTreeSet::new();
    let mut groups = BTreeMap::<String, Vec<String>>::new();

    for outbound in outbounds {
        let object = outbound
            .as_object()
            .ok_or(SubscriptionCompileError::InvalidShape(
                "compiled outbound must be an object",
            ))?;
        let kind = required_string(
            object,
            "type",
            "compiled outbound type must be a nonempty string",
        )?;
        let tag = required_string(
            object,
            "tag",
            "compiled outbound tag must be a nonempty string",
        )?;
        if !known_tags.insert(tag.to_owned()) {
            return Err(SubscriptionCompileError::InvalidShape(
                "compiled outbound tags must be unique",
            ));
        }
        if !INFRASTRUCTURE_TYPES.contains(&kind) {
            proxy_tags.insert(tag.to_owned());
        }
        if SELECTION_TYPES.contains(&kind) {
            let members = object.get("outbounds").and_then(Value::as_array).ok_or(
                SubscriptionCompileError::InvalidShape(
                    "selection-group outbounds must be an array",
                ),
            )?;
            let mut unique_members = BTreeSet::new();
            let members = members
                .iter()
                .map(|member| {
                    member.as_str().filter(|member| !member.is_empty()).ok_or(
                        SubscriptionCompileError::InvalidShape(
                            "selection-group member must be a nonempty string",
                        ),
                    )
                })
                .map(|member| {
                    let member = member?;
                    if !unique_members.insert(member) {
                        return Err(SubscriptionCompileError::InvalidShape(
                            "selection-group members must be unique",
                        ));
                    }
                    Ok(member.to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?;
            groups.insert(tag.to_owned(), members);
        }
    }

    let mut parents_by_member = BTreeMap::<String, Vec<String>>::new();
    let mut group_indegrees: BTreeMap<String, usize> =
        groups.keys().map(|tag| (tag.clone(), 0)).collect();
    for (group, members) in &groups {
        for member in members {
            if !known_tags.contains(member) {
                return Err(SubscriptionCompileError::InvalidShape(
                    "selection-group member references a missing outbound",
                ));
            }
            parents_by_member
                .entry(member.clone())
                .or_default()
                .push(group.clone());
            if let Some(indegree) = group_indegrees.get_mut(member) {
                *indegree += 1;
            }
        }
    }

    let mut acyclic = group_indegrees
        .iter()
        .filter_map(|(tag, indegree)| (*indegree == 0).then_some(tag.clone()))
        .collect::<Vec<_>>();
    let mut visited_groups = 0usize;
    while let Some(group) = acyclic.pop() {
        visited_groups += 1;
        for member in groups.get(&group).into_iter().flatten() {
            let Some(indegree) = group_indegrees.get_mut(member) else {
                continue;
            };
            *indegree -= 1;
            if *indegree == 0 {
                acyclic.push(member.clone());
            }
        }
    }
    if visited_groups != groups.len() {
        return Err(SubscriptionCompileError::InvalidShape(
            "selection-group graph must be acyclic",
        ));
    }

    let mut reaches_proxy = proxy_tags.clone();
    let mut reachable = proxy_tags.into_iter().collect::<Vec<_>>();
    while let Some(tag) = reachable.pop() {
        for group in parents_by_member.get(&tag).into_iter().flatten() {
            if reaches_proxy.insert(group.clone()) {
                reachable.push(group.clone());
            }
        }
    }
    if groups.keys().any(|group| !reaches_proxy.contains(group)) {
        return Err(SubscriptionCompileError::InvalidShape(
            "selection group cannot reach a usable proxy outbound",
        ));
    }
    Ok(())
}

fn count_proxy_nodes(template: &Value) -> Result<usize, SubscriptionCompileError> {
    let outbounds = template.get("outbounds").and_then(Value::as_array).ok_or(
        SubscriptionCompileError::InvalidShape("compiled template outbounds must be an array"),
    )?;
    Ok(outbounds
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|object| object.get("type").and_then(Value::as_str))
        .filter(|node_type| !INFRASTRUCTURE_TYPES.contains(node_type))
        .count())
}

fn validate_json_shape(value: &Value, depth: usize) -> Result<(), SubscriptionCompileError> {
    if depth > MAX_JSON_DEPTH {
        return Err(resource_limit("JSON depth", depth, MAX_JSON_DEPTH));
    }
    match value {
        Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => Err(resource_limit(
            "JSON string bytes",
            value.len(),
            MAX_JSON_STRING_BYTES,
        )),
        Value::Array(values) => {
            if values.len() > MAX_JSON_ARRAY_ITEMS {
                return Err(resource_limit(
                    "JSON array items",
                    values.len(),
                    MAX_JSON_ARRAY_ITEMS,
                ));
            }
            for value in values {
                validate_json_shape(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            if object.len() > MAX_JSON_OBJECT_FIELDS {
                return Err(resource_limit(
                    "JSON object fields",
                    object.len(),
                    MAX_JSON_OBJECT_FIELDS,
                ));
            }
            for (key, value) in object {
                if key.len() > MAX_JSON_STRING_BYTES {
                    return Err(resource_limit(
                        "JSON key bytes",
                        key.len(),
                        MAX_JSON_STRING_BYTES,
                    ));
                }
                validate_json_shape(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

fn remove_nulls(value: &mut Value) {
    match value {
        Value::Array(values) => {
            values.retain(|value| !value.is_null());
            for value in values {
                remove_nulls(value);
            }
        }
        Value::Object(object) => {
            object.retain(|_, value| !value.is_null());
            for value in object.values_mut() {
                remove_nulls(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn excluded_tag(tag: &str) -> bool {
    let lower = tag.to_ascii_lowercase();
    EXCLUDED_ASCII_TAG_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
        || EXCLUDED_UNICODE_TAG_FRAGMENTS
            .iter()
            .any(|fragment| tag.contains(fragment))
}

fn normalize_tag(tag: &str, fallback: &str) -> String {
    let mut normalized = String::with_capacity(tag.len());
    let mut pending_space = false;
    for character in tag.chars() {
        let character = match character {
            '\u{3010}' => '[',
            '\u{3011}' => ']',
            _ if emoji_like(character) => continue,
            _ => character,
        };
        if character.is_whitespace() {
            pending_space = !normalized.is_empty();
            continue;
        }
        if pending_space {
            normalized.push(' ');
            pending_space = false;
        }
        normalized.push(character);
    }
    let normalized = normalized.trim();
    let normalized = if normalized.is_empty() {
        fallback
    } else {
        normalized
    };
    truncate_tag(normalized, "")
}

fn emoji_like(character: char) -> bool {
    matches!(
        u32::from(character),
        0x1f000..=0x1faff | 0x2600..=0x27bf
    )
}

fn tag_with_suffix(base: &str, occurrence: usize) -> String {
    let suffix = format!(" #{occurrence}");
    truncate_tag(base, &suffix)
}

fn truncate_tag(base: &str, suffix: &str) -> String {
    let suffix_chars = suffix.chars().count();
    let base_limit = MAX_TAG_CHARS.saturating_sub(suffix_chars);
    let base_chars = base.chars().count();
    let mut value = if base_chars <= base_limit {
        base.to_owned()
    } else if base_limit > 3 {
        let prefix: String = base.chars().take(base_limit - 3).collect();
        format!("{prefix}...")
    } else {
        base.chars().take(base_limit).collect()
    };
    value.push_str(suffix);
    value
}

fn tag_matches_country(tag: &str, country: &str) -> bool {
    let tag = tag.to_ascii_lowercase();
    country_aliases(country)
        .iter()
        .any(|alias| tag.contains(&alias.to_ascii_lowercase()))
}

fn country_aliases(country: &str) -> &'static [&'static str] {
    match country {
        "HK" => &["hk", "hong kong", "hongkong", "\u{9999}\u{6e2f}"],
        "TW" => &["tw", "taiwan", "\u{53f0}\u{6e7e}"],
        "JP" => &["jp", "japan", "\u{65e5}\u{672c}"],
        "SG" => &["sg", "singapore", "\u{65b0}\u{52a0}\u{5761}"],
        "US" => &["us", "usa", "united states", "america", "\u{7f8e}\u{56fd}"],
        "KR" => &["kr", "korea", "\u{97e9}\u{56fd}"],
        "UK" => &["uk", "gb", "united kingdom", "britain", "\u{82f1}\u{56fd}"],
        "DE" => &["de", "germany", "\u{5fb7}\u{56fd}"],
        "FR" => &["fr", "france", "\u{6cd5}\u{56fd}"],
        "CA" => &["ca", "canada", "\u{52a0}\u{62ff}\u{5927}"],
        "AU" => &["au", "australia", "\u{6fb3}\u{5927}\u{5229}\u{4e9a}"],
        _ => &[],
    }
}

fn add_transport(node: &mut Map<String, Value>, query: &BTreeMap<String, String>) {
    let Some(kind) = first_query(query, &["type", "network"]).filter(|value| !value.is_empty())
    else {
        return;
    };
    let mut transport = Map::new();
    match kind {
        "ws" => {
            insert_string(&mut transport, "type", "ws");
            if let Some(path) = first_query(query, &["path"]).filter(|value| !value.is_empty()) {
                insert_string(&mut transport, "path", path);
            }
            if let Some(host) = first_query(query, &["host"]).filter(|value| !value.is_empty()) {
                let mut headers = Map::new();
                insert_string(&mut headers, "Host", host);
                transport.insert("headers".to_owned(), Value::Object(headers));
            }
        }
        "grpc" => {
            insert_string(&mut transport, "type", "grpc");
            if let Some(service) = first_query(query, &["serviceName", "service_name", "path"])
                .filter(|value| !value.is_empty())
            {
                insert_string(&mut transport, "service_name", service);
            }
        }
        "httpupgrade" => {
            insert_string(&mut transport, "type", "httpupgrade");
            if let Some(path) = first_query(query, &["path"]).filter(|value| !value.is_empty()) {
                insert_string(&mut transport, "path", path);
            }
            if let Some(host) = first_query(query, &["host"]).filter(|value| !value.is_empty()) {
                insert_string(&mut transport, "host", host);
            }
        }
        "tcp" => return,
        _ => return,
    }
    node.insert("transport".to_owned(), Value::Object(transport));
}

fn add_tls(
    node: &mut Map<String, Value>,
    query: &BTreeMap<String, String>,
    server: &str,
    enabled_by_default: bool,
) {
    let security = first_query(query, &["security"]);
    let enabled = enabled_by_default
        || security.is_some_and(|value| matches!(value, "tls" | "reality"))
        || first_query(query, &["tls"]).is_some_and(truthy);
    if !enabled {
        return;
    }
    let server_name = first_query(query, &["sni", "server_name", "peer"])
        .filter(|value| !value.is_empty())
        .unwrap_or(server);
    let insecure = first_query(query, &["allowInsecure", "insecure"]).is_some_and(truthy);
    let mut tls = tls_object(server_name.to_owned(), insecure);
    if let Some(alpn) = first_query(query, &["alpn"]).filter(|value| !value.is_empty()) {
        tls.insert(
            "alpn".to_owned(),
            Value::Array(
                alpn.split(',')
                    .filter(|value| !value.is_empty())
                    .map(|value| Value::String(value.to_owned()))
                    .collect(),
            ),
        );
    }
    if security == Some("reality") {
        let mut reality = Map::new();
        reality.insert("enabled".to_owned(), Value::Bool(true));
        if let Some(public_key) =
            first_query(query, &["pbk", "public_key"]).filter(|value| !value.is_empty())
        {
            insert_string(&mut reality, "public_key", public_key);
        }
        if let Some(short_id) =
            first_query(query, &["sid", "short_id"]).filter(|value| !value.is_empty())
        {
            insert_string(&mut reality, "short_id", short_id);
        }
        tls.insert("reality".to_owned(), Value::Object(reality));
    }
    node.insert("tls".to_owned(), Value::Object(tls));
}

fn tls_object(server_name: String, insecure: bool) -> Map<String, Value> {
    let mut tls = Map::new();
    tls.insert("enabled".to_owned(), Value::Bool(true));
    insert_string(&mut tls, "server_name", server_name);
    if insecure {
        tls.insert("insecure".to_owned(), Value::Bool(true));
    }
    tls
}

fn truthy(value: &str) -> bool {
    matches!(value, "1" | "true" | "yes")
}

fn first_query<'a>(query: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| query.get(*key).map(String::as_str))
}

fn insert_query_string(
    node: &mut Map<String, Value>,
    field: &str,
    query: &BTreeMap<String, String>,
    keys: &[&str],
) {
    if let Some(value) = first_query(query, keys).filter(|value| !value.is_empty()) {
        insert_string(node, field, value);
    }
}

fn insert_query_u64(
    node: &mut Map<String, Value>,
    field: &str,
    query: &BTreeMap<String, String>,
    keys: &[&str],
) -> Result<(), SubscriptionCompileError> {
    let Some(value) = first_query(query, keys).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let value = value.parse::<u64>().map_err(|_| {
        SubscriptionCompileError::InvalidShape("numeric subscription URI option is invalid")
    })?;
    node.insert(field.to_owned(), Value::from(value));
    Ok(())
}

fn query_pairs(query: &str) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn split_fragment(input: &str) -> (&str, Option<&str>) {
    input
        .split_once('#')
        .map_or((input, None), |(value, fragment)| (value, Some(fragment)))
}

fn percent_decode(
    input: &str,
    line_number: usize,
    protocol: &'static str,
) -> Result<String, SubscriptionCompileError> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(invalid_uri(
                line_number,
                protocol,
                "truncated percent escape",
            ));
        }
        let high = hex_value(bytes[index + 1])
            .ok_or_else(|| invalid_uri(line_number, protocol, "invalid percent escape"))?;
        let low = hex_value(bytes[index + 2])
            .ok_or_else(|| invalid_uri(line_number, protocol, "invalid percent escape"))?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded)
        .map_err(|_| invalid_uri(line_number, protocol, "percent-decoded text is not UTF-8"))
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn require_credential(
    value: &str,
    line_number: usize,
    protocol: &'static str,
    field: &'static str,
) -> Result<(), SubscriptionCompileError> {
    if value.is_empty() {
        Err(invalid_uri(line_number, protocol, field))
    } else {
        Ok(())
    }
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    detail: &'static str,
) -> Result<&'a str, SubscriptionCompileError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(SubscriptionCompileError::InvalidShape(detail))
}

fn json_scalar_text(object: &Map<String, Value>, field: &str) -> Option<String> {
    match object.get(field) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Number(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn json_u16(object: &Map<String, Value>, field: &str) -> Option<u16> {
    json_scalar_text(object, field)?
        .parse()
        .ok()
        .filter(|value| *value != 0)
}

fn json_u64(object: &Map<String, Value>, field: &str) -> Option<u64> {
    json_scalar_text(object, field)?.parse().ok()
}

fn insert_string(object: &mut Map<String, Value>, field: &str, value: impl Into<String>) {
    object.insert(field.to_owned(), Value::String(value.into()));
}

fn invalid_uri(
    line: usize,
    protocol: &'static str,
    detail: &'static str,
) -> SubscriptionCompileError {
    SubscriptionCompileError::InvalidUri {
        line,
        protocol,
        detail,
    }
}

fn resource_limit(
    resource: &'static str,
    actual: usize,
    maximum: usize,
) -> SubscriptionCompileError {
    SubscriptionCompileError::ResourceLimit {
        resource,
        actual,
        maximum,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEMPLATE: &[u8] = br#"{
        "outbounds": [
            {"type":"direct","tag":"DIRECT"},
            {"type":"selector","tag":"PROXY","outbounds":[]},
            {"type":"selector","tag":"HK","outbounds":[]}
        ],
        "route":{"rules":[]}
    }"#;
    const TEST_DECODED_LIMIT: u32 = 1_024 * 1_024;

    #[test]
    fn sing_box_json_is_filtered_named_and_merged_deterministically() {
        let source = br#"{
            "outbounds": [
                {"type":"direct","tag":"provider-direct"},
                {"type":"vless","tag":"  HK  One  ","server":"one.example","server_port":443,"uuid":"one","unused":null},
                {"type":"trojan","tag":"HK One","server":"two.example","server_port":443,"password":"two"},
                {"type":"vmess","tag":"traffic reset","server":"ignored.example","server_port":443,"uuid":"ignored"}
            ]
        }"#;
        let first = compile_subscription_template(SubscriptionCompileRequest::new(
            TEMPLATE,
            source,
            10,
            TEST_DECODED_LIMIT,
        ))
        .expect("valid subscription compiles");
        let second = compile_subscription_template(SubscriptionCompileRequest::new(
            TEMPLATE,
            source,
            10,
            TEST_DECODED_LIMIT,
        ))
        .expect("equal input compiles");
        assert_eq!(first, second);
        assert_eq!(first.node_count(), 2);
        assert_eq!(first.content_sha256(), &Sha256::digest(first.bytes())[..]);

        let value: Value = serde_json::from_slice(first.bytes()).expect("merged JSON parses");
        let outbounds = value["outbounds"].as_array().expect("outbounds array");
        let tags: Vec<_> = outbounds
            .iter()
            .filter_map(|outbound| outbound["tag"].as_str())
            .collect();
        assert!(tags.contains(&"HK One"));
        assert!(tags.contains(&"HK One #2"));
        assert!(!first.bytes().windows(4).any(|window| window == b"null"));
        assert_eq!(
            outbounds[1]["outbounds"],
            serde_json::json!(["HK One", "HK One #2"])
        );
        assert_eq!(
            outbounds[2]["outbounds"],
            serde_json::json!(["HK One", "HK One #2"])
        );
    }

    #[test]
    fn absent_region_leaf_is_pruned_from_its_parent() {
        let template = br#"{
            "outbounds": [
                {"type":"direct","tag":"DIRECT"},
                {"type":"selector","tag":"PROXY","outbounds":["HK","TW","US"]},
                {"type":"selector","tag":"GLOBAL","outbounds":["PROXY"]},
                {"type":"selector","tag":"HK","outbounds":[]},
                {"type":"selector","tag":"TW","outbounds":[]},
                {"type":"selector","tag":"US","outbounds":[]}
            ]
        }"#;
        let source = br#"[
            {"type":"vless","tag":"HK One","server":"hk.example","server_port":443,"uuid":"hk"},
            {"type":"vless","tag":"US One","server":"us.example","server_port":443,"uuid":"us"}
        ]"#;

        let artifact = compile_subscription_template(SubscriptionCompileRequest::new(
            template,
            source,
            10,
            TEST_DECODED_LIMIT,
        ))
        .expect("partially populated region graph compiles");
        let value: Value = serde_json::from_slice(artifact.bytes()).expect("merged JSON parses");
        let outbounds = value["outbounds"].as_array().expect("outbounds array");
        let tags: Vec<_> = outbounds
            .iter()
            .filter_map(|outbound| outbound["tag"].as_str())
            .collect();

        assert_eq!(outbound_members(outbounds, "PROXY"), &["HK", "US"]);
        assert_eq!(outbound_members(outbounds, "GLOBAL"), &["PROXY"]);
        assert_eq!(outbound_members(outbounds, "HK"), &["HK One"]);
        assert_eq!(outbound_members(outbounds, "US"), &["US One"]);
        assert!(!tags.contains(&"TW"));
    }

    #[test]
    fn empty_proxy_and_auto_roots_use_all_proxy_nodes_without_direct() {
        let template = br#"{
            "outbounds": [
                {"type":"direct","tag":"DIRECT"},
                {"type":"selector","tag":"PROXY","outbounds":["HK","TW"]},
                {"type":"urltest","tag":"AUTO","outbounds":["HK","TW"]},
                {"type":"selector","tag":"HK","outbounds":[]},
                {"type":"selector","tag":"TW","outbounds":[]}
            ]
        }"#;
        let source = br#"[
            {"type":"vless","tag":"Alpha","server":"alpha.example","server_port":443,"uuid":"alpha"},
            {"type":"vless","tag":"Beta","server":"beta.example","server_port":443,"uuid":"beta"}
        ]"#;

        let artifact = compile_subscription_template(SubscriptionCompileRequest::new(
            template,
            source,
            10,
            TEST_DECODED_LIMIT,
        ))
        .expect("unmatched regional roots compile through proxy nodes");
        let value: Value = serde_json::from_slice(artifact.bytes()).expect("merged JSON parses");
        let outbounds = value["outbounds"].as_array().expect("outbounds array");
        let expected = ["Alpha", "Beta"];

        assert_eq!(outbound_members(outbounds, "PROXY"), &expected);
        assert_eq!(outbound_members(outbounds, "AUTO"), &expected);
        assert!(!outbound_members(outbounds, "PROXY").contains(&"DIRECT"));
        assert!(!outbound_members(outbounds, "AUTO").contains(&"DIRECT"));
        assert!(
            outbounds
                .iter()
                .all(|outbound| { !matches!(outbound["tag"].as_str(), Some("HK" | "TW")) })
        );
    }

    #[test]
    fn dangling_and_unusable_selection_graphs_fail_closed() {
        for template in [
            br#"{"outbounds":[{"type":"selector","tag":"PROXY","outbounds":["MISSING"]}]}"#
                .as_slice(),
            br#"{"outbounds":[
                {"type":"selector","tag":"PROXY","outbounds":["LOOP"]},
                {"type":"selector","tag":"LOOP","outbounds":["PROXY"]}
            ]}"#
            .as_slice(),
            br#"{"outbounds":[
                {"type":"direct","tag":"DIRECT"},
                {"type":"selector","tag":"PROXY","outbounds":["DIRECT"]}
            ]}"#
            .as_slice(),
            br#"{"outbounds":[
                {"type":"direct","tag":"DIRECT"},
                {"type":"selector","tag":"GLOBAL","outbounds":[]}
            ]}"#
            .as_slice(),
            br#"{"outbounds":[
                {"type":"direct","tag":"DIRECT"},
                {"type":"selector","tag":"UNREVIEWED","outbounds":[]}
            ]}"#
            .as_slice(),
        ] {
            let error = compile_subscription_template(SubscriptionCompileRequest::new(
                template,
                br#"[{"type":"vless","tag":"Node","server":"node.example","server_port":443,"uuid":"node"}]"#,
                10,
                TEST_DECODED_LIMIT,
            ))
            .expect_err("invalid selection graph rejects before publication");
            assert_eq!(error.kind(), SubscriptionCompileErrorKind::InvalidShape);
        }
    }

    #[test]
    fn valid_nonempty_groups_keep_their_order_and_membership() {
        let template = br#"{
            "outbounds": [
                {"type":"selector","tag":"PROXY","outbounds":["MANUAL"]},
                {"type":"selector","tag":"MANUAL","outbounds":["Beta","Alpha"]}
            ]
        }"#;
        let source = br#"[
            {"type":"vless","tag":"Alpha","server":"alpha.example","server_port":443,"uuid":"alpha"},
            {"type":"vless","tag":"Beta","server":"beta.example","server_port":443,"uuid":"beta"}
        ]"#;

        let artifact = compile_subscription_template(SubscriptionCompileRequest::new(
            template,
            source,
            10,
            TEST_DECODED_LIMIT,
        ))
        .expect("valid custom selection graph compiles unchanged");
        let value: Value = serde_json::from_slice(artifact.bytes()).expect("merged JSON parses");
        let outbounds = value["outbounds"].as_array().expect("outbounds array");

        assert_eq!(outbound_members(outbounds, "PROXY"), &["MANUAL"]);
        assert_eq!(outbound_members(outbounds, "MANUAL"), &["Beta", "Alpha"]);
    }

    fn outbound_members<'a>(outbounds: &'a [Value], tag: &str) -> Vec<&'a str> {
        outbounds
            .iter()
            .find(|outbound| outbound["tag"] == tag)
            .expect("tagged outbound")
            .get("outbounds")
            .and_then(Value::as_array)
            .expect("outbound member array")
            .iter()
            .map(|member| member.as_str().expect("string outbound member"))
            .collect()
    }

    #[test]
    fn strict_base64_uri_list_supports_current_protocol_family() {
        let lines = concat!(
            "vless://11111111-1111-1111-1111-111111111111@v.example:443?security=tls&type=ws&path=%2Fws&host=edge.example#HK%20VLESS\n",
            "trojan://secret@t.example:443?sni=t.example#US%20Trojan\n",
            "hysteria2://pass@h.example:443?sni=h.example#JP%20H2\n",
            "tuic://22222222-2222-2222-2222-222222222222:pw@u.example:443?congestion_control=bbr#SG%20TUIC\n",
            "socks://user:pass@s.example:1080#SOCKS\n",
            "http://user:pass@p.example:8080#HTTP\n",
            "snell://psk@n.example:443?version=4#SNELL\n",
        );
        let encoded = STANDARD.encode(lines);
        let artifact = compile_subscription_template(SubscriptionCompileRequest::new(
            TEMPLATE,
            encoded.as_bytes(),
            20,
            TEST_DECODED_LIMIT,
        ))
        .expect("base64 URI list compiles");
        assert_eq!(artifact.node_count(), 7);
        let value: Value = serde_json::from_slice(artifact.bytes()).expect("merged JSON parses");
        let vless = value["outbounds"]
            .as_array()
            .expect("outbounds")
            .iter()
            .find(|node| node["tag"] == "HK VLESS")
            .expect("VLESS node");
        assert_eq!(vless["transport"]["path"], "/ws");
        assert_eq!(vless["tls"]["server_name"], "v.example");
    }

    #[test]
    fn vmess_and_shadowsocks_payloads_are_structurally_decoded() {
        let vmess = STANDARD.encode(
            br#"{"v":"2","ps":"HK VMess","add":"vm.example","port":"443","id":"33333333-3333-3333-3333-333333333333","aid":"0","scy":"auto","net":"ws","host":"edge.example","path":"/socket","tls":"tls","sni":"vm.example"}"#,
        );
        let ss_user = STANDARD_NO_PAD.encode("aes-128-gcm:secret");
        let source = format!("vmess://{vmess}\nss://{ss_user}@ss.example:8388#SG%20SS\n");
        let artifact = compile_subscription_template(SubscriptionCompileRequest::new(
            TEMPLATE,
            source.as_bytes(),
            10,
            TEST_DECODED_LIMIT,
        ))
        .expect("VMess and Shadowsocks compile");
        assert_eq!(artifact.node_count(), 2);
        let value: Value = serde_json::from_slice(artifact.bytes()).expect("merged JSON parses");
        let outbounds = value["outbounds"].as_array().expect("outbounds");
        assert!(outbounds.iter().any(|node| node["type"] == "vmess"));
        assert!(outbounds.iter().any(|node| node["type"] == "shadowsocks"));
    }

    #[test]
    fn limits_and_malformed_inputs_fail_closed() {
        let too_many = br#"[
            {"type":"vless","tag":"one"},
            {"type":"vless","tag":"two"}
        ]"#;
        let error = compile_subscription_template(SubscriptionCompileRequest::new(
            TEMPLATE,
            too_many,
            1,
            TEST_DECODED_LIMIT,
        ))
        .expect_err("node overflow fails");
        assert_eq!(error.kind(), SubscriptionCompileErrorKind::ResourceLimit);

        let error = compile_subscription_template(SubscriptionCompileRequest::new(
            TEMPLATE,
            b"vless://missing-host",
            10,
            TEST_DECODED_LIMIT,
        ))
        .expect_err("malformed URI fails");
        assert_eq!(error.kind(), SubscriptionCompileErrorKind::InvalidUri);

        let error = compile_subscription_template(SubscriptionCompileRequest::new(
            TEMPLATE,
            b"ftp://example.invalid/node",
            10,
            TEST_DECODED_LIMIT,
        ))
        .expect_err("unsupported protocol fails");
        assert_eq!(
            error.kind(),
            SubscriptionCompileErrorKind::UnsupportedProtocol
        );

        let encoded = STANDARD.encode("vless://id@provider.example:443#node");
        let error = compile_subscription_template(SubscriptionCompileRequest::new(
            TEMPLATE,
            encoded.as_bytes(),
            10,
            8,
        ))
        .expect_err("decoded source overflow fails");
        assert_eq!(error.kind(), SubscriptionCompileErrorKind::ResourceLimit);
    }

    #[test]
    fn deeply_nested_json_and_empty_filtered_input_fail_closed() {
        let mut nested = String::from("{\"type\":\"vless\",\"tag\":\"node\",\"x\":");
        for _ in 0..=MAX_JSON_DEPTH {
            nested.push('[');
        }
        nested.push_str("null");
        for _ in 0..=MAX_JSON_DEPTH {
            nested.push(']');
        }
        nested.push('}');
        let source = format!("[{nested}]");
        let error = compile_subscription_template(SubscriptionCompileRequest::new(
            TEMPLATE,
            source.as_bytes(),
            10,
            TEST_DECODED_LIMIT,
        ))
        .expect_err("deep JSON fails");
        assert_eq!(error.kind(), SubscriptionCompileErrorKind::ResourceLimit);

        let error = compile_subscription_template(SubscriptionCompileRequest::new(
            TEMPLATE,
            br#"[{"type":"direct","tag":"DIRECT"}]"#,
            10,
            TEST_DECODED_LIMIT,
        ))
        .expect_err("infrastructure-only input fails");
        assert_eq!(error.kind(), SubscriptionCompileErrorKind::NoUsableNodes);
    }
}
