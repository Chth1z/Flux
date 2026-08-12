use std::error::Error;
use std::fmt;
use std::io::{self, Read as _};
use std::time::Duration;

use sha2::{Digest, Sha256};
use ureq::config::RedirectAuthHeaders;
use ureq::http::header::{CONTENT_ENCODING, CONTENT_TYPE};
use ureq::http::{HeaderMap, Response};
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
use ureq::{Agent, Body};
use url::Url;

const FETCH_USER_AGENT: &str = concat!("Flux/", env!("CARGO_PKG_VERSION"), " (Android; Rust)");
// The reviewed provider returns a complete Sing-Box JSON document for this token. Keep that
// compatibility identity scoped to subscription requests; binary rule-set downloads retain
// Flux's own identity.
const SUBSCRIPTION_USER_AGENT: &str = "sing-box";
const MAX_REDIRECTS: u32 = 5;
const MAX_FETCH_BYTES: u64 = 64 * 1_024 * 1_024;
const MAX_FETCH_URL_BYTES: usize = 4_096;
const MAX_RESPONSE_HEADER_BYTES: usize = 32 * 1_024;
const INITIAL_BODY_CAPACITY: u64 = 64 * 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FetchPurpose {
    Subscription,
    BinaryRuleSet,
}

impl FetchPurpose {
    const fn accept(self) -> &'static str {
        match self {
            Self::Subscription => {
                "application/json, text/plain, application/octet-stream, application/x-subscription"
            }
            Self::BinaryRuleSet => {
                "application/octet-stream, application/vnd.sing-box.ruleset, application/x-binary"
            }
        }
    }

    const fn user_agent(self) -> &'static str {
        match self {
            Self::Subscription => SUBSCRIPTION_USER_AGENT,
            Self::BinaryRuleSet => FETCH_USER_AGENT,
        }
    }

    fn accepts_mime(self, mime: &str) -> bool {
        match self {
            Self::Subscription => matches!(
                mime,
                "application/json"
                    | "text/json"
                    | "text/plain"
                    | "application/octet-stream"
                    | "application/base64"
                    | "application/x-subscription"
            ),
            Self::BinaryRuleSet => matches!(
                mime,
                "application/octet-stream"
                    | "application/vnd.sing-box.ruleset"
                    | "application/x-binary"
                    | "application/force-download"
            ),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct FetchRequest<'a> {
    url: &'a Url,
    timeout: Duration,
    maximum_encoded_bytes: u64,
    maximum_decoded_bytes: u64,
    purpose: FetchPurpose,
}

impl fmt::Debug for FetchRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchRequest")
            .field("url", &"<redacted>")
            .field("timeout", &self.timeout)
            .field("maximum_encoded_bytes", &self.maximum_encoded_bytes)
            .field("maximum_decoded_bytes", &self.maximum_decoded_bytes)
            .field("purpose", &self.purpose)
            .finish()
    }
}

impl<'a> FetchRequest<'a> {
    pub(super) const fn new(
        url: &'a Url,
        timeout: Duration,
        maximum_encoded_bytes: u64,
        maximum_decoded_bytes: u64,
        purpose: FetchPurpose,
    ) -> Self {
        Self {
            url,
            timeout,
            maximum_encoded_bytes,
            maximum_decoded_bytes,
            purpose,
        }
    }

    #[cfg(test)]
    pub(super) const fn url(self) -> &'a Url {
        self.url
    }

    #[cfg(test)]
    pub(super) const fn purpose(self) -> FetchPurpose {
        self.purpose
    }

    #[cfg(test)]
    pub(super) const fn maximum_encoded_bytes(self) -> u64 {
        self.maximum_encoded_bytes
    }

    #[cfg(test)]
    pub(super) const fn maximum_decoded_bytes(self) -> u64 {
        self.maximum_decoded_bytes
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct FetchedResource {
    bytes: Box<[u8]>,
    content_sha256: [u8; 32],
}

impl fmt::Debug for FetchedResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchedResource")
            .field("byte_len", &self.bytes.len())
            .field("content_sha256", &hex_digest(&self.content_sha256))
            .finish()
    }
}

impl FetchedResource {
    pub(super) fn from_bytes(bytes: Vec<u8>) -> Self {
        let content_sha256 = Sha256::digest(&bytes).into();
        Self {
            bytes: bytes.into_boxed_slice(),
            content_sha256,
        }
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) const fn content_sha256(&self) -> &[u8; 32] {
        &self.content_sha256
    }
}

pub(super) trait FetchAdapter {
    fn fetch(&self, request: FetchRequest<'_>) -> Result<FetchedResource, FetchError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct UreqFetchAdapter;

impl FetchAdapter for UreqFetchAdapter {
    fn fetch(&self, request: FetchRequest<'_>) -> Result<FetchedResource, FetchError> {
        validate_request(request)?;
        let agent = build_agent(request.timeout, request.purpose);
        let mut response = agent
            .get(request.url.as_str())
            .header("accept", request.purpose.accept())
            .call()
            .map_err(FetchError::from_transport)?;
        read_response(&mut response, request)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FetchErrorKind {
    InvalidPolicy,
    InsecureUrl,
    UrlCredentials,
    UrlFragment,
    UrlTooLong,
    NonDefaultPort,
    HttpStatus(u16),
    Timeout,
    Redirect,
    Transport,
    InvalidContentType,
    InvalidContentEncoding,
    EncodedBodyTooLarge,
    DecodedBodyTooLarge,
    EmptyBody,
    BodyRead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransportFailure {
    InvalidRequest,
    Protocol,
    Io,
    NameResolution,
    Tls,
    ResponseHeaders,
    Decompression,
    Other,
}

impl fmt::Display for TransportFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "request construction",
            Self::Protocol => "HTTP protocol handling",
            Self::Io => "network I/O",
            Self::NameResolution => "name resolution",
            Self::Tls => "TLS",
            Self::ResponseHeaders => "response header processing",
            Self::Decompression => "response decompression",
            Self::Other => "transport processing",
        })
    }
}

#[derive(Debug)]
pub(super) enum FetchError {
    InvalidPolicy(&'static str),
    InsecureUrl,
    UrlCredentials,
    UrlFragment,
    UrlTooLong { actual: usize, maximum: usize },
    NonDefaultPort,
    HttpStatus(u16),
    Timeout,
    Redirect,
    Transport(TransportFailure),
    InvalidContentType,
    InvalidContentEncoding,
    EncodedBodyTooLarge { maximum: u64 },
    DecodedBodyTooLarge { maximum: u64 },
    EmptyBody,
    BodyRead,
}

impl FetchError {
    fn from_transport(source: ureq::Error) -> Self {
        match source {
            ureq::Error::StatusCode(status) => Self::HttpStatus(status),
            ureq::Error::Timeout(_) => Self::Timeout,
            ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => Self::Redirect,
            ureq::Error::Http(_)
            | ureq::Error::BadUri(_)
            | ureq::Error::RequireHttpsOnly(_)
            | ureq::Error::InvalidProxyUrl => Self::Transport(TransportFailure::InvalidRequest),
            ureq::Error::Protocol(_) | ureq::Error::BodyStalled => {
                Self::Transport(TransportFailure::Protocol)
            }
            ureq::Error::Io(_)
            | ureq::Error::ConnectionFailed
            | ureq::Error::ConnectProxyFailed(_) => Self::Transport(TransportFailure::Io),
            ureq::Error::HostNotFound => Self::Transport(TransportFailure::NameResolution),
            ureq::Error::Tls(_)
            | ureq::Error::Pem(_)
            | ureq::Error::Rustls(_)
            | ureq::Error::TlsRequired => Self::Transport(TransportFailure::Tls),
            ureq::Error::LargeResponseHeader(_, _) => {
                Self::Transport(TransportFailure::ResponseHeaders)
            }
            ureq::Error::Decompress(_, _) => Self::Transport(TransportFailure::Decompression),
            _ => Self::Transport(TransportFailure::Other),
        }
    }

    #[cfg(test)]
    pub(super) fn kind(&self) -> FetchErrorKind {
        match self {
            Self::InvalidPolicy(_) => FetchErrorKind::InvalidPolicy,
            Self::InsecureUrl => FetchErrorKind::InsecureUrl,
            Self::UrlCredentials => FetchErrorKind::UrlCredentials,
            Self::UrlFragment => FetchErrorKind::UrlFragment,
            Self::UrlTooLong { .. } => FetchErrorKind::UrlTooLong,
            Self::NonDefaultPort => FetchErrorKind::NonDefaultPort,
            Self::HttpStatus(status) => FetchErrorKind::HttpStatus(*status),
            Self::Timeout => FetchErrorKind::Timeout,
            Self::Redirect => FetchErrorKind::Redirect,
            Self::Transport(_) => FetchErrorKind::Transport,
            Self::InvalidContentType => FetchErrorKind::InvalidContentType,
            Self::InvalidContentEncoding => FetchErrorKind::InvalidContentEncoding,
            Self::EncodedBodyTooLarge { .. } => FetchErrorKind::EncodedBodyTooLarge,
            Self::DecodedBodyTooLarge { .. } => FetchErrorKind::DecodedBodyTooLarge,
            Self::EmptyBody => FetchErrorKind::EmptyBody,
            Self::BodyRead => FetchErrorKind::BodyRead,
        }
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(detail) => write!(formatter, "invalid fetch policy: {detail}"),
            Self::InsecureUrl => formatter.write_str("fetch URL must use HTTPS"),
            Self::UrlCredentials => {
                formatter.write_str("fetch URL must not contain user information")
            }
            Self::UrlFragment => formatter.write_str("fetch URL must not contain a fragment"),
            Self::UrlTooLong { actual, maximum } => write!(
                formatter,
                "fetch URL uses {actual} bytes, exceeding the limit of {maximum}"
            ),
            Self::NonDefaultPort => {
                formatter.write_str("fetch URL must use the default HTTPS port")
            }
            Self::HttpStatus(status) => {
                write!(formatter, "HTTPS fetch returned HTTP status {status}")
            }
            Self::Timeout => formatter.write_str("HTTPS fetch timed out"),
            Self::Redirect => formatter.write_str("HTTPS redirect policy rejected the response"),
            Self::Transport(failure) => write!(formatter, "HTTPS fetch failed during {failure}"),
            Self::InvalidContentType => formatter.write_str("response content type is not allowed"),
            Self::InvalidContentEncoding => {
                formatter.write_str("response content encoding is not allowed")
            }
            Self::EncodedBodyTooLarge { maximum } => write!(
                formatter,
                "encoded response body exceeds the {maximum}-byte limit"
            ),
            Self::DecodedBodyTooLarge { maximum } => write!(
                formatter,
                "decoded response body exceeds the {maximum}-byte limit"
            ),
            Self::EmptyBody => formatter.write_str("response body is empty"),
            Self::BodyRead => formatter.write_str("cannot read response body"),
        }
    }
}

impl Error for FetchError {}

pub(super) fn validate_request(request: FetchRequest<'_>) -> Result<(), FetchError> {
    if request.timeout.is_zero() {
        return Err(FetchError::InvalidPolicy("timeout must be nonzero"));
    }
    if request.maximum_encoded_bytes == 0 || request.maximum_encoded_bytes > MAX_FETCH_BYTES {
        return Err(FetchError::InvalidPolicy(
            "encoded byte limit is outside the supported range",
        ));
    }
    if request.maximum_decoded_bytes == 0 || request.maximum_decoded_bytes > MAX_FETCH_BYTES {
        return Err(FetchError::InvalidPolicy(
            "decoded byte limit is outside the supported range",
        ));
    }
    if request.url.scheme() != "https" || request.url.host_str().is_none() {
        return Err(FetchError::InsecureUrl);
    }
    if !request.url.username().is_empty() || request.url.password().is_some() {
        return Err(FetchError::UrlCredentials);
    }
    if request.url.fragment().is_some() {
        return Err(FetchError::UrlFragment);
    }
    let url_bytes = request.url.as_str().len();
    if url_bytes > MAX_FETCH_URL_BYTES {
        return Err(FetchError::UrlTooLong {
            actual: url_bytes,
            maximum: MAX_FETCH_URL_BYTES,
        });
    }
    if request.url.port_or_known_default() != Some(443) {
        return Err(FetchError::NonDefaultPort);
    }
    Ok(())
}

fn build_agent(timeout: Duration, purpose: FetchPurpose) -> Agent {
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .root_certs(RootCerts::WebPki)
        .build();
    Agent::config_builder()
        .http_status_as_error(true)
        .https_only(true)
        .tls_config(tls)
        .proxy(None)
        .max_redirects(MAX_REDIRECTS)
        .max_redirects_will_error(true)
        .redirect_auth_headers(RedirectAuthHeaders::Never)
        .user_agent(purpose.user_agent())
        .accept_encoding("gzip, br")
        .timeout_global(Some(timeout))
        .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
        .max_idle_connections(0)
        .build()
        .new_agent()
}

fn read_response(
    response: &mut Response<Body>,
    request: FetchRequest<'_>,
) -> Result<FetchedResource, FetchError> {
    let status = response.status().as_u16();
    if !response.status().is_success() {
        return Err(FetchError::HttpStatus(status));
    }
    validate_response_encoding(response.headers())?;

    // ureq places its limit around the raw reader before content decoding. Flux independently
    // caps the decoded reader so a compressed body cannot evade either resource budget.
    let encoded_read_limit = request.maximum_encoded_bytes.saturating_add(1);
    let decoded_read_limit = request.maximum_decoded_bytes.saturating_add(1);
    let reader = response
        .body_mut()
        .with_config()
        .limit(encoded_read_limit)
        .reader();
    let mut reader = reader.take(decoded_read_limit);
    let capacity = usize::try_from(request.maximum_decoded_bytes.min(INITIAL_BODY_CAPACITY))
        .map_err(|_| FetchError::InvalidPolicy("decoded limit does not fit this target"))?;
    let mut bytes = Vec::with_capacity(capacity);
    if let Err(source) = reader.read_to_end(&mut bytes) {
        return if body_limit_error(&source) {
            Err(FetchError::EncodedBodyTooLarge {
                maximum: request.maximum_encoded_bytes,
            })
        } else {
            Err(FetchError::BodyRead)
        };
    }
    if u64::try_from(bytes.len()).map_or(true, |actual| actual > request.maximum_decoded_bytes) {
        return Err(FetchError::DecodedBodyTooLarge {
            maximum: request.maximum_decoded_bytes,
        });
    }
    validate_response_content_type(response.headers(), request.purpose, Some(&bytes))?;
    if bytes.is_empty() {
        return Err(FetchError::EmptyBody);
    }
    Ok(FetchedResource::from_bytes(bytes))
}

#[cfg(test)]
fn validate_response_headers(headers: &HeaderMap, purpose: FetchPurpose) -> Result<(), FetchError> {
    validate_response_encoding(headers)?;
    validate_response_content_type(headers, purpose, None)
}

#[cfg(test)]
fn validate_response_headers_with_body(
    headers: &HeaderMap,
    purpose: FetchPurpose,
    body: &[u8],
) -> Result<(), FetchError> {
    validate_response_encoding(headers)?;
    validate_response_content_type(headers, purpose, Some(body))
}

fn validate_response_encoding(headers: &HeaderMap) -> Result<(), FetchError> {
    for value in headers.get_all(CONTENT_ENCODING) {
        let value = value
            .to_str()
            .map_err(|_| FetchError::InvalidContentEncoding)?;
        if !value.trim().eq_ignore_ascii_case("identity") {
            return Err(FetchError::InvalidContentEncoding);
        }
    }
    Ok(())
}

fn validate_response_content_type(
    headers: &HeaderMap,
    purpose: FetchPurpose,
    body: Option<&[u8]>,
) -> Result<(), FetchError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(FetchError::InvalidContentType);
    }
    let value = value.to_str().map_err(|_| FetchError::InvalidContentType)?;
    let mime = value
        .split_once(';')
        .map_or(value, |(mime, _)| mime)
        .trim()
        .to_ascii_lowercase();
    let legacy_subscription_body = matches!(purpose, FetchPurpose::Subscription)
        && mime == "text/html"
        && body.is_some_and(|value| !looks_like_html_body(value));
    if mime.is_empty() || (!purpose.accepts_mime(&mime) && !legacy_subscription_body) {
        return Err(FetchError::InvalidContentType);
    }
    Ok(())
}

fn looks_like_html_body(body: &[u8]) -> bool {
    std::str::from_utf8(body)
        .map(str::trim_start)
        .is_ok_and(|text| text.starts_with('<'))
}

fn body_limit_error(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ureq::Error>())
        .is_some_and(|source| matches!(source, ureq::Error::BodyExceedsLimit(_)))
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
    use super::*;

    fn request<'a>(url: &'a Url, encoded: u64, decoded: u64) -> FetchRequest<'a> {
        FetchRequest::new(
            url,
            Duration::from_secs(7),
            encoded,
            decoded,
            FetchPurpose::Subscription,
        )
    }

    fn response(body: impl Into<Vec<u8>>, content_type: Option<&str>) -> Response<Body> {
        let mut builder = Response::builder().status(200);
        if let Some(content_type) = content_type {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        builder
            .body(Body::builder().data(body))
            .expect("valid test response")
    }

    #[test]
    fn subscription_agent_uses_reviewed_sing_box_identity() {
        let agent = build_agent(Duration::from_secs(11), FetchPurpose::Subscription);
        let user_agent = match agent.config().user_agent() {
            ureq::config::AutoHeaderValue::Provided(value) => value.as_str(),
            value => panic!("subscription User-Agent must be explicit, got {value:?}"),
        };
        assert_eq!(user_agent, "sing-box");
        assert!(!user_agent.contains("Flux/"));
    }

    #[test]
    fn production_agent_is_https_only_proxy_free_and_globally_bounded() {
        let timeout = Duration::from_secs(11);
        let agent = build_agent(timeout, FetchPurpose::BinaryRuleSet);
        let config = agent.config();

        assert!(config.https_only());
        assert!(config.proxy().is_none());
        assert_eq!(config.max_redirects(), MAX_REDIRECTS);
        assert!(config.max_redirects_will_error());
        assert_eq!(config.redirect_auth_headers(), RedirectAuthHeaders::Never);
        assert_eq!(config.timeouts().global, Some(timeout));
        assert_eq!(config.max_response_header_size(), MAX_RESPONSE_HEADER_BYTES);
        assert_eq!(config.tls_config().provider(), TlsProvider::Rustls);
        assert!(matches!(
            config.tls_config().root_certs(),
            RootCerts::WebPki
        ));
        assert!(!config.tls_config().disable_verification());
        assert!(matches!(
            config.user_agent(),
            ureq::config::AutoHeaderValue::Provided(value) if value.as_str() == FETCH_USER_AGENT
        ));
    }

    #[test]
    fn request_policy_rejects_insecure_credentialed_fragmented_or_unbounded_urls() {
        let http = Url::parse("http://provider.example/sub").unwrap();
        assert_eq!(
            validate_request(request(&http, 10, 10)).unwrap_err().kind(),
            FetchErrorKind::InsecureUrl
        );

        let credentialed = Url::parse("https://user:secret@provider.example/sub").unwrap();
        assert_eq!(
            validate_request(request(&credentialed, 10, 10))
                .unwrap_err()
                .kind(),
            FetchErrorKind::UrlCredentials
        );

        let fragmented = Url::parse("https://provider.example/sub#token").unwrap();
        assert_eq!(
            validate_request(request(&fragmented, 10, 10))
                .unwrap_err()
                .kind(),
            FetchErrorKind::UrlFragment
        );

        let valid = Url::parse("https://provider.example/sub?token=secret").unwrap();
        assert_eq!(
            validate_request(request(&valid, 0, 10)).unwrap_err().kind(),
            FetchErrorKind::InvalidPolicy
        );
        assert!(validate_request(request(&valid, 10, 10)).is_ok());

        let non_default_port = Url::parse("https://provider.example:8443/sub").unwrap();
        assert_eq!(
            validate_request(request(&non_default_port, 10, 10))
                .unwrap_err()
                .kind(),
            FetchErrorKind::NonDefaultPort
        );

        let long_url = Url::parse(&format!(
            "https://provider.example/{}",
            "x".repeat(MAX_FETCH_URL_BYTES)
        ))
        .unwrap();
        assert_eq!(
            validate_request(request(&long_url, 10, 10))
                .unwrap_err()
                .kind(),
            FetchErrorKind::UrlTooLong
        );

        let debug = format!("{:?}", request(&valid, 10, 10));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("provider.example"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn response_policy_accepts_subscription_types_and_rejects_html_or_unknown_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            "application/json; charset=utf-8".parse().unwrap(),
        );
        assert!(validate_response_headers(&headers, FetchPurpose::Subscription).is_ok());

        headers.insert(CONTENT_TYPE, "text/html".parse().unwrap());
        assert_eq!(
            validate_response_headers(&headers, FetchPurpose::Subscription)
                .unwrap_err()
                .kind(),
            FetchErrorKind::InvalidContentType
        );

        headers.remove(CONTENT_TYPE);
        headers.insert(CONTENT_ENCODING, "zstd".parse().unwrap());
        assert_eq!(
            validate_response_headers(&headers, FetchPurpose::Subscription)
                .unwrap_err()
                .kind(),
            FetchErrorKind::InvalidContentEncoding
        );
    }

    #[test]
    fn legacy_html_mime_is_allowed_only_for_non_html_subscription_payloads() {
        let url = Url::parse("https://provider.example/sub").unwrap();
        let base64_uri = b"dmxlc3M6Ly9leGFtcGxl";
        let mut legacy = response(base64_uri.to_vec(), Some("text/html; charset=UTF-8"));
        assert_eq!(
            read_response(&mut legacy, request(&url, 64, 64))
                .unwrap()
                .bytes(),
            base64_uri
        );

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "text/html; charset=UTF-8".parse().unwrap());
        assert_eq!(
            validate_response_headers_with_body(
                &headers,
                FetchPurpose::Subscription,
                b"<!doctype html><html>login</html>"
            )
            .unwrap_err()
            .kind(),
            FetchErrorKind::InvalidContentType
        );
    }

    #[test]
    fn terminal_non_success_status_and_transport_details_are_redacted() {
        let url = Url::parse("https://provider.example/sub?token=secret").unwrap();
        let mut not_modified = Response::builder()
            .status(304)
            .body(Body::builder().data(b"cached".to_vec()))
            .unwrap();
        assert_eq!(
            read_response(&mut not_modified, request(&url, 64, 64))
                .unwrap_err()
                .kind(),
            FetchErrorKind::HttpStatus(304)
        );

        let error = FetchError::from_transport(ureq::Error::BadUri(
            "https://provider.example/sub?token=secret".to_owned(),
        ));
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert_eq!(error.kind(), FetchErrorKind::Transport);
        assert!(!display.contains("provider.example"));
        assert!(!display.contains("secret"));
        assert!(!debug.contains("provider.example"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn raw_and_decoded_body_limits_are_independent() {
        let url = Url::parse("https://provider.example/sub").unwrap();
        let mut raw_limited = response(b"12345".to_vec(), Some("text/plain"));
        assert_eq!(
            read_response(&mut raw_limited, request(&url, 4, 10))
                .unwrap_err()
                .kind(),
            FetchErrorKind::EncodedBodyTooLarge
        );

        let mut decoded_limited = response(b"12345".to_vec(), Some("text/plain"));
        assert_eq!(
            read_response(&mut decoded_limited, request(&url, 10, 4))
                .unwrap_err()
                .kind(),
            FetchErrorKind::DecodedBodyTooLarge
        );
    }

    #[test]
    fn bounded_response_has_a_stable_content_digest_and_empty_bodies_fail() {
        let url = Url::parse("https://provider.example/sub").unwrap();
        let mut valid = response(b"payload".to_vec(), None);
        let fetched = read_response(&mut valid, request(&url, 64, 64)).unwrap();
        assert_eq!(fetched.bytes(), b"payload");
        assert_eq!(fetched.content_sha256(), &Sha256::digest(b"payload")[..]);

        let mut empty = response(Vec::new(), Some("application/octet-stream"));
        assert_eq!(
            read_response(&mut empty, request(&url, 64, 64))
                .unwrap_err()
                .kind(),
            FetchErrorKind::EmptyBody
        );
    }
}
