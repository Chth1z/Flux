use std::error::Error;
use std::fmt;
use std::net::IpAddr;

use flux_core::{
    AddressHostFamilySelection, AndroidUserSelection, CaptureApplicationMode,
    CaptureInterfaceSelector, CaptureInterfaceSelectorKind, CaptureIpPrefix, CaptureTrafficDomain,
    CaptureTransportProtocol, FluxConfig, NetworkAddressFamily,
};
use serde_json::Value;

use super::EngineConfigArtifact;

pub(crate) const BRIDGE_ENVIRONMENT_SCHEMA_VERSION: u16 = 1;
pub(crate) const MAX_BRIDGE_ENVIRONMENT_BYTES: usize = 128 * 1024;
const MAX_LEGACY_INTERFACE_ROLES: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BridgeEnvironmentArtifact {
    bytes: Box<[u8]>,
}

impl BridgeEnvironmentArtifact {
    #[must_use]
    pub(crate) const fn schema_version(&self) -> u16 {
        BRIDGE_ENVIRONMENT_SCHEMA_VERSION
    }

    #[must_use]
    pub(crate) const fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BridgeEnvironmentCompileErrorKind {
    UnsupportedTrafficDomains,
    UnsupportedAddressFamilies,
    UnsupportedProtocols,
    ConfiguredBypassUnsupported,
    SubscriptionUnsupported,
    SubscriptionRequired,
    AndroidVpnUnsupported,
    FunctionalCanaryUnsupported,
    TooManyInterfaceRoles { actual: usize, maximum: usize },
    UnsafeInterfaceSelector,
    UnsafeEngineBinary,
    InvalidEngineArtifact,
    MissingFakeIpServer,
    MultipleFakeIpServers,
    InvalidFakeIpRange { family: NetworkAddressFamily },
    UnsafeValue,
    OutputTooLarge { actual: usize, maximum: usize },
}

#[derive(Debug)]
pub(crate) struct BridgeEnvironmentCompileError {
    kind: BridgeEnvironmentCompileErrorKind,
    source: Option<serde_json::Error>,
}

impl BridgeEnvironmentCompileError {
    #[must_use]
    pub(crate) const fn kind(&self) -> BridgeEnvironmentCompileErrorKind {
        self.kind
    }

    const fn new(kind: BridgeEnvironmentCompileErrorKind) -> Self {
        Self { kind, source: None }
    }

    const fn with_source(
        kind: BridgeEnvironmentCompileErrorKind,
        source: serde_json::Error,
    ) -> Self {
        Self {
            kind,
            source: Some(source),
        }
    }
}

impl fmt::Display for BridgeEnvironmentCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            BridgeEnvironmentCompileErrorKind::UnsupportedTrafficDomains => formatter.write_str(
                "the fenced shell bridge requires both local-output and forwarded-ingress capture",
            ),
            BridgeEnvironmentCompileErrorKind::UnsupportedAddressFamilies => formatter.write_str(
                "the fenced shell bridge requires IPv4 and can only add IPv6 to that baseline",
            ),
            BridgeEnvironmentCompileErrorKind::UnsupportedProtocols => formatter.write_str(
                "the fenced shell bridge requires both TCP and UDP capture",
            ),
            BridgeEnvironmentCompileErrorKind::ConfiguredBypassUnsupported => formatter.write_str(
                "configured bypass CIDRs cannot be represented by the fenced shell bridge",
            ),
            BridgeEnvironmentCompileErrorKind::SubscriptionUnsupported => formatter.write_str(
                "Rust-owned subscription retrieval is not connected to the fenced shell bridge",
            ),
            BridgeEnvironmentCompileErrorKind::SubscriptionRequired => formatter.write_str(
                "validated subscription bridge preparation requires enabled subscription intent",
            ),
            BridgeEnvironmentCompileErrorKind::AndroidVpnUnsupported => formatter.write_str(
                "Android VPN-aware egress is not qualified by the fenced shell bridge",
            ),
            BridgeEnvironmentCompileErrorKind::FunctionalCanaryUnsupported => formatter.write_str(
                "the fenced shell bridge cannot satisfy mandatory functional-canary intent",
            ),
            BridgeEnvironmentCompileErrorKind::TooManyInterfaceRoles { actual, maximum } => write!(
                formatter,
                "Desired State requires {actual} forwarded/local interface roles but the fenced shell bridge supports at most {maximum}"
            ),
            BridgeEnvironmentCompileErrorKind::UnsafeInterfaceSelector => formatter.write_str(
                "a Desired State interface selector is not representable by the fenced shell renderer",
            ),
            BridgeEnvironmentCompileErrorKind::UnsafeEngineBinary => formatter.write_str(
                "the configured engine binary path is not representable by the fenced shell manifest",
            ),
            BridgeEnvironmentCompileErrorKind::InvalidEngineArtifact => match &self.source {
                Some(source) => write!(
                    formatter,
                    "the canonical engine artifact cannot be decoded for bridge inputs: {source}"
                ),
                None => formatter
                    .write_str("the canonical engine artifact has an unsupported JSON shape"),
            },
            BridgeEnvironmentCompileErrorKind::MissingFakeIpServer => formatter.write_str(
                "the canonical engine artifact must contain exactly one FakeIP DNS server",
            ),
            BridgeEnvironmentCompileErrorKind::MultipleFakeIpServers => formatter.write_str(
                "the canonical engine artifact contains multiple FakeIP DNS servers",
            ),
            BridgeEnvironmentCompileErrorKind::InvalidFakeIpRange { family } => write!(
                formatter,
                "the canonical engine artifact contains an invalid or non-canonical {family:?} FakeIP range"
            ),
            BridgeEnvironmentCompileErrorKind::UnsafeValue => formatter.write_str(
                "a compiled bridge value cannot be represented as a bounded shell literal",
            ),
            BridgeEnvironmentCompileErrorKind::OutputTooLarge { actual, maximum } => write!(
                formatter,
                "compiled bridge environment is {actual} bytes, exceeding its {maximum}-byte limit"
            ),
        }
    }
}

impl Error for BridgeEnvironmentCompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// Compile the only product-intent input accepted by the temporary shell networking writer.
pub(crate) fn compile_bridge_environment(
    desired_state: &FluxConfig,
    engine_config: &EngineConfigArtifact,
) -> Result<BridgeEnvironmentArtifact, BridgeEnvironmentCompileError> {
    compile_bridge_environment_for_mode(
        desired_state,
        engine_config,
        BridgeSubscriptionMode::Template,
    )
}

pub(super) fn compile_validated_subscription_bridge_environment(
    desired_state: &FluxConfig,
    engine_config: &EngineConfigArtifact,
) -> Result<BridgeEnvironmentArtifact, BridgeEnvironmentCompileError> {
    compile_bridge_environment_for_mode(
        desired_state,
        engine_config,
        BridgeSubscriptionMode::ValidatedSubscription,
    )
}

#[derive(Clone, Copy)]
enum BridgeSubscriptionMode {
    Template,
    ValidatedSubscription,
}

fn compile_bridge_environment_for_mode(
    desired_state: &FluxConfig,
    engine_config: &EngineConfigArtifact,
    subscription_mode: BridgeSubscriptionMode,
) -> Result<BridgeEnvironmentArtifact, BridgeEnvironmentCompileError> {
    require_exact_bridge_shape(desired_state, subscription_mode)?;
    let (fake_ip_v4, fake_ip_v6) = extract_fake_ip_ranges(engine_config.bytes())?;
    let engine_binary = desired_state.engine().binary().to_str().ok_or_else(|| {
        BridgeEnvironmentCompileError::new(BridgeEnvironmentCompileErrorKind::UnsafeEngineBinary)
    })?;
    if !is_manifest_safe_value(engine_binary) {
        return Err(BridgeEnvironmentCompileError::new(
            BridgeEnvironmentCompileErrorKind::UnsafeEngineBinary,
        ));
    }

    let interfaces = desired_state.interfaces().policy();
    let mut roles = interfaces
        .forwarded_proxy()
        .iter()
        .copied()
        .map(|selector| bridge_interface(selector).map(|value| (value, true)))
        .chain(
            interfaces
                .local_bypass()
                .iter()
                .copied()
                .map(|selector| bridge_interface(selector).map(|value| (value, false))),
        )
        .collect::<Result<Vec<_>, _>>()?;
    let role_count = roles.len();
    if role_count > MAX_LEGACY_INTERFACE_ROLES {
        return Err(BridgeEnvironmentCompileError::new(
            BridgeEnvironmentCompileErrorKind::TooManyInterfaceRoles {
                actual: role_count,
                maximum: MAX_LEGACY_INTERFACE_ROLES,
            },
        ));
    }
    roles.resize_with(MAX_LEGACY_INTERFACE_ROLES, || (String::new(), false));
    let excluded = interfaces
        .excluded()
        .iter()
        .copied()
        .map(bridge_interface)
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");

    let credentials = desired_state.engine().credentials();
    let startup_timeout_ms = desired_state.engine().startup_timeout().as_millis();
    let stop_timeout_ms = desired_state.engine().stop_timeout().as_millis();
    let compatibility_timeout_seconds = startup_timeout_ms.max(stop_timeout_ms).div_ceil(1_000);
    let applications = desired_state.applications();
    let application_mode = match applications.mode() {
        CaptureApplicationMode::All => "0",
        CaptureApplicationMode::Denylist => "1",
        CaptureApplicationMode::Allowlist => "2",
    };
    let package_list = applications
        .packages()
        .iter()
        .map(|package| package.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let (user_scope, user_list) = match applications.android_users() {
        AndroidUserSelection::Owner => ("owner", String::new()),
        AndroidUserSelection::All => ("all", String::new()),
        AndroidUserSelection::List(ids) => (
            "list",
            ids.iter().map(u16::to_string).collect::<Vec<_>>().join(" "),
        ),
    };
    let ipv6 = match desired_state.capture().scope().families() {
        AddressHostFamilySelection::Ipv4 => "0",
        AddressHostFamilySelection::DualStack => "1",
        AddressHostFamilySelection::Ipv6 => {
            return Err(BridgeEnvironmentCompileError::new(
                BridgeEnvironmentCompileErrorKind::UnsupportedAddressFamilies,
            ));
        }
    };

    let mut output = String::with_capacity(4_096);
    output.push_str("# FLUX_DESIRED_STATE_ENV_V1\n");
    push_assignment(
        &mut output,
        "FLUX_BRIDGE_ENV_SCHEMA",
        &BRIDGE_ENVIRONMENT_SCHEMA_VERSION.to_string(),
    )?;
    push_assignment(&mut output, "ENGINE_BINARY", engine_binary)?;
    push_assignment(
        &mut output,
        "ENGINE_STARTUP_TIMEOUT_MS",
        &startup_timeout_ms.to_string(),
    )?;
    push_assignment(
        &mut output,
        "ENGINE_STOP_TIMEOUT_MS",
        &stop_timeout_ms.to_string(),
    )?;
    push_assignment(
        &mut output,
        "CORE_USER",
        &credentials.uid().get().to_string(),
    )?;
    push_assignment(
        &mut output,
        "CORE_GROUP",
        &credentials.gid().get().to_string(),
    )?;
    push_assignment(
        &mut output,
        "CORE_TIMEOUT",
        &compatibility_timeout_seconds.to_string(),
    )?;
    push_assignment(&mut output, "LOG_LEVEL", "3")?;
    push_assignment(&mut output, "LOG_MAX_SIZE", "1048576")?;
    push_assignment(&mut output, "PROXY_MODE", "tproxy")?;
    push_assignment(
        &mut output,
        "PROXY_PORT",
        &desired_state.listener().port().get().to_string(),
    )?;
    push_assignment(&mut output, "PROXY_IPV6", ipv6)?;
    push_assignment(&mut output, "APP_PROXY_MODE", application_mode)?;
    push_assignment(&mut output, "APP_LIST", &package_list)?;
    push_assignment(&mut output, "APP_USER_SCOPE", user_scope)?;
    push_assignment(&mut output, "APP_USER_LIST", &user_list)?;
    for ((name, enabled_name), (value, enabled)) in [
        ("MOBILE_INTERFACE", "PROXY_MOBILE"),
        ("WIFI_INTERFACE", "PROXY_WIFI"),
        ("HOTSPOT_INTERFACE", "PROXY_HOTSPOT"),
        ("USB_INTERFACE", "PROXY_USB"),
    ]
    .into_iter()
    .zip(roles)
    {
        push_assignment(&mut output, name, &value)?;
        push_assignment(&mut output, enabled_name, if enabled { "1" } else { "0" })?;
    }
    push_assignment(&mut output, "EXCLUDE_INTERFACES", &excluded)?;
    push_assignment(&mut output, "FAKEIP_V4_RANGE", &fake_ip_v4)?;
    push_assignment(&mut output, "FAKEIP_V6_RANGE", &fake_ip_v6)?;
    push_assignment(&mut output, "MARK_MASK", "0xff")?;
    push_assignment(&mut output, "IPV4_MARK", "0x14")?;
    push_assignment(&mut output, "IPV6_MARK", "0x19")?;
    push_assignment(&mut output, "BYPASS_MARK", "0x11")?;
    push_assignment(&mut output, "ROUTING_MARK", "")?;
    push_assignment(&mut output, "RULE_BACKEND", "iptables_restore")?;
    push_assignment(&mut output, "BYPASS_SET_BACKEND", "zone")?;
    push_assignment(&mut output, "MSS_CLAMP_ENABLE", "1")?;
    push_assignment(&mut output, "BLOCK_QUIC", "0")?;
    push_assignment(&mut output, "PERFORMANCE_MODE", "0")?;
    push_assignment(&mut output, "PRIVATE_DNS_GUARD", "0")?;
    push_assignment(&mut output, "IPV6_FORCE_DISABLE", "0")?;
    push_assignment(&mut output, "VENDOR_FIX_PROFILE", "none")?;
    push_assignment(&mut output, "HOTSPOT_FIX", "0")?;

    if output.len() > MAX_BRIDGE_ENVIRONMENT_BYTES {
        return Err(BridgeEnvironmentCompileError::new(
            BridgeEnvironmentCompileErrorKind::OutputTooLarge {
                actual: output.len(),
                maximum: MAX_BRIDGE_ENVIRONMENT_BYTES,
            },
        ));
    }
    Ok(BridgeEnvironmentArtifact {
        bytes: output.into_bytes().into_boxed_slice(),
    })
}

fn require_exact_bridge_shape(
    desired_state: &FluxConfig,
    subscription_mode: BridgeSubscriptionMode,
) -> Result<(), BridgeEnvironmentCompileError> {
    let scope = desired_state.capture().scope();
    if !scope.includes_domain(CaptureTrafficDomain::LocalOutput)
        || !scope.includes_domain(CaptureTrafficDomain::ForwardedIngress)
    {
        return Err(BridgeEnvironmentCompileError::new(
            BridgeEnvironmentCompileErrorKind::UnsupportedTrafficDomains,
        ));
    }
    let protocols = desired_state.capture().protocols();
    if !protocols.contains(CaptureTransportProtocol::Tcp)
        || !protocols.contains(CaptureTransportProtocol::Udp)
    {
        return Err(BridgeEnvironmentCompileError::new(
            BridgeEnvironmentCompileErrorKind::UnsupportedProtocols,
        ));
    }
    if !desired_state.bypass().policy().prefixes().is_empty() {
        return Err(BridgeEnvironmentCompileError::new(
            BridgeEnvironmentCompileErrorKind::ConfiguredBypassUnsupported,
        ));
    }
    match (desired_state.subscription().enabled(), subscription_mode) {
        (false, BridgeSubscriptionMode::Template)
        | (true, BridgeSubscriptionMode::ValidatedSubscription) => {}
        (true, BridgeSubscriptionMode::Template) => {
            return Err(BridgeEnvironmentCompileError::new(
                BridgeEnvironmentCompileErrorKind::SubscriptionUnsupported,
            ));
        }
        (false, BridgeSubscriptionMode::ValidatedSubscription) => {
            return Err(BridgeEnvironmentCompileError::new(
                BridgeEnvironmentCompileErrorKind::SubscriptionRequired,
            ));
        }
    }
    if desired_state.safety().respect_android_vpn() {
        return Err(BridgeEnvironmentCompileError::new(
            BridgeEnvironmentCompileErrorKind::AndroidVpnUnsupported,
        ));
    }
    if desired_state.safety().require_functional_canary() {
        return Err(BridgeEnvironmentCompileError::new(
            BridgeEnvironmentCompileErrorKind::FunctionalCanaryUnsupported,
        ));
    }
    Ok(())
}

fn bridge_interface(
    selector: CaptureInterfaceSelector,
) -> Result<String, BridgeEnvironmentCompileError> {
    let interface_name = selector.name();
    let name = std::str::from_utf8(interface_name.as_bytes()).map_err(|_| {
        BridgeEnvironmentCompileError::new(
            BridgeEnvironmentCompileErrorKind::UnsafeInterfaceSelector,
        )
    })?;
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
    {
        return Err(BridgeEnvironmentCompileError::new(
            BridgeEnvironmentCompileErrorKind::UnsafeInterfaceSelector,
        ));
    }
    let mut value = name.to_owned();
    if selector.kind() == CaptureInterfaceSelectorKind::Prefix {
        if value.len() == 15 {
            return Err(BridgeEnvironmentCompileError::new(
                BridgeEnvironmentCompileErrorKind::UnsafeInterfaceSelector,
            ));
        }
        value.push('+');
    }
    Ok(value)
}

fn extract_fake_ip_ranges(
    engine_config: &[u8],
) -> Result<(String, String), BridgeEnvironmentCompileError> {
    let document: Value = serde_json::from_slice(engine_config).map_err(|source| {
        BridgeEnvironmentCompileError::with_source(
            BridgeEnvironmentCompileErrorKind::InvalidEngineArtifact,
            source,
        )
    })?;
    let servers = document
        .get("dns")
        .and_then(Value::as_object)
        .and_then(|dns| dns.get("servers"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            BridgeEnvironmentCompileError::new(
                BridgeEnvironmentCompileErrorKind::MissingFakeIpServer,
            )
        })?;
    let mut fake_ip = None;
    for server in servers {
        let Some(server) = server.as_object() else {
            continue;
        };
        if server.get("type").and_then(Value::as_str) != Some("fakeip") {
            continue;
        }
        if fake_ip.replace(server).is_some() {
            return Err(BridgeEnvironmentCompileError::new(
                BridgeEnvironmentCompileErrorKind::MultipleFakeIpServers,
            ));
        }
    }
    let fake_ip = fake_ip.ok_or_else(|| {
        BridgeEnvironmentCompileError::new(BridgeEnvironmentCompileErrorKind::MissingFakeIpServer)
    })?;
    let ipv4 = fake_ip
        .get("inet4_range")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_fake_ip(NetworkAddressFamily::Ipv4))?;
    let ipv6 = fake_ip
        .get("inet6_range")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_fake_ip(NetworkAddressFamily::Ipv6))?;
    validate_fake_ip(ipv4, NetworkAddressFamily::Ipv4)?;
    validate_fake_ip(ipv6, NetworkAddressFamily::Ipv6)?;
    Ok((ipv4.to_owned(), ipv6.to_owned()))
}

fn validate_fake_ip(
    value: &str,
    family: NetworkAddressFamily,
) -> Result<(), BridgeEnvironmentCompileError> {
    let (address, prefix) = value
        .split_once('/')
        .filter(|(_, prefix)| !prefix.contains('/'))
        .ok_or_else(|| invalid_fake_ip(family))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| invalid_fake_ip(family))?;
    let prefix = prefix.parse::<u8>().map_err(|_| invalid_fake_ip(family))?;
    let parsed = CaptureIpPrefix::new(address, prefix).map_err(|_| invalid_fake_ip(family))?;
    if parsed.family() != family || parsed.to_string() != value {
        return Err(invalid_fake_ip(family));
    }
    Ok(())
}

fn invalid_fake_ip(family: NetworkAddressFamily) -> BridgeEnvironmentCompileError {
    BridgeEnvironmentCompileError::new(BridgeEnvironmentCompileErrorKind::InvalidFakeIpRange {
        family,
    })
}

fn push_assignment(
    output: &mut String,
    name: &'static str,
    value: &str,
) -> Result<(), BridgeEnvironmentCompileError> {
    if !is_shell_literal_safe(value) {
        return Err(BridgeEnvironmentCompileError::new(
            BridgeEnvironmentCompileErrorKind::UnsafeValue,
        ));
    }
    output.push_str(name);
    output.push_str("='");
    output.push_str(value);
    output.push_str("'\n");
    Ok(())
}

fn is_shell_literal_safe(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b' ' | b'_' | b'.' | b'/' | b':' | b'+' | b'*' | b'-')
    })
}

fn is_manifest_safe_value(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'/' | b':' | b'+' | b'-')
        })
}
