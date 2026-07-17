use std::error::Error;
use std::fmt;
use std::fmt::Write as _;
use std::net::IpAddr;

use sha2::{Digest, Sha256};

use super::{
    XtablesRestoreAction, XtablesRestoreArtifact, XtablesRestoreContext, XtablesRestoreFamily,
    XtablesRestoreParseError, XtablesRestoreResourceUsage, parse_xtables_restore,
};

const BASE_CHAINS: &[&str] = &[
    "PROXY_PREROUTING",
    "PROXY_OUTPUT",
    "BYPASS_IP",
    "APP_CHAIN",
    "ACTION_PROXY_PRE",
    "ACTION_PROXY_OUT",
    "ACTION_BYPASS",
];

const IPV4_ZONE_RULES: &[(u8, &str)] = &[
    (0, "0.0.0.0/8"),
    (0, "10.0.0.0/8"),
    (6, "100.64.0.0/10"),
    (7, "127.0.0.0/8"),
    (10, "169.254.0.0/16"),
    (10, "172.16.0.0/12"),
    (12, "192.0.0.0/24"),
    (12, "192.0.2.0/24"),
    (12, "192.88.99.0/24"),
    (12, "192.168.0.0/16"),
    (12, "198.51.100.0/24"),
    (12, "203.0.113.0/24"),
    (14, "224.0.0.0/4"),
    (15, "240.0.0.0/4"),
    (15, "255.255.255.255/32"),
];

const IPV4_DISPATCH_RULES: &[(u8, &str)] = &[
    (0, "0.0.0.0/4"),
    (6, "96.0.0.0/4"),
    (7, "112.0.0.0/4"),
    (10, "160.0.0.0/4"),
    (12, "192.0.0.0/4"),
    (14, "224.0.0.0/4"),
    (15, "240.0.0.0/4"),
];

const IPV6_ZONE_RULES: &[(u8, &str)] = &[
    (0, "::/128"),
    (0, "::1/128"),
    (0, "::ffff:0:0/96"),
    (1, "100::/64"),
    (6, "64:ff9b::/96"),
    (2, "2001::/32"),
    (2, "2001:10::/28"),
    (2, "2001:20::/28"),
    (2, "2001:db8::/32"),
    (2, "2002::/16"),
    (15, "fe80::/10"),
    (15, "ff00::/8"),
];

const IPV6_DISPATCH_RULES: &[(u8, &str)] = &[
    (0, "0000::/4"),
    (1, "1000::/4"),
    (2, "2000::/4"),
    (6, "6000::/4"),
    (15, "f000::/4"),
];

const MAX_OWNER_TOKEN_BYTES: usize = 255;
const MAX_INTERFACE_PATTERN_BYTES: usize = 15;
pub const MAX_LEGACY_APPLICATION_UIDS: usize = 20_000;
const MAX_EXCLUDED_INTERFACES: usize = 128;
const DEFAULT_IPV4_PROXY_MARK: u32 = 0x14;
const DEFAULT_IPV6_PROXY_MARK: u32 = 0x19;
const DEFAULT_BYPASS_MARK: u32 = 0x11;

/// Bump when any plan, pair, set, or resource-total digest encoding changes.
pub const LEGACY_RULES_IDENTITY_SCHEMA_VERSION: u16 = 1;
pub const LEGACY_RULES_DIGEST_BYTES: usize = 32;

const LEGACY_RULES_PLAN_DIGEST_DOMAIN: &[u8] = b"Flux legacy rules plan identity\0schema-v1\0";
const LEGACY_RULES_PAIR_DIGEST_DOMAIN: &[u8] =
    b"Flux legacy rules artifact pair identity\0schema-v1\0";
const LEGACY_RULES_SET_DIGEST_DOMAIN: &[u8] =
    b"Flux legacy rules artifact set identity\0schema-v1\0";

macro_rules! legacy_rules_digest {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name([u8; LEGACY_RULES_DIGEST_BYTES]);

        impl $name {
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; LEGACY_RULES_DIGEST_BYTES] {
                &self.0
            }
        }
    };
}

legacy_rules_digest!(LegacyRulesPlanDigest);
legacy_rules_digest!(LegacyRulesPairDigest);
legacy_rules_digest!(LegacyRulesSetDigest);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyRulesResourceTotals {
    input_bytes: usize,
    lines: usize,
    transactions: usize,
    chain_declarations: usize,
    commands: usize,
    tokens: usize,
}

impl LegacyRulesResourceTotals {
    #[must_use]
    pub const fn input_bytes(self) -> usize {
        self.input_bytes
    }

    #[must_use]
    pub const fn lines(self) -> usize {
        self.lines
    }

    #[must_use]
    pub const fn transactions(self) -> usize {
        self.transactions
    }

    #[must_use]
    pub const fn chain_declarations(self) -> usize {
        self.chain_declarations
    }

    #[must_use]
    pub const fn commands(self) -> usize {
        self.commands
    }

    #[must_use]
    pub const fn tokens(self) -> usize {
        self.tokens
    }

    const fn from_restore(usage: XtablesRestoreResourceUsage) -> Self {
        Self {
            input_bytes: usage.input_bytes(),
            lines: usage.lines(),
            transactions: usage.transactions(),
            chain_declarations: usage.chain_declarations(),
            commands: usage.commands(),
            tokens: usage.tokens(),
        }
    }

    const fn add(self, other: Self) -> Self {
        Self {
            input_bytes: self.input_bytes + other.input_bytes,
            lines: self.lines + other.lines,
            transactions: self.transactions + other.transactions,
            chain_declarations: self.chain_declarations + other.chain_declarations,
            commands: self.commands + other.commands,
            tokens: self.tokens + other.tokens,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyOwnerToken(Box<str>);

impl LegacyOwnerToken {
    pub fn new(value: &str) -> Result<Self, LegacyRulesPlanError> {
        let numeric = !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
        let identifier = value.as_bytes().split_first().is_some_and(|(first, tail)| {
            (first.is_ascii_alphabetic() || *first == b'_')
                && tail
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        });
        if value.len() > MAX_OWNER_TOKEN_BYTES || (!numeric && !identifier) {
            return Err(LegacyRulesPlanError::InvalidOwnerToken);
        }
        Ok(Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyOwnerMatch {
    uid: LegacyOwnerToken,
    gid: LegacyOwnerToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyMarkValues {
    ipv4_proxy: u32,
    ipv6_proxy: u32,
    bypass: u32,
}

impl LegacyMarkValues {
    #[must_use]
    pub const fn new(ipv4_proxy: u32, ipv6_proxy: u32, bypass: u32) -> Self {
        Self {
            ipv4_proxy,
            ipv6_proxy,
            bypass,
        }
    }

    #[must_use]
    pub const fn legacy_defaults() -> Self {
        Self::new(
            DEFAULT_IPV4_PROXY_MARK,
            DEFAULT_IPV6_PROXY_MARK,
            DEFAULT_BYPASS_MARK,
        )
    }
}

impl LegacyOwnerMatch {
    #[must_use]
    pub const fn new(uid: LegacyOwnerToken, gid: LegacyOwnerToken) -> Self {
        Self { uid, gid }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyInterfacePattern(Box<str>);

impl LegacyInterfacePattern {
    pub fn new(value: &str) -> Result<Self, LegacyRulesPlanError> {
        let (base, wildcard) = value
            .strip_suffix('+')
            .map_or((value, false), |base| (base, true));
        let valid = !base.is_empty()
            && base
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
            && (!wildcard || !base.ends_with('+'));
        if !valid || value.len() > MAX_INTERFACE_PATTERN_BYTES {
            return Err(LegacyRulesPlanError::InvalidInterfacePattern);
        }
        Ok(Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyApplicationMode {
    All,
    Denylist,
    Allowlist,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyApplicationPolicy {
    mode: LegacyApplicationMode,
    ordered_uids: Box<[u32]>,
}

impl LegacyApplicationPolicy {
    pub fn new(
        mode: LegacyApplicationMode,
        ordered_uids: impl IntoIterator<Item = u32>,
    ) -> Result<Self, LegacyRulesPlanError> {
        let ordered_uids = ordered_uids.into_iter().collect::<Vec<_>>();
        if ordered_uids.len() > MAX_LEGACY_APPLICATION_UIDS {
            return Err(LegacyRulesPlanError::TooManyApplicationUids);
        }
        Ok(Self {
            mode,
            ordered_uids: ordered_uids.into_boxed_slice(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyInterfaceRole {
    pattern: Option<LegacyInterfacePattern>,
    proxy: bool,
}

impl LegacyInterfaceRole {
    #[must_use]
    pub const fn new(pattern: Option<LegacyInterfacePattern>, proxy: bool) -> Self {
        Self { pattern, proxy }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyInterfacePolicy {
    excluded: Box<[LegacyInterfacePattern]>,
    roles: [LegacyInterfaceRole; 4],
}

impl LegacyInterfacePolicy {
    pub fn new(
        excluded: impl IntoIterator<Item = LegacyInterfacePattern>,
        mobile: LegacyInterfaceRole,
        wifi: LegacyInterfaceRole,
        hotspot: LegacyInterfaceRole,
        usb: LegacyInterfaceRole,
    ) -> Result<Self, LegacyRulesPlanError> {
        let excluded = excluded.into_iter().collect::<Vec<_>>();
        if excluded.len() > MAX_EXCLUDED_INTERFACES {
            return Err(LegacyRulesPlanError::TooManyExcludedInterfaces);
        }
        Ok(Self {
            excluded: excluded.into_boxed_slice(),
            roles: [mobile, wifi, hotspot, usb],
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyKernelFeatures {
    owner: bool,
    mark: bool,
    conntrack: bool,
    socket_tcp: bool,
    socket_udp: bool,
    ipv6_nat: bool,
    tproxy: bool,
}

impl LegacyKernelFeatures {
    #[must_use]
    pub const fn new(
        owner: bool,
        mark: bool,
        conntrack: bool,
        socket_tcp: bool,
        socket_udp: bool,
        ipv6_nat: bool,
        tproxy: bool,
    ) -> Self {
        Self {
            owner,
            mark,
            conntrack,
            socket_tcp,
            socket_udp,
            ipv6_nat,
            tproxy,
        }
    }
}

/// Sealed, source-shape compatibility inputs for the bounded legacy renderer.
///
/// The plan deliberately preserves source ordering, duplicate rules, covered prefixes, and other
/// byte-significant details that the backend-neutral shadow Capture Program canonicalizes away.
/// It carries no Generation identity, writer authority, execution path, or activation conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyRulesPlan {
    proxy_port: u16,
    mark_mask: u32,
    marks: LegacyMarkValues,
    routing_mark: Option<u32>,
    owner: LegacyOwnerMatch,
    applications: LegacyApplicationPolicy,
    interfaces: LegacyInterfacePolicy,
    features: LegacyKernelFeatures,
    performance_mode: bool,
    mss_clamp: bool,
    ipv6_enabled: bool,
    fake_ip_v4: Box<str>,
    fake_ip_v6: Box<str>,
}

impl LegacyRulesPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proxy_port: u16,
        mark_mask: u32,
        marks: LegacyMarkValues,
        routing_mark: Option<u32>,
        owner: LegacyOwnerMatch,
        applications: LegacyApplicationPolicy,
        interfaces: LegacyInterfacePolicy,
        features: LegacyKernelFeatures,
        performance_mode: bool,
        mss_clamp: bool,
        ipv6_enabled: bool,
        fake_ip_v4: &str,
        fake_ip_v6: &str,
    ) -> Result<Self, LegacyRulesPlanError> {
        if proxy_port == 0 {
            return Err(LegacyRulesPlanError::InvalidProxyPort);
        }
        if !legacy_mark_mask_is_valid(mark_mask, marks) {
            return Err(LegacyRulesPlanError::InvalidMarkMask);
        }
        validate_fake_ip(fake_ip_v4, XtablesRestoreFamily::Ipv4)?;
        validate_fake_ip(fake_ip_v6, XtablesRestoreFamily::Ipv6)?;
        Ok(Self {
            proxy_port,
            mark_mask,
            marks,
            routing_mark,
            owner,
            applications,
            interfaces,
            features,
            performance_mode,
            mss_clamp,
            ipv6_enabled,
            fake_ip_v4: fake_ip_v4.into(),
            fake_ip_v6: fake_ip_v6.into(),
        })
    }

    /// Exact reviewed `maximal-zone-v1` oracle input snapshot.
    #[must_use]
    pub fn maximal_zone_v1() -> Self {
        let pattern = |value| LegacyInterfacePattern::new(value).expect("valid fixture interface");
        let role = |value, proxy| LegacyInterfaceRole::new(Some(pattern(value)), proxy);
        Self::new(
            1536,
            0xff,
            LegacyMarkValues::legacy_defaults(),
            None,
            LegacyOwnerMatch::new(
                LegacyOwnerToken::new("1000").expect("valid fixture UID"),
                LegacyOwnerToken::new("1000").expect("valid fixture GID"),
            ),
            LegacyApplicationPolicy::new(
                LegacyApplicationMode::Allowlist,
                [210_124, 1_010_124, 210_123, 1_010_123],
            )
            .expect("valid fixture applications"),
            LegacyInterfacePolicy::new(
                [pattern("wlan+"), pattern("rmnet+"), pattern("wlan+")],
                role("rmnet_data+", true),
                role("wlan0", false),
                role("wlan2", true),
                role("rndis+", false),
            )
            .expect("valid fixture interfaces"),
            LegacyKernelFeatures::new(true, true, true, true, false, true, true),
            true,
            true,
            true,
            "198.18.0.0/15",
            "fc00::/18",
        )
        .expect("the pinned fixture plan is valid")
    }

    #[must_use]
    pub const fn ipv6_enabled(&self) -> bool {
        self.ipv6_enabled
    }

    #[must_use]
    pub const fn production_eligible(&self) -> bool {
        self.features.owner && self.features.tproxy
    }

    /// Stable identity of every byte-significant source-shape input consumed by the renderer.
    ///
    /// The digest is observation-only. It carries no Generation identity, writer ownership, or
    /// permission to execute the resulting restore artifacts.
    #[must_use]
    pub fn digest(&self) -> LegacyRulesPlanDigest {
        let mut hasher = identity_hasher(LEGACY_RULES_PLAN_DIGEST_DOMAIN);
        hash_u16(&mut hasher, self.proxy_port);
        hash_u32(&mut hasher, self.mark_mask);
        hash_u32(&mut hasher, self.marks.ipv4_proxy);
        hash_u32(&mut hasher, self.marks.ipv6_proxy);
        hash_u32(&mut hasher, self.marks.bypass);
        hash_optional_u32(&mut hasher, self.routing_mark);
        hash_text(&mut hasher, self.owner.uid.as_str());
        hash_text(&mut hasher, self.owner.gid.as_str());
        hash_u8(&mut hasher, application_mode_tag(self.applications.mode));
        hash_len(&mut hasher, self.applications.ordered_uids.len());
        for uid in &self.applications.ordered_uids {
            hash_u32(&mut hasher, *uid);
        }
        hash_len(&mut hasher, self.interfaces.excluded.len());
        for pattern in &self.interfaces.excluded {
            hash_text(&mut hasher, pattern.as_str());
        }
        hash_len(&mut hasher, self.interfaces.roles.len());
        for role in &self.interfaces.roles {
            hash_optional_text(
                &mut hasher,
                role.pattern.as_ref().map(LegacyInterfacePattern::as_str),
            );
            hash_bool(&mut hasher, role.proxy);
        }
        for enabled in [
            self.features.owner,
            self.features.mark,
            self.features.conntrack,
            self.features.socket_tcp,
            self.features.socket_udp,
            self.features.ipv6_nat,
            self.features.tproxy,
            self.performance_mode,
            self.mss_clamp,
            self.ipv6_enabled,
        ] {
            hash_bool(&mut hasher, enabled);
        }
        hash_text(&mut hasher, &self.fake_ip_v4);
        hash_text(&mut hasher, &self.fake_ip_v6);
        LegacyRulesPlanDigest(hasher.finalize().into())
    }
}

/// Renderer-owned apply/cleanup identity for one address family.
///
/// Construction is intentionally private to [`render_legacy_rules_pair`], so independently parsed
/// artifacts cannot be relabeled as a renderer-produced pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyRulesArtifactPair {
    schema_version: u16,
    family: XtablesRestoreFamily,
    plan_digest: LegacyRulesPlanDigest,
    apply: XtablesRestoreArtifact,
    cleanup: XtablesRestoreArtifact,
    resource_totals: LegacyRulesResourceTotals,
    digest: LegacyRulesPairDigest,
}

impl LegacyRulesArtifactPair {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn family(&self) -> XtablesRestoreFamily {
        self.family
    }

    #[must_use]
    pub const fn plan_digest(&self) -> LegacyRulesPlanDigest {
        self.plan_digest
    }

    #[must_use]
    pub const fn apply(&self) -> &XtablesRestoreArtifact {
        &self.apply
    }

    #[must_use]
    pub const fn cleanup(&self) -> &XtablesRestoreArtifact {
        &self.cleanup
    }

    #[must_use]
    pub const fn resource_totals(&self) -> LegacyRulesResourceTotals {
        self.resource_totals
    }

    #[must_use]
    pub const fn digest(&self) -> LegacyRulesPairDigest {
        self.digest
    }
}

/// Renderer-owned identity for the complete enabled legacy restore artifact set.
///
/// IPv4 is mandatory. IPv6 is present exactly when the immutable source plan enables it. This
/// type is still non-authorizing and has no filesystem, process, or kernel execution surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyRulesArtifactSet {
    schema_version: u16,
    plan_digest: LegacyRulesPlanDigest,
    ipv4: LegacyRulesArtifactPair,
    ipv6: Option<LegacyRulesArtifactPair>,
    resource_totals: LegacyRulesResourceTotals,
    digest: LegacyRulesSetDigest,
}

impl LegacyRulesArtifactSet {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn plan_digest(&self) -> LegacyRulesPlanDigest {
        self.plan_digest
    }

    #[must_use]
    pub const fn ipv4(&self) -> &LegacyRulesArtifactPair {
        &self.ipv4
    }

    #[must_use]
    pub const fn ipv6(&self) -> Option<&LegacyRulesArtifactPair> {
        self.ipv6.as_ref()
    }

    #[must_use]
    pub const fn resource_totals(&self) -> LegacyRulesResourceTotals {
        self.resource_totals
    }

    #[must_use]
    pub const fn digest(&self) -> LegacyRulesSetDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyRulesPlanError {
    InvalidFakeIp,
    InvalidInterfacePattern,
    InvalidMarkMask,
    InvalidOwnerToken,
    InvalidProxyPort,
    TooManyApplicationUids,
    TooManyExcludedInterfaces,
}

impl fmt::Display for LegacyRulesPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFakeIp => "legacy rules FakeIP range is invalid or has the wrong family",
            Self::InvalidInterfacePattern => "legacy rules interface pattern is invalid",
            Self::InvalidMarkMask => {
                "legacy rules mark mask must contain and distinguish every fixed legacy mark"
            }
            Self::InvalidOwnerToken => "legacy rules owner token is invalid",
            Self::InvalidProxyPort => "legacy rules proxy port must be nonzero",
            Self::TooManyApplicationUids => "legacy rules application UID list exceeds its limit",
            Self::TooManyExcludedInterfaces => {
                "legacy rules excluded interface list exceeds its limit"
            }
        })
    }
}

impl Error for LegacyRulesPlanError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyRulesRenderRequest<'a> {
    context: XtablesRestoreContext,
    plan: &'a LegacyRulesPlan,
}

impl<'a> LegacyRulesRenderRequest<'a> {
    #[must_use]
    pub const fn new(context: XtablesRestoreContext, plan: &'a LegacyRulesPlan) -> Self {
        Self { context, plan }
    }

    #[must_use]
    pub const fn context(self) -> XtablesRestoreContext {
        self.context
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyRulesRenderError {
    FamilyDisabled,
    UnsupportedAction(XtablesRestoreAction),
    InvalidRenderedArtifact(XtablesRestoreParseError),
}

impl LegacyRulesRenderError {
    #[must_use]
    pub const fn parse_error(&self) -> Option<&XtablesRestoreParseError> {
        match self {
            Self::FamilyDisabled | Self::UnsupportedAction(_) => None,
            Self::InvalidRenderedArtifact(source) => Some(source),
        }
    }
}

impl fmt::Display for LegacyRulesRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FamilyDisabled => formatter.write_str("legacy IPv6 restore family is disabled"),
            Self::UnsupportedAction(action) => {
                write!(
                    formatter,
                    "legacy rules renderer does not support {action:?}"
                )
            }
            Self::InvalidRenderedArtifact(source) => write!(
                formatter,
                "rendered legacy xtables source shape was not canonical: {source}"
            ),
        }
    }
}

impl Error for LegacyRulesRenderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FamilyDisabled | Self::UnsupportedAction(_) => None,
            Self::InvalidRenderedArtifact(source) => Some(source),
        }
    }
}

/// Render one frozen legacy source-shape artifact without performing filesystem, process, or
/// kernel I/O.
///
/// This is intentionally not a semantic lowering from `ShadowCaptureArtifact`. It reproduces the
/// reviewed shell oracle bytes so Rust generation can be compared independently of execution.
pub fn render_legacy_rules_restore(
    request: LegacyRulesRenderRequest<'_>,
) -> Result<XtablesRestoreArtifact, LegacyRulesRenderError> {
    if request.context.family() == XtablesRestoreFamily::Ipv6 && !request.plan.ipv6_enabled {
        return Err(LegacyRulesRenderError::FamilyDisabled);
    }
    if request.context.action() == XtablesRestoreAction::Replace {
        return Err(LegacyRulesRenderError::UnsupportedAction(
            XtablesRestoreAction::Replace,
        ));
    }
    let mut output = String::new();
    render_plan(request.context, request.plan, &mut output);
    parse_xtables_restore(output.as_bytes(), request.context)
        .map_err(LegacyRulesRenderError::InvalidRenderedArtifact)
}

/// Render and bind the apply/cleanup artifacts for one family from one immutable plan.
///
/// The renderer-produced identity can only originate here; there is deliberately no constructor from
/// arbitrary parsed artifacts.
pub fn render_legacy_rules_pair(
    plan: &LegacyRulesPlan,
    family: XtablesRestoreFamily,
) -> Result<LegacyRulesArtifactPair, LegacyRulesRenderError> {
    let apply = render_legacy_rules_restore(LegacyRulesRenderRequest::new(
        XtablesRestoreContext::new(XtablesRestoreAction::Apply, family),
        plan,
    ))?;
    let cleanup = render_legacy_rules_restore(LegacyRulesRenderRequest::new(
        XtablesRestoreContext::new(XtablesRestoreAction::Cleanup, family),
        plan,
    ))?;
    let plan_digest = plan.digest();
    let resource_totals = LegacyRulesResourceTotals::from_restore(apply.usage())
        .add(LegacyRulesResourceTotals::from_restore(cleanup.usage()));
    let digest = legacy_rules_pair_digest(plan_digest, family, &apply, &cleanup, resource_totals);
    Ok(LegacyRulesArtifactPair {
        schema_version: LEGACY_RULES_IDENTITY_SCHEMA_VERSION,
        family,
        plan_digest,
        apply,
        cleanup,
        resource_totals,
        digest,
    })
}

/// Render and bind the complete enabled legacy artifact set from one immutable plan.
pub fn render_legacy_rules_set(
    plan: &LegacyRulesPlan,
) -> Result<LegacyRulesArtifactSet, LegacyRulesRenderError> {
    let plan_digest = plan.digest();
    let ipv4 = render_legacy_rules_pair(plan, XtablesRestoreFamily::Ipv4)?;
    let ipv6 = if plan.ipv6_enabled {
        Some(render_legacy_rules_pair(plan, XtablesRestoreFamily::Ipv6)?)
    } else {
        None
    };
    let resource_totals = ipv6.as_ref().map_or_else(
        || ipv4.resource_totals(),
        |ipv6| ipv4.resource_totals().add(ipv6.resource_totals()),
    );
    let digest = legacy_rules_set_digest(plan_digest, &ipv4, ipv6.as_ref(), resource_totals);
    Ok(LegacyRulesArtifactSet {
        schema_version: LEGACY_RULES_IDENTITY_SCHEMA_VERSION,
        plan_digest,
        ipv4,
        ipv6,
        resource_totals,
        digest,
    })
}

fn legacy_rules_pair_digest(
    plan_digest: LegacyRulesPlanDigest,
    family: XtablesRestoreFamily,
    apply: &XtablesRestoreArtifact,
    cleanup: &XtablesRestoreArtifact,
    resource_totals: LegacyRulesResourceTotals,
) -> LegacyRulesPairDigest {
    let mut hasher = identity_hasher(LEGACY_RULES_PAIR_DIGEST_DOMAIN);
    hasher.update(plan_digest.as_bytes());
    hash_u8(&mut hasher, family_tag(family));
    hash_restore_artifact(&mut hasher, apply);
    hash_restore_artifact(&mut hasher, cleanup);
    hash_resource_totals(&mut hasher, resource_totals);
    LegacyRulesPairDigest(hasher.finalize().into())
}

fn legacy_rules_set_digest(
    plan_digest: LegacyRulesPlanDigest,
    ipv4: &LegacyRulesArtifactPair,
    ipv6: Option<&LegacyRulesArtifactPair>,
    resource_totals: LegacyRulesResourceTotals,
) -> LegacyRulesSetDigest {
    let mut hasher = identity_hasher(LEGACY_RULES_SET_DIGEST_DOMAIN);
    hasher.update(plan_digest.as_bytes());
    hash_pair_receipt(&mut hasher, ipv4);
    hash_bool(&mut hasher, ipv6.is_some());
    if let Some(ipv6) = ipv6 {
        hash_pair_receipt(&mut hasher, ipv6);
    }
    hash_resource_totals(&mut hasher, resource_totals);
    LegacyRulesSetDigest(hasher.finalize().into())
}

fn identity_hasher(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hash_u16(&mut hasher, LEGACY_RULES_IDENTITY_SCHEMA_VERSION);
    hasher
}

fn hash_pair_receipt(hasher: &mut Sha256, pair: &LegacyRulesArtifactPair) {
    hash_u16(hasher, pair.schema_version);
    hash_u8(hasher, family_tag(pair.family));
    hasher.update(pair.plan_digest.as_bytes());
    hasher.update(pair.digest.as_bytes());
    hash_resource_totals(hasher, pair.resource_totals);
}

fn hash_restore_artifact(hasher: &mut Sha256, artifact: &XtablesRestoreArtifact) {
    hash_u16(hasher, artifact.schema_version());
    hash_u8(hasher, action_tag(artifact.context().action()));
    hash_u8(hasher, family_tag(artifact.context().family()));
    hasher.update(artifact.digest().as_bytes());
    hash_restore_usage(hasher, artifact.usage());
}

fn hash_restore_usage(hasher: &mut Sha256, usage: XtablesRestoreResourceUsage) {
    hash_u64(hasher, usage.input_bytes() as u64);
    hash_u64(hasher, usage.lines() as u64);
    hash_u64(hasher, usage.transactions() as u64);
    hash_u64(hasher, usage.chain_declarations() as u64);
    hash_u64(hasher, usage.commands() as u64);
    hash_u64(hasher, usage.tokens() as u64);
}

fn hash_resource_totals(hasher: &mut Sha256, totals: LegacyRulesResourceTotals) {
    hash_u64(hasher, totals.input_bytes as u64);
    hash_u64(hasher, totals.lines as u64);
    hash_u64(hasher, totals.transactions as u64);
    hash_u64(hasher, totals.chain_declarations as u64);
    hash_u64(hasher, totals.commands as u64);
    hash_u64(hasher, totals.tokens as u64);
}

fn hash_optional_u32(hasher: &mut Sha256, value: Option<u32>) {
    hash_bool(hasher, value.is_some());
    if let Some(value) = value {
        hash_u32(hasher, value);
    }
}

fn hash_optional_text(hasher: &mut Sha256, value: Option<&str>) {
    hash_bool(hasher, value.is_some());
    if let Some(value) = value {
        hash_text(hasher, value);
    }
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hash_len(hasher, value.len());
    hasher.update(value.as_bytes());
}

fn hash_len(hasher: &mut Sha256, value: usize) {
    hash_u64(hasher, value as u64);
}

fn hash_bool(hasher: &mut Sha256, value: bool) {
    hash_u8(hasher, u8::from(value));
}

fn hash_u8(hasher: &mut Sha256, value: u8) {
    hasher.update([value]);
}

fn hash_u16(hasher: &mut Sha256, value: u16) {
    hasher.update(value.to_be_bytes());
}

fn hash_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_be_bytes());
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

const fn application_mode_tag(mode: LegacyApplicationMode) -> u8 {
    match mode {
        LegacyApplicationMode::All => 1,
        LegacyApplicationMode::Denylist => 2,
        LegacyApplicationMode::Allowlist => 3,
    }
}

const fn action_tag(action: XtablesRestoreAction) -> u8 {
    match action {
        XtablesRestoreAction::Apply => 1,
        XtablesRestoreAction::Cleanup => 2,
        XtablesRestoreAction::Replace => 3,
    }
}

const fn family_tag(family: XtablesRestoreFamily) -> u8 {
    match family {
        XtablesRestoreFamily::Ipv4 => 4,
        XtablesRestoreFamily::Ipv6 => 6,
    }
}

fn render_plan(context: XtablesRestoreContext, plan: &LegacyRulesPlan, output: &mut String) {
    let family = FamilyProfile::for_family(context.family(), plan);
    render_mangle(context.action(), family, output);
    if plan.features.owner {
        render_loopback_filter(context.action(), family, output);
    }
    if context.family() == XtablesRestoreFamily::Ipv4 || plan.features.ipv6_nat {
        render_fake_ip(context.action(), family, output);
    }
    if plan.mss_clamp {
        render_mss_clamp(context.action(), output);
    }
}

#[derive(Clone, Copy)]
struct FamilyProfile<'a> {
    plan: &'a LegacyRulesPlan,
    suffix: &'static str,
    proxy_mark: u32,
    loopback: &'static str,
    fake_ip_range: &'a str,
    fake_ip_protocol: &'static str,
    zone_rules: &'static [(u8, &'static str)],
    dispatch_rules: &'static [(u8, &'static str)],
}

impl<'a> FamilyProfile<'a> {
    fn for_family(family: XtablesRestoreFamily, plan: &'a LegacyRulesPlan) -> Self {
        match family {
            XtablesRestoreFamily::Ipv4 => Self {
                plan,
                suffix: "",
                proxy_mark: plan.marks.ipv4_proxy,
                loopback: "127.0.0.1",
                fake_ip_range: &plan.fake_ip_v4,
                fake_ip_protocol: "icmp",
                zone_rules: IPV4_ZONE_RULES,
                dispatch_rules: IPV4_DISPATCH_RULES,
            },
            XtablesRestoreFamily::Ipv6 => Self {
                plan,
                suffix: "6",
                proxy_mark: plan.marks.ipv6_proxy,
                loopback: "::1",
                fake_ip_range: &plan.fake_ip_v6,
                fake_ip_protocol: "ipv6-icmp",
                zone_rules: IPV6_ZONE_RULES,
                dispatch_rules: IPV6_DISPATCH_RULES,
            },
        }
    }
}

fn validate_fake_ip(value: &str, family: XtablesRestoreFamily) -> Result<(), LegacyRulesPlanError> {
    let Some((address, prefix)) = value.split_once('/') else {
        return Err(LegacyRulesPlanError::InvalidFakeIp);
    };
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| LegacyRulesPlanError::InvalidFakeIp)?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| LegacyRulesPlanError::InvalidFakeIp)?;
    let valid = match (family, address) {
        (XtablesRestoreFamily::Ipv4, IpAddr::V4(_)) => prefix <= 32,
        (XtablesRestoreFamily::Ipv6, IpAddr::V6(_)) => prefix <= 128,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(LegacyRulesPlanError::InvalidFakeIp)
    }
}

const fn legacy_mark_mask_is_valid(mask: u32, marks: LegacyMarkValues) -> bool {
    let mark_bits = marks.ipv4_proxy | marks.ipv6_proxy | marks.bypass;
    mask & mark_bits == mark_bits
        && (marks.ipv4_proxy ^ marks.bypass) & mask != 0
        && (marks.ipv6_proxy ^ marks.bypass) & mask != 0
}

fn render_mangle(action: XtablesRestoreAction, family: FamilyProfile<'_>, output: &mut String) {
    output.push_str("*mangle\n");
    match action {
        XtablesRestoreAction::Apply => render_apply_mangle(family, output),
        XtablesRestoreAction::Replace => {
            unreachable!("legacy rules renderer rejects replace action before rendering")
        }
        XtablesRestoreAction::Cleanup => render_cleanup_mangle(family, output),
    }
    output.push_str("COMMIT\n");
}

fn render_apply_mangle(family: FamilyProfile<'_>, output: &mut String) {
    for chain in BASE_CHAINS {
        writeln!(output, ":{chain}{} - [0:0]", family.suffix).expect("writing to String");
    }
    for zone in 0..16 {
        writeln!(output, ":BYP_Z{zone}{} - [0:0]", family.suffix).expect("writing to String");
    }
    if divert_enabled(family.plan) {
        writeln!(output, ":DIVERT{} - [0:0]", family.suffix).expect("writing to String");
    }

    if family.plan.features.conntrack && family.plan.features.mark {
        writeln!(
            output,
            "-A ACTION_BYPASS{} -j CONNMARK --set-xmark 0x{:x}/0x{:x}",
            family.suffix, family.plan.marks.bypass, family.plan.mark_mask
        )
        .expect("writing to String");
    }
    writeln!(output, "-A ACTION_BYPASS{} -j ACCEPT", family.suffix).expect("writing to String");

    render_proxy_action("ACTION_PROXY_PRE", true, family, output);
    render_proxy_action("ACTION_PROXY_OUT", false, family, output);
    render_bypass_tree(family, output);
    render_application_chain(family, output);
    if divert_enabled(family.plan) {
        render_divert(family, output);
    }
    render_fast_path(family, output);
    render_prerouting_policy(family, output);
    render_output_policy(family, output);

    writeln!(output, "-I PREROUTING -j PROXY_PREROUTING{}", family.suffix)
        .expect("writing to String");
    writeln!(output, "-I OUTPUT -j PROXY_OUTPUT{}", family.suffix).expect("writing to String");
}

fn render_proxy_action(chain: &str, tproxy: bool, family: FamilyProfile<'_>, output: &mut String) {
    if family.plan.features.conntrack && family.plan.features.mark {
        writeln!(
            output,
            "-A {chain}{} -j CONNMARK --set-xmark 0x{:x}/0x{:x}",
            family.suffix, family.proxy_mark, family.plan.mark_mask
        )
        .expect("writing to String");
        writeln!(
            output,
            "-A {chain}{} -j MARK --set-xmark 0x{:x}/0x{:x}",
            family.suffix, family.proxy_mark, family.plan.mark_mask
        )
        .expect("writing to String");
    }
    if tproxy {
        for protocol in ["tcp", "udp"] {
            writeln!(
                output,
                "-A {chain}{} -p {protocol} -j TPROXY --on-port {} --tproxy-mark 0x{:x}/0x{:x}",
                family.suffix, family.plan.proxy_port, family.proxy_mark, family.plan.mark_mask
            )
            .expect("writing to String");
        }
    }
    writeln!(output, "-A {chain}{} -j ACCEPT", family.suffix).expect("writing to String");
}

fn render_bypass_tree(family: FamilyProfile<'_>, output: &mut String) {
    for (zone, prefix) in family.zone_rules {
        writeln!(
            output,
            "-A BYP_Z{zone}{} -d {prefix} -j ACTION_BYPASS{}",
            family.suffix, family.suffix
        )
        .expect("writing to String");
    }
    for (zone, prefix) in family.dispatch_rules {
        writeln!(
            output,
            "-A BYPASS_IP{} -d {prefix} -j BYP_Z{zone}{}",
            family.suffix, family.suffix
        )
        .expect("writing to String");
    }
}

fn render_application_chain(family: FamilyProfile<'_>, output: &mut String) {
    if family.plan.features.owner {
        writeln!(
            output,
            "-A APP_CHAIN{} -m owner --uid-owner {} --gid-owner {} -j ACTION_BYPASS{}",
            family.suffix,
            family.plan.owner.uid.as_str(),
            family.plan.owner.gid.as_str(),
            family.suffix
        )
        .expect("writing to String");
    } else if family.plan.features.mark && family.plan.routing_mark.is_some() {
        writeln!(
            output,
            "-A APP_CHAIN{} -m mark --mark {} -j ACTION_BYPASS{}",
            family.suffix,
            family.plan.routing_mark.expect("checked above"),
            family.suffix
        )
        .expect("writing to String");
    }

    let mode = if family.plan.features.owner {
        family.plan.applications.mode
    } else {
        LegacyApplicationMode::All
    };
    match mode {
        LegacyApplicationMode::All => {
            writeln!(output, "-A APP_CHAIN{} -j RETURN", family.suffix).expect("writing to String");
        }
        LegacyApplicationMode::Denylist | LegacyApplicationMode::Allowlist => {
            let target = match mode {
                LegacyApplicationMode::Denylist => "ACTION_BYPASS",
                LegacyApplicationMode::Allowlist => "ACTION_PROXY_OUT",
                LegacyApplicationMode::All => unreachable!(),
            };
            for uid in &family.plan.applications.ordered_uids {
                writeln!(
                    output,
                    "-A APP_CHAIN{} -m owner --uid-owner {uid} -j {target}{}",
                    family.suffix, family.suffix
                )
                .expect("writing to String");
            }
            let final_target = match mode {
                LegacyApplicationMode::Denylist => "ACTION_PROXY_OUT",
                LegacyApplicationMode::Allowlist => "ACCEPT",
                LegacyApplicationMode::All => unreachable!(),
            };
            writeln!(
                output,
                "-A APP_CHAIN{} -j {final_target}{}",
                family.suffix,
                if final_target == "ACCEPT" {
                    ""
                } else {
                    family.suffix
                }
            )
            .expect("writing to String");
        }
    }
}

fn render_divert(family: FamilyProfile<'_>, output: &mut String) {
    writeln!(
        output,
        "-A DIVERT{} -j MARK --set-xmark 0x{:x}/0x{:x}",
        family.suffix, family.proxy_mark, family.plan.mark_mask
    )
    .expect("writing to String");
    writeln!(output, "-A DIVERT{} -j ACCEPT", family.suffix).expect("writing to String");
    writeln!(
        output,
        "-A PROXY_PREROUTING{} -p tcp -m socket --transparent -j DIVERT{}",
        family.suffix, family.suffix
    )
    .expect("writing to String");
    if family.plan.features.socket_udp {
        writeln!(
            output,
            "-A PROXY_PREROUTING{} -p udp -m socket --transparent -j DIVERT{}",
            family.suffix, family.suffix
        )
        .expect("writing to String");
    }
}

fn render_fast_path(family: FamilyProfile<'_>, output: &mut String) {
    if family.plan.features.conntrack {
        for chain in ["PROXY_PREROUTING", "PROXY_OUTPUT"] {
            writeln!(
                output,
                "-A {chain}{} -m conntrack --ctdir REPLY -j ACCEPT",
                family.suffix
            )
            .expect("writing to String");
        }
    }
    if !(family.plan.features.mark && family.plan.features.conntrack) {
        return;
    }
    for chain in ["PROXY_PREROUTING", "PROXY_OUTPUT"] {
        writeln!(
            output,
            "-A {chain}{} -m connmark --mark 0x{:x}/0x{:x} -j ACCEPT",
            family.suffix, family.plan.marks.bypass, family.plan.mark_mask
        )
        .expect("writing to String");
    }
    for protocol in ["tcp", "udp"] {
        writeln!(
            output,
            "-A PROXY_PREROUTING{} -m connmark --mark 0x{:x}/0x{:x} -p {protocol} -j TPROXY --on-port {} --tproxy-mark 0x{:x}/0x{:x}",
            family.suffix,
            family.proxy_mark,
            family.plan.mark_mask,
            family.plan.proxy_port,
            family.proxy_mark,
            family.plan.mark_mask
        )
        .expect("writing to String");
    }
    writeln!(
        output,
        "-A PROXY_PREROUTING{} -m connmark --mark 0x{:x}/0x{:x} -j ACCEPT",
        family.suffix, family.proxy_mark, family.plan.mark_mask
    )
    .expect("writing to String");
    writeln!(
        output,
        "-A PROXY_OUTPUT{} -m connmark --mark 0x{:x}/0x{:x} -j MARK --set-xmark 0x{:x}/0x{:x}",
        family.suffix,
        family.proxy_mark,
        family.plan.mark_mask,
        family.proxy_mark,
        family.plan.mark_mask
    )
    .expect("writing to String");
    writeln!(
        output,
        "-A PROXY_OUTPUT{} -m connmark --mark 0x{:x}/0x{:x} -j ACCEPT",
        family.suffix, family.proxy_mark, family.plan.mark_mask
    )
    .expect("writing to String");
}

fn render_prerouting_policy(family: FamilyProfile<'_>, output: &mut String) {
    writeln!(
        output,
        "-A PROXY_PREROUTING{} -j BYPASS_IP{}",
        family.suffix, family.suffix
    )
    .expect("writing to String");
    writeln!(
        output,
        "-A PROXY_PREROUTING{} -i lo -j ACCEPT",
        family.suffix
    )
    .expect("writing to String");
    for interface in &family.plan.interfaces.excluded {
        writeln!(
            output,
            "-A PROXY_PREROUTING{} -i {} -j ACCEPT",
            family.suffix,
            interface.as_str()
        )
        .expect("writing to String");
    }
    for role in &family.plan.interfaces.roles {
        if let (true, Some(pattern)) = (role.proxy, role.pattern.as_ref()) {
            writeln!(
                output,
                "-A PROXY_PREROUTING{} -i {} -j ACTION_PROXY_PRE{}",
                family.suffix,
                pattern.as_str(),
                family.suffix
            )
            .expect("writing to String");
        }
    }
    writeln!(output, "-A PROXY_PREROUTING{} -j ACCEPT", family.suffix).expect("writing to String");
}

fn render_output_policy(family: FamilyProfile<'_>, output: &mut String) {
    writeln!(
        output,
        "-A PROXY_OUTPUT{} -j BYPASS_IP{}",
        family.suffix, family.suffix
    )
    .expect("writing to String");
    for interface in &family.plan.interfaces.excluded {
        writeln!(
            output,
            "-A PROXY_OUTPUT{} -o {} -j ACTION_BYPASS{}",
            family.suffix,
            interface.as_str(),
            family.suffix
        )
        .expect("writing to String");
    }
    for role in &family.plan.interfaces.roles {
        if let (false, Some(pattern)) = (role.proxy, role.pattern.as_ref()) {
            writeln!(
                output,
                "-A PROXY_OUTPUT{} -o {} -j ACTION_BYPASS{}",
                family.suffix,
                pattern.as_str(),
                family.suffix
            )
            .expect("writing to String");
        }
    }
    writeln!(
        output,
        "-A PROXY_OUTPUT{} -j APP_CHAIN{}",
        family.suffix, family.suffix
    )
    .expect("writing to String");
    writeln!(
        output,
        "-A PROXY_OUTPUT{} -j ACTION_PROXY_OUT{}",
        family.suffix, family.suffix
    )
    .expect("writing to String");
}

fn render_cleanup_mangle(family: FamilyProfile<'_>, output: &mut String) {
    writeln!(output, "-D PREROUTING -j PROXY_PREROUTING{}", family.suffix)
        .expect("writing to String");
    writeln!(output, "-D OUTPUT -j PROXY_OUTPUT{}", family.suffix).expect("writing to String");
    for operation in ["-F", "-X"] {
        for chain in BASE_CHAINS {
            writeln!(output, "{operation} {chain}{}", family.suffix).expect("writing to String");
        }
        for zone in 0..16 {
            writeln!(output, "{operation} BYP_Z{zone}{}", family.suffix)
                .expect("writing to String");
        }
        if divert_enabled(family.plan) {
            writeln!(output, "{operation} DIVERT{}", family.suffix).expect("writing to String");
        }
    }
}

fn render_loopback_filter(
    action: XtablesRestoreAction,
    family: FamilyProfile<'_>,
    output: &mut String,
) {
    output.push_str("*filter\n");
    writeln!(
        output,
        "{} OUTPUT -d {} -p tcp -m owner --uid-owner {} --gid-owner {} -m tcp --dport {} -j REJECT",
        action_token(action),
        family.loopback,
        family.plan.owner.uid.as_str(),
        family.plan.owner.gid.as_str(),
        family.plan.proxy_port
    )
    .expect("writing to String");
    output.push_str("COMMIT\n");
}

fn render_fake_ip(action: XtablesRestoreAction, family: FamilyProfile<'_>, output: &mut String) {
    output.push_str("*nat\n");
    for chain in ["OUTPUT", "PREROUTING"] {
        writeln!(
            output,
            "{} {chain} -d {} -p {} -j DNAT --to-destination {}",
            action_token(action),
            family.fake_ip_range,
            family.fake_ip_protocol,
            family.loopback
        )
        .expect("writing to String");
    }
    output.push_str("COMMIT\n");
}

fn divert_enabled(plan: &LegacyRulesPlan) -> bool {
    plan.performance_mode && plan.features.socket_tcp && plan.features.mark
}

fn render_mss_clamp(action: XtablesRestoreAction, output: &mut String) {
    output.push_str("*mangle\n");
    writeln!(
        output,
        "{} POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        action_token(action)
    )
    .expect("writing to String");
    output.push_str("COMMIT\n");
}

fn action_token(action: XtablesRestoreAction) -> &'static str {
    match action {
        XtablesRestoreAction::Apply => "-A",
        XtablesRestoreAction::Replace => {
            unreachable!("legacy rules renderer rejects replace action before rendering")
        }
        XtablesRestoreAction::Cleanup => "-D",
    }
}
