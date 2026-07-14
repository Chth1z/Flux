use std::error::Error;
use std::fmt;
use std::fmt::Write as _;
use std::net::IpAddr;

use super::{
    XtablesRestoreAction, XtablesRestoreArtifact, XtablesRestoreContext, XtablesRestoreFamily,
    XtablesRestoreParseError, parse_xtables_restore,
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
    InvalidRenderedArtifact(XtablesRestoreParseError),
}

impl LegacyRulesRenderError {
    #[must_use]
    pub const fn parse_error(&self) -> Option<&XtablesRestoreParseError> {
        match self {
            Self::FamilyDisabled => None,
            Self::InvalidRenderedArtifact(source) => Some(source),
        }
    }
}

impl fmt::Display for LegacyRulesRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FamilyDisabled => formatter.write_str("legacy IPv6 restore family is disabled"),
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
            Self::FamilyDisabled => None,
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
    let mut output = String::new();
    render_plan(request.context, request.plan, &mut output);
    parse_xtables_restore(output.as_bytes(), request.context)
        .map_err(LegacyRulesRenderError::InvalidRenderedArtifact)
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

const fn action_token(action: XtablesRestoreAction) -> &'static str {
    match action {
        XtablesRestoreAction::Apply => "-A",
        XtablesRestoreAction::Cleanup => "-D",
    }
}
