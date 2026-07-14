use std::error::Error;
use std::fmt;
use std::fmt::Write as _;

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

const APPLICATION_UIDS: &[u32] = &[210_124, 1_010_124, 210_123, 1_010_123];
const EXCLUDED_INTERFACES: &[&str] = &["wlan+", "rmnet+", "wlan+"];
const FORWARDED_PROXY_INTERFACES: &[&str] = &["rmnet_data+", "wlan2"];
const LOCAL_BYPASS_INTERFACES: &[&str] = &["wlan0", "rndis+"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacyRulesProfile {
    MaximalZoneV1,
}

/// Sealed, source-shape compatibility inputs for the bounded legacy renderer.
///
/// The plan deliberately preserves source ordering, duplicate rules, covered prefixes, and other
/// byte-significant details that the backend-neutral shadow Capture Program canonicalizes away.
/// It carries no Generation identity, writer authority, execution path, or activation conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyRulesPlan {
    profile: LegacyRulesProfile,
}

impl LegacyRulesPlan {
    /// The only admitted profile: the exact reviewed `maximal-zone-v1` oracle input snapshot.
    #[must_use]
    pub const fn maximal_zone_v1() -> Self {
        Self {
            profile: LegacyRulesProfile::MaximalZoneV1,
        }
    }
}

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
pub struct LegacyRulesRenderError {
    source: XtablesRestoreParseError,
}

impl LegacyRulesRenderError {
    #[must_use]
    pub const fn parse_error(&self) -> &XtablesRestoreParseError {
        &self.source
    }
}

impl fmt::Display for LegacyRulesRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "rendered legacy xtables source shape was not canonical: {}",
            self.source
        )
    }
}

impl Error for LegacyRulesRenderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
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
    let mut output = String::new();
    match request.plan.profile {
        LegacyRulesProfile::MaximalZoneV1 => render_maximal_zone_v1(request.context, &mut output),
    }
    parse_xtables_restore(output.as_bytes(), request.context)
        .map_err(|source| LegacyRulesRenderError { source })
}

fn render_maximal_zone_v1(context: XtablesRestoreContext, output: &mut String) {
    let family = FamilyProfile::for_family(context.family());
    render_mangle(context.action(), family, output);
    render_loopback_filter(context.action(), family, output);
    render_fake_ip(context.action(), family, output);
    render_mss_clamp(context.action(), output);
}

#[derive(Clone, Copy)]
struct FamilyProfile {
    suffix: &'static str,
    proxy_mark: u32,
    loopback: &'static str,
    fake_ip_range: &'static str,
    fake_ip_protocol: &'static str,
    zone_rules: &'static [(u8, &'static str)],
    dispatch_rules: &'static [(u8, &'static str)],
}

impl FamilyProfile {
    const fn for_family(family: XtablesRestoreFamily) -> Self {
        match family {
            XtablesRestoreFamily::Ipv4 => Self {
                suffix: "",
                proxy_mark: 0x14,
                loopback: "127.0.0.1",
                fake_ip_range: "198.18.0.0/15",
                fake_ip_protocol: "icmp",
                zone_rules: IPV4_ZONE_RULES,
                dispatch_rules: IPV4_DISPATCH_RULES,
            },
            XtablesRestoreFamily::Ipv6 => Self {
                suffix: "6",
                proxy_mark: 0x19,
                loopback: "::1",
                fake_ip_range: "fc00::/18",
                fake_ip_protocol: "ipv6-icmp",
                zone_rules: IPV6_ZONE_RULES,
                dispatch_rules: IPV6_DISPATCH_RULES,
            },
        }
    }
}

fn render_mangle(action: XtablesRestoreAction, family: FamilyProfile, output: &mut String) {
    output.push_str("*mangle\n");
    match action {
        XtablesRestoreAction::Apply => render_apply_mangle(family, output),
        XtablesRestoreAction::Cleanup => render_cleanup_mangle(family, output),
    }
    output.push_str("COMMIT\n");
}

fn render_apply_mangle(family: FamilyProfile, output: &mut String) {
    for chain in BASE_CHAINS {
        writeln!(output, ":{chain}{} - [0:0]", family.suffix).expect("writing to String");
    }
    for zone in 0..16 {
        writeln!(output, ":BYP_Z{zone}{} - [0:0]", family.suffix).expect("writing to String");
    }
    writeln!(output, ":DIVERT{} - [0:0]", family.suffix).expect("writing to String");

    writeln!(
        output,
        "-A ACTION_BYPASS{} -j CONNMARK --set-xmark 0x11/0xff",
        family.suffix
    )
    .expect("writing to String");
    writeln!(output, "-A ACTION_BYPASS{} -j ACCEPT", family.suffix).expect("writing to String");

    render_proxy_action("ACTION_PROXY_PRE", true, family, output);
    render_proxy_action("ACTION_PROXY_OUT", false, family, output);
    render_bypass_tree(family, output);
    render_application_chain(family, output);
    render_divert(family, output);
    render_fast_path(family, output);
    render_prerouting_policy(family, output);
    render_output_policy(family, output);

    writeln!(output, "-I PREROUTING -j PROXY_PREROUTING{}", family.suffix)
        .expect("writing to String");
    writeln!(output, "-I OUTPUT -j PROXY_OUTPUT{}", family.suffix).expect("writing to String");
}

fn render_proxy_action(chain: &str, tproxy: bool, family: FamilyProfile, output: &mut String) {
    writeln!(
        output,
        "-A {chain}{} -j CONNMARK --set-xmark 0x{:x}/0xff",
        family.suffix, family.proxy_mark
    )
    .expect("writing to String");
    writeln!(
        output,
        "-A {chain}{} -j MARK --set-xmark 0x{:x}/0xff",
        family.suffix, family.proxy_mark
    )
    .expect("writing to String");
    if tproxy {
        for protocol in ["tcp", "udp"] {
            writeln!(
                output,
                "-A {chain}{} -p {protocol} -j TPROXY --on-port 1536 --tproxy-mark 0x{:x}/0xff",
                family.suffix, family.proxy_mark
            )
            .expect("writing to String");
        }
    }
    writeln!(output, "-A {chain}{} -j ACCEPT", family.suffix).expect("writing to String");
}

fn render_bypass_tree(family: FamilyProfile, output: &mut String) {
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

fn render_application_chain(family: FamilyProfile, output: &mut String) {
    writeln!(
        output,
        "-A APP_CHAIN{} -m owner --uid-owner 1000 --gid-owner 1000 -j ACTION_BYPASS{}",
        family.suffix, family.suffix
    )
    .expect("writing to String");
    for uid in APPLICATION_UIDS {
        writeln!(
            output,
            "-A APP_CHAIN{} -m owner --uid-owner {uid} -j ACTION_PROXY_OUT{}",
            family.suffix, family.suffix
        )
        .expect("writing to String");
    }
    writeln!(output, "-A APP_CHAIN{} -j ACCEPT", family.suffix).expect("writing to String");
}

fn render_divert(family: FamilyProfile, output: &mut String) {
    writeln!(
        output,
        "-A DIVERT{} -j MARK --set-xmark 0x{:x}/0xff",
        family.suffix, family.proxy_mark
    )
    .expect("writing to String");
    writeln!(output, "-A DIVERT{} -j ACCEPT", family.suffix).expect("writing to String");
    writeln!(
        output,
        "-A PROXY_PREROUTING{} -p tcp -m socket --transparent -j DIVERT{}",
        family.suffix, family.suffix
    )
    .expect("writing to String");
}

fn render_fast_path(family: FamilyProfile, output: &mut String) {
    for chain in ["PROXY_PREROUTING", "PROXY_OUTPUT"] {
        writeln!(
            output,
            "-A {chain}{} -m conntrack --ctdir REPLY -j ACCEPT",
            family.suffix
        )
        .expect("writing to String");
    }
    for chain in ["PROXY_PREROUTING", "PROXY_OUTPUT"] {
        writeln!(
            output,
            "-A {chain}{} -m connmark --mark 0x11/0xff -j ACCEPT",
            family.suffix
        )
        .expect("writing to String");
    }
    for protocol in ["tcp", "udp"] {
        writeln!(
            output,
            "-A PROXY_PREROUTING{} -m connmark --mark 0x{:x}/0xff -p {protocol} -j TPROXY --on-port 1536 --tproxy-mark 0x{:x}/0xff",
            family.suffix, family.proxy_mark, family.proxy_mark
        )
        .expect("writing to String");
    }
    writeln!(
        output,
        "-A PROXY_PREROUTING{} -m connmark --mark 0x{:x}/0xff -j ACCEPT",
        family.suffix, family.proxy_mark
    )
    .expect("writing to String");
    writeln!(
        output,
        "-A PROXY_OUTPUT{} -m connmark --mark 0x{:x}/0xff -j MARK --set-xmark 0x{:x}/0xff",
        family.suffix, family.proxy_mark, family.proxy_mark
    )
    .expect("writing to String");
    writeln!(
        output,
        "-A PROXY_OUTPUT{} -m connmark --mark 0x{:x}/0xff -j ACCEPT",
        family.suffix, family.proxy_mark
    )
    .expect("writing to String");
}

fn render_prerouting_policy(family: FamilyProfile, output: &mut String) {
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
    for interface in EXCLUDED_INTERFACES {
        writeln!(
            output,
            "-A PROXY_PREROUTING{} -i {interface} -j ACCEPT",
            family.suffix
        )
        .expect("writing to String");
    }
    for interface in FORWARDED_PROXY_INTERFACES {
        writeln!(
            output,
            "-A PROXY_PREROUTING{} -i {interface} -j ACTION_PROXY_PRE{}",
            family.suffix, family.suffix
        )
        .expect("writing to String");
    }
    writeln!(output, "-A PROXY_PREROUTING{} -j ACCEPT", family.suffix).expect("writing to String");
}

fn render_output_policy(family: FamilyProfile, output: &mut String) {
    writeln!(
        output,
        "-A PROXY_OUTPUT{} -j BYPASS_IP{}",
        family.suffix, family.suffix
    )
    .expect("writing to String");
    for interface in EXCLUDED_INTERFACES {
        writeln!(
            output,
            "-A PROXY_OUTPUT{} -o {interface} -j ACTION_BYPASS{}",
            family.suffix, family.suffix
        )
        .expect("writing to String");
    }
    for interface in LOCAL_BYPASS_INTERFACES {
        writeln!(
            output,
            "-A PROXY_OUTPUT{} -o {interface} -j ACTION_BYPASS{}",
            family.suffix, family.suffix
        )
        .expect("writing to String");
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

fn render_cleanup_mangle(family: FamilyProfile, output: &mut String) {
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
        writeln!(output, "{operation} DIVERT{}", family.suffix).expect("writing to String");
    }
}

fn render_loopback_filter(
    action: XtablesRestoreAction,
    family: FamilyProfile,
    output: &mut String,
) {
    output.push_str("*filter\n");
    writeln!(
        output,
        "{} OUTPUT -d {} -p tcp -m owner --uid-owner 1000 --gid-owner 1000 -m tcp --dport 1536 -j REJECT",
        action_token(action),
        family.loopback
    )
    .expect("writing to String");
    output.push_str("COMMIT\n");
}

fn render_fake_ip(action: XtablesRestoreAction, family: FamilyProfile, output: &mut String) {
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
