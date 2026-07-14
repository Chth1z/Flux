use std::net::IpAddr;

use flux_core::{
    AddressHostFamilySelection, CaptureApplicationMode, CaptureApplicationPolicy,
    CaptureBypassPolicy, CaptureClauseDecision, CaptureGroupId, CaptureInterfaceDirection,
    CaptureInterfacePolicy, CaptureInterfaceSelector, CaptureIpPrefix, CapturePredicate,
    CaptureProtocolSet, CaptureTrafficDomain, CaptureTrafficScope, CaptureUserId,
    CompatibilityEngineCredentials, InterfaceName, NetworkAddressFamily,
    ShadowCaptureProgramRequest, compile_shadow_capture_program,
};
use flux_platform::{
    LegacyApplicationMode, LegacyApplicationPolicy, LegacyInterfacePattern, LegacyInterfacePolicy,
    LegacyInterfaceRole, LegacyKernelFeatures, LegacyMarkValues, LegacyOwnerMatch,
    LegacyOwnerToken, LegacyRulesPlan, LegacyRulesPlanError, LegacyRulesRenderError,
    LegacyRulesRenderRequest, XtablesRestoreAction, XtablesRestoreContext, XtablesRestoreFamily,
    render_legacy_rules_restore,
};

struct FixtureCase {
    name: &'static str,
    context: XtablesRestoreContext,
    expected: &'static [u8],
}

const FIXTURES: [FixtureCase; 4] = [
    FixtureCase {
        name: "maximal-zone-v1-ipv4-apply",
        context: XtablesRestoreContext::new(
            XtablesRestoreAction::Apply,
            XtablesRestoreFamily::Ipv4,
        ),
        expected: include_bytes!(
            "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-apply.restore"
        ),
    },
    FixtureCase {
        name: "maximal-zone-v1-ipv4-cleanup",
        context: XtablesRestoreContext::new(
            XtablesRestoreAction::Cleanup,
            XtablesRestoreFamily::Ipv4,
        ),
        expected: include_bytes!(
            "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-cleanup.restore"
        ),
    },
    FixtureCase {
        name: "maximal-zone-v1-ipv6-apply",
        context: XtablesRestoreContext::new(
            XtablesRestoreAction::Apply,
            XtablesRestoreFamily::Ipv6,
        ),
        expected: include_bytes!(
            "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv6-apply.restore"
        ),
    },
    FixtureCase {
        name: "maximal-zone-v1-ipv6-cleanup",
        context: XtablesRestoreContext::new(
            XtablesRestoreAction::Cleanup,
            XtablesRestoreFamily::Ipv6,
        ),
        expected: include_bytes!(
            "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv6-cleanup.restore"
        ),
    },
];

#[test]
fn maximal_zone_v1_renderer_matches_all_pinned_shell_bytes() {
    let plan = LegacyRulesPlan::maximal_zone_v1();
    for case in FIXTURES {
        let artifact =
            render_legacy_rules_restore(LegacyRulesRenderRequest::new(case.context, &plan))
                .unwrap_or_else(|error| panic!("{} must render: {error}", case.name));
        assert_eq!(artifact.context(), case.context, "{} context", case.name);
        assert_eq!(
            artifact.render_canonical().as_ref(),
            case.expected,
            "{} bytes",
            case.name
        );
        assert_eq!(
            artifact.usage().input_bytes(),
            case.expected.len(),
            "{} byte accounting",
            case.name
        );
    }
}

#[test]
fn maximal_zone_v1_preserves_reviewed_source_shape_even_when_rules_are_redundant() {
    let plan = LegacyRulesPlan::maximal_zone_v1();
    let context =
        XtablesRestoreContext::new(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4);
    let artifact =
        render_legacy_rules_restore(LegacyRulesRenderRequest::new(context, &plan)).unwrap();
    let bytes = artifact.render_canonical();
    let text = std::str::from_utf8(&bytes).unwrap();

    assert_eq!(
        text.matches("-A PROXY_PREROUTING -i wlan+ -j ACCEPT\n")
            .count(),
        2,
        "the frozen source contains the duplicate exclusion"
    );
    assert!(text.contains("-A PROXY_PREROUTING -i rmnet_data+ -j ACTION_PROXY_PRE\n"));
    assert!(text.contains("-A PROXY_PREROUTING -i wlan2 -j ACTION_PROXY_PRE\n"));
    assert!(text.contains("-A PROXY_OUTPUT -o wlan0 -j ACTION_BYPASS\n"));
    assert!(text.contains("-A BYP_Z15 -d 255.255.255.255/32 -j ACTION_BYPASS\n"));

    let first_uid = text.find("--uid-owner 210124").unwrap();
    let second_uid = text.find("--uid-owner 1010124").unwrap();
    let third_uid = text.find("--uid-owner 210123").unwrap();
    let fourth_uid = text.find("--uid-owner 1010123").unwrap();
    assert!(first_uid < second_uid && second_uid < third_uid && third_uid < fourth_uid);
}

#[test]
fn shadow_normalization_cannot_be_used_to_reconstruct_the_legacy_source_shape() {
    let excluded = [prefix_interface("wlan"), prefix_interface("rmnet")];
    let interfaces = CaptureInterfacePolicy::new(
        [excluded[0], excluded[1], excluded[0]],
        [prefix_interface("rmnet_data"), exact_interface("wlan2")],
        [exact_interface("wlan0"), prefix_interface("rndis")],
    )
    .unwrap();
    let applications = CaptureApplicationPolicy::new(
        CaptureApplicationMode::Allowlist,
        [210_124, 1_010_124, 210_123, 1_010_123].map(|value| CaptureUserId::new(value).unwrap()),
    )
    .unwrap();
    let report = compile_shadow_capture_program(ShadowCaptureProgramRequest::new(
        CaptureTrafficScope::new(AddressHostFamilySelection::DualStack, true, true).unwrap(),
        CompatibilityEngineCredentials::new(
            CaptureUserId::new(1000).unwrap(),
            CaptureGroupId::new(1000).unwrap(),
        ),
        CaptureBypassPolicy::new([prefix("255.255.255.255/32")]).unwrap(),
        None,
        interfaces,
        applications,
        CaptureProtocolSet::TCP_AND_UDP,
    ))
    .unwrap();

    let forwarded = report
        .artifact()
        .programs()
        .iter()
        .find(|program| {
            program.family() == NetworkAddressFamily::Ipv4
                && program.domain() == CaptureTrafficDomain::ForwardedIngress
        })
        .unwrap();
    assert!(
        forwarded
            .clauses()
            .iter()
            .all(|clause| clause.decision() != CaptureClauseDecision::Proxy),
        "both configured forwarded selectors are covered by exclusions"
    );

    let local = report
        .artifact()
        .programs()
        .iter()
        .find(|program| {
            program.family() == NetworkAddressFamily::Ipv4
                && program.domain() == CaptureTrafficDomain::LocalOutput
        })
        .unwrap();
    let application_uids = local
        .clauses()
        .iter()
        .find_map(|clause| match clause.predicate() {
            CapturePredicate::LocalUidNotIn(uids) => Some(
                uids.iter()
                    .copied()
                    .map(CaptureUserId::get)
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        application_uids,
        [210_123, 210_124, 1_010_123, 1_010_124],
        "the shadow policy canonicalizes UID order"
    );

    let output_selectors = local
        .clauses()
        .iter()
        .filter_map(|clause| match clause.predicate() {
            CapturePredicate::InterfaceMatches {
                direction: CaptureInterfaceDirection::Output,
                selectors,
            } => Some(selectors.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(output_selectors.len(), 3);
    assert!(output_selectors.contains(&prefix_interface("wlan")));
    assert!(output_selectors.contains(&prefix_interface("rmnet")));
    assert!(output_selectors.contains(&prefix_interface("rndis")));
    assert!(!output_selectors.contains(&exact_interface("wlan0")));

    assert!(local.clauses().iter().all(|clause| {
        !matches!(clause.predicate(), CapturePredicate::DestinationPrefixes(prefixes)
            if prefixes.iter().any(|prefix| prefix.to_string() == "255.255.255.255/32"))
    }));
    assert!(local.clauses().iter().any(|clause| matches!(
        clause.predicate(),
        CapturePredicate::ProtocolNotIn(protocols)
            if *protocols == CaptureProtocolSet::TCP_AND_UDP
    )));
}

#[test]
fn general_renderer_covers_minimal_application_and_feature_branches() {
    let plan = general_plan(
        LegacyApplicationMode::All,
        [],
        LegacyKernelFeatures::new(true, false, false, false, false, true, true),
        false,
        false,
        false,
        None,
    );
    let apply = render_text(
        &plan,
        XtablesRestoreAction::Apply,
        XtablesRestoreFamily::Ipv4,
    );
    assert!(
        apply
            .contains("-A APP_CHAIN -m owner --uid-owner root --gid-owner root -j ACTION_BYPASS\n")
    );
    assert!(apply.contains("-A APP_CHAIN -j RETURN\n"));
    assert!(!apply.contains("CONNMARK"));
    assert!(!apply.contains("--set-xmark"));
    assert!(!apply.contains(":DIVERT"));
    assert!(!apply.contains("TCPMSS"));

    let cleanup = render_text(
        &plan,
        XtablesRestoreAction::Cleanup,
        XtablesRestoreFamily::Ipv4,
    );
    assert!(!cleanup.contains("DIVERT"));
    assert!(!cleanup.contains("POSTROUTING"));
    assert_eq!(
        render_legacy_rules_restore(LegacyRulesRenderRequest::new(
            XtablesRestoreContext::new(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv6,),
            &plan,
        )),
        Err(LegacyRulesRenderError::FamilyDisabled)
    );
}

#[test]
fn general_renderer_preserves_denylist_and_no_owner_fallback_semantics() {
    let denylist = general_plan(
        LegacyApplicationMode::Denylist,
        [10_123, 110_123],
        LegacyKernelFeatures::new(true, true, true, false, false, true, true),
        false,
        false,
        true,
        None,
    );
    let denylist = render_text(
        &denylist,
        XtablesRestoreAction::Apply,
        XtablesRestoreFamily::Ipv4,
    );
    assert!(denylist.contains("-A APP_CHAIN -m owner --uid-owner 10123 -j ACTION_BYPASS\n"));
    assert!(denylist.contains("-A APP_CHAIN -m owner --uid-owner 110123 -j ACTION_BYPASS\n"));
    assert!(denylist.contains("-A APP_CHAIN -j ACTION_PROXY_OUT\n"));

    let no_owner = general_plan(
        LegacyApplicationMode::Allowlist,
        [10_123],
        LegacyKernelFeatures::new(false, true, false, false, false, true, true),
        false,
        false,
        true,
        Some(77),
    );
    assert!(!no_owner.production_eligible());
    let no_owner = render_text(
        &no_owner,
        XtablesRestoreAction::Apply,
        XtablesRestoreFamily::Ipv4,
    );
    assert!(no_owner.contains("-A APP_CHAIN -m mark --mark 77 -j ACTION_BYPASS\n"));
    assert!(no_owner.contains("-A APP_CHAIN -j RETURN\n"));
    assert!(!no_owner.contains("--uid-owner 10123"));
    assert!(!no_owner.contains("*filter\n"));
}

#[test]
fn general_renderer_covers_udp_divert_and_ipv6_nat_gate() {
    let plan = general_plan(
        LegacyApplicationMode::Allowlist,
        [10_123],
        LegacyKernelFeatures::new(true, true, true, true, true, false, true),
        true,
        true,
        true,
        None,
    );
    let ipv6 = render_text(
        &plan,
        XtablesRestoreAction::Apply,
        XtablesRestoreFamily::Ipv6,
    );
    assert!(ipv6.contains(":DIVERT6 - [0:0]\n"));
    assert!(ipv6.contains("-A PROXY_PREROUTING6 -p udp -m socket --transparent -j DIVERT6\n"));
    assert!(!ipv6.contains("*nat\n"));
    assert!(ipv6.contains("TCPMSS --clamp-mss-to-pmtu\n"));
}

#[test]
fn general_renderer_rejects_invalid_source_tokens_and_ranges() {
    assert_eq!(
        LegacyOwnerToken::new("-1"),
        Err(LegacyRulesPlanError::InvalidOwnerToken)
    );
    assert_eq!(
        LegacyInterfacePattern::new("+"),
        Err(LegacyRulesPlanError::InvalidInterfacePattern)
    );
    assert_eq!(
        LegacyInterfacePattern::new("wlan++"),
        Err(LegacyRulesPlanError::InvalidInterfacePattern)
    );

    let owner = LegacyOwnerMatch::new(
        LegacyOwnerToken::new("root").unwrap(),
        LegacyOwnerToken::new("root").unwrap(),
    );
    let applications = LegacyApplicationPolicy::new(LegacyApplicationMode::All, []).unwrap();
    let interfaces = empty_interfaces();
    let features = LegacyKernelFeatures::new(true, true, true, false, false, true, true);
    assert_eq!(
        LegacyRulesPlan::new(
            0,
            0xff,
            LegacyMarkValues::legacy_defaults(),
            None,
            owner.clone(),
            applications.clone(),
            interfaces.clone(),
            features,
            false,
            false,
            false,
            "198.18.0.0/15",
            "fc00::/18",
        ),
        Err(LegacyRulesPlanError::InvalidProxyPort)
    );
    assert_eq!(
        LegacyRulesPlan::new(
            1536,
            0,
            LegacyMarkValues::legacy_defaults(),
            None,
            owner.clone(),
            applications.clone(),
            interfaces.clone(),
            features,
            false,
            false,
            false,
            "198.18.0.0/15",
            "fc00::/18",
        ),
        Err(LegacyRulesPlanError::InvalidMarkMask)
    );
    assert_eq!(
        LegacyRulesPlan::new(
            1536,
            0xff,
            LegacyMarkValues::legacy_defaults(),
            None,
            owner,
            applications,
            interfaces,
            features,
            false,
            false,
            false,
            "fc00::/18",
            "fc00::/18",
        ),
        Err(LegacyRulesPlanError::InvalidFakeIp)
    );
}

#[test]
fn mark_values_must_fit_the_mask_and_remain_distinct_from_bypass() {
    for (mask, marks) in [
        (0, LegacyMarkValues::legacy_defaults()),
        (1, LegacyMarkValues::legacy_defaults()),
        (0xff, LegacyMarkValues::new(0x14, 0x19, 0x14)),
        (0xff, LegacyMarkValues::new(0x114, 0x19, 0x11)),
    ] {
        assert_eq!(
            plan_with_marks(mask, marks),
            Err(LegacyRulesPlanError::InvalidMarkMask),
            "mask={mask:#x} marks={marks:?}"
        );
    }

    let marks = LegacyMarkValues::new(0x24, 0x29, 0x21);
    let plan = plan_with_marks(0xff, marks).unwrap();
    let ipv4 = render_text(
        &plan,
        XtablesRestoreAction::Apply,
        XtablesRestoreFamily::Ipv4,
    );
    assert!(ipv4.contains("--set-xmark 0x21/0xff"));
    assert!(ipv4.contains("--tproxy-mark 0x24/0xff"));
    let ipv6 = render_text(
        &plan,
        XtablesRestoreAction::Apply,
        XtablesRestoreFamily::Ipv6,
    );
    assert!(ipv6.contains("--tproxy-mark 0x29/0xff"));
}

fn exact_interface(name: &str) -> CaptureInterfaceSelector {
    CaptureInterfaceSelector::exact(InterfaceName::new(name.as_bytes()).unwrap())
}

fn prefix_interface(name: &str) -> CaptureInterfaceSelector {
    CaptureInterfaceSelector::prefix(InterfaceName::new(name.as_bytes()).unwrap())
}

fn prefix(value: &str) -> CaptureIpPrefix {
    let (address, length) = value.split_once('/').unwrap();
    CaptureIpPrefix::new(
        address.parse::<IpAddr>().unwrap(),
        length.parse::<u8>().unwrap(),
    )
    .unwrap()
}

fn general_plan<const N: usize>(
    mode: LegacyApplicationMode,
    uids: [u32; N],
    features: LegacyKernelFeatures,
    performance_mode: bool,
    mss_clamp: bool,
    ipv6_enabled: bool,
    routing_mark: Option<u32>,
) -> LegacyRulesPlan {
    LegacyRulesPlan::new(
        1536,
        0xff,
        LegacyMarkValues::legacy_defaults(),
        routing_mark,
        LegacyOwnerMatch::new(
            LegacyOwnerToken::new("root").unwrap(),
            LegacyOwnerToken::new("root").unwrap(),
        ),
        LegacyApplicationPolicy::new(mode, uids).unwrap(),
        LegacyInterfacePolicy::new(
            [pattern("wlan+")],
            LegacyInterfaceRole::new(Some(pattern("rmnet_data+")), true),
            LegacyInterfaceRole::new(Some(pattern("wlan0")), false),
            LegacyInterfaceRole::new(Some(pattern("wlan2")), true),
            LegacyInterfaceRole::new(Some(pattern("rndis+")), false),
        )
        .unwrap(),
        features,
        performance_mode,
        mss_clamp,
        ipv6_enabled,
        "198.18.0.0/15",
        "fc00::/18",
    )
    .unwrap()
}

fn plan_with_marks(
    mask: u32,
    marks: LegacyMarkValues,
) -> Result<LegacyRulesPlan, LegacyRulesPlanError> {
    LegacyRulesPlan::new(
        1536,
        mask,
        marks,
        None,
        LegacyOwnerMatch::new(
            LegacyOwnerToken::new("root").unwrap(),
            LegacyOwnerToken::new("root").unwrap(),
        ),
        LegacyApplicationPolicy::new(LegacyApplicationMode::All, []).unwrap(),
        empty_interfaces(),
        LegacyKernelFeatures::new(true, true, true, false, false, true, true),
        false,
        false,
        true,
        "198.18.0.0/15",
        "fc00::/18",
    )
}

fn empty_interfaces() -> LegacyInterfacePolicy {
    let empty = LegacyInterfaceRole::new(None, false);
    LegacyInterfacePolicy::new([], empty.clone(), empty.clone(), empty.clone(), empty).unwrap()
}

fn pattern(value: &str) -> LegacyInterfacePattern {
    LegacyInterfacePattern::new(value).unwrap()
}

fn render_text(
    plan: &LegacyRulesPlan,
    action: XtablesRestoreAction,
    family: XtablesRestoreFamily,
) -> String {
    let artifact = render_legacy_rules_restore(LegacyRulesRenderRequest::new(
        XtablesRestoreContext::new(action, family),
        plan,
    ))
    .unwrap();
    String::from_utf8(artifact.render_canonical().into_vec()).unwrap()
}
