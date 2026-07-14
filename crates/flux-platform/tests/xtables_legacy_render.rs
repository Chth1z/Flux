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
    LegacyRulesPlan, LegacyRulesRenderRequest, XtablesRestoreAction, XtablesRestoreContext,
    XtablesRestoreFamily, render_legacy_rules_restore,
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
