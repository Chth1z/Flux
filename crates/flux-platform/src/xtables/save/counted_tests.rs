use super::super::XtablesExpectedStatePhase;
use super::*;
use crate::xtables::{
    XtablesRestoreAction, XtablesRestoreArtifact, XtablesRestoreContext, parse_xtables_restore,
};

#[test]
fn exact_ipv4_and_ipv6_expected_chains_preserve_rule_ordered_packets() {
    for (family, chain) in [
        (XtablesRestoreFamily::Ipv4, "FLX4C0000000007"),
        (XtablesRestoreFamily::Ipv6, "FLX6C0000000007"),
    ] {
        let expected = expected_state(family, chain);
        let counted = counted_document(chain, 3, 5);
        assert_eq!(
            project_expected_counted_chain(counted.as_bytes(), family, &expected, chain)
                .expect("exact counted state")
                .as_slice(),
            &[3, 5]
        );

        let changed_counters = counted_document(chain, u64::MAX, 0);
        assert_eq!(
            project_expected_counted_chain(changed_counters.as_bytes(), family, &expected, chain,)
                .expect("counter values do not change structural identity")
                .as_slice(),
            &[u64::MAX, 0]
        );
    }
}

#[test]
fn missing_malformed_duplicate_and_overflowed_rule_prefixes_fail_at_the_source_line() {
    let family = XtablesRestoreFamily::Ipv4;
    let chain = "FLX4C0000000007";
    let expected = expected_state(family, chain);
    for (line, kind) in [
        (
            format!("-A {chain} -p tcp -j ACCEPT"),
            XtablesCountedSaveErrorKind::MissingRuleCounter,
        ),
        (
            format!("[bad:2] -A {chain} -p tcp -j ACCEPT"),
            XtablesCountedSaveErrorKind::InvalidRuleCounter,
        ),
        (
            format!("[1:2] [3:4] -A {chain} -p tcp -j ACCEPT"),
            XtablesCountedSaveErrorKind::InvalidRuleCounter,
        ),
        (
            format!("[18446744073709551616:2] -A {chain} -p tcp -j ACCEPT"),
            XtablesCountedSaveErrorKind::RuleCounterOverflow,
        ),
        (
            format!("[1:18446744073709551616] -A {chain} -p tcp -j ACCEPT"),
            XtablesCountedSaveErrorKind::RuleCounterOverflow,
        ),
    ] {
        let input = format!(
            "*mangle\n:{chain} - [0:0]\n{line}\n[5:320] -A {chain} -p udp -j ACCEPT\nCOMMIT\n"
        );
        let error = project_expected_counted_chain(input.as_bytes(), family, &expected, chain)
            .expect_err("invalid counted rule prefix must fail closed");
        assert_eq!(error.kind(), kind);
        assert_eq!(error.line(), Some(3));
    }
}

#[test]
fn missing_duplicate_substituted_and_extra_owned_rules_are_structural_drift() {
    let family = XtablesRestoreFamily::Ipv4;
    let chain = "FLX4C0000000007";
    let expected = expected_state(family, chain);
    for rules in [
        format!("[3:144] -A {chain} -p tcp -j ACCEPT\n"),
        format!("[3:144] -A {chain} -p tcp -j ACCEPT\n[4:192] -A {chain} -p tcp -j ACCEPT\n"),
        format!("[3:144] -A {chain} -p tcp -j DROP\n[5:320] -A {chain} -p udp -j ACCEPT\n"),
        format!(
            "[3:144] -A {chain} -p tcp -j ACCEPT\n[5:320] -A {chain} -p udp -j ACCEPT\n[1:64] -A {chain} -j RETURN\n"
        ),
    ] {
        let input = format!("*mangle\n:{chain} - [0:0]\n{rules}COMMIT\n");
        assert_eq!(
            project_expected_counted_chain(input.as_bytes(), family, &expected, chain)
                .expect_err("owned structural drift must fail closed")
                .kind(),
            XtablesCountedSaveErrorKind::ExpectedStateMismatch
        );
    }
}

#[test]
fn caller_must_name_one_chain_present_in_the_exact_expected_state() {
    let family = XtablesRestoreFamily::Ipv4;
    let chain = "FLX4C0000000007";
    let expected = expected_state(family, chain);
    let counted = counted_document(chain, 3, 5);
    assert_eq!(
        project_expected_counted_chain(counted.as_bytes(), family, &expected, "FLX4C0000000008",)
            .expect_err("a substituted counted chain cannot be selected")
            .kind(),
        XtablesCountedSaveErrorKind::MissingExpectedChain
    );
}

fn expected_state(family: XtablesRestoreFamily, chain: &str) -> XtablesExpectedState {
    let artifact = apply_artifact(
        format!(
            "*mangle\n:{chain} - [0:0]\n-A {chain} -p tcp -j ACCEPT\n-A {chain} -p udp -j ACCEPT\nCOMMIT\n"
        )
        .as_bytes(),
        family,
    );
    XtablesExpectedState::from_apply_artifacts(
        family,
        XtablesExpectedStatePhase::Active,
        [&artifact],
    )
    .expect("valid exact expected state")
}

fn counted_document(chain: &str, tcp_packets: u64, udp_packets: u64) -> String {
    format!(
        "*mangle\n:{chain} - [9:99]\n[{tcp_packets}:144] -A {chain} -p tcp -j ACCEPT\n[{udp_packets}:320] -A {chain} -p udp -j ACCEPT\nCOMMIT\n"
    )
}

fn apply_artifact(bytes: &[u8], family: XtablesRestoreFamily) -> XtablesRestoreArtifact {
    parse_xtables_restore(
        bytes,
        XtablesRestoreContext::new(XtablesRestoreAction::Apply, family),
    )
    .expect("valid apply artifact")
}
