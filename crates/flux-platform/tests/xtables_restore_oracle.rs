use flux_platform::{
    XtablesRestoreAction, XtablesRestoreContext, XtablesRestoreFamily, parse_xtables_restore,
};

struct OracleCase {
    name: &'static str,
    bytes: &'static [u8],
    context: XtablesRestoreContext,
    digest: &'static str,
    lines: usize,
    transactions: usize,
    chain_declarations: usize,
    commands: usize,
    tokens: usize,
}

const CASES: [OracleCase; 4] = [
    OracleCase {
        name: "maximal-zone-v1-ipv4-apply",
        bytes: include_bytes!(
            "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-apply.restore"
        ),
        context: XtablesRestoreContext::new(
            XtablesRestoreAction::Apply,
            XtablesRestoreFamily::Ipv4,
        ),
        digest: "1dc78d3a2a4121c1ef7aeecea1022af537e7268fde7ba94b8d891faac669e258",
        lines: 104,
        transactions: 4,
        chain_declarations: 24,
        commands: 72,
        tokens: 559,
    },
    OracleCase {
        name: "maximal-zone-v1-ipv4-cleanup",
        bytes: include_bytes!(
            "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-cleanup.restore"
        ),
        context: XtablesRestoreContext::new(
            XtablesRestoreAction::Cleanup,
            XtablesRestoreFamily::Ipv4,
        ),
        digest: "5f534cee13c17ac7c0974c9617aa4b0b8b82f8e183ed1994e8b84585f130a9a2",
        lines: 62,
        transactions: 4,
        chain_declarations: 0,
        commands: 54,
        tokens: 152,
    },
    OracleCase {
        name: "maximal-zone-v1-ipv6-apply",
        bytes: include_bytes!(
            "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv6-apply.restore"
        ),
        context: XtablesRestoreContext::new(
            XtablesRestoreAction::Apply,
            XtablesRestoreFamily::Ipv6,
        ),
        digest: "5357fe418a5ab6baac75364bde87856d5f066c06eb373fbb12deb8e6cbb0b14d",
        lines: 99,
        transactions: 4,
        chain_declarations: 24,
        commands: 67,
        tokens: 529,
    },
    OracleCase {
        name: "maximal-zone-v1-ipv6-cleanup",
        bytes: include_bytes!(
            "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv6-cleanup.restore"
        ),
        context: XtablesRestoreContext::new(
            XtablesRestoreAction::Cleanup,
            XtablesRestoreFamily::Ipv6,
        ),
        digest: "a4ba1f5a955ee208932aec901dac94de56a6ee51966888dc1b53bc128fcd6fcc",
        lines: 62,
        transactions: 4,
        chain_declarations: 0,
        commands: 54,
        tokens: 152,
    },
];

#[test]
fn pinned_shell_oracle_restore_bytes_parse_and_round_trip() {
    for case in CASES {
        let artifact = parse_xtables_restore(case.bytes, case.context)
            .unwrap_or_else(|error| panic!("{} must parse: {error}", case.name));
        assert_eq!(artifact.context(), case.context, "{} context", case.name);
        assert_eq!(
            artifact.render_canonical().as_ref(),
            case.bytes,
            "{} canonical bytes",
            case.name
        );
        let usage = artifact.usage();
        assert_eq!(usage.input_bytes(), case.bytes.len(), "{} bytes", case.name);
        assert_eq!(usage.lines(), case.lines, "{} lines", case.name);
        assert_eq!(
            usage.transactions(),
            case.transactions,
            "{} transactions",
            case.name
        );
        assert_eq!(
            usage.chain_declarations(),
            case.chain_declarations,
            "{} declarations",
            case.name
        );
        assert_eq!(usage.commands(), case.commands, "{} commands", case.name);
        assert_eq!(usage.tokens(), case.tokens, "{} tokens", case.name);
        assert_eq!(
            digest_hex(artifact.digest().as_bytes()),
            case.digest,
            "{} parser digest",
            case.name
        );
    }
}

fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
