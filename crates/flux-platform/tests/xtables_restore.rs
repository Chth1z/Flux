use flux_platform::{
    MAX_XTABLES_RESTORE_BYTES, MAX_XTABLES_RESTORE_CHAIN_BYTES, MAX_XTABLES_RESTORE_COMMANDS,
    MAX_XTABLES_RESTORE_LINE_BYTES, MAX_XTABLES_RESTORE_LINES, MAX_XTABLES_RESTORE_TOKEN_BYTES,
    MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND, MAX_XTABLES_RESTORE_TRANSACTIONS,
    XTABLES_RESTORE_SCHEMA_VERSION, XtablesRestoreAction, XtablesRestoreCommandKind,
    XtablesRestoreContext, XtablesRestoreEntry, XtablesRestoreFamily, XtablesRestoreLimit,
    XtablesRestoreParseErrorKind, XtablesRestoreTable, parse_xtables_restore,
};

const IPV4_APPLY: &[u8] = br#"*mangle
:PROXY_PREROUTING - [0:0]
:APP_CHAIN - [0:0]
:ACTION_BYPASS - [0:0]
:BYP_Z6 - [0:0]
-A BYP_Z6 -d 100.64.0.0/10 -j ACTION_BYPASS
-A APP_CHAIN -m owner --uid-owner 1000 --gid-owner 1000 -j ACTION_BYPASS
-A APP_CHAIN -j RETURN
-A PROXY_PREROUTING -j BYPASS_IP
-A PROXY_PREROUTING -i wlan+ -j ACCEPT
-A PROXY_PREROUTING -i wlan+ -j ACCEPT
-I PREROUTING -j PROXY_PREROUTING
COMMIT
*filter
-A OUTPUT -d 127.0.0.1 -p tcp -m owner --uid-owner 1000 --gid-owner 1000 -m tcp --dport 7893 -j REJECT
COMMIT
*nat
-A OUTPUT -d 198.18.0.0/15 -p icmp -j DNAT --to-destination 127.0.0.1
-A PREROUTING -d 198.18.0.0/15 -p icmp -j DNAT --to-destination 127.0.0.1
COMMIT
*mangle
-A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
COMMIT
"#;

const IPV6_APPLY: &[u8] = br#"*mangle
:BYP_Z06 - [0:0]
:BYP_Z66 - [0:0]
:BYP_Z156 - [0:0]
:BYPASS_IP6 - [0:0]
:ACTION_BYPASS6 - [0:0]
-A BYP_Z06 -d ::/128 -j ACTION_BYPASS6
-A BYP_Z156 -d ff00::/8 -j ACTION_BYPASS6
-A BYPASS_IP6 -d 6000::/4 -j BYP_Z66
-A ACTION_BYPASS6 -j CONNMARK --set-xmark 0x11/0xff
-I OUTPUT -j PROXY_OUTPUT6
COMMIT
*nat
-A OUTPUT -d fc00::/18 -p ipv6-icmp -j DNAT --to-destination ::1
COMMIT
"#;

const IPV4_CLEANUP: &[u8] = br#"*mangle
-D PREROUTING -j PROXY_PREROUTING
-D OUTPUT -j PROXY_OUTPUT
-F PROXY_PREROUTING
-F PROXY_OUTPUT
-X PROXY_PREROUTING
-X PROXY_OUTPUT
COMMIT
*filter
-D OUTPUT -d 127.0.0.1 -p tcp -m owner --uid-owner 1000 --gid-owner 1000 -m tcp --dport 7893 -j REJECT
COMMIT
*mangle
-D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
COMMIT
"#;

fn context(action: XtablesRestoreAction, family: XtablesRestoreFamily) -> XtablesRestoreContext {
    XtablesRestoreContext::new(action, family)
}

fn assert_error(
    input: &[u8],
    context: XtablesRestoreContext,
    expected: XtablesRestoreParseErrorKind,
    line: Option<usize>,
) {
    let error = parse_xtables_restore(input, context).expect_err("document must be rejected");
    assert_eq!(error.kind(), expected);
    assert_eq!(error.line(), line);
}

#[test]
fn current_shaped_apply_document_round_trips_and_preserves_repeated_tables_and_duplicates() {
    let artifact = parse_xtables_restore(
        IPV4_APPLY,
        context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4),
    )
    .expect("current-shaped IPv4 apply document");

    assert_eq!(artifact.schema_version(), XTABLES_RESTORE_SCHEMA_VERSION);
    assert_eq!(artifact.render_canonical().as_ref(), IPV4_APPLY);
    assert_eq!(artifact.usage().input_bytes(), IPV4_APPLY.len());
    assert_eq!(artifact.usage().lines(), 23);
    assert_eq!(artifact.usage().transactions(), 4);
    assert_eq!(artifact.usage().chain_declarations(), 4);
    assert_eq!(artifact.usage().commands(), 11);
    assert_eq!(
        artifact
            .transactions()
            .iter()
            .map(|transaction| transaction.table())
            .collect::<Vec<_>>(),
        [
            XtablesRestoreTable::Mangle,
            XtablesRestoreTable::Filter,
            XtablesRestoreTable::Nat,
            XtablesRestoreTable::Mangle,
        ]
    );

    let first = &artifact.transactions()[0];
    let commands = first
        .entries()
        .iter()
        .filter_map(|entry| match entry {
            XtablesRestoreEntry::Command(command) => Some(command),
            XtablesRestoreEntry::ChainDeclaration(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(commands[4], commands[5], "duplicate rules remain distinct");
    assert_eq!(commands[6].kind(), XtablesRestoreCommandKind::Insert);
    assert_eq!(commands[6].chain(), "PREROUTING");
    assert_eq!(
        commands[1]
            .arguments()
            .iter()
            .map(|token| token.as_str())
            .collect::<Vec<_>>(),
        [
            "-m",
            "owner",
            "--uid-owner",
            "1000",
            "--gid-owner",
            "1000",
            "-j",
            "ACTION_BYPASS",
        ]
    );
}

#[test]
fn closed_argument_grammar_accepts_every_current_mangle_option_shape() {
    let input = br#"*mangle
-A PROXY_PREROUTING -m conntrack --ctdir REPLY -j ACCEPT
-A PROXY_PREROUTING -m connmark --mark 0x11/0xff -j ACCEPT
-A ACTION_PROXY_PRE -j CONNMARK --set-xmark 0x14/0xff
-A ACTION_PROXY_PRE -j MARK --set-xmark 0x14/0xff
-A ACTION_PROXY_PRE -p tcp -j TPROXY --on-port 7893 --tproxy-mark 0x14/0xff
-A PROXY_PREROUTING -p tcp -m socket --transparent -j DIVERT
-A PROXY_PREROUTING -i rmnet+ -j ACTION_PROXY_PRE
-A PROXY_OUTPUT -o wlan+ -j ACTION_BYPASS
COMMIT
"#;
    let artifact = parse_xtables_restore(
        input,
        context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4),
    )
    .expect("all current mangle option shapes");
    assert_eq!(artifact.render_canonical().as_ref(), input);
    assert_eq!(artifact.usage().commands(), 8);
}

#[test]
fn ipv6_family_accepts_compressed_zone_names_and_rejects_ipv4_context() {
    let artifact = parse_xtables_restore(
        IPV6_APPLY,
        context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv6),
    )
    .expect("current-shaped IPv6 apply document");
    assert_eq!(artifact.render_canonical().as_ref(), IPV6_APPLY);
    assert_eq!(artifact.transactions().len(), 2);

    assert_error(
        IPV6_APPLY,
        context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::FamilyMismatch {
            expected: XtablesRestoreFamily::Ipv4,
        },
        Some(2),
    );
    assert_error(
        b"*mangle\n-A OUTPUT -d 127.0.0.1 -p icmp -j ACCEPT\nCOMMIT\n",
        context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv6),
        XtablesRestoreParseErrorKind::FamilyMismatch {
            expected: XtablesRestoreFamily::Ipv6,
        },
        Some(2),
    );
    assert_error(
        b"*mangle\n-A OUTPUT -d ::1 -p ipv6-icmp -j ACCEPT\nCOMMIT\n",
        context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::FamilyMismatch {
            expected: XtablesRestoreFamily::Ipv4,
        },
        Some(2),
    );
}

#[test]
fn canonical_capture_chain_names_are_family_scoped_and_sealed() {
    for (family_digit, family, other_family) in [
        ('4', XtablesRestoreFamily::Ipv4, XtablesRestoreFamily::Ipv6),
        ('6', XtablesRestoreFamily::Ipv6, XtablesRestoreFamily::Ipv4),
    ] {
        for role in ['F', 'O', 'P'] {
            let chain = format!("FLX{family_digit}{role}0000000001");
            let input = format!("*mangle\n:{chain} - [0:0]\nCOMMIT\n");
            let artifact = parse_xtables_restore(
                input.as_bytes(),
                context(XtablesRestoreAction::Apply, family),
            )
            .expect("canonical Capture chain name");
            assert_eq!(artifact.render_canonical().as_ref(), input.as_bytes());
            assert_error(
                input.as_bytes(),
                context(XtablesRestoreAction::Apply, other_family),
                XtablesRestoreParseErrorKind::FamilyMismatch {
                    expected: other_family,
                },
                Some(2),
            );
        }
    }

    let maximum = b"*mangle\n:FLX6P4294967295 - [0:0]\nCOMMIT\n";
    parse_xtables_restore(
        maximum,
        context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv6),
    )
    .expect("maximum nonzero u32 Capture generation");

    for chain in [
        "FLX4F0000000000",
        "FLX4O0000000000",
        "FLX4P0000000000",
        "FLX4F000000001",
        "FLX4F4294967296",
        "FLX6F000000000A",
        "FLX5F0000000001",
        "FLX4X0000000001",
    ] {
        let input = format!("*mangle\n:{chain} - [0:0]\nCOMMIT\n");
        assert_error(
            input.as_bytes(),
            context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4),
            XtablesRestoreParseErrorKind::InvalidChainName,
            Some(2),
        );
    }
}

#[test]
fn canonical_stable_capture_roots_are_family_scoped_and_sealed() {
    for (family_digit, family, other_family) in [
        ('4', XtablesRestoreFamily::Ipv4, XtablesRestoreFamily::Ipv6),
        ('6', XtablesRestoreFamily::Ipv6, XtablesRestoreFamily::Ipv4),
    ] {
        for hook in ['P', 'O'] {
            let chain = format!("FLX{family_digit}S{hook}");
            let input = format!("*mangle\n:{chain} - [0:0]\nCOMMIT\n");
            let artifact = parse_xtables_restore(
                input.as_bytes(),
                context(XtablesRestoreAction::Apply, family),
            )
            .expect("canonical stable Capture root");
            assert_eq!(artifact.render_canonical().as_ref(), input.as_bytes());
            assert_error(
                input.as_bytes(),
                context(XtablesRestoreAction::Apply, other_family),
                XtablesRestoreParseErrorKind::FamilyMismatch {
                    expected: other_family,
                },
                Some(2),
            );
        }
    }

    for chain in [
        "FLX4SF",
        "FLX4S",
        "FLX4SP0",
        "FLX4SX",
        "FLX5SP",
        "FLX6SOUTPUT",
    ] {
        let input = format!("*mangle\n:{chain} - [0:0]\nCOMMIT\n");
        assert_error(
            input.as_bytes(),
            context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4),
            XtablesRestoreParseErrorKind::InvalidChainName,
            Some(2),
        );
    }
}

#[test]
fn replace_action_requires_flush_then_complete_append_population() {
    let input = br#"*mangle
-F FLX4SP
-F FLX4SO
-A FLX4SP -i lo -m mark --mark 0x200000/0x600000 -j FLX4P0000000001
-A FLX4SO -m mark --mark 0x0/0x600000 -j FLX4O0000000001
COMMIT
"#;
    let artifact = parse_xtables_restore(
        input,
        context(XtablesRestoreAction::Replace, XtablesRestoreFamily::Ipv4),
    )
    .expect("canonical stable-root replacement");
    assert_eq!(artifact.render_canonical().as_ref(), input);

    assert_error(
        b"*mangle\n-A FLX4SP -j FLX4P0000000001\nCOMMIT\n",
        context(XtablesRestoreAction::Replace, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::ReplaceOrdering {
            command: XtablesRestoreCommandKind::Append,
        },
        Some(2),
    );
    assert_error(
        b"*mangle\n-F FLX4SP\n-A FLX4SP -j FLX4P0000000001\n-F FLX4SO\nCOMMIT\n",
        context(XtablesRestoreAction::Replace, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::ReplaceOrdering {
            command: XtablesRestoreCommandKind::Flush,
        },
        Some(4),
    );
    assert_error(
        b"*mangle\n:FLX4SP - [0:0]\nCOMMIT\n",
        context(XtablesRestoreAction::Replace, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::ChainDeclarationNotAllowed,
        Some(2),
    );
}

#[test]
fn cleanup_round_trip_preserves_delete_flush_delete_chain_phase_order() {
    let artifact = parse_xtables_restore(
        IPV4_CLEANUP,
        context(XtablesRestoreAction::Cleanup, XtablesRestoreFamily::Ipv4),
    )
    .expect("current-shaped cleanup document");
    assert_eq!(artifact.render_canonical().as_ref(), IPV4_CLEANUP);
    assert_eq!(artifact.transactions().len(), 3);

    let kinds = artifact.transactions()[0]
        .entries()
        .iter()
        .map(|entry| match entry {
            XtablesRestoreEntry::Command(command) => command.kind(),
            XtablesRestoreEntry::ChainDeclaration(_) => panic!("cleanup cannot declare chains"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        [
            XtablesRestoreCommandKind::Delete,
            XtablesRestoreCommandKind::Delete,
            XtablesRestoreCommandKind::Flush,
            XtablesRestoreCommandKind::Flush,
            XtablesRestoreCommandKind::DeleteChain,
            XtablesRestoreCommandKind::DeleteChain,
        ]
    );

    assert_error(
        b"*mangle\n-F PROXY_OUTPUT\n-D OUTPUT -j PROXY_OUTPUT\nCOMMIT\n",
        context(XtablesRestoreAction::Cleanup, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::CleanupOrdering {
            command: XtablesRestoreCommandKind::Delete,
        },
        Some(3),
    );
    assert_error(
        b"*mangle\n-X PROXY_OUTPUT\n-F PROXY_OUTPUT\nCOMMIT\n",
        context(XtablesRestoreAction::Cleanup, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::CleanupOrdering {
            command: XtablesRestoreCommandKind::DeleteChain,
        },
        Some(2),
    );
    assert_error(
        b"*filter\n-F PROXY_OUTPUT\nCOMMIT\n",
        context(XtablesRestoreAction::Cleanup, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::CommandTableMismatch {
            table: XtablesRestoreTable::Filter,
            command: XtablesRestoreCommandKind::Flush,
        },
        Some(2),
    );
}

#[test]
fn action_metadata_rejects_commands_and_declarations_from_the_other_lifecycle() {
    assert_error(
        b"*mangle\n-D OUTPUT -j PROXY_OUTPUT\nCOMMIT\n",
        context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::ActionMismatch {
            action: XtablesRestoreAction::Apply,
            command: XtablesRestoreCommandKind::Delete,
        },
        Some(2),
    );
    assert_error(
        b"*mangle\n-A OUTPUT -j PROXY_OUTPUT\nCOMMIT\n",
        context(XtablesRestoreAction::Cleanup, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::ActionMismatch {
            action: XtablesRestoreAction::Cleanup,
            command: XtablesRestoreCommandKind::Append,
        },
        Some(2),
    );
    assert_error(
        b"*mangle\n:PROXY_OUTPUT - [0:0]\nCOMMIT\n",
        context(XtablesRestoreAction::Cleanup, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::ChainDeclarationNotAllowed,
        Some(2),
    );
    assert_error(
        b"*filter\n:PROXY_OUTPUT - [0:0]\nCOMMIT\n",
        context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::ChainDeclarationTableMismatch {
            table: XtablesRestoreTable::Filter,
        },
        Some(2),
    );
}

#[test]
fn canonical_ascii_lf_and_closed_line_grammar_are_strict() {
    let apply_v4 = context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4);
    assert_error(
        b"",
        apply_v4,
        XtablesRestoreParseErrorKind::EmptyInput,
        None,
    );
    assert_error(
        b"*mangle\nCOMMIT",
        apply_v4,
        XtablesRestoreParseErrorKind::MissingFinalLineFeed,
        None,
    );
    assert_error(
        b"*mangle\r\nCOMMIT\r\n",
        apply_v4,
        XtablesRestoreParseErrorKind::NonCanonicalByte {
            offset: 7,
            byte: b'\r',
        },
        None,
    );
    assert_error(
        b"*mangle\n-A\tOUTPUT -j ACCEPT\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::NonCanonicalByte {
            offset: 10,
            byte: b'\t',
        },
        None,
    );
    assert_error(
        b"*mangle\n\xff\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::NonCanonicalByte {
            offset: 8,
            byte: 0xff,
        },
        None,
    );
    assert_error(
        b"*mangle\n\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::EmptyLine,
        Some(2),
    );
    for input in [
        b"*mangle\n -A OUTPUT -j ACCEPT\nCOMMIT\n".as_slice(),
        b"*mangle\n-A  OUTPUT -j ACCEPT\nCOMMIT\n".as_slice(),
        b"*mangle\n-A OUTPUT -j ACCEPT \nCOMMIT\n".as_slice(),
    ] {
        assert_error(
            input,
            apply_v4,
            XtablesRestoreParseErrorKind::NonCanonicalSpacing,
            Some(2),
        );
    }
    assert_error(
        b"# comment\n",
        apply_v4,
        XtablesRestoreParseErrorKind::ContentOutsideTransaction,
        Some(1),
    );
    assert_error(
        b"*raw\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::UnknownTable,
        Some(1),
    );
    assert_error(
        b"*mangle\n*filter\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::NestedTransaction,
        Some(2),
    );
    assert_error(
        b"*mangle\n-A OUTPUT -j ACCEPT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::UnterminatedTransaction,
        Some(2),
    );
    assert_error(
        b"*filter\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::EmptyTransaction {
            table: XtablesRestoreTable::Filter,
        },
        Some(2),
    );
    parse_xtables_restore(b"*mangle\nCOMMIT\n", apply_v4)
        .expect("the current empty TUN mangle artifact remains observable");
}

#[test]
fn declarations_commands_and_opaque_tokens_reject_noncanonical_shapes() {
    let apply_v4 = context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4);
    for declaration in [
        ":CHAIN ACCEPT [0:0]",
        ":CHAIN - [1:0]",
        ":CHAIN - [0:0] extra",
    ] {
        let input = format!("*mangle\n{declaration}\nCOMMIT\n");
        assert_error(
            input.as_bytes(),
            apply_v4,
            XtablesRestoreParseErrorKind::InvalidChainDeclaration,
            Some(2),
        );
    }
    assert_error(
        b"*mangle\n-A OUTPUT -j ACCEPT\n:CHAIN - [0:0]\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::ChainDeclarationAfterCommand,
        Some(3),
    );
    assert_error(
        b"*mangle\n:lowercase - [0:0]\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::InvalidChainName,
        Some(2),
    );
    assert_error(
        b"*mangle\n-Z OUTPUT\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::UnsupportedCommand,
        Some(2),
    );
    assert_error(
        b"*mangle\n-A OUTPUT\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::InvalidCommandArity {
            command: XtablesRestoreCommandKind::Append,
        },
        Some(2),
    );
    assert_error(
        b"*mangle\n-I OUTPUT 1 -j ACCEPT\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::PositionalInsertNotSupported,
        Some(2),
    );
    assert_error(
        b"*mangle\n-D OUTPUT 1:3\nCOMMIT\n",
        context(XtablesRestoreAction::Cleanup, XtablesRestoreFamily::Ipv4),
        XtablesRestoreParseErrorKind::PositionalDeleteNotSupported,
        Some(2),
    );
    assert_error(
        b"*mangle\n-A OUTPUT -m 'owner' -j ACCEPT\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::InvalidToken,
        Some(2),
    );
    for arguments in [
        "-d",
        "--to-destination",
        "-p",
        "-j",
        "-m",
        "--tcp-flags SYN,RST",
        "-j -p tcp",
    ] {
        let input = format!("*mangle\n-A OUTPUT {arguments}\nCOMMIT\n");
        assert_error(
            input.as_bytes(),
            apply_v4,
            XtablesRestoreParseErrorKind::MissingOptionValue,
            Some(2),
        );
    }
    assert_error(
        b"*mangle\n-A OUTPUT -j lowercase\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::InvalidJumpTarget,
        Some(2),
    );
    assert_error(
        b"*mangle\n-A OUTPUT -j BYP_Z016\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::InvalidChainName,
        Some(2),
    );
    assert_error(
        b"*mangle\n-A OUTPUT -p icmpv6 -j ACCEPT\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::UnsupportedProtocol,
        Some(2),
    );
    for arguments in [
        "--destination 127.0.0.1 -j ACCEPT",
        "--to-destination=127.0.0.1 -j ACCEPT",
        "--protocol tcp -j ACCEPT",
        "-s 127.0.0.1 -j ACCEPT",
    ] {
        let input = format!("*mangle\n-A OUTPUT {arguments}\nCOMMIT\n");
        assert_error(
            input.as_bytes(),
            apply_v4,
            XtablesRestoreParseErrorKind::UnsupportedRuleOption,
            Some(2),
        );
    }
    assert_error(
        b"*mangle\n-A OUTPUT -d not-an-ip -j ACCEPT\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::InvalidAddress,
        Some(2),
    );
    assert_error(
        b"*mangle\n-A OUTPUT -d 192.0.2.0/33 -j ACCEPT\nCOMMIT\n",
        apply_v4,
        XtablesRestoreParseErrorKind::InvalidAddress,
        Some(2),
    );
    for input in [
        b"*mangle\n-A OUTPUT -d 192.0.2.0/+24 -j ACCEPT\nCOMMIT\n".as_slice(),
        b"*mangle\n-A OUTPUT -d 2001:db8::/+64 -j ACCEPT\nCOMMIT\n".as_slice(),
    ] {
        assert_error(
            input,
            if input.contains(&b':') {
                context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv6)
            } else {
                apply_v4
            },
            XtablesRestoreParseErrorKind::InvalidAddress,
            Some(2),
        );
    }
}

#[test]
fn exact_token_chain_transaction_and_command_bounds_are_enforced() {
    let apply_v4 = context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4);

    let maximum_token = "a".repeat(MAX_XTABLES_RESTORE_TOKEN_BYTES);
    let exact_token = format!("*mangle\n-A OUTPUT -m {maximum_token}\nCOMMIT\n");
    parse_xtables_restore(exact_token.as_bytes(), apply_v4).expect("maximum-size token");
    let oversized_token = format!("{maximum_token}a");
    let oversized_token = format!("*mangle\n-A OUTPUT -m {oversized_token}\nCOMMIT\n");
    assert_error(
        oversized_token.as_bytes(),
        apply_v4,
        XtablesRestoreParseErrorKind::LimitExceeded {
            resource: XtablesRestoreLimit::TokenBytes,
            maximum: MAX_XTABLES_RESTORE_TOKEN_BYTES,
            actual: MAX_XTABLES_RESTORE_TOKEN_BYTES + 1,
        },
        Some(2),
    );

    let maximum_chain = "A".repeat(MAX_XTABLES_RESTORE_CHAIN_BYTES);
    let exact_chain = format!("*mangle\n:{maximum_chain} - [0:0]\nCOMMIT\n");
    parse_xtables_restore(exact_chain.as_bytes(), apply_v4).expect("maximum-size chain");
    let oversized_chain = format!("{maximum_chain}A");
    let oversized_chain = format!("*mangle\n:{oversized_chain} - [0:0]\nCOMMIT\n");
    assert_error(
        oversized_chain.as_bytes(),
        apply_v4,
        XtablesRestoreParseErrorKind::LimitExceeded {
            resource: XtablesRestoreLimit::ChainBytes,
            maximum: MAX_XTABLES_RESTORE_CHAIN_BYTES,
            actual: MAX_XTABLES_RESTORE_CHAIN_BYTES + 1,
        },
        Some(2),
    );

    let exact_arguments = (0..(MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND - 2) / 2)
        .flat_map(|_| ["-m", "x"])
        .collect::<Vec<_>>()
        .join(" ");
    let exact_tokens = format!("*mangle\n-A OUTPUT {exact_arguments}\nCOMMIT\n");
    let artifact =
        parse_xtables_restore(exact_tokens.as_bytes(), apply_v4).expect("maximum token count");
    assert_eq!(
        artifact.usage().tokens(),
        MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND
    );
    let excess_tokens = format!("*mangle\n-A OUTPUT {exact_arguments} --transparent\nCOMMIT\n");
    assert_error(
        excess_tokens.as_bytes(),
        apply_v4,
        XtablesRestoreParseErrorKind::LimitExceeded {
            resource: XtablesRestoreLimit::TokensPerCommand,
            maximum: MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND,
            actual: MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND + 1,
        },
        Some(2),
    );

    let exact_transactions = "*mangle\nCOMMIT\n".repeat(MAX_XTABLES_RESTORE_TRANSACTIONS);
    let artifact = parse_xtables_restore(exact_transactions.as_bytes(), apply_v4)
        .expect("maximum transaction count");
    assert_eq!(
        artifact.usage().transactions(),
        MAX_XTABLES_RESTORE_TRANSACTIONS
    );
    let excess_transactions = "*mangle\nCOMMIT\n".repeat(MAX_XTABLES_RESTORE_TRANSACTIONS + 1);
    assert_error(
        excess_transactions.as_bytes(),
        apply_v4,
        XtablesRestoreParseErrorKind::LimitExceeded {
            resource: XtablesRestoreLimit::Transactions,
            maximum: MAX_XTABLES_RESTORE_TRANSACTIONS,
            actual: MAX_XTABLES_RESTORE_TRANSACTIONS + 1,
        },
        Some(MAX_XTABLES_RESTORE_TRANSACTIONS * 2 + 1),
    );

    let mut exact_commands = String::from("*mangle\n");
    exact_commands.push_str(&"-A OUTPUT -j ACCEPT\n".repeat(MAX_XTABLES_RESTORE_COMMANDS));
    exact_commands.push_str("COMMIT\n");
    let artifact =
        parse_xtables_restore(exact_commands.as_bytes(), apply_v4).expect("maximum command count");
    assert_eq!(artifact.usage().commands(), MAX_XTABLES_RESTORE_COMMANDS);
    exact_commands.insert_str(
        exact_commands.len() - "COMMIT\n".len(),
        "-A OUTPUT -j ACCEPT\n",
    );
    assert_error(
        exact_commands.as_bytes(),
        apply_v4,
        XtablesRestoreParseErrorKind::LimitExceeded {
            resource: XtablesRestoreLimit::Commands,
            maximum: MAX_XTABLES_RESTORE_COMMANDS,
            actual: MAX_XTABLES_RESTORE_COMMANDS + 1,
        },
        Some(MAX_XTABLES_RESTORE_COMMANDS + 2),
    );
}

#[test]
fn exact_line_line_count_and_document_byte_bounds_are_enforced() {
    let apply_v4 = context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4);

    let maximum_line = command_line_of_length(MAX_XTABLES_RESTORE_LINE_BYTES);
    let exact_line = format!("*mangle\n{maximum_line}\nCOMMIT\n");
    parse_xtables_restore(exact_line.as_bytes(), apply_v4).expect("maximum-size line");
    let oversized_line = command_line_of_length(MAX_XTABLES_RESTORE_LINE_BYTES + 1);
    let oversized_line = format!("*mangle\n{oversized_line}\nCOMMIT\n");
    assert_error(
        oversized_line.as_bytes(),
        apply_v4,
        XtablesRestoreParseErrorKind::LimitExceeded {
            resource: XtablesRestoreLimit::LineBytes,
            maximum: MAX_XTABLES_RESTORE_LINE_BYTES,
            actual: MAX_XTABLES_RESTORE_LINE_BYTES + 1,
        },
        Some(2),
    );

    let mut exact_lines = String::from("*mangle\n");
    exact_lines.push_str(&":A - [0:0]\n".repeat(MAX_XTABLES_RESTORE_LINES - 2));
    exact_lines.push_str("COMMIT\n");
    let artifact =
        parse_xtables_restore(exact_lines.as_bytes(), apply_v4).expect("maximum line count");
    assert_eq!(artifact.usage().lines(), MAX_XTABLES_RESTORE_LINES);
    exact_lines.insert_str(exact_lines.len() - "COMMIT\n".len(), ":A - [0:0]\n");
    assert_error(
        exact_lines.as_bytes(),
        apply_v4,
        XtablesRestoreParseErrorKind::LimitExceeded {
            resource: XtablesRestoreLimit::Lines,
            maximum: MAX_XTABLES_RESTORE_LINES,
            actual: MAX_XTABLES_RESTORE_LINES + 1,
        },
        None,
    );

    let mut exact_bytes = b"*mangle\n".to_vec();
    for _ in 0..255 {
        exact_bytes.extend_from_slice(maximum_line.as_bytes());
        exact_bytes.push(b'\n');
    }
    let final_line_length = MAX_XTABLES_RESTORE_BYTES - exact_bytes.len() - 1 - b"COMMIT\n".len();
    let final_line = command_line_of_length(final_line_length);
    exact_bytes.extend_from_slice(final_line.as_bytes());
    exact_bytes.extend_from_slice(b"\nCOMMIT\n");
    assert_eq!(exact_bytes.len(), MAX_XTABLES_RESTORE_BYTES);
    let artifact = parse_xtables_restore(&exact_bytes, apply_v4).expect("maximum document bytes");
    assert_eq!(artifact.usage().input_bytes(), MAX_XTABLES_RESTORE_BYTES);

    let oversized = vec![b'x'; MAX_XTABLES_RESTORE_BYTES + 1];
    assert_error(
        &oversized,
        apply_v4,
        XtablesRestoreParseErrorKind::LimitExceeded {
            resource: XtablesRestoreLimit::Bytes,
            maximum: MAX_XTABLES_RESTORE_BYTES,
            actual: MAX_XTABLES_RESTORE_BYTES + 1,
        },
        None,
    );
}

#[test]
fn digest_is_deterministic_and_binds_bytes_action_and_family() {
    let apply_v4 = context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4);
    let first = parse_xtables_restore(IPV4_APPLY, apply_v4).expect("first parse");
    let second = parse_xtables_restore(IPV4_APPLY, apply_v4).expect("second parse");
    assert_eq!(first.digest(), second.digest());

    let reordered = b"*mangle\n-A OUTPUT -j ACCEPT\n-A PREROUTING -j ACCEPT\nCOMMIT\n";
    let reordered_other = b"*mangle\n-A PREROUTING -j ACCEPT\n-A OUTPUT -j ACCEPT\nCOMMIT\n";
    let first_order = parse_xtables_restore(reordered, apply_v4).expect("first order");
    let second_order = parse_xtables_restore(reordered_other, apply_v4).expect("second order");
    assert_ne!(first_order.digest(), second_order.digest());

    let empty = b"*mangle\nCOMMIT\n";
    let apply_v4 = parse_xtables_restore(
        empty,
        context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4),
    )
    .expect("IPv4 apply metadata");
    assert_eq!(
        digest_hex(apply_v4.digest().as_bytes()),
        "fb0e7d3103876a64df67196d8cefdb53bf6980d8407b2163dc44bb001574cf8a"
    );
    let cleanup_v4 = parse_xtables_restore(
        empty,
        context(XtablesRestoreAction::Cleanup, XtablesRestoreFamily::Ipv4),
    )
    .expect("IPv4 cleanup metadata");
    let apply_v6 = parse_xtables_restore(
        empty,
        context(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv6),
    )
    .expect("IPv6 apply metadata");
    assert_ne!(apply_v4.digest(), cleanup_v4.digest());
    assert_ne!(apply_v4.digest(), apply_v6.digest());
}

fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn command_line_of_length(target: usize) -> String {
    const PREFIX: &str = "-A OUTPUT";
    let option_pairs = (MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND - 2) / 2;
    let mut remaining_characters = target
        .checked_sub(PREFIX.len() + option_pairs * " -m ".len())
        .expect("target must fit command prefix and option pairs");
    assert!(remaining_characters >= option_pairs);
    assert!(remaining_characters <= option_pairs * MAX_XTABLES_RESTORE_TOKEN_BYTES);

    let mut line = String::with_capacity(target);
    line.push_str(PREFIX);
    for remaining_values in (1..=option_pairs).rev() {
        let token_length = remaining_characters
            .saturating_sub(remaining_values - 1)
            .min(MAX_XTABLES_RESTORE_TOKEN_BYTES);
        line.push_str(" -m ");
        line.push_str(&"a".repeat(token_length));
        remaining_characters -= token_length;
    }
    assert_eq!(remaining_characters, 0);
    assert_eq!(line.len(), target);
    line
}
