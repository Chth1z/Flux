use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::num::{NonZeroU16, NonZeroU32};

use flux_core::{
    AddressBypassRuleBudget, AddressHostFamilySelection, AddressHostSetPlan, AddressHostSetPolicy,
    CaptureApplicationMode, CaptureApplicationPolicy, CaptureBypassPolicy, CaptureGroupId,
    CaptureInterfacePolicy, CaptureInterfaceSelector, CaptureIpPrefix, CaptureProgram,
    CaptureProgramCompilation, CaptureProgramRequest, CaptureProtocolSet, CaptureTrafficDomain,
    CaptureTrafficScope, CaptureUserId, EngineCredentials, FwmarkCandidate, GenerationId,
    InterfaceAddressFlags, InterfaceAddressRecord, InterfaceIndex, InterfaceName,
    NetworkAddressFamily, NetworkInventoryTracker, RouteProtocol, RouteTableId, RuleFwMark,
    RulePriority, RuleProtocol, compile_capture_program, plan_address_host_set,
};
use flux_platform::{
    MAX_XTABLES_RESTORE_BYTES, XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION, XtablesCaptureArtifactSet,
    XtablesCaptureEntryPointRole, XtablesCaptureEntrySelector, XtablesCaptureExtension,
    XtablesCaptureExtensions, XtablesCaptureHook, XtablesCaptureLoweringBudget,
    XtablesCaptureLoweringError, XtablesCaptureLoweringRequest, XtablesCaptureNamespace,
    XtablesCaptureTransactionStep, XtablesInterfaceRenderErrorKind, XtablesLocalOutputRoutingSpec,
    XtablesLocalOutputRoutingSpecError, XtablesLocalOutputRoutingTarget,
    XtablesLocalOutputRoutingTargetError, XtablesRestoreAction, XtablesRestoreContext,
    XtablesRestoreFamily, XtablesTproxyTarget, lower_xtables_capture,
};

const DEFAULT_GENERATION: u32 = 42;
const DEFAULT_PROXY_PORT: u16 = 1536;
const DEFAULT_MARK_MASK: u32 = 0x0060_0000;
const DEFAULT_PROXY_MARK: u32 = 0x0020_0000;
const DEFAULT_BYPASS_MARK: u32 = 0x0040_0000;
const DEFAULT_ROUTE_PRIORITY: u32 = 30_999;
const DEFAULT_ROUTE_TABLE: u32 = 20_253;
const DEFAULT_ROUTE_METRIC: u32 = 1_024;
const DEFAULT_ROUTE_PROTOCOL: u8 = 4;
const DEFAULT_RULE_PROTOCOL: u8 = 99;

#[test]
fn dual_stack_forwarded_lowering_is_deterministic_and_unattached() {
    let report = compile_program(
        scope(AddressHostFamilySelection::DualStack, false, true),
        interfaces(
            &[exact("tun0")],
            &[prefix_interface("wlan"), exact("rmnet0")],
            &[],
        ),
        CaptureProtocolSet::TCP_AND_UDP,
        &["100.64.0.0/10", "2001:db8::/32"],
    );

    let first = lower(&report, DEFAULT_GENERATION, default_target()).unwrap();
    let second = lower(&report, DEFAULT_GENERATION, default_target()).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.source_program_digest(), report.program().digest());
    assert_eq!(first.usage().domain_programs(), 2);
    assert_eq!(first.usage().implementation_chains(), 2);
    assert_eq!(first.usage().maximum_jump_depth(), 1);

    for (family, family_digit) in [
        (XtablesRestoreFamily::Ipv4, '4'),
        (XtablesRestoreFamily::Ipv6, '6'),
    ] {
        let pair = first.pair(family).expect("selected address family");
        let chain = format!("FLX{family_digit}F0000000042");
        assert_eq!(
            pair.entries()
                .iter()
                .map(|entry| (entry.domain(), entry.chain()))
                .collect::<Vec<_>>(),
            [(CaptureTrafficDomain::ForwardedIngress, chain.as_str())]
        );
        assert_eq!(
            pair.prepare().context(),
            XtablesRestoreContext::new(XtablesRestoreAction::Apply, family)
        );
        assert_eq!(
            pair.retire().context(),
            XtablesRestoreContext::new(XtablesRestoreAction::Cleanup, family)
        );
        assert_eq!(
            restore_text(pair.retire()),
            format!("*mangle\n-F {chain}\n-X {chain}\nCOMMIT\n")
        );

        let prepare = restore_text(pair.prepare());
        assert!(prepare.starts_with(&format!("*mangle\n:{chain} - [0:0]\n")));
        assert!(prepare.contains(" -j TPROXY --on-port 1536 --tproxy-mark 0x200000/0x600000\n"));
        for artifact in [prepare.as_str(), restore_text(pair.retire()).as_str()] {
            assert!(!modifies_builtin_hook(artifact));
            assert!(!artifact.contains("CONNMARK"));
            assert!(!artifact.contains("DIVERT"));
            assert!(!artifact.contains(" -j MARK "));
            assert!(!artifact.contains("--set-xmark"));
        }
    }
}

#[test]
fn forwarded_fixture_pins_exact_bytes_and_identities() {
    let report = compile_program(
        scope(AddressHostFamilySelection::Ipv4, false, true),
        interfaces(&[], &[exact("wlan0")], &[]),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    let lowered = lower(&report, 1, default_target()).unwrap();
    let pair = lowered.ipv4().unwrap();
    assert_eq!(
        lowered.schema_version(),
        XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION
    );

    assert_eq!(
        restore_text(pair.prepare()),
        concat!(
            "*mangle\n",
            ":FLX4F0000000001 - [0:0]\n",
            "-A FLX4F0000000001 -d 0.0.0.0/8 -j RETURN\n",
            "-A FLX4F0000000001 -d 127.0.0.0/8 -j RETURN\n",
            "-A FLX4F0000000001 -d 169.254.0.0/16 -j RETURN\n",
            "-A FLX4F0000000001 -d 224.0.0.0/4 -j RETURN\n",
            "-A FLX4F0000000001 -d 240.0.0.0/4 -j RETURN\n",
            "-A FLX4F0000000001 -i lo -j RETURN\n",
            "-A FLX4F0000000001 -i wlan0 -p tcp -j TPROXY --on-port 1536 ",
            "--tproxy-mark 0x200000/0x600000\n",
            "-A FLX4F0000000001 -i wlan0 -p udp -j TPROXY --on-port 1536 ",
            "--tproxy-mark 0x200000/0x600000\n",
            "-A FLX4F0000000001 -j RETURN\n",
            "COMMIT\n",
        )
    );
    assert_eq!(
        restore_text(pair.retire()),
        "*mangle\n-F FLX4F0000000001\n-X FLX4F0000000001\nCOMMIT\n"
    );
    assert_eq!(
        digest_hex(lowered.source_program_digest().as_bytes()),
        "8b78445f63c20ebd5610a41c73f6706ed23dda799a5dc9113c7f30c9e5ed7034"
    );
    assert_eq!(
        digest_hex(lowered.lowering_digest().as_bytes()),
        "b32cd5db848476089647f38bd03000b3f36f34af4f48f745d48a9eb8f1041207"
    );
    assert_eq!(
        digest_hex(pair.digest().as_bytes()),
        "b869f8c4ab6f6e7a2d6c1cbcad98dc5e77ba413d901b10d1926a5b763f07a8f0"
    );
    assert_eq!(
        digest_hex(lowered.digest().as_bytes()),
        "9c85eeb3fd1cbc719dcca3bb682a7c0a257d8423721f7c82bcd266ab342acbe8"
    );
}

#[test]
fn forwarded_interface_whole_set_expands_as_positive_proxy_membership() {
    let report = compile_program(
        scope(AddressHostFamilySelection::Ipv4, false, true),
        interfaces(
            &[exact("tun0")],
            &[exact("wlan0"), prefix_interface("rmnet")],
            &[],
        ),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    let lowered = lower(&report, 7, default_target()).unwrap();
    let prepare = restore_text(lowered.ipv4().unwrap().prepare());
    let chain = "FLX4F0000000007";

    assert!(prepare.contains(&format!("-A {chain} -i tun0 -j RETURN\n")));
    for interface in ["wlan0", "rmnet+"] {
        for protocol in ["tcp", "udp"] {
            assert!(prepare.contains(&format!(
                "-A {chain} -i {interface} -p {protocol} -j TPROXY --on-port 1536 --tproxy-mark 0x200000/0x600000\n"
            )));
        }
    }
    assert!(prepare.contains(&format!("-A {chain} -j RETURN\n")));
    assert!(!prepare.contains(" ! "));
    assert!(!prepare.contains("--uid-owner"));
    assert!(!prepare.contains(" -o "));
}

#[test]
fn forwarded_direct_rules_preserve_safety_host_loopback_and_configured_order() {
    let report = compile_program_with_host(
        scope(AddressHostFamilySelection::Ipv4, false, true),
        interfaces(&[], &[exact("wlan0")], &[]),
        CaptureProtocolSet::TCP,
        &["100.64.0.0/10"],
        Some(host_plan("203.0.113.7")),
    );
    let lowered = lower(&report, 9, default_target()).unwrap();
    let prepare = restore_text(lowered.ipv4().unwrap().prepare());
    let mandatory = prepare.find("-d 0.0.0.0/8 -j RETURN").unwrap();
    let host = prepare.find("-d 203.0.113.7/32 -j RETURN").unwrap();
    let loopback = prepare.find("-i lo -j RETURN").unwrap();
    let configured = prepare.find("-d 100.64.0.0/10 -j RETURN").unwrap();
    let proxy = prepare.find("-i wlan0 -p tcp -j TPROXY").unwrap();
    assert!(mandatory < host && host < loopback && loopback < configured && configured < proxy);
}

#[test]
fn address_hosts_render_as_save_canonical_full_length_prefixes() {
    let report = compile_program_with_host(
        scope(AddressHostFamilySelection::Ipv6, false, true),
        interfaces(&[], &[exact("wlan0")], &[]),
        CaptureProtocolSet::TCP,
        &[],
        Some(host_plan("2001:4860:4860::8888")),
    );
    let lowered = lower(&report, 10, default_target()).unwrap();
    let prepare = restore_text(lowered.ipv6().unwrap().prepare());
    assert!(prepare.contains("-d 2001:4860:4860::8888/128 -j RETURN"));
}

#[test]
fn protocol_subsets_emit_only_the_selected_forwarded_proxy_rules() {
    for (protocols, selected, omitted) in [
        (CaptureProtocolSet::TCP, "tcp", "udp"),
        (CaptureProtocolSet::UDP, "udp", "tcp"),
    ] {
        let report = compile_program(
            scope(AddressHostFamilySelection::Ipv4, false, true),
            interfaces(&[], &[exact("wlan0")], &[]),
            protocols,
            &[],
        );
        let lowered = lower(&report, 8, default_target()).unwrap();
        let prepare = restore_text(lowered.ipv4().unwrap().prepare());

        assert!(prepare.contains(&format!(
            "-A FLX4F0000000008 -i wlan0 -p {selected} -j TPROXY"
        )));
        assert!(!prepare.contains(&format!(" -p {omitted} ")));
        assert!(!prepare.contains("--uid-owner"));
        assert!(!prepare.contains(" -j MARK "));
    }
}

#[test]
fn local_protocol_subsets_align_classifier_companion_and_listener() {
    for (protocols, selected, omitted) in [
        (CaptureProtocolSet::TCP, "tcp", "udp"),
        (CaptureProtocolSet::UDP, "udp", "tcp"),
    ] {
        let report = compile_program(
            scope(AddressHostFamilySelection::Ipv4, true, false),
            interfaces(&[], &[], &[]),
            protocols,
            &[],
        );
        let lowered = lower_with_routing(
            &report,
            24,
            default_target(),
            local_routing_spec(Some(default_routing_target()), None),
        )
        .unwrap();
        let pair = lowered.ipv4().unwrap();
        let prepare = restore_text(pair.prepare());
        assert!(prepare.contains(&format!(
            "-A FLX4O0000000024 -p {selected} -j MARK --set-xmark"
        )));
        assert!(prepare.contains(&format!("-A FLX4P0000000024 -p {selected} -j TPROXY")));
        assert!(!prepare.contains(&format!(" -p {omitted} ")));
        assert_eq!(
            pair.local_output().unwrap().listener().protocols(),
            protocols
        );
    }
}

#[test]
fn proxying_local_output_requires_exact_family_routing() {
    let local_only = compile_program(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        interfaces(&[], &[], &[]),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    assert_eq!(
        lower(&local_only, DEFAULT_GENERATION, default_target()),
        Err(XtablesCaptureLoweringError::MissingLocalOutputRouting {
            family: NetworkAddressFamily::Ipv4,
        })
    );

    let ipv6_only = local_routing_spec(None, Some(default_routing_target()));
    assert_eq!(
        lower_with_routing(&local_only, DEFAULT_GENERATION, default_target(), ipv6_only,),
        Err(XtablesCaptureLoweringError::MissingLocalOutputRouting {
            family: NetworkAddressFamily::Ipv4,
        })
    );
}

#[test]
fn ipv4_local_output_pins_complete_non_authorizing_transaction() {
    let report = compile_program(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        interfaces(&[], &[], &[]),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    let lowered = lower_with_routing(
        &report,
        1,
        default_target(),
        local_routing_spec(Some(default_routing_target()), None),
    )
    .unwrap();
    assert_eq!(lowered.schema_version(), 2);
    let pair = lowered.ipv4().unwrap();
    assert_eq!(
        pair.entries()
            .iter()
            .map(|entry| (entry.role(), entry.hook(), entry.selector(), entry.chain()))
            .collect::<Vec<_>>(),
        [
            (
                XtablesCaptureEntryPointRole::LocalOutputClassifier,
                XtablesCaptureHook::Output,
                XtablesCaptureEntrySelector::Mark(RuleFwMark::new(0, DEFAULT_MARK_MASK).unwrap(),),
                "FLX4O0000000001",
            ),
            (
                XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy,
                XtablesCaptureHook::Prerouting,
                XtablesCaptureEntrySelector::InputInterfaceAndMark {
                    interface: interface_bytes(b"lo"),
                    mark: RuleFwMark::new(DEFAULT_PROXY_MARK, DEFAULT_MARK_MASK).unwrap(),
                },
                "FLX4P0000000001",
            ),
        ]
    );
    assert_eq!(
        restore_text(pair.prepare()),
        concat!(
            "*mangle\n",
            ":FLX4O0000000001 - [0:0]\n",
            ":FLX4P0000000001 - [0:0]\n",
            "-A FLX4O0000000001 -m owner --uid-owner 1000 --gid-owner 1000 -j RETURN\n",
            "-A FLX4O0000000001 -d 0.0.0.0/8 -j RETURN\n",
            "-A FLX4O0000000001 -d 127.0.0.0/8 -j RETURN\n",
            "-A FLX4O0000000001 -d 169.254.0.0/16 -j RETURN\n",
            "-A FLX4O0000000001 -d 224.0.0.0/4 -j RETURN\n",
            "-A FLX4O0000000001 -d 240.0.0.0/4 -j RETURN\n",
            "-A FLX4O0000000001 -p tcp -j MARK --set-xmark 0x200000/0x600000\n",
            "-A FLX4O0000000001 -p udp -j MARK --set-xmark 0x200000/0x600000\n",
            "-A FLX4O0000000001 -j RETURN\n",
            "-A FLX4P0000000001 -p tcp -j TPROXY --on-port 1536 ",
            "--tproxy-mark 0x200000/0x600000\n",
            "-A FLX4P0000000001 -p udp -j TPROXY --on-port 1536 ",
            "--tproxy-mark 0x200000/0x600000\n",
            "-A FLX4P0000000001 -j RETURN\n",
            "COMMIT\n",
        )
    );
    assert_eq!(
        restore_text(pair.retire()),
        concat!(
            "*mangle\n",
            "-F FLX4O0000000001\n",
            "-F FLX4P0000000001\n",
            "-X FLX4O0000000001\n",
            "-X FLX4P0000000001\n",
            "COMMIT\n",
        )
    );
    for artifact in [restore_text(pair.prepare()), restore_text(pair.retire())] {
        assert!(!modifies_builtin_hook(&artifact));
        assert!(!artifact.contains("CONNMARK"));
    }

    let requirements = pair.local_output().unwrap();
    let routing = requirements.routing();
    assert_eq!(routing.priority().get(), DEFAULT_ROUTE_PRIORITY);
    assert_eq!(routing.table().get(), DEFAULT_ROUTE_TABLE);
    assert_eq!(routing.route_metric().get(), DEFAULT_ROUTE_METRIC);
    assert_eq!(routing.route_protocol().raw(), DEFAULT_ROUTE_PROTOCOL);
    assert_eq!(routing.rule_protocol().raw(), DEFAULT_RULE_PROTOCOL);
    assert_eq!(
        routing.route_destination(),
        "0.0.0.0".parse::<IpAddr>().unwrap()
    );
    assert_eq!(routing.route_prefix_length(), 0);
    assert_eq!(routing.route_scope().raw(), 254);
    assert_eq!(routing.route_type().raw(), 2);
    assert_eq!(
        routing.mark(),
        RuleFwMark::new(DEFAULT_PROXY_MARK, DEFAULT_MARK_MASK).unwrap()
    );
    assert_eq!(routing.loopback_interface(), interface_bytes(b"lo"));
    let listener = requirements.listener();
    assert_eq!(
        listener.bind_address(),
        "0.0.0.0".parse::<IpAddr>().unwrap()
    );
    assert_eq!(listener.port().get(), DEFAULT_PROXY_PORT);
    assert_eq!(listener.protocols(), CaptureProtocolSet::TCP_AND_UDP);
    assert!(listener.requires_transparent_socket());
    assert!(listener.requires_original_destination());
    let escape = requirements.loop_escape();
    assert_eq!(escape.engine_credentials().uid(), uid(1000));
    assert_eq!(escape.engine_credentials().gid(), gid(1000));
    assert_eq!(
        escape.socket_mark(),
        RuleFwMark::new(DEFAULT_BYPASS_MARK, DEFAULT_MARK_MASK).unwrap()
    );

    let order = pair.transaction_order();
    assert_eq!(
        order.prepare(),
        [
            XtablesCaptureTransactionStep::PrepareEntryPoint(
                XtablesCaptureEntryPointRole::LocalOutputClassifier,
            ),
            XtablesCaptureTransactionStep::PrepareEntryPoint(
                XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy,
            ),
            XtablesCaptureTransactionStep::PrepareTransparentListener,
            XtablesCaptureTransactionStep::PreparePolicyRouting,
            XtablesCaptureTransactionStep::PrepareLoopEscape,
            XtablesCaptureTransactionStep::AttachEntryPoint(
                XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy,
            ),
            XtablesCaptureTransactionStep::AttachEntryPoint(
                XtablesCaptureEntryPointRole::LocalOutputClassifier,
            ),
        ]
    );
    assert_eq!(
        order.retire(),
        [
            XtablesCaptureTransactionStep::DetachEntryPoint(
                XtablesCaptureEntryPointRole::LocalOutputClassifier,
            ),
            XtablesCaptureTransactionStep::DetachEntryPoint(
                XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy,
            ),
            XtablesCaptureTransactionStep::RetireLoopEscape,
            XtablesCaptureTransactionStep::RetirePolicyRouting,
            XtablesCaptureTransactionStep::RetireTransparentListener,
            XtablesCaptureTransactionStep::RetireEntryPoint(
                XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy,
            ),
            XtablesCaptureTransactionStep::RetireEntryPoint(
                XtablesCaptureEntryPointRole::LocalOutputClassifier,
            ),
        ]
    );
    assert_eq!(pair.usage().implementation_chains(), 2);
    assert_eq!(pair.usage().entry_points(), 2);
    assert_eq!(pair.usage().listener_requirements(), 2);
    assert_eq!(pair.usage().routing_objects(), 2);
    assert_eq!(
        pair.usage().transaction_steps(),
        order.prepare().len() + order.retire().len()
    );
    assert_eq!(
        digest_hex(lowered.source_program_digest().as_bytes()),
        "6e12d9b1205a952552bb7723821f032827cdffcf30999d48c3b1215644f5982b"
    );
    assert_eq!(
        digest_hex(lowered.lowering_digest().as_bytes()),
        "fa54eaf9774d90ed5925e2548d661069515d3f202d1d231151fc8f4c2b81e6c7"
    );
    assert_eq!(
        digest_hex(pair.digest().as_bytes()),
        "ffdd643b5ec8278c20f1123f16c8c029b2b87688fc32dd96766b93936ebc9f86"
    );
    assert_eq!(
        digest_hex(lowered.digest().as_bytes()),
        "22eab3e33c2c920a77e1f6b831660e72e9eef7a2d90683ea8e7e6a0878dda617"
    );
}

#[test]
fn local_output_canary_slots_are_empty_owned_and_selector_precedes_configurable_policy() {
    let report = compile_program_with_application_and_host(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        interfaces(&[exact("tun0")], &[], &[]),
        CaptureApplicationPolicy::new(CaptureApplicationMode::Denylist, [uid(1001)]).unwrap(),
        CaptureProtocolSet::TCP_AND_UDP,
        &["100.64.0.0/10"],
        Some(host_plan("203.0.113.7")),
    );
    let routing = local_routing_spec(Some(default_routing_target()), None);
    let baseline = lower_with_routing(&report, 24, default_target(), routing).unwrap();
    let lowered = lower_xtables_capture(
        lowering_request(report.program(), 24, default_target())
            .with_local_output_routing(routing)
            .with_local_output_canary_selector_slot(),
    )
    .unwrap();
    let baseline_pair = baseline.ipv4().unwrap();
    let pair = lowered.ipv4().unwrap();
    let slot = pair
        .local_output_canary_selector()
        .expect("required lowering reserves one selector slot");
    let observation = pair
        .local_output_canary_observation()
        .expect("required lowering reserves one attempt-observation slot");
    assert_eq!(slot, "FLX4C0000000024");
    assert_eq!(observation, "FLX4A0000000024");
    assert!(
        pair.entries()
            .iter()
            .all(|entry| entry.chain() != slot && entry.chain() != observation)
    );

    let prepare = restore_text(pair.prepare());
    let owner = prepare.find("--uid-owner 1000 --gid-owner 1000").unwrap();
    let mandatory = prepare.find("-d 0.0.0.0/8 -j RETURN").unwrap();
    let host = prepare.find("-d 203.0.113.7/32 -j RETURN").unwrap();
    let selector = prepare
        .find("-A FLX4O0000000024 -j FLX4C0000000024")
        .unwrap();
    let configured = prepare.find("-d 100.64.0.0/10 -j RETURN").unwrap();
    let application = prepare.find("--uid-owner 1001 -j RETURN").unwrap();
    let proxy = prepare.find("-p tcp -j MARK --set-xmark").unwrap();
    assert!(
        owner < mandatory
            && mandatory < host
            && host < selector
            && selector < configured
            && configured < application
            && application < proxy
    );
    assert!(prepare.contains(":FLX4C0000000024 - [0:0]\n"));
    assert!(!prepare.contains("-A FLX4C0000000024 "));
    assert!(prepare.contains(":FLX4A0000000024 - [0:0]\n"));
    assert!(!prepare.contains("-A FLX4A0000000024 "));

    let retire = restore_text(pair.retire());
    assert!(retire.contains("-F FLX4C0000000024\n"));
    assert!(retire.contains("-X FLX4C0000000024\n"));
    assert!(retire.contains("-F FLX4A0000000024\n"));
    assert!(retire.contains("-X FLX4A0000000024\n"));
    assert_eq!(
        pair.usage().implementation_chains(),
        baseline_pair.usage().implementation_chains() + 2
    );
    assert_eq!(
        pair.usage().prepare_commands(),
        baseline_pair.usage().prepare_commands() + 1
    );
    assert_eq!(
        pair.usage().retire_commands(),
        baseline_pair.usage().retire_commands() + 4
    );
    assert_eq!(pair.usage().maximum_jump_depth(), 2);
    assert_ne!(lowered.lowering_digest(), baseline.lowering_digest());
}

#[test]
fn canary_slot_requires_a_proxy_capable_local_output_program() {
    let forwarded = compile_program(
        scope(AddressHostFamilySelection::Ipv4, false, true),
        interfaces(&[], &[exact("wlan0")], &[]),
        CaptureProtocolSet::TCP,
        &[],
    );
    assert_eq!(
        lower_xtables_capture(
            lowering_request(forwarded.program(), 25, default_target())
                .with_local_output_canary_selector_slot(),
        ),
        Err(
            XtablesCaptureLoweringError::MissingLocalOutputCanarySelectorAnchor {
                family: NetworkAddressFamily::Ipv4,
            }
        )
    );

    let all_direct = compile_program_with_application(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        interfaces(&[], &[], &[]),
        CaptureApplicationPolicy::new(CaptureApplicationMode::Allowlist, []).unwrap(),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    assert_eq!(
        lower_xtables_capture(
            lowering_request(all_direct.program(), 25, default_target())
                .with_local_output_canary_selector_slot(),
        ),
        Err(
            XtablesCaptureLoweringError::MissingLocalOutputCanarySelectorAnchor {
                family: NetworkAddressFamily::Ipv4,
            }
        )
    );
}

#[test]
fn ipv6_local_output_uses_kernel_canonical_scope_and_explicit_metric() {
    let report = compile_program(
        scope(AddressHostFamilySelection::Ipv6, true, false),
        interfaces(&[], &[], &[]),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    let lowered = lower_with_routing(
        &report,
        2,
        default_target(),
        local_routing_spec(None, Some(default_routing_target())),
    )
    .unwrap();
    let routing = lowered.ipv6().unwrap().local_output().unwrap().routing();

    assert_eq!(routing.route_scope().raw(), 0);
    assert_eq!(routing.route_metric().get(), DEFAULT_ROUTE_METRIC);
    assert_eq!(routing.rule_protocol().raw(), DEFAULT_RULE_PROTOCOL);
}

#[test]
fn dual_stack_mixed_programs_use_distinct_local_and_forwarded_roles() {
    let report = compile_program(
        scope(AddressHostFamilySelection::DualStack, true, true),
        interfaces(&[], &[exact("wlan0")], &[]),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    let lowered = lower_with_routing(
        &report,
        17,
        default_target(),
        local_routing_spec(
            Some(default_routing_target()),
            Some(routing_target(
                DEFAULT_ROUTE_PRIORITY + 1,
                DEFAULT_ROUTE_TABLE + 1,
                DEFAULT_ROUTE_METRIC,
                DEFAULT_ROUTE_PROTOCOL,
                DEFAULT_RULE_PROTOCOL,
            )),
        ),
    )
    .unwrap();
    assert_eq!(lowered.schema_version(), 2);

    for (family, digit) in [
        (XtablesRestoreFamily::Ipv4, '4'),
        (XtablesRestoreFamily::Ipv6, '6'),
    ] {
        let pair = lowered.pair(family).unwrap();
        assert_eq!(
            pair.entries()
                .iter()
                .map(|entry| (entry.role(), entry.chain().to_owned()))
                .collect::<Vec<_>>(),
            vec![
                (
                    XtablesCaptureEntryPointRole::LocalOutputClassifier,
                    format!("FLX{digit}O0000000017"),
                ),
                (
                    XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy,
                    format!("FLX{digit}P0000000017"),
                ),
                (
                    XtablesCaptureEntryPointRole::ForwardedIngress,
                    format!("FLX{digit}F0000000017"),
                ),
            ]
        );
        let order = pair.transaction_order();
        let attach = order
            .prepare()
            .iter()
            .copied()
            .filter(|step| matches!(step, XtablesCaptureTransactionStep::AttachEntryPoint(_)))
            .collect::<Vec<_>>();
        assert_eq!(
            attach,
            [
                XtablesCaptureTransactionStep::AttachEntryPoint(
                    XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy,
                ),
                XtablesCaptureTransactionStep::AttachEntryPoint(
                    XtablesCaptureEntryPointRole::ForwardedIngress,
                ),
                XtablesCaptureTransactionStep::AttachEntryPoint(
                    XtablesCaptureEntryPointRole::LocalOutputClassifier,
                ),
            ]
        );
        let prepare = restore_text(pair.prepare());
        assert!(prepare.contains(" -j MARK --set-xmark "));
        assert!(prepare.contains(" -j TPROXY --on-port "));
        assert!(!modifies_builtin_hook(&prepare));
        assert_eq!(pair.usage().implementation_chains(), 3);
    }
}

#[test]
fn local_uid_set_algebra_is_preserved_during_mark_lowering() {
    let allowlist = compile_program_with_application(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        interfaces(&[], &[], &[]),
        CaptureApplicationPolicy::new(CaptureApplicationMode::Allowlist, [uid(1001), uid(1002)])
            .unwrap(),
        CaptureProtocolSet::TCP,
        &[],
    );
    let allowlist = lower_with_routing(
        &allowlist,
        21,
        default_target(),
        local_routing_spec(Some(default_routing_target()), None),
    )
    .unwrap();
    let allowlist = restore_text(allowlist.ipv4().unwrap().prepare());
    for selected in [1001, 1002] {
        assert!(allowlist.contains(&format!(
            "-A FLX4O0000000021 -m owner --uid-owner {selected} -p tcp -j MARK --set-xmark 0x200000/0x600000\n"
        )));
    }
    assert!(!allowlist.contains(" ! "));
    assert!(!allowlist.contains("-A FLX4O0000000021 -p tcp -j MARK"));
    assert!(!allowlist.contains(" -p udp "));

    let denylist = compile_program_with_application(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        interfaces(&[], &[], &[]),
        CaptureApplicationPolicy::new(CaptureApplicationMode::Denylist, [uid(1001), uid(1002)])
            .unwrap(),
        CaptureProtocolSet::UDP,
        &[],
    );
    let denylist = lower_with_routing(
        &denylist,
        22,
        default_target(),
        local_routing_spec(Some(default_routing_target()), None),
    )
    .unwrap();
    let denylist = restore_text(denylist.ipv4().unwrap().prepare());
    let first_uid = denylist.find("--uid-owner 1001 -j RETURN").unwrap();
    let second_uid = denylist.find("--uid-owner 1002 -j RETURN").unwrap();
    let proxy = denylist
        .find("-A FLX4O0000000022 -p udp -j MARK --set-xmark")
        .unwrap();
    assert!(first_uid < second_uid && second_uid < proxy);
    assert!(!denylist.contains(" -p tcp "));
}

#[test]
fn local_direct_rules_preserve_owner_destination_interface_uid_and_proxy_order() {
    let report = compile_program_with_application_and_host(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        interfaces(
            &[exact("tun0")],
            &[],
            &[prefix_interface("wlan"), exact("rmnet0")],
        ),
        CaptureApplicationPolicy::new(CaptureApplicationMode::Denylist, [uid(1001)]).unwrap(),
        CaptureProtocolSet::TCP,
        &["100.64.0.0/10"],
        Some(host_plan("203.0.113.7")),
    );
    let lowered = lower_with_routing(
        &report,
        23,
        default_target(),
        local_routing_spec(Some(default_routing_target()), None),
    )
    .unwrap();
    let prepare = restore_text(lowered.ipv4().unwrap().prepare());

    let owner = prepare.find("--uid-owner 1000 --gid-owner 1000").unwrap();
    let mandatory = prepare.find("-d 0.0.0.0/8 -j RETURN").unwrap();
    let host = prepare.find("-d 203.0.113.7/32 -j RETURN").unwrap();
    let configured = prepare.find("-d 100.64.0.0/10 -j RETURN").unwrap();
    let excluded = prepare.find("-o tun0 -j RETURN").unwrap();
    let local_prefix = prepare.find("-o wlan+ -j RETURN").unwrap();
    let local_exact = prepare.find("-o rmnet0 -j RETURN").unwrap();
    let denied_uid = prepare.find("--uid-owner 1001 -j RETURN").unwrap();
    let proxy = prepare.find("-p tcp -j MARK --set-xmark").unwrap();
    assert!(
        owner < mandatory
            && mandatory < host
            && host < configured
            && configured < excluded
            && excluded < local_prefix
            && local_prefix < local_exact
            && local_exact < denied_uid
            && denied_uid < proxy
    );
}

#[test]
fn all_direct_local_output_needs_no_companion_or_routing() {
    let report = compile_program_with_application(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        interfaces(&[], &[], &[]),
        CaptureApplicationPolicy::new(CaptureApplicationMode::Allowlist, []).unwrap(),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    let lowered = lower(&report, 25, default_target()).unwrap();
    assert_eq!(lowered.schema_version(), 2);
    let pair = lowered.ipv4().unwrap();
    assert_eq!(pair.entries().len(), 1);
    assert_eq!(
        pair.entries()[0].role(),
        XtablesCaptureEntryPointRole::LocalOutputClassifier
    );
    assert_eq!(pair.local_output(), None);
    assert_eq!(pair.usage().routing_objects(), 0);
    assert_eq!(pair.usage().listener_requirements(), 0);
    let prepare = restore_text(pair.prepare());
    assert!(!prepare.contains(" -j MARK "));
    assert!(!prepare.contains("TPROXY"));
    assert!(!prepare.contains("FLX4P"));

    assert_eq!(
        lower_with_routing(
            &report,
            25,
            default_target(),
            local_routing_spec(Some(default_routing_target()), None),
        ),
        Err(XtablesCaptureLoweringError::UnexpectedLocalOutputRouting {
            family: NetworkAddressFamily::Ipv4,
        })
    );
}

#[test]
fn local_routing_target_rejects_non_actionable_identities() {
    assert_eq!(
        XtablesLocalOutputRoutingSpec::new(None, None),
        Err(XtablesLocalOutputRoutingSpecError::NoEnabledFamilies)
    );
    assert_eq!(
        XtablesLocalOutputRoutingTarget::new(
            RulePriority::from_raw(0),
            RouteTableId::from_raw(DEFAULT_ROUTE_TABLE),
            NonZeroU32::new(DEFAULT_ROUTE_METRIC).unwrap(),
            RouteProtocol::from_raw(DEFAULT_ROUTE_PROTOCOL),
            RuleProtocol::from_raw(DEFAULT_RULE_PROTOCOL),
        ),
        Err(XtablesLocalOutputRoutingTargetError::ZeroPriority)
    );
    for table in [0, 252, 253, 254, 255] {
        assert_eq!(
            XtablesLocalOutputRoutingTarget::new(
                RulePriority::from_raw(DEFAULT_ROUTE_PRIORITY),
                RouteTableId::from_raw(table),
                NonZeroU32::new(DEFAULT_ROUTE_METRIC).unwrap(),
                RouteProtocol::from_raw(DEFAULT_ROUTE_PROTOCOL),
                RuleProtocol::from_raw(DEFAULT_RULE_PROTOCOL),
            ),
            Err(XtablesLocalOutputRoutingTargetError::ReservedTable {
                table: RouteTableId::from_raw(table),
            })
        );
    }
    assert_eq!(
        XtablesLocalOutputRoutingTarget::new(
            RulePriority::from_raw(DEFAULT_ROUTE_PRIORITY),
            RouteTableId::from_raw(DEFAULT_ROUTE_TABLE),
            NonZeroU32::new(DEFAULT_ROUTE_METRIC).unwrap(),
            RouteProtocol::from_raw(0),
            RuleProtocol::from_raw(DEFAULT_RULE_PROTOCOL),
        ),
        Err(XtablesLocalOutputRoutingTargetError::UnspecifiedRouteProtocol)
    );
    assert_eq!(
        XtablesLocalOutputRoutingTarget::new(
            RulePriority::from_raw(DEFAULT_ROUTE_PRIORITY),
            RouteTableId::from_raw(DEFAULT_ROUTE_TABLE),
            NonZeroU32::new(DEFAULT_ROUTE_METRIC).unwrap(),
            RouteProtocol::from_raw(DEFAULT_ROUTE_PROTOCOL),
            RuleProtocol::from_raw(0),
        ),
        Err(XtablesLocalOutputRoutingTargetError::UnspecifiedRuleProtocol)
    );
}

#[test]
fn every_unsupported_extension_is_rejected_explicitly() {
    let report = compile_program(
        scope(AddressHostFamilySelection::Ipv4, false, true),
        interfaces(&[], &[exact("wlan0")], &[]),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    let cases = [
        (
            XtablesCaptureExtensions::new(true, false, false, false, false),
            XtablesCaptureExtension::EstablishedFlowCache,
        ),
        (
            XtablesCaptureExtensions::new(false, true, false, false, false),
            XtablesCaptureExtension::TransparentSocketDivert,
        ),
        (
            XtablesCaptureExtensions::new(false, false, true, false, false),
            XtablesCaptureExtension::FakeIpIcmp,
        ),
        (
            XtablesCaptureExtensions::new(false, false, false, true, false),
            XtablesCaptureExtension::QuicReject,
        ),
        (
            XtablesCaptureExtensions::new(false, false, false, false, true),
            XtablesCaptureExtension::MssClamp,
        ),
    ];

    for (extensions, extension) in cases {
        assert_eq!(
            lower_xtables_capture(
                lowering_request(report.program(), DEFAULT_GENERATION, default_target())
                    .with_extensions(extensions)
            ),
            Err(XtablesCaptureLoweringError::UnsupportedExtension { extension })
        );
    }
}

#[test]
fn forwarded_interface_token_boundaries_fail_closed() {
    let cases = [
        (
            CaptureInterfaceSelector::exact(interface_bytes(b"-wlan0")),
            XtablesInterfaceRenderErrorKind::LeadingDash,
        ),
        (
            CaptureInterfaceSelector::exact(interface_bytes(b"bad name")),
            XtablesInterfaceRenderErrorKind::UnsupportedByte,
        ),
        (
            CaptureInterfaceSelector::exact(interface_bytes(&[b'w', 0xff])),
            XtablesInterfaceRenderErrorKind::UnsupportedByte,
        ),
        (
            CaptureInterfaceSelector::exact(interface_bytes(b"wlan+")),
            XtablesInterfaceRenderErrorKind::AmbiguousTrailingWildcard,
        ),
        (
            CaptureInterfaceSelector::prefix(interface_bytes(b"abcdefghijklmno")),
            XtablesInterfaceRenderErrorKind::PrefixWildcardExceedsInterfaceLimit,
        ),
    ];

    for (selector, expected_reason) in cases {
        let report = compile_program(
            scope(AddressHostFamilySelection::Ipv4, false, true),
            interfaces(&[], &[selector], &[]),
            CaptureProtocolSet::TCP_AND_UDP,
            &[],
        );
        let error = lower(&report, DEFAULT_GENERATION, default_target()).unwrap_err();
        assert!(matches!(
            error,
            XtablesCaptureLoweringError::UnrenderableInterface {
                reason,
                ..
            } if reason == expected_reason
        ));
    }

    for selector in [
        CaptureInterfaceSelector::exact(interface_bytes(b"abcdefghijklmno")),
        CaptureInterfaceSelector::prefix(interface_bytes(b"abcdefghijklmn")),
    ] {
        let report = compile_program(
            scope(AddressHostFamilySelection::Ipv4, false, true),
            interfaces(&[], &[selector], &[]),
            CaptureProtocolSet::TCP_AND_UDP,
            &[],
        );
        lower(&report, DEFAULT_GENERATION, default_target()).expect("renderable IFNAMSIZ boundary");
    }
}

#[test]
fn forwarded_expansion_honors_the_exact_command_budget() {
    let report = compile_program(
        scope(AddressHostFamilySelection::Ipv4, false, true),
        interfaces(
            &[],
            &[exact("wlan0"), prefix_interface("rmnet"), exact("rndis0")],
            &[],
        ),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    let baseline = lower(&report, DEFAULT_GENERATION, default_target()).unwrap();
    let required = baseline.ipv4().unwrap().usage().prepare_commands();
    assert!(required > 1);

    let exact_budget = XtablesCaptureLoweringBudget::new(required).unwrap();
    let exact = lower_xtables_capture(
        lowering_request(report.program(), DEFAULT_GENERATION, default_target())
            .with_budget(exact_budget),
    )
    .expect("exact command budget");
    assert_eq!(exact, baseline);

    let smaller_budget = XtablesCaptureLoweringBudget::new(required - 1).unwrap();
    assert_eq!(
        lower_xtables_capture(
            lowering_request(report.program(), DEFAULT_GENERATION, default_target())
                .with_budget(smaller_budget)
        ),
        Err(XtablesCaptureLoweringError::CommandBudgetExceeded {
            family: XtablesRestoreFamily::Ipv4,
            action: XtablesRestoreAction::Apply,
            maximum: required - 1,
            required,
        })
    );
}

#[test]
fn local_output_preflights_the_combined_classifier_and_companion_budget() {
    let report = compile_program_with_application(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        interfaces(&[], &[], &[]),
        CaptureApplicationPolicy::new(
            CaptureApplicationMode::Allowlist,
            [uid(1001), uid(1002), uid(1003)],
        )
        .unwrap(),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    let routing = local_routing_spec(Some(default_routing_target()), None);
    let baseline = lower_with_routing(&report, 31, default_target(), routing).unwrap();
    let required = baseline.ipv4().unwrap().usage().prepare_commands();
    let exact = lower_xtables_capture(
        lowering_request(report.program(), 31, default_target())
            .with_local_output_routing(routing)
            .with_budget(XtablesCaptureLoweringBudget::new(required).unwrap()),
    )
    .unwrap();
    assert_eq!(exact, baseline);

    assert_eq!(
        lower_xtables_capture(
            lowering_request(report.program(), 31, default_target())
                .with_local_output_routing(routing)
                .with_budget(XtablesCaptureLoweringBudget::new(required - 1).unwrap()),
        ),
        Err(XtablesCaptureLoweringError::CommandBudgetExceeded {
            family: XtablesRestoreFamily::Ipv4,
            action: XtablesRestoreAction::Apply,
            maximum: required - 1,
            required,
        })
    );
}

#[test]
fn forwarded_expansion_preflights_the_immutable_restore_byte_limit() {
    let configured = (1_u128..=16_377).map(|offset| {
        CaptureIpPrefix::new(
            IpAddr::V6(Ipv6Addr::from(
                0x2001_0db8_1111_2222_3333_4444_5555_0000_u128 + offset,
            )),
            128,
        )
        .unwrap()
    });
    let report = compile_capture_program(CaptureProgramRequest::new(
        scope(AddressHostFamilySelection::Ipv6, false, true),
        EngineCredentials::new(uid(1000), gid(1000)),
        CaptureBypassPolicy::new(configured).unwrap(),
        None,
        interfaces(&[], &[], &[]),
        CaptureApplicationPolicy::new(CaptureApplicationMode::All, []).unwrap(),
        CaptureProtocolSet::TCP,
    ))
    .unwrap();

    assert!(matches!(
        lower(&report, DEFAULT_GENERATION, default_target()),
        Err(XtablesCaptureLoweringError::ArtifactByteLimitExceeded {
            family: XtablesRestoreFamily::Ipv6,
            action: XtablesRestoreAction::Apply,
            maximum: MAX_XTABLES_RESTORE_BYTES,
            required,
        }) if required > MAX_XTABLES_RESTORE_BYTES
    ));
}

#[test]
fn local_output_expansion_preflights_the_immutable_restore_byte_limit() {
    let configured = (1_u128..=14_050).map(|offset| {
        CaptureIpPrefix::new(
            IpAddr::V6(Ipv6Addr::from(
                0x2001_0db8_1111_2222_3333_4444_5555_0000_u128 + offset,
            )),
            128,
        )
        .unwrap()
    });
    let report = compile_capture_program(CaptureProgramRequest::new(
        scope(AddressHostFamilySelection::Ipv6, true, false),
        EngineCredentials::new(uid(1000), gid(1000)),
        CaptureBypassPolicy::new(configured).unwrap(),
        None,
        interfaces(&[], &[], &[]),
        CaptureApplicationPolicy::new(CaptureApplicationMode::All, []).unwrap(),
        CaptureProtocolSet::TCP,
    ))
    .unwrap();

    let result = lower_with_routing(
        &report,
        DEFAULT_GENERATION,
        default_target(),
        local_routing_spec(None, Some(default_routing_target())),
    );
    match result {
        Err(XtablesCaptureLoweringError::ArtifactByteLimitExceeded {
            family: XtablesRestoreFamily::Ipv6,
            action: XtablesRestoreAction::Apply,
            maximum: MAX_XTABLES_RESTORE_BYTES,
            required,
        }) => assert!(required > MAX_XTABLES_RESTORE_BYTES),
        Ok(artifact) => panic!(
            "local byte-limit fixture unexpectedly lowered {} bytes",
            artifact.ipv6().unwrap().prepare().usage().input_bytes()
        ),
        Err(error) => panic!("unexpected local byte-limit error: {error}"),
    }
}

#[test]
fn forwarded_artifact_identity_binds_program_namespace_port_and_marks_but_not_budget() {
    let report = compile_program(
        scope(AddressHostFamilySelection::Ipv4, false, true),
        interfaces(&[], &[exact("wlan0")], &[]),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    let baseline = lower(&report, 1, default_target()).unwrap();
    let required = baseline.ipv4().unwrap().usage().prepare_commands();
    let bounded = lower_xtables_capture(
        lowering_request(report.program(), 1, default_target())
            .with_budget(XtablesCaptureLoweringBudget::new(required).unwrap()),
    )
    .unwrap();
    assert_eq!(baseline, bounded);

    let next_generation = lower(&report, 2, default_target()).unwrap();
    assert_ne!(
        baseline.lowering_digest(),
        next_generation.lowering_digest()
    );
    assert_ne!(baseline.digest(), next_generation.digest());
    assert_ne!(
        restore_text(baseline.ipv4().unwrap().prepare()),
        restore_text(next_generation.ipv4().unwrap().prepare())
    );

    let next_port = lower(&report, 1, target(1537, default_mark())).unwrap();
    assert_ne!(baseline.lowering_digest(), next_port.lowering_digest());
    assert_ne!(baseline.digest(), next_port.digest());

    let reversed_mark =
        FwmarkCandidate::new(DEFAULT_MARK_MASK, DEFAULT_BYPASS_MARK, DEFAULT_PROXY_MARK).unwrap();
    let next_mark = lower(&report, 1, target(DEFAULT_PROXY_PORT, reversed_mark)).unwrap();
    assert_ne!(baseline.lowering_digest(), next_mark.lowering_digest());
    assert_ne!(baseline.digest(), next_mark.digest());

    let alternate_bypass =
        FwmarkCandidate::new(DEFAULT_MARK_MASK, DEFAULT_PROXY_MARK, DEFAULT_MARK_MASK).unwrap();
    let next_bypass = lower(&report, 1, target(DEFAULT_PROXY_PORT, alternate_bypass)).unwrap();
    assert_ne!(baseline.lowering_digest(), next_bypass.lowering_digest());
    assert_ne!(baseline.digest(), next_bypass.digest());
    assert_eq!(
        restore_text(baseline.ipv4().unwrap().prepare()),
        restore_text(next_bypass.ipv4().unwrap().prepare()),
        "the unused bypass value is identity-bound without changing forwarded restore bytes"
    );

    let tcp_only = compile_program(
        scope(AddressHostFamilySelection::Ipv4, false, true),
        interfaces(&[], &[exact("wlan0")], &[]),
        CaptureProtocolSet::TCP,
        &[],
    );
    let next_program = lower(&tcp_only, 1, default_target()).unwrap();
    assert_ne!(
        baseline.source_program_digest(),
        next_program.source_program_digest()
    );
    assert_ne!(baseline.lowering_digest(), next_program.lowering_digest());
    assert_ne!(baseline.digest(), next_program.digest());
}

#[test]
fn local_identity_binds_routing_and_derived_transaction_requirements() {
    let report = compile_program(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        interfaces(&[], &[], &[]),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    let baseline_routing = local_routing_spec(Some(default_routing_target()), None);
    let baseline = lower_with_routing(&report, 41, default_target(), baseline_routing).unwrap();
    let required = baseline.ipv4().unwrap().usage().prepare_commands();
    let bounded = lower_xtables_capture(
        lowering_request(report.program(), 41, default_target())
            .with_local_output_routing(baseline_routing)
            .with_budget(XtablesCaptureLoweringBudget::new(required).unwrap()),
    )
    .unwrap();
    assert_eq!(baseline, bounded);

    for changed in [
        routing_target(
            DEFAULT_ROUTE_PRIORITY + 1,
            DEFAULT_ROUTE_TABLE,
            DEFAULT_ROUTE_METRIC,
            DEFAULT_ROUTE_PROTOCOL,
            DEFAULT_RULE_PROTOCOL,
        ),
        routing_target(
            DEFAULT_ROUTE_PRIORITY,
            DEFAULT_ROUTE_TABLE + 1,
            DEFAULT_ROUTE_METRIC,
            DEFAULT_ROUTE_PROTOCOL,
            DEFAULT_RULE_PROTOCOL,
        ),
        routing_target(
            DEFAULT_ROUTE_PRIORITY,
            DEFAULT_ROUTE_TABLE,
            DEFAULT_ROUTE_METRIC + 1,
            DEFAULT_ROUTE_PROTOCOL,
            DEFAULT_RULE_PROTOCOL,
        ),
        routing_target(
            DEFAULT_ROUTE_PRIORITY,
            DEFAULT_ROUTE_TABLE,
            DEFAULT_ROUTE_METRIC,
            DEFAULT_ROUTE_PROTOCOL + 1,
            DEFAULT_RULE_PROTOCOL,
        ),
        routing_target(
            DEFAULT_ROUTE_PRIORITY,
            DEFAULT_ROUTE_TABLE,
            DEFAULT_ROUTE_METRIC,
            DEFAULT_ROUTE_PROTOCOL,
            DEFAULT_RULE_PROTOCOL + 1,
        ),
    ] {
        let changed = lower_with_routing(
            &report,
            41,
            default_target(),
            local_routing_spec(Some(changed), None),
        )
        .unwrap();
        assert_ne!(baseline.lowering_digest(), changed.lowering_digest());
        assert_ne!(baseline.digest(), changed.digest());
        assert_eq!(
            restore_text(baseline.ipv4().unwrap().prepare()),
            restore_text(changed.ipv4().unwrap().prepare()),
            "routing identity is descriptive and does not alter private chain bytes"
        );
    }
}

fn compile_program(
    scope: CaptureTrafficScope,
    interfaces: CaptureInterfacePolicy,
    protocols: CaptureProtocolSet,
    bypasses: &[&str],
) -> CaptureProgramCompilation {
    compile_program_with_host(scope, interfaces, protocols, bypasses, None)
}

fn compile_program_with_host(
    scope: CaptureTrafficScope,
    interfaces: CaptureInterfacePolicy,
    protocols: CaptureProtocolSet,
    bypasses: &[&str],
    host_bypass: Option<AddressHostSetPlan>,
) -> CaptureProgramCompilation {
    compile_program_with_application_and_host(
        scope,
        interfaces,
        CaptureApplicationPolicy::new(CaptureApplicationMode::All, []).unwrap(),
        protocols,
        bypasses,
        host_bypass,
    )
}

fn compile_program_with_application(
    scope: CaptureTrafficScope,
    interfaces: CaptureInterfacePolicy,
    applications: CaptureApplicationPolicy,
    protocols: CaptureProtocolSet,
    bypasses: &[&str],
) -> CaptureProgramCompilation {
    compile_program_with_application_and_host(
        scope,
        interfaces,
        applications,
        protocols,
        bypasses,
        None,
    )
}

fn compile_program_with_application_and_host(
    scope: CaptureTrafficScope,
    interfaces: CaptureInterfacePolicy,
    applications: CaptureApplicationPolicy,
    protocols: CaptureProtocolSet,
    bypasses: &[&str],
    host_bypass: Option<AddressHostSetPlan>,
) -> CaptureProgramCompilation {
    compile_capture_program(CaptureProgramRequest::new(
        scope,
        EngineCredentials::new(uid(1000), gid(1000)),
        CaptureBypassPolicy::new(bypasses.iter().copied().map(capture_prefix)).unwrap(),
        host_bypass,
        interfaces,
        applications,
        protocols,
    ))
    .unwrap()
}

fn host_plan(address: &str) -> AddressHostSetPlan {
    let address = address.parse::<IpAddr>().unwrap();
    let mut tracker = NetworkInventoryTracker::new();
    let inventory = tracker
        .publish_complete(
            [],
            [InterfaceAddressRecord::new(
                InterfaceIndex::new(1).unwrap(),
                address,
                match address {
                    IpAddr::V4(_) => 24,
                    IpAddr::V6(_) => 64,
                },
                InterfaceAddressFlags::from_bits(0),
            )
            .unwrap()],
        )
        .unwrap()
        .clone();
    let families = match address {
        IpAddr::V4(_) => AddressHostFamilySelection::Ipv4,
        IpAddr::V6(_) => AddressHostFamilySelection::Ipv6,
    };
    plan_address_host_set(
        &inventory,
        &AddressHostSetPolicy::new(families, AddressBypassRuleBudget::new(64).unwrap()),
    )
    .unwrap()
}

fn lower(
    report: &CaptureProgramCompilation,
    generation: u32,
    target: XtablesTproxyTarget,
) -> Result<XtablesCaptureArtifactSet, XtablesCaptureLoweringError> {
    lower_xtables_capture(lowering_request(report.program(), generation, target))
}

fn lower_with_routing(
    report: &CaptureProgramCompilation,
    generation: u32,
    target: XtablesTproxyTarget,
    routing: XtablesLocalOutputRoutingSpec,
) -> Result<XtablesCaptureArtifactSet, XtablesCaptureLoweringError> {
    lower_xtables_capture(
        lowering_request(report.program(), generation, target).with_local_output_routing(routing),
    )
}

fn lowering_request(
    artifact: &CaptureProgram,
    generation: u32,
    target: XtablesTproxyTarget,
) -> XtablesCaptureLoweringRequest<'_> {
    XtablesCaptureLoweringRequest::new(
        artifact,
        XtablesCaptureNamespace::new(GenerationId::new(generation).unwrap()),
        target,
    )
}

fn default_target() -> XtablesTproxyTarget {
    target(DEFAULT_PROXY_PORT, default_mark())
}

fn target(proxy_port: u16, mark: FwmarkCandidate) -> XtablesTproxyTarget {
    XtablesTproxyTarget::new(NonZeroU16::new(proxy_port).unwrap(), mark)
}

fn default_mark() -> FwmarkCandidate {
    FwmarkCandidate::new(DEFAULT_MARK_MASK, DEFAULT_PROXY_MARK, DEFAULT_BYPASS_MARK).unwrap()
}

fn local_routing_spec(
    ipv4: Option<XtablesLocalOutputRoutingTarget>,
    ipv6: Option<XtablesLocalOutputRoutingTarget>,
) -> XtablesLocalOutputRoutingSpec {
    XtablesLocalOutputRoutingSpec::new(ipv4, ipv6).unwrap()
}

fn default_routing_target() -> XtablesLocalOutputRoutingTarget {
    routing_target(
        DEFAULT_ROUTE_PRIORITY,
        DEFAULT_ROUTE_TABLE,
        DEFAULT_ROUTE_METRIC,
        DEFAULT_ROUTE_PROTOCOL,
        DEFAULT_RULE_PROTOCOL,
    )
}

fn routing_target(
    priority: u32,
    table: u32,
    route_metric: u32,
    route_protocol: u8,
    rule_protocol: u8,
) -> XtablesLocalOutputRoutingTarget {
    XtablesLocalOutputRoutingTarget::new(
        RulePriority::from_raw(priority),
        RouteTableId::from_raw(table),
        NonZeroU32::new(route_metric).unwrap(),
        RouteProtocol::from_raw(route_protocol),
        RuleProtocol::from_raw(rule_protocol),
    )
    .unwrap()
}

fn scope(
    families: AddressHostFamilySelection,
    local_output: bool,
    forwarded_ingress: bool,
) -> CaptureTrafficScope {
    CaptureTrafficScope::new(families, local_output, forwarded_ingress).unwrap()
}

fn interfaces(
    excluded: &[CaptureInterfaceSelector],
    forwarded_proxy: &[CaptureInterfaceSelector],
    local_bypass: &[CaptureInterfaceSelector],
) -> CaptureInterfacePolicy {
    CaptureInterfacePolicy::new(
        excluded.iter().copied(),
        forwarded_proxy.iter().copied(),
        local_bypass.iter().copied(),
    )
    .unwrap()
}

fn exact(value: &str) -> CaptureInterfaceSelector {
    CaptureInterfaceSelector::exact(interface_bytes(value.as_bytes()))
}

fn prefix_interface(value: &str) -> CaptureInterfaceSelector {
    CaptureInterfaceSelector::prefix(interface_bytes(value.as_bytes()))
}

fn interface_bytes(value: &[u8]) -> InterfaceName {
    InterfaceName::new(value).unwrap()
}

fn uid(value: u32) -> CaptureUserId {
    CaptureUserId::new(value).unwrap()
}

fn gid(value: u32) -> CaptureGroupId {
    CaptureGroupId::new(value).unwrap()
}

fn capture_prefix(value: &str) -> CaptureIpPrefix {
    let (address, prefix_length) = value.split_once('/').unwrap();
    CaptureIpPrefix::new(
        address.parse::<IpAddr>().unwrap(),
        prefix_length.parse().unwrap(),
    )
    .unwrap()
}

fn restore_text(artifact: &flux_platform::XtablesRestoreArtifact) -> String {
    String::from_utf8(artifact.render_canonical().into_vec()).unwrap()
}

fn modifies_builtin_hook(artifact: &str) -> bool {
    artifact.lines().any(|line| {
        let mut tokens = line.split_ascii_whitespace();
        matches!(tokens.next(), Some("-A" | "-I" | "-D" | "-F" | "-X"))
            && matches!(tokens.next(), Some("OUTPUT" | "PREROUTING"))
    })
}

fn digest_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
