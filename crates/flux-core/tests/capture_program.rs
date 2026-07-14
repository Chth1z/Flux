use std::net::IpAddr;

use flux_core::{
    AddressBypassRuleBudget, AddressHostFamilySelection, AddressHostSetPlan, AddressHostSetPolicy,
    CaptureApplicationMode, CaptureApplicationPolicy, CaptureApplicationPolicyError,
    CaptureBypassPolicy, CaptureBypassPolicyError, CaptureClause, CaptureClauseDecision,
    CaptureDecisionStage, CaptureDomainProgram, CaptureGroupId, CaptureInterfaceDirection,
    CaptureInterfacePolicy, CaptureInterfacePolicyError, CaptureInterfaceSelector, CaptureIpPrefix,
    CapturePredicate, CaptureProgramBudget, CaptureProgramBudgetError, CaptureProgramDigest,
    CaptureProgramResourceKind, CaptureProtocolSet, CaptureProtocolSetError, CaptureTrafficDomain,
    CaptureTrafficScope, CaptureTrafficScopeError, CaptureTransportProtocol, CaptureUserId,
    CompatibilityEngineCredentials, InterfaceAddressFlags, InterfaceAddressRecord, InterfaceIndex,
    InterfaceName, MAX_CAPTURE_HOST_ADDRESSES_PER_FAMILY, MAX_CAPTURE_INTERFACE_SELECTORS,
    MAX_CAPTURE_POLICY_PREFIX_INPUTS, MAX_CAPTURE_POLICY_PREFIXES_PER_FAMILY,
    MAX_CAPTURE_POLICY_UIDS, NetworkAddressFamily, NetworkInventoryTracker,
    SHADOW_CAPTURE_PROGRAM_SCHEMA_VERSION, ShadowCaptureCompileError, ShadowCaptureProgramRequest,
    ShadowCompatibilityAssumption, ShadowCompilationReport, ShadowDeferredPrerequisite,
    compile_shadow_capture_program, plan_address_host_set,
};

const LEGACY_ORACLE: &str = include_str!("fixtures/capture_program_legacy_oracle.fixture");

#[test]
fn frozen_shell_oracle_preserves_source_facts_but_compiles_canonical_semantics() {
    let source_ipv4 = fixture_prefixes("shell_bypass_ipv4");
    let source_ipv6 = fixture_prefixes("shell_bypass_ipv6");
    assert_eq!(source_ipv4.len(), 15);
    assert_eq!(source_ipv6.len(), 12);
    assert!(source_ipv4.contains(&prefix("255.255.255.255/32")));
    assert!(source_ipv6.contains(&prefix("::ffff:0:0/96")));

    let rfc6598 = prefix("100.64.0.0/10");
    let forbidden = fixture_prefixes("forbidden_regression_ipv4")[0];
    assert!(source_ipv4.contains(&rfc6598));
    assert!(!source_ipv4.contains(&forbidden));

    let report = compile(request(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        bypass([rfc6598]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let compiled = program(
        &report,
        NetworkAddressFamily::Ipv4,
        CaptureTrafficDomain::LocalOutput,
    );

    assert_eq!(
        prefixes_at(compiled, CaptureDecisionStage::MandatorySafety),
        [
            prefix("0.0.0.0/8"),
            prefix("127.0.0.0/8"),
            prefix("169.254.0.0/16"),
            prefix("224.0.0.0/4"),
            prefix("240.0.0.0/4"),
        ]
    );
    assert_eq!(
        prefixes_at(compiled, CaptureDecisionStage::ConfigurableBypass),
        [rfc6598]
    );
    assert!(!all_program_prefixes(compiled).contains(&forbidden));
    assert!(!all_program_prefixes(compiled).contains(&prefix("255.255.255.255/32")));

    assert_evaluation(
        compiled,
        local_packet(
            "100.64.1.2",
            CaptureTransportProtocol::Tcp,
            20_000,
            20_000,
            "wlan0",
        ),
        CaptureDecisionStage::ConfigurableBypass,
        CaptureClauseDecision::Direct,
    );
    assert_evaluation(
        compiled,
        local_packet(
            "100.1.2.3",
            CaptureTransportProtocol::Tcp,
            20_000,
            20_000,
            "wlan0",
        ),
        CaptureDecisionStage::ProxyAction,
        CaptureClauseDecision::Proxy,
    );
}

#[test]
fn mandatory_safety_is_compiler_owned_and_cannot_be_removed_or_reclassified() {
    let scope = scope(AddressHostFamilySelection::Ipv4, true, true);
    let baseline = compile(request(
        scope,
        bypass([]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let repeated_mandatory = compile(request(
        scope,
        bypass([
            prefix("0.0.0.0/8"),
            prefix("127.0.0.0/8"),
            prefix("169.254.0.0/16"),
            prefix("224.0.0.0/4"),
            prefix("240.0.0.0/4"),
            prefix("255.255.255.255/32"),
        ]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));

    assert_eq!(baseline.artifact(), repeated_mandatory.artifact());
    for domain in [
        CaptureTrafficDomain::LocalOutput,
        CaptureTrafficDomain::ForwardedIngress,
    ] {
        let compiled = program(&baseline, NetworkAddressFamily::Ipv4, domain);
        assert_eq!(
            prefixes_at(compiled, CaptureDecisionStage::MandatorySafety).len(),
            5
        );
        assert!(prefixes_at(compiled, CaptureDecisionStage::ConfigurableBypass).is_empty());
    }

    let local = program(
        &baseline,
        NetworkAddressFamily::Ipv4,
        CaptureTrafficDomain::LocalOutput,
    );
    assert_eq!(
        local.clauses()[0].stage(),
        CaptureDecisionStage::LoopPrevention
    );
    assert_eq!(
        local.clauses()[1].stage(),
        CaptureDecisionStage::MandatorySafety
    );
    let forwarded = program(
        &baseline,
        NetworkAddressFamily::Ipv4,
        CaptureTrafficDomain::ForwardedIngress,
    );
    assert_eq!(
        forwarded.clauses()[0].stage(),
        CaptureDecisionStage::MandatorySafety
    );
}

#[test]
fn ipv4_mapped_ipv6_prefixes_remain_in_the_ipv6_classifier() {
    let mapped = prefix("::ffff:192.0.2.129/120");
    assert_eq!(
        mapped.network(),
        "::ffff:192.0.2.0".parse::<IpAddr>().unwrap()
    );
    assert_eq!(mapped.prefix_length(), 120);
    assert_eq!(mapped.family(), NetworkAddressFamily::Ipv6);
    assert!(mapped.contains("::ffff:192.0.2.200".parse().unwrap()));
    assert!(!mapped.contains("192.0.2.200".parse().unwrap()));

    let report = compile(request(
        scope(AddressHostFamilySelection::DualStack, true, false),
        bypass([]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let ipv6 = program(
        &report,
        NetworkAddressFamily::Ipv6,
        CaptureTrafficDomain::LocalOutput,
    );
    let mandatory = prefixes_at(ipv6, CaptureDecisionStage::MandatorySafety);
    assert!(mandatory.contains(&prefix("::ffff:0:0/96")));
    assert!(
        mandatory
            .iter()
            .all(|prefix| prefix.family() == NetworkAddressFamily::Ipv6)
    );
}

#[test]
fn local_and_forwarded_domains_compile_separate_ordered_programs_without_forwarded_uids() {
    let report = compile(request(
        all_scope(),
        bypass([]),
        None,
        interfaces(
            &[],
            &[CaptureInterfaceSelector::prefix(interface("wlan"))],
            &[CaptureInterfaceSelector::exact(interface("tun0"))],
        ),
        applications(CaptureApplicationMode::Allowlist, &[10_123, 110_123]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    assert_eq!(
        report
            .artifact()
            .programs()
            .iter()
            .map(|program| (program.family(), program.domain()))
            .collect::<Vec<_>>(),
        [
            (
                NetworkAddressFamily::Ipv4,
                CaptureTrafficDomain::LocalOutput
            ),
            (
                NetworkAddressFamily::Ipv4,
                CaptureTrafficDomain::ForwardedIngress,
            ),
            (
                NetworkAddressFamily::Ipv6,
                CaptureTrafficDomain::LocalOutput
            ),
            (
                NetworkAddressFamily::Ipv6,
                CaptureTrafficDomain::ForwardedIngress,
            ),
        ]
    );

    for compiled in report.artifact().programs() {
        assert!(
            compiled
                .clauses()
                .windows(2)
                .all(|pair| pair[0].stage() <= pair[1].stage())
        );
        match compiled.domain() {
            CaptureTrafficDomain::LocalOutput => {
                assert!(compiled.clauses().iter().any(|clause| matches!(
                    clause.predicate(),
                    CapturePredicate::EngineCredentials(_)
                )));
                assert!(compiled.clauses().iter().any(|clause| matches!(
                    clause.predicate(),
                    CapturePredicate::LocalUidNotIn(_)
                )));
            }
            CaptureTrafficDomain::ForwardedIngress => {
                assert!(compiled.clauses().iter().all(|clause| !matches!(
                    clause.predicate(),
                    CapturePredicate::EngineCredentials(_)
                        | CapturePredicate::LocalUidIn(_)
                        | CapturePredicate::LocalUidNotIn(_)
                )));
            }
        }
    }
}

#[test]
fn application_modes_preserve_empty_populated_and_multi_user_semantics() {
    let local_scope = scope(AddressHostFamilySelection::Ipv4, true, false);
    let all = compile(request(
        local_scope,
        bypass([]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let empty_denylist = compile(request(
        local_scope,
        bypass([]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::Denylist, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    assert_eq!(all.artifact(), empty_denylist.artifact());
    assert_eq!(all.artifact().digest(), empty_denylist.artifact().digest());

    let empty_allowlist = compile(request(
        local_scope,
        bypass([]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::Allowlist, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let empty_allow_program = program(
        &empty_allowlist,
        NetworkAddressFamily::Ipv4,
        CaptureTrafficDomain::LocalOutput,
    );
    let terminal = empty_allow_program.clauses().last().unwrap();
    assert_eq!(terminal.stage(), CaptureDecisionStage::ApplicationPolicy);
    assert_eq!(terminal.predicate(), &CapturePredicate::Any);
    assert_eq!(terminal.decision(), CaptureClauseDecision::Direct);
    assert!(!empty_allow_program.clauses().iter().any(|clause| {
        matches!(
            clause.stage(),
            CaptureDecisionStage::ProtocolSafety | CaptureDecisionStage::ProxyAction
        )
    }));

    let resolved = fixture_values("resolved_uid")
        .into_iter()
        .map(|value| value.parse::<u32>().unwrap())
        .collect::<Vec<_>>();
    let allowlist = compile(request(
        local_scope,
        bypass([]),
        None,
        interfaces(&[], &[], &[]),
        applications(
            CaptureApplicationMode::Allowlist,
            &[resolved[1], resolved[0], resolved[1]],
        ),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let allow_program = program(
        &allowlist,
        NetworkAddressFamily::Ipv4,
        CaptureTrafficDomain::LocalOutput,
    );
    assert_eq!(
        local_uid_predicate(allow_program),
        [uid(10_123), uid(110_123)]
    );
    for selected in resolved {
        assert_evaluation(
            allow_program,
            local_packet(
                "8.8.8.8",
                CaptureTransportProtocol::Tcp,
                selected,
                30_000,
                "wlan0",
            ),
            CaptureDecisionStage::ProxyAction,
            CaptureClauseDecision::Proxy,
        );
    }
    assert_evaluation(
        allow_program,
        local_packet(
            "8.8.8.8",
            CaptureTransportProtocol::Tcp,
            210_123,
            30_000,
            "wlan0",
        ),
        CaptureDecisionStage::ApplicationPolicy,
        CaptureClauseDecision::Direct,
    );

    let denylist = compile(request(
        local_scope,
        bypass([]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::Denylist, &[10_123]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let deny_program = program(
        &denylist,
        NetworkAddressFamily::Ipv4,
        CaptureTrafficDomain::LocalOutput,
    );
    assert_evaluation(
        deny_program,
        local_packet(
            "8.8.8.8",
            CaptureTransportProtocol::Udp,
            10_123,
            30_000,
            "wlan0",
        ),
        CaptureDecisionStage::ApplicationPolicy,
        CaptureClauseDecision::Direct,
    );
    assert_evaluation(
        deny_program,
        local_packet(
            "8.8.8.8",
            CaptureTransportProtocol::Udp,
            10_124,
            30_000,
            "wlan0",
        ),
        CaptureDecisionStage::ProxyAction,
        CaptureClauseDecision::Proxy,
    );
}

#[test]
fn engine_loop_bypass_requires_the_exact_pair_and_precedes_safety_policy() {
    let report = compile(request(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        bypass([]),
        None,
        interfaces(
            &[CaptureInterfaceSelector::exact(interface("wlan0"))],
            &[],
            &[],
        ),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let program = program(
        &report,
        NetworkAddressFamily::Ipv4,
        CaptureTrafficDomain::LocalOutput,
    );
    let engine_uid = fixture_u32("engine_uid");
    let engine_gid = fixture_u32("engine_gid");

    assert_evaluation(
        program,
        local_packet(
            "127.0.0.1",
            CaptureTransportProtocol::Other,
            engine_uid,
            engine_gid,
            "wlan0",
        ),
        CaptureDecisionStage::LoopPrevention,
        CaptureClauseDecision::Direct,
    );
    assert_evaluation(
        program,
        local_packet(
            "127.0.0.1",
            CaptureTransportProtocol::Other,
            engine_uid,
            engine_gid + 1,
            "wlan0",
        ),
        CaptureDecisionStage::MandatorySafety,
        CaptureClauseDecision::Direct,
    );
    assert_evaluation(
        program,
        local_packet(
            "8.8.8.8",
            CaptureTransportProtocol::Tcp,
            engine_uid + 1,
            engine_gid,
            "eth0",
        ),
        CaptureDecisionStage::ProxyAction,
        CaptureClauseDecision::Proxy,
    );
}

#[test]
fn interface_rules_distinguish_exact_prefix_excluded_loopback_and_direction() {
    let exact = CaptureInterfaceSelector::exact(interface("wlan"));
    let prefix_selector = CaptureInterfaceSelector::prefix(interface("wlan"));
    assert!(exact.matches(interface("wlan")));
    assert!(!exact.matches(interface("wlan0")));
    assert!(prefix_selector.matches(interface("wlan0")));
    assert!(!prefix_selector.matches(interface("xwlan0")));

    let report = compile(request(
        scope(AddressHostFamilySelection::Ipv4, true, true),
        bypass([]),
        None,
        interfaces(
            &[CaptureInterfaceSelector::exact(interface("rmnet0"))],
            &[prefix_selector],
            &[CaptureInterfaceSelector::prefix(interface("tun"))],
        ),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let local = program(
        &report,
        NetworkAddressFamily::Ipv4,
        CaptureTrafficDomain::LocalOutput,
    );
    let forwarded = program(
        &report,
        NetworkAddressFamily::Ipv4,
        CaptureTrafficDomain::ForwardedIngress,
    );

    assert_evaluation(
        local,
        local_packet(
            "8.8.8.8",
            CaptureTransportProtocol::Tcp,
            20_000,
            20_000,
            "tun0",
        ),
        CaptureDecisionStage::InterfaceRole,
        CaptureClauseDecision::Direct,
    );
    assert_evaluation(
        forwarded,
        forwarded_packet("8.8.8.8", CaptureTransportProtocol::Tcp, "rmnet0"),
        CaptureDecisionStage::InterfaceRole,
        CaptureClauseDecision::Direct,
    );
    assert_evaluation(
        forwarded,
        forwarded_packet("8.8.8.8", CaptureTransportProtocol::Tcp, "wlan9"),
        CaptureDecisionStage::ProxyAction,
        CaptureClauseDecision::Proxy,
    );
    assert_evaluation(
        forwarded,
        forwarded_packet("8.8.8.8", CaptureTransportProtocol::Tcp, "eth0"),
        CaptureDecisionStage::InterfaceRole,
        CaptureClauseDecision::Direct,
    );
    assert_evaluation(
        forwarded,
        forwarded_packet("8.8.8.8", CaptureTransportProtocol::Tcp, "lo"),
        CaptureDecisionStage::MandatorySafety,
        CaptureClauseDecision::Direct,
    );

    assert!(
        local
            .clauses()
            .iter()
            .filter_map(interface_direction)
            .all(|direction| { direction == CaptureInterfaceDirection::Output })
    );
    assert!(
        forwarded
            .clauses()
            .iter()
            .filter_map(interface_direction)
            .all(|direction| direction == CaptureInterfaceDirection::Input)
    );
}

#[test]
fn protocol_safety_allows_only_the_selected_tcp_udp_set() {
    let report = compile(request(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        bypass([]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let both_protocols = program(
        &report,
        NetworkAddressFamily::Ipv4,
        CaptureTrafficDomain::LocalOutput,
    );
    for protocol in [CaptureTransportProtocol::Tcp, CaptureTransportProtocol::Udp] {
        assert_evaluation(
            both_protocols,
            local_packet("8.8.8.8", protocol, 20_000, 20_000, "wlan0"),
            CaptureDecisionStage::ProxyAction,
            CaptureClauseDecision::Proxy,
        );
    }
    assert_evaluation(
        both_protocols,
        local_packet(
            "8.8.8.8",
            CaptureTransportProtocol::Other,
            20_000,
            20_000,
            "wlan0",
        ),
        CaptureDecisionStage::ProtocolSafety,
        CaptureClauseDecision::Direct,
    );

    let tcp_only = compile(request(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        bypass([]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP,
    ));
    assert_evaluation(
        program(
            &tcp_only,
            NetworkAddressFamily::Ipv4,
            CaptureTrafficDomain::LocalOutput,
        ),
        local_packet(
            "8.8.8.8",
            CaptureTransportProtocol::Udp,
            20_000,
            20_000,
            "wlan0",
        ),
        CaptureDecisionStage::ProtocolSafety,
        CaptureClauseDecision::Direct,
    );
}

#[test]
fn semantic_prefix_subsumption_handles_duplicates_families_and_universal_bypass() {
    let policy = bypass([
        prefix("10.1.0.0/16"),
        prefix("10.0.0.0/8"),
        prefix("10.0.0.0/8"),
        prefix("2001:db8:1::/48"),
        prefix("2001:db8::/32"),
    ]);
    assert_eq!(
        policy.prefixes(),
        [prefix("10.0.0.0/8"), prefix("2001:db8::/32")]
    );

    let universal = compile(request(
        scope(AddressHostFamilySelection::DualStack, true, false),
        bypass([
            prefix("10.0.0.0/8"),
            prefix("0.0.0.0/0"),
            prefix("192.168.0.0/16"),
            prefix("2001:db8::/32"),
            prefix("::/0"),
        ]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::Allowlist, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let ipv4 = program(
        &universal,
        NetworkAddressFamily::Ipv4,
        CaptureTrafficDomain::LocalOutput,
    );
    assert_eq!(
        prefixes_at(ipv4, CaptureDecisionStage::ConfigurableBypass),
        [prefix("0.0.0.0/0")]
    );
    assert_eq!(
        ipv4.clauses().last().unwrap().stage(),
        CaptureDecisionStage::ConfigurableBypass
    );
    let ipv6 = program(
        &universal,
        NetworkAddressFamily::Ipv6,
        CaptureTrafficDomain::LocalOutput,
    );
    assert_eq!(
        prefixes_at(ipv6, CaptureDecisionStage::ConfigurableBypass),
        [prefix("::/0")]
    );
    assert_eq!(
        ipv6.clauses().last().unwrap().stage(),
        CaptureDecisionStage::ConfigurableBypass
    );
}

#[test]
fn input_permutation_and_dedup_produce_identical_clauses_and_digest() {
    let first = compile(request(
        all_scope(),
        bypass([
            prefix("2001:db8:1::/48"),
            prefix("10.1.0.0/16"),
            prefix("2001:db8::/32"),
            prefix("10.0.0.0/8"),
            prefix("10.0.0.0/8"),
        ]),
        None,
        interfaces(
            &[
                CaptureInterfaceSelector::prefix(interface("rmnet")),
                CaptureInterfaceSelector::exact(interface("rmnet0")),
                CaptureInterfaceSelector::prefix(interface("rmnet")),
            ],
            &[
                CaptureInterfaceSelector::prefix(interface("wlan")),
                CaptureInterfaceSelector::exact(interface("rndis0")),
            ],
            &[CaptureInterfaceSelector::exact(interface("tun0"))],
        ),
        applications(
            CaptureApplicationMode::Allowlist,
            &[110_123, 10_123, 110_123],
        ),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let second = compile(request(
        all_scope(),
        bypass([prefix("10.0.0.0/8"), prefix("2001:db8::/32")]),
        None,
        interfaces(
            &[
                CaptureInterfaceSelector::exact(interface("rmnet0")),
                CaptureInterfaceSelector::prefix(interface("rmnet")),
            ],
            &[
                CaptureInterfaceSelector::exact(interface("rndis0")),
                CaptureInterfaceSelector::prefix(interface("wlan")),
            ],
            &[CaptureInterfaceSelector::exact(interface("tun0"))],
        ),
        applications(CaptureApplicationMode::Allowlist, &[10_123, 110_123]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));

    assert_eq!(first.artifact().programs(), second.artifact().programs());
    assert_eq!(first.artifact().digest(), second.artifact().digest());
    assert_eq!(first.artifact().usage(), second.artifact().usage());
}

#[test]
fn per_family_prefix_and_host_budgets_report_the_exact_exhausted_family() {
    let ipv4_too_small = budget(
        4,
        MAX_CAPTURE_POLICY_UIDS,
        MAX_CAPTURE_INTERFACE_SELECTORS,
        8,
    );
    assert_eq!(
        compile_shadow_capture_program(
            request(
                scope(AddressHostFamilySelection::DualStack, true, false),
                bypass([]),
                None,
                interfaces(&[], &[], &[]),
                applications(CaptureApplicationMode::All, &[]),
                CaptureProtocolSet::TCP_AND_UDP,
            )
            .with_budget(ipv4_too_small)
        ),
        Err(ShadowCaptureCompileError::ResourceBudgetExceeded {
            resource: CaptureProgramResourceKind::DestinationPrefixes,
            family: Some(NetworkAddressFamily::Ipv4),
            maximum: 4,
            required_at_least: 5,
        })
    );

    let ipv6_configured = budget(
        5,
        MAX_CAPTURE_POLICY_UIDS,
        MAX_CAPTURE_INTERFACE_SELECTORS,
        8,
    );
    assert_eq!(
        compile_shadow_capture_program(
            request(
                scope(AddressHostFamilySelection::DualStack, true, false),
                bypass([prefix("2001:db8::/32")]),
                None,
                interfaces(&[], &[], &[]),
                applications(CaptureApplicationMode::All, &[]),
                CaptureProtocolSet::TCP_AND_UDP,
            )
            .with_budget(ipv6_configured)
        ),
        Err(ShadowCaptureCompileError::ResourceBudgetExceeded {
            resource: CaptureProgramResourceKind::DestinationPrefixes,
            family: Some(NetworkAddressFamily::Ipv6),
            maximum: 5,
            required_at_least: 6,
        })
    );

    let host_plan = host_plan(&["2001:db8::7"]);
    let no_hosts = budget(
        8,
        MAX_CAPTURE_POLICY_UIDS,
        MAX_CAPTURE_INTERFACE_SELECTORS,
        0,
    );
    assert_eq!(
        compile_shadow_capture_program(
            request(
                scope(AddressHostFamilySelection::Ipv6, true, false),
                bypass([]),
                Some(host_plan),
                interfaces(&[], &[], &[]),
                applications(CaptureApplicationMode::All, &[]),
                CaptureProtocolSet::TCP_AND_UDP,
            )
            .with_budget(no_hosts)
        ),
        Err(ShadowCaptureCompileError::ResourceBudgetExceeded {
            resource: CaptureProgramResourceKind::DestinationHosts,
            family: Some(NetworkAddressFamily::Ipv6),
            maximum: 0,
            required_at_least: 1,
        })
    );
}

#[test]
fn early_universal_bypass_charges_only_resources_reached_by_selected_family_programs() {
    let configured_interfaces = interfaces(
        &[CaptureInterfaceSelector::exact(interface("rmnet0"))],
        &[CaptureInterfaceSelector::prefix(interface("wlan"))],
        &[CaptureInterfaceSelector::prefix(interface("tun"))],
    );
    let configured_applications =
        applications(CaptureApplicationMode::Allowlist, &[10_123, 110_123]);
    let all_families_terminate = compile_request(
        request(
            all_scope(),
            bypass([prefix("0.0.0.0/0"), prefix("::/0")]),
            None,
            configured_interfaces.clone(),
            configured_applications.clone(),
            CaptureProtocolSet::TCP_AND_UDP,
        )
        .with_budget(budget(8, 0, 0, 0)),
    );
    assert_eq!(
        all_families_terminate.artifact().usage().application_uids(),
        0
    );
    assert_eq!(
        all_families_terminate
            .artifact()
            .usage()
            .interface_selectors(),
        0
    );
    assert!(
        all_families_terminate
            .artifact()
            .programs()
            .iter()
            .all(|program| {
                program.clauses().iter().all(|clause| {
                    !matches!(
                        clause.stage(),
                        CaptureDecisionStage::InterfaceRole
                            | CaptureDecisionStage::ApplicationPolicy
                            | CaptureDecisionStage::ProtocolSafety
                            | CaptureDecisionStage::ProxyAction
                    )
                })
            })
    );

    let one_family_continues = compile_request(
        request(
            all_scope(),
            bypass([prefix("0.0.0.0/0")]),
            None,
            configured_interfaces.clone(),
            configured_applications.clone(),
            CaptureProtocolSet::TCP_AND_UDP,
        )
        .with_budget(budget(8, 2, 3, 0)),
    );
    assert_eq!(
        one_family_continues.artifact().usage().application_uids(),
        2
    );
    assert_eq!(
        one_family_continues
            .artifact()
            .usage()
            .interface_selectors(),
        3
    );
    assert_eq!(
        compile_shadow_capture_program(
            request(
                all_scope(),
                bypass([prefix("0.0.0.0/0")]),
                None,
                configured_interfaces,
                configured_applications,
                CaptureProtocolSet::TCP_AND_UDP,
            )
            .with_budget(budget(8, 0, 3, 0))
        ),
        Err(ShadowCaptureCompileError::ResourceBudgetExceeded {
            resource: CaptureProgramResourceKind::ApplicationUids,
            family: None,
            maximum: 0,
            required_at_least: 2,
        })
    );
}

#[test]
fn invalid_values_raw_input_ceilings_and_global_budgets_fail_closed() {
    assert!(CaptureUserId::new(u32::MAX).is_none());
    assert!(CaptureGroupId::new(u32::MAX).is_none());
    assert_eq!(
        CaptureTrafficScope::new(AddressHostFamilySelection::DualStack, false, false),
        Err(CaptureTrafficScopeError::NoTrafficDomains)
    );
    assert_eq!(
        CaptureProtocolSet::new(false, false),
        Err(CaptureProtocolSetError::Empty)
    );
    let invalid_v4 = CaptureIpPrefix::new("192.0.2.1".parse().unwrap(), 33).unwrap_err();
    assert_eq!(invalid_v4.prefix_length(), 33);

    assert_eq!(
        CaptureApplicationPolicy::new(CaptureApplicationMode::All, [uid(1)]),
        Err(CaptureApplicationPolicyError::UnexpectedUidForAll)
    );
    assert_eq!(
        CaptureApplicationPolicy::new(
            CaptureApplicationMode::Allowlist,
            std::iter::repeat_n(uid(1), MAX_CAPTURE_POLICY_UIDS + 1),
        ),
        Err(CaptureApplicationPolicyError::RawUidLimitExceeded {
            maximum: MAX_CAPTURE_POLICY_UIDS,
            required_at_least: MAX_CAPTURE_POLICY_UIDS + 1,
        })
    );
    assert_eq!(
        CaptureInterfacePolicy::new(
            std::iter::repeat_n(
                CaptureInterfaceSelector::exact(interface("if0")),
                MAX_CAPTURE_INTERFACE_SELECTORS + 1,
            ),
            [],
            [],
        ),
        Err(CaptureInterfacePolicyError::RawSelectorLimitExceeded {
            maximum: MAX_CAPTURE_INTERFACE_SELECTORS,
            required_at_least: MAX_CAPTURE_INTERFACE_SELECTORS + 1,
        })
    );
    assert_eq!(
        CaptureBypassPolicy::new(std::iter::repeat_n(
            prefix("10.0.0.0/8"),
            MAX_CAPTURE_POLICY_PREFIX_INPUTS + 1,
        ),),
        Err(CaptureBypassPolicyError::RawPrefixLimitExceeded {
            maximum: MAX_CAPTURE_POLICY_PREFIX_INPUTS,
            required_at_least: MAX_CAPTURE_POLICY_PREFIX_INPUTS + 1,
        })
    );
    assert_eq!(
        CaptureProgramBudget::new(MAX_CAPTURE_POLICY_PREFIXES_PER_FAMILY + 1, 0, 0, 0,),
        Err(CaptureProgramBudgetError::ExceedsCompiledMaximum {
            resource: CaptureProgramResourceKind::DestinationPrefixes,
            requested: MAX_CAPTURE_POLICY_PREFIXES_PER_FAMILY + 1,
            maximum: MAX_CAPTURE_POLICY_PREFIXES_PER_FAMILY,
        })
    );
    assert_eq!(
        CaptureProgramBudget::new(0, 0, 0, MAX_CAPTURE_HOST_ADDRESSES_PER_FAMILY + 1),
        Err(CaptureProgramBudgetError::ExceedsCompiledMaximum {
            resource: CaptureProgramResourceKind::DestinationHosts,
            requested: MAX_CAPTURE_HOST_ADDRESSES_PER_FAMILY + 1,
            maximum: MAX_CAPTURE_HOST_ADDRESSES_PER_FAMILY,
        })
    );
}

#[test]
fn irrelevant_domain_and_family_inputs_do_not_change_programs_or_digest() {
    let local_scope = scope(AddressHostFamilySelection::Ipv4, true, false);
    let local_first = compile(request(
        local_scope,
        bypass([]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let local_with_forwarded_inputs = compile(request(
        local_scope,
        bypass([prefix("2001:db8::/32")]),
        None,
        interfaces(
            &[],
            &[CaptureInterfaceSelector::prefix(interface("wlan"))],
            &[],
        ),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    assert_eq!(
        local_first.artifact(),
        local_with_forwarded_inputs.artifact()
    );

    let forwarded_scope = scope(AddressHostFamilySelection::Ipv4, false, true);
    let forwarded_first = compile_request(ShadowCaptureProgramRequest::new(
        forwarded_scope,
        engine_credentials(1000, 1000),
        bypass([]),
        None,
        interfaces(
            &[],
            &[CaptureInterfaceSelector::prefix(interface("wlan"))],
            &[],
        ),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    let forwarded_with_local_inputs = compile_request(ShadowCaptureProgramRequest::new(
        forwarded_scope,
        engine_credentials(42_000, 43_000),
        bypass([]),
        None,
        interfaces(
            &[],
            &[CaptureInterfaceSelector::prefix(interface("wlan"))],
            &[CaptureInterfaceSelector::prefix(interface("tun"))],
        ),
        applications(CaptureApplicationMode::Allowlist, &[10_123, 110_123]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    assert_eq!(
        forwarded_first.artifact(),
        forwarded_with_local_inputs.artifact()
    );
}

#[test]
fn digest_excludes_budget_and_host_provenance_but_changes_with_semantics() {
    let first_plan = host_plan(&["203.0.113.7"]);
    let second_plan = host_plan(&["203.0.113.7"]);
    let first = compile_request(
        request(
            scope(AddressHostFamilySelection::Ipv4, true, false),
            bypass([]),
            Some(first_plan),
            interfaces(&[], &[], &[]),
            applications(CaptureApplicationMode::All, &[]),
            CaptureProtocolSet::TCP_AND_UDP,
        )
        .with_budget(budget(8, 0, 0, 1)),
    );
    let second = compile_request(
        request(
            scope(AddressHostFamilySelection::Ipv4, true, false),
            bypass([]),
            Some(second_plan),
            interfaces(&[], &[], &[]),
            applications(CaptureApplicationMode::All, &[]),
            CaptureProtocolSet::TCP_AND_UDP,
        )
        .with_budget(budget(64, 10, 10, 16)),
    );

    assert_ne!(first.budget(), second.budget());
    assert_ne!(first.host_set_provenance(), second.host_set_provenance());
    assert_eq!(first.artifact().programs(), second.artifact().programs());
    assert_eq!(first.artifact().digest(), second.artifact().digest());

    let semantic_change = compile(request(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        bypass([]),
        Some(host_plan(&["203.0.113.7"])),
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP,
    ));
    assert_ne!(
        first.artifact().digest(),
        semantic_change.artifact().digest()
    );
}

#[test]
fn host_observation_coverage_reports_partial_and_complete_family_evidence() {
    let partial = compile(request(
        all_scope(),
        bypass([]),
        Some(host_plan_for(
            &["203.0.113.7"],
            AddressHostFamilySelection::Ipv4,
        )),
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    assert_eq!(
        partial.host_set_provenance().unwrap().families(),
        AddressHostFamilySelection::Ipv4
    );
    assert_eq!(
        partial.missing_host_observation_families(),
        [NetworkAddressFamily::Ipv6]
    );
    assert!(
        partial
            .deferred_prerequisites()
            .contains(&ShadowDeferredPrerequisite::InventoryHostBypassObservation)
    );
    assert!(
        partial
            .deferred_prerequisites()
            .contains(&ShadowDeferredPrerequisite::HostSetFreshnessAtGenerationFinalization)
    );

    let complete = compile(request(
        all_scope(),
        bypass([]),
        Some(host_plan_for(
            &["203.0.113.7", "2001:db8::7"],
            AddressHostFamilySelection::DualStack,
        )),
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    assert_eq!(
        complete.host_set_provenance().unwrap().families(),
        AddressHostFamilySelection::DualStack
    );
    assert!(complete.missing_host_observation_families().is_empty());
    assert!(
        !complete
            .deferred_prerequisites()
            .contains(&ShadowDeferredPrerequisite::InventoryHostBypassObservation)
    );
    assert!(
        complete
            .deferred_prerequisites()
            .contains(&ShadowDeferredPrerequisite::HostSetFreshnessAtGenerationFinalization)
    );
}

#[test]
fn schema_v1_small_fixture_has_a_fixed_digest_and_non_authorizing_report() {
    let report = compile(request(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        bypass([]),
        None,
        interfaces(&[], &[], &[]),
        applications(CaptureApplicationMode::All, &[]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    assert_eq!(
        report.artifact().schema_version(),
        SHADOW_CAPTURE_PROGRAM_SCHEMA_VERSION
    );
    assert_eq!(
        digest_hex(report.artifact().digest()),
        "fdee3e01e9f90c898a2147e3d288303b2a3593e24dfce878224c59fab8e8bc8d"
    );
    assert_eq!(
        report.compatibility_assumptions(),
        [ShadowCompatibilityAssumption::CompatibilityEngineUidGidBypass]
    );
    assert_eq!(
        report.deferred_prerequisites(),
        [
            ShadowDeferredPrerequisite::AndroidMarkAndRpdbAuthority,
            ShadowDeferredPrerequisite::BackendRenderingAndReadback,
            ShadowDeferredPrerequisite::EstablishedFlowDecisionCache,
            ShadowDeferredPrerequisite::ExactControlAndEngineLoopPrevention,
            ShadowDeferredPrerequisite::GenerationActivation,
            ShadowDeferredPrerequisite::InventoryHostBypassObservation,
            ShadowDeferredPrerequisite::KernelWriterOwnership,
            ShadowDeferredPrerequisite::LegacyOracleParity,
            ShadowDeferredPrerequisite::ProtocolSpecificCompatibilityRules,
        ]
    );
    assert!(report.host_set_provenance().is_none());
    assert_eq!(
        report.missing_host_observation_families(),
        [NetworkAddressFamily::Ipv4]
    );
}

#[test]
fn report_exposes_host_assumptions_usage_and_deferred_authority_without_granting_it() {
    let report = compile(request(
        all_scope(),
        bypass([prefix("100.64.0.0/10")]),
        Some(host_plan(&["203.0.113.7"])),
        interfaces(
            &[CaptureInterfaceSelector::exact(interface("rmnet0"))],
            &[CaptureInterfaceSelector::prefix(interface("wlan"))],
            &[CaptureInterfaceSelector::prefix(interface("tun"))],
        ),
        applications(CaptureApplicationMode::Allowlist, &[10_123, 110_123]),
        CaptureProtocolSet::TCP_AND_UDP,
    ));
    assert_eq!(
        report.compatibility_assumptions(),
        [
            ShadowCompatibilityAssumption::CompatibilityEngineUidGidBypass,
            ShadowCompatibilityAssumption::InventoryHostBypassProjection,
            ShadowCompatibilityAssumption::LegacyInterfacePrefixMatching,
            ShadowCompatibilityAssumption::LegacyLoopbackInterfaceName,
            ShadowCompatibilityAssumption::ResolvedApplicationUidInventory,
        ]
    );
    assert_eq!(
        report.deferred_prerequisites(),
        [
            ShadowDeferredPrerequisite::AndroidMarkAndRpdbAuthority,
            ShadowDeferredPrerequisite::BackendRenderingAndReadback,
            ShadowDeferredPrerequisite::EstablishedFlowDecisionCache,
            ShadowDeferredPrerequisite::ExactControlAndEngineLoopPrevention,
            ShadowDeferredPrerequisite::GenerationActivation,
            ShadowDeferredPrerequisite::HostSetFreshnessAtGenerationFinalization,
            ShadowDeferredPrerequisite::KernelWriterOwnership,
            ShadowDeferredPrerequisite::LegacyOracleParity,
            ShadowDeferredPrerequisite::ProtocolSpecificCompatibilityRules,
        ]
    );
    let usage = report.artifact().usage();
    assert_eq!(usage.prefixes(NetworkAddressFamily::Ipv4), 6);
    assert_eq!(usage.prefixes(NetworkAddressFamily::Ipv6), 5);
    assert_eq!(usage.hosts(NetworkAddressFamily::Ipv4), 1);
    assert_eq!(usage.hosts(NetworkAddressFamily::Ipv6), 0);
    assert_eq!(usage.application_uids(), 2);
    assert_eq!(usage.interface_selectors(), 3);
    assert_eq!(usage.domain_programs(), 4);
    assert!(usage.clauses() > 0);
    assert!(report.host_set_provenance().is_some());
}

fn compile(request: ShadowCaptureProgramRequest) -> ShadowCompilationReport {
    compile_request(request)
}

fn compile_request(request: ShadowCaptureProgramRequest) -> ShadowCompilationReport {
    compile_shadow_capture_program(request).expect("valid shadow Capture Program request")
}

fn request(
    scope: CaptureTrafficScope,
    configured_bypass: CaptureBypassPolicy,
    host_bypass: Option<AddressHostSetPlan>,
    interfaces: CaptureInterfacePolicy,
    applications: CaptureApplicationPolicy,
    protocols: CaptureProtocolSet,
) -> ShadowCaptureProgramRequest {
    ShadowCaptureProgramRequest::new(
        scope,
        engine_credentials(fixture_u32("engine_uid"), fixture_u32("engine_gid")),
        configured_bypass,
        host_bypass,
        interfaces,
        applications,
        protocols,
    )
}

fn scope(
    families: AddressHostFamilySelection,
    local_output: bool,
    forwarded_ingress: bool,
) -> CaptureTrafficScope {
    CaptureTrafficScope::new(families, local_output, forwarded_ingress).unwrap()
}

fn all_scope() -> CaptureTrafficScope {
    scope(AddressHostFamilySelection::DualStack, true, true)
}

fn bypass(prefixes: impl IntoIterator<Item = CaptureIpPrefix>) -> CaptureBypassPolicy {
    CaptureBypassPolicy::new(prefixes).unwrap()
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

fn applications(mode: CaptureApplicationMode, values: &[u32]) -> CaptureApplicationPolicy {
    CaptureApplicationPolicy::new(mode, values.iter().copied().map(uid)).unwrap()
}

fn budget(
    prefixes_per_family: usize,
    application_uids: usize,
    interface_selectors: usize,
    hosts_per_family: usize,
) -> CaptureProgramBudget {
    CaptureProgramBudget::new(
        prefixes_per_family,
        application_uids,
        interface_selectors,
        hosts_per_family,
    )
    .unwrap()
}

fn program(
    report: &ShadowCompilationReport,
    family: NetworkAddressFamily,
    domain: CaptureTrafficDomain,
) -> &CaptureDomainProgram {
    report
        .artifact()
        .programs()
        .iter()
        .find(|program| program.family() == family && program.domain() == domain)
        .expect("requested family/domain program")
}

fn prefixes_at(
    program: &CaptureDomainProgram,
    stage: CaptureDecisionStage,
) -> Vec<CaptureIpPrefix> {
    program
        .clauses()
        .iter()
        .filter(|clause| clause.stage() == stage)
        .filter_map(|clause| match clause.predicate() {
            CapturePredicate::DestinationPrefixes(prefixes) => Some(prefixes.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect()
}

fn all_program_prefixes(program: &CaptureDomainProgram) -> Vec<CaptureIpPrefix> {
    program
        .clauses()
        .iter()
        .filter_map(|clause| match clause.predicate() {
            CapturePredicate::DestinationPrefixes(prefixes) => Some(prefixes.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect()
}

fn local_uid_predicate(program: &CaptureDomainProgram) -> Vec<CaptureUserId> {
    program
        .clauses()
        .iter()
        .find_map(|clause| match clause.predicate() {
            CapturePredicate::LocalUidIn(uids) | CapturePredicate::LocalUidNotIn(uids) => {
                Some(uids.to_vec())
            }
            _ => None,
        })
        .expect("local UID predicate")
}

fn interface_direction(clause: &CaptureClause) -> Option<CaptureInterfaceDirection> {
    match clause.predicate() {
        CapturePredicate::InterfaceMatches { direction, .. }
        | CapturePredicate::InterfaceDoesNotMatch { direction, .. } => Some(*direction),
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct TestPacket {
    family: NetworkAddressFamily,
    destination: IpAddr,
    protocol: CaptureTransportProtocol,
    domain: TestPacketDomain,
}

#[derive(Clone, Copy)]
enum TestPacketDomain {
    Local {
        uid: CaptureUserId,
        gid: CaptureGroupId,
        output: InterfaceName,
    },
    Forwarded {
        input: InterfaceName,
    },
}

impl TestPacketDomain {
    fn interface(self, direction: CaptureInterfaceDirection) -> Option<InterfaceName> {
        match (self, direction) {
            (Self::Local { output, .. }, CaptureInterfaceDirection::Output) => Some(output),
            (Self::Forwarded { input }, CaptureInterfaceDirection::Input) => Some(input),
            _ => None,
        }
    }
}

fn local_packet(
    destination: &str,
    protocol: CaptureTransportProtocol,
    uid_value: u32,
    gid_value: u32,
    output: &str,
) -> TestPacket {
    packet(
        destination,
        protocol,
        TestPacketDomain::Local {
            uid: uid(uid_value),
            gid: gid(gid_value),
            output: interface(output),
        },
    )
}

fn forwarded_packet(
    destination: &str,
    protocol: CaptureTransportProtocol,
    input: &str,
) -> TestPacket {
    packet(
        destination,
        protocol,
        TestPacketDomain::Forwarded {
            input: interface(input),
        },
    )
}

fn packet(
    destination: &str,
    protocol: CaptureTransportProtocol,
    domain: TestPacketDomain,
) -> TestPacket {
    let destination = destination.parse::<IpAddr>().unwrap();
    TestPacket {
        family: match destination {
            IpAddr::V4(_) => NetworkAddressFamily::Ipv4,
            IpAddr::V6(_) => NetworkAddressFamily::Ipv6,
        },
        destination,
        protocol,
        domain,
    }
}

fn assert_evaluation(
    program: &CaptureDomainProgram,
    packet: TestPacket,
    expected_stage: CaptureDecisionStage,
    expected_decision: CaptureClauseDecision,
) {
    let (stage, decision) = evaluate(program, packet);
    assert_eq!(stage, expected_stage);
    assert_eq!(decision, expected_decision);
}

fn evaluate(
    program: &CaptureDomainProgram,
    packet: TestPacket,
) -> (CaptureDecisionStage, CaptureClauseDecision) {
    assert_eq!(program.family(), packet.family);
    let expected_domain = match packet.domain {
        TestPacketDomain::Local { .. } => CaptureTrafficDomain::LocalOutput,
        TestPacketDomain::Forwarded { .. } => CaptureTrafficDomain::ForwardedIngress,
    };
    assert_eq!(program.domain(), expected_domain);
    program
        .clauses()
        .iter()
        .find(|clause| predicate_matches(clause.predicate(), packet))
        .map(|clause| (clause.stage(), clause.decision()))
        .expect("compiled program has a terminal matching clause")
}

fn predicate_matches(predicate: &CapturePredicate, packet: TestPacket) -> bool {
    match predicate {
        CapturePredicate::Any => true,
        CapturePredicate::EngineCredentials(credentials) => matches!(
            packet.domain,
            TestPacketDomain::Local { uid, gid, .. }
                if uid == credentials.uid() && gid == credentials.gid()
        ),
        CapturePredicate::DestinationPrefixes(prefixes) => prefixes
            .iter()
            .any(|prefix| prefix.contains(packet.destination)),
        CapturePredicate::DestinationHosts(hosts) => hosts.contains(&packet.destination),
        CapturePredicate::InterfaceMatches {
            direction,
            selectors,
        } => packet
            .domain
            .interface(*direction)
            .is_some_and(|observed| selectors.iter().any(|selector| selector.matches(observed))),
        CapturePredicate::InterfaceDoesNotMatch {
            direction,
            selectors,
        } => packet
            .domain
            .interface(*direction)
            .is_some_and(|observed| !selectors.iter().any(|selector| selector.matches(observed))),
        CapturePredicate::LocalUidIn(uids) => matches!(
            packet.domain,
            TestPacketDomain::Local { uid, .. } if uids.contains(&uid)
        ),
        CapturePredicate::LocalUidNotIn(uids) => matches!(
            packet.domain,
            TestPacketDomain::Local { uid, .. } if !uids.contains(&uid)
        ),
        CapturePredicate::ProtocolNotIn(protocols) => !protocols.contains(packet.protocol),
    }
}

fn host_plan(addresses: &[&str]) -> AddressHostSetPlan {
    host_plan_for(addresses, AddressHostFamilySelection::DualStack)
}

fn host_plan_for(addresses: &[&str], families: AddressHostFamilySelection) -> AddressHostSetPlan {
    let mut tracker = NetworkInventoryTracker::new();
    let records = addresses.iter().enumerate().map(|(index, address)| {
        let address = address.parse::<IpAddr>().unwrap();
        InterfaceAddressRecord::new(
            InterfaceIndex::new(u32::try_from(index + 1).unwrap()).unwrap(),
            address,
            match address {
                IpAddr::V4(_) => 24,
                IpAddr::V6(_) => 64,
            },
            InterfaceAddressFlags::from_bits(0),
        )
        .unwrap()
    });
    let inventory = tracker.publish_complete([], records).unwrap().clone();
    plan_address_host_set(
        &inventory,
        &AddressHostSetPolicy::new(families, AddressBypassRuleBudget::new(64).unwrap()),
    )
    .unwrap()
}

fn prefix(value: &str) -> CaptureIpPrefix {
    let (address, prefix_length) = value.split_once('/').unwrap();
    CaptureIpPrefix::new(address.parse().unwrap(), prefix_length.parse().unwrap()).unwrap()
}

fn interface(value: &str) -> InterfaceName {
    InterfaceName::new(value.as_bytes()).unwrap()
}

fn uid(value: u32) -> CaptureUserId {
    CaptureUserId::new(value).unwrap()
}

fn gid(value: u32) -> CaptureGroupId {
    CaptureGroupId::new(value).unwrap()
}

fn engine_credentials(uid_value: u32, gid_value: u32) -> CompatibilityEngineCredentials {
    CompatibilityEngineCredentials::new(uid(uid_value), gid(gid_value))
}

fn digest_hex(digest: CaptureProgramDigest) -> String {
    digest
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fixture_u32(key: &str) -> u32 {
    fixture_values(key)[0].parse().unwrap()
}

fn fixture_prefixes(key: &str) -> Vec<CaptureIpPrefix> {
    fixture_values(key).into_iter().map(prefix).collect()
}

fn fixture_values(key: &str) -> Vec<&'static str> {
    LEGACY_ORACLE
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (observed_key, value) = line.split_once('=').unwrap();
            (observed_key == key).then_some(value)
        })
        .collect()
}
