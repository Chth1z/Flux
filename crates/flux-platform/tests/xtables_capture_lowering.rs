use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::num::{NonZeroU16, NonZeroU32};

use flux_core::{
    AddressBypassRuleBudget, AddressHostFamilySelection, AddressHostSetPlan, AddressHostSetPolicy,
    CaptureApplicationMode, CaptureApplicationPolicy, CaptureBypassPolicy, CaptureGroupId,
    CaptureInterfacePolicy, CaptureInterfaceSelector, CaptureIpPrefix, CaptureProtocolSet,
    CaptureTrafficDomain, CaptureTrafficScope, CaptureUserId, CompatibilityEngineCredentials,
    FwmarkCandidate, InterfaceAddressFlags, InterfaceAddressRecord, InterfaceIndex, InterfaceName,
    NetworkAddressFamily, NetworkInventoryTracker, ShadowCaptureArtifact,
    ShadowCaptureProgramRequest, ShadowCompilationReport, compile_shadow_capture_program,
    plan_address_host_set,
};
use flux_platform::{
    MAX_XTABLES_RESTORE_BYTES, XtablesCaptureArtifactSet, XtablesCaptureExtension,
    XtablesCaptureExtensions, XtablesCaptureLoweringBudget, XtablesCaptureLoweringError,
    XtablesCaptureLoweringRequest, XtablesCaptureNamespace, XtablesInterfaceRenderErrorKind,
    XtablesRestoreAction, XtablesRestoreContext, XtablesRestoreFamily, XtablesTproxyTarget,
    lower_xtables_capture,
};

const DEFAULT_GENERATION: u32 = 42;
const DEFAULT_PROXY_PORT: u16 = 1536;
const DEFAULT_MARK_MASK: u32 = 0x0060_0000;
const DEFAULT_PROXY_MARK: u32 = 0x0020_0000;
const DEFAULT_BYPASS_MARK: u32 = 0x0040_0000;

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
    assert_eq!(first.source_program_digest(), report.artifact().digest());
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
fn forwarded_schema_v1_fixture_pins_exact_bytes_and_identities() {
    let report = compile_program(
        scope(AddressHostFamilySelection::Ipv4, false, true),
        interfaces(&[], &[exact("wlan0")], &[]),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    let lowered = lower(&report, 1, default_target()).unwrap();
    let pair = lowered.ipv4().unwrap();

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
        "f1147e59670fe9ff11ae1811ff1b2a3259fbdf1ac0a76200a375f560f1409994"
    );
    assert_eq!(
        digest_hex(lowered.lowering_digest().as_bytes()),
        "0bc1a9be6f62023f78ef59f760e0d45d200e65c817fcc17d1e9237216aa0e518"
    );
    assert_eq!(
        digest_hex(pair.digest().as_bytes()),
        "7262387157f77600877e4ec44e5211f1d2f8f52276bdfc687c7a81b1efaaa92a"
    );
    assert_eq!(
        digest_hex(lowered.digest().as_bytes()),
        "348fa46a9c283a2dfdda69a8ad12634dc838b0d99a27d08f3414159bd3864e1c"
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
    let host = prepare.find("-d 203.0.113.7 -j RETURN").unwrap();
    let loopback = prepare.find("-i lo -j RETURN").unwrap();
    let configured = prepare.find("-d 100.64.0.0/10 -j RETURN").unwrap();
    let proxy = prepare.find("-i wlan0 -p tcp -j TPROXY").unwrap();
    assert!(mandatory < host && host < loopback && loopback < configured && configured < proxy);
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
fn local_output_and_dual_domain_programs_reject_at_the_first_local_program() {
    let local_only = compile_program(
        scope(AddressHostFamilySelection::Ipv4, true, false),
        interfaces(&[], &[], &[]),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    assert_eq!(
        lower(&local_only, DEFAULT_GENERATION, default_target()),
        Err(XtablesCaptureLoweringError::UnsupportedTrafficDomain {
            family: NetworkAddressFamily::Ipv4,
            domain: CaptureTrafficDomain::LocalOutput,
        })
    );

    let dual_domain = compile_program(
        scope(AddressHostFamilySelection::DualStack, true, true),
        interfaces(&[], &[exact("wlan0")], &[]),
        CaptureProtocolSet::TCP_AND_UDP,
        &[],
    );
    assert_eq!(
        lower(&dual_domain, DEFAULT_GENERATION, default_target()),
        Err(XtablesCaptureLoweringError::UnsupportedTrafficDomain {
            family: NetworkAddressFamily::Ipv4,
            domain: CaptureTrafficDomain::LocalOutput,
        }),
        "canonical program order exposes IPv4 LocalOutput before any forwarded or IPv6 program"
    );
}

#[test]
fn every_schema_v1_extension_is_rejected_explicitly() {
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
                lowering_request(report.artifact(), DEFAULT_GENERATION, default_target())
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
        lowering_request(report.artifact(), DEFAULT_GENERATION, default_target())
            .with_budget(exact_budget),
    )
    .expect("exact command budget");
    assert_eq!(exact, baseline);

    let smaller_budget = XtablesCaptureLoweringBudget::new(required - 1).unwrap();
    assert_eq!(
        lower_xtables_capture(
            lowering_request(report.artifact(), DEFAULT_GENERATION, default_target())
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
    let report = compile_shadow_capture_program(ShadowCaptureProgramRequest::new(
        scope(AddressHostFamilySelection::Ipv6, false, true),
        CompatibilityEngineCredentials::new(uid(1000), gid(1000)),
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
        lowering_request(report.artifact(), 1, default_target())
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

fn compile_program(
    scope: CaptureTrafficScope,
    interfaces: CaptureInterfacePolicy,
    protocols: CaptureProtocolSet,
    bypasses: &[&str],
) -> ShadowCompilationReport {
    compile_program_with_host(scope, interfaces, protocols, bypasses, None)
}

fn compile_program_with_host(
    scope: CaptureTrafficScope,
    interfaces: CaptureInterfacePolicy,
    protocols: CaptureProtocolSet,
    bypasses: &[&str],
    host_bypass: Option<AddressHostSetPlan>,
) -> ShadowCompilationReport {
    compile_shadow_capture_program(ShadowCaptureProgramRequest::new(
        scope,
        CompatibilityEngineCredentials::new(uid(1000), gid(1000)),
        CaptureBypassPolicy::new(bypasses.iter().copied().map(capture_prefix)).unwrap(),
        host_bypass,
        interfaces,
        CaptureApplicationPolicy::new(CaptureApplicationMode::All, []).unwrap(),
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
    plan_address_host_set(
        &inventory,
        &AddressHostSetPolicy::new(
            AddressHostFamilySelection::Ipv4,
            AddressBypassRuleBudget::new(64).unwrap(),
        ),
    )
    .unwrap()
}

fn lower(
    report: &ShadowCompilationReport,
    generation: u32,
    target: XtablesTproxyTarget,
) -> Result<XtablesCaptureArtifactSet, XtablesCaptureLoweringError> {
    lower_xtables_capture(lowering_request(report.artifact(), generation, target))
}

fn lowering_request(
    artifact: &ShadowCaptureArtifact,
    generation: u32,
    target: XtablesTproxyTarget,
) -> XtablesCaptureLoweringRequest<'_> {
    XtablesCaptureLoweringRequest::new(
        artifact,
        XtablesCaptureNamespace::new(NonZeroU32::new(generation).unwrap()),
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
