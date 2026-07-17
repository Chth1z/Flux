use std::num::{NonZeroU16, NonZeroU32};

use flux_core::{
    AddressHostFamilySelection, CaptureApplicationMode, CaptureApplicationPolicy,
    CaptureBypassPolicy, CaptureGroupId, CaptureInterfacePolicy, CaptureInterfaceSelector,
    CaptureIpPrefix, CaptureProtocolSet, CaptureTrafficScope, CaptureUserId,
    CompatibilityEngineCredentials, FwmarkCandidate, InterfaceName, RouteProtocol, RouteTableId,
    RulePriority, RuleProtocol, ShadowCaptureProgramRequest, compile_shadow_capture_program,
};

use super::*;
use crate::xtables::{
    XtablesCaptureLoweringRequest, XtablesCaptureNamespace, XtablesLocalOutputRoutingSpec,
    XtablesLocalOutputRoutingTarget, XtablesTproxyTarget, lower_xtables_capture,
};

const GENERATION: u32 = 7;
const MARK_MASK: u32 = 0x0060_0000;
const PROXY_MARK: u32 = 0x0020_0000;
const BYPASS_MARK: u32 = 0x0040_0000;

#[test]
fn local_output_topology_pins_stable_roots_and_output_last_install() {
    let artifacts = artifacts(AddressHostFamilySelection::Ipv4, true, false);
    let plan = XtablesStableTopologyPlan::from_artifacts(&artifacts)
        .expect("derive local-OUTPUT stable topology");
    let family = plan
        .family(XtablesRestoreFamily::Ipv4)
        .expect("IPv4 stable topology");

    assert_eq!(family.family(), XtablesRestoreFamily::Ipv4);
    assert_eq!(family.prerouting_root(), Some("FLX4SP"));
    assert_eq!(family.output_root(), Some("FLX4SO"));
    assert_eq!(
        text(family.install()),
        concat!(
            "*mangle\n",
            ":FLX4SP - [0:0]\n",
            ":FLX4SO - [0:0]\n",
            "-A FLX4SP -i lo -m mark --mark 0x200000/0x600000 -j FLX4P0000000007\n",
            "-A FLX4SO -m mark --mark 0x0/0x600000 -j FLX4O0000000007\n",
            "-I PREROUTING -j FLX4SP\n",
            "-I OUTPUT -j FLX4SO\n",
            "COMMIT\n",
        )
    );
    assert_eq!(
        text(family.switch()),
        concat!(
            "*mangle\n",
            "-F FLX4SP\n",
            "-F FLX4SO\n",
            "-A FLX4SP -i lo -m mark --mark 0x200000/0x600000 -j FLX4P0000000007\n",
            "-A FLX4SO -m mark --mark 0x0/0x600000 -j FLX4O0000000007\n",
            "COMMIT\n",
        )
    );
    assert_eq!(
        text(family.detach_output().expect("OUTPUT detach phase")),
        "*mangle\n-D OUTPUT -j FLX4SO\nCOMMIT\n"
    );
    assert_eq!(
        text(family.detach_remaining()),
        concat!(
            "*mangle\n",
            "-D PREROUTING -j FLX4SP\n",
            "-F FLX4SO\n",
            "-F FLX4SP\n",
            "-X FLX4SO\n",
            "-X FLX4SP\n",
            "COMMIT\n",
        )
    );
    assert_eq!(
        family.prepared_state().phase(),
        XtablesExpectedStatePhase::Prepared
    );
    assert_eq!(
        family.active_state().phase(),
        XtablesExpectedStatePhase::Active
    );
    assert_eq!(
        family.output_detached_state().phase(),
        XtablesExpectedStatePhase::OutputDetached
    );
    assert_eq!(
        family
            .prepared_state()
            .projection()
            .native_references()
            .len(),
        0
    );
    assert_eq!(
        family.active_state().projection().native_references().len(),
        2
    );
    assert_eq!(
        family
            .output_detached_state()
            .projection()
            .native_references()
            .len(),
        1
    );
}

#[test]
fn prerouting_root_orders_loopback_tproxy_before_forwarded_ingress() {
    let artifacts = artifacts(AddressHostFamilySelection::Ipv4, true, true);
    let plan = XtablesStableTopologyPlan::from_artifacts(&artifacts)
        .expect("derive combined stable topology");
    let install = text(
        plan.family(XtablesRestoreFamily::Ipv4)
            .expect("IPv4 plan")
            .install(),
    );

    let loopback = install.find("-A FLX4SP -i lo -m mark").unwrap();
    let forwarded = install.find("-A FLX4SP -j FLX4F0000000007").unwrap();
    let prerouting_attach = install.find("-I PREROUTING -j FLX4SP").unwrap();
    let output_attach = install.find("-I OUTPUT -j FLX4SO").unwrap();
    assert!(loopback < forwarded);
    assert!(forwarded < prerouting_attach);
    assert!(prerouting_attach < output_attach);
}

#[test]
fn dual_stack_topology_uses_family_scoped_stable_roots() {
    let artifacts = artifacts(AddressHostFamilySelection::DualStack, true, false);
    let plan = XtablesStableTopologyPlan::from_artifacts(&artifacts)
        .expect("derive dual-stack stable topology");

    assert_eq!(plan.families().len(), 2);
    for (family, prerouting, output) in [
        (XtablesRestoreFamily::Ipv4, "FLX4SP", "FLX4SO"),
        (XtablesRestoreFamily::Ipv6, "FLX6SP", "FLX6SO"),
    ] {
        let plan = plan.family(family).expect("enabled family");
        assert_eq!(plan.prerouting_root(), Some(prerouting));
        assert_eq!(plan.output_root(), Some(output));
    }
}

#[test]
fn forwarded_only_schema_v1_cannot_enter_the_native_owner_topology() {
    let artifacts = artifacts(AddressHostFamilySelection::Ipv4, false, true);
    let error = XtablesStableTopologyPlan::from_artifacts(&artifacts)
        .expect_err("schema-v1 artifact must remain outside native owner");
    assert!(matches!(
        error,
        XtablesStableTopologyError::UnsupportedSchema { actual: 1 }
    ));
}

fn artifacts(
    families: AddressHostFamilySelection,
    local_output: bool,
    forwarded_ingress: bool,
) -> XtablesCaptureArtifactSet {
    let scope = CaptureTrafficScope::new(families, local_output, forwarded_ingress).unwrap();
    let forwarded = forwarded_ingress.then_some(exact("wlan0"));
    let interfaces = CaptureInterfacePolicy::new([], forwarded, []).unwrap();
    let report = compile_shadow_capture_program(ShadowCaptureProgramRequest::new(
        scope,
        CompatibilityEngineCredentials::new(uid(1000), gid(1000)),
        CaptureBypassPolicy::new(std::iter::empty::<CaptureIpPrefix>()).unwrap(),
        None,
        interfaces,
        CaptureApplicationPolicy::new(CaptureApplicationMode::All, []).unwrap(),
        CaptureProtocolSet::TCP_AND_UDP,
    ))
    .unwrap();
    let request = XtablesCaptureLoweringRequest::new(
        report.artifact(),
        XtablesCaptureNamespace::new(NonZeroU32::new(GENERATION).unwrap()),
        XtablesTproxyTarget::new(
            NonZeroU16::new(1536).unwrap(),
            FwmarkCandidate::new(MARK_MASK, PROXY_MARK, BYPASS_MARK).unwrap(),
        ),
    );
    if local_output {
        lower_xtables_capture(request.with_local_output_routing(routing(families))).unwrap()
    } else {
        lower_xtables_capture(request).unwrap()
    }
}

fn routing(families: AddressHostFamilySelection) -> XtablesLocalOutputRoutingSpec {
    let target = || {
        XtablesLocalOutputRoutingTarget::new(
            RulePriority::from_raw(30_999),
            RouteTableId::from_raw(20_253),
            NonZeroU32::new(1_024).unwrap(),
            RouteProtocol::from_raw(4),
            RuleProtocol::from_raw(99),
        )
        .unwrap()
    };
    XtablesLocalOutputRoutingSpec::new(
        families
            .includes(flux_core::NetworkAddressFamily::Ipv4)
            .then(target),
        families
            .includes(flux_core::NetworkAddressFamily::Ipv6)
            .then(target),
    )
    .unwrap()
}

fn exact(name: &str) -> CaptureInterfaceSelector {
    CaptureInterfaceSelector::exact(InterfaceName::new(name.as_bytes()).unwrap())
}

fn uid(value: u32) -> CaptureUserId {
    CaptureUserId::new(value).unwrap()
}

fn gid(value: u32) -> CaptureGroupId {
    CaptureGroupId::new(value).unwrap()
}

fn text(artifact: &XtablesRestoreArtifact) -> String {
    String::from_utf8(artifact.render_canonical().into_vec()).unwrap()
}
