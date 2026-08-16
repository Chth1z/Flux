use std::error::Error as _;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU16, NonZeroU32};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use flux_core::{
    AddressHostFamilySelection, CapabilityProfile, CapabilityProfileRevision,
    CaptureApplicationMode, CaptureApplicationPolicy, CaptureDecisionStage, CaptureGroupId,
    CaptureInterfaceDirection, CapturePathId, CapturePathQualificationState,
    CapturePathQualifications, CapturePathRequest, CapturePredicate, CaptureTrafficDomain,
    CaptureUserId, EngineCredentials, FluxConfig, FwmarkCandidate, InterfaceAddressRecord,
    InterfaceLinkRecord, KernelSupport, NetworkAddressFamily, NetworkInventory,
    NetworkInventoryTracker, NetworkNamespaceIdentity, Observation, ObservationKind, RouteProtocol,
    RouteTableId, RulePriority, RuleProtocol, SelinuxMode,
    select_reviewed_android_platform_profile,
};
use flux_platform::internal::SingBoxProcessError;
use flux_platform::{
    AndroidCapturePathState, SingBoxLaunchSpec, SingBoxPrivilege, SingBoxReadiness,
    XtablesLocalOutputRoutingSpec, XtablesLocalOutputRoutingTarget,
};
use flux_testkit::CapabilityProfileFixture;

use super::capture_path_selection::CapturePathSelectionErrorKind;
use super::{
    ADMITTED_GENERATION_SCHEMA_VERSION, AdmittedGeneration, AdmittedGenerationIdentity,
    CapturePathDecision, CapturePathQualificationEvidence, CapturePathRejection,
    CapturePathRejectionReason, CapturePathSelectionReason, DesiredStateArtifacts,
    DesiredStateCompileErrorKind, DesiredStateCompileRequest, DesiredStateEngineBindingError,
    ENGINE_CAPABILITY_PROFILE_SCHEMA_VERSION, ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION,
    EngineCapabilityProfile, EngineCapabilityProfileErrorKind, EngineConfigBindingErrorKind,
    EngineConfigCompileErrorKind, EngineVersionOutputErrorKind,
    GENERATION_ENGINE_CONFIG_SCHEMA_VERSION, GenerationAdmissionKind, GenerationAssembler,
    GenerationAssemblyDigest, GenerationAssemblyError, GenerationAssemblyRequest,
    GenerationPlanningAuthority, GenerationPlanningErrorKind, HostInspectionPlanningAuthority,
    MAX_GENERATION_ENGINE_CONFIG_INBOUNDS, MAX_PREPARED_GENERATION_RECORD_BYTES,
    NativeGenerationPromotionError, PREPARED_GENERATION_RECORD_SCHEMA_VERSION,
    PreparedGenerationRecord, PreparedGenerationRecordError, PreparedGenerationRecordStore,
    SelectedEngineSource, SelectedEngineSourceIdentity, TPROXY_GENERATION_CANDIDATE_SCHEMA_VERSION,
    TproxyCanaryEngineRoute, TproxyEngineConfigRequest, TproxyGenerationCandidateErrorKind,
    bind_engine_config_to_spec, bind_engine_spec_to_desired_state,
    collect_tproxy_engine_capability_profile, compile_desired_state, compile_desired_state_capture,
    compile_tproxy_engine_config, compile_tproxy_generation_candidate,
    declare_supervised_delivery_report_profile_fixture, parse_sing_box_version_output,
    qualified_xtables_capture_path_evidence, qualified_xtables_kernel_config,
    rebind_engine_capability_profile_fixture, reconstruct_canonical_tproxy_engine_config,
};
use crate::engine_supervisor::EngineCapabilityProbeError;
use crate::functional_canary::FunctionalCanaryGateMode;
use crate::{EngineSpec, MAX_ENGINE_CONFIG_BYTES, RestartPolicy};

const PORT: u16 = 1536;
const PACKAGED_DESIRED_STATE: &str = include_str!("../../../../conf/flux.toml");
const PACKAGED_ENGINE_TEMPLATE: &[u8] = include_bytes!("../../../../conf/template.json");

#[test]
fn desired_state_compiles_the_packaged_config_and_binds_the_listener() {
    let config = FluxConfig::parse(PACKAGED_DESIRED_STATE).expect("packaged Desired State");
    let expected = config.clone();
    let applications = CaptureApplicationPolicy::new(CaptureApplicationMode::All, [])
        .expect("resolved all-app policy");

    let artifacts = compile_desired_state(
        DesiredStateCompileRequest::new(config, applications, None),
        PACKAGED_ENGINE_TEMPLATE,
    )
    .expect("complete packaged Desired State");

    assert_eq!(artifacts.desired_state(), &expected);
    assert_eq!(
        artifacts.engine_config().listener_port(),
        expected.listener().port()
    );
    assert!(
        artifacts
            .engine_config()
            .bytes()
            .windows(br#""listen_port":1536"#.len())
            .any(|window| window == br#""listen_port":1536"#)
    );
    assert_eq!(artifacts.capture().program().programs().len(), 1);
}

#[test]
fn desired_state_maps_scope_interfaces_and_resolved_applications() {
    let input = PACKAGED_DESIRED_STATE
        .replacen("mode = \"all\"", "mode = \"allowlist\"", 1)
        .replacen("packages = []", "packages = [\"com.example.client\"]", 1)
        .replacen("forwarded_ingress = false", "forwarded_ingress = true", 1)
        .replacen("local_bypass = []", "local_bypass = [\"wlan1\"]", 1);
    let config = FluxConfig::parse(&input).expect("custom complete Desired State");
    let selected_uid = CaptureUserId::new(10_123).expect("ordinary Android application UID");
    let applications =
        CaptureApplicationPolicy::new(CaptureApplicationMode::Allowlist, [selected_uid])
            .expect("resolved allowlist");

    let artifacts = compile_desired_state(
        DesiredStateCompileRequest::new(config.clone(), applications, None),
        PACKAGED_ENGINE_TEMPLATE,
    )
    .expect("capture artifacts");
    let programs = artifacts.capture().program().programs();

    assert_eq!(programs.len(), 2);
    assert!(
        programs
            .iter()
            .all(|program| program.family() == NetworkAddressFamily::Ipv4)
    );
    let local = programs
        .iter()
        .find(|program| program.domain() == CaptureTrafficDomain::LocalOutput)
        .expect("local OUTPUT program");
    assert!(local.clauses().iter().any(|clause| {
        clause.stage() == CaptureDecisionStage::ApplicationPolicy
            && matches!(
                clause.predicate(),
                CapturePredicate::LocalUidNotIn(uids) if uids.as_ref() == [selected_uid]
            )
    }));
    assert!(local.clauses().iter().any(|clause| {
        matches!(
            clause.predicate(),
            CapturePredicate::InterfaceMatches {
                direction: CaptureInterfaceDirection::Output,
                selectors,
            } if selectors.as_ref() == config.interfaces().policy().local_bypass()
        )
    }));
    let forwarded = programs
        .iter()
        .find(|program| program.domain() == CaptureTrafficDomain::ForwardedIngress)
        .expect("forwarded ingress program");
    assert!(forwarded.clauses().iter().any(|clause| {
        matches!(
            clause.predicate(),
            CapturePredicate::InterfaceDoesNotMatch {
                direction: CaptureInterfaceDirection::Input,
                selectors,
            } if selectors.as_ref() == config.interfaces().policy().forwarded_proxy()
        )
    }));
}

#[test]
fn desired_state_compilation_is_deterministic_for_identical_inputs() {
    let config = FluxConfig::parse(PACKAGED_DESIRED_STATE).expect("packaged Desired State");
    let applications = CaptureApplicationPolicy::new(CaptureApplicationMode::All, [])
        .expect("resolved all-app policy");

    let first = compile_desired_state(
        DesiredStateCompileRequest::new(config.clone(), applications.clone(), None),
        PACKAGED_ENGINE_TEMPLATE,
    )
    .expect("first compilation");
    let second = compile_desired_state(
        DesiredStateCompileRequest::new(config, applications, None),
        PACKAGED_ENGINE_TEMPLATE,
    )
    .expect("second compilation");

    assert_eq!(first, second);
}

#[test]
fn desired_state_rejects_a_resolved_application_mode_mismatch() {
    let config = FluxConfig::parse(PACKAGED_DESIRED_STATE).expect("packaged Desired State");
    let applications = CaptureApplicationPolicy::new(CaptureApplicationMode::Denylist, [])
        .expect("resolved denylist");

    let error = compile_desired_state(
        DesiredStateCompileRequest::new(config, applications, None),
        PACKAGED_ENGINE_TEMPLATE,
    )
    .expect_err("resolved mode must match configured intent");

    assert_eq!(
        error.kind(),
        DesiredStateCompileErrorKind::ApplicationModeMismatch {
            configured: CaptureApplicationMode::All,
            resolved: CaptureApplicationMode::Denylist,
        }
    );
}

#[test]
fn desired_state_propagates_engine_template_errors() {
    let config = FluxConfig::parse(PACKAGED_DESIRED_STATE).expect("packaged Desired State");
    let applications = CaptureApplicationPolicy::new(CaptureApplicationMode::All, [])
        .expect("resolved all-app policy");

    let error = compile_desired_state(
        DesiredStateCompileRequest::new(config, applications, None),
        br#"{"inbounds":["#,
    )
    .expect_err("invalid engine template must fail closed");

    assert_eq!(
        error.kind(),
        DesiredStateCompileErrorKind::EngineConfig(EngineConfigCompileErrorKind::InvalidJson)
    );
    assert!(error.source().is_some());
}

#[test]
fn desired_state_rejects_an_engine_source_with_different_listener_families() {
    let config = FluxConfig::parse(PACKAGED_DESIRED_STATE).expect("packaged Desired State");
    let applications = CaptureApplicationPolicy::new(CaptureApplicationMode::All, [])
        .expect("resolved all-app policy");
    let capture =
        compile_desired_state_capture(DesiredStateCompileRequest::new(config, applications, None))
            .expect("capture artifacts");
    let artifact = compile_for_families(
        PACKAGED_ENGINE_TEMPLATE,
        PORT,
        AddressHostFamilySelection::DualStack,
    )
    .expect("dual-stack engine artifact");

    let error = capture
        .with_engine_source(SelectedEngineSource::template(artifact))
        .expect_err("listener-family substitution must fail closed");
    assert_eq!(
        error.kind(),
        DesiredStateCompileErrorKind::EngineSourceListenerFamiliesMismatch {
            configured: AddressHostFamilySelection::Ipv4,
            selected: AddressHostFamilySelection::DualStack,
        }
    );
}

#[test]
fn compiles_canonical_family_specific_tcp_udp_tproxy_inbounds() {
    let template = br#"{
            "route": {"rules": []},
            "inbounds": [
                {"type": "mixed", "tag": "mixed-in"},
                {
                    "type": "tproxy",
                    "tag": "existing-tproxy",
                    "listen": "127.0.0.1",
                    "listen_port": 1,
                    "network": "udp",
                    "sniff": true
                },
                {"type": "tun", "tag": "old-tun"}
            ]
        }"#;

    let artifact = compile(template, PORT).expect("canonical TPROXY configuration");

    assert_eq!(
        artifact.bytes(),
        concat!(
            "{\"inbounds\":[",
            "{\"tag\":\"mixed-in\",\"type\":\"mixed\"},",
            "{\"listen\":\"0.0.0.0\",\"listen_port\":1536,\"sniff\":true,",
            "\"tag\":\"tproxy-in-ipv4\",\"type\":\"tproxy\"},",
            "{\"listen\":\"::\",\"listen_port\":1536,\"sniff\":true,",
            "\"tag\":\"tproxy-in-ipv6\",\"type\":\"tproxy\"}",
            "],\"route\":{\"rules\":[]}}\n"
        )
        .as_bytes()
    );
    assert_eq!(
        artifact.schema_version(),
        GENERATION_ENGINE_CONFIG_SCHEMA_VERSION
    );
    assert_eq!(artifact.listener_port().get(), PORT);
    assert_eq!(artifact.usage().input_inbounds(), 3);
    assert_eq!(artifact.usage().output_inbounds(), 3);
    assert_eq!(artifact.usage().input_bytes(), template.len());
    assert_eq!(artifact.usage().output_bytes(), artifact.bytes().len());
    assert_eq!(
        hex(artifact.content_sha256()),
        "eb4b4fccc008180a89e5ac6ac7d1a5851f9644638d961ec5d085028780150f80"
    );
    assert_eq!(
        artifact.digest().to_string(),
        "befda47123b7f3d08bc20a7ae3cbb5ae2af35222d07af2a1cbb0e1a61b20ce6b"
    );
    assert_eq!(artifact.digest().as_bytes().len(), 32);
}

#[test]
fn adds_the_default_listener_when_the_template_has_none() {
    let artifact = compile(br#"{"inbounds":[],"log":{"level":"info"}}"#, PORT)
        .expect("missing TPROXY listener is generated");

    assert_eq!(
        artifact.bytes(),
        concat!(
            "{\"inbounds\":[{\"listen\":\"0.0.0.0\",\"listen_port\":1536,",
            "\"tag\":\"tproxy-in-ipv4\",\"type\":\"tproxy\"},",
            "{\"listen\":\"::\",\"listen_port\":1536,",
            "\"tag\":\"tproxy-in-ipv6\",\"type\":\"tproxy\"}],",
            "\"log\":{\"level\":\"info\"}}\n"
        )
        .as_bytes()
    );
}

#[test]
fn requested_listener_families_are_exact_and_identity_bound() {
    let template = br#"{"inbounds":[]}"#;
    let ipv4 = compile_for_families(template, PORT, AddressHostFamilySelection::Ipv4).unwrap();
    let ipv6 = compile_for_families(template, PORT, AddressHostFamilySelection::Ipv6).unwrap();
    let dual = compile_for_families(template, PORT, AddressHostFamilySelection::DualStack).unwrap();

    assert_eq!(ipv4.listener_families(), AddressHostFamilySelection::Ipv4);
    assert_eq!(ipv6.listener_families(), AddressHostFamilySelection::Ipv6);
    assert_eq!(
        dual.listener_families(),
        AddressHostFamilySelection::DualStack
    );
    assert_eq!(
        ipv4.bytes(),
        b"{\"inbounds\":[{\"listen\":\"0.0.0.0\",\"listen_port\":1536,\"tag\":\"tproxy-in-ipv4\",\"type\":\"tproxy\"}]}\n"
    );
    assert_eq!(
        ipv6.bytes(),
        b"{\"inbounds\":[{\"listen\":\"::\",\"listen_port\":1536,\"tag\":\"tproxy-in-ipv6\",\"type\":\"tproxy\"}]}\n"
    );
    assert_eq!(dual.usage().output_inbounds(), 2);
    assert_ne!(ipv4.content_sha256(), ipv6.content_sha256());
    assert_ne!(ipv4.digest(), ipv6.digest());
    assert_ne!(ipv4.digest(), dual.digest());

    let error = reconstruct_canonical_tproxy_engine_config(
        ipv4.bytes(),
        NonZeroU16::new(PORT).unwrap(),
        AddressHostFamilySelection::DualStack,
    )
    .expect_err("an IPv4 artifact must not reconstruct as dual-stack");
    assert_eq!(error.kind(), EngineConfigCompileErrorKind::NonCanonical);
}

#[test]
fn inherited_tproxy_tag_references_expand_to_the_selected_family_tags() {
    let artifact = compile(
        br#"{
          "inbounds":[{"type":"tproxy","tag":"legacy-transparent"}],
          "route":{"rules":[{"inbound":"legacy-transparent","action":"reject"}]},
          "dns":{"rules":[{"inbound":["other","legacy-transparent"],"action":"reject"}]}
        }"#,
        PORT,
    )
    .unwrap();
    let document: serde_json::Value = serde_json::from_slice(artifact.bytes()).unwrap();

    assert_eq!(
        document["route"]["rules"][0]["inbound"],
        serde_json::json!(["tproxy-in-ipv4", "tproxy-in-ipv6"])
    );
    assert_eq!(
        document["dns"]["rules"][0]["inbound"],
        serde_json::json!(["other", "tproxy-in-ipv4", "tproxy-in-ipv6"])
    );
}

#[test]
fn default_tproxy_tag_references_expand_and_ambiguous_tags_fail_closed() {
    let default = compile(
        br#"{"route":{"rules":[{"inbound":"tproxy-in","action":"reject"}]}}"#,
        PORT,
    )
    .unwrap();
    let document: serde_json::Value = serde_json::from_slice(default.bytes()).unwrap();
    assert_eq!(
        document["route"]["rules"][0]["inbound"],
        serde_json::json!(["tproxy-in-ipv4", "tproxy-in-ipv6"])
    );

    let inherited_collision = compile(
        br#"{"inbounds":[
          {"type":"mixed","tag":"legacy-transparent"},
          {"type":"tproxy","tag":"legacy-transparent"}
        ]}"#,
        PORT,
    )
    .expect_err("an inherited TPROXY tag shared by another inbound is ambiguous");
    assert_eq!(
        inherited_collision.kind(),
        EngineConfigCompileErrorKind::InheritedTproxyInboundTagCollision { index: 0 }
    );

    let canonical_collision = compile(
        br#"{"inbounds":[{"type":"tun","tag":"tproxy-in-ipv6"}]}"#,
        PORT,
    )
    .expect_err("compiler-owned family tags cannot be inherited from any inbound");
    assert_eq!(
        canonical_collision.kind(),
        EngineConfigCompileErrorKind::CanonicalTproxyInboundTagCollision { index: 0 }
    );
}

#[test]
fn compiler_owned_tproxy_tag_references_require_the_exact_canonical_bundle() {
    for template in [
        br#"{"route":{"rules":[{"inbound":"tproxy-in-ipv4"}]}}"#.as_slice(),
        br#"{"dns":{"rules":[{"inbound":["other","tproxy-in-ipv6"]}]}}"#.as_slice(),
    ] {
        let error = compile(template, PORT)
            .expect_err("compiler-owned tags require their exact canonical listeners");
        assert_eq!(
            error.kind(),
            EngineConfigCompileErrorKind::CanonicalTproxyInboundReferenceCollision
        );
    }
}

#[test]
fn exact_single_family_bundles_reject_cross_family_canonical_references() {
    for (families, configured_tag, configured_listen, foreign_tag) in [
        (
            AddressHostFamilySelection::Ipv4,
            "tproxy-in-ipv4",
            "0.0.0.0",
            "tproxy-in-ipv6",
        ),
        (
            AddressHostFamilySelection::Ipv6,
            "tproxy-in-ipv6",
            "::",
            "tproxy-in-ipv4",
        ),
    ] {
        for root in ["route", "dns"] {
            let template = format!(
                r#"{{
                  "inbounds":[{{
                    "type":"tproxy","tag":"{configured_tag}",
                    "listen":"{configured_listen}","listen_port":{PORT}
                  }}],
                  "{root}":{{"rules":[{{"inbound":"{foreign_tag}"}}]}}
                }}"#
            );
            let error = compile_for_families(template.as_bytes(), PORT, families)
                .expect_err("a canonical reference must belong to the requested listener family");
            assert_eq!(
                error.kind(),
                EngineConfigCompileErrorKind::CanonicalTproxyInboundReferenceCollision
            );
        }
    }
}

#[test]
fn malformed_route_and_dns_inbound_references_fail_closed() {
    for template in [
        br#"{"route":{"rules":[{"inbound":null}]}}"#.as_slice(),
        br#"{"route":{"rules":[{"inbound":false}]}}"#.as_slice(),
        br#"{"route":{"rules":[{"inbound":{"tag":"tproxy-in"}}]}}"#.as_slice(),
        br#"{"dns":{"rules":[{"inbound":7}]}}"#.as_slice(),
        br#"{"dns":{"rules":[{"inbound":["other",7]}]}}"#.as_slice(),
        br#"{"dns":{"rules":[{"rules":[{"inbound":{}}]}]}}"#.as_slice(),
    ] {
        let error = compile(template, PORT)
            .expect_err("route and DNS inbound references must have a closed string shape");
        assert_eq!(
            error.kind(),
            EngineConfigCompileErrorKind::InvalidTproxyInboundReference
        );
    }
}

#[test]
fn exact_dual_stack_bundle_recompiles_and_reconstructs_with_shared_options() {
    let artifact = compile(
        br#"{
          "inbounds":[{
            "type":"tproxy",
            "tag":"legacy-transparent",
            "network":"udp",
            "sniff":true,
            "sniff_override_destination":false
          }],
          "route":{"rules":[{"inbound":"legacy-transparent","action":"reject"}]},
          "dns":{"rules":[{"inbound":["legacy-transparent","other"],"action":"reject"}]}
        }"#,
        PORT,
    )
    .expect("single inherited TPROXY inbound compiles into a canonical pair");

    let recompiled = compile_for_families(
        artifact.bytes(),
        PORT,
        AddressHostFamilySelection::DualStack,
    )
    .expect("an exact canonical pair with shared inherited options recompiles");
    assert_eq!(recompiled.bytes(), artifact.bytes());
    assert_eq!(recompiled.content_sha256(), artifact.content_sha256());

    let reconstructed = reconstruct_canonical_tproxy_engine_config(
        artifact.bytes(),
        NonZeroU16::new(PORT).unwrap(),
        AddressHostFamilySelection::DualStack,
    )
    .expect("an exact canonical pair with shared inherited options reconstructs");
    assert_eq!(reconstructed.bytes(), artifact.bytes());
    assert_eq!(
        reconstructed.listener_families(),
        artifact.listener_families()
    );
}

#[test]
fn partial_substituted_and_duplicate_canonical_tproxy_pairs_fail_closed() {
    let cases: &[(&[u8], EngineConfigCompileErrorKind)] = &[
        (
            br#"{"inbounds":[{
              "type":"tproxy","tag":"tproxy-in-ipv4",
              "listen":"0.0.0.0","listen_port":1536
            }]}"#,
            EngineConfigCompileErrorKind::NonCanonical,
        ),
        (
            br#"{"inbounds":[
              {"type":"tproxy","tag":"tproxy-in-ipv4","listen":"0.0.0.0","listen_port":1536},
              {"type":"tproxy","tag":"substituted-ipv6","listen":"::","listen_port":1536}
            ]}"#,
            EngineConfigCompileErrorKind::CanonicalTproxyInboundTagCollision { index: 0 },
        ),
        (
            br#"{"inbounds":[
              {"type":"tproxy","tag":"tproxy-in-ipv4","listen":"0.0.0.0","listen_port":1536},
              {"type":"tproxy","tag":"tproxy-in-ipv6","listen":"::","listen_port":1536},
              {"type":"tproxy","tag":"tproxy-in-ipv6","listen":"::","listen_port":1536}
            ]}"#,
            EngineConfigCompileErrorKind::CanonicalTproxyInboundTagCollision { index: 0 },
        ),
    ];

    for (template, expected) in cases {
        let error = compile_for_families(template, PORT, AddressHostFamilySelection::DualStack)
            .expect_err("a non-exact canonical TPROXY pair must not be inherited");
        assert_eq!(error.kind(), *expected);
    }
}

#[test]
fn separated_family_specific_tproxy_pair_is_not_a_canonical_bundle() {
    let template = br#"{
      "inbounds":[
        {"type":"tproxy","tag":"tproxy-in-ipv4","listen":"0.0.0.0","listen_port":1536},
        {"type":"mixed","tag":"other"},
        {"type":"tproxy","tag":"tproxy-in-ipv6","listen":"::","listen_port":1536}
      ]
    }"#;
    let error = compile_for_families(template, PORT, AddressHostFamilySelection::DualStack)
        .expect_err("only an adjacent family-specific pair can be compiler output");
    assert!(matches!(
        error.kind(),
        EngineConfigCompileErrorKind::CanonicalTproxyInboundTagCollision { .. }
            | EngineConfigCompileErrorKind::NonCanonical
    ));
    reconstruct_canonical_tproxy_engine_config(
        template,
        NonZeroU16::new(PORT).unwrap(),
        AddressHostFamilySelection::DualStack,
    )
    .expect_err("a separated family-specific pair cannot reconstruct as canonical output");
}

#[test]
fn untagged_source_tproxy_preserves_unowned_legacy_references() {
    let artifact = compile(
        br#"{
          "inbounds":[
            {"type":"tproxy"},
            {"type":"mixed","tag":"tproxy-in"}
          ],
          "route":{"rules":[{"inbound":"tproxy-in"}]},
          "dns":{"rules":[{"inbound":["other","tproxy-in"]}]}
        }"#,
        PORT,
    )
    .expect("an untagged source does not claim the legacy default tag");
    let document: serde_json::Value = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(document["route"]["rules"][0]["inbound"], "tproxy-in");
    assert_eq!(
        document["dns"]["rules"][0]["inbound"],
        serde_json::json!(["other", "tproxy-in"])
    );
}

#[test]
fn semantic_template_key_order_does_not_change_identities_or_output() {
    let first = compile(
        br#"{"route":{"final":"proxy"},"inbounds":[],"log":{"level":"warn"}}"#,
        PORT,
    )
    .unwrap();
    let second = compile(
        br#" { "log" : { "level" : "warn" }, "inbounds" : [ ], "route" : { "final" : "proxy" } } "#,
        PORT,
    )
    .unwrap();

    assert_eq!(first.bytes(), second.bytes());
    assert_eq!(first.template_digest(), second.template_digest());
    assert_eq!(first.content_sha256(), second.content_sha256());
    assert_eq!(first.digest(), second.digest());
}

#[test]
fn listener_port_changes_only_the_compiled_identity_not_the_template_identity() {
    let template = br#"{"inbounds":[]}"#;
    let first = compile(template, PORT).unwrap();
    let second = compile(template, PORT + 1).unwrap();

    assert_eq!(first.template_digest(), second.template_digest());
    assert_ne!(first.content_sha256(), second.content_sha256());
    assert_ne!(first.digest(), second.digest());
}

#[test]
fn canary_route_precedes_and_preserves_user_policy() {
    let template = br#"{
        "outbounds": [
            {"type":"direct","tag":"USER-DIRECT"},
            {"type":"selector","tag":"USER-PROXY","outbounds":["USER-DIRECT"]}
        ],
        "route": {
            "rules": [
                {"action":"sniff"},
                {"action":"route","network":"tcp","outbound":"USER-PROXY"}
            ],
            "final":"USER-PROXY"
        }
    }"#;
    let artifact = compile_with_canary_route(
        template,
        PORT,
        AddressHostFamilySelection::DualStack,
        dual_stack_canary_route(),
    )
    .expect("canonical canary route");
    let document: serde_json::Value =
        serde_json::from_slice(artifact.bytes()).expect("compiled configuration JSON");

    assert_eq!(
        document["outbounds"],
        serde_json::json!([
            {"tag":"flux-canary-direct-v1","type":"direct"},
            {"tag":"USER-DIRECT","type":"direct"},
            {"outbounds":["USER-DIRECT"],"tag":"USER-PROXY","type":"selector"}
        ])
    );
    assert_eq!(
        document["route"]["rules"],
        serde_json::json!([
            {
                "action":"route",
                "ip_cidr":["192.0.2.2/32","2001:db8::2/128"],
                "network":"tcp",
                "outbound":"flux-canary-direct-v1",
                "port":[41001,41053]
            },
            {
                "action":"route",
                "ip_cidr":["192.0.2.2/32","2001:db8::2/128"],
                "network":"udp",
                "outbound":"flux-canary-direct-v1",
                "port":[41002,41053]
            },
            {"action":"sniff"},
            {"action":"route","network":"tcp","outbound":"USER-PROXY"}
        ])
    );
    assert_eq!(document["route"]["final"], "USER-PROXY");
}

#[test]
fn canary_route_is_deterministic_and_bound_to_config_identity() {
    let template = br#"{"inbounds":[],"route":{"rules":[]}}"#;
    let reordered = br#" { "route" : { "rules" : [ ] }, "inbounds" : [ ] } "#;
    let route = dual_stack_canary_route();
    let first =
        compile_with_canary_route(template, PORT, AddressHostFamilySelection::DualStack, route)
            .unwrap();
    let second = compile_with_canary_route(
        reordered,
        PORT,
        AddressHostFamilySelection::DualStack,
        route,
    )
    .unwrap();

    assert_eq!(first.bytes(), second.bytes());
    assert_eq!(first.template_digest(), second.template_digest());
    assert_eq!(first.content_sha256(), second.content_sha256());
    assert_eq!(first.digest(), second.digest());

    let changed_route = TproxyCanaryEngineRoute::new(
        Ipv4Addr::new(192, 0, 2, 3),
        Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3)),
        NonZeroU16::new(41001).unwrap(),
        NonZeroU16::new(41002).unwrap(),
        NonZeroU16::new(41053).unwrap(),
    );
    let changed = compile_with_canary_route(
        template,
        PORT,
        AddressHostFamilySelection::DualStack,
        changed_route,
    )
    .unwrap();
    assert_eq!(first.template_digest(), changed.template_digest());
    assert_ne!(first.content_sha256(), changed.content_sha256());
    assert_ne!(first.digest(), changed.digest());
}

#[test]
fn canary_route_families_must_exactly_match_listener_families() {
    let cases = [
        (
            AddressHostFamilySelection::DualStack,
            ipv4_only_canary_route(),
        ),
        (AddressHostFamilySelection::Ipv4, dual_stack_canary_route()),
        (AddressHostFamilySelection::Ipv6, ipv4_only_canary_route()),
        (AddressHostFamilySelection::Ipv6, dual_stack_canary_route()),
    ];

    for (families, route) in cases {
        let error = compile_with_canary_route(br#"{}"#, PORT, families, route)
            .expect_err("canary route and listener families must match exactly");
        assert_eq!(
            error.kind(),
            EngineConfigCompileErrorKind::CanaryRouteListenerFamilyMismatch
        );
    }
}

#[test]
fn ipv4_only_canary_route_recompiles_idempotently() {
    let route = ipv4_only_canary_route();
    let artifact = compile_with_canary_route(
        br#"{"inbounds":[]}"#,
        PORT,
        AddressHostFamilySelection::Ipv4,
        route,
    )
    .unwrap();
    let document: serde_json::Value = serde_json::from_slice(artifact.bytes()).unwrap();
    let rules = document["route"]["rules"].as_array().unwrap();
    assert_eq!(rules[0]["ip_cidr"], serde_json::json!(["192.0.2.2/32"]));
    assert_eq!(rules[1]["ip_cidr"], serde_json::json!(["192.0.2.2/32"]));

    let recompiled = compile_with_canary_route(
        artifact.bytes(),
        PORT,
        AddressHostFamilySelection::Ipv4,
        route,
    )
    .expect("exact generated canary bundle recompiles");
    assert_eq!(recompiled.bytes(), artifact.bytes());
    assert_eq!(recompiled.content_sha256(), artifact.content_sha256());

    let reconstructed = reconstruct_canonical_tproxy_engine_config(
        artifact.bytes(),
        NonZeroU16::new(PORT).unwrap(),
        AddressHostFamilySelection::Ipv4,
    )
    .expect("exact routed artifact reconstructs canonically");
    assert_eq!(reconstructed.bytes(), artifact.bytes());
}

#[test]
fn canary_route_rejects_reserved_tag_substitution_and_duplicates() {
    for template in [
        br#"{"outbounds":[{"type":"block","tag":"flux-canary-direct-v1"}]}"#.as_slice(),
        br#"{"route":{"rules":[{"action":"route","outbound":"flux-canary-direct-v1"}]}}"#
            .as_slice(),
        br#"{"route":{"final":"flux-canary-direct-v1"}}"#.as_slice(),
    ] {
        let error = compile_with_canary_route(
            template,
            PORT,
            AddressHostFamilySelection::DualStack,
            dual_stack_canary_route(),
        )
        .expect_err("reserved canary tag must remain compiler-owned");
        assert_eq!(
            error.kind(),
            EngineConfigCompileErrorKind::CanaryRouteReservedTagCollision
        );
    }

    let artifact = compile_with_canary_route(
        br#"{}"#,
        PORT,
        AddressHostFamilySelection::DualStack,
        dual_stack_canary_route(),
    )
    .unwrap();
    let mut duplicate: serde_json::Value = serde_json::from_slice(artifact.bytes()).unwrap();
    let outbound = duplicate["outbounds"][0].clone();
    duplicate["outbounds"]
        .as_array_mut()
        .unwrap()
        .push(outbound);
    let duplicate = serde_json::to_vec(&duplicate).unwrap();
    let error = compile_with_canary_route(
        &duplicate,
        PORT,
        AddressHostFamilySelection::DualStack,
        dual_stack_canary_route(),
    )
    .expect_err("duplicate reserved outbound must fail");
    assert_eq!(
        error.kind(),
        EngineConfigCompileErrorKind::CanaryRouteReservedTagCollision
    );
}

#[test]
fn canary_route_rejects_malformed_route_and_outbound_containers() {
    let cases: &[(&[u8], EngineConfigCompileErrorKind)] = &[
        (
            br#"{"outbounds":{}}"#,
            EngineConfigCompileErrorKind::OutboundsNotArray,
        ),
        (
            br#"{"outbounds":[false]}"#,
            EngineConfigCompileErrorKind::OutboundNotObject { index: 0 },
        ),
        (
            br#"{"outbounds":[{"tag":7}]}"#,
            EngineConfigCompileErrorKind::OutboundTagNotString { index: 0 },
        ),
        (
            br#"{"route":[]}"#,
            EngineConfigCompileErrorKind::RouteNotObject,
        ),
        (
            br#"{"route":{"rules":{}}}"#,
            EngineConfigCompileErrorKind::RouteRulesNotArray,
        ),
        (
            br#"{"route":{"rules":[false]}}"#,
            EngineConfigCompileErrorKind::RouteRuleNotObject { index: 0 },
        ),
        (
            br#"{"route":{"rules":[{"outbound":7}]}}"#,
            EngineConfigCompileErrorKind::RouteRuleOutboundNotString { index: 0 },
        ),
    ];

    for (template, expected) in cases {
        let error = compile_with_canary_route(
            template,
            PORT,
            AddressHostFamilySelection::DualStack,
            dual_stack_canary_route(),
        )
        .expect_err("malformed canary route container must fail");
        assert_eq!(error.kind(), *expected);
    }
}

#[test]
fn binds_exact_config_listener_and_launch_artifact_identities() {
    let artifact = compile(br#"{"inbounds":[{"type":"tproxy","network":"udp"}]}"#, PORT).unwrap();
    let artifact_digest = artifact.digest();
    let fixture = EngineSpecFixture::new(
        artifact.bytes(),
        b"sing-box-v1",
        SingBoxReadiness::Listener {
            port: NonZeroU16::new(PORT).unwrap(),
        },
    );

    let binding = bind_engine_config_to_spec(artifact, &fixture.spec).unwrap();

    assert_eq!(
        binding.schema_version(),
        ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION
    );
    assert_eq!(binding.artifact().digest(), artifact_digest);
    assert_eq!(binding.binary_digest(), fixture.spec.binary_digest());
    assert_eq!(binding.config_digest(), fixture.spec.config_digest());
    assert_eq!(binding.privilege(), SingBoxPrivilege::Inherit);
    assert_eq!(binding.digest().as_bytes().len(), 32);
    assert_eq!(
        binding.digest().to_string(),
        "e78104b0d1fd6eb757046c5d13eba5b3cbd2d2b3f41a9aac71a1467281a4f42b"
    );
}

#[test]
fn rejects_config_content_or_listener_shape_drift() {
    let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
    let mismatched_config = EngineSpecFixture::new(
        b"{}\n",
        b"sing-box",
        SingBoxReadiness::Listener {
            port: NonZeroU16::new(PORT).unwrap(),
        },
    );
    let expected_artifact = *artifact.content_sha256();
    let expected_spec = mismatched_config.spec.config_digest();
    let error = bind_engine_config_to_spec(artifact, &mismatched_config.spec).unwrap_err();
    assert_eq!(
        error.kind(),
        EngineConfigBindingErrorKind::ConfigDigestMismatch {
            artifact: expected_artifact,
            engine_spec: expected_spec,
        }
    );

    let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
    let mismatched_port = EngineSpecFixture::new(
        artifact.bytes(),
        b"sing-box",
        SingBoxReadiness::Listener {
            port: NonZeroU16::new(PORT + 1).unwrap(),
        },
    );
    let error = bind_engine_config_to_spec(artifact, &mismatched_port.spec).unwrap_err();
    assert_eq!(
        error.kind(),
        EngineConfigBindingErrorKind::ListenerPortMismatch {
            artifact: NonZeroU16::new(PORT).unwrap(),
            engine_spec: NonZeroU16::new(PORT + 1).unwrap(),
        }
    );

    let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
    let tun = EngineSpecFixture::new(
        artifact.bytes(),
        b"sing-box",
        SingBoxReadiness::TunInterface {
            name: "tun0".to_owned(),
        },
    );
    let error = bind_engine_config_to_spec(artifact, &tun.spec).unwrap_err();
    assert_eq!(
        error.kind(),
        EngineConfigBindingErrorKind::TunReadinessUnsupported
    );
}

#[test]
fn binding_identity_retains_binary_privilege_and_removed_template_provenance() {
    let empty = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
    let old_tun = compile(br#"{"inbounds":[{"type":"tun","tag":"old-tun"}]}"#, PORT).unwrap();
    assert_eq!(empty.bytes(), old_tun.bytes());

    let first_engine = EngineSpecFixture::new(
        empty.bytes(),
        b"sing-box-v1",
        SingBoxReadiness::Listener {
            port: NonZeroU16::new(PORT).unwrap(),
        },
    );
    let second_engine = EngineSpecFixture::new(
        empty.bytes(),
        b"sing-box-v2",
        SingBoxReadiness::Listener {
            port: NonZeroU16::new(PORT).unwrap(),
        },
    );
    let privilege_engine = EngineSpecFixture::new_with_privilege(
        empty.bytes(),
        b"sing-box-v1",
        SingBoxPrivilege::transparent_proxy(engine_credentials(1000, 1000)),
        SingBoxReadiness::Listener {
            port: NonZeroU16::new(PORT).unwrap(),
        },
    );

    let first = bind_engine_config_to_spec(empty.clone(), &first_engine.spec).unwrap();
    let binary_drift = bind_engine_config_to_spec(empty.clone(), &second_engine.spec).unwrap();
    let privilege_drift = bind_engine_config_to_spec(empty, &privilege_engine.spec).unwrap();
    let source_drift = bind_engine_config_to_spec(old_tun, &first_engine.spec).unwrap();

    assert_ne!(first.digest(), binary_drift.digest());
    assert_ne!(first.digest(), privilege_drift.digest());
    assert_eq!(
        privilege_drift.privilege(),
        SingBoxPrivilege::transparent_proxy(engine_credentials(1000, 1000))
    );
    assert_ne!(first.digest(), source_drift.digest());
}

#[test]
fn desired_state_binding_requires_exact_transparent_proxy_privilege() {
    let fixture = HostAssemblyFixture::new();
    let desired_state = fixture.desired_state.desired_state();

    bind_engine_spec_to_desired_state(desired_state, fixture.engine.spec.clone())
        .expect("exact configured privilege binds");

    for privilege in [
        SingBoxPrivilege::Inherit,
        SingBoxPrivilege::transparent_proxy(engine_credentials(1000, 1000)),
    ] {
        let mut process = fixture.engine.spec.process().clone();
        process.privilege = privilege;
        let spec = EngineSpec::new(process, fixture.engine.spec.restart_policy())
            .expect("inspect privilege-drift fixture");
        assert!(matches!(
            bind_engine_spec_to_desired_state(desired_state, spec),
            Err(DesiredStateEngineBindingError::Privilege)
        ));
    }
}

#[test]
fn collects_exact_binary_profile_and_pins_its_revision() {
    let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
    let fixture =
        EngineSpecFixture::new_executable(artifact.bytes(), PROFILE_SCRIPT, listener_readiness());
    let binding = bind_engine_config_to_spec(artifact, &fixture.spec).unwrap();

    let profile = collect_tproxy_engine_capability_profile(&binding, &fixture.spec)
        .expect("exact binary accepts its exact canonical config");

    assert_eq!(
        profile.schema_version(),
        ENGINE_CAPABILITY_PROFILE_SCHEMA_VERSION
    );
    assert_eq!(profile.artifacts(), binding.artifacts());
    assert_eq!(profile.validated_binding(), binding.digest());
    assert_eq!(profile.version().release(), "1.13.14-rc.1+flux.2");
    assert_eq!(profile.version().major(), 1);
    assert_eq!(profile.version().minor(), 13);
    assert_eq!(profile.version().patch(), 14);
    assert_eq!(
        profile.build().stdout(),
        "sing-box version 1.13.14-rc.1+flux.2\n\nEnvironment: go1.24.5 linux/amd64\n"
    );
    assert_eq!(profile.build().stderr(), "Tags: with_quic,with_wireguard\n");
    assert_eq!(
        profile.revision().to_string(),
        "d0ea1b00cfc7ea9686e29aabf4a89173e3b82b65b72b75920f602052e21ca985"
    );
    assert_eq!(profile.revision().as_bytes().len(), 32);
    assert_eq!(profile.supervised_delivery_report(), None);
}

#[test]
fn supervised_report_fixture_changes_and_pins_the_complete_profile_revision() {
    let (binding, profile, _fixture) = collected_profile();
    let baseline_revision = profile.revision();
    let declared = declare_supervised_delivery_report_profile_fixture(profile);
    let contract = declared
        .supervised_delivery_report()
        .expect("test fixture declares the sealed report producer");

    assert!(contract.is_canonical_schema_v1());
    assert_eq!(
        contract.schema_version().get(),
        super::ENGINE_SUPERVISED_DELIVERY_REPORT_SCHEMA_VERSION
    );
    assert_eq!(
        contract.handoff_schema_version().get(),
        super::ENGINE_SUPERVISED_DELIVERY_REPORT_HANDOFF_SCHEMA_VERSION
    );
    assert_ne!(declared.revision(), baseline_revision);
    assert_eq!(
        declared.revision().to_string(),
        "be0d00645e6c39cb53a0576f8ea16aa4129e2602e1484abe9c1410bd50444796"
    );
    assert_eq!(declared.artifacts(), binding.artifacts());
    assert_eq!(declared.validated_binding(), binding.digest());
    assert_eq!(
        declare_supervised_delivery_report_profile_fixture(declared.clone()).revision(),
        declared.revision(),
        "redeclaring the same sealed contract is revision-stable"
    );
}

#[test]
fn profile_collection_rejects_artifact_mismatch_before_execution() {
    let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
    let fixture =
        EngineSpecFixture::new_executable(artifact.bytes(), PROFILE_SCRIPT, listener_readiness());
    let binding = bind_engine_config_to_spec(artifact, &fixture.spec).unwrap();
    let marker_directory = tempfile::tempdir().expect("create probe marker directory");
    let marker = marker_directory.path().join("probe-invoked");
    let mismatched_script = format!(
        "#!/bin/sh\nprintf invoked > \"{}\"\n{}",
        marker.display(),
        std::str::from_utf8(PROFILE_SCRIPT)
            .unwrap()
            .trim_start_matches("#!/bin/sh\n")
    );
    let mismatched = EngineSpecFixture::new_executable(
        binding.artifact().bytes(),
        mismatched_script.as_bytes(),
        listener_readiness(),
    );

    let error = collect_tproxy_engine_capability_profile(&binding, &mismatched.spec)
        .expect_err("artifact-set mismatch must fail before probing");

    assert!(matches!(
        error.kind(),
        EngineCapabilityProfileErrorKind::ArtifactSetMismatch
    ));
    assert!(!marker.exists());
}

#[test]
fn profile_collection_rejects_privilege_mismatch_before_execution() {
    let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
    let marker_directory = tempfile::tempdir().expect("create probe marker directory");
    let marker = marker_directory.path().join("probe-invoked");
    let script = format!(
        "#!/bin/sh\nprintf invoked > \"{}\"\n{}",
        marker.display(),
        std::str::from_utf8(PROFILE_SCRIPT)
            .unwrap()
            .trim_start_matches("#!/bin/sh\n")
    );
    let fixture = EngineSpecFixture::new_executable(
        artifact.bytes(),
        script.as_bytes(),
        listener_readiness(),
    );
    let binding = bind_engine_config_to_spec(artifact, &fixture.spec).unwrap();
    let mut process = fixture.spec.process().clone();
    process.privilege = SingBoxPrivilege::transparent_proxy(engine_credentials(1000, 1000));
    let mismatched = EngineSpec::new(process, fixture.spec.restart_policy())
        .expect("inspect privilege-drift fixture");

    let error = collect_tproxy_engine_capability_profile(&binding, &mismatched)
        .expect_err("privilege mismatch must fail before probing");

    assert!(matches!(
        error.kind(),
        EngineCapabilityProfileErrorKind::PrivilegeMismatch
    ));
    assert!(!marker.exists());
}

#[test]
fn version_output_requires_one_valid_safe_header_across_both_streams() {
    let cases: &[(&[u8], &[u8], EngineVersionOutputErrorKind)] = &[
        (
            b"Environment: go1.24.5 linux/amd64\n",
            b"",
            EngineVersionOutputErrorKind::MissingVersionHeader,
        ),
        (
            b"sing-box version 1.13.14\n",
            b"sing-box version 1.13.14\n",
            EngineVersionOutputErrorKind::AmbiguousVersionHeader,
        ),
        (
            b"sing-box version 1.13\n",
            b"",
            EngineVersionOutputErrorKind::InvalidRelease,
        ),
        (
            b"sing-box version 01.13.14\n",
            b"",
            EngineVersionOutputErrorKind::InvalidRelease,
        ),
        (
            b"sing-box version 1.13.14-rc..1\n",
            b"",
            EngineVersionOutputErrorKind::InvalidRelease,
        ),
    ];

    for (stdout, stderr, expected) in cases {
        let error = parse_sing_box_version_output(stdout, stderr)
            .expect_err("invalid version output must fail closed");
        assert_eq!(
            error.kind(),
            EngineCapabilityProfileErrorKind::VersionOutput(*expected)
        );
    }

    let invalid_utf8 = parse_sing_box_version_output(b"sing-box version 1.13.14\n\xff", b"")
        .expect_err("version output must be exact UTF-8");
    assert_eq!(
        invalid_utf8.kind(),
        EngineCapabilityProfileErrorKind::VersionOutput(
            EngineVersionOutputErrorKind::InvalidUtf8 { stream: "stdout" }
        )
    );

    let unsafe_text = parse_sing_box_version_output(b"sing-box version 1.13.14\n\x1b[31m", b"")
        .expect_err("terminal control output must fail closed");
    assert_eq!(
        unsafe_text.kind(),
        EngineCapabilityProfileErrorKind::VersionOutput(EngineVersionOutputErrorKind::UnsafeText {
            stream: "stdout"
        })
    );
}

#[test]
fn profile_collection_propagates_exact_configuration_check_failure() {
    let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
    let fixture = EngineSpecFixture::new_executable(
        artifact.bytes(),
        PROFILE_CHECK_FAILURE_SCRIPT,
        listener_readiness(),
    );
    let binding = bind_engine_config_to_spec(artifact, &fixture.spec).unwrap();

    let error = collect_tproxy_engine_capability_profile(&binding, &fixture.spec)
        .expect_err("configuration rejection must fail profile collection");

    assert_eq!(
        error.kind(),
        EngineCapabilityProfileErrorKind::Probe(
            crate::engine_supervisor::EngineCapabilityProbeErrorKind::Process
        )
    );
    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<EngineCapabilityProbeError>()),
        Some(EngineCapabilityProbeError::Process {
            source: SingBoxProcessError::CheckFailed { .. }
        })
    ));
}

#[test]
fn compiles_the_same_non_authorizing_candidate_for_identical_inputs() {
    let (binding, profile, _fixture) = collected_profile();
    let mut tracker = NetworkInventoryTracker::new();
    let inventory = empty_inventory(&mut tracker);
    let device_profile = CapabilityProfileFixture::device_qualified();

    let first = compile_tproxy_generation_candidate(
        device_profile.clone(),
        inventory,
        profile.clone(),
        binding.clone(),
    )
    .expect("verified inputs compile");
    let second =
        compile_tproxy_generation_candidate(device_profile.clone(), inventory, profile, binding)
            .expect("identical verified inputs compile");

    assert_eq!(first, second);
    assert_eq!(
        first.schema_version(),
        TPROXY_GENERATION_CANDIDATE_SCHEMA_VERSION
    );
    assert_eq!(first.device_profile(), &device_profile);
    assert_eq!(first.inventory_snapshot(), inventory.snapshot_id());
    assert_eq!(first.inventory_epoch(), inventory.epoch());
    assert_eq!(
        first.engine_profile().validated_binding(),
        first.engine_config().digest()
    );
}

#[test]
fn candidate_rejects_mismatched_engine_binding_or_artifact_set() {
    let (binding, profile, fixture) = collected_profile();
    let mut tracker = NetworkInventoryTracker::new();
    let inventory = empty_inventory(&mut tracker);
    let device_profile = CapabilityProfileFixture::device_qualified();
    let source_drift = compile(br#"{"inbounds":[{"type":"tun","tag":"removed"}]}"#, PORT).unwrap();
    assert_eq!(source_drift.bytes(), binding.artifact().bytes());
    let different_binding = bind_engine_config_to_spec(source_drift, &fixture.spec).unwrap();

    let error = compile_tproxy_generation_candidate(
        device_profile.clone(),
        inventory,
        profile.clone(),
        different_binding,
    )
    .expect_err("profile must validate the exact binding");
    assert_eq!(
        error.kind(),
        TproxyGenerationCandidateErrorKind::EngineBindingMismatch
    );

    let other_fixture = EngineSpecFixture::new_executable(
        binding.artifact().bytes(),
        PROFILE_ALTERNATE_BINARY_SCRIPT,
        listener_readiness(),
    );
    let other_artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
    let other_binding = bind_engine_config_to_spec(other_artifact, &other_fixture.spec).unwrap();
    let error =
        compile_tproxy_generation_candidate(device_profile, inventory, profile, other_binding)
            .expect_err("profile and binding artifact sets must agree");
    assert_eq!(
        error.kind(),
        TproxyGenerationCandidateErrorKind::EngineArtifactSetMismatch
    );
}

#[test]
fn candidate_requires_verified_device_identity_and_supported_kernel() {
    let (binding, profile, _fixture) = collected_profile();
    let mut tracker = NetworkInventoryTracker::new();
    let inventory = empty_inventory(&mut tracker);

    let error = compile_tproxy_generation_candidate(
        CapabilityProfileFixture::unverified_boot(),
        inventory,
        profile.clone(),
        binding.clone(),
    )
    .expect_err("boot identity must be verified");
    assert_eq!(
        error.kind(),
        TproxyGenerationCandidateErrorKind::BootIdentityNotVerified {
            observation: ObservationKind::Unavailable,
        }
    );

    let error = compile_tproxy_generation_candidate(
        CapabilityProfileFixture::supported(),
        inventory,
        profile.clone(),
        binding.clone(),
    )
    .expect_err("exact device identity must be verified");
    assert_eq!(
        error.kind(),
        TproxyGenerationCandidateErrorKind::DeviceIdentityNotVerified {
            observation: ObservationKind::Unavailable,
        }
    );

    let qualified = CapabilityProfileFixture::device_qualified();
    let unsupported = CapabilityProfileFixture::unsupported_kernel();
    let unsupported = CapabilityProfile::new(
        qualified.revision(),
        qualified.boot_identity().clone(),
        qualified.device_identity().clone(),
        unsupported.kernel().clone(),
        qualified.selinux().clone(),
    );
    let error = compile_tproxy_generation_candidate(unsupported, inventory, profile, binding)
        .expect_err("unsupported kernel must fail closed");
    assert!(matches!(
        error.kind(),
        TproxyGenerationCandidateErrorKind::KernelNotSupported {
            support: Some(KernelSupport::Unsupported { .. })
        }
    ));
}

#[test]
fn assembler_produces_one_complete_host_inspection_generation() {
    let fixture = HostAssemblyFixture::new();
    let admitted = fixture.assemble(None, None).expect("host Generation");

    assert_eq!(
        admitted.schema_version(),
        ADMITTED_GENERATION_SCHEMA_VERSION
    );
    assert_eq!(admitted.generation().get(), 1);
    assert_eq!(
        admitted.functional_canary_mode(),
        FunctionalCanaryGateMode::RequiredUnqualified
    );
    assert!(
        admitted
            .supervised_delivery_report()
            .expect("required Generation retains its sealed report contract")
            .is_canonical_schema_v1()
    );
    assert_eq!(
        admitted.admission_kind(),
        GenerationAdmissionKind::HostInspectionOnly
    );
    assert_eq!(
        admitted.candidate().inventory_snapshot(),
        fixture.inventory.snapshot_id()
    );
    assert_eq!(
        admitted.candidate().inventory_epoch(),
        fixture.inventory.epoch()
    );
    assert_eq!(
        admitted.xtables().namespace().generation(),
        admitted.generation()
    );
    assert_eq!(
        admitted.xtables().source_program_digest(),
        admitted.capture().program().digest()
    );
    assert!(admitted.xtables().ipv4().is_some());
    assert!(admitted.xtables().ipv6().is_none());
    assert_eq!(
        admitted
            .xtables()
            .ipv4()
            .and_then(|pair| pair.local_output_canary_selector()),
        Some("FLX4C0000000001")
    );
    assert_eq!(
        admitted
            .xtables()
            .ipv4()
            .and_then(|pair| pair.local_output_canary_observation()),
        Some("FLX4A0000000001")
    );
    assert_eq!(
        admitted.engine_spec().restart_policy().maximum_backoff(),
        admitted
            .desired_state()
            .engine()
            .restart()
            .maximum_backoff()
    );
    assert!(
        admitted
            .identity()
            .digest()
            .as_bytes()
            .iter()
            .any(|byte| *byte != 0)
    );

    let inspection = crate::runtime_coordinator::inspect_admitted_generation(&admitted);
    assert_eq!(inspection.identity(), admitted.identity());
    assert_eq!(inspection.admission(), admitted.admission_kind());
    assert_eq!(
        inspection.capability_profile_revision(),
        admitted.candidate().device_profile().revision().get()
    );
    assert_eq!(
        inspection.inventory_snapshot(),
        admitted.candidate().inventory_snapshot().get()
    );
    assert_eq!(
        inspection.inventory_epoch(),
        admitted.candidate().inventory_epoch().get()
    );
}

#[test]
fn required_functional_canary_rejects_an_unqualified_engine_profile() {
    let fixture = HostAssemblyFixture::new();
    let error = match fixture.assemble_with_engine_profile(
        fixture.desired_state.clone(),
        fixture.unqualified_engine_profile.clone(),
    ) {
        Ok(_) => panic!("required functional canary admitted an unqualified engine profile"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        GenerationAssemblyError::RequiredFunctionalCanaryReportUnavailable
    ));
    assert_eq!(
        error.to_string(),
        "require_functional_canary needs an exact engine profile with the canonical supervised-delivery report contract"
    );
}

#[test]
fn structural_functional_canary_admits_an_unqualified_engine_profile() {
    let fixture = HostAssemblyFixture::new();
    let source = fixture.base_desired_state.replacen(
        "require_functional_canary = true",
        "require_functional_canary = false",
        1,
    );
    let admitted = fixture
        .assemble_with_engine_profile(
            fixture.compile_desired_state(&source),
            fixture.unqualified_engine_profile.clone(),
        )
        .expect("structural functional-canary policy accepts an unqualified engine profile");

    assert_eq!(
        admitted.functional_canary_mode(),
        FunctionalCanaryGateMode::StructuralVerificationOnly
    );
    assert_eq!(admitted.supervised_delivery_report(), None);
    assert!(
        admitted
            .xtables()
            .ipv4()
            .is_some_and(|pair| pair.local_output_canary_selector().is_none())
    );
}

#[test]
fn host_inspection_generation_cannot_be_promoted_to_a_native_target() {
    let generation = HostAssemblyFixture::new()
        .assemble(None, None)
        .expect("complete host-inspection Generation");

    let error = match generation.into_native_target_request() {
        Ok(_) => panic!("host evidence unexpectedly crossed the native target seam"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        NativeGenerationPromotionError::HostInspectionNonPromotable
    );
    assert_eq!(
        error.to_string(),
        "host inspection evidence cannot be promoted to native mutation authority"
    );
}

#[test]
fn assembler_is_deterministic_and_advances_from_prior_owned_identity() {
    let fixture = HostAssemblyFixture::new();
    let first = fixture.assemble(None, None).expect("first Generation");
    let repeated = fixture.assemble(None, None).expect("repeated Generation");
    assert_eq!(first.identity(), repeated.identity());
    assert_eq!(first.xtables(), repeated.xtables());

    let successor = fixture
        .assemble(Some(first.identity()), None)
        .expect("successor Generation");
    assert_eq!(successor.generation().get(), 2);
    assert_ne!(first.identity(), successor.identity());
    assert_eq!(
        successor.xtables().namespace().generation(),
        successor.generation()
    );
    assert_ne!(first.xtables().digest(), successor.xtables().digest());
}

#[test]
fn automatic_capture_path_selection_chooses_the_only_implemented_qualified_adapter() {
    let admitted = HostAssemblyFixture::new()
        .assemble(None, None)
        .expect("automatic Capture Path Generation");
    let selection = admitted.capture_path_selection();

    assert_eq!(selection.request(), CapturePathRequest::Auto);
    assert_eq!(selection.selected(), CapturePathId::XtablesTproxy);
    assert_eq!(
        selection.reason(),
        CapturePathSelectionReason::AutomaticHighestRankedQualified
    );
    assert_eq!(
        selection.candidates().map(|candidate| candidate.state()),
        [
            AndroidCapturePathState::Unimplemented,
            AndroidCapturePathState::Qualified,
            AndroidCapturePathState::Unimplemented,
        ]
    );
}

#[test]
fn kernel_eligibility_without_behavioral_qualification_rejects_every_production_adapter() {
    let fixture = HostAssemblyFixture::new();
    let rejection = unqualified_capture_path_rejection(&fixture);

    assert_eq!(rejection.request(), CapturePathRequest::Auto);
    assert_eq!(
        rejection.reason(),
        CapturePathRejectionReason::NoQualifiedPath
    );
    assert_eq!(
        rejection.candidates().map(|candidate| candidate.state()),
        [
            AndroidCapturePathState::Unimplemented,
            AndroidCapturePathState::Unqualified,
            AndroidCapturePathState::Unimplemented,
        ]
    );
    assert_eq!(
        rejection
            .candidates()
            .map(|candidate| candidate.qualification_state()),
        [CapturePathQualificationState::Unqualified; 3]
    );
    assert_eq!(rejection.candidates()[1].first_kernel_gap(), None);
}

#[test]
fn capture_path_behavior_from_a_different_capability_profile_is_rejected() {
    let fixture = HostAssemblyFixture::new();
    let current = &fixture.capability_profile;
    let drifted = CapabilityProfile::new(
        CapabilityProfileRevision::new(current.revision().get() + 1)
            .expect("next Capability Profile revision"),
        current.boot_identity().clone(),
        current.device_identity().clone(),
        current.kernel().clone(),
        current.selinux().clone(),
    );
    let platform_profile =
        select_reviewed_android_platform_profile(&drifted, test_network_namespace())
            .expect("unmatched exact platform produces zero-grant evidence");
    let evidence = CapturePathQualificationEvidence::with_maximum_lifetime(
        platform_profile.capture_path_evidence(),
        Instant::now(),
    )
    .expect("reviewed Capture Path evidence has a bounded daemon lease");
    let planning = HostInspectionPlanningAuthority::new(
        current,
        qualified_xtables_kernel_config(),
        evidence,
        &fixture.inventory,
        test_network_namespace(),
        test_mark(),
        Some(test_routing()),
    );

    let error = fixture
        .assemble_with(
            None,
            fixture.desired_state.clone(),
            &fixture.inventory,
            GenerationPlanningAuthority::host_inspection(planning),
        )
        .expect_err("stale Capture Path context cannot authorize selection");
    let GenerationAssemblyError::CapturePath(error) = error else {
        panic!("unexpected stale Capture Path context error: {error}");
    };
    assert_eq!(
        error.kind(),
        CapturePathRejectionReason::QualificationEvidenceContextMismatch
    );
    let decision = CapturePathDecision::Rejected {
        rejection: error.rejection(),
    };
    let encoded = serde_json::to_vec(&decision).expect("encode context-mismatch decision");
    assert_eq!(
        serde_json::from_slice::<CapturePathDecision>(&encoded)
            .expect("decode context-mismatch decision"),
        decision
    );
}

#[test]
fn rejected_capture_path_decision_round_trips_complete_candidate_evidence() {
    let fixture = HostAssemblyFixture::new();
    let decision = CapturePathDecision::Rejected {
        rejection: unqualified_capture_path_rejection(&fixture),
    };

    let encoded = serde_json::to_vec(&decision).expect("encode rejected Capture Path decision");
    let decoded = serde_json::from_slice::<CapturePathDecision>(&encoded)
        .expect("decode rejected Capture Path decision");

    assert_eq!(decoded, decision);
    assert!(
        encoded
            .windows(b"\"qualification_state\":\"unqualified\"".len())
            .any(|window| { window == b"\"qualification_state\":\"unqualified\"" })
    );
}

#[test]
fn selected_capture_path_decode_rejects_qualified_state_without_qualified_behavior() {
    let selection = HostAssemblyFixture::new()
        .assemble(None, None)
        .expect("qualified Capture Path Generation")
        .capture_path_selection();
    let mut encoded = serde_json::to_value(CapturePathDecision::Selected { selection })
        .expect("encode selected Capture Path decision");
    encoded["selection"]["candidates"][1]["qualification_state"] =
        serde_json::Value::String("unqualified".to_owned());

    serde_json::from_value::<CapturePathDecision>(encoded)
        .expect_err("qualified aggregate state without qualified behavior must fail closed");
}

#[test]
fn selected_capture_path_decode_rejects_qualified_state_with_a_disabled_kernel_gap() {
    let selection = HostAssemblyFixture::new()
        .assemble(None, None)
        .expect("qualified Capture Path Generation")
        .capture_path_selection();
    let mut encoded = serde_json::to_value(CapturePathDecision::Selected { selection })
        .expect("encode selected Capture Path decision");
    encoded["selection"]["candidates"][1]["first_kernel_gap"] = serde_json::json!({
        "config_symbol": "CONFIG_NETFILTER",
        "state": "disabled"
    });

    serde_json::from_value::<CapturePathDecision>(encoded).expect_err(
        "qualified aggregate state with a disabled kernel prerequisite must fail closed",
    );
}

#[test]
fn exact_unimplemented_capture_paths_fail_without_xtables_fallback() {
    let fixture = HostAssemblyFixture::new();
    for (token, path) in [
        ("nftables_tproxy", CapturePathId::NftablesTproxy),
        ("managed_tun", CapturePathId::ManagedTun),
    ] {
        let source = fixture.base_desired_state.replacen(
            "path = \"auto\"",
            &format!("path = \"{token}\""),
            1,
        );
        let desired_state = fixture.compile_desired_state(&source);
        let error = fixture
            .assemble(None, Some(desired_state))
            .expect_err("an unimplemented exact Capture Path must be rejected");
        let GenerationAssemblyError::CapturePath(error) = error else {
            panic!("unexpected exact Capture Path error: {error}");
        };

        assert_eq!(
            error.kind(),
            CapturePathSelectionErrorKind::ExactPathUnavailable {
                path,
                state: AndroidCapturePathState::Unimplemented,
            }
        );
        assert_eq!(
            error.candidates()[1].state(),
            AndroidCapturePathState::Qualified,
            "qualified xtables must remain diagnostic evidence, not an exact-request fallback"
        );
    }
}

#[test]
fn exact_xtables_selection_succeeds_and_changes_generation_identity() {
    let fixture = HostAssemblyFixture::new();
    let automatic = fixture
        .assemble(None, None)
        .expect("automatic Capture Path Generation");
    let exact_source =
        fixture
            .base_desired_state
            .replacen("path = \"auto\"", "path = \"xtables_tproxy\"", 1);
    let exact = fixture
        .assemble(None, Some(fixture.compile_desired_state(&exact_source)))
        .expect("exact xtables Capture Path Generation");

    assert_eq!(
        exact.capture_path_selection().request(),
        CapturePathRequest::Exact(CapturePathId::XtablesTproxy)
    );
    assert_eq!(
        exact.capture_path_selection().reason(),
        CapturePathSelectionReason::ExactRequestQualified
    );
    assert_ne!(
        automatic.capture_path_selection().evidence_digest(),
        exact.capture_path_selection().evidence_digest()
    );
    assert_ne!(automatic.identity(), exact.identity());
}

#[test]
fn admitted_generation_preserves_the_original_capture_path_evidence_deadline() {
    let fixture = HostAssemblyFixture::new();
    let observed_at = Instant::now();
    let valid_until = observed_at
        .checked_add(Duration::from_secs(42))
        .expect("test deadline remains representable");
    let qualified = qualified_xtables_capture_path_evidence();
    let evidence = CapturePathQualificationEvidence::host_inspection(
        qualified.qualifications(),
        observed_at,
        valid_until,
    )
    .expect("test evidence lifetime is bounded");
    let planning = HostInspectionPlanningAuthority::new(
        &fixture.capability_profile,
        qualified_xtables_kernel_config(),
        evidence,
        &fixture.inventory,
        test_network_namespace(),
        test_mark(),
        Some(test_routing()),
    );

    let admitted = fixture
        .assemble_with(
            None,
            fixture.desired_state.clone(),
            &fixture.inventory,
            GenerationPlanningAuthority::host_inspection(planning),
        )
        .expect("Generation with bounded Capture Path evidence");

    assert_eq!(admitted.capture_path_evidence_deadline(), valid_until);
}

fn unqualified_capture_path_rejection(fixture: &HostAssemblyFixture) -> CapturePathRejection {
    let planning = HostInspectionPlanningAuthority::new(
        &fixture.capability_profile,
        qualified_xtables_kernel_config(),
        CapturePathQualificationEvidence::host_inspection_with_maximum_lifetime(
            CapturePathQualifications::default(),
            Instant::now(),
        )
        .expect("unqualified test evidence has a bounded lifetime"),
        &fixture.inventory,
        test_network_namespace(),
        test_mark(),
        Some(test_routing()),
    );
    let error = fixture
        .assemble_with(
            None,
            fixture.desired_state.clone(),
            &fixture.inventory,
            GenerationPlanningAuthority::host_inspection(planning),
        )
        .expect_err("kernel eligibility alone must not qualify a Capture Path");
    let GenerationAssemblyError::CapturePath(error) = error else {
        panic!("unexpected unqualified Capture Path error: {error}");
    };
    error.rejection()
}

#[test]
fn assembler_successor_identity_binds_the_complete_prior_identity() {
    let fixture = HostAssemblyFixture::new();
    let first = fixture.assemble(None, None).expect("first Generation");
    let alternate_prior = AdmittedGenerationIdentity::new(
        first.generation(),
        GenerationAssemblyDigest::from_bytes([0xa5; 32]),
    );

    let successor = fixture
        .assemble(Some(first.identity()), None)
        .expect("successor Generation");
    let alternate = fixture
        .assemble(Some(alternate_prior), None)
        .expect("alternate successor Generation");

    assert_eq!(successor.generation(), alternate.generation());
    assert_ne!(successor.identity(), alternate.identity());
}

#[test]
fn assembler_identity_binds_the_selected_subscription_source() {
    let fixture = HostAssemblyFixture::new();
    let config = FluxConfig::parse(&fixture.base_desired_state).expect("fixture Desired State");
    let applications =
        CaptureApplicationPolicy::new(CaptureApplicationMode::All, []).expect("all applications");
    let capture =
        compile_desired_state_capture(DesiredStateCompileRequest::new(config, applications, None))
            .expect("capture artifacts");
    let artifact = fixture.desired_state.engine_config().clone();
    let first_source = SelectedEngineSource::subscription(artifact.clone(), [0x11; 32], [0x21; 32]);
    let second_source = SelectedEngineSource::subscription(artifact, [0x12; 32], [0x22; 32]);
    let first = fixture
        .assemble(
            None,
            Some(capture.clone().with_engine_source(first_source).unwrap()),
        )
        .expect("first subscription-backed Generation");
    let second = fixture
        .assemble(
            None,
            Some(capture.with_engine_source(second_source).unwrap()),
        )
        .expect("second subscription-backed Generation");

    assert_eq!(first.candidate(), second.candidate());
    assert_eq!(first.capture(), second.capture());
    assert_eq!(first.xtables(), second.xtables());
    assert_eq!(
        first.engine_source(),
        SelectedEngineSourceIdentity::Subscription {
            snapshot_digest: [0x11; 32],
            subscription_source: [0x21; 32],
        }
    );
    assert_ne!(first.engine_source(), second.engine_source());
    assert_ne!(first.identity(), second.identity());
}

#[test]
fn assembler_rejects_stale_host_inventory_binding() {
    let fixture = HostAssemblyFixture::new();
    let mut tracker = NetworkInventoryTracker::new();
    let replacement = empty_inventory(&mut tracker).clone();

    let error = fixture
        .assemble_with(
            None,
            fixture.desired_state.clone(),
            &replacement,
            GenerationPlanningAuthority::host_inspection(fixture.planning.clone()),
        )
        .expect_err("stale inspection authority must fail");

    assert!(matches!(
        error,
        GenerationAssemblyError::Planning(ref source)
            if source.kind() == GenerationPlanningErrorKind::InventorySnapshotMismatch
    ));
}

#[test]
fn assembler_requires_local_output_routing_evidence() {
    let fixture = HostAssemblyFixture::new();
    let authority = HostInspectionPlanningAuthority::new(
        &fixture.capability_profile,
        qualified_xtables_kernel_config(),
        qualified_xtables_capture_path_evidence(),
        &fixture.inventory,
        test_network_namespace(),
        test_mark(),
        None,
    );

    let error = fixture
        .assemble_with(
            None,
            fixture.desired_state.clone(),
            &fixture.inventory,
            GenerationPlanningAuthority::host_inspection(authority),
        )
        .expect_err("local OUTPUT without routing evidence must fail");

    assert!(matches!(
        error,
        GenerationAssemblyError::Planning(ref source)
            if source.kind() == GenerationPlanningErrorKind::MissingLocalOutputRouting
    ));
}

#[test]
fn assembler_identity_binds_product_policy_outside_engine_and_xtables_bytes() {
    let fixture = HostAssemblyFixture::new();
    let baseline = fixture.assemble(None, None).expect("baseline Generation");
    let changed_source = fixture.base_desired_state.replacen(
        "respect_android_vpn = true",
        "respect_android_vpn = false",
        1,
    );
    let changed_desired_state = fixture.compile_desired_state(&changed_source);
    let changed = fixture
        .assemble(None, Some(changed_desired_state))
        .expect("changed policy Generation");

    assert_eq!(baseline.xtables(), changed.xtables());
    assert_eq!(
        baseline.candidate().engine_config(),
        changed.candidate().engine_config()
    );
    assert_ne!(baseline.identity(), changed.identity());
}

#[test]
fn assembler_identity_binds_complete_capability_profile_not_only_revision() {
    let fixture = HostAssemblyFixture::new();
    let baseline = fixture.assemble(None, None).expect("baseline Generation");
    let changed_profile = CapabilityProfile::new(
        fixture.capability_profile.revision(),
        fixture.capability_profile.boot_identity().clone(),
        fixture.capability_profile.device_identity().clone(),
        fixture.capability_profile.kernel().clone(),
        Observation::Verified(SelinuxMode::Permissive),
    );
    let planning = HostInspectionPlanningAuthority::new(
        &changed_profile,
        qualified_xtables_kernel_config(),
        qualified_xtables_capture_path_evidence(),
        &fixture.inventory,
        test_network_namespace(),
        test_mark(),
        Some(test_routing()),
    );
    let changed = GenerationAssembler
        .assemble(GenerationAssemblyRequest::new(
            fixture.desired_state.clone(),
            fixture.engine.spec.clone(),
            changed_profile.clone(),
            &fixture.inventory,
            fixture.engine_profile.clone(),
            GenerationPlanningAuthority::host_inspection(planning),
        ))
        .expect("Generation with changed complete profile");

    assert_eq!(
        baseline.candidate().device_profile().revision(),
        changed.candidate().device_profile().revision()
    );
    assert_ne!(
        baseline.candidate().device_profile().digest(),
        changed_profile.digest()
    );
    assert_eq!(baseline.xtables(), changed.xtables());
    assert_ne!(baseline.planning_digest(), changed.planning_digest());
    assert_ne!(baseline.identity(), changed.identity());
}

#[test]
fn prepared_generation_record_round_trips_and_replaces_atomically() {
    let fixture = HostAssemblyFixture::new();
    let first = fixture.assemble(None, None).expect("first Generation");
    let successor = fixture
        .assemble(Some(first.identity()), None)
        .expect("successor Generation");
    let first_record = PreparedGenerationRecord::from_admitted(&first);
    let successor_record = PreparedGenerationRecord::from_admitted(&successor);
    let directory = tempfile::tempdir().expect("Generation record directory");
    let record_path = directory.path().join("state/generations/prepared.json");
    let store = PreparedGenerationRecordStore::new(&record_path);

    assert!(store.load().expect("missing record").is_none());
    store.persist(&first_record).expect("persist first record");
    assert_eq!(store.load().expect("load first record"), Some(first_record));
    store
        .persist(&successor_record)
        .expect("replace prepared record");
    assert_eq!(
        store.load().expect("load successor record"),
        Some(successor_record.clone())
    );
    assert_eq!(
        successor_record.schema_version(),
        PREPARED_GENERATION_RECORD_SCHEMA_VERSION
    );
    assert_eq!(successor_record.previous(), Some(first.identity()));
    assert_eq!(
        successor_record.capability_profile_digest(),
        successor.candidate().device_profile().digest().as_bytes()
    );
    assert_eq!(
        successor_record.planning_evidence_digest(),
        successor.planning_digest().as_bytes()
    );
    assert_eq!(
        successor_record.capture_path_selection(),
        successor.capture_path_selection()
    );

    let encoded = fs::read(&record_path).expect("encoded Generation record");
    assert!(encoded.ends_with(b"\n"));
    assert!(encoded.len() <= MAX_PREPARED_GENERATION_RECORD_BYTES);
    assert!(
        fs::read_dir(record_path.parent().expect("record parent"))
            .expect("record directory")
            .all(|entry| !entry
                .expect("record entry")
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp"))
    );
}

#[test]
fn prepared_generation_record_rejects_symlink_targets() {
    use std::os::unix::fs::symlink;

    let fixture = HostAssemblyFixture::new();
    let admitted = fixture.assemble(None, None).expect("host Generation");
    let record = PreparedGenerationRecord::from_admitted(&admitted);
    let directory = tempfile::tempdir().expect("Generation record directory");
    let target_path = directory.path().join("target.json");
    PreparedGenerationRecordStore::new(&target_path)
        .persist(&record)
        .expect("persist symlink target fixture");
    let record_path = directory.path().join("prepared.json");
    symlink(&target_path, &record_path).expect("create Generation-record symlink");
    let store = PreparedGenerationRecordStore::new(&record_path);

    assert!(matches!(
        store.load(),
        Err(PreparedGenerationRecordError::Storage(
            crate::IntentStoreError::Symlink(ref path)
        )) if path == &record_path
    ));
    assert!(matches!(
        store.persist(&record),
        Err(PreparedGenerationRecordError::Storage(
            crate::IntentStoreError::Symlink(ref path)
        )) if path == &record_path
    ));
}

#[test]
fn prepared_generation_record_rejects_invalid_digest_and_oversized_input() {
    let fixture = HostAssemblyFixture::new();
    let admitted = fixture.assemble(None, None).expect("host Generation");
    let record = PreparedGenerationRecord::from_admitted(&admitted);
    let directory = tempfile::tempdir().expect("Generation record directory");
    let record_path = directory.path().join("prepared.json");
    let store = PreparedGenerationRecordStore::new(&record_path);
    store.persist(&record).expect("persist valid record");

    let digest = record.identity().digest().to_string();
    let invalid = format!("G{}", &digest[1..]);
    let encoded = fs::read_to_string(&record_path)
        .expect("read Generation record")
        .replacen(&digest, &invalid, 1);
    fs::write(&record_path, encoded).expect("write invalid digest fixture");
    assert!(matches!(
        store.load(),
        Err(PreparedGenerationRecordError::InvalidDigest {
            field: "identity.digest"
        })
    ));

    fs::write(
        &record_path,
        vec![b'x'; MAX_PREPARED_GENERATION_RECORD_BYTES + 1],
    )
    .expect("write oversized Generation record");
    assert!(matches!(
        store.load(),
        Err(PreparedGenerationRecordError::Storage(
            crate::IntentStoreError::RecordTooLarge {
                limit: MAX_PREPARED_GENERATION_RECORD_BYTES
            }
        ))
    ));
}

#[test]
fn prepared_generation_record_rejects_noncontiguous_lineage() {
    let fixture = HostAssemblyFixture::new();
    let first = fixture.assemble(None, None).expect("first Generation");
    let successor = fixture
        .assemble(Some(first.identity()), None)
        .expect("successor Generation");
    let record = PreparedGenerationRecord::from_admitted(&successor);
    let directory = tempfile::tempdir().expect("Generation record directory");
    let record_path = directory.path().join("prepared.json");
    let store = PreparedGenerationRecordStore::new(&record_path);
    store.persist(&record).expect("persist successor record");

    let mut encoded: serde_json::Value =
        serde_json::from_slice(&fs::read(&record_path).expect("read Generation record"))
            .expect("decode Generation record fixture");
    encoded["identity"]["generation"] = serde_json::Value::from(3);
    fs::write(
        &record_path,
        serde_json::to_vec(&encoded).expect("encode noncontiguous lineage fixture"),
    )
    .expect("write noncontiguous lineage fixture");

    assert!(matches!(
        store.load(),
        Err(PreparedGenerationRecordError::InvalidPreviousGeneration)
    ));
}

#[test]
fn rejects_duplicate_or_ambiguous_json_before_compilation() {
    for template in [
        br#"{"inbounds":[],"inbounds":[]}"#.as_slice(),
        br#"{"inbounds":[{"type":"tproxy","type":"tun"}]}"#.as_slice(),
        br#"{"inbounds":[]} trailing"#.as_slice(),
    ] {
        let error = compile(template, PORT).expect_err("ambiguous JSON must fail closed");
        assert_eq!(error.kind(), EngineConfigCompileErrorKind::InvalidJson);
        assert!(error.source().is_some());
    }
}

#[test]
fn rejects_invalid_or_multiple_inbound_shapes() {
    let cases: &[(&[u8], EngineConfigCompileErrorKind)] = &[
        (b"[]", EngineConfigCompileErrorKind::RootNotObject),
        (
            br#"{"inbounds":{}}"#,
            EngineConfigCompileErrorKind::InboundsNotArray,
        ),
        (
            br#"{"inbounds":[false]}"#,
            EngineConfigCompileErrorKind::InboundNotObject { index: 0 },
        ),
        (
            br#"{"inbounds":[{}]}"#,
            EngineConfigCompileErrorKind::InboundTypeMissing { index: 0 },
        ),
        (
            br#"{"inbounds":[{"type":7}]}"#,
            EngineConfigCompileErrorKind::InboundTypeNotString { index: 0 },
        ),
        (
            br#"{"inbounds":[{"type":"tproxy","tag":7}]}"#,
            EngineConfigCompileErrorKind::InboundTagNotString { index: 0 },
        ),
        (
            br#"{"inbounds":[{"type":"tproxy"},{"type":"tproxy"}]}"#,
            EngineConfigCompileErrorKind::MultipleTproxyInbounds,
        ),
    ];

    for (template, expected) in cases {
        let error = compile(template, PORT).expect_err("invalid inbound shape must fail");
        assert_eq!(error.kind(), *expected);
    }
}

#[test]
fn removed_template_input_remains_bound_to_the_artifact_identity() {
    let empty = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
    let old_tun = compile(br#"{"inbounds":[{"type":"tun","tag":"old-tun"}]}"#, PORT).unwrap();

    assert_eq!(empty.bytes(), old_tun.bytes());
    assert_eq!(empty.content_sha256(), old_tun.content_sha256());
    assert_ne!(empty.template_digest(), old_tun.template_digest());
    assert_ne!(empty.digest(), old_tun.digest());
}

#[test]
fn canonical_artifact_reconstruction_rejects_semantically_equal_noncanonical_bytes() {
    let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
    let port = NonZeroU16::new(PORT).unwrap();
    let reconstructed = reconstruct_canonical_tproxy_engine_config(
        artifact.bytes(),
        port,
        AddressHostFamilySelection::DualStack,
    )
    .expect("exact canonical bytes reconstruct");
    assert_eq!(reconstructed.bytes(), artifact.bytes());
    assert_eq!(reconstructed.content_sha256(), artifact.content_sha256());
    assert_eq!(reconstructed.listener_port(), artifact.listener_port());
    assert_ne!(reconstructed.template_digest(), artifact.template_digest());

    let error = reconstruct_canonical_tproxy_engine_config(
        br#"{"inbounds":[]}"#,
        port,
        AddressHostFamilySelection::DualStack,
    )
    .expect_err("raw template bytes are not a canonical output artifact");
    assert_eq!(error.kind(), EngineConfigCompileErrorKind::NonCanonical);
}

#[test]
fn enforces_document_and_inbound_resource_budgets() {
    let oversized = vec![b' '; usize::try_from(MAX_ENGINE_CONFIG_BYTES).unwrap() + 1];
    let error = compile(&oversized, PORT).expect_err("oversized template must fail early");
    assert_eq!(
        error.kind(),
        EngineConfigCompileErrorKind::TemplateTooLarge {
            actual: oversized.len(),
            maximum: MAX_ENGINE_CONFIG_BYTES,
        }
    );

    let inbounds = std::iter::repeat_n("{}", MAX_GENERATION_ENGINE_CONFIG_INBOUNDS + 1)
        .collect::<Vec<_>>()
        .join(",");
    let template = format!("{{\"inbounds\":[{inbounds}]}}");
    let error = compile(template.as_bytes(), PORT).expect_err("inbound count must be bounded");
    assert_eq!(
        error.kind(),
        EngineConfigCompileErrorKind::TooManyInbounds {
            actual: MAX_GENERATION_ENGINE_CONFIG_INBOUNDS + 1,
            maximum: MAX_GENERATION_ENGINE_CONFIG_INBOUNDS,
        }
    );
}

struct HostAssemblyFixture {
    desired_state: DesiredStateArtifacts,
    base_desired_state: String,
    engine: EngineSpecFixture,
    capability_profile: CapabilityProfile,
    inventory: NetworkInventory,
    engine_profile: EngineCapabilityProfile,
    unqualified_engine_profile: EngineCapabilityProfile,
    planning: HostInspectionPlanningAuthority,
}

impl HostAssemblyFixture {
    fn new() -> Self {
        let base_desired_state = PACKAGED_DESIRED_STATE
            .replacen("/data/adb/flux/bin/sing-box", "/tmp/flux-test-sing-box", 1)
            .replacen("startup_timeout_ms = 5000", "startup_timeout_ms = 1000", 1)
            .replacen("stop_timeout_ms = 5000", "stop_timeout_ms = 1000", 1);
        let base_config = FluxConfig::parse(&base_desired_state).expect("fixture Desired State");
        let canonical = compile_for_families(
            PACKAGED_ENGINE_TEMPLATE,
            PORT,
            base_config.capture().scope().families(),
        )
        .expect("canonical engine config");
        let mut engine = EngineSpecFixture::new_executable(
            canonical.bytes(),
            PROFILE_SCRIPT,
            listener_readiness(),
        );
        let binary = engine
            .spec
            .process()
            .binary
            .to_str()
            .expect("UTF-8 fixture path");
        let base_desired_state = base_desired_state.replacen("/tmp/flux-test-sing-box", binary, 1);
        let desired_state = compile_fixture_desired_state(&base_desired_state);
        let probe_binding =
            bind_engine_config_to_spec(desired_state.engine_config().clone(), &engine.spec)
                .expect("fixture probe binding");
        let engine_profile = collect_tproxy_engine_capability_profile(&probe_binding, &engine.spec)
            .expect("fixture Engine Capability Profile");
        engine.set_privilege(SingBoxPrivilege::transparent_proxy(
            desired_state.desired_state().engine().credentials(),
        ));
        let binding =
            bind_engine_config_to_spec(desired_state.engine_config().clone(), &engine.spec)
                .expect("fixture production binding");
        let unqualified_engine_profile =
            rebind_engine_capability_profile_fixture(engine_profile, &binding);
        let engine_profile =
            declare_supervised_delivery_report_profile_fixture(unqualified_engine_profile.clone());
        let capability_profile = CapabilityProfileFixture::device_qualified();
        let mut tracker = NetworkInventoryTracker::new();
        let inventory = empty_inventory(&mut tracker).clone();
        let planning = HostInspectionPlanningAuthority::new(
            &capability_profile,
            qualified_xtables_kernel_config(),
            qualified_xtables_capture_path_evidence(),
            &inventory,
            test_network_namespace(),
            test_mark(),
            Some(test_routing()),
        );
        Self {
            desired_state,
            base_desired_state,
            engine,
            capability_profile,
            inventory,
            engine_profile,
            unqualified_engine_profile,
            planning,
        }
    }

    fn compile_desired_state(&self, source: &str) -> DesiredStateArtifacts {
        compile_fixture_desired_state(source)
    }

    fn assemble(
        &self,
        prior: Option<AdmittedGenerationIdentity>,
        desired_state: Option<DesiredStateArtifacts>,
    ) -> Result<AdmittedGeneration, GenerationAssemblyError> {
        self.assemble_with(
            prior,
            desired_state.unwrap_or_else(|| self.desired_state.clone()),
            &self.inventory,
            GenerationPlanningAuthority::host_inspection(self.planning.clone()),
        )
    }

    fn assemble_with(
        &self,
        prior: Option<AdmittedGenerationIdentity>,
        desired_state: DesiredStateArtifacts,
        inventory: &NetworkInventory,
        planning: GenerationPlanningAuthority,
    ) -> Result<AdmittedGeneration, GenerationAssemblyError> {
        self.assemble_with_profile(
            prior,
            desired_state,
            inventory,
            self.engine_profile.clone(),
            planning,
        )
    }

    fn assemble_with_engine_profile(
        &self,
        desired_state: DesiredStateArtifacts,
        engine_profile: EngineCapabilityProfile,
    ) -> Result<AdmittedGeneration, GenerationAssemblyError> {
        self.assemble_with_profile(
            None,
            desired_state,
            &self.inventory,
            engine_profile,
            GenerationPlanningAuthority::host_inspection(self.planning.clone()),
        )
    }

    fn assemble_with_profile(
        &self,
        prior: Option<AdmittedGenerationIdentity>,
        desired_state: DesiredStateArtifacts,
        inventory: &NetworkInventory,
        engine_profile: EngineCapabilityProfile,
        planning: GenerationPlanningAuthority,
    ) -> Result<AdmittedGeneration, GenerationAssemblyError> {
        let request = GenerationAssemblyRequest::new(
            desired_state,
            self.engine.spec.clone(),
            self.capability_profile.clone(),
            inventory,
            engine_profile,
            planning,
        );
        let request = match prior {
            Some(prior) => request.with_prior_owned(prior),
            None => request,
        };
        GenerationAssembler.assemble(request)
    }
}

fn compile_fixture_desired_state(source: &str) -> DesiredStateArtifacts {
    let config = FluxConfig::parse(source).expect("fixture Desired State");
    let applications =
        CaptureApplicationPolicy::new(CaptureApplicationMode::All, []).expect("all applications");
    compile_desired_state(
        DesiredStateCompileRequest::new(config, applications, None),
        PACKAGED_ENGINE_TEMPLATE,
    )
    .expect("fixture Desired State artifacts")
}

fn test_mark() -> FwmarkCandidate {
    FwmarkCandidate::new(0x00ff_0000, 0x0080_0000, 0x0040_0000).expect("test mark")
}

fn test_network_namespace() -> NetworkNamespaceIdentity {
    NetworkNamespaceIdentity::new(10, 20).expect("test network namespace")
}

fn test_routing() -> XtablesLocalOutputRoutingSpec {
    let target = XtablesLocalOutputRoutingTarget::new(
        RulePriority::from_raw(30_999),
        RouteTableId::from_raw(20_253),
        NonZeroU32::new(1_024).expect("test route metric"),
        RouteProtocol::from_raw(4),
        RuleProtocol::from_raw(99),
    )
    .expect("test routing target");
    XtablesLocalOutputRoutingSpec::new(Some(target), None).expect("IPv4 routing")
}

fn compile(
    template: &[u8],
    port: u16,
) -> Result<super::EngineConfigArtifact, super::EngineConfigCompileError> {
    compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
        template,
        NonZeroU16::new(port).unwrap(),
        AddressHostFamilySelection::DualStack,
    ))
}

fn compile_for_families(
    template: &[u8],
    port: u16,
    families: AddressHostFamilySelection,
) -> Result<super::EngineConfigArtifact, super::EngineConfigCompileError> {
    compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
        template,
        NonZeroU16::new(port).unwrap(),
        families,
    ))
}

fn compile_with_canary_route(
    template: &[u8],
    port: u16,
    families: AddressHostFamilySelection,
    canary_route: TproxyCanaryEngineRoute,
) -> Result<super::EngineConfigArtifact, super::EngineConfigCompileError> {
    compile_tproxy_engine_config(
        TproxyEngineConfigRequest::new(template, NonZeroU16::new(port).unwrap(), families)
            .with_canary_route(canary_route),
    )
}

fn dual_stack_canary_route() -> TproxyCanaryEngineRoute {
    TproxyCanaryEngineRoute::new(
        Ipv4Addr::new(192, 0, 2, 2),
        Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        NonZeroU16::new(41001).unwrap(),
        NonZeroU16::new(41002).unwrap(),
        NonZeroU16::new(41053).unwrap(),
    )
}

fn ipv4_only_canary_route() -> TproxyCanaryEngineRoute {
    TproxyCanaryEngineRoute::new(
        Ipv4Addr::new(192, 0, 2, 2),
        None,
        NonZeroU16::new(41001).unwrap(),
        NonZeroU16::new(41002).unwrap(),
        NonZeroU16::new(41053).unwrap(),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn listener_readiness() -> SingBoxReadiness {
    SingBoxReadiness::Listener {
        port: NonZeroU16::new(PORT).unwrap(),
    }
}

fn collected_profile() -> (
    super::EngineConfigLaunchBinding,
    super::EngineCapabilityProfile,
    EngineSpecFixture,
) {
    let artifact = compile(br#"{"inbounds":[]}"#, PORT).unwrap();
    let fixture =
        EngineSpecFixture::new_executable(artifact.bytes(), PROFILE_SCRIPT, listener_readiness());
    let binding = bind_engine_config_to_spec(artifact, &fixture.spec).unwrap();
    let profile = collect_tproxy_engine_capability_profile(&binding, &fixture.spec).unwrap();
    (binding, profile, fixture)
}

fn empty_inventory(tracker: &mut NetworkInventoryTracker) -> &flux_core::NetworkInventory {
    tracker
        .publish_complete(
            Vec::<InterfaceLinkRecord>::new(),
            Vec::<InterfaceAddressRecord>::new(),
        )
        .expect("publish complete empty inventory")
}

const PROFILE_SCRIPT: &[u8] = br#"#!/bin/sh
case "$1" in
    version)
        printf '%s\n\n%s\n' 'sing-box version 1.13.14-rc.1+flux.2' 'Environment: go1.24.5 linux/amd64'
        printf '%s\n' 'Tags: with_quic,with_wireguard' >&2
        ;;
    check)
        exit 0
        ;;
    *)
        exit 64
        ;;
esac
"#;

const PROFILE_CHECK_FAILURE_SCRIPT: &[u8] = br#"#!/bin/sh
case "$1" in
    version)
        printf '%s\n' 'sing-box version 1.13.14'
        ;;
    check)
        printf '%s\n' 'configuration rejected' >&2
        exit 42
        ;;
    *)
        exit 64
        ;;
esac
"#;

const PROFILE_ALTERNATE_BINARY_SCRIPT: &[u8] = br#"#!/bin/sh
case "$1" in
    version)
        printf '%s\n' 'sing-box version 1.13.15'
        ;;
    check)
        exit 0
        ;;
    *)
        exit 64
        ;;
esac
"#;

struct EngineSpecFixture {
    spec: EngineSpec,
    _directory: tempfile::TempDir,
}

impl EngineSpecFixture {
    fn new(config: &[u8], binary: &[u8], readiness: SingBoxReadiness) -> Self {
        Self::build(config, binary, SingBoxPrivilege::Inherit, readiness)
    }

    fn new_with_privilege(
        config: &[u8],
        binary: &[u8],
        privilege: SingBoxPrivilege,
        readiness: SingBoxReadiness,
    ) -> Self {
        Self::build(config, binary, privilege, readiness)
    }

    fn new_executable(config: &[u8], binary: &[u8], readiness: SingBoxReadiness) -> Self {
        let fixture = Self::new(config, binary, readiness);
        let path = &fixture.spec.process().binary;
        let mut permissions = fs::metadata(path).expect("read fixture mode").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("make engine fixture executable");
        fixture
    }

    fn set_privilege(&mut self, privilege: SingBoxPrivilege) {
        let mut process = self.spec.process().clone();
        process.privilege = privilege;
        self.spec =
            EngineSpec::new(process, self.spec.restart_policy()).expect("rebind fixture privilege");
    }

    fn build(
        config: &[u8],
        binary: &[u8],
        privilege: SingBoxPrivilege,
        readiness: SingBoxReadiness,
    ) -> Self {
        let directory = tempfile::tempdir().expect("create engine config binding fixture");
        let binary_path = directory.path().join("sing-box");
        let config_path = directory.path().join("config.json");
        fs::write(&binary_path, binary).expect("write engine binary fixture");
        fs::write(&config_path, config).expect("write engine config fixture");
        let restart = RestartPolicy::new(
            3,
            Duration::from_secs(60),
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::from_secs(10),
        )
        .expect("valid restart policy");
        let spec = EngineSpec::new(
            SingBoxLaunchSpec {
                binary: binary_path,
                config: config_path,
                working_directory: directory.path().to_path_buf(),
                log: directory.path().join("sing-box.log"),
                privilege,
                readiness,
                startup_timeout: Duration::from_secs(1),
                stop_timeout: Duration::from_secs(1),
            },
            restart,
        )
        .expect("inspect engine config binding fixture");
        Self {
            spec,
            _directory: directory,
        }
    }
}

fn engine_credentials(uid: u32, gid: u32) -> EngineCredentials {
    EngineCredentials::new(
        CaptureUserId::new(uid).expect("valid fixture UID"),
        CaptureGroupId::new(gid).expect("valid fixture GID"),
    )
}
