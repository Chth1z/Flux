use std::error::Error as _;
use std::fs;
use std::num::{NonZeroU16, NonZeroU32};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use flux_core::{
    CapabilityProfile, CaptureApplicationMode, CaptureApplicationPolicy, CaptureDecisionStage,
    CaptureInterfaceDirection, CapturePredicate, CaptureTrafficDomain, CaptureUserId, FluxConfig,
    FwmarkCandidate, InterfaceAddressRecord, InterfaceLinkRecord, KernelSupport,
    NetworkAddressFamily, NetworkInventory, NetworkInventoryTracker, NetworkNamespaceIdentity,
    Observation, ObservationKind, RouteProtocol, RouteTableId, RulePriority, RuleProtocol,
    SelinuxMode,
};
use flux_platform::internal::SingBoxProcessError;
use flux_platform::{
    SingBoxLaunchSpec, SingBoxLauncher, SingBoxReadiness, XtablesLocalOutputRoutingSpec,
    XtablesLocalOutputRoutingTarget,
};
use flux_testkit::CapabilityProfileFixture;

use super::{
    ADMITTED_GENERATION_SCHEMA_VERSION, AdmittedGeneration, AdmittedGenerationIdentity,
    BRIDGE_ENVIRONMENT_SCHEMA_VERSION, BridgeEnvironmentCompileErrorKind,
    CanonicalEngineConfigPreparationErrorKind, DesiredStateArtifacts, DesiredStateCompileErrorKind,
    DesiredStateCompileRequest, ENGINE_CAPABILITY_PROFILE_SCHEMA_VERSION,
    ENGINE_CONFIG_LAUNCH_BINDING_SCHEMA_VERSION, EngineCapabilityProfile,
    EngineCapabilityProfileErrorKind, EngineConfigBindingErrorKind, EngineConfigCompileErrorKind,
    EngineVersionOutputErrorKind, GENERATION_ENGINE_CONFIG_SCHEMA_VERSION, GenerationAdmissionKind,
    GenerationAssembler, GenerationAssemblyDigest, GenerationAssemblyError,
    GenerationAssemblyRequest, GenerationPlanningAuthority, GenerationPlanningErrorKind,
    HostInspectionPlanningAuthority, MAX_GENERATION_ENGINE_CONFIG_INBOUNDS,
    MAX_PREPARED_GENERATION_RECORD_BYTES, PREPARED_GENERATION_RECORD_SCHEMA_VERSION,
    PreparedGenerationRecord, PreparedGenerationRecordError, PreparedGenerationRecordStore,
    TPROXY_GENERATION_CANDIDATE_SCHEMA_VERSION, TproxyEngineConfigRequest,
    TproxyGenerationCandidateErrorKind, bind_engine_config_to_spec,
    collect_tproxy_engine_capability_profile, compile_bridge_environment, compile_desired_state,
    compile_tproxy_engine_config, compile_tproxy_generation_candidate,
    parse_sing_box_version_output, publish_bridge_preparation, publish_canonical_engine_config,
    publish_validated_subscription_bridge_preparation, reconstruct_canonical_tproxy_engine_config,
};
use crate::engine_supervisor::EngineCapabilityProbeError;
use crate::{EngineSpec, MAX_ENGINE_CONFIG_BYTES, RestartPolicy};

const PORT: u16 = 1536;
const PACKAGED_DESIRED_STATE: &str = include_str!("../../../../conf/flux.toml");
const PACKAGED_ENGINE_TEMPLATE: &[u8] = include_bytes!("../../../../conf/template.json");

#[test]
fn bridge_environment_maps_the_packaged_desired_state_without_shell_policy_inputs() {
    let config = FluxConfig::parse(PACKAGED_DESIRED_STATE).expect("packaged Desired State");
    let engine = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
        PACKAGED_ENGINE_TEMPLATE,
        config.listener().port(),
    ))
    .expect("packaged engine artifact");

    let first = compile_bridge_environment(&config, &engine).expect("packaged bridge environment");
    let second =
        compile_bridge_environment(&config, &engine).expect("deterministic bridge environment");
    let document = std::str::from_utf8(first.bytes()).expect("UTF-8 bridge environment");

    assert_eq!(first.schema_version(), BRIDGE_ENVIRONMENT_SCHEMA_VERSION);
    assert_eq!(first, second);
    assert!(document.starts_with("# FLUX_DESIRED_STATE_ENV_V1\n"));
    for expected in [
        "ENGINE_BINARY='/data/adb/flux/bin/sing-box'",
        "ENGINE_STARTUP_TIMEOUT_MS='5000'",
        "ENGINE_STOP_TIMEOUT_MS='5000'",
        "CORE_USER='0'",
        "CORE_GROUP='0'",
        "PROXY_MODE='tproxy'",
        "PROXY_PORT='1536'",
        "PROXY_IPV6='0'",
        "APP_PROXY_MODE='0'",
        "MOBILE_INTERFACE='rndis+'",
        "WIFI_INTERFACE='wlan0'",
        "HOTSPOT_INTERFACE='wlan2'",
        "USB_INTERFACE='rmnet_data+'",
        "FAKEIP_V4_RANGE='198.18.0.0/15'",
        "FAKEIP_V6_RANGE='fc00::/18'",
        "RULE_BACKEND='iptables_restore'",
        "BYPASS_SET_BACKEND='zone'",
    ] {
        assert!(
            document.lines().any(|line| line == expected),
            "missing {expected}"
        );
    }
    assert!(!document.contains("settings.ini"));
    assert!(!document.contains("JQ"));
    assert!(!document.contains("KFEAT_"));
}

#[test]
fn bridge_environment_maps_typed_app_user_interface_family_and_timeout_intent() {
    let input = PACKAGED_DESIRED_STATE
        .replacen("startup_timeout_ms = 5000", "startup_timeout_ms = 5500", 1)
        .replacen("stop_timeout_ms = 5000", "stop_timeout_ms = 6200", 1)
        .replacen("ipv6 = false", "ipv6 = true", 1)
        .replacen("mode = \"all\"", "mode = \"allowlist\"", 1)
        .replacen("android_users = \"owner\"", "android_users = \"list\"", 1)
        .replacen("user_ids = []", "user_ids = [10, 2]", 1)
        .replacen(
            "packages = []",
            "packages = [\"com.example.zeta\", \"com.example.alpha\"]",
            1,
        )
        .replacen(
            "forwarded_proxy = [\"rmnet_data*\", \"wlan0\", \"wlan2\", \"rndis*\"]",
            "forwarded_proxy = [\"rmnet_data*\", \"wlan0\"]",
            1,
        )
        .replacen("local_bypass = []", "local_bypass = [\"wlan1\"]", 1)
        .replacen("excluded = []", "excluded = [\"tun*\"]", 1);
    let config = FluxConfig::parse(&input).expect("custom bridge Desired State");
    let engine = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
        PACKAGED_ENGINE_TEMPLATE,
        config.listener().port(),
    ))
    .expect("custom engine artifact");

    let artifact = compile_bridge_environment(&config, &engine).expect("custom bridge environment");
    let document = std::str::from_utf8(artifact.bytes()).unwrap();

    for expected in [
        "ENGINE_STARTUP_TIMEOUT_MS='5500'",
        "ENGINE_STOP_TIMEOUT_MS='6200'",
        "CORE_TIMEOUT='7'",
        "PROXY_IPV6='1'",
        "APP_PROXY_MODE='2'",
        "APP_LIST='com.example.alpha com.example.zeta'",
        "APP_USER_SCOPE='list'",
        "APP_USER_LIST='2 10'",
        "MOBILE_INTERFACE='wlan0'",
        "PROXY_MOBILE='1'",
        "WIFI_INTERFACE='rmnet_data+'",
        "PROXY_WIFI='1'",
        "HOTSPOT_INTERFACE='wlan1'",
        "PROXY_HOTSPOT='0'",
        "USB_INTERFACE=''",
        "EXCLUDE_INTERFACES='tun+'",
    ] {
        assert!(
            document.lines().any(|line| line == expected),
            "missing {expected}"
        );
    }
}

#[test]
fn bridge_environment_rejects_desired_state_shapes_the_fenced_renderer_cannot_express() {
    let cases = [
        (
            PACKAGED_DESIRED_STATE.replacen("local_output = true", "local_output = false", 1),
            BridgeEnvironmentCompileErrorKind::UnsupportedTrafficDomains,
        ),
        (
            PACKAGED_DESIRED_STATE
                .replacen("ipv4 = true", "ipv4 = false", 1)
                .replacen("ipv6 = false", "ipv6 = true", 1),
            BridgeEnvironmentCompileErrorKind::UnsupportedAddressFamilies,
        ),
        (
            PACKAGED_DESIRED_STATE.replacen("tcp = true", "tcp = false", 1),
            BridgeEnvironmentCompileErrorKind::UnsupportedProtocols,
        ),
        (
            PACKAGED_DESIRED_STATE.replacen("cidrs = []", "cidrs = [\"203.0.113.0/24\"]", 1),
            BridgeEnvironmentCompileErrorKind::ConfiguredBypassUnsupported,
        ),
        (
            PACKAGED_DESIRED_STATE.replacen("enabled = false", "enabled = true", 1),
            BridgeEnvironmentCompileErrorKind::SubscriptionUnsupported,
        ),
        (
            PACKAGED_DESIRED_STATE.replacen(
                "respect_android_vpn = false",
                "respect_android_vpn = true",
                1,
            ),
            BridgeEnvironmentCompileErrorKind::AndroidVpnUnsupported,
        ),
        (
            PACKAGED_DESIRED_STATE.replacen(
                "require_functional_canary = false",
                "require_functional_canary = true",
                1,
            ),
            BridgeEnvironmentCompileErrorKind::FunctionalCanaryUnsupported,
        ),
        (
            PACKAGED_DESIRED_STATE.replacen("local_bypass = []", "local_bypass = [\"wlan1\"]", 1),
            BridgeEnvironmentCompileErrorKind::TooManyInterfaceRoles {
                actual: 5,
                maximum: 4,
            },
        ),
    ];

    for (input, expected) in cases {
        let config = FluxConfig::parse(&input).expect("schema-valid unsupported bridge shape");
        let engine = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
            PACKAGED_ENGINE_TEMPLATE,
            config.listener().port(),
        ))
        .unwrap();
        let error = compile_bridge_environment(&config, &engine)
            .expect_err("non-representable bridge shape must fail closed");
        assert_eq!(error.kind(), expected);
    }
}

#[test]
fn bridge_environment_requires_one_canonical_dual_family_fakeip_server() {
    let config = FluxConfig::parse(PACKAGED_DESIRED_STATE).expect("packaged Desired State");
    let cases: &[(&[u8], BridgeEnvironmentCompileErrorKind)] = &[
        (
            br#"{"dns":{"servers":[]},"inbounds":[]}"#,
            BridgeEnvironmentCompileErrorKind::MissingFakeIpServer,
        ),
        (
            br#"{"dns":{"servers":[{"type":"fakeip","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"},{"type":"fakeip","inet4_range":"198.19.0.0/16","inet6_range":"fd00::/8"}]},"inbounds":[]}"#,
            BridgeEnvironmentCompileErrorKind::MultipleFakeIpServers,
        ),
        (
            br#"{"dns":{"servers":[{"type":"fakeip","inet4_range":"198.18.1.1/15","inet6_range":"fc00::/18"}]},"inbounds":[]}"#,
            BridgeEnvironmentCompileErrorKind::InvalidFakeIpRange {
                family: NetworkAddressFamily::Ipv4,
            },
        ),
    ];

    for (template, expected) in cases {
        let engine = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
            template,
            config.listener().port(),
        ))
        .unwrap();
        let error = compile_bridge_environment(&config, &engine)
            .expect_err("invalid FakeIP bridge shape must fail closed");
        assert_eq!(error.kind(), *expected);
    }
}

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
    assert_eq!(artifacts.capture().artifact().programs().len(), 2);
}

#[test]
fn desired_state_maps_scope_interfaces_and_resolved_applications() {
    let input = PACKAGED_DESIRED_STATE
        .replacen("mode = \"all\"", "mode = \"allowlist\"", 1)
        .replacen("packages = []", "packages = [\"com.example.client\"]", 1)
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
    let programs = artifacts.capture().artifact().programs();

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
fn canonical_engine_publication_atomically_replaces_the_shared_config() {
    let directory = tempfile::tempdir().expect("canonical config fixture");
    let template_path = directory.path().join("template.json");
    let desired_state_path = directory.path().join("flux.toml");
    let output_path = directory.path().join("config.json");
    fs::write(&template_path, br#"{"inbounds":[],"log":{"level":"warn"}}"#)
        .expect("write template");
    fs::write(
        &desired_state_path,
        desired_state_with_template(&template_path),
    )
    .expect("write Desired State");
    fs::write(&output_path, b"stale shell-owned config\n").expect("write stale output");

    let publication = publish_canonical_engine_config(&desired_state_path, &output_path)
        .expect("publish canonical config");
    let (desired_state, artifact) = publication.into_parts();

    assert_eq!(desired_state.listener().port().get(), PORT);
    assert_eq!(fs::read(&output_path).unwrap(), artifact.bytes());
    assert_eq!(
        fs::metadata(&output_path)
            .expect("published metadata")
            .permissions()
            .mode()
            & 0o777,
        0o444
    );
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".fluxd-")
    }));
}

#[test]
fn bridge_preparation_publishes_read_only_engine_and_environment_artifacts() {
    let directory = tempfile::tempdir().expect("bridge preparation fixture");
    let template_path = directory.path().join("template.json");
    let desired_state_path = directory.path().join("flux.toml");
    let engine_path = directory.path().join("config.json");
    let environment_path = directory.path().join("desired-state.env");
    fs::write(&template_path, PACKAGED_ENGINE_TEMPLATE).expect("write template");
    fs::write(
        &desired_state_path,
        desired_state_with_template(&template_path),
    )
    .expect("write Desired State");

    let publication =
        publish_bridge_preparation(&desired_state_path, &engine_path, &environment_path)
            .expect("publish bridge preparation");
    let (_desired_state, engine, environment) = publication.into_parts();

    assert_eq!(fs::read(&engine_path).unwrap(), engine.bytes());
    assert_eq!(fs::read(&environment_path).unwrap(), environment.bytes());
    for path in [&engine_path, &environment_path] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o444
        );
    }
}

#[test]
fn validated_subscription_bridge_preparation_requires_exact_unchanged_desired_state() {
    let directory = tempfile::tempdir().expect("subscription bridge preparation fixture");
    let template_path = directory.path().join("template.json");
    let desired_state_path = directory.path().join("flux.toml");
    let engine_path = directory.path().join("config.json");
    let environment_path = directory.path().join("desired-state.env");
    fs::write(&template_path, PACKAGED_ENGINE_TEMPLATE).expect("write template");
    let desired_state = desired_state_with_template(&template_path).replacen(
        "enabled = false",
        "enabled = true",
        1,
    );
    fs::write(&desired_state_path, &desired_state).expect("write enabled Desired State");
    let expected = FluxConfig::parse(&desired_state).expect("enabled Desired State");
    let artifact = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
        PACKAGED_ENGINE_TEMPLATE,
        expected.listener().port(),
    ))
    .expect("validated subscription engine artifact");

    let publication = publish_validated_subscription_bridge_preparation(
        &desired_state_path,
        &expected,
        artifact.clone(),
        &engine_path,
        &environment_path,
    )
    .expect("validated subscription bridge preparation");
    let (published_state, published_engine, _) = publication.into_parts();

    assert_eq!(published_state, expected);
    assert_eq!(fs::read(&engine_path).unwrap(), published_engine.bytes());
    let prior_engine = fs::read(&engine_path).unwrap();
    let prior_environment = fs::read(&environment_path).unwrap();
    fs::write(
        &desired_state_path,
        desired_state.replacen(
            "update_interval_secs = 86400",
            "update_interval_secs = 3600",
            1,
        ),
    )
    .expect("change Desired State after validation");

    let error = match publish_validated_subscription_bridge_preparation(
        &desired_state_path,
        &expected,
        artifact,
        &engine_path,
        &environment_path,
    ) {
        Ok(_) => panic!("changed Desired State must fail closed"),
        Err(error) => error,
    };

    assert_eq!(
        error.kind(),
        CanonicalEngineConfigPreparationErrorKind::DesiredStateChanged
    );
    assert_eq!(fs::read(&engine_path).unwrap(), prior_engine);
    assert_eq!(fs::read(&environment_path).unwrap(), prior_environment);
}

#[cfg(unix)]
#[test]
fn canonical_engine_publication_rejects_a_symbolic_link_template() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("canonical config fixture");
    let target = directory.path().join("template-target.json");
    let template_path = directory.path().join("template.json");
    let desired_state_path = directory.path().join("flux.toml");
    let output_path = directory.path().join("config.json");
    fs::write(&target, br#"{"inbounds":[]}"#).expect("write template target");
    symlink(&target, &template_path).expect("link template");
    fs::write(
        &desired_state_path,
        desired_state_with_template(&template_path),
    )
    .expect("write Desired State");

    let error = match publish_canonical_engine_config(&desired_state_path, &output_path) {
        Ok(_) => panic!("template symlink must fail closed"),
        Err(error) => error,
    };

    assert_eq!(
        error.kind(),
        CanonicalEngineConfigPreparationErrorKind::Template
    );
    assert!(!output_path.exists());
}

#[test]
fn compiles_one_canonical_tcp_udp_tproxy_inbound() {
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
            "{\"listen\":\"::\",\"listen_port\":1536,\"sniff\":true,",
            "\"tag\":\"existing-tproxy\",\"type\":\"tproxy\"}",
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
    assert_eq!(artifact.usage().output_inbounds(), 2);
    assert_eq!(artifact.usage().input_bytes(), template.len());
    assert_eq!(artifact.usage().output_bytes(), artifact.bytes().len());
    assert_eq!(
        hex(artifact.content_sha256()),
        "d06fd8595a4a85897ad2c5fe68a4ab42ce126afad4570546142c3bc7bf489470"
    );
    assert_eq!(
        artifact.digest().to_string(),
        "fa4d5069c6bb6d889bbf1edb4ea0459f0697c7a6b82f17fda83c87e9774d033f"
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
            "{\"inbounds\":[{\"listen\":\"::\",\"listen_port\":1536,",
            "\"tag\":\"tproxy-in\",\"type\":\"tproxy\"}],",
            "\"log\":{\"level\":\"info\"}}\n"
        )
        .as_bytes()
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
    assert_eq!(binding.launcher_digest(), None);
    assert_eq!(binding.digest().as_bytes().len(), 32);
    assert_eq!(
        binding.digest().to_string(),
        "fdacd3c8d087371e5c7f51c879298a3aa42e4369c559dde4fe9337ba97630f5f"
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
fn binding_identity_retains_binary_and_removed_template_provenance() {
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
    let launcher_engine = EngineSpecFixture::new_with_busybox(
        empty.bytes(),
        b"sing-box-v1",
        b"busybox-v1",
        SingBoxReadiness::Listener {
            port: NonZeroU16::new(PORT).unwrap(),
        },
    );

    let first = bind_engine_config_to_spec(empty.clone(), &first_engine.spec).unwrap();
    let binary_drift = bind_engine_config_to_spec(empty.clone(), &second_engine.spec).unwrap();
    let launcher_drift = bind_engine_config_to_spec(empty, &launcher_engine.spec).unwrap();
    let source_drift = bind_engine_config_to_spec(old_tun, &first_engine.spec).unwrap();

    assert_ne!(first.digest(), binary_drift.digest());
    assert_ne!(first.digest(), launcher_drift.digest());
    assert_eq!(
        launcher_drift.launcher_digest(),
        launcher_engine.spec.launcher_digest()
    );
    assert_ne!(first.digest(), source_drift.digest());
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
        "d129642ba9e1ac385d42a36a7d125b240514d477268a63fdcda448b42edc02ec"
    );
    assert_eq!(profile.revision().as_bytes().len(), 32);
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
        qualified.legacy_bridge().clone(),
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
        admitted.capture().artifact().digest()
    );
    assert!(admitted.xtables().ipv4().is_some());
    assert!(admitted.xtables().ipv6().is_none());
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
        "respect_android_vpn = false",
        "respect_android_vpn = true",
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
        fixture.capability_profile.legacy_bridge().clone(),
    );
    let planning = HostInspectionPlanningAuthority::new(
        &changed_profile,
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
    let reconstructed = reconstruct_canonical_tproxy_engine_config(artifact.bytes(), port)
        .expect("exact canonical bytes reconstruct");
    assert_eq!(reconstructed.bytes(), artifact.bytes());
    assert_eq!(reconstructed.content_sha256(), artifact.content_sha256());
    assert_eq!(reconstructed.listener_port(), artifact.listener_port());
    assert_ne!(reconstructed.template_digest(), artifact.template_digest());

    let error = reconstruct_canonical_tproxy_engine_config(br#"{"inbounds":[]}"#, port)
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
    planning: HostInspectionPlanningAuthority,
}

impl HostAssemblyFixture {
    fn new() -> Self {
        let canonical = compile(PACKAGED_ENGINE_TEMPLATE, PORT).expect("canonical engine config");
        let engine = EngineSpecFixture::new_executable(
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
        let base_desired_state = PACKAGED_DESIRED_STATE
            .replacen("/data/adb/flux/bin/sing-box", binary, 1)
            .replacen("startup_timeout_ms = 5000", "startup_timeout_ms = 1000", 1)
            .replacen("stop_timeout_ms = 5000", "stop_timeout_ms = 1000", 1);
        let desired_state = compile_fixture_desired_state(&base_desired_state);
        let binding =
            bind_engine_config_to_spec(desired_state.engine_config().clone(), &engine.spec)
                .expect("fixture engine binding");
        let engine_profile = collect_tproxy_engine_capability_profile(&binding, &engine.spec)
            .expect("fixture Engine Capability Profile");
        let capability_profile = CapabilityProfileFixture::device_qualified();
        let mut tracker = NetworkInventoryTracker::new();
        let inventory = empty_inventory(&mut tracker).clone();
        let planning = HostInspectionPlanningAuthority::new(
            &capability_profile,
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
        let request = GenerationAssemblyRequest::new(
            desired_state,
            self.engine.spec.clone(),
            self.capability_profile.clone(),
            inventory,
            self.engine_profile.clone(),
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
    ))
}

fn desired_state_with_template(template_path: &std::path::Path) -> String {
    PACKAGED_DESIRED_STATE.replacen(
        "/data/adb/flux/conf/template.json",
        template_path.to_str().expect("UTF-8 test path"),
        1,
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
        Self::build(config, binary, None, readiness)
    }

    fn new_with_busybox(
        config: &[u8],
        binary: &[u8],
        busybox: &[u8],
        readiness: SingBoxReadiness,
    ) -> Self {
        Self::build(config, binary, Some(busybox), readiness)
    }

    fn new_executable(config: &[u8], binary: &[u8], readiness: SingBoxReadiness) -> Self {
        let fixture = Self::new(config, binary, readiness);
        let path = &fixture.spec.process().binary;
        let mut permissions = fs::metadata(path).expect("read fixture mode").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("make engine fixture executable");
        fixture
    }

    fn build(
        config: &[u8],
        binary: &[u8],
        busybox: Option<&[u8]>,
        readiness: SingBoxReadiness,
    ) -> Self {
        let directory = tempfile::tempdir().expect("create engine config binding fixture");
        let binary_path = directory.path().join("sing-box");
        let config_path = directory.path().join("config.json");
        fs::write(&binary_path, binary).expect("write engine binary fixture");
        fs::write(&config_path, config).expect("write engine config fixture");
        let launcher = match busybox {
            Some(bytes) => {
                let path = directory.path().join("busybox");
                fs::write(&path, bytes).expect("write engine launcher fixture");
                SingBoxLauncher::BusyBoxSetuidgid {
                    busybox: path,
                    identity: "1000:1000".into(),
                }
            }
            None => SingBoxLauncher::Direct,
        };
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
                launcher,
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
