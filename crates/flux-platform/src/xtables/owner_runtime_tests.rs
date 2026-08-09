use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroI32, NonZeroU16, NonZeroU32};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use flux_core::{
    AddressHostFamilySelection, CaptureApplicationMode, CaptureApplicationPolicy,
    CaptureBypassPolicy, CaptureGroupId, CaptureInterfacePolicy, CaptureInterfaceSelector,
    CaptureIpPrefix, CaptureProgramRequest, CaptureProtocolSet, CaptureTrafficScope, CaptureUserId,
    EngineCredentials, FwmarkCandidate, GenerationId, InterfaceIndex, InterfaceName, RouteProtocol,
    RouteTableId, RulePriority, RuleProtocol, compile_capture_program,
};
use tempfile::TempDir;

use crate::netlink::policy_routing::{
    ManagedFwmarkRuleIdentity, ManagedLocalRouteIdentity, PolicyRoutingMutationKind,
};
use crate::xtables::native::{XtablesRestoreProcessConfig, XtablesToolSetProcessAdapter};
use crate::xtables::owner_durable::{
    DurableEvent, NativeXtablesAttemptPayload, NativeXtablesAttemptPhase,
    NativeXtablesAttemptRecord,
};
use crate::xtables::save::project_xtables_save;
use crate::xtables::{
    NativeCaptureCanaryRouteObservation, NativeCaptureCanaryRouteRejection,
    XtablesCaptureLoweringRequest, XtablesCaptureNamespace, XtablesLocalOutputRoutingSpec,
    XtablesLocalOutputRoutingTarget, XtablesRestoreAction, XtablesRestoreCommandKind,
    XtablesRestoreEntry, XtablesTproxyTarget, lower_xtables_capture,
};

use super::*;

const TOOL_DIGEST: [u8; 32] = [0x44; 32];
const MARK_MASK: u32 = 0x0060_0000;
const PROXY_MARK: u32 = 0x0020_0000;
const BYPASS_MARK: u32 = 0x0040_0000;

#[test]
fn zero_to_active_and_idempotent_active_use_one_exact_transaction() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();

    let report = owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .expect("activate zero-state target");
    assert_eq!(
        report.state(),
        NativeXtablesConvergedState::Active(target.identity())
    );
    assert!(report.changed());
    assert_eq!(
        owner.adapter.operations,
        [
            "restore:ipv4:prepare:7",
            "policy:ipv4:AddRoute",
            "policy:ipv4:AddRule",
            "restore:ipv4:install:7",
        ]
    );
    assert!(owner.target_is_exact_active(&target).unwrap());
    assert!(owner.durable.load_lease().unwrap().is_some());
    assert_eq!(
        owner.durable.load_journal().unwrap().unwrap().phase(),
        NativeXtablesJournalPhase::Active
    );

    owner.adapter.operations.clear();
    let report = owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .expect("idempotent active convergence");
    assert_eq!(
        report.state(),
        NativeXtablesConvergedState::Active(target.identity())
    );
    assert!(!report.changed());
    assert!(owner.adapter.operations.is_empty());
}

#[test]
fn dual_stack_canary_selector_population_and_retirement_are_exact() {
    const EXPECTED_IPV4: &str = concat!(
        "*mangle\n",
        "-F FLX4C0000000007\n",
        "-A FLX4C0000000007 -d 198.18.0.2/32 -p tcp -m owner --uid-owner 2000 -m tcp --dport 10080 -m mark --mark 0x0/0x600000 -j MARK --set-xmark 0x200000/0x600000\n",
        "-A FLX4C0000000007 -d 198.18.0.2/32 -p tcp -m owner --uid-owner 2000 -m tcp --dport 10080 -m mark --mark 0x200000/0x600000 -j FLX4A0000000007\n",
        "-A FLX4C0000000007 -d 198.18.0.2/32 -p tcp -m owner --uid-owner 2000 -m tcp --dport 10080 -m mark --mark 0x200000/0x600000 -j ACCEPT\n",
        "-A FLX4C0000000007 -d 198.18.0.2/32 -p tcp -m owner --uid-owner 2000 -m tcp --dport 10053 -m mark --mark 0x0/0x600000 -j MARK --set-xmark 0x200000/0x600000\n",
        "-A FLX4C0000000007 -d 198.18.0.2/32 -p tcp -m owner --uid-owner 2000 -m tcp --dport 10053 -m mark --mark 0x200000/0x600000 -j FLX4A0000000007\n",
        "-A FLX4C0000000007 -d 198.18.0.2/32 -p tcp -m owner --uid-owner 2000 -m tcp --dport 10053 -m mark --mark 0x200000/0x600000 -j ACCEPT\n",
        "-A FLX4C0000000007 -d 198.18.0.2/32 -p udp -m owner --uid-owner 2000 -m udp --dport 10081 -m mark --mark 0x0/0x600000 -j MARK --set-xmark 0x200000/0x600000\n",
        "-A FLX4C0000000007 -d 198.18.0.2/32 -p udp -m owner --uid-owner 2000 -m udp --dport 10081 -m mark --mark 0x200000/0x600000 -j FLX4A0000000007\n",
        "-A FLX4C0000000007 -d 198.18.0.2/32 -p udp -m owner --uid-owner 2000 -m udp --dport 10081 -m mark --mark 0x200000/0x600000 -j ACCEPT\n",
        "-A FLX4C0000000007 -d 198.18.0.2/32 -p udp -m owner --uid-owner 2000 -m udp --dport 10053 -m mark --mark 0x0/0x600000 -j MARK --set-xmark 0x200000/0x600000\n",
        "-A FLX4C0000000007 -d 198.18.0.2/32 -p udp -m owner --uid-owner 2000 -m udp --dport 10053 -m mark --mark 0x200000/0x600000 -j FLX4A0000000007\n",
        "-A FLX4C0000000007 -d 198.18.0.2/32 -p udp -m owner --uid-owner 2000 -m udp --dport 10053 -m mark --mark 0x200000/0x600000 -j ACCEPT\n",
        "COMMIT\n",
    );
    const EXPECTED_IPV6: &str = concat!(
        "*mangle\n",
        "-F FLX6C0000000007\n",
        "-A FLX6C0000000007 -d fd00::2/128 -p tcp -m owner --uid-owner 2000 -m tcp --dport 10080 -m mark --mark 0x0/0x600000 -j MARK --set-xmark 0x200000/0x600000\n",
        "-A FLX6C0000000007 -d fd00::2/128 -p tcp -m owner --uid-owner 2000 -m tcp --dport 10080 -m mark --mark 0x200000/0x600000 -j FLX6A0000000007\n",
        "-A FLX6C0000000007 -d fd00::2/128 -p tcp -m owner --uid-owner 2000 -m tcp --dport 10080 -m mark --mark 0x200000/0x600000 -j ACCEPT\n",
        "-A FLX6C0000000007 -d fd00::2/128 -p tcp -m owner --uid-owner 2000 -m tcp --dport 10053 -m mark --mark 0x0/0x600000 -j MARK --set-xmark 0x200000/0x600000\n",
        "-A FLX6C0000000007 -d fd00::2/128 -p tcp -m owner --uid-owner 2000 -m tcp --dport 10053 -m mark --mark 0x200000/0x600000 -j FLX6A0000000007\n",
        "-A FLX6C0000000007 -d fd00::2/128 -p tcp -m owner --uid-owner 2000 -m tcp --dport 10053 -m mark --mark 0x200000/0x600000 -j ACCEPT\n",
        "-A FLX6C0000000007 -d fd00::2/128 -p udp -m owner --uid-owner 2000 -m udp --dport 10081 -m mark --mark 0x0/0x600000 -j MARK --set-xmark 0x200000/0x600000\n",
        "-A FLX6C0000000007 -d fd00::2/128 -p udp -m owner --uid-owner 2000 -m udp --dport 10081 -m mark --mark 0x200000/0x600000 -j FLX6A0000000007\n",
        "-A FLX6C0000000007 -d fd00::2/128 -p udp -m owner --uid-owner 2000 -m udp --dport 10081 -m mark --mark 0x200000/0x600000 -j ACCEPT\n",
        "-A FLX6C0000000007 -d fd00::2/128 -p udp -m owner --uid-owner 2000 -m udp --dport 10053 -m mark --mark 0x0/0x600000 -j MARK --set-xmark 0x200000/0x600000\n",
        "-A FLX6C0000000007 -d fd00::2/128 -p udp -m owner --uid-owner 2000 -m udp --dport 10053 -m mark --mark 0x200000/0x600000 -j FLX6A0000000007\n",
        "-A FLX6C0000000007 -d fd00::2/128 -p udp -m owner --uid-owner 2000 -m udp --dport 10053 -m mark --mark 0x200000/0x600000 -j ACCEPT\n",
        "COMMIT\n",
    );
    const EXPECTED_IPV4_OBSERVATION: &str = concat!(
        "*mangle\n",
        "-F FLX4A0000000007\n",
        "-A FLX4A0000000007 -m owner --uid-owner 2000 -m mark --mark 0x200000/0x600000 -j RETURN\n",
        "-A FLX4A0000000007 -m owner --uid-owner 1000 -m mark --mark 0x200000/0x600000 -j RETURN\n",
        "-A FLX4A0000000007 -m owner --uid-owner 1000 -j RETURN\n",
        "COMMIT\n",
    );
    const EXPECTED_IPV6_OBSERVATION: &str = concat!(
        "*mangle\n",
        "-F FLX6A0000000007\n",
        "-A FLX6A0000000007 -m owner --uid-owner 2000 -m mark --mark 0x200000/0x600000 -j RETURN\n",
        "-A FLX6A0000000007 -m owner --uid-owner 1000 -m mark --mark 0x200000/0x600000 -j RETURN\n",
        "-A FLX6A0000000007 -m owner --uid-owner 1000 -j RETURN\n",
        "COMMIT\n",
    );

    let target = canary_target(7, AddressHostFamilySelection::DualStack);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    let primary = owner.durable.load_journal().unwrap().unwrap();
    let primary_bytes = std::fs::read(owner.durable.journal_path()).unwrap();
    owner.adapter.operations.clear();

    let session = owner
        .populate_canary_selector(&target, canary_attempt(true))
        .expect("populate exact dual-stack canary selector");

    assert_eq!(
        owner.adapter.operations,
        [
            "restore:ipv4:populate_canary_selector:7",
            "restore:ipv6:populate_canary_selector:7",
            "restore:ipv4:populate_canary_observation:7",
            "restore:ipv6:populate_canary_observation:7",
        ]
    );
    assert_eq!(
        owner
            .adapter
            .family_state(XtablesRestoreFamily::Ipv4)
            .canary_selector
            .as_ref()
            .unwrap()
            .render_canonical()
            .as_ref(),
        EXPECTED_IPV4.as_bytes()
    );
    assert_eq!(
        owner
            .adapter
            .family_state(XtablesRestoreFamily::Ipv6)
            .canary_selector
            .as_ref()
            .unwrap()
            .render_canonical()
            .as_ref(),
        EXPECTED_IPV6.as_bytes()
    );
    assert_eq!(
        owner
            .adapter
            .family_state(XtablesRestoreFamily::Ipv4)
            .canary_observation
            .as_ref()
            .unwrap()
            .render_canonical()
            .as_ref(),
        EXPECTED_IPV4_OBSERVATION.as_bytes()
    );
    assert_eq!(
        owner
            .adapter
            .family_state(XtablesRestoreFamily::Ipv6)
            .canary_observation
            .as_ref()
            .unwrap()
            .render_canonical()
            .as_ref(),
        EXPECTED_IPV6_OBSERVATION.as_bytes()
    );
    assert_eq!(owner.durable.load_journal().unwrap().unwrap(), primary);
    assert_eq!(
        std::fs::read(owner.durable.journal_path()).unwrap(),
        primary_bytes
    );
    assert_eq!(
        owner.durable.load_attempt().unwrap().unwrap().phase(),
        NativeXtablesAttemptPhase::Active
    );
    assert!(!owner.target_is_exact_active(&target).unwrap());

    owner.adapter.operations.clear();
    owner
        .retire_canary_selector(&target, canary_attempt(true), session)
        .expect("retire exact dual-stack canary selector");

    assert_eq!(
        owner.adapter.operations,
        [
            "restore:ipv4:retire_canary_observation:7",
            "restore:ipv6:retire_canary_observation:7",
            "restore:ipv4:retire_canary_selector:7",
            "restore:ipv6:retire_canary_selector:7",
        ]
    );
    assert!(
        owner
            .adapter
            .family_state(XtablesRestoreFamily::Ipv4)
            .canary_selector
            .is_none()
    );
    assert!(
        owner
            .adapter
            .family_state(XtablesRestoreFamily::Ipv6)
            .canary_selector
            .is_none()
    );
    assert!(owner.target_is_exact_active(&target).unwrap());
    assert!(owner.durable.load_attempt().unwrap().is_none());
    assert_eq!(owner.durable.load_journal().unwrap().unwrap(), primary);
    assert_eq!(
        std::fs::read(owner.durable.journal_path()).unwrap(),
        primary_bytes
    );
}

#[test]
fn canary_selector_family_mismatch_is_rejected_before_any_write() {
    for (families, attempt) in [
        (AddressHostFamilySelection::Ipv4, canary_attempt(true)),
        (AddressHostFamilySelection::DualStack, canary_attempt(false)),
    ] {
        let target = canary_target(7, families);
        let fixture = Fixture::new([target.clone()]);
        let mut owner = fixture.owner();
        owner
            .converge(NativeXtablesDesiredTarget::Active(target.clone()))
            .unwrap();
        owner.adapter.operations.clear();
        let write_count = owner.adapter.write_count;

        let error = owner
            .populate_canary_selector(&target, attempt)
            .expect_err("selector/target family mismatch must fail closed");

        assert!(matches!(
            error,
            NativeXtablesOwnerError::InvalidCanarySelector(
                "selector address families differ from the admitted target"
            )
        ));
        assert_eq!(owner.adapter.write_count, write_count);
        assert!(owner.adapter.operations.is_empty());
        assert!(owner.target_is_exact_active(&target).unwrap());
    }
}

#[test]
fn canary_route_lookup_requires_the_exact_active_selector_target_and_query() {
    let target = canary_target(7, AddressHostFamilySelection::DualStack);
    let substituted_target = canary_target(8, AddressHostFamilySelection::DualStack);
    let fixture = Fixture::new([target.clone(), substituted_target.clone()]);
    let mut owner = fixture.owner();
    let attempt = canary_attempt(true);
    let selector = attempt.selector();
    let ipv4_destination = SocketAddr::new(
        IpAddr::V4(selector.ipv4_peer()),
        selector.tcp_echo_port().get(),
    );
    let ipv4_query = canary_route_query(ipv4_destination);
    owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();

    let session = owner.populate_canary_selector(&target, attempt).unwrap();
    let invalid_queries = [
        NativeCaptureCanaryRouteQuery::new(
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 18, 0, 3)),
                selector.tcp_echo_port().get(),
            ),
            ipv4_query.uid(),
            ipv4_query.mark(),
            ipv4_query.deadline(),
        )
        .unwrap(),
        NativeCaptureCanaryRouteQuery::new(
            SocketAddr::new(
                IpAddr::V4(selector.ipv4_peer()),
                selector.udp_echo_port().get(),
            ),
            ipv4_query.uid(),
            ipv4_query.mark(),
            ipv4_query.deadline(),
        )
        .unwrap(),
        NativeCaptureCanaryRouteQuery::new(
            ipv4_destination,
            ipv4_query.uid(),
            BYPASS_MARK,
            ipv4_query.deadline(),
        )
        .unwrap(),
        NativeCaptureCanaryRouteQuery::new(
            ipv4_destination,
            NonZeroU32::new(ipv4_query.uid().get() + 1).unwrap(),
            ipv4_query.mark(),
            ipv4_query.deadline(),
        )
        .unwrap(),
        NativeCaptureCanaryRouteQuery::new(
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3)),
                selector.tcp_echo_port().get(),
            ),
            ipv4_query.uid(),
            ipv4_query.mark(),
            ipv4_query.deadline(),
        )
        .unwrap(),
    ];
    for query in invalid_queries {
        assert!(matches!(
            owner.observe_canary_route(&target, attempt, query, &session),
            Err(NativeXtablesOwnerError::InvalidCanarySelector(_))
        ));
    }
    assert!(owner.adapter.canary_route_queries.is_empty());

    let ipv4_observation = match owner
        .observe_canary_route(&target, attempt, ipv4_query, &session)
        .unwrap()
    {
        NativeCaptureCanaryRouteOutcome::Resolved(observation) => observation,
        NativeCaptureCanaryRouteOutcome::Rejected(_) => panic!("fake route must resolve"),
    };
    assert_eq!(ipv4_observation.query(), ipv4_query);
    assert_eq!(ipv4_observation.selected_table().get(), 20_253);
    assert!(ipv4_observation.observed_at() < ipv4_query.deadline());

    let ipv6_query = canary_route_query(SocketAddr::new(
        IpAddr::V6(selector.ipv6_peer().unwrap()),
        selector.tcp_echo_port().get(),
    ));
    assert!(matches!(
        owner.observe_canary_route(&target, attempt, ipv6_query, &session),
        Ok(NativeCaptureCanaryRouteOutcome::Resolved(observation))
            if observation.query() == ipv6_query
    ));
    assert_eq!(owner.adapter.canary_route_queries, [ipv4_query, ipv6_query]);

    for substituted_attempt in [
        NativeCaptureCanaryAttempt::new(
            selector,
            [0x12; 32],
            *attempt.selector_identity(),
            *attempt.facility_digest(),
        )
        .unwrap(),
        NativeCaptureCanaryAttempt::new(
            selector,
            *attempt.nonce(),
            [0x23; 32],
            *attempt.facility_digest(),
        )
        .unwrap(),
        NativeCaptureCanaryAttempt::new(
            selector,
            *attempt.nonce(),
            *attempt.selector_identity(),
            [0x34; 32],
        )
        .unwrap(),
    ] {
        assert!(matches!(
            owner.observe_canary_route(&target, substituted_attempt, ipv4_query, &session),
            Err(NativeXtablesOwnerError::LiveStateConflict(
                "native canary attempt session was substituted"
            ))
        ));
    }
    assert_eq!(owner.adapter.canary_route_queries, [ipv4_query, ipv6_query]);

    let error = owner
        .observe_canary_route(&substituted_target, attempt, ipv4_query, &session)
        .expect_err("a substituted admitted target must fail closed");
    assert!(matches!(
        error,
        NativeXtablesOwnerError::LiveStateConflict("native canary attempt session was substituted")
    ));
    assert_eq!(owner.adapter.canary_route_queries, [ipv4_query, ipv6_query]);

    owner
        .retire_canary_selector(&target, attempt, session)
        .unwrap();
}

#[test]
fn canary_route_lookup_rechecks_selector_policy_target_and_journal_after_observation() {
    for case in 0..5 {
        let target = canary_target(7, AddressHostFamilySelection::Ipv4);
        let substituted_target = canary_target(8, AddressHostFamilySelection::Ipv4);
        let fixture = Fixture::new([target.clone(), substituted_target.clone()]);
        let mut owner = fixture.owner();
        let attempt = canary_attempt(false);
        let selector = attempt.selector();
        owner
            .converge(NativeXtablesDesiredTarget::Active(target.clone()))
            .unwrap();
        let session = owner.populate_canary_selector(&target, attempt).unwrap();
        owner.adapter.canary_route_post_action = Some(match case {
            0 => FakeCanaryRoutePostAction::DropSelector(XtablesRestoreFamily::Ipv4),
            1 => FakeCanaryRoutePostAction::DropObservation(XtablesRestoreFamily::Ipv4),
            2 => FakeCanaryRoutePostAction::DropPolicyRules,
            3 => FakeCanaryRoutePostAction::SubstituteTarget {
                family: XtablesRestoreFamily::Ipv4,
                identity: substituted_target.identity(),
            },
            4 => FakeCanaryRoutePostAction::CorruptJournal(fixture.store.journal_path()),
            _ => unreachable!(),
        });
        let query = canary_route_query(SocketAddr::new(
            IpAddr::V4(selector.ipv4_peer()),
            selector.tcp_echo_port().get(),
        ));

        let error = owner
            .observe_canary_route(&target, attempt, query, &session)
            .expect_err("post-lookup owner substitution must fail closed");

        if case == 4 {
            assert!(matches!(error, NativeXtablesOwnerError::Durable(_)));
        } else {
            assert!(matches!(
                error,
                NativeXtablesOwnerError::LiveStateConflict(_)
            ));
        }
        assert_eq!(owner.adapter.canary_route_queries, [query]);
    }
}

#[test]
fn runtime_writer_keeps_definite_route_rejection_cleanup_but_poisons_ambiguity() {
    let target = canary_target(7, AddressHostFamilySelection::Ipv4);
    let fixture = Fixture::new([target.clone()]);
    let mut writer = NativeXtablesRuntimeWriter::new(
        FakeAdapter::new(vec![target.clone()]),
        fixture.store.clone(),
        fixture.environment.clone(),
    )
    .unwrap();
    let attempt = canary_attempt(false);
    let selector = attempt.selector();
    let query = canary_route_query(SocketAddr::new(
        IpAddr::V4(selector.ipv4_peer()),
        selector.tcp_echo_port().get(),
    ));
    writer.recover().unwrap();
    writer
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    writer.populate_canary_selector(&target, attempt).unwrap();
    let errno = NonZeroI32::new(libc::EHOSTUNREACH).unwrap();
    writer.test_adapter_mut().canary_route_result = FakeCanaryRouteResult::Rejected(errno);

    assert!(matches!(
        writer.observe_canary_route(&target, attempt, query),
        Ok(NativeCaptureCanaryRouteOutcome::Rejected(rejection))
            if rejection.errno() == errno
    ));
    writer
        .retire_canary_selector(&target, attempt)
        .expect("definite route rejection must retain normal selector cleanup");

    writer.populate_canary_selector(&target, attempt).unwrap();
    writer.test_adapter_mut().canary_route_result = FakeCanaryRouteResult::AmbiguousFailure;
    assert!(matches!(
        writer.observe_canary_route(&target, attempt, query),
        Err(NativeXtablesRuntimeWriterError::Owner(source))
            if matches!(source.as_ref(), NativeXtablesOwnerError::Adapter(_))
    ));
    assert!(matches!(
        writer.retire_canary_selector(&target, attempt),
        Err(NativeXtablesRuntimeWriterError::RecoveryRequired)
    ));
}

#[test]
fn interrupted_canary_session_flushes_reserved_chains_before_target_cleanup() {
    let target = canary_target(7, AddressHostFamilySelection::DualStack);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    owner
        .populate_canary_selector(&target, canary_attempt(true))
        .unwrap();
    owner.adapter.operations.clear();
    let (adapter, resolver, durable) = owner.into_parts();
    let mut restarted =
        NativeXtablesOwner::new(adapter, resolver, durable, fixture.environment.clone());

    let report = restarted
        .recover()
        .expect("crash recovery must normalize the attempt back to active ownership");

    assert_eq!(
        report.state(),
        NativeXtablesConvergedState::Active(target.identity())
    );
    assert!(report.changed());
    assert_eq!(
        restarted.adapter.operations,
        [
            "restore:ipv4:retire_canary_observation:7",
            "restore:ipv6:retire_canary_observation:7",
            "restore:ipv4:retire_canary_selector:7",
            "restore:ipv6:retire_canary_selector:7",
        ]
    );
    assert!(restarted.target_is_exact_active(&target).unwrap());
    assert!(restarted.durable.load_attempt().unwrap().is_none());
}

#[test]
fn every_canary_attempt_phase_recovers_from_its_pre_and_post_mutation_state() {
    for (families, phases) in [
        (
            AddressHostFamilySelection::Ipv4,
            vec![
                NativeXtablesAttemptPhase::Reserved,
                NativeXtablesAttemptPhase::PopulateSelectorIpv4,
                NativeXtablesAttemptPhase::PopulateObservationIpv4,
                NativeXtablesAttemptPhase::Active,
                NativeXtablesAttemptPhase::RetireObservationIpv4,
                NativeXtablesAttemptPhase::RetireSelectorIpv4,
            ],
        ),
        (
            AddressHostFamilySelection::DualStack,
            vec![
                NativeXtablesAttemptPhase::Reserved,
                NativeXtablesAttemptPhase::PopulateSelectorIpv4,
                NativeXtablesAttemptPhase::PopulateSelectorIpv6,
                NativeXtablesAttemptPhase::PopulateObservationIpv4,
                NativeXtablesAttemptPhase::PopulateObservationIpv6,
                NativeXtablesAttemptPhase::Active,
                NativeXtablesAttemptPhase::RetireObservationIpv4,
                NativeXtablesAttemptPhase::RetireObservationIpv6,
                NativeXtablesAttemptPhase::RetireSelectorIpv4,
                NativeXtablesAttemptPhase::RetireSelectorIpv6,
            ],
        ),
    ] {
        for phase in phases {
            for post_mutation in [false, true] {
                let target = canary_target(7, families);
                let fixture = Fixture::new([target.clone()]);
                let mut owner = fixture.owner();
                let attempt =
                    canary_attempt(matches!(families, AddressHostFamilySelection::DualStack));
                owner
                    .converge(NativeXtablesDesiredTarget::Active(target.clone()))
                    .unwrap();
                let primary = owner.durable.load_journal().unwrap().unwrap();
                let primary_bytes = std::fs::read(owner.durable.journal_path()).unwrap();
                let plans = canary_attempt_plans(&target, attempt.selector()).unwrap();
                let mut steps = vec![(
                    NativeXtablesAttemptPhase::PopulateSelectorIpv4,
                    Some((plans[0].family, &plans[0].populate_selector)),
                )];
                if plans.len() == 2 {
                    steps.push((
                        NativeXtablesAttemptPhase::PopulateSelectorIpv6,
                        Some((plans[1].family, &plans[1].populate_selector)),
                    ));
                }
                steps.push((
                    NativeXtablesAttemptPhase::PopulateObservationIpv4,
                    Some((plans[0].family, &plans[0].populate_observation)),
                ));
                if plans.len() == 2 {
                    steps.push((
                        NativeXtablesAttemptPhase::PopulateObservationIpv6,
                        Some((plans[1].family, &plans[1].populate_observation)),
                    ));
                }
                steps.push((NativeXtablesAttemptPhase::Active, None));
                steps.push((
                    NativeXtablesAttemptPhase::RetireObservationIpv4,
                    Some((plans[0].family, &plans[0].retire_observation)),
                ));
                if plans.len() == 2 {
                    steps.push((
                        NativeXtablesAttemptPhase::RetireObservationIpv6,
                        Some((plans[1].family, &plans[1].retire_observation)),
                    ));
                }
                steps.push((
                    NativeXtablesAttemptPhase::RetireSelectorIpv4,
                    Some((plans[0].family, &plans[0].retire_selector)),
                ));
                if plans.len() == 2 {
                    steps.push((
                        NativeXtablesAttemptPhase::RetireSelectorIpv6,
                        Some((plans[1].family, &plans[1].retire_selector)),
                    ));
                }
                let phase_mutates = steps
                    .iter()
                    .find(|(candidate, _)| *candidate == phase)
                    .is_some_and(|(_, mutation)| mutation.is_some());
                if post_mutation && !phase_mutates {
                    continue;
                }

                let (lease, guarded) = owner
                    .begin_canary_transition(&target, NativeOwnerStep::PublishActive)
                    .unwrap();
                assert_eq!(guarded, primary);
                let record = NativeXtablesAttemptRecord::new(
                    primary.binding().clone(),
                    NativeXtablesAttemptPhase::Reserved,
                    NativeCanaryAttemptBinding::new(attempt).payload().unwrap(),
                );
                let mut session = NativeXtablesAttemptSession {
                    lease,
                    record: record.clone(),
                    target: target.identity(),
                    attempt,
                    primary: primary.clone(),
                };
                session.lease.publish_attempt(record).unwrap();
                let mut reached = phase == NativeXtablesAttemptPhase::Reserved;
                if !reached {
                    for (step_phase, mutation) in &steps {
                        owner
                            .advance_canary_attempt(&plans, &mut session, *step_phase)
                            .unwrap();
                        if (*step_phase != phase || post_mutation)
                            && let Some((family, artifact)) = mutation
                        {
                            owner.adapter.restore(*family, artifact).unwrap();
                        }
                        if *step_phase == phase {
                            reached = true;
                            break;
                        }
                    }
                }
                assert!(reached, "test fixture did not reach phase {phase:?}");
                assert_eq!(session.record.phase(), phase);
                owner.adapter.operations.clear();
                drop(session);
                let (adapter, resolver, durable) = owner.into_parts();
                let mut restarted = NativeXtablesOwner::new(
                    adapter,
                    resolver,
                    durable,
                    fixture.environment.clone(),
                );

                let report = restarted.recover().unwrap_or_else(|error| {
                    panic!(
                        "{families:?} phase {phase:?} post_mutation={post_mutation} failed: {error}"
                    )
                });

                assert_eq!(
                    report.state(),
                    NativeXtablesConvergedState::Active(target.identity())
                );
                assert!(report.changed());
                assert!(restarted.target_is_exact_active(&target).unwrap());
                assert!(restarted.durable.load_attempt().unwrap().is_none());
                assert_eq!(restarted.durable.load_journal().unwrap().unwrap(), primary);
                assert_eq!(
                    std::fs::read(restarted.durable.journal_path()).unwrap(),
                    primary_bytes
                );
            }
        }
    }
}

#[test]
fn active_canary_attempt_recovery_rejects_a_missing_selector() {
    let target = canary_target(7, AddressHostFamilySelection::Ipv4);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    owner
        .populate_canary_selector(&target, canary_attempt(false))
        .unwrap();
    owner
        .adapter
        .family_state_mut(XtablesRestoreFamily::Ipv4)
        .canary_selector = None;
    owner.adapter.operations.clear();
    let (adapter, resolver, durable) = owner.into_parts();
    let mut restarted =
        NativeXtablesOwner::new(adapter, resolver, durable, fixture.environment.clone());

    let error = restarted
        .recover()
        .expect_err("an Active attempt with a missing selector must fail closed");

    assert!(matches!(
        error,
        NativeXtablesOwnerError::LiveStateConflict(
            "canary recovery state does not match the durable phase boundary"
        )
    ));
    assert!(restarted.adapter.operations.is_empty());
    assert!(restarted.durable.load_attempt().unwrap().is_some());
}

#[test]
fn ipv4_canary_attempt_recovery_rejects_an_ipv6_phase() {
    let target = canary_target(7, AddressHostFamilySelection::Ipv4);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    let attempt = canary_attempt(false);
    owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    let plans = canary_attempt_plans(&target, attempt.selector()).unwrap();
    let (lease, primary) = owner
        .begin_canary_transition(&target, NativeOwnerStep::PublishActive)
        .unwrap();
    let record = NativeXtablesAttemptRecord::new(
        primary.binding().clone(),
        NativeXtablesAttemptPhase::Reserved,
        NativeCanaryAttemptBinding::new(attempt).payload().unwrap(),
    );
    let mut session = NativeXtablesAttemptSession {
        lease,
        record: record.clone(),
        target: target.identity(),
        attempt,
        primary,
    };
    session.lease.publish_attempt(record).unwrap();
    owner
        .advance_canary_attempt(
            &plans,
            &mut session,
            NativeXtablesAttemptPhase::PopulateSelectorIpv4,
        )
        .unwrap();
    owner
        .adapter
        .restore(plans[0].family, &plans[0].populate_selector)
        .unwrap();
    let error = owner
        .advance_canary_attempt(
            &plans,
            &mut session,
            NativeXtablesAttemptPhase::PopulateSelectorIpv6,
        )
        .expect_err("IPv4 owner must reject an IPv6 phase before persistence");
    assert!(matches!(
        error,
        NativeXtablesOwnerError::InvalidCanaryAttempt(
            "IPv4-only attempt carries an IPv6 durable phase"
        )
    ));
    assert_eq!(
        session.record.phase(),
        NativeXtablesAttemptPhase::PopulateSelectorIpv4
    );
    let invalid = NativeXtablesAttemptRecord::new(
        session.record.binding().clone(),
        NativeXtablesAttemptPhase::PopulateSelectorIpv6,
        session.record.payload().clone(),
    );
    session
        .lease
        .update_attempt(&session.record, invalid.clone())
        .unwrap();
    session.record = invalid;
    drop(session);
    let (adapter, resolver, durable) = owner.into_parts();
    let mut restarted =
        NativeXtablesOwner::new(adapter, resolver, durable, fixture.environment.clone());

    assert!(matches!(
        restarted.recover(),
        Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
            "IPv4-only attempt carries an IPv6 durable phase"
        ))
    ));
    assert!(restarted.durable.load_attempt().unwrap().is_some());
}

#[test]
fn canary_attempt_recovery_rejects_nonadjacent_chain_state() {
    let target = canary_target(7, AddressHostFamilySelection::DualStack);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    let attempt = canary_attempt(true);
    owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    let plans = canary_attempt_plans(&target, attempt.selector()).unwrap();
    let (lease, primary) = owner
        .begin_canary_transition(&target, NativeOwnerStep::PublishActive)
        .unwrap();
    let record = NativeXtablesAttemptRecord::new(
        primary.binding().clone(),
        NativeXtablesAttemptPhase::Reserved,
        NativeCanaryAttemptBinding::new(attempt).payload().unwrap(),
    );
    let mut session = NativeXtablesAttemptSession {
        lease,
        record: record.clone(),
        target: target.identity(),
        attempt,
        primary,
    };
    session.lease.publish_attempt(record).unwrap();
    for plan in &plans {
        owner
            .advance_canary_attempt(&plans, &mut session, populate_selector_phase(plan.family))
            .unwrap();
        owner
            .adapter
            .restore(plan.family, &plan.populate_selector)
            .unwrap();
    }
    owner
        .advance_canary_attempt(
            &plans,
            &mut session,
            NativeXtablesAttemptPhase::PopulateObservationIpv4,
        )
        .unwrap();
    owner
        .adapter
        .restore(plans[1].family, &plans[1].populate_observation)
        .unwrap();
    drop(session);
    let (adapter, resolver, durable) = owner.into_parts();
    let mut restarted =
        NativeXtablesOwner::new(adapter, resolver, durable, fixture.environment.clone());

    assert!(matches!(
        restarted.recover(),
        Err(NativeXtablesOwnerError::LiveStateConflict(
            "canary recovery state does not match the durable phase boundary"
        ))
    ));
    assert!(restarted.durable.load_attempt().unwrap().is_some());
}

#[test]
fn canary_attempt_recovery_rejects_unreachable_cleanup_tuples_without_mutation() {
    #[derive(Clone, Copy)]
    enum ChainState {
        Base,
        Selector,
        Active,
    }

    let cases = [
        (
            AddressHostFamilySelection::Ipv4,
            NativeXtablesAttemptPhase::RetireSelectorIpv4,
            ChainState::Active,
            None,
        ),
        (
            AddressHostFamilySelection::DualStack,
            NativeXtablesAttemptPhase::RetireObservationIpv4,
            ChainState::Base,
            Some(ChainState::Active),
        ),
        (
            AddressHostFamilySelection::DualStack,
            NativeXtablesAttemptPhase::RetireObservationIpv6,
            ChainState::Active,
            Some(ChainState::Selector),
        ),
        (
            AddressHostFamilySelection::DualStack,
            NativeXtablesAttemptPhase::RetireSelectorIpv4,
            ChainState::Selector,
            Some(ChainState::Active),
        ),
        (
            AddressHostFamilySelection::DualStack,
            NativeXtablesAttemptPhase::RetireSelectorIpv6,
            ChainState::Selector,
            Some(ChainState::Selector),
        ),
    ];

    for (families, phase, ipv4_state, ipv6_state) in cases {
        let target = canary_target(7, families);
        let fixture = Fixture::new([target.clone()]);
        let mut owner = fixture.owner();
        let attempt = canary_attempt(matches!(families, AddressHostFamilySelection::DualStack));
        owner
            .converge(NativeXtablesDesiredTarget::Active(target.clone()))
            .unwrap();
        let primary = owner.durable.load_journal().unwrap().unwrap();
        let plans = canary_attempt_plans(&target, attempt.selector()).unwrap();
        let mut session = owner.populate_canary_selector(&target, attempt).unwrap();
        let retirement = if plans.len() == 1 {
            vec![
                NativeXtablesAttemptPhase::RetireObservationIpv4,
                NativeXtablesAttemptPhase::RetireSelectorIpv4,
            ]
        } else {
            vec![
                NativeXtablesAttemptPhase::RetireObservationIpv4,
                NativeXtablesAttemptPhase::RetireObservationIpv6,
                NativeXtablesAttemptPhase::RetireSelectorIpv4,
                NativeXtablesAttemptPhase::RetireSelectorIpv6,
            ]
        };
        for candidate in retirement {
            owner
                .advance_canary_attempt(&plans, &mut session, candidate)
                .unwrap();
            if candidate == phase {
                break;
            }
        }

        let states = [Some(ipv4_state), ipv6_state];
        for (plan, state) in plans.iter().zip(states.into_iter().flatten()) {
            match state {
                ChainState::Active => {}
                ChainState::Selector => owner
                    .adapter
                    .restore(plan.family, &plan.retire_observation)
                    .unwrap(),
                ChainState::Base => {
                    owner
                        .adapter
                        .restore(plan.family, &plan.retire_observation)
                        .unwrap();
                    owner
                        .adapter
                        .restore(plan.family, &plan.retire_selector)
                        .unwrap();
                }
            }
        }
        owner.adapter.operations.clear();
        drop(session);
        let (adapter, resolver, durable) = owner.into_parts();
        let mut restarted =
            NativeXtablesOwner::new(adapter, resolver, durable, fixture.environment.clone());

        let error = restarted
            .recover()
            .expect_err("an unreachable cleanup tuple must fail closed");

        assert!(matches!(
            error,
            NativeXtablesOwnerError::LiveStateConflict(
                "canary recovery state is not reachable at the durable cleanup phase"
            )
        ));
        assert!(restarted.adapter.operations.is_empty());
        assert!(restarted.durable.load_attempt().unwrap().is_some());
        assert_eq!(restarted.durable.load_journal().unwrap().unwrap(), primary);
    }
}

#[test]
fn canary_selector_write_failures_are_compensated_or_proven_by_readback() {
    for retiring in [false, true] {
        for write in 1..=4 {
            for after_apply in [false, true] {
                let target = canary_target(7, AddressHostFamilySelection::DualStack);
                let fixture = Fixture::new([target.clone()]);
                let mut owner = fixture.owner();
                owner
                    .converge(NativeXtablesDesiredTarget::Active(target.clone()))
                    .unwrap();
                let session = if retiring {
                    Some(
                        owner
                            .populate_canary_selector(&target, canary_attempt(true))
                            .unwrap(),
                    )
                } else {
                    None
                };
                owner.adapter.write_count = 0;
                owner.adapter.failures = vec![Failure { write, after_apply }];

                if let Some(session) = session {
                    let result =
                        owner.retire_canary_selector(&target, canary_attempt(true), session);
                    if after_apply {
                        result.expect("post-apply error with exact readback must be accepted");
                    } else {
                        assert!(matches!(
                            result,
                            Err(NativeXtablesOwnerError::RolledBack {
                                state: NativeXtablesConvergedState::Active(identity),
                                ..
                            }) if identity == target.identity()
                        ));
                    }
                } else {
                    let result = owner.populate_canary_selector(&target, canary_attempt(true));
                    if after_apply {
                        let session =
                            result.expect("post-apply error with exact readback must be accepted");
                        owner.adapter.failures.clear();
                        owner
                            .retire_canary_selector(&target, canary_attempt(true), session)
                            .unwrap();
                    } else {
                        assert!(matches!(
                            result,
                            Err(NativeXtablesOwnerError::RolledBack {
                                state: NativeXtablesConvergedState::Active(identity),
                                ..
                            }) if identity == target.identity()
                        ));
                    }
                }
                assert!(owner.target_is_exact_active(&target).unwrap());
                assert!(owner.durable.load_attempt().unwrap().is_none());
            }
        }
    }
}

#[test]
fn failed_canary_compensation_remains_recoverable() {
    let target = canary_target(7, AddressHostFamilySelection::DualStack);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    owner.adapter.write_count = 0;
    owner.adapter.failures = vec![
        Failure {
            write: 2,
            after_apply: false,
        },
        Failure {
            write: 3,
            after_apply: false,
        },
    ];

    let error = owner
        .populate_canary_selector(&target, canary_attempt(true))
        .expect_err("failed compensation must retain the durable attempt");

    assert!(matches!(error, NativeXtablesOwnerError::Uncertain { .. }));
    assert_eq!(
        owner.durable.load_journal().unwrap().unwrap().phase(),
        NativeXtablesJournalPhase::Active
    );
    assert!(owner.durable.load_attempt().unwrap().is_some());
    assert!(owner.durable.load_lease().unwrap().is_some());
    owner.adapter.failures.clear();

    let report = owner
        .recover()
        .expect("restart recovery must normalize the attempt");

    assert_eq!(
        report.state(),
        NativeXtablesConvergedState::Active(target.identity())
    );
    assert!(owner.target_is_exact_active(&target).unwrap());
    assert!(owner.durable.load_attempt().unwrap().is_none());
}

#[test]
fn recovery_rejects_drift_outside_the_reserved_canary_chain() {
    let target = canary_target(7, AddressHostFamilySelection::Ipv4);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    owner
        .populate_canary_selector(&target, canary_attempt(false))
        .unwrap();
    owner.adapter.operations.clear();
    owner.adapter.foreign_xtables[family_index(XtablesRestoreFamily::Ipv4)] = true;

    let error = owner
        .recover()
        .expect_err("recovery must not normalize unrelated native drift");

    assert!(matches!(
        error,
        NativeXtablesOwnerError::LiveStateConflict(
            "canary recovery state does not match the durable phase boundary"
        )
    ));
    assert!(owner.adapter.operations.is_empty());
    owner.adapter.foreign_xtables[family_index(XtablesRestoreFamily::Ipv4)] = false;

    let report = owner
        .recover()
        .expect("recovery may continue after unrelated drift is removed");
    assert_eq!(
        report.state(),
        NativeXtablesConvergedState::Active(target.identity())
    );
    assert_eq!(
        owner.adapter.operations.first(),
        Some(&"restore:ipv4:retire_canary_observation:7")
    );
    assert!(owner.target_is_exact_active(&target).unwrap());
}

#[test]
fn active_ownership_observation_binds_exact_journal_descriptor_and_live_target() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .expect("activate target before ownership observation");

    let encoded = std::fs::read(fixture.store.journal_path()).expect("read active journal bytes");
    let metadata = std::fs::metadata(fixture.store.journal_path())
        .expect("inspect active journal descriptor identity");
    let journal = fixture.store.load_journal().unwrap().unwrap();
    let observation = owner
        .observe_active_ownership()
        .expect("observe exact active ownership")
        .expect("active target has ownership evidence");

    assert_eq!(
        observation.target().generation(),
        target.identity().generation()
    );
    assert_eq!(
        observation.target().target_digest(),
        target.identity().target_digest()
    );
    assert_eq!(
        observation.target().tool_digest(),
        target.identity().tool_digest()
    );
    assert_eq!(
        observation.target().routing_digest(),
        target.identity().routing_digest()
    );
    assert_eq!(
        observation.boot_identity(),
        &fixture.environment.boot_identity
    );
    assert_eq!(
        observation.network_namespace(),
        fixture.environment.network_namespace
    );
    assert_eq!(
        observation.journal_identity(),
        fixture.environment.journal_identity
    );
    assert_eq!(observation.journal_revision(), journal.revision());
    assert!(observation.journal_revision() > OwnershipJournalRevision::INITIAL);
    assert_eq!(
        observation.record_schema_version().get(),
        NATIVE_XTABLES_JOURNAL_SCHEMA_VERSION
    );
    assert_eq!(observation.record_device(), metadata.dev());
    assert_eq!(observation.record_inode().get(), metadata.ino());
    assert_eq!(
        observation.record_digest(),
        <[u8; 32]>::from(Sha256::digest(encoded))
    );
}

#[test]
fn active_ownership_observation_rejects_generation_target_substitution() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .expect("activate target before journal substitution");
    let current = fixture.store.load_journal().unwrap().unwrap();
    let expected = current.binding().clone();
    let NativeXtablesRecovery::Leased(mut lease) = fixture.store.recover(&expected).unwrap() else {
        panic!("active journal must retain its durable lease");
    };
    lease
        .rebind(NativeXtablesJournalRecord::new(
            fixture.environment.binding(GenerationId::new(8).unwrap()),
            next_revision(current.revision()).unwrap(),
            NativeXtablesJournalPhase::Active,
            current.owner_payload().clone(),
        ))
        .expect("publish substituted Generation for negative control");
    drop(lease);

    let error = owner
        .observe_active_ownership()
        .expect_err("journal Generation and target substitution must fail");
    assert!(
        error
            .to_string()
            .contains("substituted target or Generation")
    );
}

#[test]
fn active_ownership_observation_rejects_writer_fence() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target))
        .expect("activate target before writer-fence control");
    create_same_scope_writer_lock(&fixture.store, &fixture.environment);

    let error = owner
        .observe_active_ownership()
        .expect_err("active writer fence must block ownership observation");
    assert!(error.to_string().contains("active writer lock"));
}

#[test]
fn invalid_outstanding_attempt_blocks_recovery_and_active_ownership_observation() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target))
        .expect("activate target before attempt control");
    let journal = fixture.store.load_journal().unwrap().unwrap();
    let expected = journal.binding().clone();
    let primary = std::fs::read(fixture.store.journal_path()).unwrap();
    let NativeXtablesRecovery::Leased(mut lease) = fixture.store.recover(&expected).unwrap() else {
        panic!("active journal must retain its durable lease");
    };
    lease
        .publish_attempt(NativeXtablesAttemptRecord::new(
            expected,
            NativeXtablesAttemptPhase::Reserved,
            NativeXtablesAttemptPayload::new(b"nonce=runtime-control".to_vec()).unwrap(),
        ))
        .unwrap();
    drop(lease);

    assert!(matches!(
        owner.observe_active_ownership().unwrap_err(),
        NativeXtablesOwnerError::AttemptRecoveryRequired
    ));
    assert!(matches!(
        owner.recover().unwrap_err(),
        NativeXtablesOwnerError::InvalidCanaryAttempt(
            "payload must contain eleven canonical fields"
        )
    ));
    assert_eq!(
        std::fs::read(fixture.store.journal_path()).unwrap(),
        primary
    );
    assert!(fixture.store.load_attempt().unwrap().is_some());
}

#[test]
fn active_ownership_observation_rejects_live_readback_drift() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target))
        .expect("activate target before live-state control");
    owner.adapter.foreign_xtables[0] = true;

    let error = owner
        .observe_active_ownership()
        .expect_err("live xtables substitution must fail ownership observation");
    assert!(error.to_string().contains("did not match exact live state"));
}

#[test]
fn durable_target_archive_round_trips_exact_runtime_material() {
    let temp = TempDir::new().unwrap();
    let store = NativeXtablesDurableStore::new(temp.path().join("run"));
    let target = target(7, AddressHostFamilySelection::DualStack, true);
    let resolver = DurableNativeXtablesTargetResolver::open(store.clone()).unwrap();

    resolver.stage(target.clone()).unwrap();
    assert_eq!(resolver.identities().unwrap(), [target.identity()]);
    let encoded = store.load_target_archive().unwrap().unwrap();
    let generation_offset = b"flux-native-xtables-target-archive\0".len() + 2 + 1;
    assert_eq!(
        &encoded[generation_offset..generation_offset + std::mem::size_of::<u32>()],
        &7_u32.to_be_bytes()
    );

    let mut reopened = DurableNativeXtablesTargetResolver::open(store).unwrap();
    let recovered = reopened.resolve(target.identity()).unwrap();
    assert_eq!(recovered, target);
}

#[test]
fn read_only_archive_observation_distinguishes_retained_target_from_clean_settlement() {
    let temp = TempDir::new().unwrap();
    let store = NativeXtablesDurableStore::new(temp.path().join("run"));
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let resolver = DurableNativeXtablesTargetResolver::open(store.clone()).unwrap();

    resolver.stage(target).unwrap();
    let durable = store.observe_read_only().unwrap();
    let archived = observe_native_xtables_target_archive(durable.target_archive()).unwrap();
    assert!(archived.present());
    assert_eq!(archived.target_count(), 1);

    resolver
        .retain_state(NativeXtablesConvergedState::CleanAbsent)
        .unwrap();
    let durable = store.observe_read_only().unwrap();
    let settled = observe_native_xtables_target_archive(durable.target_archive()).unwrap();
    assert!(settled.present());
    assert_eq!(settled.target_count(), 0);
    assert_ne!(archived.digest(), settled.digest());
}

#[test]
fn durable_target_archive_retains_replacement_pair_then_prunes_to_settled_state() {
    let temp = TempDir::new().unwrap();
    let store = NativeXtablesDurableStore::new(temp.path().join("run"));
    let old = target(7, AddressHostFamilySelection::Ipv4, false);
    let new = target(8, AddressHostFamilySelection::Ipv4, true);
    let resolver = DurableNativeXtablesTargetResolver::open(store.clone()).unwrap();

    resolver.stage(old.clone()).unwrap();
    resolver.stage(new.clone()).unwrap();
    assert_eq!(
        resolver.identities().unwrap(),
        [old.identity(), new.identity()]
    );
    resolver
        .retain_state(NativeXtablesConvergedState::Active(new.identity()))
        .unwrap();

    let reopened = DurableNativeXtablesTargetResolver::open(store).unwrap();
    assert_eq!(reopened.identities().unwrap(), [new.identity()]);
}

#[test]
fn durable_target_archive_rejects_corruption_before_resolution() {
    let temp = TempDir::new().unwrap();
    let store = NativeXtablesDurableStore::new(temp.path().join("run"));
    let resolver = DurableNativeXtablesTargetResolver::open(store.clone()).unwrap();
    resolver
        .stage(target(7, AddressHostFamilySelection::Ipv4, false))
        .unwrap();
    let path = store.target_archive_path();
    let mut encoded = std::fs::read(&path).unwrap();
    encoded[0] ^= 0xff;
    std::fs::write(path, encoded).unwrap();

    let error = match DurableNativeXtablesTargetResolver::open(store) {
        Ok(_) => panic!("corrupted target archive must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        NativeXtablesTargetArchiveError::Invalid("archive checksum does not match")
    ));
}

#[test]
fn durable_target_archive_never_discards_unsettled_third_target() {
    let temp = TempDir::new().unwrap();
    let store = NativeXtablesDurableStore::new(temp.path().join("run"));
    let first = target(7, AddressHostFamilySelection::Ipv4, false);
    let second = target(8, AddressHostFamilySelection::Ipv4, true);
    let third = target(9, AddressHostFamilySelection::Ipv4, false);
    let resolver = DurableNativeXtablesTargetResolver::open(store.clone()).unwrap();
    resolver.stage(first.clone()).unwrap();
    resolver.stage(second.clone()).unwrap();

    assert!(matches!(
        resolver.stage(third),
        Err(NativeXtablesTargetArchiveError::CapacityExceeded)
    ));
    let reopened = DurableNativeXtablesTargetResolver::open(store).unwrap();
    assert_eq!(
        reopened.identities().unwrap(),
        [first.identity(), second.identity()]
    );
}

#[test]
fn runtime_writer_requires_recovery_before_any_convergence() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut writer = NativeXtablesRuntimeWriter::new(
        FakeAdapter::new(vec![target.clone()]),
        fixture.store.clone(),
        fixture.environment.clone(),
    )
    .unwrap();

    let error = writer
        .converge(NativeXtablesDesiredTarget::Active(target))
        .expect_err("convergence before recovery must fail closed");

    assert!(matches!(
        error,
        NativeXtablesRuntimeWriterError::RecoveryRequired
    ));
    assert!(writer.test_adapter().operations.is_empty());
    assert!(writer.test_archived_identities().unwrap().is_empty());
}

#[test]
fn runtime_writer_forwards_canary_mutation_and_invalidates_after_owner_error() {
    let target = canary_target(7, AddressHostFamilySelection::Ipv4);
    let fixture = Fixture::new([target.clone()]);
    let mut writer = NativeXtablesRuntimeWriter::new(
        FakeAdapter::new(vec![target.clone()]),
        fixture.store.clone(),
        fixture.environment.clone(),
    )
    .unwrap();
    writer.recover().unwrap();
    writer
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    writer.test_adapter_mut().operations.clear();

    writer
        .populate_canary_selector(&target, canary_attempt(false))
        .unwrap();
    writer
        .retire_canary_selector(&target, canary_attempt(false))
        .unwrap();

    assert_eq!(
        writer.test_adapter().operations,
        [
            "restore:ipv4:populate_canary_selector:7",
            "restore:ipv4:populate_canary_observation:7",
            "restore:ipv4:retire_canary_observation:7",
            "restore:ipv4:retire_canary_selector:7",
        ]
    );

    let error = writer
        .populate_canary_selector(&target, canary_attempt(true))
        .expect_err("owner selector error must invalidate the runtime writer");
    assert!(matches!(
        error,
        NativeXtablesRuntimeWriterError::Owner(source)
            if matches!(
                source.as_ref(),
                NativeXtablesOwnerError::InvalidCanarySelector(
                    "selector address families differ from the admitted target"
                )
            )
    ));
    assert!(matches!(
        writer.observe_active_ownership(),
        Err(NativeXtablesRuntimeWriterError::RecoveryRequired)
    ));
    assert_eq!(
        writer.recover().unwrap().state(),
        NativeXtablesConvergedState::Active(target.identity())
    );
}

#[test]
fn runtime_writer_holds_the_runtime_guard_for_the_complete_canary_attempt() {
    let target = canary_target(7, AddressHostFamilySelection::Ipv4);
    let fixture = Fixture::new([target.clone()]);
    let mut writer = NativeXtablesRuntimeWriter::new(
        FakeAdapter::new(vec![target.clone()]),
        fixture.store.clone(),
        fixture.environment.clone(),
    )
    .unwrap();
    let attempt = canary_attempt(false);
    let selector = attempt.selector();
    let query = canary_route_query(SocketAddr::new(
        IpAddr::V4(selector.ipv4_peer()),
        selector.tcp_echo_port().get(),
    ));
    writer.recover().unwrap();
    writer
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    writer.populate_canary_selector(&target, attempt).unwrap();

    let competing_store = fixture.store.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let competing_thread = std::thread::spawn(move || {
        sender
            .send(competing_store.acquire_runtime_guard())
            .unwrap();
    });
    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));

    writer
        .observe_canary_route(&target, attempt, query)
        .expect("route observation must borrow the retained attempt guard");
    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));

    writer.retire_canary_selector(&target, attempt).unwrap();
    let guard = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("competing writer must proceed after attempt retirement")
        .expect("runtime guard acquisition after retirement must succeed");
    drop(guard);
    competing_thread.join().unwrap();
}

#[test]
fn runtime_writer_missing_attempt_sidecar_poisoning_requires_full_recovery() {
    let target = canary_target(7, AddressHostFamilySelection::Ipv4);
    let fixture = Fixture::new([target.clone()]);
    let mut writer = NativeXtablesRuntimeWriter::new(
        FakeAdapter::new(vec![target.clone()]),
        fixture.store.clone(),
        fixture.environment.clone(),
    )
    .unwrap();
    let attempt = canary_attempt(false);
    let selector = attempt.selector();
    let query = canary_route_query(SocketAddr::new(
        IpAddr::V4(selector.ipv4_peer()),
        selector.tcp_echo_port().get(),
    ));
    writer.recover().unwrap();
    writer
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    writer.populate_canary_selector(&target, attempt).unwrap();
    writer.test_adapter_mut().operations.clear();
    std::fs::remove_file(fixture.store.attempt_path()).unwrap();

    let error = writer
        .observe_canary_route(&target, attempt, query)
        .expect_err("a missing retained sidecar must poison the writer");

    assert!(matches!(
        error,
        NativeXtablesRuntimeWriterError::Owner(source)
            if matches!(
                source.as_ref(),
                NativeXtablesOwnerError::LiveStateConflict(
                    "native canary attempt sidecar disappeared"
                )
            )
    ));
    assert!(writer.test_adapter().canary_route_queries.is_empty());
    assert!(matches!(
        writer.retire_canary_selector(&target, attempt),
        Err(NativeXtablesRuntimeWriterError::RecoveryRequired)
    ));

    let recovery = writer
        .recover()
        .expect_err("recovery cannot infer cleanup authority after the sidecar disappears");
    assert!(matches!(
        recovery,
        NativeXtablesRuntimeWriterError::Owner(source)
            if matches!(source.as_ref(), NativeXtablesOwnerError::Uncertain { .. })
    ));
    assert!(fixture.store.load_attempt().unwrap().is_none());
    assert_eq!(
        fixture.store.load_journal().unwrap().unwrap().phase(),
        NativeXtablesJournalPhase::Uncertain
    );
    assert!(fixture.store.load_lease().unwrap().is_some());
    assert_eq!(
        writer.test_archived_identities().unwrap(),
        [target.identity()]
    );
    assert!(matches!(
        writer.observe_active_ownership(),
        Err(NativeXtablesRuntimeWriterError::RecoveryRequired)
    ));
}

#[test]
fn runtime_writer_persists_target_before_owner_journal_can_name_it() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut writer = NativeXtablesRuntimeWriter::new(
        FakeAdapter::new(vec![target.clone()]),
        fixture.store.clone(),
        fixture.environment.clone(),
    )
    .unwrap();
    writer.recover().unwrap();
    fixture
        .store
        .set_failpoint(Some(DurableEvent::JournalTempDurable));

    let error = writer
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .expect_err("injected journal interruption must fail convergence");
    assert!(matches!(
        error,
        NativeXtablesRuntimeWriterError::Owner(source)
            if matches!(
                source.as_ref(),
                NativeXtablesOwnerError::Durable(NativeXtablesDurableError::InterruptedAt(
                    DurableEvent::JournalTempDurable
                ))
            )
    ));
    drop(writer);

    let resolver = DurableNativeXtablesTargetResolver::open(fixture.store.clone()).unwrap();
    assert_eq!(resolver.identities().unwrap(), [target.identity()]);
}

#[test]
fn runtime_writer_serializes_archive_and_owner_journal_as_one_transaction() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut writer = NativeXtablesRuntimeWriter::new(
        FakeAdapter::new(vec![target.clone()]),
        fixture.store.clone(),
        fixture.environment.clone(),
    )
    .unwrap();
    writer.recover().unwrap();
    fixture.store.pause_at(DurableEvent::JournalDurable);

    let writer_thread =
        std::thread::spawn(move || writer.converge(NativeXtablesDesiredTarget::Active(target)));
    fixture
        .store
        .wait_until_paused(DurableEvent::JournalDurable);

    let competing_store = fixture.store.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let competing_thread = std::thread::spawn(move || {
        sender
            .send(competing_store.acquire_runtime_guard())
            .unwrap();
    });
    let early = receiver.recv_timeout(Duration::from_millis(50));
    fixture.store.release_pause();

    assert!(matches!(
        early,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    assert!(writer_thread.join().unwrap().is_ok());
    let guard = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("competing runtime guard acquisition must finish after convergence")
        .expect("competing runtime guard acquisition must succeed after convergence");
    drop(guard);
    competing_thread.join().unwrap();
}

#[test]
fn runtime_writer_restart_recovers_active_target_without_current_configuration() {
    let target = target(7, AddressHostFamilySelection::DualStack, true);
    let fixture = Fixture::new([target.clone()]);
    let mut writer = NativeXtablesRuntimeWriter::new(
        FakeAdapter::new(vec![target.clone()]),
        fixture.store.clone(),
        fixture.environment.clone(),
    )
    .unwrap();
    writer.recover().unwrap();
    writer
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    let (adapter, durable, environment) = writer.into_parts();

    let mut restarted = NativeXtablesRuntimeWriter::new(adapter, durable, environment).unwrap();
    let report = restarted.recover().unwrap();

    assert_eq!(
        report.state(),
        NativeXtablesConvergedState::Active(target.identity())
    );
    assert!(!report.changed());
    assert_eq!(
        restarted.test_archived_identities().unwrap(),
        [target.identity()]
    );
}

#[test]
fn runtime_writer_recovery_resolves_replacement_rollback_then_prunes_candidate() {
    let old = target(7, AddressHostFamilySelection::Ipv4, false);
    let new = target(8, AddressHostFamilySelection::Ipv4, true);
    let fixture = Fixture::new([old.clone(), new.clone()]);
    let mut writer = NativeXtablesRuntimeWriter::new(
        FakeAdapter::new(vec![old.clone(), new.clone()]),
        fixture.store.clone(),
        fixture.environment.clone(),
    )
    .unwrap();
    writer.recover().unwrap();
    writer
        .converge(NativeXtablesDesiredTarget::Active(old.clone()))
        .unwrap();
    writer.test_adapter_mut().write_count = 0;
    writer.test_adapter_mut().failures = vec![Failure {
        write: 1,
        after_apply: false,
    }];

    let error = writer
        .converge(NativeXtablesDesiredTarget::Active(new.clone()))
        .expect_err("replacement failure must report rollback");
    assert!(matches!(
        error,
        NativeXtablesRuntimeWriterError::Owner(source)
            if matches!(
                source.as_ref(),
                NativeXtablesOwnerError::RolledBack {
                    state: NativeXtablesConvergedState::Active(identity),
                    ..
                } if *identity == old.identity()
            )
    ));
    assert_eq!(
        writer.test_archived_identities().unwrap(),
        [old.identity(), new.identity()]
    );

    writer.test_adapter_mut().failures.clear();
    let report = writer.recover().unwrap();
    assert_eq!(
        report.state(),
        NativeXtablesConvergedState::Active(old.identity())
    );
    assert_eq!(writer.test_archived_identities().unwrap(), [old.identity()]);
}

#[test]
fn runtime_writer_stop_reaches_exact_absence_and_prunes_target_material() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let target_identity = target.identity();
    let fixture = Fixture::new([target.clone()]);
    let mut writer = NativeXtablesRuntimeWriter::new(
        FakeAdapter::new(vec![target.clone()]),
        fixture.store.clone(),
        fixture.environment.clone(),
    )
    .unwrap();
    writer.recover().unwrap();
    writer
        .converge(NativeXtablesDesiredTarget::Active(target))
        .unwrap();

    let report = writer
        .converge(NativeXtablesDesiredTarget::Stopped)
        .unwrap();

    assert_eq!(report.state(), NativeXtablesConvergedState::CleanAbsent);
    assert_eq!(
        writer.test_archived_identities().unwrap(),
        [target_identity]
    );
    assert_eq!(
        fixture.store.load_journal().unwrap().unwrap().phase(),
        NativeXtablesJournalPhase::CleanAbsent
    );
    assert!(fixture.store.load_lease().unwrap().is_none());

    let recovered = writer.recover().unwrap();
    assert_eq!(recovered.state(), NativeXtablesConvergedState::CleanAbsent);
    assert!(writer.test_archived_identities().unwrap().is_empty());
    assert!(fixture.store.load_journal().unwrap().is_none());
}

#[test]
fn runtime_writer_dry_run_reports_intent_without_archive_journal_or_kernel_mutation() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut writer = NativeXtablesRuntimeWriter::new(
        FakeAdapter::new(vec![target.clone()]),
        fixture.store.clone(),
        fixture.environment.clone(),
    )
    .unwrap();

    let report = writer
        .observe(NativeXtablesDryRunTarget::Active(&target))
        .unwrap();

    assert!(!report.recovered());
    assert!(!report.journal_present());
    assert!(report.archived_targets().is_empty());
    assert_eq!(report.desired_identity(), Some(target.identity()));
    assert!(report.tool_identity_matches());
    assert!(!report.exact_desired());
    assert!(report.clean_absent());
    assert_eq!(
        report.disposition(),
        NativeXtablesDryRunDisposition::Activate
    );
    assert!(writer.test_adapter().operations.is_empty());
    assert!(fixture.store.load_target_archive().unwrap().is_none());
    assert!(fixture.store.load_journal().unwrap().is_none());
}

#[test]
fn opposite_family_routing_residue_blocks_activation_before_any_write() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    let residue = target.routing_audit().identity(NetworkAddressFamily::Ipv6);
    owner.adapter.routes.push(residue.route());
    owner.adapter.rules.push(residue.rule());

    let error = owner
        .converge(NativeXtablesDesiredTarget::Active(target))
        .expect_err("opposite-family residue must block exact activation");

    assert!(
        matches!(error, NativeXtablesOwnerError::LiveStateConflict(_)),
        "unexpected error: {error:?}"
    );
    assert!(owner.adapter.operations.is_empty());
    assert!(owner.durable.load_journal().unwrap().is_none());
}

#[test]
fn opposite_family_xtables_residue_blocks_activation_before_any_write() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner.adapter.foreign_xtables[family_index(XtablesRestoreFamily::Ipv6)] = true;

    let error = owner
        .converge(NativeXtablesDesiredTarget::Active(target))
        .expect_err("opposite-family xtables residue must block exact activation");

    assert!(
        matches!(error, NativeXtablesOwnerError::LiveStateConflict(_)),
        "unexpected error: {error:?}"
    );
    assert!(owner.adapter.operations.is_empty());
    assert!(owner.durable.load_journal().unwrap().is_none());
}

#[test]
fn stale_loopback_binding_blocks_activation_before_any_write() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner.adapter.interface_identity_valid = false;

    let error = owner
        .converge(NativeXtablesDesiredTarget::Active(target))
        .expect_err("stale loopback identity must block activation");

    assert!(matches!(error, NativeXtablesOwnerError::Adapter(_)));
    assert!(owner.adapter.operations.is_empty());
    assert!(owner.durable.load_journal().unwrap().is_none());
}

#[test]
fn active_replacement_rebinds_generation_without_releasing_component_lease() {
    let old = target(7, AddressHostFamilySelection::Ipv4, false);
    let new = target(8, AddressHostFamilySelection::Ipv4, true);
    let fixture = Fixture::new([old.clone(), new.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(old.clone()))
        .unwrap();
    owner.adapter.operations.clear();

    let report = owner
        .converge(NativeXtablesDesiredTarget::Active(new.clone()))
        .expect("replace active generation");
    assert_eq!(
        report.state(),
        NativeXtablesConvergedState::Active(new.identity())
    );
    assert!(report.changed());
    assert_eq!(
        owner.adapter.operations,
        [
            "restore:ipv4:prepare:8",
            "restore:ipv4:switch:8",
            "restore:ipv4:retire:7",
        ]
    );
    let journal = owner.durable.load_journal().unwrap().unwrap();
    assert_eq!(journal.binding().generation(), new.identity().generation());
    assert_eq!(journal.phase(), NativeXtablesJournalPhase::Active);
    assert!(owner.durable.load_lease().unwrap().is_some());
    assert!(owner.target_is_exact_active(&new).unwrap());
}

#[test]
fn active_replacement_rejects_same_generation_before_any_write() {
    let old = target(7, AddressHostFamilySelection::Ipv4, false);
    let replacement = target(7, AddressHostFamilySelection::Ipv4, true);
    let fixture = Fixture::new([old.clone(), replacement.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(old.clone()))
        .unwrap();
    owner.adapter.operations.clear();
    let journal_before = owner.durable.load_journal().unwrap().unwrap();

    let error = owner
        .converge(NativeXtablesDesiredTarget::Active(replacement))
        .expect_err("a Generation cannot be reused for a different target");

    assert!(matches!(
        error,
        NativeXtablesOwnerError::ReplacementIncompatible("replacement must use a fresh generation")
    ));
    assert!(owner.adapter.operations.is_empty());
    assert_eq!(
        owner.durable.load_journal().unwrap().unwrap(),
        journal_before
    );
    assert!(owner.target_is_exact_active(&old).unwrap());
}

#[test]
fn restart_after_successful_replacement_preserves_the_new_active_generation() {
    let old = target(7, AddressHostFamilySelection::Ipv4, false);
    let new = target(8, AddressHostFamilySelection::Ipv4, true);
    let fixture = Fixture::new([old.clone(), new.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(old))
        .unwrap();
    owner
        .converge(NativeXtablesDesiredTarget::Active(new.clone()))
        .unwrap();
    let (adapter, resolver, durable) = owner.into_parts();
    let mut restarted =
        NativeXtablesOwner::new(adapter, resolver, durable, fixture.environment.clone());

    let report = restarted.recover().expect("recover new active generation");
    assert_eq!(
        report.state(),
        NativeXtablesConvergedState::Active(new.identity())
    );
    assert!(!report.changed());
    assert!(restarted.target_is_exact_active(&new).unwrap());
}

#[test]
fn journal_less_recovery_reclaims_same_scope_lock_only_under_live_absence_fence() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    create_same_scope_writer_lock(&fixture.store, &fixture.environment);
    assert!(fixture.store.writer_lock_exists().unwrap());
    let mut owner = fixture.owner();

    let report = owner.recover().unwrap();

    assert_eq!(report.state(), NativeXtablesConvergedState::CleanAbsent);
    assert!(!fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn journal_less_recovery_keeps_lease_only_state_fail_closed() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let lease = acquire_unmutated_lease(&fixture.store, &fixture.environment, &target);
    std::fs::remove_file(fixture.store.journal_path()).unwrap();
    drop(lease);
    let mut owner = fixture.owner();

    let error = owner
        .recover()
        .expect_err("a lease without its journal cannot authorize absence");

    assert!(matches!(
        error,
        NativeXtablesOwnerError::Durable(NativeXtablesDurableError::MissingJournal)
    ));
    assert!(fixture.store.load_lease().unwrap().is_some());
    assert!(fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn terminal_empty_payload_audits_two_family_policy_under_the_writer_fence() {
    let active_target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([active_target.clone()]);
    let binding = fixture
        .environment
        .binding(active_target.identity().generation());
    let payload = NativeOwnerIntent {
        step: NativeOwnerStep::Failed,
        target: None,
        previous: None,
    }
    .payload()
    .unwrap();
    let lease = fixture
        .store
        .acquire(NativeXtablesJournalRecord::new(
            binding.clone(),
            OwnershipJournalRevision::INITIAL,
            NativeXtablesJournalPhase::Activating,
            payload.clone(),
        ))
        .unwrap();
    lease
        .complete(NativeXtablesJournalRecord::new(
            binding,
            OwnershipJournalRevision::new(2).unwrap(),
            NativeXtablesJournalPhase::CleanAbsent,
            payload,
        ))
        .unwrap();

    let residue = active_target
        .routing_audit()
        .identity(NetworkAddressFamily::Ipv6);
    let mut owner = fixture.owner();
    owner.adapter.routes.push(residue.route());
    owner.adapter.rules.push(residue.rule());

    let error = owner
        .recover()
        .expect_err("terminal recovery must audit both routing families");

    assert!(matches!(
        error,
        NativeXtablesOwnerError::LiveStateConflict(_)
    ));
    assert!(fixture.store.load_journal().unwrap().is_some());
    assert!(fixture.store.writer_lock_exists().unwrap());
    let competing = target(8, AddressHostFamilySelection::Ipv4, false);
    let competing_intent = NativeOwnerIntent {
        step: NativeOwnerStep::Begin,
        target: Some(competing.identity()),
        previous: None,
    };
    assert!(matches!(
        fixture.store.acquire(NativeXtablesJournalRecord::new(
            fixture
                .environment
                .binding(competing.identity().generation()),
            OwnershipJournalRevision::INITIAL,
            NativeXtablesJournalPhase::Activating,
            competing_intent.payload().unwrap(),
        )),
        Err(NativeXtablesDurableError::NativeOwnerBusy
            | NativeXtablesDurableError::InterruptedPublication)
    ));
}

#[test]
fn terminal_recovery_readback_failure_retains_surviving_lease_and_fence() {
    let active_target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([active_target.clone()]);
    let binding = fixture
        .environment
        .binding(active_target.identity().generation());
    let intent = NativeOwnerIntent {
        step: NativeOwnerStep::Failed,
        target: Some(active_target.identity()),
        previous: None,
    };
    let lease = fixture
        .store
        .acquire(NativeXtablesJournalRecord::new(
            binding.clone(),
            OwnershipJournalRevision::INITIAL,
            NativeXtablesJournalPhase::Activating,
            intent.payload().unwrap(),
        ))
        .unwrap();
    fixture
        .store
        .set_failpoint(Some(DurableEvent::TerminalJournalDurable));
    assert!(matches!(
        lease.complete(NativeXtablesJournalRecord::new(
            binding,
            OwnershipJournalRevision::new(2).unwrap(),
            NativeXtablesJournalPhase::CleanAbsent,
            intent.payload().unwrap(),
        )),
        Err(NativeXtablesDurableError::InterruptedAt(
            DurableEvent::TerminalJournalDurable
        ))
    ));

    let mut owner = fixture.owner();
    owner.adapter.foreign_xtables[family_index(XtablesRestoreFamily::Ipv6)] = true;
    let error = owner
        .recover()
        .expect_err("terminal recovery cannot release a surviving lease before live absence");

    assert!(matches!(
        error,
        NativeXtablesOwnerError::LiveStateConflict(_)
    ));
    assert!(fixture.store.load_journal().unwrap().is_some());
    assert!(fixture.store.load_lease().unwrap().is_some());
    assert!(fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn previous_boot_recovery_retires_durable_artifacts_only_after_live_absence() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let prior_environment = NativeXtablesEnvironment::new(
        BootIdentity::parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap(),
        NetworkNamespaceIdentity::new(9, 10).unwrap(),
        OwnershipJournalIdentity::new([0x55; 32]).unwrap(),
        *target.routing_audit(),
    );
    let lease = acquire_unmutated_lease(&fixture.store, &prior_environment, &target);
    drop(lease);
    let mut owner = fixture.owner();

    let report = owner.recover().unwrap();

    assert_eq!(report.state(), NativeXtablesConvergedState::CleanAbsent);
    assert!(fixture.store.load_journal().unwrap().is_none());
    assert!(fixture.store.load_lease().unwrap().is_none());
    assert!(!fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn previous_boot_journal_before_lease_refuses_retirement_when_live_residue_exists() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let prior_environment = NativeXtablesEnvironment::new(
        BootIdentity::parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap(),
        NetworkNamespaceIdentity::new(9, 10).unwrap(),
        OwnershipJournalIdentity::new([0x55; 32]).unwrap(),
        *target.routing_audit(),
    );
    let intent = NativeOwnerIntent {
        step: NativeOwnerStep::Begin,
        target: Some(target.identity()),
        previous: None,
    };
    fixture
        .store
        .set_failpoint(Some(DurableEvent::JournalDurable));
    assert!(matches!(
        fixture.store.acquire(NativeXtablesJournalRecord::new(
            prior_environment.binding(target.identity().generation()),
            OwnershipJournalRevision::INITIAL,
            NativeXtablesJournalPhase::Activating,
            intent.payload().unwrap(),
        )),
        Err(NativeXtablesDurableError::InterruptedAt(
            DurableEvent::JournalDurable
        ))
    ));

    let mut owner = fixture.owner();
    owner.adapter.foreign_xtables[family_index(XtablesRestoreFamily::Ipv6)] = true;
    let error = owner
        .recover()
        .expect_err("previous-boot pre-lease state cannot retire across live residue");

    assert!(matches!(
        error,
        NativeXtablesOwnerError::LiveStateConflict(_)
    ));
    assert!(fixture.store.load_journal().unwrap().is_some());
    assert!(fixture.store.load_lease().unwrap().is_none());
    assert!(fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn restart_resolves_same_artifacts_by_bound_loopback_identity() {
    let other_binding = target_with_loopback_index(
        7,
        AddressHostFamilySelection::Ipv4,
        false,
        InterfaceIndex::new(1).unwrap(),
    );
    let active = target_with_loopback_index(
        7,
        AddressHostFamilySelection::Ipv4,
        false,
        InterfaceIndex::new(7).unwrap(),
    );
    assert_eq!(
        other_binding.source_artifact_digest(),
        active.source_artifact_digest()
    );
    assert_eq!(
        other_binding.identity().tool_digest(),
        active.identity().tool_digest()
    );
    assert_ne!(other_binding.identity(), active.identity());

    let fixture = Fixture::new([other_binding, active.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(active.clone()))
        .unwrap();
    let (adapter, resolver, durable) = owner.into_parts();
    let mut restarted =
        NativeXtablesOwner::new(adapter, resolver, durable, fixture.environment.clone());

    assert_eq!(
        restarted.recover().unwrap().state(),
        NativeXtablesConvergedState::Active(active.identity())
    );
}

#[test]
fn active_to_stopped_detaches_output_before_rule_route_and_private_cleanup() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    owner.adapter.operations.clear();

    let report = owner
        .converge(NativeXtablesDesiredTarget::Stopped)
        .expect("stop active target");
    assert_eq!(report.state(), NativeXtablesConvergedState::CleanAbsent);
    assert!(report.changed());
    assert_eq!(
        owner.adapter.operations,
        [
            "restore:ipv4:detach_output:7",
            "policy:ipv4:DeleteRule",
            "policy:ipv4:DeleteRoute",
            "restore:ipv4:detach_remaining:7",
            "restore:ipv4:retire:7",
        ]
    );
    assert!(owner.durable.load_lease().unwrap().is_none());
    assert_eq!(
        owner.durable.load_journal().unwrap().unwrap().phase(),
        NativeXtablesJournalPhase::CleanAbsent
    );
    owner
        .require_clean_absence(std::slice::from_ref(&target))
        .unwrap();
}

#[test]
fn dual_stack_partial_activation_rolls_back_to_proven_clean_absence() {
    let target = target(7, AddressHostFamilySelection::DualStack, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner.adapter.failures = vec![Failure {
        write: 8,
        after_apply: true,
    }];

    let error = owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .expect_err("partial dual-stack attach must not report active");
    assert!(matches!(
        error,
        NativeXtablesOwnerError::RolledBack {
            state: NativeXtablesConvergedState::CleanAbsent,
            ..
        }
    ));
    assert!(owner.durable.load_lease().unwrap().is_none());
    owner
        .require_clean_absence(std::slice::from_ref(&target))
        .unwrap();
}

#[test]
fn rollback_failure_retains_uncertain_journal_and_restart_recovery_cleans_it() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner.adapter.failures = vec![
        Failure {
            write: 4,
            after_apply: true,
        },
        Failure {
            write: 5,
            after_apply: false,
        },
    ];

    let error = owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .expect_err("failed compensation must retain uncertainty");
    assert!(matches!(error, NativeXtablesOwnerError::Uncertain { .. }));
    assert!(owner.durable.load_lease().unwrap().is_some());
    assert_eq!(
        owner.durable.load_journal().unwrap().unwrap().phase(),
        NativeXtablesJournalPhase::Uncertain
    );

    owner.adapter.failures.clear();
    owner.adapter.write_count = 0;
    let report = owner
        .recover()
        .expect("restart recovery reaches clean absence");
    assert_eq!(report.state(), NativeXtablesConvergedState::CleanAbsent);
    assert!(report.changed());
    assert!(owner.durable.load_lease().unwrap().is_none());
    owner
        .require_clean_absence(std::slice::from_ref(&target))
        .unwrap();
}

#[test]
fn recovery_accepts_replacement_state_after_old_private_retirement() {
    let old = target(7, AddressHostFamilySelection::Ipv4, false);
    let new = target(8, AddressHostFamilySelection::Ipv4, true);
    let fixture = Fixture::new([old.clone(), new.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(old))
        .unwrap();
    owner.adapter.write_count = 0;
    owner.adapter.failures = vec![
        Failure {
            write: 3,
            after_apply: true,
        },
        Failure {
            write: 4,
            after_apply: false,
        },
    ];
    assert!(matches!(
        owner.converge(NativeXtablesDesiredTarget::Active(new.clone())),
        Err(NativeXtablesOwnerError::Uncertain { .. })
    ));
    assert!(owner.durable.load_lease().unwrap().is_some());

    owner.adapter.failures.clear();
    let report = owner
        .recover()
        .expect("recover monotonic replacement cleanup");
    assert_eq!(report.state(), NativeXtablesConvergedState::CleanAbsent);
    owner
        .require_clean_absence(std::slice::from_ref(&new))
        .unwrap();
    assert!(owner.durable.load_lease().unwrap().is_none());
}

#[test]
fn opposite_family_routing_residue_blocks_clean_absence_publication() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .unwrap();
    let residue = target.routing_audit().identity(NetworkAddressFamily::Ipv6);
    owner.adapter.routes.push(residue.route());
    owner.adapter.rules.push(residue.rule());

    let error = owner
        .converge(NativeXtablesDesiredTarget::Stopped)
        .expect_err("opposite-family residue must block clean absence");

    assert!(matches!(error, NativeXtablesOwnerError::Uncertain { .. }));
    assert!(owner.durable.load_lease().unwrap().is_some());
}

#[test]
fn opposite_family_xtables_residue_blocks_clean_absence_publication() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target))
        .unwrap();
    owner.adapter.foreign_xtables[family_index(XtablesRestoreFamily::Ipv6)] = true;

    let error = owner
        .converge(NativeXtablesDesiredTarget::Stopped)
        .expect_err("opposite-family xtables residue must block clean absence");

    assert!(matches!(error, NativeXtablesOwnerError::Uncertain { .. }));
    assert!(owner.durable.load_lease().unwrap().is_some());
}

#[test]
fn stale_loopback_binding_blocks_policy_deletion() {
    let target = target(7, AddressHostFamilySelection::Ipv4, false);
    let fixture = Fixture::new([target.clone()]);
    let mut owner = fixture.owner();
    owner
        .converge(NativeXtablesDesiredTarget::Active(target))
        .unwrap();
    owner.adapter.interface_identity_valid = false;
    owner.adapter.operations.clear();

    let error = owner
        .converge(NativeXtablesDesiredTarget::Stopped)
        .expect_err("stale loopback identity must block policy deletion");

    assert!(matches!(error, NativeXtablesOwnerError::Uncertain { .. }));
    assert!(
        owner
            .adapter
            .operations
            .iter()
            .all(|operation| !operation.contains("Delete"))
    );
}

#[test]
fn every_dual_stack_activation_write_boundary_rolls_back_or_recovers_cleanly() {
    for write in 1..=8 {
        for after_apply in [false, true] {
            let target = target(7, AddressHostFamilySelection::DualStack, false);
            let fixture = Fixture::new([target.clone()]);
            let mut owner = fixture.owner();
            owner.adapter.failures = vec![Failure { write, after_apply }];
            let error = owner
                .converge(NativeXtablesDesiredTarget::Active(target.clone()))
                .expect_err("injected activation boundary must not reach desired active state");
            match error {
                NativeXtablesOwnerError::RolledBack {
                    state: NativeXtablesConvergedState::CleanAbsent,
                    ..
                } => {}
                NativeXtablesOwnerError::Uncertain { .. } => {
                    owner.adapter.failures.clear();
                    owner.recover().unwrap();
                }
                other => panic!(
                    "write {write} after_apply={after_apply} returned unexpected error: {other}"
                ),
            }
            owner
                .require_clean_absence(std::slice::from_ref(&target))
                .unwrap();
            assert!(owner.durable.load_lease().unwrap().is_none());
        }
    }
}

#[test]
fn every_replacement_write_boundary_restores_the_old_generation() {
    for write in 1..=3 {
        for after_apply in [false, true] {
            let old = target(7, AddressHostFamilySelection::Ipv4, false);
            let new = target(8, AddressHostFamilySelection::Ipv4, true);
            let fixture = Fixture::new([old.clone(), new.clone()]);
            let mut owner = fixture.owner();
            owner
                .converge(NativeXtablesDesiredTarget::Active(old.clone()))
                .unwrap();
            owner.adapter.write_count = 0;
            owner.adapter.failures = vec![Failure { write, after_apply }];
            let error = owner
                .converge(NativeXtablesDesiredTarget::Active(new.clone()))
                .expect_err("injected replacement boundary must roll back");
            assert!(matches!(
                error,
                NativeXtablesOwnerError::RolledBack {
                    state: NativeXtablesConvergedState::Active(identity),
                    ..
                } if identity == old.identity()
            ));
            assert!(owner.target_is_exact_active(&old).unwrap());
            assert_eq!(
                owner
                    .durable
                    .load_journal()
                    .unwrap()
                    .unwrap()
                    .binding()
                    .generation(),
                old.identity().generation()
            );
        }
    }
}

#[test]
fn every_stop_write_boundary_reaches_clean_absence_after_retry_recovery() {
    for write in 1..=5 {
        for after_apply in [false, true] {
            let target = target(7, AddressHostFamilySelection::Ipv4, false);
            let fixture = Fixture::new([target.clone()]);
            let mut owner = fixture.owner();
            owner
                .converge(NativeXtablesDesiredTarget::Active(target.clone()))
                .unwrap();
            owner.adapter.write_count = 0;
            owner.adapter.failures = vec![Failure { write, after_apply }];
            if owner.converge(NativeXtablesDesiredTarget::Stopped).is_err() {
                owner.adapter.failures.clear();
                owner.recover().unwrap();
            }
            owner
                .require_clean_absence(std::slice::from_ref(&target))
                .unwrap();
            assert!(owner.durable.load_lease().unwrap().is_none());
        }
    }
}

#[test]
#[ignore = "requires UID 0 in a disposable Linux/Android network namespace"]
fn privileged_real_owner_apply_recover_and_stop_is_exactly_invertible() {
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid != 0 {
        if std::env::var_os("FLUX_NATIVE_OWNER_TEST_REQUIRED").is_some() {
            panic!("FLUX_NATIVE_OWNER_TEST_REQUIRED needs UID 0");
        }
        return;
    }
    let registration_before = registration_snapshot();
    require_registration(&registration_before, "targets", "TPROXY");
    require_registration(&registration_before, "targets", "MARK");
    require_registration(&registration_before, "matches", "mark");
    require_registration(&registration_before, "matches", "owner");

    let tool_root = std::env::var_os("FLUX_NATIVE_XTABLES_TOOL_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            if cfg!(target_os = "android") {
                "/system/bin".into()
            } else {
                "/usr/sbin".into()
            }
        });
    let tools = XtablesToolSetProcessAdapter::discover_standard(
        tool_root,
        true,
        XtablesRestoreProcessConfig::new(2, Duration::from_secs(5)).unwrap(),
    )
    .expect("discover coherent real xtables tool set");
    let tool_digest = *tools.identity().digest().as_bytes();
    let target = target_with_tool_digest(
        9_001,
        AddressHostFamilySelection::DualStack,
        false,
        tool_digest,
    );
    let temp = TempDir::new().expect("create disposable durable root");
    let namespace = std::fs::metadata("/proc/self/ns/net").expect("stat current network namespace");
    let environment = NativeXtablesEnvironment::new(
        BootIdentity::parse(
            &std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .expect("read boot identity"),
        )
        .expect("parse boot identity"),
        NetworkNamespaceIdentity::new(namespace.dev(), namespace.ino())
            .expect("nonzero network namespace inode"),
        OwnershipJournalIdentity::new([0x91; 32]).unwrap(),
        *target.routing_audit(),
    );
    let durable = NativeXtablesDurableStore::new(temp.path().join("run"));
    let resolver = FakeResolver {
        targets: vec![target.clone()],
    };
    let adapter = NativeXtablesProcessOwnerAdapter::new(tools);
    let mut owner = NativeXtablesOwner::new(adapter, resolver, durable, environment.clone());

    let report = owner
        .converge(NativeXtablesDesiredTarget::Active(target.clone()))
        .expect("real owner activation");
    assert_eq!(
        report.state(),
        NativeXtablesConvergedState::Active(target.identity())
    );
    let (adapter, resolver, durable) = owner.into_parts();
    let mut restarted = NativeXtablesOwner::new(adapter, resolver, durable, environment);
    assert_eq!(
        restarted.recover().unwrap().state(),
        NativeXtablesConvergedState::Active(target.identity())
    );
    assert_eq!(
        restarted
            .converge(NativeXtablesDesiredTarget::Stopped)
            .unwrap()
            .state(),
        NativeXtablesConvergedState::CleanAbsent
    );
    restarted
        .require_clean_absence(std::slice::from_ref(&target))
        .unwrap();
    assert_eq!(registration_snapshot(), registration_before);
}

struct Fixture {
    _temp: TempDir,
    store: NativeXtablesDurableStore,
    environment: NativeXtablesEnvironment,
    targets: Vec<NativeXtablesAdmittedTarget>,
}

impl Fixture {
    fn new(targets: impl IntoIterator<Item = NativeXtablesAdmittedTarget>) -> Self {
        let temp = TempDir::new().unwrap();
        let targets = targets.into_iter().collect::<Vec<_>>();
        let routing_audit = *targets
            .last()
            .expect("owner fixture requires at least one target")
            .routing_audit();
        Self {
            store: NativeXtablesDurableStore::new(temp.path().join("run")),
            environment: NativeXtablesEnvironment::new(
                BootIdentity::parse("11111111-2222-3333-4444-555555555555").unwrap(),
                NetworkNamespaceIdentity::new(9, 10).unwrap(),
                OwnershipJournalIdentity::new([0x55; 32]).unwrap(),
                routing_audit,
            ),
            targets,
            _temp: temp,
        }
    }

    fn owner(&self) -> NativeXtablesOwner<FakeAdapter, FakeResolver> {
        NativeXtablesOwner::new(
            FakeAdapter::new(self.targets.clone()),
            FakeResolver {
                targets: self.targets.clone(),
            },
            self.store.clone(),
            self.environment.clone(),
        )
    }
}

fn acquire_unmutated_lease(
    store: &NativeXtablesDurableStore,
    environment: &NativeXtablesEnvironment,
    target: &NativeXtablesAdmittedTarget,
) -> NativeXtablesTransitionLease {
    let intent = NativeOwnerIntent {
        step: NativeOwnerStep::Begin,
        target: Some(target.identity()),
        previous: None,
    };
    store
        .acquire(NativeXtablesJournalRecord::new(
            environment.binding(target.identity().generation()),
            OwnershipJournalRevision::INITIAL,
            NativeXtablesJournalPhase::Activating,
            intent.payload().unwrap(),
        ))
        .unwrap()
}

fn create_same_scope_writer_lock(
    store: &NativeXtablesDurableStore,
    environment: &NativeXtablesEnvironment,
) {
    let lock = store.writer_lock_path();
    std::fs::create_dir_all(&lock).unwrap();
    let mut encoded = format!(
        "flux-native-xtables-writer-owner-v1\ncomponent=native_xtables\nboot={}\nnetns_device={}\nnetns_inode={}\nowner={}\n",
        environment.boot_identity.as_str(),
        environment.network_namespace.device(),
        environment.network_namespace.inode(),
        encode_hex(environment.journal_identity.as_bytes()),
    )
    .into_bytes();
    let checksum = Sha256::digest(&encoded);
    encoded.extend_from_slice(format!("sha256={}\n", encode_hex(&checksum)).as_bytes());
    std::fs::write(lock.join("native-owner"), encoded).unwrap();
}

#[derive(Clone)]
struct FakeResolver {
    targets: Vec<NativeXtablesAdmittedTarget>,
}

impl NativeXtablesTargetResolver for FakeResolver {
    fn resolve(
        &mut self,
        identity: NativeXtablesTargetIdentity,
    ) -> Result<NativeXtablesAdmittedTarget, Box<str>> {
        self.targets
            .iter()
            .find(|target| target.identity() == identity)
            .cloned()
            .ok_or_else(|| "target not registered".into())
    }
}

#[derive(Clone, Copy)]
struct Failure {
    write: usize,
    after_apply: bool,
}

#[derive(Clone, Default)]
struct FakeFamilyState {
    prepared: Vec<NativeXtablesTargetIdentity>,
    stable: Option<NativeXtablesTargetIdentity>,
    output_attached: bool,
    canary_selector: Option<XtablesRestoreArtifact>,
    canary_observation: Option<XtablesRestoreArtifact>,
}

#[derive(Clone, Copy)]
enum FakeCanaryRouteResult {
    Resolved(RouteTableId),
    Rejected(NonZeroI32),
    AmbiguousFailure,
}

#[derive(Clone)]
enum FakeCanaryRoutePostAction {
    DropSelector(XtablesRestoreFamily),
    DropObservation(XtablesRestoreFamily),
    DropPolicyRules,
    SubstituteTarget {
        family: XtablesRestoreFamily,
        identity: NativeXtablesTargetIdentity,
    },
    CorruptJournal(PathBuf),
}

#[derive(Clone)]
struct FakeAdapter {
    targets: Vec<NativeXtablesAdmittedTarget>,
    families: [FakeFamilyState; 2],
    routes: Vec<ManagedLocalRouteIdentity>,
    rules: Vec<ManagedFwmarkRuleIdentity>,
    operations: Vec<&'static str>,
    failures: Vec<Failure>,
    write_count: usize,
    interface_identity_valid: bool,
    foreign_xtables: [bool; 2],
    canary_route_queries: Vec<NativeCaptureCanaryRouteQuery>,
    canary_route_result: FakeCanaryRouteResult,
    canary_route_post_action: Option<FakeCanaryRoutePostAction>,
}

impl FakeAdapter {
    fn new(targets: Vec<NativeXtablesAdmittedTarget>) -> Self {
        Self {
            targets,
            families: std::array::from_fn(|_| FakeFamilyState::default()),
            routes: Vec::new(),
            rules: Vec::new(),
            operations: Vec::new(),
            failures: Vec::new(),
            write_count: 0,
            interface_identity_valid: true,
            foreign_xtables: [false; 2],
            canary_route_queries: Vec::new(),
            canary_route_result: FakeCanaryRouteResult::Resolved(RouteTableId::from_raw(20_253)),
            canary_route_post_action: None,
        }
    }

    fn family_state(&self, family: XtablesRestoreFamily) -> &FakeFamilyState {
        &self.families[family_index(family)]
    }

    fn family_state_mut(&mut self, family: XtablesRestoreFamily) -> &mut FakeFamilyState {
        &mut self.families[family_index(family)]
    }

    fn failure(&self, after_apply: bool) -> bool {
        self.failures
            .iter()
            .any(|failure| failure.write == self.write_count && failure.after_apply == after_apply)
    }

    fn target_by_identity(
        &self,
        identity: NativeXtablesTargetIdentity,
    ) -> &NativeXtablesAdmittedTarget {
        self.targets
            .iter()
            .find(|target| target.identity() == identity)
            .unwrap()
    }

    fn classify_restore(
        &self,
        family: XtablesRestoreFamily,
        artifact: &XtablesRestoreArtifact,
    ) -> (&'static str, NativeXtablesTargetIdentity) {
        if artifact.context().action() == XtablesRestoreAction::Replace {
            let flush = artifact
                .transactions()
                .first()
                .and_then(|transaction| transaction.entries().first())
                .and_then(|entry| match entry {
                    XtablesRestoreEntry::Command(command)
                        if command.kind() == XtablesRestoreCommandKind::Flush =>
                    {
                        Some(command)
                    }
                    XtablesRestoreEntry::ChainDeclaration(_) | XtablesRestoreEntry::Command(_) => {
                        None
                    }
                });
            let target = flush.and_then(|flush| {
                self.targets.iter().find_map(|target| {
                    let family_plan = target.topology().family(family)?;
                    let slot = if family_plan.local_output_canary_selector() == Some(flush.chain())
                    {
                        "selector"
                    } else if family_plan.local_output_canary_observation() == Some(flush.chain()) {
                        "observation"
                    } else {
                        return None;
                    };
                    Some((target, flush, slot))
                })
            });
            if let Some((target, flush, slot)) = target {
                let [transaction] = artifact.transactions() else {
                    panic!("selector replacement must contain one transaction");
                };
                let [XtablesRestoreEntry::Command(_), remaining @ ..] = transaction.entries()
                else {
                    unreachable!("the first selector entry was already classified as a flush");
                };
                assert!(remaining.iter().all(|entry| {
                    matches!(
                        entry,
                        XtablesRestoreEntry::Command(command)
                            if command.kind() == XtablesRestoreCommandKind::Append
                                && command.chain() == flush.chain()
                    )
                }));
                let kind = match (slot, remaining.is_empty()) {
                    ("selector", false) => "populate_canary_selector",
                    ("selector", true) => "retire_canary_selector",
                    ("observation", false) => "populate_canary_observation",
                    ("observation", true) => "retire_canary_observation",
                    _ => unreachable!(),
                };
                return (kind, target.identity());
            }
        }
        for target in &self.targets {
            let Some(plan) = target.topology().family(family) else {
                continue;
            };
            for (name, candidate) in [
                ("prepare", plan.prepare()),
                ("retire", plan.retire()),
                ("install", plan.install()),
                ("switch", plan.switch()),
                ("detach_remaining", plan.detach_remaining()),
            ] {
                if candidate == artifact {
                    return (name, target.identity());
                }
            }
            if plan.detach_output() == Some(artifact) {
                return ("detach_output", target.identity());
            }
        }
        panic!("unregistered restore artifact")
    }

    fn apply_restore(
        &mut self,
        family: XtablesRestoreFamily,
        kind: &str,
        identity: NativeXtablesTargetIdentity,
        artifact: &XtablesRestoreArtifact,
    ) {
        let state = self.family_state_mut(family);
        match kind {
            "prepare" => {
                if !state.prepared.contains(&identity) {
                    state.prepared.push(identity);
                    state.prepared.sort_unstable();
                }
            }
            "install" | "switch" => {
                state.stable = Some(identity);
                state.output_attached = true;
            }
            "detach_output" => state.output_attached = false,
            "detach_remaining" => {
                state.stable = None;
                state.output_attached = false;
            }
            "retire" => state.prepared.retain(|candidate| *candidate != identity),
            "populate_canary_selector" => state.canary_selector = Some(artifact.clone()),
            "retire_canary_selector" => state.canary_selector = None,
            "populate_canary_observation" => state.canary_observation = Some(artifact.clone()),
            "retire_canary_observation" => state.canary_observation = None,
            _ => unreachable!(),
        }
    }

    fn projection(
        &self,
        family: XtablesRestoreFamily,
    ) -> Result<XtablesSaveProjection, NativeXtablesAdapterError> {
        let state = self.family_state(family);
        if state.prepared.is_empty() && state.stable.is_none() {
            return project_xtables_save(b"*mangle\nCOMMIT\n", family).map_err(|error| {
                NativeXtablesAdapterError::new(
                    "fake empty save",
                    NativeMutationCertainty::NotMutated,
                    error.to_string(),
                )
            });
        }
        let prepared = state
            .prepared
            .iter()
            .map(|identity| self.target_by_identity(*identity))
            .collect::<Vec<_>>();
        let stable = state
            .stable
            .map(|identity| self.target_by_identity(identity));
        let projection = expected_state(
            &prepared,
            stable,
            family,
            stable.is_some() && !state.output_attached,
        )
        .map(|expected| expected.projection().clone());
        let projection = match (projection, &state.canary_selector) {
            (Ok(projection), Some(selector)) => projection.with_owned_chain_replacement(selector),
            (Ok(projection), None) => Ok(projection),
            (Err(error), _) => {
                return Err(NativeXtablesAdapterError::new(
                    "fake save",
                    NativeMutationCertainty::NotMutated,
                    error.to_string(),
                ));
            }
        };
        let projection = match (projection, &state.canary_observation) {
            (Ok(projection), Some(observation)) => {
                projection.with_owned_chain_replacement(observation)
            }
            (Ok(projection), None) => Ok(projection),
            (Err(error), _) => Err(error),
        };
        projection.map_err(|error| {
            NativeXtablesAdapterError::new(
                "fake save",
                NativeMutationCertainty::NotMutated,
                error.to_string(),
            )
        })
    }
}

impl NativeXtablesOwnerAdapter for FakeAdapter {
    fn tool_digest(&self) -> [u8; 32] {
        TOOL_DIGEST
    }

    fn validate_interface_identity(
        &mut self,
        _identity: ManagedInterfaceIdentity,
    ) -> Result<(), NativeXtablesAdapterError> {
        if self.interface_identity_valid {
            Ok(())
        } else {
            Err(NativeXtablesAdapterError::new(
                "fake interface identity validation",
                NativeMutationCertainty::NotMutated,
                "bound loopback identity is stale",
            ))
        }
    }

    fn restore(
        &mut self,
        family: XtablesRestoreFamily,
        artifact: &XtablesRestoreArtifact,
    ) -> Result<(), NativeXtablesAdapterError> {
        let (kind, identity) = self.classify_restore(family, artifact);
        self.write_count += 1;
        if self.failure(false) {
            return Err(NativeXtablesAdapterError::new(
                "fake restore",
                NativeMutationCertainty::NotMutated,
                "injected failure",
            ));
        }
        self.apply_restore(family, kind, identity, artifact);
        self.operations.push(operation(kind, family, identity));
        if self.failure(true) {
            return Err(NativeXtablesAdapterError::new(
                "fake restore",
                NativeMutationCertainty::MayHaveMutated,
                "injected post-apply failure",
            ));
        }
        Ok(())
    }

    fn observe_xtables(
        &mut self,
        family: XtablesRestoreFamily,
    ) -> Result<XtablesSaveProjection, NativeXtablesAdapterError> {
        if self.foreign_xtables[family_index(family)] {
            let save = match family {
                XtablesRestoreFamily::Ipv4 => {
                    b"*mangle\n:FLX4O0000009999 - [0:0]\n-A FLX4O0000009999 -j RETURN\nCOMMIT\n"
                        .as_slice()
                }
                XtablesRestoreFamily::Ipv6 => {
                    b"*mangle\n:FLX6O0000009999 - [0:0]\n-A FLX6O0000009999 -j RETURN\nCOMMIT\n"
                        .as_slice()
                }
            };
            return project_xtables_save(save, family).map_err(|error| {
                NativeXtablesAdapterError::new(
                    "fake opposite-family xtables residue",
                    NativeMutationCertainty::NotMutated,
                    error.to_string(),
                )
            });
        }
        self.projection(family)
    }

    fn mutate_policy_routing(
        &mut self,
        mutation: PolicyRoutingMutation,
    ) -> Result<(), NativeXtablesAdapterError> {
        self.write_count += 1;
        if self.failure(false) {
            return Err(NativeXtablesAdapterError::new(
                "fake policy mutation",
                NativeMutationCertainty::NotMutated,
                "injected failure",
            ));
        }
        let (family, kind) = match mutation {
            PolicyRoutingMutation::AddRoute(route) => {
                if !self.routes.contains(&route) {
                    self.routes.push(route);
                }
                (route.family(), PolicyRoutingMutationKind::AddRoute)
            }
            PolicyRoutingMutation::DeleteRoute(route) => {
                self.routes.retain(|candidate| *candidate != route);
                (route.family(), PolicyRoutingMutationKind::DeleteRoute)
            }
            PolicyRoutingMutation::AddRule(rule) => {
                if !self.rules.contains(&rule) {
                    self.rules.push(rule);
                }
                (rule.family(), PolicyRoutingMutationKind::AddRule)
            }
            PolicyRoutingMutation::DeleteRule(rule) => {
                self.rules.retain(|candidate| *candidate != rule);
                (rule.family(), PolicyRoutingMutationKind::DeleteRule)
            }
        };
        self.operations.push(policy_operation(family, kind));
        if self.failure(true) {
            return Err(NativeXtablesAdapterError::new(
                "fake policy mutation",
                NativeMutationCertainty::MayHaveMutated,
                "injected post-apply failure",
            ));
        }
        Ok(())
    }

    fn observe_policy_routing(
        &mut self,
        identity: ManagedPolicyRoutingIdentity,
    ) -> Result<NativePolicyRoutingObservation, NativeXtablesAdapterError> {
        Ok(NativePolicyRoutingObservation::new(
            usize::from(self.routes.contains(&identity.route())),
            0,
            usize::from(self.rules.contains(&identity.rule())),
            0,
        ))
    }

    fn observe_canary_route(
        &mut self,
        query: NativeCaptureCanaryRouteQuery,
    ) -> Result<NativeCaptureCanaryRouteOutcome, NativeXtablesAdapterError> {
        self.canary_route_queries.push(query);
        let outcome = match self.canary_route_result {
            FakeCanaryRouteResult::Resolved(table) => NativeCaptureCanaryRouteOutcome::Resolved(
                NativeCaptureCanaryRouteObservation::new(query, table, Instant::now()),
            ),
            FakeCanaryRouteResult::Rejected(errno) => NativeCaptureCanaryRouteOutcome::Rejected(
                NativeCaptureCanaryRouteRejection::new(errno),
            ),
            FakeCanaryRouteResult::AmbiguousFailure => {
                return Err(NativeXtablesAdapterError::new(
                    "fake canary route lookup",
                    NativeMutationCertainty::NotMutated,
                    "ambiguous route response",
                ));
            }
        };
        if let Some(action) = self.canary_route_post_action.take() {
            match action {
                FakeCanaryRoutePostAction::DropSelector(family) => {
                    self.family_state_mut(family).canary_selector = None;
                }
                FakeCanaryRoutePostAction::DropObservation(family) => {
                    self.family_state_mut(family).canary_observation = None;
                }
                FakeCanaryRoutePostAction::DropPolicyRules => self.rules.clear(),
                FakeCanaryRoutePostAction::SubstituteTarget { family, identity } => {
                    let state = self.family_state_mut(family);
                    state.prepared.clear();
                    state.prepared.push(identity);
                    state.stable = Some(identity);
                    state.canary_selector = None;
                    state.canary_observation = None;
                }
                FakeCanaryRoutePostAction::CorruptJournal(path) => {
                    let mut encoded = std::fs::read(&path).unwrap();
                    encoded[0] ^= 0xff;
                    std::fs::write(path, encoded).unwrap();
                }
            }
        }
        Ok(outcome)
    }
}

fn target(
    generation: u32,
    families: AddressHostFamilySelection,
    forwarded_ingress: bool,
) -> NativeXtablesAdmittedTarget {
    target_with_tool_digest(generation, families, forwarded_ingress, TOOL_DIGEST)
}

fn canary_target(
    generation: u32,
    families: AddressHostFamilySelection,
) -> NativeXtablesAdmittedTarget {
    admit_target(
        lowered_canary_artifacts(generation, families),
        false,
        InterfaceIndex::new(1).unwrap(),
        TOOL_DIGEST,
    )
}

fn target_with_tool_digest(
    generation: u32,
    families: AddressHostFamilySelection,
    forwarded_ingress: bool,
    tool_digest: [u8; 32],
) -> NativeXtablesAdmittedTarget {
    target_with_loopback_index_and_tool_digest(
        generation,
        families,
        forwarded_ingress,
        InterfaceIndex::new(1).unwrap(),
        tool_digest,
    )
}

fn target_with_loopback_index(
    generation: u32,
    families: AddressHostFamilySelection,
    forwarded_ingress: bool,
    loopback_index: InterfaceIndex,
) -> NativeXtablesAdmittedTarget {
    target_with_loopback_index_and_tool_digest(
        generation,
        families,
        forwarded_ingress,
        loopback_index,
        TOOL_DIGEST,
    )
}

fn target_with_loopback_index_and_tool_digest(
    generation: u32,
    families: AddressHostFamilySelection,
    forwarded_ingress: bool,
    loopback_index: InterfaceIndex,
    tool_digest: [u8; 32],
) -> NativeXtablesAdmittedTarget {
    admit_target(
        lowered_artifacts(generation, families, forwarded_ingress),
        forwarded_ingress,
        loopback_index,
        tool_digest,
    )
}

fn admit_target(
    artifacts: XtablesCaptureArtifactSet,
    forwarded_ingress: bool,
    loopback_index: InterfaceIndex,
    tool_digest: [u8; 32],
) -> NativeXtablesAdmittedTarget {
    let identities = routing_identities(&artifacts, loopback_index);
    let audit_artifacts = lowered_artifacts(
        artifacts.namespace().generation().get(),
        AddressHostFamilySelection::DualStack,
        forwarded_ingress,
    );
    let audit_identities: [ManagedPolicyRoutingIdentity; 2] =
        routing_identities(&audit_artifacts, loopback_index)
            .try_into()
            .expect("dual-stack lowering has exactly two routing identities");
    let routing_audit = NativePolicyRoutingAudit::new(audit_identities).unwrap();
    NativeXtablesAdmittedTarget::admit_for_test(artifacts, identities, routing_audit, tool_digest)
        .unwrap()
}

fn lowered_artifacts(
    generation: u32,
    families: AddressHostFamilySelection,
    forwarded_ingress: bool,
) -> XtablesCaptureArtifactSet {
    lower_artifacts(generation, families, forwarded_ingress, false)
}

fn lowered_canary_artifacts(
    generation: u32,
    families: AddressHostFamilySelection,
) -> XtablesCaptureArtifactSet {
    lower_artifacts(generation, families, false, true)
}

fn lower_artifacts(
    generation: u32,
    families: AddressHostFamilySelection,
    forwarded_ingress: bool,
    reserve_canary_selector: bool,
) -> XtablesCaptureArtifactSet {
    let scope = CaptureTrafficScope::new(families, true, forwarded_ingress).unwrap();
    let forwarded = forwarded_ingress.then_some(exact("wlan0"));
    let program = compile_capture_program(CaptureProgramRequest::new(
        scope,
        EngineCredentials::new(uid(1000), gid(1000)),
        CaptureBypassPolicy::new(std::iter::empty::<CaptureIpPrefix>()).unwrap(),
        None,
        CaptureInterfacePolicy::new([], forwarded, []).unwrap(),
        CaptureApplicationPolicy::new(CaptureApplicationMode::All, []).unwrap(),
        CaptureProtocolSet::TCP_AND_UDP,
    ))
    .unwrap();
    let mut request = XtablesCaptureLoweringRequest::new(
        program.program(),
        XtablesCaptureNamespace::new(GenerationId::new(generation).unwrap()),
        XtablesTproxyTarget::new(
            NonZeroU16::new(1536).unwrap(),
            FwmarkCandidate::new(MARK_MASK, PROXY_MARK, BYPASS_MARK).unwrap(),
        ),
    )
    .with_local_output_routing(routing(families));
    if reserve_canary_selector {
        request = request.with_local_output_canary_selector_slot();
    }
    lower_xtables_capture(request).unwrap()
}

fn routing_identities(
    artifacts: &XtablesCaptureArtifactSet,
    loopback_index: InterfaceIndex,
) -> Vec<ManagedPolicyRoutingIdentity> {
    [XtablesRestoreFamily::Ipv4, XtablesRestoreFamily::Ipv6]
        .into_iter()
        .filter_map(|family| {
            artifacts
                .pair(family)
                .and_then(|pair| pair.local_output())
                .map(|requirements| {
                    ManagedPolicyRoutingIdentity::bind(requirements.routing(), loopback_index)
                        .unwrap()
                })
        })
        .collect()
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
        families.includes(NetworkAddressFamily::Ipv4).then(target),
        families.includes(NetworkAddressFamily::Ipv6).then(target),
    )
    .unwrap()
}

fn family_index(family: XtablesRestoreFamily) -> usize {
    match family {
        XtablesRestoreFamily::Ipv4 => 0,
        XtablesRestoreFamily::Ipv6 => 1,
    }
}

fn operation(
    kind: &str,
    family: XtablesRestoreFamily,
    identity: NativeXtablesTargetIdentity,
) -> &'static str {
    match (kind, family, identity.generation().get()) {
        ("prepare", XtablesRestoreFamily::Ipv4, 7) => "restore:ipv4:prepare:7",
        ("prepare", XtablesRestoreFamily::Ipv4, 8) => "restore:ipv4:prepare:8",
        ("prepare", XtablesRestoreFamily::Ipv6, 7) => "restore:ipv6:prepare:7",
        ("install", XtablesRestoreFamily::Ipv4, 7) => "restore:ipv4:install:7",
        ("install", XtablesRestoreFamily::Ipv6, 7) => "restore:ipv6:install:7",
        ("switch", XtablesRestoreFamily::Ipv4, 7) => "restore:ipv4:switch:7",
        ("switch", XtablesRestoreFamily::Ipv4, 8) => "restore:ipv4:switch:8",
        ("retire", XtablesRestoreFamily::Ipv4, 7) => "restore:ipv4:retire:7",
        ("retire", XtablesRestoreFamily::Ipv4, 8) => "restore:ipv4:retire:8",
        ("retire", XtablesRestoreFamily::Ipv6, 7) => "restore:ipv6:retire:7",
        ("detach_output", XtablesRestoreFamily::Ipv4, 7) => "restore:ipv4:detach_output:7",
        ("detach_output", XtablesRestoreFamily::Ipv6, 7) => "restore:ipv6:detach_output:7",
        ("detach_remaining", XtablesRestoreFamily::Ipv4, 7) => "restore:ipv4:detach_remaining:7",
        ("detach_remaining", XtablesRestoreFamily::Ipv6, 7) => "restore:ipv6:detach_remaining:7",
        ("populate_canary_selector", XtablesRestoreFamily::Ipv4, 7) => {
            "restore:ipv4:populate_canary_selector:7"
        }
        ("populate_canary_selector", XtablesRestoreFamily::Ipv6, 7) => {
            "restore:ipv6:populate_canary_selector:7"
        }
        ("populate_canary_observation", XtablesRestoreFamily::Ipv4, 7) => {
            "restore:ipv4:populate_canary_observation:7"
        }
        ("populate_canary_observation", XtablesRestoreFamily::Ipv6, 7) => {
            "restore:ipv6:populate_canary_observation:7"
        }
        ("retire_canary_observation", XtablesRestoreFamily::Ipv4, 7) => {
            "restore:ipv4:retire_canary_observation:7"
        }
        ("retire_canary_observation", XtablesRestoreFamily::Ipv6, 7) => {
            "restore:ipv6:retire_canary_observation:7"
        }
        ("retire_canary_selector", XtablesRestoreFamily::Ipv4, 7) => {
            "restore:ipv4:retire_canary_selector:7"
        }
        ("retire_canary_selector", XtablesRestoreFamily::Ipv6, 7) => {
            "restore:ipv6:retire_canary_selector:7"
        }
        _ => "restore:other",
    }
}

fn canary_selector(ipv6: bool) -> NativeCaptureCanarySelector {
    NativeCaptureCanarySelector::new(
        NonZeroU32::new(2_000).unwrap(),
        Ipv4Addr::new(198, 18, 0, 2),
        ipv6.then_some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
        NonZeroU16::new(10_080).unwrap(),
        NonZeroU16::new(10_081).unwrap(),
        NonZeroU16::new(10_053).unwrap(),
    )
    .unwrap()
}

fn canary_attempt(ipv6: bool) -> NativeCaptureCanaryAttempt {
    NativeCaptureCanaryAttempt::new(canary_selector(ipv6), [0x11; 32], [0x22; 32], [0x33; 32])
        .unwrap()
}

fn canary_route_query(destination: SocketAddr) -> NativeCaptureCanaryRouteQuery {
    NativeCaptureCanaryRouteQuery::new(
        destination,
        NonZeroU32::new(1_000).unwrap(),
        PROXY_MARK,
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap()
}

fn policy_operation(family: NetworkAddressFamily, kind: PolicyRoutingMutationKind) -> &'static str {
    match (family, kind) {
        (NetworkAddressFamily::Ipv4, PolicyRoutingMutationKind::AddRoute) => "policy:ipv4:AddRoute",
        (NetworkAddressFamily::Ipv4, PolicyRoutingMutationKind::AddRule) => "policy:ipv4:AddRule",
        (NetworkAddressFamily::Ipv4, PolicyRoutingMutationKind::DeleteRule) => {
            "policy:ipv4:DeleteRule"
        }
        (NetworkAddressFamily::Ipv4, PolicyRoutingMutationKind::DeleteRoute) => {
            "policy:ipv4:DeleteRoute"
        }
        (NetworkAddressFamily::Ipv6, PolicyRoutingMutationKind::AddRoute) => "policy:ipv6:AddRoute",
        (NetworkAddressFamily::Ipv6, PolicyRoutingMutationKind::AddRule) => "policy:ipv6:AddRule",
        (NetworkAddressFamily::Ipv6, PolicyRoutingMutationKind::DeleteRule) => {
            "policy:ipv6:DeleteRule"
        }
        (NetworkAddressFamily::Ipv6, PolicyRoutingMutationKind::DeleteRoute) => {
            "policy:ipv6:DeleteRoute"
        }
    }
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

fn registration_snapshot() -> Vec<(Box<str>, Box<str>)> {
    let mut entries = Vec::new();
    for (kind, path) in [
        ("targets", Path::new("/proc/net/ip_tables_targets")),
        ("matches", Path::new("/proc/net/ip_tables_matches")),
        ("modules", Path::new("/proc/modules")),
    ] {
        let contents = std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        for line in contents.lines() {
            entries.push((kind.into(), line.into()));
        }
    }
    entries.sort();
    entries
}

fn require_registration(snapshot: &[(Box<str>, Box<str>)], kind: &str, name: &str) {
    assert!(
        snapshot
            .iter()
            .any(|(entry_kind, entry)| entry_kind.as_ref() == kind && entry.as_ref() == name),
        "required already-active {kind} registration {name} is missing"
    );
}
