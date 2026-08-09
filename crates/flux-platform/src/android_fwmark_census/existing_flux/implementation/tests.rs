use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use flux_core::{
    AndroidNetdSourceProfile, CapabilityProfile, CapabilityProfileRevision, FwmarkCandidate,
    FwmarkCensusCoverageState, FwmarkEvidenceSource, FwmarkPlane, InterfaceAddressRecord,
    InterfaceHardwareType, InterfaceIndex, InterfaceLinkFlags, InterfaceLinkRecord, InterfaceName,
    KernelFacts, NetworkAddressFamily, NetworkInventory, NetworkInventoryTracker,
    NetworkRouteRecord, NetworkRuleRecord, Observation, RouteFlags, RoutePath, RoutePrefix,
    RouteProperties, RouteProtocol, RouteScope, RouteTableId, RouteType, RuleAction, RuleFlags,
    RuleFwMark, RulePrefix, RulePriority, RuleProperties, RuleProtocol, RuleTableId,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::*;
use crate::android_fwmark_census::{
    AndroidXtablesFwmarkObservation, observe_android_xtables_fwmarks,
};

struct Fixture {
    _temp: TempDir,
    proc_root: PathBuf,
    durable_root: PathBuf,
    inventory: NetworkInventory,
    capability_profile: CapabilityProfile,
    network_namespace: flux_core::NetworkNamespaceIdentity,
    xtables: AndroidXtablesFwmarkObservation,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary observation root");
        let proc_root = temp.path().join("proc");
        fs::create_dir(&proc_root).expect("create proc fixture root");
        write_process(&proc_root, 1, "init", 1);
        let network_namespace =
            flux_core::NetworkNamespaceIdentity::new(7, 11).expect("nonzero network namespace");
        Self {
            durable_root: temp.path().join("run/native"),
            proc_root,
            inventory: inventory(Vec::new(), Vec::new(), false),
            capability_profile: capability_profile(CapabilityProfileRevision::INITIAL),
            network_namespace,
            xtables: xtables(&[]),
            _temp: temp,
        }
    }

    fn collect(
        &self,
    ) -> Result<AndroidExistingFluxOwnershipObservation, AndroidExistingFluxOwnershipError> {
        collect_from_roots(
            &self.durable_root,
            &self.proc_root,
            &self.inventory,
            &self.capability_profile,
            self.network_namespace,
            &self.xtables,
            None,
        )
    }
}

#[test]
fn missing_durable_root_proves_all_three_planes_without_creating_it() {
    let fixture = Fixture::new();

    let observation = fixture.collect().expect("clean absence observation");

    assert!(!fixture.durable_root.exists());
    assert!(!observation.durable_root_present());
    assert!(!observation.empty_target_archive_present());
    assert_eq!(
        observation.ownership_journal_revision(),
        OwnershipJournalRevision::INITIAL
    );
    assert_eq!(observation.durable_artifact_count(), 0);
    assert_eq!(observation.archived_target_count(), 0);
    assert_eq!(observation.flux_process_count(), 0);
    assert_eq!(observation.flux_chain_count(), 0);
    assert_eq!(observation.flux_route_count(), 0);
    assert_eq!(observation.flux_rule_count(), 0);
    assert_eq!(observation.coverage().len(), 3);
    for (record, plane) in observation.coverage().iter().zip([
        FwmarkPlane::Packet,
        FwmarkPlane::Socket,
        FwmarkPlane::Conntrack,
    ]) {
        assert_eq!(record.source(), FwmarkEvidenceSource::ExistingFluxOwnership);
        assert_eq!(record.plane(), plane);
        assert_eq!(record.state(), FwmarkCensusCoverageState::CompleteAbsent);
    }
}

#[test]
fn clean_journal_identity_binds_profile_inventory_root_and_xtables_facts() {
    let fixture = Fixture::new();
    let baseline = fixture.collect().expect("baseline absence");
    let repeated = fixture.collect().expect("repeated absence");
    assert_eq!(baseline.digest(), repeated.digest());
    assert_eq!(
        baseline.ownership_journal_identity(),
        repeated.ownership_journal_identity()
    );

    let mut changed_profile = Fixture::new();
    changed_profile.proc_root = fixture.proc_root.clone();
    changed_profile.durable_root = fixture.durable_root.clone();
    changed_profile.inventory = fixture.inventory.clone();
    changed_profile.xtables = fixture.xtables.clone();
    changed_profile.capability_profile =
        capability_profile(CapabilityProfileRevision::new(2).expect("second profile revision"));
    let profile_identity = changed_profile
        .collect()
        .expect("changed-profile absence")
        .ownership_journal_identity();
    assert_ne!(baseline.ownership_journal_identity(), profile_identity);

    let mut changed_inventory = Fixture::new();
    changed_inventory.proc_root = fixture.proc_root.clone();
    changed_inventory.durable_root = fixture.durable_root.clone();
    changed_inventory.capability_profile = fixture.capability_profile.clone();
    changed_inventory.xtables = fixture.xtables.clone();
    let inventory_identity = changed_inventory
        .collect()
        .expect("changed-inventory absence")
        .ownership_journal_identity();
    assert_ne!(baseline.ownership_journal_identity(), inventory_identity);

    let alternate_root = fixture._temp.path().join("alternate/native");
    let root_identity = collect_from_roots(
        &alternate_root,
        &fixture.proc_root,
        &fixture.inventory,
        &fixture.capability_profile,
        fixture.network_namespace,
        &fixture.xtables,
        None,
    )
    .expect("alternate-root absence")
    .ownership_journal_identity();
    assert_ne!(baseline.ownership_journal_identity(), root_identity);

    let unrelated_xtables = xtables(&["unrelated_chain"]);
    let xtables_identity = collect_from_roots(
        &fixture.durable_root,
        &fixture.proc_root,
        &fixture.inventory,
        &fixture.capability_profile,
        fixture.network_namespace,
        &unrelated_xtables,
        None,
    )
    .expect("changed-xtables absence")
    .ownership_journal_identity();
    assert_ne!(baseline.ownership_journal_identity(), xtables_identity);
}

#[test]
fn valid_empty_target_archive_is_clean_but_bound_into_the_proof() {
    let fixture = Fixture::new();
    let missing = fixture.collect().expect("missing archive is clean");
    fs::create_dir_all(&fixture.durable_root).expect("create durable root");
    fs::write(
        fixture.durable_root.join("native_xtables.targets"),
        empty_target_archive(),
    )
    .expect("write empty target archive");

    let observation = fixture.collect().expect("empty archive is clean");

    assert!(observation.durable_root_present());
    assert!(observation.empty_target_archive_present());
    assert_eq!(observation.archived_target_count(), 0);
    assert_ne!(missing.digest(), observation.digest());
    assert_ne!(
        missing.ownership_journal_identity(),
        observation.ownership_journal_identity()
    );
}

#[test]
fn malformed_archive_and_no_follow_paths_fail_closed() {
    let malformed = Fixture::new();
    fs::create_dir_all(&malformed.durable_root).expect("create durable root");
    fs::write(
        malformed.durable_root.join("native_xtables.targets"),
        b"not an archive",
    )
    .expect("write malformed archive");
    assert_eq!(
        malformed
            .collect()
            .expect_err("malformed archive must fail")
            .kind(),
        AndroidExistingFluxOwnershipErrorKind::DurableObservationFailed
    );

    let linked = Fixture::new();
    let real = linked._temp.path().join("real-native");
    fs::create_dir(&real).expect("create real root");
    fs::create_dir_all(linked.durable_root.parent().expect("durable parent"))
        .expect("create durable parent");
    std::os::unix::fs::symlink(&real, &linked.durable_root).expect("link durable root");
    assert_eq!(
        linked.collect().expect_err("linked root must fail").kind(),
        AndroidExistingFluxOwnershipErrorKind::DurableObservationFailed
    );
}

#[test]
fn journal_lease_attempt_and_writer_lock_each_block_clean_absence() {
    for artifact in [
        "native_xtables.journal",
        "native_xtables.lease",
        "native_xtables.attempt",
        "xtables-writer.lock",
    ] {
        let fixture = Fixture::new();
        fs::create_dir_all(&fixture.durable_root).expect("create durable root");
        let path = fixture.durable_root.join(artifact);
        if artifact.ends_with(".lock") {
            fs::create_dir(&path).expect("create writer lock");
        } else {
            fs::write(&path, b"opaque existing state").expect("write durable artifact");
        }

        let error = fixture.collect().expect_err("durable ownership must block");
        assert_eq!(
            error.kind(),
            AndroidExistingFluxOwnershipErrorKind::DurableOwnershipPresent,
            "artifact {artifact}"
        );
        assert_eq!(error.observed_count(), Some(1));
    }
}

#[test]
fn exact_flux_process_names_block_without_reading_command_lines() {
    for (index, command) in ["fluxd", "sing-box"].into_iter().enumerate() {
        let fixture = Fixture::new();
        write_process(
            &fixture.proc_root,
            u32::try_from(index + 10).expect("fixture PID"),
            command,
            u64::try_from(index + 100).expect("fixture start time"),
        );

        let error = fixture.collect().expect_err("Flux process must block");
        assert_eq!(
            error.kind(),
            AndroidExistingFluxOwnershipErrorKind::ProcessOwnershipPresent
        );
        assert_eq!(error.observed_count(), Some(1));
    }

    let unrelated = Fixture::new();
    write_process(&unrelated.proc_root, 20, "fluxd-helper", 200);
    unrelated
        .collect()
        .expect("nonexact process identity is unrelated");
}

#[test]
fn startup_exclusion_applies_only_to_the_named_daemon_pid() {
    let current = Fixture::new();
    write_process(&current.proc_root, 50, "fluxd", 500);
    collect_from_roots(
        &current.durable_root,
        &current.proc_root,
        &current.inventory,
        &current.capability_profile,
        current.network_namespace,
        &current.xtables,
        Some(50),
    )
    .expect("the lease-owning daemon is excluded");

    let other_daemon = Fixture::new();
    write_process(&other_daemon.proc_root, 50, "fluxd", 500);
    write_process(&other_daemon.proc_root, 51, "fluxd", 501);
    let error = collect_from_roots(
        &other_daemon.durable_root,
        &other_daemon.proc_root,
        &other_daemon.inventory,
        &other_daemon.capability_profile,
        other_daemon.network_namespace,
        &other_daemon.xtables,
        Some(50),
    )
    .expect_err("another daemon remains an ownership conflict");
    assert_eq!(
        error.kind(),
        AndroidExistingFluxOwnershipErrorKind::ProcessOwnershipPresent
    );
    assert_eq!(error.observed_count(), Some(1));

    let engine = Fixture::new();
    write_process(&engine.proc_root, 50, "sing-box", 500);
    let error = collect_from_roots(
        &engine.durable_root,
        &engine.proc_root,
        &engine.inventory,
        &engine.capability_profile,
        engine.network_namespace,
        &engine.xtables,
        Some(50),
    )
    .expect_err("the PID exclusion cannot hide a different Flux process kind");
    assert_eq!(
        error.kind(),
        AndroidExistingFluxOwnershipErrorKind::ProcessOwnershipPresent
    );
    assert_eq!(error.observed_count(), Some(1));
}

#[test]
fn malformed_or_linked_proc_stat_cannot_prove_process_absence() {
    let malformed = Fixture::new();
    let directory = malformed.proc_root.join("42");
    fs::create_dir(&directory).expect("create PID directory");
    fs::write(directory.join("comm"), b"fluxd\n").expect("write process comm");
    fs::write(directory.join("stat"), b"42 (fluxd) S\n").expect("write malformed stat");
    assert_eq!(
        malformed
            .collect()
            .expect_err("malformed stat must fail")
            .process_observation_class(),
        Some(AndroidExistingFluxProcessObservationErrorClass::StatMalformed)
    );

    let linked = Fixture::new();
    let directory = linked.proc_root.join("43");
    fs::create_dir(&directory).expect("create PID directory");
    fs::write(directory.join("comm"), b"fluxd\n").expect("write process comm");
    let target = linked._temp.path().join("foreign-stat");
    fs::write(&target, proc_stat(43, "init", 43)).expect("write link target");
    std::os::unix::fs::symlink(target, directory.join("stat")).expect("link proc stat");
    assert_eq!(
        linked
            .collect()
            .expect_err("linked stat must fail")
            .process_observation_class(),
        Some(AndroidExistingFluxProcessObservationErrorClass::StatRead)
    );
}

#[test]
fn unrelated_processes_do_not_require_parseable_proc_stat() {
    let fixture = Fixture::new();
    let directory = fixture.proc_root.join("44");
    fs::create_dir(&directory).expect("create PID directory");
    fs::write(directory.join("comm"), b"custom-root-ui\n").expect("write unrelated comm");
    fs::write(directory.join("stat"), b"vendor-specific stat shape\n")
        .expect("write unrelated stat");

    fixture
        .collect()
        .expect("unrelated process stat is outside Flux ownership evidence");
}

#[test]
fn candidate_comm_and_stat_must_identify_the_same_process() {
    let fixture = Fixture::new();
    let directory = fixture.proc_root.join("45");
    fs::create_dir(&directory).expect("create PID directory");
    fs::write(directory.join("comm"), b"fluxd\n").expect("write candidate comm");
    fs::write(directory.join("stat"), proc_stat(45, "init", 45)).expect("write changed stat");

    assert_eq!(
        fixture
            .collect()
            .expect_err("candidate identity drift must fail")
            .process_observation_class(),
        Some(AndroidExistingFluxProcessObservationErrorClass::StatMalformed)
    );
}

#[test]
fn candidate_comm_requires_the_kernel_newline_and_no_follow_file() {
    let malformed = Fixture::new();
    let directory = malformed.proc_root.join("46");
    fs::create_dir(&directory).expect("create PID directory");
    fs::write(directory.join("comm"), b"fluxd").expect("write malformed comm");
    assert_eq!(
        malformed
            .collect()
            .expect_err("malformed candidate comm must fail")
            .process_observation_class(),
        Some(AndroidExistingFluxProcessObservationErrorClass::CommMalformed)
    );

    let linked = Fixture::new();
    let directory = linked.proc_root.join("47");
    fs::create_dir(&directory).expect("create PID directory");
    let target = linked._temp.path().join("foreign-comm");
    fs::write(&target, b"fluxd\n").expect("write link target");
    std::os::unix::fs::symlink(target, directory.join("comm")).expect("link proc comm");
    assert_eq!(
        linked
            .collect()
            .expect_err("linked comm must fail")
            .process_observation_class(),
        Some(AndroidExistingFluxProcessObservationErrorClass::CommRead)
    );
}

#[test]
fn malformed_numeric_proc_entries_fail_closed() {
    for name in ["00042", "4294967296", "18446744073709551616"] {
        let fixture = Fixture::new();
        fs::create_dir(fixture.proc_root.join(name)).expect("create malformed numeric PID entry");
        assert_eq!(
            fixture
                .collect()
                .expect_err("malformed numeric PID entry must fail")
                .process_observation_class(),
            Some(AndroidExistingFluxProcessObservationErrorClass::InvalidPid),
            "entry {name}"
        );
    }
}

#[test]
fn process_scan_budget_counts_nonnumeric_entries() {
    let temp = tempfile::tempdir().expect("temporary proc root");
    fs::create_dir(temp.path().join("net")).expect("create first non-PID entry");
    fs::create_dir(temp.path().join("self")).expect("create second non-PID entry");

    assert_eq!(
        scan_flux_processes_bounded(temp.path(), 1, None),
        Err(AndroidExistingFluxProcessObservationErrorClass::LimitExceeded)
    );
}

#[test]
fn proc_stat_parser_handles_spaces_and_closing_parentheses_but_rejects_zero_start() {
    let encoded = proc_stat(77, "name with ) punctuation", 909);
    let parsed = parse_proc_stat(&encoded, 77).expect("parse Linux stat grammar");
    assert_eq!(parsed.command, b"name with ) punctuation");
    assert_eq!(parsed.start_time_ticks, 909);
    assert!(parse_proc_stat(&proc_stat(77, "fluxd", 0), 77).is_none());
    assert!(parse_proc_stat(&encoded, 78).is_none());
}

#[test]
fn native_chain_namespace_blocks_clean_absence() {
    for chain in ["FLX4O0000000001", "FLX4SP", "FLX6O0000000001"] {
        let mut fixture = Fixture::new();
        fixture.xtables = xtables(&[chain]);
        let error = fixture.collect().expect_err("Flux chain must block");
        assert_eq!(
            error.kind(),
            AndroidExistingFluxOwnershipErrorKind::ChainOwnershipPresent,
            "chain {chain}"
        );
        assert_eq!(error.observed_count(), Some(2));
    }
}

#[test]
fn native_policy_routing_identities_fail_closed() {
    let cases = [
        (vec![native_route()], Vec::new(), "native route"),
        (Vec::new(), vec![native_rule()], "native rule"),
    ];
    for (routes, rules, label) in cases {
        let mut fixture = Fixture::new();
        fixture.inventory = inventory(routes, rules, true);
        let error = fixture.collect().expect_err("routing residue must block");
        assert_eq!(
            error.kind(),
            AndroidExistingFluxOwnershipErrorKind::PolicyRoutingOwnershipPresent,
            "{label}"
        );
        assert_eq!(error.observed_count(), Some(1));
    }

    let mut unrelated = Fixture::new();
    unrelated.inventory = inventory(vec![unrelated_static_route()], Vec::new(), false);
    unrelated
        .collect()
        .expect("ordinary protocol-static route is not a Flux identity");
}

#[test]
fn relative_durable_root_is_rejected_before_observation() {
    let fixture = Fixture::new();
    let error = collect_from_roots(
        Path::new("relative/native"),
        &fixture.proc_root,
        &fixture.inventory,
        &fixture.capability_profile,
        fixture.network_namespace,
        &fixture.xtables,
        None,
    )
    .expect_err("relative root must fail");
    assert_eq!(
        error.kind(),
        AndroidExistingFluxOwnershipErrorKind::UnsafeDurableRoot
    );
}

fn capability_profile(revision: CapabilityProfileRevision) -> CapabilityProfile {
    CapabilityProfile::new(
        revision,
        Observation::Unavailable,
        Observation::Unavailable,
        KernelFacts::from_release(Observation::Unavailable),
        Observation::Unavailable,
    )
}

fn xtables(chains: &[&str]) -> AndroidXtablesFwmarkObservation {
    let mut snapshot = String::from("# Generated by iptables-save\n*mangle\n:INPUT ACCEPT [0:0]\n");
    for chain in chains {
        snapshot.push(':');
        snapshot.push_str(chain);
        snapshot.push_str(" - [0:0]\n");
    }
    snapshot.push_str("COMMIT\n");
    observe_android_xtables_fwmarks(
        snapshot.as_bytes(),
        snapshot.as_bytes(),
        AndroidNetdSourceProfile::AospNetd20250324,
        FwmarkCandidate::new(0x0060_0000, 0x0020_0000, 0x0040_0000)
            .expect("fixture mark candidate"),
    )
    .expect("complete xtables fixture")
}

fn inventory(
    routes: Vec<NetworkRouteRecord>,
    rules: Vec<NetworkRuleRecord>,
    loopback: bool,
) -> NetworkInventory {
    let links = loopback.then(|| {
        InterfaceLinkRecord::new(
            loopback_index(),
            InterfaceName::new(b"lo").expect("loopback name"),
            InterfaceHardwareType::from_raw(772),
            InterfaceLinkFlags::LOOPBACK | InterfaceLinkFlags::UP,
        )
    });
    let mut tracker = NetworkInventoryTracker::new();
    tracker
        .publish_complete_with_routing(
            links,
            std::iter::empty::<InterfaceAddressRecord>(),
            routes,
            rules,
        )
        .expect("publish inventory")
        .clone()
}

fn native_route() -> NetworkRouteRecord {
    route(
        20_253,
        NATIVE_ROUTE_PROTOCOL,
        RT_SCOPE_HOST,
        RTN_LOCAL,
        NATIVE_ROUTE_METRIC,
        RoutePath::Single {
            output_interface: Some(loopback_index()),
            gateway: None,
        },
    )
}

fn unrelated_static_route() -> NetworkRouteRecord {
    route(
        100,
        NATIVE_ROUTE_PROTOCOL,
        RT_SCOPE_UNIVERSE,
        1,
        0,
        RoutePath::None,
    )
}

fn route(
    table: u32,
    protocol: u8,
    scope: u8,
    route_type: u8,
    priority: u32,
    path: RoutePath,
) -> NetworkRouteRecord {
    NetworkRouteRecord::new(
        RoutePrefix::new(Ipv4Addr::UNSPECIFIED.into(), 0).expect("default destination"),
        RoutePrefix::new(Ipv4Addr::UNSPECIFIED.into(), 0).expect("default source"),
        RouteProperties::new(
            0,
            RouteTableId::from_raw(table),
            RouteProtocol::from_raw(protocol),
            RouteScope::from_raw(scope),
            RouteType::from_raw(route_type),
            RouteFlags::from_raw(0),
        ),
        priority,
        path,
    )
    .expect("route fixture")
}

fn native_rule() -> NetworkRuleRecord {
    rule(30_999, 20_253, NATIVE_RULE_PROTOCOL)
}

fn rule(priority: u32, table: u32, protocol: u8) -> NetworkRuleRecord {
    NetworkRuleRecord::new(
        RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
        RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
        RuleProperties::new(
            0,
            RuleTableId::from_raw(table),
            RuleAction::TO_TABLE,
            RuleProtocol::from_raw(protocol),
            RuleFlags::from_raw(0),
        ),
        RulePriority::from_raw(priority),
        None,
    )
    .expect("rule fixture")
    .with_fwmark(RuleFwMark::new(0x0020_0000, 0x0060_0000).expect("mark selector"))
}

fn loopback_index() -> InterfaceIndex {
    InterfaceIndex::new(1).expect("loopback index")
}

fn write_process(root: &Path, pid: u32, command: &str, start_time_ticks: u64) {
    let directory = root.join(pid.to_string());
    fs::create_dir(&directory).expect("create process directory");
    fs::write(directory.join("comm"), format!("{command}\n")).expect("write process comm");
    fs::write(
        directory.join("stat"),
        proc_stat(pid, command, start_time_ticks),
    )
    .expect("write process stat");
}

fn proc_stat(pid: u32, command: &str, start_time_ticks: u64) -> Vec<u8> {
    let mut fields = vec![String::from("S")];
    fields.extend(std::iter::repeat_n(String::from("0"), 18));
    fields.push(start_time_ticks.to_string());
    format!("{pid} ({command}) {}\n", fields.join(" ")).into_bytes()
}

fn empty_target_archive() -> Vec<u8> {
    let mut encoded = b"flux-native-xtables-target-archive\0".to_vec();
    encoded.extend_from_slice(&2_u16.to_be_bytes());
    encoded.push(0);
    let checksum = Sha256::digest(&encoded);
    encoded.extend_from_slice(&checksum);
    encoded
}
