use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use flux_core::{
    AndroidBuildIdentity, AndroidMarkDevicePolicy, AndroidProductIdentity,
    AndroidTproxyRoutingShape, AndroidTproxyTopologyScopeRequest,
    AndroidTproxyTrafficDomainRequest, ArtifactIdentity, BootIdentity, CapabilityProfileRevision,
    DeviceIdentity, FwmarkNetfilterChainName, FwmarkPacketSelectorDigest, InterfaceAddressFlags,
    InterfaceAddressRecord, InterfaceHardwareType, InterfaceIndex, InterfaceLinkFlags,
    InterfaceLinkRecord, InterfaceName, KernelBuildIdentity, KernelFacts, KernelRelease,
    LegacyArtifactReadiness, LegacyArtifactResolution, LegacyBridgeFacts, NetworkInventoryTracker,
    NetworkRuleRecord, Observation, RuleAction, RuleFlags, RuleFwMark, RulePrefix, RulePriority,
    RuleProperties, RuleProtocol, RuleTableId, SecurityPatchLevel, SelinuxMode,
    SelinuxPolicyIdentity, Sha256Digest, ToolId, VendorBuildIdentity, VerifiedBootIdentity,
    VerifiedBootState, assess_android_tproxy_topology_scope, classify_android_rpdb,
    project_android_net_id_fwmark_census_fragment, project_rpdb_fwmark_census_fragment,
    select_reviewed_android_mark_policy,
};

use super::super::{existing_flux, nftables, traffic_control_bpf, xfrm};
use super::*;
use crate::android_fwmark_census::observe_android_xtables_fwmarks;

const PROFILE: AndroidNetdSourceProfile = AndroidNetdSourceProfile::AospNetd20250324;
const CANDIDATE_MASK: u32 = 0x0300_0000;
const PROXY_VALUE: u32 = 0x0100_0000;
const BYPASS_VALUE: u32 = 0x0200_0000;
const NET_ID_MASK: u32 = 0x0000_ffff;
const EXPLICIT_NETWORK: u32 = 0x0001_0000;
const NETWORK_PERMISSION: u32 = 0x0004_0000;
const SYSTEM_PERMISSION: u32 = 0x000c_0000;
const EMPTY_XTABLES: &[u8] = b"*mangle\n:INPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n";

pub(super) struct Fixture {
    pub(super) inventory: NetworkInventory,
    pub(super) capability_profile: CapabilityProfile,
    pub(super) network_namespace: NetworkNamespaceIdentity,
    pub(super) kernel_config_digest: AndroidKernelConfigDigest,
    pub(super) device_policy: AndroidMarkDevicePolicy,
    pub(super) android_net_id: AndroidNetIdFwmarkCensusFragment,
    pub(super) rpdb: RpdbFwmarkCensusFragment,
    pub(super) xtables: AndroidXtablesFwmarkObservation,
    pub(super) nftables: AndroidNftablesFwmarkObservation,
    pub(super) traffic_control_bpf: AndroidTrafficControlBpfFwmarkObservation,
    pub(super) xfrm: AndroidXfrmFwmarkObservation,
    pub(super) existing_flux: AndroidExistingFluxOwnershipObservation,
}

impl Fixture {
    fn projection(
        &self,
    ) -> Result<AndroidFwmarkCensusProjection, AndroidFwmarkCensusAssemblyError> {
        assemble_android_fwmark_census_projection(
            &self.inventory,
            &self.capability_profile,
            self.network_namespace,
            self.kernel_config_digest,
            &self.device_policy,
            &self.android_net_id,
            &self.rpdb,
            &self.xtables,
            &self.nftables,
            &self.traffic_control_bpf,
            &self.xfrm,
            &self.existing_flux,
        )
    }
}

#[test]
fn projection_has_exact_core_source_and_plane_order() {
    let fixture = fixture(Ipv4Addr::new(203, 0, 113, 77), true);
    let projection = fixture.projection().expect("complete positive projection");
    let expected_sources = [
        FwmarkEvidenceSource::AndroidNetId,
        FwmarkEvidenceSource::Rpdb,
        FwmarkEvidenceSource::DeviceMarkPolicy,
        FwmarkEvidenceSource::LegacyXtables,
        FwmarkEvidenceSource::Nftables,
        FwmarkEvidenceSource::TrafficControlAndBpf,
        FwmarkEvidenceSource::Xfrm,
        FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
        FwmarkEvidenceSource::ExistingFluxOwnership,
    ];
    let expected_planes = [
        FwmarkPlane::Packet,
        FwmarkPlane::Socket,
        FwmarkPlane::Conntrack,
    ];

    assert_eq!(
        projection.cells().len(),
        ANDROID_FWMARK_CENSUS_PROJECTION_CELLS
    );
    for (index, cell) in projection.cells().iter().enumerate() {
        assert_eq!(
            cell.source(),
            expected_sources[index / expected_planes.len()]
        );
        assert_eq!(cell.plane(), expected_planes[index % expected_planes.len()]);
    }
    assert!(projection.is_complete());
    assert_ne!(projection.digest().as_bytes(), &[0; 32]);
}

#[test]
fn projection_has_exact_fixed_metric_order() {
    use AndroidFwmarkCensusMetricKind as Kind;

    let projection = fixture(Ipv4Addr::new(203, 0, 113, 77), true)
        .projection()
        .expect("complete projection");
    let expected = [
        Kind::InventoryLinks,
        Kind::InventoryAddresses,
        Kind::InventoryRoutes,
        Kind::InventoryRules,
        Kind::XtablesTables,
        Kind::XtablesChains,
        Kind::XtablesRules,
        Kind::XtablesFluxOwnedChains,
        Kind::NftablesKernelSupported,
        Kind::NftablesTables,
        Kind::NftablesChains,
        Kind::NftablesRules,
        Kind::NftablesExpressions,
        Kind::NftablesOpaqueExpressions,
        Kind::TrafficControlAttachedFilters,
        Kind::BpfLoadedPrograms,
        Kind::BpfRelevantPrograms,
        Kind::BpfInaccessiblePrograms,
        Kind::BpfOpaquePrograms,
        Kind::BpfInstructions,
        Kind::XfrmKernelSupported,
        Kind::XfrmStates,
        Kind::XfrmPolicies,
        Kind::XfrmMarkAttributes,
        Kind::XfrmOpaqueAttributes,
        Kind::ExistingFluxDurableRootPresent,
        Kind::ExistingFluxEmptyTargetArchivePresent,
        Kind::ExistingFluxDurableArtifacts,
        Kind::ExistingFluxArchivedTargets,
        Kind::ExistingFluxProcesses,
        Kind::ExistingFluxChains,
        Kind::ExistingFluxRoutes,
        Kind::ExistingFluxRules,
        Kind::RawMarkUses,
        Kind::CanonicalMarkUses,
        Kind::OrderedLateWrites,
    ];
    let labels: BTreeSet<_> = projection
        .metrics()
        .iter()
        .map(|metric| metric.kind().as_str())
        .collect();

    assert_eq!(
        projection.metrics().len(),
        ANDROID_FWMARK_CENSUS_PROJECTION_METRICS
    );
    assert_eq!(
        projection.metrics().map(AndroidFwmarkCensusMetric::kind),
        expected
    );
    assert_eq!(labels.len(), ANDROID_FWMARK_CENSUS_PROJECTION_METRICS);
    assert!(metric_value(&projection, Kind::RawMarkUses) > 0);
    assert!(
        metric_value(&projection, Kind::RawMarkUses)
            >= metric_value(&projection, Kind::CanonicalMarkUses)
    );
}

#[test]
fn generic_policy_remains_noncomplete_diagnostic_evidence() {
    let projection = fixture(Ipv4Addr::new(203, 0, 113, 77), false)
        .projection()
        .expect("zero-grant policy remains diagnosable");
    let device_policy_cells = &projection.cells()[6..9];

    assert!(!projection.is_complete());
    assert!(device_policy_cells.iter().all(|cell| {
        cell.source() == FwmarkEvidenceSource::DeviceMarkPolicy
            && cell.state() == FwmarkCensusCoverageState::Unavailable
    }));
}

#[test]
fn missing_duplicate_and_wrong_source_coverage_are_rejected() {
    let missing = [
        coverage(FwmarkEvidenceSource::Rpdb, FwmarkPlane::Packet),
        coverage(FwmarkEvidenceSource::Rpdb, FwmarkPlane::Socket),
    ];
    assert_eq!(
        normalize_source_coverage(FwmarkEvidenceSource::Rpdb, &missing),
        Err(AndroidFwmarkCensusAssemblyError::MissingCoverage {
            source: FwmarkEvidenceSource::Rpdb,
            plane: FwmarkPlane::Conntrack,
        })
    );

    let duplicate = [
        coverage(FwmarkEvidenceSource::Rpdb, FwmarkPlane::Packet),
        coverage(FwmarkEvidenceSource::Rpdb, FwmarkPlane::Packet),
        coverage(FwmarkEvidenceSource::Rpdb, FwmarkPlane::Conntrack),
    ];
    assert_eq!(
        normalize_source_coverage(FwmarkEvidenceSource::Rpdb, &duplicate),
        Err(AndroidFwmarkCensusAssemblyError::DuplicateCoverage {
            source: FwmarkEvidenceSource::Rpdb,
            plane: FwmarkPlane::Packet,
        })
    );

    let wrong_source = [
        coverage(FwmarkEvidenceSource::AndroidNetId, FwmarkPlane::Packet),
        coverage(FwmarkEvidenceSource::Rpdb, FwmarkPlane::Socket),
        coverage(FwmarkEvidenceSource::Rpdb, FwmarkPlane::Conntrack),
    ];
    assert_eq!(
        normalize_source_coverage(FwmarkEvidenceSource::Rpdb, &wrong_source),
        Err(AndroidFwmarkCensusAssemblyError::CoverageSourceMismatch {
            expected: FwmarkEvidenceSource::Rpdb,
            observed: FwmarkEvidenceSource::AndroidNetId,
        })
    );
}

#[test]
fn mark_use_provenance_and_complete_state_consistency_are_rejected() {
    let android_use = mark_use(
        FwmarkEvidenceSource::AndroidNetId,
        FwmarkPlane::Packet,
        FwmarkUseOperation::MaskedWrite,
        1,
    );
    assert_eq!(
        append_mark_uses(&mut Vec::new(), FwmarkEvidenceSource::Rpdb, &[android_use]),
        Err(AndroidFwmarkCensusAssemblyError::MarkUseSourceMismatch {
            expected: FwmarkEvidenceSource::Rpdb,
            observed: FwmarkEvidenceSource::AndroidNetId,
        })
    );

    let mut absent_cells = complete_absent_cells();
    assert_eq!(
        validate_coverage_use_consistency(&absent_cells, &[android_use]),
        Err(AndroidFwmarkCensusAssemblyError::AbsentCoverageHasMarkUse {
            source: FwmarkEvidenceSource::AndroidNetId,
            plane: FwmarkPlane::Packet,
        })
    );
    absent_cells[0] = FwmarkCensusCoverageRecord::new(
        FwmarkEvidenceSource::AndroidNetId,
        FwmarkPlane::Packet,
        FwmarkCensusCoverageState::CompletePresent,
    );
    assert_eq!(
        validate_coverage_use_consistency(&absent_cells, &[]),
        Err(
            AndroidFwmarkCensusAssemblyError::PresentCoverageHasNoMarkUse {
                source: FwmarkEvidenceSource::AndroidNetId,
                plane: FwmarkPlane::Packet,
            }
        )
    );
}

#[test]
fn global_raw_mark_use_budget_rejects_the_513th_duplicate() {
    let record = mark_use(
        FwmarkEvidenceSource::Rpdb,
        FwmarkPlane::Packet,
        FwmarkUseOperation::PredicateRead,
        1,
    );
    let mut output = vec![record; MAX_COMPLETE_FWMARK_CENSUS_MARK_USES];

    assert_eq!(
        append_mark_uses(&mut output, FwmarkEvidenceSource::Rpdb, &[record]),
        Err(AndroidFwmarkCensusAssemblyError::TooManyMarkUses {
            maximum: MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
            required_at_least: MAX_COMPLETE_FWMARK_CENSUS_MARK_USES + 1,
        })
    );
}

#[test]
fn ordered_write_budget_membership_and_uniqueness_are_enforced() {
    let use_record = mark_use(
        FwmarkEvidenceSource::LegacyXtables,
        FwmarkPlane::Packet,
        FwmarkUseOperation::MaskedWrite,
        CANDIDATE_MASK,
    );
    let oversized: Vec<_> = (1..=MAX_ORDERED_LATE_PACKET_WRITES + 1)
        .map(|ordinal| ordered_write(use_record, u32::try_from(ordinal).expect("bounded ordinal")))
        .collect();
    assert_eq!(
        normalize_ordered_late_writes(&oversized, &[use_record]),
        Err(AndroidFwmarkCensusAssemblyError::TooManyOrderedLateWrites {
            maximum: MAX_ORDERED_LATE_PACKET_WRITES,
            required_at_least: MAX_ORDERED_LATE_PACKET_WRITES + 1,
        })
    );

    let one = ordered_write(use_record, 1);
    assert_eq!(
        normalize_ordered_late_writes(&[one.clone(), one.clone()], &[use_record]),
        Err(AndroidFwmarkCensusAssemblyError::DuplicateOrderedLateWrite)
    );
    assert_eq!(
        normalize_ordered_late_writes(&[one], &[]),
        Err(AndroidFwmarkCensusAssemblyError::OrderedLateWriteHasNoMarkUse)
    );
}

#[test]
fn transfer_state_precedence_is_fail_closed_and_deterministic() {
    use FwmarkCensusCoverageState as State;

    assert_eq!(
        combine_coverage_states(State::CompleteAbsent, State::CompletePresent),
        State::CompletePresent
    );
    assert_eq!(
        combine_coverage_states(State::CompletePresent, State::Opaque),
        State::Opaque
    );
    assert_eq!(
        combine_coverage_states(State::Unavailable, State::Opaque),
        State::Opaque
    );
    assert_eq!(
        combine_coverage_states(State::Opaque, State::Incomplete),
        State::Incomplete
    );
    assert_eq!(
        combine_coverage_states(State::Incomplete, State::Transient),
        State::Transient
    );
    assert_eq!(
        combine_coverage_states(State::Transient, State::Denied),
        State::Denied
    );
}

#[test]
fn cross_inventory_profile_capability_namespace_xtables_and_candidate_drift_reject() {
    let fixture = fixture(Ipv4Addr::new(203, 0, 113, 77), true);
    let other_inventory = inventory(Ipv4Addr::new(203, 0, 113, 78));
    assert_eq!(
        assemble_with(
            &fixture,
            &other_inventory,
            &fixture.capability_profile,
            fixture.network_namespace,
            &fixture.android_net_id,
            &fixture.xtables,
            &fixture.existing_flux,
        ),
        Err(AndroidFwmarkCensusAssemblyError::RpdbInventoryMismatch)
    );

    let other_net_id =
        project_android_net_id_fwmark_census_fragment(AndroidNetdSourceProfile::AospAndroid13R1);
    assert_eq!(
        assemble_with(
            &fixture,
            &fixture.inventory,
            &fixture.capability_profile,
            fixture.network_namespace,
            &other_net_id,
            &fixture.xtables,
            &fixture.existing_flux,
        ),
        Err(AndroidFwmarkCensusAssemblyError::XtablesNetdSourceProfileMismatch)
    );

    let changed_capability = CapabilityProfile::new(
        CapabilityProfileRevision::new(2).expect("second revision"),
        fixture.capability_profile.boot_identity().clone(),
        fixture.capability_profile.device_identity().clone(),
        fixture.capability_profile.kernel().clone(),
        fixture.capability_profile.selinux().clone(),
        fixture.capability_profile.legacy_bridge().clone(),
    );
    let changed_capability_existing = test_existing(
        &fixture.inventory,
        &changed_capability,
        fixture.network_namespace,
        &fixture.xtables,
    );
    assert_eq!(
        assemble_with(
            &fixture,
            &fixture.inventory,
            &changed_capability,
            fixture.network_namespace,
            &fixture.android_net_id,
            &fixture.xtables,
            &changed_capability_existing,
        ),
        Err(AndroidFwmarkCensusAssemblyError::DevicePolicyCapabilityProfileMismatch)
    );

    let other_namespace = NetworkNamespaceIdentity::new(99, 100).expect("other namespace");
    let other_namespace_existing = test_existing(
        &fixture.inventory,
        &fixture.capability_profile,
        other_namespace,
        &fixture.xtables,
    );
    assert_eq!(
        assemble_with(
            &fixture,
            &fixture.inventory,
            &fixture.capability_profile,
            other_namespace,
            &fixture.android_net_id,
            &fixture.xtables,
            &other_namespace_existing,
        ),
        Err(AndroidFwmarkCensusAssemblyError::DevicePolicyNetworkNamespaceMismatch)
    );

    let other_candidate =
        FwmarkCandidate::new(0x0c00_0000, 0x0400_0000, 0x0800_0000).expect("alternate candidate");
    let other_xtables =
        observe_android_xtables_fwmarks(EMPTY_XTABLES, EMPTY_XTABLES, PROFILE, other_candidate)
            .expect("alternate candidate observation");
    let other_xtables_existing = test_existing(
        &fixture.inventory,
        &fixture.capability_profile,
        fixture.network_namespace,
        &other_xtables,
    );
    assert_eq!(
        assemble_with(
            &fixture,
            &fixture.inventory,
            &fixture.capability_profile,
            fixture.network_namespace,
            &fixture.android_net_id,
            &other_xtables,
            &other_xtables_existing,
        ),
        Err(AndroidFwmarkCensusAssemblyError::DevicePolicyCandidateMismatch)
    );

    let mismatched_existing = test_existing(
        &fixture.inventory,
        &fixture.capability_profile,
        fixture.network_namespace,
        &other_xtables,
    );
    assert_eq!(
        assemble_with(
            &fixture,
            &fixture.inventory,
            &fixture.capability_profile,
            fixture.network_namespace,
            &fixture.android_net_id,
            &fixture.xtables,
            &mismatched_existing,
        ),
        Err(AndroidFwmarkCensusAssemblyError::ExistingFluxXtablesMismatch)
    );
}

#[test]
fn endpoint_and_private_identity_changes_do_not_escape_the_sanitized_surface() {
    let first = fixture(Ipv4Addr::new(203, 0, 113, 77), true)
        .projection()
        .expect("first projection");
    let second = fixture(Ipv4Addr::new(198, 51, 100, 211), true)
        .projection()
        .expect("second projection");
    let debug = format!("{first:?}");

    assert_eq!(first.cells(), second.cells());
    assert_eq!(first.mark_uses(), second.mark_uses());
    assert_eq!(first.ordered_late_writes(), second.ordered_late_writes());
    assert_eq!(first.metrics(), second.metrics());
    assert_ne!(
        first.digest(),
        second.digest(),
        "the opaque inventory identity remains aggregate-bound"
    );
    for private in [
        "203.0.113.77",
        "198.51.100.211",
        "samsung/dm3qzhx/dm3q",
        "00112233-4455-6677-8899-aabbccddeeff",
    ] {
        assert!(!debug.contains(private), "public Debug leaked {private}");
    }
}

#[test]
fn projection_digest_binds_the_complete_kernel_config_identity() {
    let fixture = fixture(Ipv4Addr::new(203, 0, 113, 77), true);
    let first = fixture.projection().expect("first projection");
    let changed_kernel_config = crate::parse_android_kernel_config(
        b"CONFIG_NETFILTER=y\nCONFIG_NETFILTER_NETLINK=y\nCONFIG_NF_TABLES=y\n",
    )
    .expect("changed kernel config")
    .digest();
    let second = assemble_android_fwmark_census_projection(
        &fixture.inventory,
        &fixture.capability_profile,
        fixture.network_namespace,
        changed_kernel_config,
        &fixture.device_policy,
        &fixture.android_net_id,
        &fixture.rpdb,
        &fixture.xtables,
        &fixture.nftables,
        &fixture.traffic_control_bpf,
        &fixture.xfrm,
        &fixture.existing_flux,
    )
    .expect("projection with changed config identity");

    assert_eq!(first.cells(), second.cells());
    assert_eq!(first.mark_uses(), second.mark_uses());
    assert_eq!(first.ordered_late_writes(), second.ordered_late_writes());
    assert_eq!(first.metrics(), second.metrics());
    assert_ne!(first.digest(), second.digest());
}

pub(super) fn fixture(endpoint: Ipv4Addr, positive_policy: bool) -> Fixture {
    let network_namespace = NetworkNamespaceIdentity::new(20, 234_673).expect("namespace");
    let inventory = inventory(endpoint);
    let capability_profile = samsung_capability_profile(network_namespace);
    let kernel_config_digest = crate::parse_android_kernel_config(
        b"CONFIG_NETFILTER=y\nCONFIG_NETFILTER_NETLINK=y\n# CONFIG_NF_TABLES is not set\n",
    )
    .expect("fixture kernel config")
    .digest();
    let candidate = FwmarkCandidate::new(CANDIDATE_MASK, PROXY_VALUE, BYPASS_VALUE)
        .expect("reviewed candidate");
    let android_net_id = project_android_net_id_fwmark_census_fragment(PROFILE);
    let rpdb = project_rpdb_fwmark_census_fragment(&inventory).expect("bounded RPDB evidence");
    let xtables = observe_android_xtables_fwmarks(EMPTY_XTABLES, EMPTY_XTABLES, PROFILE, candidate)
        .expect("complete empty xtables documents");
    let nftables = nftables::test_absent_observation(true);
    let traffic_control_bpf = traffic_control_bpf::test_absent_observation();
    let xfrm = xfrm::test_absent_observation(true);
    let existing_flux = test_existing(&inventory, &capability_profile, network_namespace, &xtables);
    let device_policy = if positive_policy {
        positive_policy_for(&inventory, &capability_profile, network_namespace)
    } else {
        AndroidMarkDevicePolicy::generic_aosp()
    };
    Fixture {
        inventory,
        capability_profile,
        network_namespace,
        kernel_config_digest,
        device_policy,
        android_net_id,
        rpdb,
        xtables,
        nftables,
        traffic_control_bpf,
        xfrm,
        existing_flux,
    }
}

fn assemble_with(
    fixture: &Fixture,
    inventory: &NetworkInventory,
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    android_net_id: &AndroidNetIdFwmarkCensusFragment,
    xtables: &AndroidXtablesFwmarkObservation,
    existing_flux: &AndroidExistingFluxOwnershipObservation,
) -> Result<AndroidFwmarkCensusProjection, AndroidFwmarkCensusAssemblyError> {
    assemble_android_fwmark_census_projection(
        inventory,
        capability_profile,
        network_namespace,
        fixture.kernel_config_digest,
        &fixture.device_policy,
        android_net_id,
        &fixture.rpdb,
        xtables,
        &fixture.nftables,
        &fixture.traffic_control_bpf,
        &fixture.xfrm,
        existing_flux,
    )
}

fn test_existing(
    inventory: &NetworkInventory,
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    xtables: &AndroidXtablesFwmarkObservation,
) -> AndroidExistingFluxOwnershipObservation {
    existing_flux::test_clean_observation(
        inventory.snapshot_id(),
        inventory.epoch(),
        capability_profile.digest(),
        network_namespace,
        xtables.digest(),
    )
}

fn positive_policy_for(
    inventory: &NetworkInventory,
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
) -> AndroidMarkDevicePolicy {
    let selection = select_reviewed_android_mark_policy(capability_profile, network_namespace)
        .expect("exact Samsung selector is valid");
    assert!(selection.is_match());
    let classification = classify_android_rpdb(inventory, PROFILE);
    let request = AndroidTproxyTopologyScopeRequest::new(
        AndroidTproxyRoutingShape::PreMarkAddressHostSet,
        [AndroidTproxyTrafficDomainRequest::residual_local_output(
            NetworkAddressFamily::Ipv4,
        )],
    )
    .expect("bounded topology request");
    let topology = assess_android_tproxy_topology_scope(inventory, &classification, &request)
        .expect("recognized default-network anchor");
    selection
        .bind_topology(&topology)
        .expect("selected semantic profile matches topology")
}

fn inventory(endpoint: Ipv4Addr) -> NetworkInventory {
    let loopback_index = InterfaceIndex::new(1).expect("loopback index");
    let loopback = InterfaceLinkRecord::new(
        loopback_index,
        InterfaceName::new(b"lo").expect("loopback name"),
        InterfaceHardwareType::from_raw(772),
        InterfaceLinkFlags::UP | InterfaceLinkFlags::LOOPBACK,
    );
    let address = InterfaceAddressRecord::new(
        loopback_index,
        IpAddr::V4(endpoint),
        32,
        InterfaceAddressFlags::PERMANENT,
    )
    .expect("test endpoint");
    let mut tracker = NetworkInventoryTracker::new();
    tracker
        .publish_complete_with_routing([loopback], [address], [], android_rules())
        .expect("complete inventory")
        .clone()
}

fn android_rules() -> Vec<NetworkRuleRecord> {
    let mut rules = vec![
        RuleSpec::netd(0, 255, RuleAction::TO_TABLE)
            .protocol(2)
            .build(),
        RuleSpec::netd(10_000, 99, RuleAction::TO_TABLE)
            .mark(SYSTEM_PERMISSION, EXPLICIT_NETWORK | SYSTEM_PERMISSION)
            .build(),
        RuleSpec::netd(16_000, 97, RuleAction::TO_TABLE)
            .mark(99 | EXPLICIT_NETWORK, NET_ID_MASK | EXPLICIT_NETWORK)
            .input(b"lo")
            .build(),
        RuleSpec::netd(18_000, 99, RuleAction::TO_TABLE)
            .mark(0, EXPLICIT_NETWORK)
            .build(),
        RuleSpec::netd(19_000, 98, RuleAction::TO_TABLE)
            .mark(0, EXPLICIT_NETWORK)
            .build(),
        RuleSpec::netd(20_000, 97, RuleAction::TO_TABLE)
            .mark(0, EXPLICIT_NETWORK)
            .build(),
        RuleSpec::netd(31_000, 1_003, RuleAction::TO_TABLE)
            .mark(NETWORK_PERMISSION, NET_ID_MASK | NETWORK_PERMISSION)
            .input(b"lo")
            .build(),
        RuleSpec::netd(32_000, 0, RuleAction::UNREACHABLE).build(),
    ];
    rules.sort_by_key(NetworkRuleRecord::priority);
    rules
}

struct RuleSpec {
    priority: u32,
    table: u32,
    action: RuleAction,
    protocol: u8,
    fwmark: Option<RuleFwMark>,
    input: Option<InterfaceName>,
}

impl RuleSpec {
    fn netd(priority: u32, table: u32, action: RuleAction) -> Self {
        Self {
            priority,
            table,
            action,
            protocol: 0,
            fwmark: None,
            input: None,
        }
    }

    fn protocol(mut self, protocol: u8) -> Self {
        self.protocol = protocol;
        self
    }

    fn mark(mut self, value: u32, mask: u32) -> Self {
        self.fwmark = RuleFwMark::new(value, mask);
        self
    }

    fn input(mut self, name: &[u8]) -> Self {
        self.input = Some(InterfaceName::new(name).expect("interface name"));
        self
    }

    fn build(self) -> NetworkRuleRecord {
        let family = NetworkAddressFamily::Ipv4;
        let mut record = NetworkRuleRecord::new(
            RulePrefix::unspecified(family),
            RulePrefix::unspecified(family),
            RuleProperties::new(
                0,
                RuleTableId::from_raw(self.table),
                self.action,
                RuleProtocol::from_raw(self.protocol),
                RuleFlags::default(),
            ),
            RulePriority::from_raw(self.priority),
            None,
        )
        .expect("rule fixture");
        if let Some(fwmark) = self.fwmark {
            record = record.with_fwmark(fwmark);
        }
        if let Some(input) = self.input {
            record = record.with_input_interface(input);
        }
        record
    }
}

fn samsung_capability_profile(network_namespace: NetworkNamespaceIdentity) -> CapabilityProfile {
    CapabilityProfile::new(
        CapabilityProfileRevision::INITIAL,
        Observation::Verified(
            BootIdentity::parse("00112233-4455-6677-8899-aabbccddeeff")
                .expect("canonical boot identity"),
        ),
        Observation::Verified(
            DeviceIdentity::new(
                AndroidProductIdentity::new("samsung/dm3qzhx/dm3q").expect("product"),
                AndroidBuildIdentity::new(
                    "samsung/dm3qzhx/dm3q:16/BP4A.251205.006/S9180ZHU7FZDP:user/release-keys",
                )
                .expect("Android build"),
                VendorBuildIdentity::new(
                    "samsung/dm3qzhx/dm3q:13/TP1A.220624.014/S9180ZHU7FZDP:user/release-keys",
                )
                .expect("vendor build"),
                SecurityPatchLevel::new("2026-04-05").expect("security patch"),
                VerifiedBootIdentity::new(
                    VerifiedBootState::Orange,
                    false,
                    Sha256Digest::new([0x11; 32]).expect("vbmeta digest"),
                ),
                KernelBuildIdentity::new(
                    "5.15.207-Qkernel-ga2c4e0b796 #3 SMP PREEMPT Fri May 22 14:03:17 UTC 2026",
                )
                .expect("kernel build"),
                SelinuxPolicyIdentity::from(artifact(
                    [
                        0xd9, 0x0a, 0x3e, 0x32, 0xfc, 0x84, 0x4a, 0x71, 0x4b, 0xf3, 0x7c, 0xea,
                        0xdc, 0x6e, 0xa5, 0xb7, 0x57, 0x48, 0x62, 0x90, 0x0e, 0x43, 0xf1, 0x41,
                        0x9e, 0x37, 0xa0, 0x08, 0xdd, 0x63, 0xc0, 0x1f,
                    ],
                    2_825_193,
                )),
                artifact(
                    [
                        0xaa, 0xbe, 0xab, 0x17, 0x6d, 0x29, 0xa2, 0xef, 0x29, 0x9f, 0xdd, 0xa3,
                        0x18, 0x00, 0x2d, 0xde, 0x25, 0x3e, 0x00, 0xa1, 0xc4, 0x75, 0x06, 0xf3,
                        0xaf, 0x06, 0x2b, 0x73, 0x11, 0x2d, 0x0a, 0xdd,
                    ],
                    1_033_576,
                ),
                artifact(
                    [
                        0xec, 0x4d, 0x66, 0xb2, 0x4a, 0x5d, 0x7b, 0xf2, 0xfe, 0x4f, 0x0a, 0xff,
                        0x22, 0x04, 0xdd, 0x51, 0xb4, 0x04, 0x97, 0x48, 0x56, 0x9e, 0xe0, 0xc0,
                        0xbc, 0x85, 0x01, 0x04, 0xbf, 0x0d, 0x75, 0x49,
                    ],
                    36_827_136,
                ),
                [(
                    ToolId::new("fluxd").expect("tool ID"),
                    artifact([0x41; 32], 32_768),
                )],
                network_namespace,
            )
            .expect("complete device identity"),
        ),
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new("5.15.207-Qkernel-ga2c4e0b796").expect("kernel release"),
        )),
        Observation::Verified(SelinuxMode::Enforcing),
        ready_legacy_bridge(),
    )
}

fn artifact(digest: [u8; 32], size: u64) -> ArtifactIdentity {
    ArtifactIdentity::new(
        Sha256Digest::new(digest).expect("nonzero artifact digest"),
        size,
    )
    .expect("nonempty artifact")
}

fn ready_legacy_bridge() -> LegacyBridgeFacts {
    let ready = Observation::Verified(LegacyArtifactReadiness::new(
        LegacyArtifactResolution::Direct,
        true,
    ));
    LegacyBridgeFacts::new(ready.clone(), ready.clone(), ready)
}

fn coverage(source: FwmarkEvidenceSource, plane: FwmarkPlane) -> FwmarkCensusCoverageRecord {
    FwmarkCensusCoverageRecord::new(source, plane, FwmarkCensusCoverageState::CompleteAbsent)
}

fn mark_use(
    source: FwmarkEvidenceSource,
    plane: FwmarkPlane,
    operation: FwmarkUseOperation,
    mask: u32,
) -> FwmarkUseRecord {
    FwmarkUseRecord::new(source, plane, operation, mask).expect("nonzero test mark mask")
}

fn complete_absent_cells() -> [FwmarkCensusCoverageRecord; ANDROID_FWMARK_CENSUS_PROJECTION_CELLS] {
    std::array::from_fn(|index| {
        FwmarkCensusCoverageRecord::new(
            ALL_SOURCES[index / ALL_PLANES.len()],
            ALL_PLANES[index % ALL_PLANES.len()],
            FwmarkCensusCoverageState::CompleteAbsent,
        )
    })
}

fn ordered_write(
    mark_use: FwmarkUseRecord,
    rule_ordinal: u32,
) -> FwmarkOrderedLateWriteQualification {
    FwmarkOrderedLateWriteQualification::new(
        mark_use,
        NetworkAddressFamily::Ipv4,
        FwmarkNetfilterBuiltinHook::Postrouting,
        FwmarkNetfilterChainName::new("vendor_postrouting").expect("chain name"),
        1,
        rule_ordinal,
        FwmarkPacketSelectorDigest::new([0x91; 32]).expect("selector digest"),
        FwmarkOrderedLateWritePlacement::PostroutingAfterFinalFluxUse,
        false,
        false,
        false,
    )
    .expect("valid ordered write")
}

fn metric_value(
    projection: &AndroidFwmarkCensusProjection,
    kind: AndroidFwmarkCensusMetricKind,
) -> u64 {
    projection
        .metrics()
        .iter()
        .find(|metric| metric.kind() == kind)
        .expect("fixed metric exists")
        .value()
}
