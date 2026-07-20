use super::*;
use crate::android_mark_authority::{AndroidMarkDeviceGrantKind, FwmarkPlaneSet};
use crate::android_rpdb::{AndroidRpdbPolicyProfile, classify_android_rpdb};
use crate::android_tproxy_topology::{
    AndroidTproxyRoutingShape, AndroidTproxyTopologyScopeRequest,
    AndroidTproxyTrafficDomainRequest, assess_android_tproxy_topology_scope,
};
use crate::capability::{
    BootIdentity, CapabilityProfileRevision, DeviceIdentity, KernelFacts, KernelRelease,
    LegacyAddressSynchronization, LegacyArtifactReadiness, LegacyArtifactResolution,
    LegacyBridgeFacts, LegacyMutationWriter, LegacyRuleBackend, Observation, SelinuxMode,
    VerifiedBootIdentity, VerifiedBootState,
};
use crate::network_inventory::{
    InterfaceHardwareType, InterfaceIndex, InterfaceLinkFlags, InterfaceLinkRecord, InterfaceName,
    NetworkInventoryTracker,
};
use crate::network_route::NetworkAddressFamily;
use crate::network_rule::{
    NetworkRuleRecord, RuleAction, RuleFlags, RuleFwMark, RulePrefix, RulePriority, RuleProperties,
    RuleProtocol, RuleTableId,
};

const NET_ID_MASK: u32 = 0x0000_ffff;
const EXPLICIT_NETWORK: u32 = 0x0001_0000;
const NETWORK_PERMISSION: u32 = 0x0004_0000;
const SYSTEM_PERMISSION: u32 = 0x000c_0000;
const CANDIDATE_MASK: u32 = 0x0300_0000;
const PROXY_VALUE: u32 = 0x0100_0000;
const BYPASS_VALUE: u32 = 0x0200_0000;

const FLUXD_TOOL: &[ReviewedToolArtifactLiteral] = &[ReviewedToolArtifactLiteral {
    id: "fluxd",
    artifact: artifact_literal(0x24, 32_768),
}];
const CHANGED_TOOL_ID: &[ReviewedToolArtifactLiteral] = &[ReviewedToolArtifactLiteral {
    id: "fluxd-v2",
    artifact: artifact_literal(0x24, 32_768),
}];
const CHANGED_TOOL_ARTIFACT: &[ReviewedToolArtifactLiteral] = &[ReviewedToolArtifactLiteral {
    id: "fluxd",
    artifact: artifact_literal(0x25, 32_768),
}];
const SELECTOR: ReviewedPolicySelectorLiteral = ReviewedPolicySelectorLiteral {
    android_product: "google/redfin/redfin",
    android_build: "google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys",
    vendor_build: "google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys",
    security_patch: "2023-08-05",
    kernel_build: "5.10.198-android13-gki synthetic-build",
    selinux_policy: artifact_literal(0x21, 4_096),
    netd: artifact_literal(0x22, 8_192),
    connectivity: artifact_literal(0x23, 16_384),
    tools: FLUXD_TOOL,
};
const ENTRY: ReviewedAndroidMarkPolicyCatalogEntry = ReviewedAndroidMarkPolicyCatalogEntry {
    id: "google-redfin-tq3a-20230805-v1",
    selector: SELECTOR,
    policy_name: "synthetic cooperative policy",
    policy_revision: 1,
    policy_artifact_digest: [0x31; 32],
    candidate_mask: CANDIDATE_MASK,
    proxy_value: PROXY_VALUE,
    bypass_value: BYPASS_VALUE,
    planes: FwmarkPlaneSet::ALL.bits(),
};

#[test]
fn empty_production_catalog_returns_explicit_zero_grant() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let topology = topology_scope();

    let selection = select_reviewed_android_mark_policy(&topology, &profile, namespace)
        .expect("empty compiled catalog is valid");

    assert!(!selection.is_match());
    assert!(selection.catalog_entry().is_none());
    assert_eq!(
        selection.policy().grant_kind(),
        AndroidMarkDeviceGrantKind::NoGrant
    );
}

#[test]
fn exact_entry_selects_positive_policy_and_retains_catalog_provenance() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let topology = topology_scope();

    let selection =
        select_from_catalog(&[ENTRY], &topology, &profile, namespace).expect("exact match");
    let policy = selection.policy();
    let grant = policy.positive_grant().expect("matched positive policy");

    assert!(selection.is_match());
    assert_eq!(
        selection
            .catalog_entry()
            .map(ReviewedPolicyCatalogEntryId::as_str),
        Some("google-redfin-tq3a-20230805-v1")
    );
    assert_eq!(policy.grant_kind(), AndroidMarkDeviceGrantKind::Positive);
    assert_eq!(policy.revision().get(), 1);
    assert_eq!(grant.candidate().mask(), CANDIDATE_MASK);
    assert_eq!(grant.planes(), FwmarkPlaneSet::ALL);
    assert_eq!(grant.capability_profile(), &profile);
    assert_eq!(grant.network_namespace(), namespace);
    assert_eq!(
        policy
            .identity()
            .artifact_digest()
            .expect("policy artifact")
            .as_bytes(),
        &[0x31; 32]
    );
}

#[test]
fn every_stable_selector_fact_drift_returns_zero_grant() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let topology = topology_scope();
    let changed_selectors = [
        ReviewedPolicySelectorLiteral {
            android_product: "google/redfin/other",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            android_build: "google/redfin/redfin:13/TQ3A.230805.001/2:user/release-keys",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            vendor_build: "google/redfin/redfin:13/TQ3A.230805.001/2:user/release-keys",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            security_patch: "2023-09-05",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            kernel_build: "5.10.198-android13-gki other-build",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            selinux_policy: artifact_literal(0x41, 4_096),
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            netd: artifact_literal(0x42, 8_192),
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            connectivity: artifact_literal(0x43, 16_384),
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            tools: CHANGED_TOOL_ID,
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            tools: CHANGED_TOOL_ARTIFACT,
            ..SELECTOR
        },
    ];

    for selector in changed_selectors {
        let changed = ReviewedAndroidMarkPolicyCatalogEntry { selector, ..ENTRY };
        let selection = select_from_catalog(&[changed], &topology, &profile, namespace)
            .expect("valid nonmatching catalog");

        assert!(!selection.is_match());
        assert_eq!(
            selection.policy().grant_kind(),
            AndroidMarkDeviceGrantKind::NoGrant
        );
    }
}

#[test]
fn duplicate_ids_selectors_and_oversized_catalogs_fail_closed() {
    let different_selector = ReviewedPolicySelectorLiteral {
        android_build: "google/redfin/redfin:13/TQ3A.230805.001/2:user/release-keys",
        ..SELECTOR
    };
    let repeated_id = ReviewedAndroidMarkPolicyCatalogEntry {
        selector: different_selector,
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[ENTRY, repeated_id]),
        Err(ReviewedAndroidMarkPolicyCatalogError::DuplicateEntryId {
            first: 0,
            second: 1,
        })
    );

    let repeated_selector = ReviewedAndroidMarkPolicyCatalogEntry {
        id: "google-redfin-tq3a-20230805-v2",
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[ENTRY, repeated_selector]),
        Err(ReviewedAndroidMarkPolicyCatalogError::DuplicateSelector {
            first: 0,
            second: 1,
        })
    );

    let oversized = [ENTRY; MAX_REVIEWED_ANDROID_MARK_POLICY_CATALOG_ENTRIES + 1];
    assert_eq!(
        validate_catalog(&oversized),
        Err(ReviewedAndroidMarkPolicyCatalogError::TooManyEntries {
            maximum: MAX_REVIEWED_ANDROID_MARK_POLICY_CATALOG_ENTRIES,
            required_at_least: MAX_REVIEWED_ANDROID_MARK_POLICY_CATALOG_ENTRIES + 1,
        })
    );
}

#[test]
fn malformed_tools_candidate_and_planes_fail_closed() {
    const UNSORTED_TOOLS: &[ReviewedToolArtifactLiteral] = &[
        ReviewedToolArtifactLiteral {
            id: "z-tool",
            artifact: artifact_literal(0x41, 1),
        },
        ReviewedToolArtifactLiteral {
            id: "a-tool",
            artifact: artifact_literal(0x42, 1),
        },
    ];
    let unsorted_tools = ReviewedAndroidMarkPolicyCatalogEntry {
        selector: ReviewedPolicySelectorLiteral {
            tools: UNSORTED_TOOLS,
            ..SELECTOR
        },
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[unsorted_tools]),
        Err(ReviewedAndroidMarkPolicyCatalogError::InvalidEntry {
            index: 0,
            field: ReviewedAndroidMarkPolicyCatalogField::Tools,
        })
    );

    let ineligible_candidate = ReviewedAndroidMarkPolicyCatalogEntry {
        candidate_mask: 0xc000_0000,
        proxy_value: 0x8000_0000,
        bypass_value: 0x4000_0000,
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[ineligible_candidate]),
        Err(ReviewedAndroidMarkPolicyCatalogError::InvalidEntry {
            index: 0,
            field: ReviewedAndroidMarkPolicyCatalogField::Candidate,
        })
    );

    let unknown_planes = ReviewedAndroidMarkPolicyCatalogEntry {
        planes: 0x80,
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[unknown_planes]),
        Err(ReviewedAndroidMarkPolicyCatalogError::InvalidEntry {
            index: 0,
            field: ReviewedAndroidMarkPolicyCatalogField::Planes,
        })
    );

    let empty_planes = ReviewedAndroidMarkPolicyCatalogEntry { planes: 0, ..ENTRY };
    assert_eq!(
        validate_catalog(&[empty_planes]),
        Err(ReviewedAndroidMarkPolicyCatalogError::InvalidEntry {
            index: 0,
            field: ReviewedAndroidMarkPolicyCatalogField::Planes,
        })
    );
}

#[test]
fn malformed_unrelated_entry_poisoning_is_rejected_before_exact_selection() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let topology = topology_scope();
    let malformed_unrelated = ReviewedAndroidMarkPolicyCatalogEntry {
        id: "unrelated-invalid-entry",
        selector: ReviewedPolicySelectorLiteral {
            android_product: "other/product/device",
            ..SELECTOR
        },
        policy_revision: 0,
        ..ENTRY
    };

    assert_eq!(
        select_from_catalog(
            &[ENTRY, malformed_unrelated],
            &topology,
            &profile,
            namespace,
        ),
        Err(ReviewedAndroidMarkPolicyCatalogError::InvalidEntry {
            index: 1,
            field: ReviewedAndroidMarkPolicyCatalogField::PolicyRevision,
        })
    );
}

#[test]
fn selection_rejects_unverified_boot_identity_and_namespace_drift() {
    let profile_namespace = namespace(4, 40);
    let topology = topology_scope();
    let verified = capability_profile(profile_namespace);
    let unavailable_boot = CapabilityProfile::initial(
        Observation::Unavailable,
        verified.device_identity().clone(),
        verified.kernel().clone(),
        verified.selinux().clone(),
        verified.legacy_bridge().clone(),
    );
    assert_eq!(
        select_from_catalog(&[ENTRY], &topology, &unavailable_boot, profile_namespace,),
        Err(
            ReviewedAndroidMarkPolicyCatalogError::UnverifiedBootIdentity {
                observation: ObservationKind::Unavailable,
            }
        )
    );

    let unavailable = CapabilityProfile::initial(
        Observation::Verified(
            BootIdentity::parse("00112233-4455-6677-8899-aabbccddeeff").expect("boot identity"),
        ),
        Observation::Unavailable,
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new("5.10.198-android13-gki").expect("kernel release"),
        )),
        Observation::Verified(SelinuxMode::Enforcing),
        ready_legacy_bridge(),
    );
    assert_eq!(
        select_from_catalog(&[ENTRY], &topology, &unavailable, profile_namespace),
        Err(
            ReviewedAndroidMarkPolicyCatalogError::UnverifiedDeviceIdentity {
                observation: ObservationKind::Unavailable,
            }
        )
    );

    let profile = capability_profile(profile_namespace);
    let other_namespace = namespace(4, 41);
    assert_eq!(
        select_from_catalog(&[ENTRY], &topology, &profile, other_namespace),
        Err(
            ReviewedAndroidMarkPolicyCatalogError::NetworkNamespaceMismatch {
                profile: profile_namespace,
                observed: other_namespace,
            }
        )
    );
}

const fn artifact_literal(byte: u8, size: u64) -> ReviewedArtifactLiteral {
    ReviewedArtifactLiteral {
        digest: [byte; 32],
        size,
    }
}

fn namespace(device: u64, inode: u64) -> NetworkNamespaceIdentity {
    NetworkNamespaceIdentity::new(device, inode).expect("nonzero namespace inode")
}

fn capability_profile(network_namespace: NetworkNamespaceIdentity) -> CapabilityProfile {
    CapabilityProfile::new(
        CapabilityProfileRevision::INITIAL,
        Observation::Verified(
            BootIdentity::parse("00112233-4455-6677-8899-aabbccddeeff").expect("boot identity"),
        ),
        Observation::Verified(
            DeviceIdentity::new(
                AndroidProductIdentity::new(SELECTOR.android_product).expect("product"),
                AndroidBuildIdentity::new(SELECTOR.android_build).expect("Android build"),
                VendorBuildIdentity::new(SELECTOR.vendor_build).expect("vendor build"),
                SecurityPatchLevel::new(SELECTOR.security_patch).expect("security patch"),
                VerifiedBootIdentity::new(
                    VerifiedBootState::Green,
                    true,
                    Sha256Digest::new([0x11; 32]).expect("vbmeta digest"),
                ),
                KernelBuildIdentity::new(SELECTOR.kernel_build).expect("kernel build"),
                SelinuxPolicyIdentity::from(artifact(0x21, 4_096)),
                artifact(0x22, 8_192),
                artifact(0x23, 16_384),
                [(
                    ToolId::new("fluxd").expect("tool ID"),
                    artifact(0x24, 32_768),
                )],
                network_namespace,
            )
            .expect("device identity"),
        ),
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new("5.10.198-android13-gki").expect("kernel release"),
        )),
        Observation::Verified(SelinuxMode::Enforcing),
        ready_legacy_bridge(),
    )
}

fn artifact(byte: u8, size: u64) -> ArtifactIdentity {
    ArtifactIdentity::new(
        Sha256Digest::new([byte; 32]).expect("artifact digest"),
        size,
    )
    .expect("nonempty artifact")
}

fn ready_legacy_bridge() -> LegacyBridgeFacts {
    let ready = Observation::Verified(LegacyArtifactReadiness::new(
        LegacyArtifactResolution::Direct,
        true,
    ));
    let bridge = LegacyBridgeFacts::new(ready.clone(), ready.clone(), ready);
    assert_eq!(bridge.mutation_writer(), LegacyMutationWriter::Dispatcher);
    assert_eq!(bridge.rule_backend(), LegacyRuleBackend::IptablesRestore);
    assert_eq!(
        bridge.address_synchronization(),
        LegacyAddressSynchronization::StandaloneAddrsyncdViaScript
    );
    bridge
}

fn topology_scope() -> AndroidTproxyTopologyScopeReport {
    let mut tracker = NetworkInventoryTracker::new();
    let inventory = tracker
        .publish_complete_with_routing(
            [InterfaceLinkRecord::new(
                InterfaceIndex::new(1).expect("loopback index"),
                InterfaceName::new(b"lo").expect("loopback name"),
                InterfaceHardwareType::from_raw(1),
                InterfaceLinkFlags::UP | InterfaceLinkFlags::LOOPBACK,
            )],
            [],
            [],
            android_13_rules(),
        )
        .expect("complete inventory")
        .clone();
    let classification =
        classify_android_rpdb(&inventory, AndroidRpdbPolicyProfile::AospAndroid13R1);
    let request = AndroidTproxyTopologyScopeRequest::new(
        AndroidTproxyRoutingShape::PreMarkAddressHostSet,
        [AndroidTproxyTrafficDomainRequest::residual_local_output(
            NetworkAddressFamily::Ipv4,
        )],
    )
    .expect("topology request");
    assess_android_tproxy_topology_scope(&inventory, &classification, &request)
        .expect("trusted residual local-output scope")
}

fn android_13_rules() -> Vec<NetworkRuleRecord> {
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
