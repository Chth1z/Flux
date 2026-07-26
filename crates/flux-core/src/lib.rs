//! Domain models and controller primitives for Flux.
//!
//! Capability types in this crate model transport-independent observations
//! and the mutation gate derived from them. Platform adapters collect those
//! facts, while `fluxd` owns their external wire representation. The
//! configuration and control APIs keep validation, bounded state, and
//! mutation intent explicit at their domain boundaries.

mod address_bypass;
mod android_mark_authority;
mod android_mark_policy_catalog;
mod android_netd;
mod android_rpdb;
mod android_tproxy_topology;
mod canonical_evidence;
mod capability;
mod capture_program;
mod config;
mod control;
mod fwmark_audit;
mod fwmark_census;
mod network_inventory;
mod network_route;
mod network_rule;
mod rpdb_placement;

pub use address_bypass::{
    AddressBypassInventoryAddressErrorKind, AddressBypassPlan, AddressBypassPlanError,
    AddressBypassPolicy, AddressBypassPrefix, AddressBypassPrefixError,
    AddressBypassPrefixErrorKind, AddressBypassRoutingSpec, AddressBypassRoutingSpecError,
    AddressBypassRoutingSpecErrorKind, AddressBypassRuleBudget, AddressBypassRuleConflict,
    AddressBypassRuleConflictKind, AddressBypassRuleIntent, AddressHostFamilySelection,
    AddressHostSetPlan, AddressHostSetPlanError, AddressHostSetPolicy,
    MAX_ADDRESS_BYPASS_CONFLICTS, MAX_ADDRESS_BYPASS_RULES, StaleAddressBypassPlan,
    StaleAddressHostSetPlan, plan_address_bypass, plan_address_host_set,
};
pub use android_mark_authority::{
    ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK, ANDROID_MARK_DEVICE_POLICY_ARTIFACT_DIGEST_BYTES,
    ANDROID_MARK_PLANNING_EVIDENCE_DIGEST_BYTES, AndroidMarkCandidateEligibilityError,
    AndroidMarkDeviceGrantKind, AndroidMarkDevicePolicy, AndroidMarkDevicePolicyArtifactDigest,
    AndroidMarkDevicePolicyArtifactDigestError, AndroidMarkDevicePolicyError,
    AndroidMarkDevicePolicyIdentity, AndroidMarkDevicePolicyKind, AndroidMarkDevicePolicyName,
    AndroidMarkDevicePolicyNameError, AndroidMarkDevicePolicyRevision,
    AndroidMarkPlanningAuthority, AndroidMarkPlanningAuthorizationError,
    AndroidMarkPlanningEvidenceDigest, AndroidMarkPositiveGrant,
    COMPLETE_FWMARK_CENSUS_COVERAGE_RECORDS, CompleteFwmarkCensus, CompleteFwmarkCensusError,
    CompleteFwmarkCensusObservationId, DeferredAndroidMarkActivationPrerequisite,
    FwmarkCensusCollectorRevision, FwmarkCensusConflict, FwmarkCensusCoverageRecord,
    FwmarkCensusCoverageState, FwmarkCensusOrderedPacketWrite, FwmarkOrderedPacketWriteRequirement,
    FwmarkPlane, FwmarkPlaneSet, FwmarkUseOperation, FwmarkUseRecord, FwmarkUseRecordError,
    MAX_ANDROID_MARK_DEVICE_POLICY_NAME_BYTES, MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
    OWNERSHIP_JOURNAL_IDENTITY_BYTES, OwnershipJournalIdentity, OwnershipJournalIdentityError,
    OwnershipJournalRevision, ReviewedPolicyCatalogEntryId, authorize_android_mark_planning,
};
pub use android_mark_policy_catalog::{
    MAX_REVIEWED_ANDROID_MARK_POLICY_CATALOG_ENTRIES, ReviewedAndroidMarkPolicyCatalogError,
    ReviewedAndroidMarkPolicyCatalogField, ReviewedAndroidMarkPolicySelection,
    select_reviewed_android_mark_policy,
};
pub use android_netd::AndroidNetdSourceProfile;
pub use android_rpdb::{
    AndroidRpdbClassificationReport, AndroidRpdbPlacementPlanError, AndroidRpdbPriorityBand,
    AndroidRpdbPriorityContract, AndroidRpdbProfileIssue, AndroidRpdbRuleRole,
    AndroidRpdbUnknownReason, AndroidRpdbUnknownRule, MAX_ANDROID_RPDB_UNKNOWN_RULES,
    classify_android_rpdb, plan_android_rpdb_placement,
};
pub use android_tproxy_topology::{
    AndroidTproxyDomainSelector, AndroidTproxyEvidenceCoverage, AndroidTproxyPriorityInterval,
    AndroidTproxyRoutingShape, AndroidTproxyRuleDisposition, AndroidTproxySelectionAnchor,
    AndroidTproxySelectorDisjointReason, AndroidTproxyStructuralFeasibility,
    AndroidTproxyTopologyError, AndroidTproxyTopologyFeasibilityReport,
    AndroidTproxyTopologyScopeEntry, AndroidTproxyTopologyScopeError,
    AndroidTproxyTopologyScopeReport, AndroidTproxyTopologyScopeRequest,
    AndroidTproxyTopologyScopeRequestError, AndroidTproxyTopologyScopeStructuralFeasibility,
    AndroidTproxyTrafficDomainKind, AndroidTproxyTrafficDomainRequest,
    DeferredAndroidTproxyPrerequisite, MAX_ANDROID_TPROXY_REQUESTED_DOMAINS,
    MAX_ANDROID_TPROXY_SCOPE_ANCHORS, StaleAndroidTproxyTopologyReport,
    StaleAndroidTproxyTopologyScopeReport, assess_android_tproxy_topology,
    assess_android_tproxy_topology_scope,
};
pub use capability::{
    AndroidBuildIdentity, AndroidProductIdentity, ArtifactIdentity, ArtifactIdentityError,
    BootIdentity, BootIdentityMutationStatus, CAPABILITY_PROFILE_DIGEST_BYTES,
    CAPABILITY_PROFILE_SCHEMA_VERSION, CapabilityProfile, CapabilityProfileDigest,
    CapabilityProfileRevision, CapabilityProfileSource, DeviceIdentity, DeviceIdentityError,
    IdentityTextError, IdentityTextErrorKind, KernelBuildIdentity, KernelFacts,
    KernelMutationStatus, KernelRelease, KernelReleaseError, KernelSupport, KernelVersion,
    LegacyAddressSynchronization, LegacyArtifactReadiness, LegacyArtifactResolution,
    LegacyBridgeFacts, LegacyMutationGate, LegacyMutationWriter, LegacyRuleBackend,
    MAX_BOOT_IDENTITY_BYTES, MAX_DEVICE_IDENTITY_TEXT_BYTES, MAX_DEVICE_TOOL_IDENTITIES,
    MAX_KERNEL_RELEASE_BYTES, MAX_TOOL_ID_BYTES, MIN_SUPPORTED_KERNEL, NetworkNamespaceIdentity,
    Observation, ObservationKind, ParseBootIdentityError, ParseBootIdentityErrorKind,
    ParseKernelVersionError, ReviewedPolicySelector, SHA256_DIGEST_BYTES, SecurityPatchLevel,
    SelinuxMode, SelinuxPolicyIdentity, Sha256Digest, Sha256DigestError, ToolId,
    VendorBuildIdentity, VerifiedBootIdentity, VerifiedBootState,
};
pub use capture_program::{
    CaptureApplicationMode, CaptureApplicationPolicy, CaptureApplicationPolicyError,
    CaptureBypassPolicy, CaptureBypassPolicyError, CaptureClause, CaptureClauseDecision,
    CaptureDecisionStage, CaptureDomainProgram, CaptureGroupId, CaptureInterfaceDirection,
    CaptureInterfacePolicy, CaptureInterfacePolicyError, CaptureInterfaceSelector,
    CaptureInterfaceSelectorKind, CaptureIpPrefix, CaptureIpPrefixError, CapturePredicate,
    CaptureProgramBudget, CaptureProgramBudgetError, CaptureProgramDigest,
    CaptureProgramResourceKind, CaptureProgramResourceUsage, CaptureProtocolSet,
    CaptureProtocolSetError, CaptureTrafficDomain, CaptureTrafficScope, CaptureTrafficScopeError,
    CaptureTransportProtocol, CaptureUserId, CompatibilityEngineCredentials,
    MAX_CAPTURE_HOST_ADDRESSES_PER_FAMILY, MAX_CAPTURE_INTERFACE_SELECTORS,
    MAX_CAPTURE_POLICY_PREFIX_INPUTS, MAX_CAPTURE_POLICY_PREFIXES_PER_FAMILY,
    MAX_CAPTURE_POLICY_UIDS, SHADOW_CAPTURE_PROGRAM_SCHEMA_VERSION, ShadowAddressHostSetProvenance,
    ShadowCaptureArtifact, ShadowCaptureCompileError, ShadowCaptureProgramRequest,
    ShadowCompatibilityAssumption, ShadowCompilationReport, ShadowDeferredPrerequisite,
    compile_shadow_capture_program,
};
pub use config::{
    AndroidPackageName, AndroidUserSelection, ApplicationConfig, BypassConfig, CaptureBackend,
    CaptureConfig, ConfigError, ConfigErrorKind, DaemonConfig, EngineConfig, EngineRestartConfig,
    EventQueueCapacity, FailurePolicy, FluxConfig, GenerationHistory, InterfaceConfig,
    ListenerConfig, MAX_CONFIG_DOCUMENT_BYTES, ReconcileDebounce, SafetyConfig, SubscriptionConfig,
};
pub use control::{
    AdministrativeState, ConfigurationChangeClient, ConfigurationChangeReport, ControlClient,
    ControlError, ControlObservation, ControlObservationIngress, ControlService, ControlSnapshot,
    ControlSnapshotSource, LegacyControlBridge, LegacyDispatcher, LegacyIntent, OperationHandle,
    OperationReport, Reason,
};
pub use fwmark_audit::{
    ANDROID_NET_ID_FWMARK_MASK, DeferredFwmarkPrerequisite, FwmarkCandidate, FwmarkCandidateError,
    FwmarkEvidenceSource, FwmarkEvidenceState, FwmarkPartialAudit, FwmarkPartialAuditOutcome,
    FwmarkPartialConflict, FwmarkRole, FwmarkSourceStatus, MAX_FWMARK_PARTIAL_CONFLICTS,
    StaleFwmarkPartialAudit, audit_fwmark_candidate_partial,
};
pub use fwmark_census::{
    AndroidNetIdFwmarkCensusFragment, RpdbFwmarkCensusFragment, RpdbFwmarkCensusFragmentError,
    StaleRpdbFwmarkCensusFragment, project_android_net_id_fwmark_census_fragment,
    project_rpdb_fwmark_census_fragment,
};
pub use network_inventory::{
    AddressFlagConflict, INTERFACE_LINK_KIND_MAX_BYTES, INTERFACE_NAME_MAX_BYTES,
    InterfaceAddressFlags, InterfaceAddressRecord, InterfaceAddressRecordError,
    InterfaceAddressRecordErrorKind, InterfaceHardwareType, InterfaceIndex, InterfaceLinkConflict,
    InterfaceLinkFlags, InterfaceLinkKind, InterfaceLinkRecord, InterfaceName,
    InterfaceNameConflict, InterfaceOperationalState, NetworkEpoch, NetworkInventory,
    NetworkInventoryError, NetworkInventorySnapshotId, NetworkInventoryTracker,
};
pub use network_route::{
    NetworkAddressFamily, NetworkRouteRecord, NetworkRouteRecordError, NetworkRouteRecordErrorKind,
    RouteFlags, RouteGateway, RouteNexthop, RouteNexthopFlags, RoutePath, RoutePreference,
    RoutePrefix, RoutePrefixError, RoutePrefixErrorKind, RouteProperties, RouteProtocol,
    RouteScope, RouteTableId, RouteType,
};
pub use network_rule::{
    MAX_OPAQUE_RULE_ATTRIBUTE_DETAILS, NetworkRuleRecord, NetworkRuleRecordError,
    NetworkRuleRecordErrorKind, OpaqueRuleAttribute, RuleAction, RuleAttributeCoverage,
    RuleAttributeOpacity, RuleFlags, RuleFlowId, RuleFwMark, RuleIpProtocol,
    RuleOpaqueAttributeFingerprint, RulePortRange, RulePortRangeError, RulePortRangeErrorKind,
    RulePrefix, RulePrefixError, RulePrefixErrorKind, RulePriority, RuleProperties, RuleProtocol,
    RuleSuppressInterfaceGroup, RuleSuppressPrefixLength, RuleTableId, RuleTunnelId, RuleUidRange,
    RuleUidRangeError, RuleUidRangeErrorKind,
};
pub use rpdb_placement::{
    DeferredRoutingPrerequisite, RpdbClassifierRevision, RpdbFamilyPlacement,
    RpdbFamilyPlacementError, RpdbPlacementLease, RpdbPlacementPlanError, RpdbPlacementRequest,
    RpdbPlacementRequestError, RpdbPriorityRole, RpdbPriorityWindow, RpdbRuleAudit,
    RpdbRuleAuditError, RpdbRuleClassification, StaleRpdbPlacementLease, plan_rpdb_placement,
};
