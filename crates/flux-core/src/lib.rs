//! Domain models and controller primitives for Flux.
//!
//! Capability types in this crate model transport-independent observations
//! and the mutation gate derived from them. Platform adapters collect those
//! facts, while `fluxd` owns their external wire representation. The
//! configuration and control APIs keep validation, bounded state, and
//! mutation intent explicit at their domain boundaries.

mod capability;
mod config;
mod control;
mod network_inventory;
mod network_route;
mod network_rule;

pub use capability::{
    BootIdentity, BootIdentityMutationStatus, CAPABILITY_PROFILE_SCHEMA_VERSION, CapabilityProfile,
    CapabilityProfileRevision, CapabilityProfileSource, KernelFacts, KernelMutationStatus,
    KernelRelease, KernelReleaseError, KernelSupport, KernelVersion, LegacyAddressSynchronization,
    LegacyArtifactReadiness, LegacyArtifactResolution, LegacyBridgeFacts, LegacyMutationGate,
    LegacyMutationWriter, LegacyRuleBackend, MAX_BOOT_IDENTITY_BYTES, MAX_KERNEL_RELEASE_BYTES,
    MIN_SUPPORTED_KERNEL, Observation, ObservationKind, ParseBootIdentityError,
    ParseBootIdentityErrorKind, ParseKernelVersionError, SelinuxMode,
};
pub use config::{
    ConfigError, ConfigErrorKind, DaemonConfig, EventQueueCapacity, FailurePolicy, FluxConfig,
    GenerationHistory, MAX_CONFIG_DOCUMENT_BYTES, ReconcileDebounce,
};
pub use control::{
    AdministrativeState, ConfigurationChangeClient, ConfigurationChangeReport, ControlClient,
    ControlError, ControlService, ControlSnapshot, ControlSnapshotSource, LegacyControlBridge,
    LegacyDispatcher, LegacyIntent, OperationHandle, OperationReport, Reason,
};
pub use network_inventory::{
    AddressFlagConflict, INTERFACE_LINK_KIND_MAX_BYTES, INTERFACE_NAME_MAX_BYTES,
    InterfaceAddressFlags, InterfaceAddressRecord, InterfaceAddressRecordError,
    InterfaceAddressRecordErrorKind, InterfaceHardwareType, InterfaceIndex, InterfaceLinkConflict,
    InterfaceLinkFlags, InterfaceLinkKind, InterfaceLinkRecord, InterfaceName,
    InterfaceNameConflict, InterfaceOperationalState, NetworkEpoch, NetworkInventory,
    NetworkInventoryError, NetworkInventoryTracker,
};
pub use network_route::{
    NetworkAddressFamily, NetworkRouteRecord, NetworkRouteRecordError, NetworkRouteRecordErrorKind,
    RouteFlags, RouteGateway, RouteNexthop, RouteNexthopFlags, RoutePath, RoutePreference,
    RoutePrefix, RoutePrefixError, RoutePrefixErrorKind, RouteProperties, RouteProtocol,
    RouteScope, RouteTableId, RouteType,
};
pub use network_rule::{
    NetworkRuleRecord, NetworkRuleRecordError, NetworkRuleRecordErrorKind, RuleAction, RuleFlags,
    RuleFlowId, RuleFwMark, RuleIpProtocol, RulePortRange, RulePortRangeError,
    RulePortRangeErrorKind, RulePrefix, RulePrefixError, RulePrefixErrorKind, RulePriority,
    RuleProperties, RuleProtocol, RuleSuppressInterfaceGroup, RuleSuppressPrefixLength,
    RuleTableId, RuleTunnelId, RuleUidRange, RuleUidRangeError, RuleUidRangeErrorKind,
};
