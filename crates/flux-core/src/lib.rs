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
