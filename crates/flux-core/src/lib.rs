//! Domain types and pure planning logic for Flux.

mod capability;
mod control;

pub use capability::{KernelSupport, KernelVersion, MIN_SUPPORTED_KERNEL, ParseKernelVersionError};
pub use control::{
    AdministrativeState, ConfigurationChangeReport, ControlClient, ControlError, ControlSnapshot,
    LegacyControlBridge, LegacyDispatcher, LegacyIntent, OperationHandle, OperationReport, Reason,
};
