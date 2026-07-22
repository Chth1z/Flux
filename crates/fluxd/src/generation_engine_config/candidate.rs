/// Deterministic, non-authorizing input bundle for later complete Generation compilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TproxyGenerationCandidate {
    device_profile: CapabilityProfile,
    inventory_snapshot: NetworkInventorySnapshotId,
    inventory_epoch: NetworkEpoch,
    engine_profile: EngineCapabilityProfile,
    engine_config: EngineConfigLaunchBinding,
}

impl TproxyGenerationCandidate {
    #[must_use]
    pub(crate) const fn schema_version(&self) -> u16 {
        TPROXY_GENERATION_CANDIDATE_SCHEMA_VERSION
    }

    #[must_use]
    pub(crate) const fn device_profile(&self) -> &CapabilityProfile {
        &self.device_profile
    }

    #[must_use]
    pub(crate) const fn inventory_snapshot(&self) -> NetworkInventorySnapshotId {
        self.inventory_snapshot
    }

    #[must_use]
    pub(crate) const fn inventory_epoch(&self) -> NetworkEpoch {
        self.inventory_epoch
    }

    #[must_use]
    pub(crate) const fn engine_profile(&self) -> &EngineCapabilityProfile {
        &self.engine_profile
    }

    #[must_use]
    pub(crate) const fn engine_config(&self) -> &EngineConfigLaunchBinding {
        &self.engine_config
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TproxyGenerationCandidateErrorKind {
    EngineArtifactSetMismatch,
    EngineBindingMismatch,
    BootIdentityNotVerified { observation: ObservationKind },
    DeviceIdentityNotVerified { observation: ObservationKind },
    KernelNotSupported { support: Option<KernelSupport> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TproxyGenerationCandidateError {
    kind: TproxyGenerationCandidateErrorKind,
}

impl TproxyGenerationCandidateError {
    #[must_use]
    pub(crate) const fn kind(self) -> TproxyGenerationCandidateErrorKind {
        self.kind
    }
}

impl fmt::Display for TproxyGenerationCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            TproxyGenerationCandidateErrorKind::EngineArtifactSetMismatch => formatter.write_str(
                "Engine Capability Profile and config binding identify different artifacts",
            ),
            TproxyGenerationCandidateErrorKind::EngineBindingMismatch => formatter
                .write_str("Engine Capability Profile did not validate this exact config binding"),
            TproxyGenerationCandidateErrorKind::BootIdentityNotVerified { .. } => {
                formatter.write_str("device boot identity is not verified")
            }
            TproxyGenerationCandidateErrorKind::DeviceIdentityNotVerified { .. } => {
                formatter.write_str("exact device identity is not verified")
            }
            TproxyGenerationCandidateErrorKind::KernelNotSupported { .. } => {
                formatter.write_str("device kernel is not verified at the supported floor")
            }
        }
    }
}

impl Error for TproxyGenerationCandidateError {}

pub(crate) fn compile_tproxy_generation_candidate(
    device_profile: CapabilityProfile,
    inventory: &NetworkInventory,
    engine_profile: EngineCapabilityProfile,
    engine_config: EngineConfigLaunchBinding,
) -> Result<TproxyGenerationCandidate, TproxyGenerationCandidateError> {
    if engine_profile.artifacts() != engine_config.artifacts() {
        return Err(TproxyGenerationCandidateError {
            kind: TproxyGenerationCandidateErrorKind::EngineArtifactSetMismatch,
        });
    }
    if engine_profile.validated_binding() != engine_config.digest() {
        return Err(TproxyGenerationCandidateError {
            kind: TproxyGenerationCandidateErrorKind::EngineBindingMismatch,
        });
    }
    if device_profile.boot_identity().verified().is_none() {
        return Err(TproxyGenerationCandidateError {
            kind: TproxyGenerationCandidateErrorKind::BootIdentityNotVerified {
                observation: device_profile.boot_identity().kind(),
            },
        });
    }
    if device_profile.device_identity().verified().is_none() {
        return Err(TproxyGenerationCandidateError {
            kind: TproxyGenerationCandidateErrorKind::DeviceIdentityNotVerified {
                observation: device_profile.device_identity().kind(),
            },
        });
    }
    let support = device_profile.kernel_support();
    if !support.is_some_and(KernelSupport::is_supported) {
        return Err(TproxyGenerationCandidateError {
            kind: TproxyGenerationCandidateErrorKind::KernelNotSupported { support },
        });
    }

    Ok(TproxyGenerationCandidate {
        device_profile,
        inventory_snapshot: inventory.snapshot_id(),
        inventory_epoch: inventory.epoch(),
        engine_profile,
        engine_config,
    })
}
use std::error::Error;
use std::fmt;

use flux_core::{
    CapabilityProfile, KernelSupport, NetworkEpoch, NetworkInventory, NetworkInventorySnapshotId,
    ObservationKind,
};

use super::compiler::EngineConfigLaunchBinding;
use super::engine_profile::EngineCapabilityProfile;

pub(crate) const TPROXY_GENERATION_CANDIDATE_SCHEMA_VERSION: u16 = 1;
