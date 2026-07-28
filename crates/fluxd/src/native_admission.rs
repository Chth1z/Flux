use std::fmt;
use std::sync::Arc;

use flux_core::{
    BootIdentity, CapabilityProfile, FluxConfig, KernelMutationStatus, MutationGate,
    NetworkInventory, NetworkNamespaceIdentity,
};
use flux_platform::NetworkInventorySource;

use crate::runtime_coordinator::RuntimeFunctionalCanary;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAdmissionState {
    Admitted,
    Rejected(NativeAdmissionRejection),
}

impl NativeAdmissionState {
    #[must_use]
    pub const fn rejection(self) -> Option<NativeAdmissionRejection> {
        match self {
            Self::Admitted => None,
            Self::Rejected(reason) => Some(reason),
        }
    }

    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Rejected(reason) => reason.as_token(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAdmissionRejection {
    UnsupportedKernel,
    UnverifiedKernel,
    UnverifiedBootIdentity,
    UnverifiedDeviceIdentity,
    AndroidVpnPolicyUnavailable,
    FunctionalCanaryUnavailable,
    NetworkInventoryUnavailable,
}

impl NativeAdmissionRejection {
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::UnsupportedKernel => "unsupported_kernel",
            Self::UnverifiedKernel => "unverified_kernel",
            Self::UnverifiedBootIdentity => "unverified_boot_identity",
            Self::UnverifiedDeviceIdentity => "unverified_device_identity",
            Self::AndroidVpnPolicyUnavailable => "android_vpn_policy_unavailable",
            Self::FunctionalCanaryUnavailable => "functional_canary_unavailable",
            Self::NetworkInventoryUnavailable => "network_inventory_unavailable",
        }
    }
}

impl fmt::Display for NativeAdmissionRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedKernel => "the kernel is below the minimum supported version",
            Self::UnverifiedKernel => "the kernel version is unverified",
            Self::UnverifiedBootIdentity => "the boot identity is unverified",
            Self::UnverifiedDeviceIdentity => "the Android device identity is unverified",
            Self::AndroidVpnPolicyUnavailable => {
                "respect_android_vpn requires a qualified Android VPN policy adapter"
            }
            Self::FunctionalCanaryUnavailable => {
                "require_functional_canary requires a qualified Android functional-canary adapter"
            }
            Self::NetworkInventoryUnavailable => {
                "a complete reactor-owned network inventory is unavailable"
            }
        })
    }
}

pub(crate) struct NativeAdmissionCandidate {
    boot_identity: BootIdentity,
    network_namespace: NetworkNamespaceIdentity,
}

impl NativeAdmissionCandidate {
    pub(crate) fn evaluate(profile: &CapabilityProfile) -> Result<Self, NativeAdmissionRejection> {
        match profile.mutation_gate() {
            MutationGate::Allowed => {}
            MutationGate::ReadOnly {
                kernel: KernelMutationStatus::Unsupported { .. },
                ..
            } => return Err(NativeAdmissionRejection::UnsupportedKernel),
            MutationGate::ReadOnly {
                kernel: KernelMutationStatus::Unverified,
                ..
            } => return Err(NativeAdmissionRejection::UnverifiedKernel),
            MutationGate::ReadOnly { .. } => {
                return Err(NativeAdmissionRejection::UnverifiedBootIdentity);
            }
        }

        let boot_identity = profile
            .boot_identity()
            .verified()
            .cloned()
            .ok_or(NativeAdmissionRejection::UnverifiedBootIdentity)?;
        let network_namespace = profile
            .device_identity()
            .verified()
            .ok_or(NativeAdmissionRejection::UnverifiedDeviceIdentity)?
            .network_namespace();
        Ok(Self {
            boot_identity,
            network_namespace,
        })
    }

    pub(crate) fn configure(
        self,
        config: FluxConfig,
    ) -> Result<ConfiguredNativeAdmission, NativeAdmissionRejection> {
        if config.safety().respect_android_vpn() {
            return Err(NativeAdmissionRejection::AndroidVpnPolicyUnavailable);
        }
        if config.safety().require_functional_canary() {
            return Err(NativeAdmissionRejection::FunctionalCanaryUnavailable);
        }
        Ok(ConfiguredNativeAdmission {
            boot_identity: self.boot_identity,
            network_namespace: self.network_namespace,
            config,
        })
    }
}

pub(crate) struct ConfiguredNativeAdmission {
    boot_identity: BootIdentity,
    network_namespace: NetworkNamespaceIdentity,
    config: FluxConfig,
}

impl ConfiguredNativeAdmission {
    pub(crate) fn admit(
        self,
        source: Option<NetworkInventorySource>,
    ) -> Result<AdmittedNativeRuntime, NativeAdmissionRejection> {
        let inventory = source.ok_or(NativeAdmissionRejection::NetworkInventoryUnavailable)?;
        let initial_inventory = inventory
            .snapshot()
            .ok_or(NativeAdmissionRejection::NetworkInventoryUnavailable)?;
        Ok(AdmittedNativeRuntime {
            boot_identity: self.boot_identity,
            network_namespace: self.network_namespace,
            config: self.config,
            initial_inventory,
            inventory,
            functional_canary: RuntimeFunctionalCanary::StructuralVerificationOnly,
        })
    }
}

pub(crate) struct AdmittedNativeRuntime {
    pub(crate) boot_identity: BootIdentity,
    pub(crate) network_namespace: NetworkNamespaceIdentity,
    pub(crate) config: FluxConfig,
    pub(crate) initial_inventory: Arc<NetworkInventory>,
    pub(crate) inventory: NetworkInventorySource,
    pub(crate) functional_canary: RuntimeFunctionalCanary,
}

#[cfg(test)]
mod tests {
    use flux_testkit::CapabilityProfileFixture;

    use super::*;

    const PACKAGED_CONFIG: &str = include_str!("../../../conf/flux.toml");

    #[test]
    fn capability_rejections_are_typed_before_configuration_is_needed() {
        let unsupported = CapabilityProfileFixture::unsupported_kernel();
        assert!(matches!(
            NativeAdmissionCandidate::evaluate(&unsupported),
            Err(NativeAdmissionRejection::UnsupportedKernel)
        ));
    }

    #[test]
    fn every_requested_unqualified_safety_guarantee_rejects_admission() {
        let profile = CapabilityProfileFixture::device_qualified();
        let base = PACKAGED_CONFIG
            .replace("respect_android_vpn = true", "respect_android_vpn = false")
            .replace(
                "require_functional_canary = true",
                "require_functional_canary = false",
            );

        let vpn = base.replace("respect_android_vpn = false", "respect_android_vpn = true");
        assert!(matches!(
            NativeAdmissionCandidate::evaluate(&profile)
                .expect("supported profile")
                .configure(FluxConfig::parse(&vpn).expect("VPN safety config")),
            Err(NativeAdmissionRejection::AndroidVpnPolicyUnavailable)
        ));

        let canary = base.replace(
            "require_functional_canary = false",
            "require_functional_canary = true",
        );
        assert!(matches!(
            NativeAdmissionCandidate::evaluate(&profile)
                .expect("supported profile")
                .configure(FluxConfig::parse(&canary).expect("canary safety config")),
            Err(NativeAdmissionRejection::FunctionalCanaryUnavailable)
        ));
    }

    #[test]
    fn admitted_configuration_still_requires_the_reactor_inventory() {
        let profile = CapabilityProfileFixture::device_qualified();
        let config = PACKAGED_CONFIG
            .replace("respect_android_vpn = true", "respect_android_vpn = false")
            .replace(
                "require_functional_canary = true",
                "require_functional_canary = false",
            );
        let configured = NativeAdmissionCandidate::evaluate(&profile)
            .expect("supported profile")
            .configure(FluxConfig::parse(&config).expect("admitted config"))
            .expect("supported safety policy");

        assert!(matches!(
            configured.admit(None),
            Err(NativeAdmissionRejection::NetworkInventoryUnavailable)
        ));
    }
}
