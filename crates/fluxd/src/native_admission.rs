use std::fmt;
use std::sync::Arc;

use flux_core::{
    BootIdentity, CapabilityProfile, FluxConfig, FwmarkCandidate, KernelMutationStatus,
    MutationGate, NetworkInventory, NetworkNamespaceIdentity, ReviewedCanaryFacilityPolicy,
    ReviewedCanaryFacilitySelection, select_reviewed_android_platform_profile,
};
use flux_platform::NetworkInventorySource;

use crate::functional_canary::CanaryFacilityIdentity;
use crate::functional_canary::local_output::qualified_xtables_tproxy_local_output_executor;
use crate::native_runtime_writer::RetainedCanaryFacilityAuthority;
use crate::runtime_coordinator::{
    QualificationCanaryAttemptContext, QualificationCanaryAttemptEnvironmentOwner,
    RuntimeFunctionalCanary,
};

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
    reviewed_mark_candidate: Option<FwmarkCandidate>,
    reviewed_canary_facility_policy: Option<ReviewedCanaryFacilityPolicy>,
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
        let selected = select_reviewed_android_platform_profile(profile, network_namespace)
            .map_err(|_| NativeAdmissionRejection::UnverifiedDeviceIdentity)?;
        let reviewed_mark_candidate = selected.mark_candidate();
        let reviewed_canary_facility_policy = selected.canary_facility_policy().cloned();
        Ok(Self {
            boot_identity,
            network_namespace,
            reviewed_mark_candidate,
            reviewed_canary_facility_policy,
        })
    }

    pub(crate) fn configure(
        self,
        config: FluxConfig,
    ) -> Result<ConfiguredNativeAdmission, NativeAdmissionRejection> {
        if config.safety().respect_android_vpn() {
            return Err(NativeAdmissionRejection::AndroidVpnPolicyUnavailable);
        }
        Ok(ConfiguredNativeAdmission {
            boot_identity: self.boot_identity,
            network_namespace: self.network_namespace,
            reviewed_mark_candidate: self.reviewed_mark_candidate,
            reviewed_canary_facility_policy: self.reviewed_canary_facility_policy,
            config,
        })
    }
}

pub(crate) struct ConfiguredNativeAdmission {
    boot_identity: BootIdentity,
    network_namespace: NetworkNamespaceIdentity,
    reviewed_mark_candidate: Option<FwmarkCandidate>,
    reviewed_canary_facility_policy: Option<ReviewedCanaryFacilityPolicy>,
    config: FluxConfig,
}

impl ConfiguredNativeAdmission {
    #[must_use]
    pub(crate) const fn requires_functional_canary(&self) -> bool {
        self.config.safety().require_functional_canary()
    }

    #[must_use]
    pub(crate) const fn config(&self) -> &FluxConfig {
        &self.config
    }

    #[must_use]
    pub(crate) const fn boot_identity(&self) -> &BootIdentity {
        &self.boot_identity
    }

    #[must_use]
    pub(crate) const fn network_namespace(&self) -> NetworkNamespaceIdentity {
        self.network_namespace
    }

    #[must_use]
    pub(crate) const fn reviewed_canary_facility_policy(
        &self,
    ) -> Option<&ReviewedCanaryFacilityPolicy> {
        self.reviewed_canary_facility_policy.as_ref()
    }

    pub(crate) fn admit(
        self,
        source: Option<NetworkInventorySource>,
    ) -> Result<AdmittedNativeRuntime, NativeAdmissionRejection> {
        self.admit_with_functional_canary_owner(source, None)
    }

    pub(crate) fn admit_with_functional_canary_owner(
        self,
        source: Option<NetworkInventorySource>,
        functional_canary_owner: Option<Box<dyn QualificationCanaryAttemptEnvironmentOwner>>,
    ) -> Result<AdmittedNativeRuntime, NativeAdmissionRejection> {
        let functional_canary = if self.config.safety().require_functional_canary() {
            let owner = functional_canary_owner
                .ok_or(NativeAdmissionRejection::FunctionalCanaryUnavailable)?;
            RuntimeFunctionalCanary::RequiredUnqualified {
                context: Box::new(QualificationCanaryAttemptContext::new(owner)),
                executor: qualified_xtables_tproxy_local_output_executor(),
            }
        } else {
            RuntimeFunctionalCanary::StructuralVerificationOnly
        };
        let inventory = source.ok_or(NativeAdmissionRejection::NetworkInventoryUnavailable)?;
        let initial_inventory = inventory
            .snapshot()
            .ok_or(NativeAdmissionRejection::NetworkInventoryUnavailable)?;
        Ok(AdmittedNativeRuntime {
            boot_identity: self.boot_identity,
            network_namespace: self.network_namespace,
            reviewed_mark_candidate: self.reviewed_mark_candidate,
            config: self.config,
            initial_inventory,
            inventory,
            functional_canary,
            retained_canary_facility: None,
            reviewed_canary_facility_planning: None,
            retained_canary_facility_authority: None,
        })
    }
}

pub(crate) struct AdmittedNativeRuntime {
    pub(crate) boot_identity: BootIdentity,
    pub(crate) network_namespace: NetworkNamespaceIdentity,
    pub(crate) reviewed_mark_candidate: Option<FwmarkCandidate>,
    pub(crate) config: FluxConfig,
    pub(crate) initial_inventory: Arc<NetworkInventory>,
    pub(crate) inventory: NetworkInventorySource,
    pub(crate) functional_canary: RuntimeFunctionalCanary,
    pub(crate) retained_canary_facility: Option<CanaryFacilityIdentity>,
    pub(crate) reviewed_canary_facility_planning: Option<(
        ReviewedCanaryFacilityPolicy,
        ReviewedCanaryFacilitySelection,
    )>,
    pub(crate) retained_canary_facility_authority: Option<RetainedCanaryFacilityAuthority>,
}

#[cfg(test)]
mod tests {
    use flux_testkit::CapabilityProfileFixture;

    use super::*;

    const PACKAGED_CONFIG: &str = include_str!("../../../conf/flux.toml");

    struct InertQualifiedCanaryOwner;

    impl QualificationCanaryAttemptEnvironmentOwner for InertQualifiedCanaryOwner {
        fn prepare_environment(
            &mut self,
            _generation: &crate::functional_canary::ActiveCanaryGenerationBinding,
            _nonce: crate::functional_canary::CanaryNonce,
            _deadline: crate::functional_canary::CanaryDeadline,
        ) -> Result<
            crate::runtime_coordinator::QualificationCanaryAttemptEnvironmentSeed,
            crate::functional_canary::FunctionalCanaryError,
        > {
            unreachable!("admission test does not execute a canary attempt")
        }

        fn reobserve_environment(
            &mut self,
            _request: &crate::functional_canary::CanaryAttemptRequest,
            _generation: &crate::functional_canary::ActiveCanaryGenerationBinding,
        ) -> Result<(), crate::functional_canary::FunctionalCanaryError> {
            unreachable!("admission test does not execute a canary attempt")
        }
    }

    #[test]
    fn capability_rejections_are_typed_before_configuration_is_needed() {
        let unsupported = CapabilityProfileFixture::unsupported_kernel();
        assert!(matches!(
            NativeAdmissionCandidate::evaluate(&unsupported),
            Err(NativeAdmissionRejection::UnsupportedKernel)
        ));
    }

    #[test]
    fn vpn_policy_remains_unavailable_before_native_admission() {
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
    }

    #[test]
    fn required_canary_configuration_selects_the_fail_closed_runtime_gate() {
        let profile = CapabilityProfileFixture::device_qualified();
        let config =
            PACKAGED_CONFIG.replace("respect_android_vpn = true", "respect_android_vpn = false");
        let configured = NativeAdmissionCandidate::evaluate(&profile)
            .expect("supported profile")
            .configure(FluxConfig::parse(&config).expect("required canary config"))
            .expect("required mode is deferred to the runtime qualification owner");

        assert!(configured.config.safety().require_functional_canary());
        assert!(configured.reviewed_canary_facility_policy().is_none());
        assert!(matches!(
            configured.admit(None),
            Err(NativeAdmissionRejection::FunctionalCanaryUnavailable)
        ));
    }

    #[test]
    fn exact_canary_owner_advances_only_to_the_next_native_admission_gate() {
        let profile = CapabilityProfileFixture::device_qualified();
        let config =
            PACKAGED_CONFIG.replace("respect_android_vpn = true", "respect_android_vpn = false");
        let configured = NativeAdmissionCandidate::evaluate(&profile)
            .expect("supported profile")
            .configure(FluxConfig::parse(&config).expect("required canary config"))
            .expect("required mode is deferred to the runtime qualification owner");

        assert!(matches!(
            configured.admit_with_functional_canary_owner(
                None,
                Some(Box::new(InertQualifiedCanaryOwner)),
            ),
            Err(NativeAdmissionRejection::NetworkInventoryUnavailable)
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
