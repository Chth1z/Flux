//! Deterministic model adapters and fixtures for Flux tests.

use std::cell::Cell;

use flux_core::{
    BootIdentity, CapabilityProfile, CapabilityProfileSource, KernelFacts, KernelRelease,
    LegacyArtifactReadiness, LegacyArtifactResolution, LegacyBridgeFacts, Observation, SelinuxMode,
};
use flux_platform::{KernelReleaseSource, PlatformError};

#[derive(Debug)]
pub struct StaticCapabilityProfileSource {
    profile: CapabilityProfile,
    calls: Cell<usize>,
}

impl StaticCapabilityProfileSource {
    #[must_use]
    pub const fn new(profile: CapabilityProfile) -> Self {
        Self {
            profile,
            calls: Cell::new(0),
        }
    }

    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl CapabilityProfileSource for StaticCapabilityProfileSource {
    fn collect_capability_profile(&self) -> CapabilityProfile {
        self.calls.set(self.calls.get().saturating_add(1));
        self.profile.clone()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CapabilityProfileFixture;

impl CapabilityProfileFixture {
    #[must_use]
    pub fn supported() -> CapabilityProfile {
        fixture(
            Observation::Verified(test_boot_identity()),
            "5.10.198-android12-9-gki",
        )
    }

    #[must_use]
    pub fn unsupported_kernel() -> CapabilityProfile {
        fixture(
            Observation::Verified(test_boot_identity()),
            "5.4.280-android-vendor",
        )
    }

    #[must_use]
    pub fn unverified_boot() -> CapabilityProfile {
        fixture(Observation::Unavailable, "5.10.198-android12-9-gki")
    }
}

fn fixture(boot_identity: Observation<BootIdentity>, release: &str) -> CapabilityProfile {
    let ready = Observation::Verified(LegacyArtifactReadiness::new(
        LegacyArtifactResolution::Direct,
        true,
    ));
    CapabilityProfile::initial(
        boot_identity,
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new(release).expect("fixture kernel release is bounded"),
        )),
        Observation::Verified(SelinuxMode::Enforcing),
        LegacyBridgeFacts::new(ready.clone(), ready.clone(), ready),
    )
}

fn test_boot_identity() -> BootIdentity {
    BootIdentity::parse("01234567-89ab-cdef-0123-456789abcdef")
        .expect("fixture boot identity is canonical")
}

#[derive(Debug)]
pub struct StaticKernelReleaseSource {
    release: String,
    calls: Cell<usize>,
}

impl StaticKernelReleaseSource {
    #[must_use]
    pub fn new(release: impl Into<String>) -> Self {
        Self {
            release: release.into(),
            calls: Cell::new(0),
        }
    }

    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl KernelReleaseSource for StaticKernelReleaseSource {
    fn kernel_release(&self) -> Result<String, PlatformError> {
        self.calls.set(self.calls.get().saturating_add(1));
        Ok(self.release.clone())
    }
}
