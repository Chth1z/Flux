//! Deterministic model adapters and fixtures for Flux tests.

use std::cell::Cell;

use flux_core::{
    AndroidBuildIdentity, AndroidProductIdentity, ArtifactIdentity, BootIdentity,
    CapabilityProfile, CapabilityProfileSource, DeviceIdentity, KernelBuildIdentity, KernelFacts,
    KernelRelease, NetworkNamespaceIdentity, Observation, SecurityPatchLevel, SelinuxMode,
    SelinuxPolicyIdentity, Sha256Digest, ToolId, VendorBuildIdentity, VerifiedBootIdentity,
    VerifiedBootState,
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

    #[must_use]
    pub fn device_qualified() -> CapabilityProfile {
        Self::device_qualified_for(
            test_boot_identity(),
            NetworkNamespaceIdentity::new(10, 20).expect("namespace identity"),
        )
    }

    #[must_use]
    pub fn device_qualified_for(
        boot_identity: BootIdentity,
        network_namespace: NetworkNamespaceIdentity,
    ) -> CapabilityProfile {
        fixture_with_device(
            Observation::Verified(boot_identity),
            Observation::Verified(test_device_identity(network_namespace)),
            "5.10.198-android13-gki",
        )
    }
}

fn fixture(boot_identity: Observation<BootIdentity>, release: &str) -> CapabilityProfile {
    fixture_with_device(boot_identity, Observation::Unavailable, release)
}

fn fixture_with_device(
    boot_identity: Observation<BootIdentity>,
    device_identity: Observation<DeviceIdentity>,
    release: &str,
) -> CapabilityProfile {
    CapabilityProfile::initial(
        boot_identity,
        device_identity,
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new(release).expect("fixture kernel release is bounded"),
        )),
        Observation::Verified(SelinuxMode::Enforcing),
    )
}

fn test_device_identity(network_namespace: NetworkNamespaceIdentity) -> DeviceIdentity {
    DeviceIdentity::new(
        AndroidProductIdentity::new("google/redfin/redfin").expect("product identity"),
        AndroidBuildIdentity::new("google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys")
            .expect("Android build identity"),
        VendorBuildIdentity::new("google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys")
            .expect("vendor build identity"),
        SecurityPatchLevel::new("2023-08-05").expect("security patch level"),
        VerifiedBootIdentity::new(
            VerifiedBootState::Green,
            true,
            Sha256Digest::new([0x11; 32]).expect("vbmeta digest"),
        ),
        KernelBuildIdentity::new("5.10.198-android13-gki fixture-build")
            .expect("kernel build identity"),
        SelinuxPolicyIdentity::from(artifact(0x21, 4_096)),
        artifact(0x22, 8_192),
        artifact(0x23, 16_384),
        [(
            ToolId::new("fluxd").expect("tool identity"),
            artifact(0x24, 32_768),
        )],
        network_namespace,
    )
    .expect("complete device identity")
}

fn artifact(byte: u8, size: u64) -> ArtifactIdentity {
    ArtifactIdentity::new(
        Sha256Digest::new([byte; 32]).expect("nonzero artifact digest"),
        size,
    )
    .expect("nonempty artifact")
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
