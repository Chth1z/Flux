use flux_core::{
    AndroidBuildIdentity, AndroidProductIdentity, ArtifactIdentity, BootIdentity,
    CAPABILITY_PROFILE_SCHEMA_VERSION, CapabilityProfile, CapabilityProfileRevision,
    DeviceIdentity, DeviceIdentityError, IdentityTextErrorKind, KernelBuildIdentity, KernelFacts,
    KernelRelease, KernelVersion, LegacyAddressSynchronization, LegacyArtifactReadiness,
    LegacyArtifactResolution, LegacyBridgeFacts, LegacyMutationGate, LegacyMutationWriter,
    LegacyRuleBackend, NetworkNamespaceIdentity, Observation, ReviewedPolicySelector,
    SecurityPatchLevel, SelinuxMode, SelinuxPolicyIdentity, Sha256Digest, ToolId,
    VendorBuildIdentity, VerifiedBootIdentity, VerifiedBootState,
};

#[test]
fn verified_boot_and_supported_kernel_allow_the_legacy_bridge_to_mutate() {
    let profile = CapabilityProfile::initial(
        Observation::Verified(
            BootIdentity::parse("01234567-89ab-cdef-0123-456789abcdef")
                .expect("canonical boot identity"),
        ),
        Observation::Unavailable,
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new("5.10.198-android12-9-gki").expect("bounded kernel release"),
        )),
        Observation::Verified(SelinuxMode::Enforcing),
        ready_legacy_bridge(),
    );

    assert_eq!(profile.schema_version(), CAPABILITY_PROFILE_SCHEMA_VERSION);
    assert_eq!(profile.revision(), CapabilityProfileRevision::INITIAL);
    assert_eq!(
        profile.kernel().version(),
        &Observation::Verified(KernelVersion::new(5, 10, 198))
    );
    assert_eq!(profile.legacy_mutation_gate(), LegacyMutationGate::Allowed);
}

#[test]
fn malformed_kernel_keeps_the_raw_release_and_makes_the_profile_read_only() {
    let release = KernelRelease::new("android-mainline").expect("bounded raw release");
    let profile = CapabilityProfile::initial(
        Observation::Verified(
            BootIdentity::parse("01234567-89ab-cdef-0123-456789abcdef")
                .expect("canonical boot identity"),
        ),
        Observation::Unavailable,
        KernelFacts::from_release(Observation::Verified(release.clone())),
        Observation::Absent,
        ready_legacy_bridge(),
    );

    assert_eq!(profile.kernel().release(), &Observation::Verified(release));
    assert_eq!(profile.kernel().version(), &Observation::Malformed);
    assert_eq!(
        profile.legacy_mutation_gate(),
        LegacyMutationGate::ReadOnly {
            kernel: flux_core::KernelMutationStatus::Unverified,
            boot_identity: flux_core::BootIdentityMutationStatus::Verified,
        }
    );
}

#[test]
fn legacy_bridge_reports_contract_without_claiming_an_active_capture_mode() {
    let bridge = ready_legacy_bridge();

    assert_eq!(bridge.mutation_writer(), LegacyMutationWriter::Dispatcher);
    assert_eq!(bridge.rule_backend(), LegacyRuleBackend::IptablesRestore);
    assert_eq!(
        bridge.address_synchronization(),
        LegacyAddressSynchronization::StandaloneAddrsyncdViaScript
    );
    assert!(bridge.shell().verified().expect("shell fact").is_ready());
}

#[test]
fn nonzero_same_schema_revisions_can_be_preserved_by_adapters() {
    assert_eq!(CapabilityProfileRevision::new(0), None);
    let revision = CapabilityProfileRevision::new(7).expect("nonzero revision");
    let profile = CapabilityProfile::new(
        revision,
        Observation::Verified(
            BootIdentity::parse("01234567-89ab-cdef-0123-456789abcdef")
                .expect("canonical boot identity"),
        ),
        Observation::Unavailable,
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new("5.10.0").expect("bounded kernel release"),
        )),
        Observation::Verified(SelinuxMode::Permissive),
        ready_legacy_bridge(),
    );

    assert_eq!(profile.revision(), revision);
}

#[test]
fn complete_profile_digest_distinguishes_equal_revisions() {
    let revision = CapabilityProfileRevision::new(7).expect("nonzero revision");
    let enforcing = CapabilityProfile::new(
        revision,
        Observation::Verified(
            BootIdentity::parse("01234567-89ab-cdef-0123-456789abcdef")
                .expect("canonical boot identity"),
        ),
        Observation::Unavailable,
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new("5.10.0").expect("bounded kernel release"),
        )),
        Observation::Verified(SelinuxMode::Enforcing),
        ready_legacy_bridge(),
    );
    let permissive = CapabilityProfile::new(
        revision,
        enforcing.boot_identity().clone(),
        enforcing.device_identity().clone(),
        enforcing.kernel().clone(),
        Observation::Verified(SelinuxMode::Permissive),
        enforcing.legacy_bridge().clone(),
    );

    assert_eq!(enforcing.revision(), permissive.revision());
    assert_eq!(enforcing.digest(), enforcing.digest());
    assert_ne!(enforcing.digest(), permissive.digest());
}

#[test]
fn exact_device_identity_is_ordered_and_catalog_keys_exclude_runtime_bindings() {
    let first = device_identity(
        NetworkNamespaceIdentity::new(10, 20).expect("namespace"),
        VerifiedBootState::Green,
        0x11,
    );
    let second = device_identity(
        NetworkNamespaceIdentity::new(11, 21).expect("namespace"),
        VerifiedBootState::Orange,
        0x12,
    );

    assert_ne!(first, second);
    assert_eq!(
        ReviewedPolicySelector::from_device_identity(&first),
        ReviewedPolicySelector::from_device_identity(&second),
        "verified-boot and namespace freshness must not become literal catalog keys"
    );
    assert_eq!(
        first.tools().keys().map(ToolId::as_str).collect::<Vec<_>>(),
        ["fluxd", "iptables-restore"]
    );
}

#[test]
fn device_identity_rejects_ambiguous_tools_and_noncanonical_security_dates() {
    let namespace = NetworkNamespaceIdentity::new(10, 20).expect("namespace");
    let tool = ToolId::new("fluxd").expect("tool ID");
    let duplicate = base_device_identity(
        namespace,
        VerifiedBootState::Green,
        0x11,
        [
            (tool.clone(), artifact(0x31, 1)),
            (tool.clone(), artifact(0x32, 2)),
        ],
    )
    .expect_err("duplicate tool identities must fail closed");
    assert_eq!(duplicate, DeviceIdentityError::DuplicateTool { tool });

    let invalid_patch =
        SecurityPatchLevel::new("2023-02-29").expect_err("non-leap February date is not canonical");
    assert_eq!(invalid_patch.kind(), IdentityTextErrorKind::InvalidFormat);
    assert!(SecurityPatchLevel::new("2024-02-29").is_ok());
    assert_eq!(
        ToolId::new("Fluxd")
            .expect_err("tool IDs use one stable lowercase grammar")
            .kind(),
        IdentityTextErrorKind::InvalidFormat
    );
    assert_eq!(
        AndroidBuildIdentity::new(" build")
            .expect_err("identity whitespace must not be silently normalized")
            .kind(),
        IdentityTextErrorKind::InvalidFormat
    );
    assert_eq!(
        AndroidBuildIdentity::new("build\u{2028}spoofed-line")
            .expect_err("catalog identity text must be printable ASCII")
            .kind(),
        IdentityTextErrorKind::InvalidFormat
    );
    assert_eq!(
        KernelBuildIdentity::new("kernel \u{202e}identity")
            .expect_err("bidirectional formatting must not enter status or catalog keys")
            .kind(),
        IdentityTextErrorKind::InvalidFormat
    );
    assert!(Sha256Digest::new([0; 32]).is_err());
    assert!(ArtifactIdentity::new(Sha256Digest::new([1; 32]).expect("digest"), 0).is_err());
}

fn ready_legacy_bridge() -> LegacyBridgeFacts {
    let ready = Observation::Verified(LegacyArtifactReadiness::new(
        LegacyArtifactResolution::Direct,
        true,
    ));
    LegacyBridgeFacts::new(ready.clone(), ready.clone(), ready)
}

fn device_identity(
    network_namespace: NetworkNamespaceIdentity,
    verified_boot_state: VerifiedBootState,
    vbmeta_byte: u8,
) -> DeviceIdentity {
    base_device_identity(
        network_namespace,
        verified_boot_state,
        vbmeta_byte,
        [
            (
                ToolId::new("iptables-restore").expect("tool ID"),
                artifact(0x25, 10),
            ),
            (ToolId::new("fluxd").expect("tool ID"), artifact(0x24, 9)),
        ],
    )
    .expect("complete device identity")
}

fn base_device_identity(
    network_namespace: NetworkNamespaceIdentity,
    verified_boot_state: VerifiedBootState,
    vbmeta_byte: u8,
    tools: impl IntoIterator<Item = (ToolId, ArtifactIdentity)>,
) -> Result<DeviceIdentity, DeviceIdentityError> {
    DeviceIdentity::new(
        AndroidProductIdentity::new("google/redfin/redfin").expect("product identity"),
        AndroidBuildIdentity::new("google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys")
            .expect("Android build identity"),
        VendorBuildIdentity::new("google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys")
            .expect("vendor build identity"),
        SecurityPatchLevel::new("2023-08-05").expect("security patch level"),
        VerifiedBootIdentity::new(
            verified_boot_state,
            true,
            Sha256Digest::new([vbmeta_byte; 32]).expect("vbmeta digest"),
        ),
        KernelBuildIdentity::new("5.10.198-android13-gki test-build")
            .expect("kernel build identity"),
        SelinuxPolicyIdentity::from(artifact(0x21, 6)),
        artifact(0x22, 7),
        artifact(0x23, 8),
        tools,
        network_namespace,
    )
}

fn artifact(byte: u8, size: u64) -> ArtifactIdentity {
    ArtifactIdentity::new(
        Sha256Digest::new([byte; 32]).expect("nonzero artifact digest"),
        size,
    )
    .expect("nonempty artifact")
}
