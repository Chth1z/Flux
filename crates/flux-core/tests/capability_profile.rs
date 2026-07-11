use flux_core::{
    BootIdentity, CAPABILITY_PROFILE_SCHEMA_VERSION, CapabilityProfile, CapabilityProfileRevision,
    KernelFacts, KernelRelease, KernelVersion, LegacyAddressSynchronization,
    LegacyArtifactReadiness, LegacyArtifactResolution, LegacyBridgeFacts, LegacyMutationGate,
    LegacyMutationWriter, LegacyRuleBackend, Observation, SelinuxMode,
};

#[test]
fn verified_boot_and_supported_kernel_allow_the_legacy_bridge_to_mutate() {
    let profile = CapabilityProfile::initial(
        Observation::Verified(
            BootIdentity::parse("01234567-89ab-cdef-0123-456789abcdef")
                .expect("canonical boot identity"),
        ),
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
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new("5.10.0").expect("bounded kernel release"),
        )),
        Observation::Verified(SelinuxMode::Permissive),
        ready_legacy_bridge(),
    );

    assert_eq!(profile.revision(), revision);
}

fn ready_legacy_bridge() -> LegacyBridgeFacts {
    let ready = Observation::Verified(LegacyArtifactReadiness::new(
        LegacyArtifactResolution::Direct,
        true,
    ));
    LegacyBridgeFacts::new(ready.clone(), ready.clone(), ready)
}
