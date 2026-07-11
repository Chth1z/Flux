use flux_core::{CapabilityProfileSource, LegacyMutationGate};
use flux_testkit::{CapabilityProfileFixture, StaticCapabilityProfileSource};

#[test]
fn static_source_replays_one_recorded_profile_deterministically() {
    let source = StaticCapabilityProfileSource::new(CapabilityProfileFixture::supported());

    let first = source.collect_capability_profile();
    let second = source.collect_capability_profile();

    assert_eq!(first, second);
    assert_eq!(source.calls(), 2);
    assert_eq!(first.legacy_mutation_gate(), LegacyMutationGate::Allowed);
}

#[test]
fn fixtures_include_queryable_read_only_profiles() {
    for profile in [
        CapabilityProfileFixture::unsupported_kernel(),
        CapabilityProfileFixture::unverified_boot(),
    ] {
        assert!(matches!(
            profile.legacy_mutation_gate(),
            LegacyMutationGate::ReadOnly { .. }
        ));
    }
}
