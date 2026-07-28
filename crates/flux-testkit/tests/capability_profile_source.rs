use flux_core::{CapabilityProfileSource, MutationGate};
use flux_testkit::{CapabilityProfileFixture, StaticCapabilityProfileSource};

#[test]
fn static_source_replays_one_recorded_profile_deterministically() {
    let source = StaticCapabilityProfileSource::new(CapabilityProfileFixture::supported());

    let first = source.collect_capability_profile();
    let second = source.collect_capability_profile();

    assert_eq!(first, second);
    assert_eq!(source.calls(), 2);
    assert_eq!(first.mutation_gate(), MutationGate::Allowed);
}

#[test]
fn fixtures_include_queryable_read_only_profiles() {
    for profile in [
        CapabilityProfileFixture::unsupported_kernel(),
        CapabilityProfileFixture::unverified_boot(),
    ] {
        assert!(matches!(
            profile.mutation_gate(),
            MutationGate::ReadOnly { .. }
        ));
    }
}

#[test]
fn device_qualified_fixture_contains_exact_freshness_bound_identity() {
    let profile = CapabilityProfileFixture::device_qualified();
    let identity = profile
        .device_identity()
        .verified()
        .expect("device-qualified fixture identity");

    assert_eq!(identity.android_product().as_str(), "google/redfin/redfin");
    assert_eq!(identity.network_namespace().device(), 10);
    assert_eq!(identity.network_namespace().inode(), 20);
    assert_eq!(identity.tools().len(), 1);
}
