use flux_core::{
    AndroidMarkDevicePolicy, AndroidNetdSourceProfile, CapabilityProfile, NetworkNamespaceIdentity,
    ReviewedAndroidMarkPolicyCatalogError, ReviewedAndroidMarkPolicySelection,
    ReviewedPolicyCatalogEntryId, select_reviewed_android_mark_policy,
};

#[test]
fn public_catalog_surface_exposes_selection_and_provenance_readback() {
    let _: fn(
        &CapabilityProfile,
        NetworkNamespaceIdentity,
    )
        -> Result<ReviewedAndroidMarkPolicySelection, ReviewedAndroidMarkPolicyCatalogError> =
        select_reviewed_android_mark_policy;
    let _: fn(&ReviewedAndroidMarkPolicySelection) -> Option<AndroidNetdSourceProfile> =
        ReviewedAndroidMarkPolicySelection::netd_source_profile;
    let _: fn(&ReviewedPolicyCatalogEntryId) -> &str = ReviewedPolicyCatalogEntryId::as_str;

    let policy = AndroidMarkDevicePolicy::generic_aosp();
    assert!(policy.identity().catalog_entry().is_none());
}
