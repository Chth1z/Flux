use flux_core::{
    AndroidMarkDevicePolicy, AndroidNetdSourceProfile, CapabilityProfile,
    CapturePathBehavioralEvidence, CapturePathBehavioralEvidenceDigest, CapturePathQualifications,
    NetworkNamespaceIdentity, ReviewedAndroidPlatformProfileCatalogError,
    ReviewedAndroidPlatformProfileSelection, ReviewedPolicyCatalogEntryId,
    select_reviewed_android_platform_profile,
};

#[test]
fn public_catalog_surface_exposes_selection_and_provenance_readback() {
    let _: fn(
        &CapabilityProfile,
        NetworkNamespaceIdentity,
    ) -> Result<
        ReviewedAndroidPlatformProfileSelection,
        ReviewedAndroidPlatformProfileCatalogError,
    > = select_reviewed_android_platform_profile;
    let _: fn(&ReviewedAndroidPlatformProfileSelection) -> Option<AndroidNetdSourceProfile> =
        ReviewedAndroidPlatformProfileSelection::netd_source_profile;
    let _: fn(&CapturePathBehavioralEvidence) -> CapturePathQualifications =
        CapturePathBehavioralEvidence::qualifications;
    let _: fn(&CapturePathBehavioralEvidence) -> CapturePathBehavioralEvidenceDigest =
        CapturePathBehavioralEvidence::digest;
    let _: fn(&ReviewedPolicyCatalogEntryId) -> &str = ReviewedPolicyCatalogEntryId::as_str;

    let policy = AndroidMarkDevicePolicy::generic_aosp();
    assert!(policy.identity().catalog_entry().is_none());
}
