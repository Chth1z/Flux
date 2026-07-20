/// Explicit, source-pinned AOSP netd revision shared by source-specific models.
///
/// Callers must select this profile from independently verified runtime artifact identity. No
/// source-specific classifier or census fragment infers it from an SDK level, observed rules, or
/// artifact names.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidNetdSourceProfile {
    /// AOSP `android-12.0.0_r1`, netd commit `5ca3d903...`.
    AospAndroid12R1,
    /// AOSP `android-13.0.0_r1`, netd commit `03311137...`.
    AospAndroid13R1,
    /// Repository-pinned AOSP netd commit `e11b8688...` from 2025-03-24.
    AospNetd20250324,
}

impl AndroidNetdSourceProfile {
    /// Every source revision currently modeled by Flux.
    pub const ALL: [Self; 3] = [
        Self::AospAndroid12R1,
        Self::AospAndroid13R1,
        Self::AospNetd20250324,
    ];

    /// Returns the exact AOSP netd source revision modeled by this profile.
    #[must_use]
    pub const fn source_revision(self) -> &'static str {
        match self {
            Self::AospAndroid12R1 => "5ca3d903c0253ec29fb4c3e3390f292494612e88",
            Self::AospAndroid13R1 => "03311137011f7ca55f263b61a8c86681c1581518",
            Self::AospNetd20250324 => "e11b8688b1f99292ade06f89f957c1f7e76ceae9",
        }
    }
}
