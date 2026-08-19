#[cfg(flux_android_qualification)]
// This helper consumes the shared decoder; the parent xtask owns the matching encoder.
#[allow(dead_code)]
#[path = "android_qualification_cohort_frame.rs"]
mod frame;

#[cfg(flux_android_qualification)]
fn main() {
    match run() {
        Ok(()) => println!("FLUX_ANDROID_Q11_COHORT_PREFLIGHT_PASS"),
        Err(failure) => {
            if let Some(summary) = failure.mismatch {
                print!("{}", summary.receipt());
            }
            std::process::exit(failure.boundary.exit_code());
        }
    }
}

#[cfg(not(flux_android_qualification))]
fn main() {
    std::process::exit(64);
}

#[cfg(flux_android_qualification)]
fn run() -> Result<(), ValidationFailure> {
    use std::io::Read as _;

    let mut bytes = Vec::new();
    std::io::stdin()
        .take((frame::MAX_FRAME_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ValidationFailure::at(frame::ValidationBoundary::InvalidInput))?;
    validate_frame(&bytes)
}

#[cfg(flux_android_qualification)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidationFailure {
    boundary: frame::ValidationBoundary,
    mismatch: Option<frame::MismatchSummary>,
}

#[cfg(flux_android_qualification)]
impl ValidationFailure {
    const fn at(boundary: frame::ValidationBoundary) -> Self {
        Self {
            boundary,
            mismatch: None,
        }
    }

    const fn mismatch(summary: frame::MismatchSummary) -> Self {
        Self {
            boundary: frame::ValidationBoundary::UnreviewedCohort,
            mismatch: Some(summary),
        }
    }
}

#[cfg(flux_android_qualification)]
fn validate_frame(bytes: &[u8]) -> Result<(), ValidationFailure> {
    let decoded = frame::decode(bytes)
        .map_err(|_| ValidationFailure::at(frame::ValidationBoundary::InvalidInput))?;
    let [ipv4_before, ipv6_before, ipv4_after, ipv6_after] = decoded.snapshots();
    let contract = flux_core::qualification_android_ordered_write_preflight()
        .map_err(|_| ValidationFailure::at(frame::ValidationBoundary::InvalidInput))?;
    let before = flux_platform::observe_android_xtables_fwmarks(
        ipv4_before,
        ipv6_before,
        contract.netd_source_profile(),
        contract.candidate(),
    )
    .map_err(|_| ValidationFailure::at(frame::ValidationBoundary::InvalidSnapshot))?;
    let after = flux_platform::observe_android_xtables_fwmarks(
        ipv4_after,
        ipv6_after,
        contract.netd_source_profile(),
        contract.candidate(),
    )
    .map_err(|_| ValidationFailure::at(frame::ValidationBoundary::InvalidSnapshot))?;
    if before != after {
        return Err(ValidationFailure::at(
            frame::ValidationBoundary::SnapshotDrift,
        ));
    }
    let comparison = contract.compare(before.ordered_late_writes());
    if comparison.relation() != flux_core::QualificationAndroidOrderedWriteRelation::Exact {
        let relation = match comparison.relation() {
            flux_core::QualificationAndroidOrderedWriteRelation::Exact => {
                frame::MismatchRelation::Exact
            }
            flux_core::QualificationAndroidOrderedWriteRelation::MissingOnly => {
                frame::MismatchRelation::MissingOnly
            }
            flux_core::QualificationAndroidOrderedWriteRelation::AdditionalOnly => {
                frame::MismatchRelation::AdditionalOnly
            }
            flux_core::QualificationAndroidOrderedWriteRelation::OrderOnly => {
                frame::MismatchRelation::OrderOnly
            }
            flux_core::QualificationAndroidOrderedWriteRelation::Substitution => {
                frame::MismatchRelation::Substitution
            }
            flux_core::QualificationAndroidOrderedWriteRelation::Ambiguous => {
                frame::MismatchRelation::Ambiguous
            }
        };
        let summary = frame::MismatchSummary::new(
            relation,
            comparison.observed_count(),
            comparison.expected_count(),
            comparison.missing_count(),
            comparison.additional_count(),
            comparison.equally_close_cohort_count(),
        )
        .ok_or_else(|| ValidationFailure::at(frame::ValidationBoundary::InvalidInput))?;
        return Err(ValidationFailure::mismatch(summary));
    }
    Ok(())
}

#[cfg(all(test, flux_android_qualification))]
mod tests {
    use super::*;

    const EMPTY: &[u8] = b"*mangle\n:INPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n";
    const CHANGED: &[u8] =
        b"*mangle\n:INPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n-A INPUT -j ACCEPT\nCOMMIT\n";

    #[test]
    fn helper_distinguishes_frame_parser_drift_and_cohort_boundaries() {
        assert_eq!(
            validate_frame(b"not-a-frame"),
            Err(ValidationFailure::at(
                frame::ValidationBoundary::InvalidInput
            ))
        );
        let invalid_snapshot = frame::encode([b"invalid".as_slice(), EMPTY, EMPTY, EMPTY])
            .expect("bounded invalid snapshot frame");
        assert_eq!(
            validate_frame(&invalid_snapshot),
            Err(ValidationFailure::at(
                frame::ValidationBoundary::InvalidSnapshot
            ))
        );
        let drift = frame::encode([EMPTY, EMPTY, CHANGED, EMPTY]).expect("bounded drift frame");
        assert_eq!(
            validate_frame(&drift),
            Err(ValidationFailure::at(
                frame::ValidationBoundary::SnapshotDrift
            ))
        );
        let unreviewed =
            frame::encode([EMPTY, EMPTY, EMPTY, EMPTY]).expect("bounded unreviewed cohort frame");
        let failure = validate_frame(&unreviewed).expect_err("empty cohort must reject");
        assert_eq!(
            failure.boundary,
            frame::ValidationBoundary::UnreviewedCohort
        );
        assert_eq!(
            failure.mismatch,
            frame::MismatchSummary::new(frame::MismatchRelation::MissingOnly, 0, 10, 10, 0, 1)
        );
    }
}
