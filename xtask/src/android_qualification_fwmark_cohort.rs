#[cfg(flux_android_qualification)]
// This helper consumes the shared decoder; the parent xtask owns the matching encoder.
#[allow(dead_code)]
#[path = "android_qualification_cohort_frame.rs"]
mod frame;

#[cfg(flux_android_qualification)]
fn main() {
    match run() {
        Ok(()) => println!("FLUX_ANDROID_Q11_COHORT_PREFLIGHT_PASS"),
        Err(status) => std::process::exit(status),
    }
}

#[cfg(not(flux_android_qualification))]
fn main() {
    std::process::exit(64);
}

#[cfg(flux_android_qualification)]
fn run() -> Result<(), i32> {
    use std::io::Read as _;

    let mut bytes = Vec::new();
    std::io::stdin()
        .take((frame::MAX_FRAME_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| frame::ValidationBoundary::InvalidInput.exit_code())?;
    validate_frame(&bytes)
}

#[cfg(flux_android_qualification)]
fn validate_frame(bytes: &[u8]) -> Result<(), i32> {
    let decoded =
        frame::decode(bytes).map_err(|_| frame::ValidationBoundary::InvalidInput.exit_code())?;
    let [ipv4_before, ipv6_before, ipv4_after, ipv6_after] = decoded.snapshots();
    let contract = flux_core::qualification_android_ordered_write_preflight()
        .map_err(|_| frame::ValidationBoundary::InvalidInput.exit_code())?;
    let before = flux_platform::observe_android_xtables_fwmarks(
        ipv4_before,
        ipv6_before,
        contract.netd_source_profile(),
        contract.candidate(),
    )
    .map_err(|_| frame::ValidationBoundary::InvalidSnapshot.exit_code())?;
    let after = flux_platform::observe_android_xtables_fwmarks(
        ipv4_after,
        ipv6_after,
        contract.netd_source_profile(),
        contract.candidate(),
    )
    .map_err(|_| frame::ValidationBoundary::InvalidSnapshot.exit_code())?;
    if before != after {
        return Err(frame::ValidationBoundary::SnapshotDrift.exit_code());
    }
    if !contract.accepts(before.ordered_late_writes()) {
        return Err(frame::ValidationBoundary::UnreviewedCohort.exit_code());
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
        assert_eq!(validate_frame(b"not-a-frame"), Err(70));
        let invalid_snapshot = frame::encode([b"invalid".as_slice(), EMPTY, EMPTY, EMPTY])
            .expect("bounded invalid snapshot frame");
        assert_eq!(validate_frame(&invalid_snapshot), Err(71));
        let drift = frame::encode([EMPTY, EMPTY, CHANGED, EMPTY]).expect("bounded drift frame");
        assert_eq!(validate_frame(&drift), Err(72));
        let unreviewed =
            frame::encode([EMPTY, EMPTY, EMPTY, EMPTY]).expect("bounded unreviewed cohort frame");
        assert_eq!(validate_frame(&unreviewed), Err(73));
    }
}
