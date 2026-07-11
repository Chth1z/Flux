use std::error::Error;
use std::io;

use flux_core::ControlError;

#[test]
fn persistence_error_preserves_its_source_and_recovery_guidance() {
    let error = ControlError::persistence(
        "write administrative intent",
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state directory is read-only",
        ),
        "repair the state directory and restart fluxd",
    );

    assert_eq!(
        error.source().map(ToString::to_string).as_deref(),
        Some("state directory is read-only")
    );
    assert_eq!(
        error.to_string(),
        concat!(
            "cannot persist control state during write administrative intent: ",
            "state directory is read-only; recovery: repair the state directory and restart fluxd"
        )
    );
}

#[test]
fn runtime_error_preserves_its_source_and_recovery_guidance() {
    let error = ControlError::runtime(
        "publish capture",
        io::Error::new(io::ErrorKind::PermissionDenied, "iptables lock denied"),
        "detach capture and retry reconciliation",
    );

    assert_eq!(
        error.source().map(ToString::to_string).as_deref(),
        Some("iptables lock denied")
    );
    assert_eq!(
        error.to_string(),
        concat!(
            "runtime reconciliation failed during publish capture: ",
            "iptables lock denied; recovery: detach capture and retry reconciliation"
        )
    );
}

#[test]
fn request_rejection_preserves_its_stable_code() {
    let error = ControlError::request_rejected(
        "unsupported_kernel",
        "kernel 5.4.280 is below minimum 5.10.0",
    );

    assert_eq!(error.rejection_code(), Some("unsupported_kernel"));
    assert_eq!(
        error.to_string(),
        "control request rejected (unsupported_kernel): kernel 5.4.280 is below minimum 5.10.0"
    );
    assert!(error.source().is_none());
}
