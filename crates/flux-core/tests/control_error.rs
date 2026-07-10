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
