use flux_core::{KernelSupport, KernelVersion, MIN_SUPPORTED_KERNEL};

#[test]
fn parses_android_vendor_kernel_release() {
    let version = KernelVersion::parse_release("5.10.198-android12-9-g123456789abc")
        .expect("Android release should parse");

    assert_eq!(version, KernelVersion::new(5, 10, 198));
}

#[test]
fn accepts_the_minimum_supported_kernel() {
    let support = KernelSupport::evaluate("5.10.0-gki").expect("release should parse");

    assert_eq!(
        support,
        KernelSupport::Supported(KernelVersion::new(5, 10, 0))
    );
    assert_eq!(MIN_SUPPORTED_KERNEL, KernelVersion::new(5, 10, 0));
}

#[test]
fn rejects_a_kernel_below_the_support_floor() {
    let support = KernelSupport::evaluate("5.9.16-vendor").expect("release should parse");

    assert_eq!(
        support,
        KernelSupport::Unsupported {
            found: KernelVersion::new(5, 9, 16),
            minimum: KernelVersion::new(5, 10, 0),
        }
    );
}

#[test]
fn rejects_a_release_without_numeric_major_and_minor_components() {
    let error = KernelVersion::parse_release("android-mainline").expect_err("must reject");

    assert_eq!(
        error.to_string(),
        "invalid kernel release 'android-mainline': expected numeric major.minor"
    );
}
