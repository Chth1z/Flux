use flux_testkit::StaticKernelReleaseSource;
use fluxd::run_cli;

#[test]
fn json_status_reports_a_settled_unsupported_kernel() {
    let source = StaticKernelReleaseSource::new("5.9.16-android-vendor");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli(
        ["fluxd", "status", "--json"],
        &source,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 0);
    assert!(stderr.is_empty());
    assert_eq!(
        String::from_utf8(stdout).expect("UTF-8 output"),
        concat!(
            "{\"daemon\":\"unsupported_kernel\",",
            "\"kernel\":{\"release\":\"5.9.16-android-vendor\",",
            "\"version\":\"5.9.16\",\"minimum\":\"5.10.0\",",
            "\"supported\":false}}\n"
        )
    );
}

#[test]
fn text_status_accepts_an_android_vendor_suffix() {
    let source = StaticKernelReleaseSource::new("6.6.30-android15-8-gki");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli(["fluxd", "status"], &source, &mut stdout, &mut stderr);

    assert_eq!(exit, 0);
    assert!(stderr.is_empty());
    assert_eq!(
        String::from_utf8(stdout).expect("UTF-8 output"),
        concat!(
            "daemon: stopped\n",
            "kernel release: 6.6.30-android15-8-gki\n",
            "kernel version: 6.6.30\n",
            "minimum kernel: 5.10.0\n",
            "kernel supported: yes\n"
        )
    );
}

#[test]
fn status_rejects_unknown_options_without_probing() {
    let source = StaticKernelReleaseSource::new("6.6.30");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli(
        ["fluxd", "status", "--verbose"],
        &source,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert_eq!(
        String::from_utf8(stderr).expect("UTF-8 error"),
        "fluxd: unknown status option '--verbose'\n"
    );
    assert_eq!(source.calls(), 0);
}
