use flux_core::{CapabilityProfileSource, LegacyMutationGate, Observation};
#[cfg(any(target_os = "linux", target_os = "android"))]
use flux_core::{LegacyArtifactResolution, SelinuxMode};
#[cfg(any(target_os = "linux", target_os = "android"))]
use flux_platform::CapabilityProfilePaths;
use flux_platform::SystemCapabilityProfileSource;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn system_source_collects_one_read_only_snapshot_without_executing_artifacts() {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempfile::tempdir().expect("temporary directory");
    let boot = directory.path().join("boot_id");
    let selinux = directory.path().join("enforce");
    let shell = directory.path().join("sh");
    let dispatcher_target = directory.path().join("dispatcher-target");
    let dispatcher = directory.path().join("dispatcher");
    let addrsync = directory.path().join("addrsync");
    fs::write(&boot, "01234567-89ab-cdef-0123-456789abcdef\n").expect("boot identity");
    fs::write(&selinux, "1\n").expect("SELinux state");
    for path in [&shell, &dispatcher_target, &addrsync] {
        fs::write(path, "exit 99\n").expect("artifact");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("executable mode");
    }
    symlink(&dispatcher_target, &dispatcher).expect("dispatcher symlink");

    let source = SystemCapabilityProfileSource::new(CapabilityProfilePaths::new(
        boot, selinux, shell, dispatcher, addrsync,
    ));
    let profile = source.collect_capability_profile();

    assert_eq!(
        profile.selinux(),
        &Observation::Verified(SelinuxMode::Enforcing)
    );
    assert!(profile.boot_identity().verified().is_some());
    assert_eq!(
        profile
            .legacy_bridge()
            .dispatcher()
            .verified()
            .expect("dispatcher observation")
            .resolution(),
        LegacyArtifactResolution::SymbolicLink
    );
    assert_eq!(profile.legacy_mutation_gate(), LegacyMutationGate::Allowed);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn missing_selinux_node_and_malformed_boot_identity_remain_queryable_facts() {
    use std::fs;

    let directory = tempfile::tempdir().expect("temporary directory");
    let boot = directory.path().join("boot_id");
    fs::write(&boot, "not-a-boot-id\n").expect("malformed boot identity");
    let source = SystemCapabilityProfileSource::new(CapabilityProfilePaths::new(
        boot,
        directory.path().join("missing-enforce"),
        directory.path().join("missing-shell"),
        directory.path().join("missing-dispatcher"),
        directory.path().join("missing-addrsync"),
    ));

    let profile = source.collect_capability_profile();

    assert_eq!(profile.boot_identity(), &Observation::Malformed);
    assert_eq!(profile.selinux(), &Observation::Absent);
    assert!(matches!(
        profile.legacy_mutation_gate(),
        LegacyMutationGate::ReadOnly { .. }
    ));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn bounded_fact_reads_reject_oversized_content_and_symlinks() {
    use std::fs;
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("temporary directory");
    let oversized_boot = directory.path().join("boot_id");
    let real_selinux = directory.path().join("real-enforce");
    let linked_selinux = directory.path().join("enforce");
    fs::write(&oversized_boot, vec![b'a'; 129]).expect("oversized boot identity");
    fs::write(&real_selinux, "1\n").expect("SELinux state");
    symlink(&real_selinux, &linked_selinux).expect("SELinux symlink");
    let source = SystemCapabilityProfileSource::new(CapabilityProfilePaths::new(
        oversized_boot,
        linked_selinux,
        directory.path().join("missing-shell"),
        directory.path().join("missing-dispatcher"),
        directory.path().join("missing-addrsync"),
    ));

    let profile = source.collect_capability_profile();

    assert_eq!(profile.boot_identity(), &Observation::Malformed);
    assert_eq!(profile.selinux(), &Observation::Malformed);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn bounded_fact_reads_reject_a_fifo_without_blocking() {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::mpsc;
    use std::time::Duration;

    let directory = tempfile::tempdir().expect("temporary directory");
    let boot = directory.path().join("boot_id");
    let fifo_name = CString::new(boot.as_os_str().as_bytes()).expect("FIFO path without NUL");
    // SAFETY: `fifo_name` is a valid NUL-terminated pathname and the mode is
    // restricted to ordinary permission bits.
    let result = unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) };
    assert_eq!(result, 0, "create FIFO: {}", io::Error::last_os_error());

    let source = SystemCapabilityProfileSource::new(CapabilityProfilePaths::new(
        boot,
        directory.path().join("missing-enforce"),
        directory.path().join("missing-shell"),
        directory.path().join("missing-dispatcher"),
        directory.path().join("missing-addrsync"),
    ));
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _ = sender.send(source.collect_capability_profile());
    });
    let profile = receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("opening a FIFO must not block");
    worker.join().expect("capability collector worker");

    assert_eq!(profile.boot_identity(), &Observation::Malformed);
    assert!(matches!(
        profile.legacy_mutation_gate(),
        LegacyMutationGate::ReadOnly { .. }
    ));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn bounded_fact_reads_reject_a_stable_device_node() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let source = SystemCapabilityProfileSource::new(CapabilityProfilePaths::new(
        "/dev/null",
        directory.path().join("missing-enforce"),
        directory.path().join("missing-shell"),
        directory.path().join("missing-dispatcher"),
        directory.path().join("missing-addrsync"),
    ));

    let profile = source.collect_capability_profile();

    assert_eq!(profile.boot_identity(), &Observation::Malformed);
    assert!(matches!(
        profile.legacy_mutation_gate(),
        LegacyMutationGate::ReadOnly { .. }
    ));
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[test]
fn unsupported_host_is_still_queryable_and_read_only() {
    let profile = SystemCapabilityProfileSource::default().collect_capability_profile();

    assert!(matches!(
        profile.kernel().release(),
        Observation::Unavailable
    ));
    assert!(matches!(
        profile.legacy_mutation_gate(),
        LegacyMutationGate::ReadOnly { .. }
    ));
}
