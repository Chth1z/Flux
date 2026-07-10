use std::fs;

use flux_core::AdministrativeState;
use fluxd::AdministrativeIntentStore;
use tempfile::tempdir;

#[test]
fn same_boot_administrative_intent_round_trips_through_the_runtime_record() {
    let directory = tempdir().expect("temporary directory");
    let boot_id_path = directory.path().join("boot_id");
    let record_path = directory.path().join("intent.json");
    fs::write(&boot_id_path, "boot-a\n").expect("write boot identity");
    let store = AdministrativeIntentStore::new(&record_path, &boot_id_path);

    assert_eq!(
        store.load().expect("missing record is valid"),
        AdministrativeState::Unknown
    );

    store
        .persist(AdministrativeState::Running)
        .expect("persist running intent");

    assert_eq!(
        fs::read_to_string(&record_path).expect("runtime record"),
        concat!(
            "{\"schema_version\":1,\"boot_id\":\"boot-a\",",
            "\"administrative_state\":\"running\"}\n"
        )
    );
    assert_eq!(
        store.load().expect("load same-boot intent"),
        AdministrativeState::Running
    );
}

#[test]
fn previous_boot_intent_is_ignored() {
    let directory = tempdir().expect("temporary directory");
    let boot_id_path = directory.path().join("boot_id");
    let record_path = directory.path().join("intent.json");
    fs::write(&boot_id_path, "boot-b\n").expect("write current boot identity");
    fs::write(
        &record_path,
        concat!(
            "{\"schema_version\":1,\"boot_id\":\"boot-a\",",
            "\"administrative_state\":\"stopped\"}\n"
        ),
    )
    .expect("write previous-boot record");
    let store = AdministrativeIntentStore::new(&record_path, &boot_id_path);

    assert_eq!(
        store.load().expect("stale record is valid"),
        AdministrativeState::Unknown
    );
}

#[test]
fn oversized_administrative_intent_record_is_rejected_before_decoding() {
    let directory = tempdir().expect("temporary directory");
    let boot_id_path = directory.path().join("boot_id");
    let record_path = directory.path().join("intent.json");
    fs::write(&boot_id_path, "boot-a\n").expect("write boot identity");
    fs::write(&record_path, vec![b'x'; 4097]).expect("write oversized intent record");
    let store = AdministrativeIntentStore::new(&record_path, &boot_id_path);

    let error = store
        .load()
        .expect_err("oversized intent record must be rejected");

    assert!(error.to_string().contains("exceeds 4096-byte limit"));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn fifo_intent_record_is_rejected_without_blocking() {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let directory = tempdir().expect("temporary directory");
    let boot_id_path = directory.path().join("boot_id");
    let record_path = directory.path().join("intent.json");
    fs::write(&boot_id_path, "boot-a\n").expect("write boot identity");
    let fifo_path = CString::new(record_path.as_os_str().as_bytes()).expect("FIFO path CString");
    // SAFETY: `fifo_path` is NUL-terminated and the mode is a valid permission mask.
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
    let store = AdministrativeIntentStore::new(&record_path, &boot_id_path);
    let (result_sender, result_receiver) = mpsc::sync_channel(1);
    let loader = thread::spawn(move || {
        result_sender
            .send(store.load())
            .expect("intent load result receiver remains alive");
    });

    let result = match result_receiver.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            match fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&record_path)
            {
                Ok(mut writer) => writer.write_all(b"not-json\n").expect("write FIFO payload"),
                Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
                Err(error) => panic!("cannot unblock FIFO reader: {error}"),
            }
            loader.join().expect("join unblocked FIFO loader");
            panic!("loading a FIFO blocked instead of rejecting its file type");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("FIFO loader exited without reporting a result");
        }
    };
    loader.join().expect("join FIFO loader");
    let error = result.expect_err("FIFO intent record must be rejected");

    assert!(error.to_string().contains("not a regular file"));
}

#[test]
fn unknown_state_cannot_replace_a_concrete_administrative_intent() {
    let directory = tempdir().expect("temporary directory");
    let boot_id_path = directory.path().join("boot_id");
    fs::write(&boot_id_path, "boot-a\n").expect("write boot identity");
    let store = AdministrativeIntentStore::new(directory.path().join("intent.json"), &boot_id_path);

    let error = store
        .persist(AdministrativeState::Unknown)
        .expect_err("unknown intent must be rejected");

    assert!(error.to_string().contains("cannot persist unknown"));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn parent_symlink_is_rejected_without_writing_through_it() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("temporary directory");
    let outside = directory.path().join("outside");
    let linked_parent = directory.path().join("linked-state");
    let boot_id_path = directory.path().join("boot_id");
    fs::create_dir(&outside).expect("create outside directory");
    symlink(&outside, &linked_parent).expect("create parent symlink");
    fs::write(&boot_id_path, "boot-a\n").expect("write boot identity");

    let store = AdministrativeIntentStore::new(linked_parent.join("intent.json"), &boot_id_path);
    let load_error = store
        .load()
        .expect_err("symlinked parent must also be rejected for reads");
    let error = store
        .persist(AdministrativeState::Running)
        .expect_err("symlinked parent must be rejected");

    assert!(load_error.to_string().contains("symbolic-link intent path"));
    assert!(error.to_string().contains("symbolic-link intent path"));
    assert!(!outside.join("intent.json").exists());
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn final_symlink_is_rejected_without_reading_or_replacing_its_target() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("temporary directory");
    let boot_id_path = directory.path().join("boot_id");
    let outside_record = directory.path().join("outside.json");
    let record_path = directory.path().join("intent.json");
    fs::write(&boot_id_path, "boot-a\n").expect("write boot identity");
    fs::write(&outside_record, "do-not-touch\n").expect("write outside sentinel");
    symlink(&outside_record, &record_path).expect("create final symlink");
    let store = AdministrativeIntentStore::new(&record_path, &boot_id_path);

    let load_error = store
        .load()
        .expect_err("final symlink must be rejected for reads");
    let persist_error = store
        .persist(AdministrativeState::Stopped)
        .expect_err("final symlink must be rejected for writes");

    assert!(load_error.to_string().contains("symbolic-link intent path"));
    assert!(
        persist_error
            .to_string()
            .contains("symbolic-link intent path")
    );
    assert_eq!(
        fs::read_to_string(&outside_record).expect("outside sentinel"),
        "do-not-touch\n"
    );
}

#[test]
fn io_errors_expose_their_raw_os_error() {
    let directory = tempdir().expect("temporary directory");
    let store = AdministrativeIntentStore::new(
        directory.path().join("intent.json"),
        directory.path().join("missing-boot-id"),
    );

    let error = store.load().expect_err("missing boot identity must fail");

    assert!(error.raw_os_error().is_some());
}
