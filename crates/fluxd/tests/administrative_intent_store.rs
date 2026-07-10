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
