use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use flux_core::{
    BootIdentity, GenerationId, NetworkNamespaceIdentity, OwnershipJournalIdentity,
    OwnershipJournalRevision,
};
use tempfile::TempDir;

use super::*;

#[test]
fn canonical_journal_and_lease_round_trip_with_exact_paths() {
    let fixture = Fixture::new();
    let binding = test_binding(1);
    let initial = record(
        binding.clone(),
        1,
        NativeXtablesJournalPhase::Activating,
        b"target=v4+v6\0previous=absent",
    );

    let lease = fixture
        .store
        .acquire(initial.clone())
        .expect("durably acquire native owner");

    assert_eq!(lease.binding(), &binding);
    assert_eq!(
        fixture.store.journal_path(),
        fixture.root().join("native_xtables.journal")
    );
    assert_eq!(
        fixture.store.lease_path(),
        fixture.root().join("native_xtables.lease")
    );
    assert_eq!(
        fixture.store.writer_lock_path(),
        fixture.root().join("xtables-writer.lock")
    );
    assert_eq!(fixture.store.load_journal().unwrap(), Some(initial.clone()));
    assert_eq!(
        fixture.store.load_lease().unwrap(),
        Some(binding.lease_scope())
    );
    assert!(!fixture.store.writer_lock_exists().unwrap());

    let journal_bytes = fs::read(fixture.store.journal_path()).unwrap();
    let lease_bytes = fs::read(fixture.store.lease_path()).unwrap();
    assert!(journal_bytes.ends_with(b"\n"));
    assert!(lease_bytes.ends_with(b"\n"));
    assert!(journal_bytes.len() <= MAX_NATIVE_XTABLES_DURABLE_RECORD_BYTES);
    assert!(lease_bytes.len() <= MAX_NATIVE_XTABLES_DURABLE_RECORD_BYTES);
    assert_eq!(parse_journal(&journal_bytes).unwrap(), initial);
    assert_eq!(parse_lease(&lease_bytes).unwrap(), binding.lease_scope());

    drop(lease);
    match fixture.store.recover(&test_binding(1)).unwrap() {
        NativeXtablesRecovery::Leased(recovered) => {
            assert_eq!(recovered.binding(), &test_binding(1));
        }
        other => panic!("expected recovered durable lease, found {other:?}"),
    }
}

#[test]
fn acquisition_conflicts_and_updates_require_exact_lease_and_next_revision() {
    let fixture = Fixture::new();
    let binding = test_binding(2);
    let mut lease = fixture
        .store
        .acquire(record(
            binding.clone(),
            7,
            NativeXtablesJournalPhase::Activating,
            b"initial",
        ))
        .unwrap();

    let conflict = fixture
        .store
        .acquire(record(
            test_binding(3),
            1,
            NativeXtablesJournalPhase::Activating,
            b"other",
        ))
        .expect_err("a live lease must block another acquisition");
    assert!(matches!(conflict, NativeXtablesDurableError::LeaseConflict));
    assert!(!fixture.store.writer_lock_exists().unwrap());

    let wrong_revision = lease
        .update(record(
            binding.clone(),
            9,
            NativeXtablesJournalPhase::Active,
            b"skipped revision",
        ))
        .expect_err("journal revisions must advance exactly once");
    assert!(matches!(
        wrong_revision,
        NativeXtablesDurableError::RevisionConflict { .. }
    ));
    assert!(!fixture.store.writer_lock_exists().unwrap());

    let wrong_binding = lease
        .update(record(
            test_binding(4),
            8,
            NativeXtablesJournalPhase::Active,
            b"stale binding",
        ))
        .expect_err("update must remain bound to the acquired lease");
    assert!(matches!(
        wrong_binding,
        NativeXtablesDurableError::BindingMismatch { .. }
    ));
    assert_eq!(
        fixture
            .store
            .load_journal()
            .unwrap()
            .unwrap()
            .revision()
            .get(),
        7
    );

    lease
        .update(record(
            binding,
            8,
            NativeXtablesJournalPhase::Active,
            b"active",
        ))
        .expect("exact next revision under exact lease");
    assert_eq!(
        fixture
            .store
            .load_journal()
            .unwrap()
            .unwrap()
            .revision()
            .get(),
        8
    );
}

#[test]
fn attempt_sidecar_advances_without_changing_primary_journal_and_requires_exact_retirement() {
    let fixture = Fixture::new();
    let binding = test_binding(20);
    let mut lease = fixture
        .store
        .acquire(record(
            binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"target=active",
        ))
        .unwrap();
    lease
        .update(record(
            binding.clone(),
            2,
            NativeXtablesJournalPhase::Active,
            b"target=active",
        ))
        .unwrap();
    let primary = fs::read(fixture.store.journal_path()).unwrap();
    let reserved = attempt(
        binding.clone(),
        NativeXtablesAttemptPhase::Reserved,
        b"nonce=20;selector=v4",
    );
    lease.publish_attempt(reserved.clone()).unwrap();
    assert_eq!(fs::read(fixture.store.journal_path()).unwrap(), primary);
    assert_eq!(
        fixture.store.load_attempt().unwrap(),
        Some(reserved.clone())
    );
    assert!(fixture.store.observe_read_only().unwrap().attempt_present());

    let populated = attempt(
        binding.clone(),
        NativeXtablesAttemptPhase::PopulateSelectorIpv4,
        b"nonce=20;selector=v4",
    );
    lease.update_attempt(&reserved, populated.clone()).unwrap();
    assert_eq!(fs::read(fixture.store.journal_path()).unwrap(), primary);

    drop(lease);
    let mut lease = match fixture.store.recover(&binding).unwrap() {
        NativeXtablesRecovery::OutstandingAttempt { lease, record } => {
            assert_eq!(record, populated);
            lease
        }
        other => {
            panic!("outstanding attempt must remain explicit during recovery, found {other:?}")
        }
    };

    let blocked = lease
        .update(record(
            binding.clone(),
            3,
            NativeXtablesJournalPhase::Retiring,
            b"must not advance primary",
        ))
        .expect_err("primary journal cannot advance while an attempt is present");
    assert!(matches!(
        blocked,
        NativeXtablesDurableError::AttemptConflict
    ));

    for invalid in [populated.clone(), reserved.clone()] {
        assert!(matches!(
            lease.update_attempt(&populated, invalid),
            Err(NativeXtablesDurableError::InvalidRecord {
                artifact: DurableArtifact::Attempt,
                ..
            })
        ));
    }

    let changed_payload = attempt(
        binding.clone(),
        NativeXtablesAttemptPhase::Active,
        b"nonce=20;selector=v6",
    );
    assert!(matches!(
        lease.update_attempt(&populated, changed_payload),
        Err(NativeXtablesDurableError::InvalidRecord {
            artifact: DurableArtifact::Attempt,
            ..
        })
    ));

    let replacement_binding = NativeXtablesJournalBinding::new(
        binding.boot_identity().clone(),
        binding.network_namespace(),
        GenerationId::new(binding.generation().get() + 1).unwrap(),
        binding.journal_identity(),
    );
    assert!(matches!(
        lease.rebind(record(
            replacement_binding,
            1,
            NativeXtablesJournalPhase::Active,
            b"replacement must remain blocked",
        )),
        Err(NativeXtablesDurableError::AttemptConflict)
    ));

    let substituted = attempt(
        binding.clone(),
        NativeXtablesAttemptPhase::Active,
        b"nonce=21;selector=v4",
    );
    let error = lease
        .remove_attempt(&substituted)
        .expect_err("retirement must reject a substituted sidecar");
    assert!(matches!(
        error,
        NativeXtablesDurableError::BindingMismatch {
            artifact: DurableArtifact::Attempt
        }
    ));

    let error = lease
        .complete(record(
            binding.clone(),
            3,
            NativeXtablesJournalPhase::CleanAbsent,
            b"completion must remain blocked",
        ))
        .expect_err("completion cannot retire the primary owner with an attempt present");
    assert!(matches!(error, NativeXtablesDurableError::AttemptConflict));
    let mut lease = match fixture.store.recover(&binding).unwrap() {
        NativeXtablesRecovery::OutstandingAttempt { lease, record } => {
            assert_eq!(record, populated);
            lease
        }
        other => panic!("failed completion must retain the attempt, found {other:?}"),
    };
    lease.remove_attempt(&populated).unwrap();
    assert!(fixture.store.load_attempt().unwrap().is_none());
    assert!(!fixture.store.observe_read_only().unwrap().attempt_present());
    assert_eq!(fs::read(fixture.store.journal_path()).unwrap(), primary);
}

#[test]
fn current_boot_attempt_requires_an_active_primary_journal() {
    let fixture = Fixture::new();
    let binding = test_binding(22);
    let lease = fixture
        .store
        .acquire(record(
            binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"not active",
        ))
        .unwrap();
    fs::write(
        fixture.store.attempt_path(),
        encode_attempt(&attempt(
            binding.clone(),
            NativeXtablesAttemptPhase::Reserved,
            b"nonce=22",
        )),
    )
    .unwrap();
    drop(lease);

    assert!(matches!(
        fixture.store.recover(&binding).unwrap_err(),
        NativeXtablesDurableError::OrphanedAttempt
    ));
    assert!(fixture.store.writer_lock_exists().unwrap());
    assert!(matches!(
        fixture
            .store
            .inspect_for_recovery(&binding.lease_scope())
            .unwrap_err(),
        NativeXtablesDurableError::OrphanedAttempt
    ));

    let terminal = Fixture::new();
    let binding = test_binding(26);
    let lease = terminal
        .store
        .acquire(record(
            binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"terminal control",
        ))
        .unwrap();
    lease
        .complete(record(
            binding.clone(),
            2,
            NativeXtablesJournalPhase::CleanAbsent,
            b"terminal control",
        ))
        .unwrap();
    fs::write(
        terminal.store.attempt_path(),
        encode_attempt(&attempt(
            binding.clone(),
            NativeXtablesAttemptPhase::Reserved,
            b"nonce=terminal",
        )),
    )
    .unwrap();

    assert!(matches!(
        terminal.store.recover(&binding).unwrap_err(),
        NativeXtablesDurableError::OrphanedAttempt
    ));
}

#[test]
fn attempt_crash_boundaries_preserve_exact_recoverable_state() {
    for event in [
        DurableEvent::AttemptTempDurable,
        DurableEvent::AttemptDurable,
    ] {
        let fixture = Fixture::new();
        let binding = test_binding(23 + u8::from(event == DurableEvent::AttemptDurable));
        let mut lease = fixture
            .store
            .acquire(record(
                binding.clone(),
                1,
                NativeXtablesJournalPhase::Activating,
                b"active target",
            ))
            .unwrap();
        lease
            .update(record(
                binding.clone(),
                2,
                NativeXtablesJournalPhase::Active,
                b"active target",
            ))
            .unwrap();
        let primary = fs::read(fixture.store.journal_path()).unwrap();
        let reserved = attempt(
            binding.clone(),
            NativeXtablesAttemptPhase::Reserved,
            b"nonce=crash",
        );
        let next = attempt(
            binding.clone(),
            NativeXtablesAttemptPhase::PopulateSelectorIpv4,
            b"nonce=crash",
        );
        lease.publish_attempt(reserved.clone()).unwrap();
        fixture.store.set_failpoint(Some(event));

        assert!(matches!(
            lease.update_attempt(&reserved, next.clone()),
            Err(NativeXtablesDurableError::InterruptedAt(actual)) if actual == event
        ));
        drop(lease);
        assert!(fixture.store.writer_lock_exists().unwrap());
        assert_eq!(fs::read(fixture.store.journal_path()).unwrap(), primary);
        let expected = if event == DurableEvent::AttemptTempDurable {
            reserved
        } else {
            next.clone()
        };
        let (mut lease, recovered) = match fixture.store.recover(&binding).unwrap() {
            NativeXtablesRecovery::OutstandingAttempt { lease, record } => (lease, record),
            other => {
                panic!("attempt publication boundary must recover explicitly, found {other:?}")
            }
        };
        assert_eq!(recovered, expected);
        if recovered != next {
            lease.update_attempt(&recovered, next.clone()).unwrap();
        }
        lease.remove_attempt(&next).unwrap();
    }

    let fixture = Fixture::new();
    let binding = test_binding(25);
    let mut lease = fixture
        .store
        .acquire(record(
            binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"active target",
        ))
        .unwrap();
    lease
        .update(record(
            binding.clone(),
            2,
            NativeXtablesJournalPhase::Active,
            b"active target",
        ))
        .unwrap();
    let primary = fs::read(fixture.store.journal_path()).unwrap();
    let reserved = attempt(
        binding.clone(),
        NativeXtablesAttemptPhase::Reserved,
        b"nonce=remove",
    );
    lease.publish_attempt(reserved.clone()).unwrap();
    fixture
        .store
        .set_failpoint(Some(DurableEvent::AttemptRemovedDurable));

    assert!(matches!(
        lease.remove_attempt(&reserved),
        Err(NativeXtablesDurableError::InterruptedAt(
            DurableEvent::AttemptRemovedDurable
        ))
    ));
    drop(lease);
    assert!(fixture.store.writer_lock_exists().unwrap());
    assert!(fixture.store.load_attempt().unwrap().is_none());
    assert_eq!(fs::read(fixture.store.journal_path()).unwrap(), primary);
    match fixture.store.recover(&binding).unwrap() {
        NativeXtablesRecovery::Leased(_) => {}
        other => panic!("durable attempt removal must recover the primary lease, found {other:?}"),
    }
}

#[test]
fn malformed_or_orphaned_attempt_sidecar_blocks_recovery_and_new_acquisition() {
    let fixture = Fixture::new();
    assert!(matches!(
        NativeXtablesAttemptPayload::new(vec![0; MAX_NATIVE_XTABLES_ATTEMPT_PAYLOAD_BYTES + 1]),
        Err(NativeXtablesDurableError::AttemptPayloadTooLarge { .. })
    ));
    fs::write(fixture.store.attempt_path(), b"not-a-canonical-attempt\n").unwrap();
    let error = fixture
        .store
        .load_attempt()
        .expect_err("malformed attempt sidecar must not be accepted");
    assert!(matches!(
        error,
        NativeXtablesDurableError::InvalidRecord {
            artifact: DurableArtifact::Attempt,
            ..
        }
    ));
    let error = fixture
        .store
        .acquire(record(
            test_binding(21),
            1,
            NativeXtablesJournalPhase::Activating,
            b"new owner",
        ))
        .expect_err("an orphaned attempt must block a fresh owner");
    assert!(matches!(
        error,
        NativeXtablesDurableError::InvalidRecord {
            artifact: DurableArtifact::Attempt,
            ..
        }
    ));
    assert!(fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn recovery_rejects_each_stale_binding_dimension() {
    let fixture = Fixture::new();
    let actual = test_binding(5);
    drop(
        fixture
            .store
            .acquire(record(
                actual.clone(),
                1,
                NativeXtablesJournalPhase::Activating,
                b"owned",
            ))
            .unwrap(),
    );

    let stale = [
        NativeXtablesJournalBinding::new(
            BootIdentity::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
            actual.network_namespace(),
            actual.generation(),
            actual.journal_identity(),
        ),
        NativeXtablesJournalBinding::new(
            actual.boot_identity().clone(),
            NetworkNamespaceIdentity::new(99, 100).unwrap(),
            actual.generation(),
            actual.journal_identity(),
        ),
        NativeXtablesJournalBinding::new(
            actual.boot_identity().clone(),
            actual.network_namespace(),
            GenerationId::new(actual.generation().get() + 1).unwrap(),
            actual.journal_identity(),
        ),
        NativeXtablesJournalBinding::new(
            actual.boot_identity().clone(),
            actual.network_namespace(),
            actual.generation(),
            OwnershipJournalIdentity::new([0x7f; 32]).unwrap(),
        ),
    ];

    for expected in stale {
        let error = fixture
            .store
            .recover(&expected)
            .expect_err("stale recovery binding must fail closed");
        assert!(matches!(
            error,
            NativeXtablesDurableError::BindingMismatch { .. }
        ));
        assert_eq!(
            fixture.store.load_lease().unwrap(),
            Some(actual.lease_scope())
        );
        assert!(!fixture.store.writer_lock_exists().unwrap());
    }
}

#[test]
fn atomic_replacement_preserves_old_journal_before_rename() {
    let fixture = Fixture::new();
    let binding = test_binding(6);
    let initial = record(
        binding.clone(),
        1,
        NativeXtablesJournalPhase::Activating,
        b"old",
    );
    let mut lease = fixture.store.acquire(initial.clone()).unwrap();
    let old_bytes = fs::read(fixture.store.journal_path()).unwrap();

    fixture
        .store
        .set_failpoint(Some(DurableEvent::JournalTempDurable));
    let error = lease
        .update(record(
            binding.clone(),
            2,
            NativeXtablesJournalPhase::Active,
            b"new",
        ))
        .expect_err("simulated interruption before atomic rename");
    assert!(matches!(
        error,
        NativeXtablesDurableError::InterruptedAt(DurableEvent::JournalTempDurable)
    ));
    assert_eq!(fs::read(fixture.store.journal_path()).unwrap(), old_bytes);
    assert_eq!(fixture.store.load_journal().unwrap(), Some(initial));
    assert_eq!(
        fixture.store.load_lease().unwrap(),
        Some(binding.lease_scope())
    );
    assert!(fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn live_native_owner_guard_prevents_recovery_from_stealing_paused_writer_lock() {
    let fixture = Fixture::new();
    let binding = test_binding(60);
    let mut lease = fixture
        .store
        .acquire(record(
            binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"old",
        ))
        .unwrap();
    fixture.store.pause_at(DurableEvent::JournalTempDurable);

    let update_binding = binding.clone();
    let update = std::thread::spawn(move || {
        lease.update(record(
            update_binding,
            2,
            NativeXtablesJournalPhase::Active,
            b"new",
        ))
    });
    fixture
        .store
        .wait_until_paused(DurableEvent::JournalTempDurable);

    let error = fixture
        .store
        .recover(&binding)
        .expect_err("recovery must not adopt a live native writer lock");
    assert!(matches!(error, NativeXtablesDurableError::NativeOwnerBusy));
    assert!(fixture.store.writer_lock_exists().unwrap());
    assert_eq!(
        fixture.store.load_journal().unwrap().unwrap().revision(),
        OwnershipJournalRevision::new(1).unwrap()
    );

    fixture.store.release_pause();
    update.join().unwrap().unwrap();
    assert!(!fixture.store.writer_lock_exists().unwrap());
    assert_eq!(
        fixture.store.load_journal().unwrap().unwrap().revision(),
        OwnershipJournalRevision::new(2).unwrap()
    );
}

#[test]
fn rebind_atomically_replaces_generation_under_component_scoped_lease() {
    let fixture = Fixture::new();
    let old = test_binding(61);
    let replacement = replacement_binding(&old, old.generation().get() + 1);
    let scope = old.lease_scope();
    let mut lease = fixture
        .store
        .acquire(record(
            old.clone(),
            8,
            NativeXtablesJournalPhase::Activating,
            b"current=old;target=old",
        ))
        .unwrap();
    lease
        .update(record(
            old.clone(),
            9,
            NativeXtablesJournalPhase::Active,
            b"current=old;target=replacement",
        ))
        .unwrap();

    lease
        .rebind(record(
            replacement.clone(),
            10,
            NativeXtablesJournalPhase::Active,
            b"current=replacement;previous=old",
        ))
        .unwrap();

    assert_eq!(lease.binding(), &replacement);
    assert_eq!(fixture.store.load_lease().unwrap(), Some(scope));
    assert_eq!(
        fixture.store.load_journal().unwrap().unwrap().binding(),
        &replacement
    );
    assert!(!fixture.store.writer_lock_exists().unwrap());
    lease
        .update(record(
            replacement.clone(),
            11,
            NativeXtablesJournalPhase::Active,
            b"replacement active",
        ))
        .expect("replacement journal continues at its exact next revision");
}

#[test]
fn interrupted_rebind_recovers_exact_old_or_new_generation_without_releasing_lease() {
    for (event, expect_replacement) in [
        (DurableEvent::JournalTempDurable, false),
        (DurableEvent::JournalDurable, true),
    ] {
        let fixture = Fixture::new();
        let old = test_binding(if expect_replacement { 63 } else { 62 });
        let replacement = replacement_binding(&old, old.generation().get() + 1);
        let mut lease = fixture
            .store
            .acquire(record(
                old.clone(),
                3,
                NativeXtablesJournalPhase::Activating,
                b"old activating",
            ))
            .unwrap();
        lease
            .update(record(
                old.clone(),
                4,
                NativeXtablesJournalPhase::Active,
                b"old active",
            ))
            .unwrap();
        fixture.store.set_failpoint(Some(event));

        let error = lease
            .rebind(record(
                replacement.clone(),
                5,
                NativeXtablesJournalPhase::Active,
                b"current=replacement;previous=old",
            ))
            .expect_err("injected rebind interruption");
        assert!(
            matches!(error, NativeXtablesDurableError::InterruptedAt(actual) if actual == event)
        );
        assert_eq!(fixture.store.load_lease().unwrap(), Some(old.lease_scope()));
        assert!(fixture.store.writer_lock_exists().unwrap());
        let observed = fixture.store.load_journal().unwrap().unwrap();
        let expected = if expect_replacement {
            &replacement
        } else {
            &old
        };
        assert_eq!(observed.binding(), expected);

        drop(lease);
        match fixture.store.recover(expected).unwrap() {
            NativeXtablesRecovery::Leased(recovered) => {
                assert_eq!(recovered.binding(), expected);
            }
            other => panic!("interrupted rebind must recover exact binding, found {other:?}"),
        }
        assert!(!fixture.store.writer_lock_exists().unwrap());
    }
}

#[test]
fn nofollow_io_refuses_symlinks_directories_and_symlinked_roots() {
    let fixture = Fixture::new();
    let outside = fixture.directory.path().join("outside");
    fs::write(&outside, b"do not replace").unwrap();
    symlink(&outside, fixture.store.lease_path()).unwrap();
    let lease_error = fixture
        .store
        .acquire(record(
            test_binding(7),
            1,
            NativeXtablesJournalPhase::Activating,
            b"lease symlink",
        ))
        .expect_err("lease symlink must be refused");
    assert!(matches!(lease_error, NativeXtablesDurableError::Symlink(_)));
    assert_eq!(fs::read(&outside).unwrap(), b"do not replace");
    assert!(fixture.store.writer_lock_exists().unwrap());

    let directory_fixture = Fixture::new();
    fs::create_dir(directory_fixture.store.journal_path()).unwrap();
    let directory_error = directory_fixture
        .store
        .acquire(record(
            test_binding(8),
            1,
            NativeXtablesJournalPhase::Activating,
            b"directory",
        ))
        .expect_err("journal directory must be refused");
    assert!(matches!(
        directory_error,
        NativeXtablesDurableError::UnexpectedFileType(_)
    ));

    let root_fixture = tempfile::tempdir().unwrap();
    let real_root = root_fixture.path().join("real");
    let linked_root = root_fixture.path().join("linked");
    fs::create_dir(&real_root).unwrap();
    symlink(&real_root, &linked_root).unwrap();
    let linked_store = NativeXtablesDurableStore::new(linked_root.join("state"));
    let root_error = linked_store
        .acquire(record(
            test_binding(9),
            1,
            NativeXtablesJournalPhase::Activating,
            b"root symlink",
        ))
        .expect_err("symlinked root component must be refused");
    assert!(matches!(root_error, NativeXtablesDurableError::Symlink(_)));
}

#[test]
fn ownerless_writer_lock_remains_fail_closed_and_is_never_adopted() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.store.writer_lock_path()).unwrap();

    let error = fixture
        .store
        .recover(&test_binding(65))
        .expect_err("an ownerless lock cannot be identified as native state");
    assert!(matches!(
        error,
        NativeXtablesDurableError::InterruptedPublication
    ));
    assert!(fixture.store.writer_lock_exists().unwrap());
    assert!(fixture.store.load_journal().unwrap().is_none());
    assert!(fixture.store.load_lease().unwrap().is_none());
}

#[test]
fn recovery_inspection_fences_vacant_state_until_live_absence_is_proved() {
    let fixture = Fixture::new();
    let scope = test_binding(66).lease_scope();

    let fence = match fixture.store.inspect_for_recovery(&scope).unwrap() {
        NativeXtablesRecoveryInspection::Vacant(fence) => fence,
        other => panic!("fresh durable state must be fenced as vacant, found {other:?}"),
    };

    assert!(fixture.store.writer_lock_exists().unwrap());
    assert!(matches!(
        fixture.store.inspect_for_recovery(&scope).unwrap_err(),
        NativeXtablesDurableError::NativeOwnerBusy
    ));

    fence.finish_clean().unwrap();
    assert!(!fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn recovery_inspection_adopts_a_prejournal_native_lock_only_boundary() {
    let fixture = Fixture::new();
    let binding = test_binding(67);
    fixture
        .store
        .set_failpoint(Some(DurableEvent::WriterLockDurable));
    assert!(matches!(
        fixture.store.acquire(record(
            binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"pre-journal",
        )),
        Err(NativeXtablesDurableError::InterruptedAt(
            DurableEvent::WriterLockDurable
        ))
    ));
    assert!(fixture.store.load_journal().unwrap().is_none());
    assert!(fixture.store.load_lease().unwrap().is_none());

    let fence = match fixture
        .store
        .inspect_for_recovery(&binding.lease_scope())
        .unwrap()
    {
        NativeXtablesRecoveryInspection::Vacant(fence) => fence,
        other => panic!("pre-journal native publication is mutation-safe, found {other:?}"),
    };
    assert!(fixture.store.writer_lock_exists().unwrap());

    fence.finish_clean().unwrap();
    assert!(!fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn recovery_inspection_retires_an_internally_consistent_previous_boot_pair_on_finish() {
    let fixture = Fixture::new();
    let previous = test_binding(69);
    let mut lease = fixture
        .store
        .acquire(record(
            previous.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"previous boot",
        ))
        .unwrap();
    lease
        .update(record(
            previous.clone(),
            2,
            NativeXtablesJournalPhase::Active,
            b"previous boot",
        ))
        .unwrap();
    let reserved = attempt(
        previous.clone(),
        NativeXtablesAttemptPhase::Reserved,
        b"nonce=69;selector=v4",
    );
    lease.publish_attempt(reserved.clone()).unwrap();
    lease
        .update_attempt(
            &reserved,
            attempt(
                previous.clone(),
                NativeXtablesAttemptPhase::Active,
                b"nonce=69;selector=v4",
            ),
        )
        .unwrap();
    drop(lease);
    let _ = fixture.store.take_events();
    let current = NativeXtablesLeaseScope::new(
        BootIdentity::parse("11111111-aaaa-bbbb-cccc-222222222222").unwrap(),
        previous.network_namespace(),
        previous.journal_identity(),
    );

    let fence = match fixture.store.inspect_for_recovery(&current).unwrap() {
        NativeXtablesRecoveryInspection::Vacant(fence) => fence,
        other => panic!("previous-boot durable pair must become fenced vacant, found {other:?}"),
    };
    assert!(fixture.store.load_journal().unwrap().is_some());
    assert!(fixture.store.load_lease().unwrap().is_some());
    assert!(fixture.store.load_attempt().unwrap().is_some());
    assert!(fixture.store.writer_lock_exists().unwrap());

    fence.finish_clean().unwrap();
    assert_event_order(
        &fixture.store.take_events(),
        &[
            DurableEvent::TerminalJournalDurable,
            DurableEvent::AttemptRemovedDurable,
            DurableEvent::LeaseRemovedDurable,
            DurableEvent::JournalRemovedDurable,
            DurableEvent::WriterLockReleased,
        ],
    );
    assert!(fixture.store.load_journal().unwrap().is_none());
    assert!(fixture.store.load_lease().unwrap().is_none());
    assert!(fixture.store.load_attempt().unwrap().is_none());
    assert!(!fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn unrecognized_or_mixed_writer_lock_entries_remain_fail_closed() {
    for include_native in [false, true] {
        let fixture = Fixture::new();
        let scope = current_scope(if include_native { 86 } else { 70 });
        fs::create_dir(fixture.store.writer_lock_path()).unwrap();
        if include_native {
            fs::write(
                fixture.store.writer_lock_path().join("native-owner"),
                encode_writer_owner(&scope),
            )
            .unwrap();
        }
        fs::write(
            fixture.store.writer_lock_path().join("unrecognized-owner"),
            b"opaque\n",
        )
        .unwrap();

        assert!(matches!(
            fixture.store.inspect_for_recovery(&scope).unwrap_err(),
            NativeXtablesDurableError::InterruptedPublication
        ));
        assert!(fixture.store.writer_lock_exists().unwrap());
    }
}

#[test]
fn recovery_inspection_adopts_a_previous_boot_native_lock_only_boundary() {
    let fixture = Fixture::new();
    let previous = test_binding(73);
    fixture
        .store
        .set_failpoint(Some(DurableEvent::WriterLockDurable));
    assert!(matches!(
        fixture.store.acquire(record(
            previous.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"previous boot pre-journal",
        )),
        Err(NativeXtablesDurableError::InterruptedAt(
            DurableEvent::WriterLockDurable
        ))
    ));
    let current = current_scope_for_binding(&previous);

    let fence = match fixture.store.inspect_for_recovery(&current).unwrap() {
        NativeXtablesRecoveryInspection::Vacant(fence) => fence,
        other => panic!("previous-boot native lock-only must be recoverable, found {other:?}"),
    };
    fence.finish_clean().unwrap();
    assert!(!fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn recovery_inspection_retires_previous_boot_journal_before_lease_boundary() {
    for event in [
        DurableEvent::JournalDurable,
        DurableEvent::JournalBeforeLease,
    ] {
        let fixture = Fixture::new();
        let previous = test_binding(78);
        fixture.store.set_failpoint(Some(event));

        assert!(matches!(
            fixture.store.acquire(record(
                previous.clone(),
                1,
                NativeXtablesJournalPhase::Activating,
                b"previous boot pre-lease",
            )),
            Err(NativeXtablesDurableError::InterruptedAt(actual)) if actual == event
        ));
        assert!(fixture.store.writer_lock_exists().unwrap());
        assert!(fixture.store.load_journal().unwrap().is_some());
        assert!(fixture.store.load_lease().unwrap().is_none());

        let fence = match fixture
            .store
            .inspect_for_recovery(&current_scope_for_binding(&previous))
            .unwrap()
        {
            NativeXtablesRecoveryInspection::Vacant(fence) => fence,
            other => panic!(
                "previous-boot journal-before-lease boundary must be fenced vacant, found {other:?}"
            ),
        };
        assert!(fixture.store.writer_lock_exists().unwrap());

        fence.finish_clean().unwrap();
        assert!(fixture.store.load_journal().unwrap().is_none());
        assert!(fixture.store.load_lease().unwrap().is_none());
        assert!(!fixture.store.writer_lock_exists().unwrap());
    }
}

#[test]
fn previous_boot_journal_before_lease_rejects_mismatched_native_writer_scope() {
    let fixture = Fixture::new();
    let journal_binding = test_binding(81);
    fixture
        .store
        .set_failpoint(Some(DurableEvent::JournalDurable));
    assert!(matches!(
        fixture.store.acquire(record(
            journal_binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"previous boot mismatched writer",
        )),
        Err(NativeXtablesDurableError::InterruptedAt(
            DurableEvent::JournalDurable
        ))
    ));
    fs::write(
        fixture.store.writer_lock_path().join("native-owner"),
        encode_writer_owner(&test_binding(83).lease_scope()),
    )
    .unwrap();

    let error = fixture
        .store
        .inspect_for_recovery(&current_scope_for_binding(&journal_binding))
        .expect_err("mismatched previous-boot writer and journal scopes must fail closed");

    assert!(matches!(
        error,
        NativeXtablesDurableError::BindingMismatch {
            artifact: DurableArtifact::Lease
        }
    ));
    assert!(fixture.store.load_journal().unwrap().is_some());
    assert!(fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn recovery_inspection_retires_every_nonterminal_previous_boot_phase() {
    for phase in [
        NativeXtablesJournalPhase::Activating,
        NativeXtablesJournalPhase::Active,
        NativeXtablesJournalPhase::Retiring,
        NativeXtablesJournalPhase::Uncertain,
    ] {
        let fixture = Fixture::new();
        let previous = test_binding(74);
        let mut lease = fixture
            .store
            .acquire(record(
                previous.clone(),
                1,
                NativeXtablesJournalPhase::Activating,
                b"previous boot phase",
            ))
            .unwrap();
        if phase != NativeXtablesJournalPhase::Activating {
            lease
                .update(record(previous.clone(), 2, phase, b"previous boot phase"))
                .unwrap();
        }
        drop(lease);

        let fence = match fixture
            .store
            .inspect_for_recovery(&current_scope_for_binding(&previous))
            .unwrap()
        {
            NativeXtablesRecoveryInspection::Vacant(fence) => fence,
            other => panic!("previous-boot {phase:?} pair must retire, found {other:?}"),
        };
        fence.finish_clean().unwrap();
        assert!(fixture.store.load_journal().unwrap().is_none());
        assert!(fixture.store.load_lease().unwrap().is_none());
        assert!(!fixture.store.writer_lock_exists().unwrap());
    }
}

#[test]
fn recovery_inspection_retires_terminal_previous_boot_release_boundaries() {
    for failpoint in [
        Some(DurableEvent::TerminalJournalDurable),
        Some(DurableEvent::LeaseRemovedDurable),
        None,
    ] {
        let fixture = Fixture::new();
        let previous = test_binding(75);
        let lease = fixture
            .store
            .acquire(record(
                previous.clone(),
                1,
                NativeXtablesJournalPhase::Activating,
                b"previous boot terminal",
            ))
            .unwrap();
        fixture.store.set_failpoint(failpoint);
        let completion = lease.complete(record(
            previous.clone(),
            2,
            NativeXtablesJournalPhase::CleanAbsent,
            b"previous boot terminal",
        ));
        if let Some(event) = failpoint {
            assert!(matches!(
                completion,
                Err(NativeXtablesDurableError::InterruptedAt(actual)) if actual == event
            ));
        } else {
            completion.unwrap();
        }

        let fence = match fixture
            .store
            .inspect_for_recovery(&current_scope_for_binding(&previous))
            .unwrap()
        {
            NativeXtablesRecoveryInspection::Vacant(fence) => fence,
            other => panic!("terminal previous-boot boundary must retire, found {other:?}"),
        };
        fence.finish_clean().unwrap();
        assert!(fixture.store.load_journal().unwrap().is_none());
        assert!(fixture.store.load_lease().unwrap().is_none());
        assert!(!fixture.store.writer_lock_exists().unwrap());
    }
}

#[test]
fn previous_boot_retirement_resumes_after_each_durable_cleanup_boundary() {
    for event in [
        DurableEvent::TerminalJournalDurable,
        DurableEvent::AttemptRemovedDurable,
        DurableEvent::LeaseRemovedDurable,
        DurableEvent::JournalRemovedDurable,
    ] {
        let fixture = Fixture::new();
        let previous = test_binding(76);
        let mut lease = fixture
            .store
            .acquire(record(
                previous.clone(),
                1,
                NativeXtablesJournalPhase::Activating,
                b"retirement retry",
            ))
            .unwrap();
        lease
            .update(record(
                previous.clone(),
                2,
                NativeXtablesJournalPhase::Active,
                b"retirement retry",
            ))
            .unwrap();
        lease
            .publish_attempt(attempt(
                previous.clone(),
                NativeXtablesAttemptPhase::Reserved,
                b"nonce=previous-boot",
            ))
            .unwrap();
        drop(lease);
        let current = current_scope_for_binding(&previous);
        let fence = match fixture.store.inspect_for_recovery(&current).unwrap() {
            NativeXtablesRecoveryInspection::Vacant(fence) => fence,
            other => panic!("previous-boot pair must enter retirement, found {other:?}"),
        };
        fixture.store.set_failpoint(Some(event));
        assert!(matches!(
            fence.finish_clean(),
            Err(NativeXtablesDurableError::InterruptedAt(actual)) if actual == event
        ));
        assert!(fixture.store.writer_lock_exists().unwrap());

        let retry = match fixture.store.inspect_for_recovery(&current).unwrap() {
            NativeXtablesRecoveryInspection::Vacant(fence) => fence,
            other => panic!("retirement residual must remain recoverable, found {other:?}"),
        };
        retry.finish_clean().unwrap();
        assert!(fixture.store.load_journal().unwrap().is_none());
        assert!(fixture.store.load_lease().unwrap().is_none());
        assert!(fixture.store.load_attempt().unwrap().is_none());
        assert!(!fixture.store.writer_lock_exists().unwrap());
    }
}

#[test]
fn recovery_inspection_keeps_same_boot_incomplete_matrices_fatal() {
    let lease_only = Fixture::new();
    let scope = current_scope(77);
    fs::create_dir_all(lease_only.root()).unwrap();
    fs::write(lease_only.store.lease_path(), encode_lease(&scope)).unwrap();
    assert!(matches!(
        lease_only.store.inspect_for_recovery(&scope).unwrap_err(),
        NativeXtablesDurableError::MissingJournal
    ));
    assert!(lease_only.store.writer_lock_exists().unwrap());

    let journal_only = Fixture::new();
    let binding = NativeXtablesJournalBinding::new(
        scope.boot_identity().clone(),
        scope.network_namespace(),
        GenerationId::new(1).unwrap(),
        scope.journal_identity(),
    );
    fs::create_dir_all(journal_only.root()).unwrap();
    fs::write(
        journal_only.store.journal_path(),
        encode_journal(&record(
            binding,
            1,
            NativeXtablesJournalPhase::Uncertain,
            b"same boot incomplete",
        )),
    )
    .unwrap();
    assert!(matches!(
        journal_only.store.inspect_for_recovery(&scope).unwrap_err(),
        NativeXtablesDurableError::MissingLease
    ));
    assert!(journal_only.store.writer_lock_exists().unwrap());
}

#[test]
fn same_boot_initial_journal_before_lease_remains_fail_closed() {
    let fixture = Fixture::new();
    let scope = current_scope(84);
    let binding = NativeXtablesJournalBinding::new(
        scope.boot_identity().clone(),
        scope.network_namespace(),
        GenerationId::new(85).unwrap(),
        scope.journal_identity(),
    );
    fixture
        .store
        .set_failpoint(Some(DurableEvent::JournalDurable));
    assert!(matches!(
        fixture.store.acquire(record(
            binding,
            1,
            NativeXtablesJournalPhase::Activating,
            b"same boot initial pre-lease",
        )),
        Err(NativeXtablesDurableError::InterruptedAt(
            DurableEvent::JournalDurable
        ))
    ));

    let error = fixture
        .store
        .inspect_for_recovery(&scope)
        .expect_err("same-boot journal-before-lease state remains deliberately blocking");

    assert!(matches!(error, NativeXtablesDurableError::MissingLease));
    assert!(fixture.store.load_journal().unwrap().is_some());
    assert!(fixture.store.load_lease().unwrap().is_none());
    assert!(fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn interrupted_publication_states_remain_blocking_until_complete_evidence_exists() {
    let lock_fixture = Fixture::new();
    lock_fixture
        .store
        .set_failpoint(Some(DurableEvent::WriterLockDurable));
    let binding = test_binding(10);
    let lock_error = lock_fixture
        .store
        .acquire(record(
            binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"lock only",
        ))
        .expect_err("interrupt after durable writer lock");
    assert!(matches!(
        lock_error,
        NativeXtablesDurableError::InterruptedAt(DurableEvent::WriterLockDurable)
    ));
    assert!(lock_fixture.store.writer_lock_exists().unwrap());
    assert!(lock_fixture.store.load_journal().unwrap().is_none());
    assert!(lock_fixture.store.load_lease().unwrap().is_none());
    assert!(matches!(
        lock_fixture.store.recover(&binding).unwrap_err(),
        NativeXtablesDurableError::InterruptedPublication
    ));

    let journal_fixture = Fixture::new();
    journal_fixture
        .store
        .set_failpoint(Some(DurableEvent::JournalDurable));
    let journal_binding = test_binding(11);
    journal_fixture
        .store
        .acquire(record(
            journal_binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"journal only",
        ))
        .expect_err("interrupt after durable journal");
    assert!(journal_fixture.store.writer_lock_exists().unwrap());
    assert!(journal_fixture.store.load_journal().unwrap().is_some());
    assert!(journal_fixture.store.load_lease().unwrap().is_none());
    assert!(matches!(
        journal_fixture.store.recover(&journal_binding).unwrap_err(),
        NativeXtablesDurableError::InterruptedPublication
    ));

    let lease_fixture = Fixture::new();
    lease_fixture
        .store
        .set_failpoint(Some(DurableEvent::LeaseDurable));
    let lease_binding = test_binding(12);
    lease_fixture
        .store
        .acquire(record(
            lease_binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"complete durable pair",
        ))
        .expect_err("interrupt after durable lease");
    assert!(lease_fixture.store.writer_lock_exists().unwrap());
    assert!(lease_fixture.store.load_journal().unwrap().is_some());
    assert!(lease_fixture.store.load_lease().unwrap().is_some());
    match lease_fixture.store.recover(&lease_binding).unwrap() {
        NativeXtablesRecovery::Leased(lease) => assert_eq!(lease.binding(), &lease_binding),
        other => panic!("complete pair should be recoverable, found {other:?}"),
    }
    assert!(!lease_fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn uncertain_state_retains_journal_and_lease_and_cannot_complete() {
    let fixture = Fixture::new();
    let binding = test_binding(13);
    let mut lease = fixture
        .store
        .acquire(record(
            binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"before mutation",
        ))
        .unwrap();
    let uncertain = record(
        binding.clone(),
        2,
        NativeXtablesJournalPhase::Uncertain,
        b"restore outcome unknown",
    );
    lease.update(uncertain.clone()).unwrap();

    let error = lease
        .complete(record(
            binding.clone(),
            3,
            NativeXtablesJournalPhase::Active,
            b"not clean absence",
        ))
        .expect_err("active or uncertain state may not release the lease");
    assert!(matches!(
        error,
        NativeXtablesDurableError::NonTerminalCompletion(NativeXtablesJournalPhase::Active)
    ));
    assert_eq!(fixture.store.load_journal().unwrap(), Some(uncertain));
    assert_eq!(
        fixture.store.load_lease().unwrap(),
        Some(binding.lease_scope())
    );
    match fixture.store.recover(&binding).unwrap() {
        NativeXtablesRecovery::Leased(_) => {}
        other => panic!("uncertain state must retain recoverable lease, found {other:?}"),
    }
}

#[test]
fn terminal_journal_is_durable_before_lease_release() {
    let fixture = Fixture::new();
    let binding = test_binding(14);
    let lease = fixture
        .store
        .acquire(record(
            binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"activating",
        ))
        .unwrap();
    let _ = fixture.store.take_events();
    let terminal = record(
        binding.clone(),
        2,
        NativeXtablesJournalPhase::CleanAbsent,
        b"exact absence proved",
    );
    lease.complete(terminal.clone()).unwrap();

    let events = fixture.store.take_events();
    assert_event_order(
        &events,
        &[
            DurableEvent::TerminalJournalDurable,
            DurableEvent::LeaseRemovedDurable,
            DurableEvent::WriterLockReleased,
        ],
    );
    assert_eq!(
        fixture.store.load_journal().unwrap(),
        Some(terminal.clone())
    );
    assert!(fixture.store.load_lease().unwrap().is_none());
    assert!(!fixture.store.writer_lock_exists().unwrap());
    let fence = match fixture.store.recover(&binding).unwrap() {
        NativeXtablesRecovery::CleanAbsent { record, fence } => {
            assert_eq!(record, terminal);
            fence
        }
        other => panic!("terminal journal should recover as clean absence, found {other:?}"),
    };
    assert!(fixture.store.writer_lock_exists().unwrap());
    (*fence).finish_clean().unwrap();
    assert!(fixture.store.load_journal().unwrap().is_none());
    assert!(!fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn interruption_after_terminal_publication_retains_lease_for_recovery() {
    let fixture = Fixture::new();
    let binding = test_binding(15);
    let lease = fixture
        .store
        .acquire(record(
            binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"activating",
        ))
        .unwrap();
    fixture.store.take_events();
    fixture
        .store
        .set_failpoint(Some(DurableEvent::TerminalJournalDurable));
    let terminal = record(
        binding.clone(),
        2,
        NativeXtablesJournalPhase::CleanAbsent,
        b"clean",
    );
    let error = lease
        .complete(terminal.clone())
        .expect_err("interrupt after terminal journal fsync");
    assert!(matches!(
        error,
        NativeXtablesDurableError::InterruptedAt(DurableEvent::TerminalJournalDurable)
    ));
    assert_eq!(
        fixture.store.load_journal().unwrap(),
        Some(terminal.clone())
    );
    assert_eq!(
        fixture.store.load_lease().unwrap(),
        Some(binding.lease_scope())
    );
    assert!(fixture.store.writer_lock_exists().unwrap());
    let events = fixture.store.take_events();
    assert!(events.contains(&DurableEvent::TerminalJournalDurable));
    assert!(!events.contains(&DurableEvent::LeaseRemovedDurable));

    let fence = match fixture.store.recover(&binding).unwrap() {
        NativeXtablesRecovery::CleanAbsent { record, fence } => {
            assert_eq!(record, terminal);
            fence
        }
        other => panic!("recovery should finish terminal release, found {other:?}"),
    };
    assert!(fixture.store.load_lease().unwrap().is_some());
    assert!(fixture.store.writer_lock_exists().unwrap());
    (*fence).finish_clean().unwrap();
    assert!(fixture.store.load_lease().unwrap().is_none());
    assert!(fixture.store.load_journal().unwrap().is_none());
    assert!(!fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn interruption_after_durable_lease_removal_recovers_clean_absence_and_stale_native_lock() {
    let fixture = Fixture::new();
    let binding = test_binding(64);
    let lease = fixture
        .store
        .acquire(record(
            binding.clone(),
            1,
            NativeXtablesJournalPhase::Activating,
            b"activating",
        ))
        .unwrap();
    fixture
        .store
        .set_failpoint(Some(DurableEvent::LeaseRemovedDurable));
    let terminal = record(
        binding.clone(),
        2,
        NativeXtablesJournalPhase::CleanAbsent,
        b"exact absence proved",
    );

    let error = lease
        .complete(terminal.clone())
        .expect_err("interrupt after durable lease removal");
    assert!(matches!(
        error,
        NativeXtablesDurableError::InterruptedAt(DurableEvent::LeaseRemovedDurable)
    ));
    assert_eq!(
        fixture.store.load_journal().unwrap(),
        Some(terminal.clone())
    );
    assert!(fixture.store.load_lease().unwrap().is_none());
    assert!(fixture.store.writer_lock_exists().unwrap());

    let fence = match fixture.store.recover(&binding).unwrap() {
        NativeXtablesRecovery::CleanAbsent { record, fence } => {
            assert_eq!(record, terminal);
            fence
        }
        other => panic!("terminal journal plus removed lease must recover, found {other:?}"),
    };
    assert!(fixture.store.writer_lock_exists().unwrap());
    (*fence).finish_clean().unwrap();
    assert!(fixture.store.load_journal().unwrap().is_none());
    assert!(!fixture.store.writer_lock_exists().unwrap());
}

#[test]
fn oversized_truncated_and_noncanonical_records_are_rejected() {
    let oversized = Fixture::new();
    fs::write(
        oversized.store.journal_path(),
        vec![b'x'; MAX_NATIVE_XTABLES_DURABLE_RECORD_BYTES + 1],
    )
    .unwrap();
    let error = oversized
        .store
        .load_journal()
        .expect_err("oversized journal must be rejected before parsing");
    assert!(matches!(
        error,
        NativeXtablesDurableError::RecordTooLarge {
            artifact: DurableArtifact::Journal,
            ..
        }
    ));

    let truncated = Fixture::new();
    let mut bytes = encode_journal(&record(
        test_binding(16),
        1,
        NativeXtablesJournalPhase::Activating,
        b"complete",
    ));
    bytes.pop();
    fs::write(truncated.store.journal_path(), bytes).unwrap();
    let error = truncated
        .store
        .load_journal()
        .expect_err("truncated journal must be rejected");
    assert!(matches!(
        error,
        NativeXtablesDurableError::InvalidRecord {
            artifact: DurableArtifact::Journal,
            ..
        }
    ));

    let noncanonical = Fixture::new();
    let mut bytes = encode_lease(&test_binding(17).lease_scope());
    let checksum_start = bytes
        .windows(b"sha256=".len())
        .position(|window| window == b"sha256=")
        .unwrap();
    bytes[checksum_start + b"sha256=".len()] = b'A';
    fs::write(noncanonical.store.lease_path(), bytes).unwrap();
    let error = noncanonical
        .store
        .load_lease()
        .expect_err("uppercase or mismatching checksum must be rejected");
    assert!(matches!(
        error,
        NativeXtablesDurableError::InvalidRecord {
            artifact: DurableArtifact::Lease,
            ..
        }
    ));
}

#[test]
fn nonterminal_journal_without_lease_blocks_fresh_acquisition() {
    let fixture = Fixture::new();
    let stale = record(
        test_binding(18),
        4,
        NativeXtablesJournalPhase::Uncertain,
        b"may have mutated",
    );
    fs::write(fixture.store.journal_path(), encode_journal(&stale)).unwrap();

    let error = fixture
        .store
        .acquire(record(
            test_binding(19),
            1,
            NativeXtablesJournalPhase::Activating,
            b"must not replace uncertainty",
        ))
        .expect_err("unresolved journal must not be overwritten");
    assert!(matches!(
        error,
        NativeXtablesDurableError::UnresolvedJournal
    ));
    assert_eq!(fixture.store.load_journal().unwrap(), Some(stale));
    assert!(fixture.store.load_lease().unwrap().is_none());
    assert!(fixture.store.writer_lock_exists().unwrap());
}

fn assert_event_order(events: &[DurableEvent], ordered: &[DurableEvent]) {
    let mut previous = None;
    for event in ordered {
        let index = events
            .iter()
            .position(|candidate| candidate == event)
            .unwrap_or_else(|| panic!("missing event {event:?} in {events:?}"));
        if let Some(previous) = previous {
            assert!(previous < index, "events out of order: {events:?}");
        }
        previous = Some(index);
    }
}

fn test_binding(seed: u8) -> NativeXtablesJournalBinding {
    let boot = if seed.is_multiple_of(2) {
        "11111111-2222-3333-4444-555555555555"
    } else {
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    };
    NativeXtablesJournalBinding::new(
        BootIdentity::parse(boot).unwrap(),
        NetworkNamespaceIdentity::new(u64::from(seed) + 10, u64::from(seed) + 100).unwrap(),
        GenerationId::new(u32::from(seed) + 1).unwrap(),
        OwnershipJournalIdentity::new([seed.max(1); 32]).unwrap(),
    )
}

fn replacement_binding(
    current: &NativeXtablesJournalBinding,
    generation: u32,
) -> NativeXtablesJournalBinding {
    NativeXtablesJournalBinding::new(
        current.boot_identity().clone(),
        current.network_namespace(),
        GenerationId::new(generation).unwrap(),
        current.journal_identity(),
    )
}

fn current_scope(seed: u8) -> NativeXtablesLeaseScope {
    NativeXtablesLeaseScope::new(
        BootIdentity::parse(
            fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .unwrap()
                .trim(),
        )
        .unwrap(),
        NetworkNamespaceIdentity::new(u64::from(seed) + 10, u64::from(seed) + 100).unwrap(),
        OwnershipJournalIdentity::new([seed.max(1); 32]).unwrap(),
    )
}

fn current_scope_for_binding(binding: &NativeXtablesJournalBinding) -> NativeXtablesLeaseScope {
    NativeXtablesLeaseScope::new(
        BootIdentity::parse(
            fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .unwrap()
                .trim(),
        )
        .unwrap(),
        binding.network_namespace(),
        binding.journal_identity(),
    )
}

fn record(
    binding: NativeXtablesJournalBinding,
    revision: u64,
    phase: NativeXtablesJournalPhase,
    payload: &[u8],
) -> NativeXtablesJournalRecord {
    NativeXtablesJournalRecord::new(
        binding,
        OwnershipJournalRevision::new(revision).unwrap(),
        phase,
        NativeXtablesOwnerPayload::new(payload.to_vec()).unwrap(),
    )
}

fn attempt(
    binding: NativeXtablesJournalBinding,
    phase: NativeXtablesAttemptPhase,
    payload: &[u8],
) -> NativeXtablesAttemptRecord {
    NativeXtablesAttemptRecord::new(
        binding,
        phase,
        NativeXtablesAttemptPayload::new(payload.to_vec()).unwrap(),
    )
}

struct Fixture {
    directory: TempDir,
    store: NativeXtablesDurableStore,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("create durable-store fixture");
        let store = NativeXtablesDurableStore::new(directory.path().join("state"));
        fs::create_dir(store.root.as_path()).expect("create durable-store root");
        Self { directory, store }
    }

    fn root(&self) -> &Path {
        &self.store.root
    }
}
