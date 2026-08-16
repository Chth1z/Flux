use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs;
use std::num::NonZeroU16;
use std::rc::Rc;
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use serde_json::Value;
use tempfile::tempdir;
use url::Url;

use flux_core::AddressHostFamilySelection;

#[cfg(target_os = "linux")]
use flux_platform::{SingBoxLaunchSpec, SingBoxPrivilege, SingBoxReadiness};

use super::*;
#[cfg(target_os = "linux")]
use crate::RestartPolicy;
use crate::subscription::assets::{
    PrepareSubscriptionRequest, SubscriptionRefreshLimits, prepare_subscription_refresh,
};
use crate::subscription::fetch::{
    FetchAdapter, FetchError, FetchPurpose, FetchRequest, FetchedResource,
};

const TEMPLATE: &[u8] = br#"{
    "outbounds":[
        {"type":"direct","tag":"DIRECT"},
        {"type":"selector","tag":"PROXY","outbounds":[]}
    ],
    "route":{"rule_set":[{
        "type":"remote","tag":"geo","format":"binary",
        "url":"https://assets.example/geo.srs"
    }]}
}"#;
const SUBSCRIPTION_URL: &str = "https://provider.example/sub?token=redacted";
const MAX_BYTES: u32 = 16 * 1_024;

#[derive(Default)]
struct ValidatorState {
    calls: usize,
    reject: bool,
    tamper_after_check: bool,
}

#[derive(Clone, Default)]
struct DeterministicValidator {
    state: Rc<RefCell<ValidatorState>>,
}

impl SubscriptionSnapshotValidator for DeterministicValidator {
    fn validate(&self, config_path: &Path) -> Result<(), SnapshotValidationErrorKind> {
        let mut state = self.state.borrow_mut();
        state.calls += 1;
        let document: Value = serde_json::from_slice(
            &fs::read(config_path).expect("candidate config exists at its final path"),
        )
        .expect("candidate config is JSON");
        for entry in document["route"]["rule_set"]
            .as_array()
            .expect("candidate rule sets")
        {
            let path = entry["path"].as_str().expect("local rule-set path");
            assert!(Path::new(path).is_file());
        }
        if state.reject {
            return Err(SnapshotValidationErrorKind::Rejected);
        }
        if state.tamper_after_check {
            fs::write(config_path, b"{}\n").expect("tamper with candidate after validation");
        }
        Ok(())
    }
}

struct FixtureFetch {
    subscription: Vec<u8>,
    asset: Vec<u8>,
}

impl FetchAdapter for FixtureFetch {
    fn fetch(&self, request: FetchRequest<'_>) -> Result<FetchedResource, FetchError> {
        let bytes = match request.purpose() {
            FetchPurpose::Subscription => self.subscription.clone(),
            FetchPurpose::BinaryRuleSet => self.asset.clone(),
        };
        Ok(FetchedResource::from_bytes(bytes))
    }
}

fn prepared<V: SubscriptionSnapshotValidator>(
    store: &SubscriptionSnapshotStore<V>,
    name: &str,
    asset: &[u8],
) -> PreparedSubscriptionRefresh {
    let source = format!(
        "[{{\"type\":\"vless\",\"tag\":\"{name}\",\"server\":\"{name}.example\",\"server_port\":443,\"uuid\":\"id-{name}\"}}]"
    );
    let fetch = FixtureFetch {
        subscription: source.into_bytes(),
        asset: asset.to_vec(),
    };
    let url = Url::parse(SUBSCRIPTION_URL).expect("fixture URL");
    let asset_root = store.asset_root();
    prepare_subscription_refresh(
        &fetch,
        PrepareSubscriptionRequest::new(
            TEMPLATE,
            &url,
            &asset_root,
            NonZeroU16::new(1_536).unwrap(),
            AddressHostFamilySelection::DualStack,
            SubscriptionRefreshLimits::new(Duration::from_secs(1), MAX_BYTES, MAX_BYTES, 100),
        ),
    )
    .expect("prepare subscription fixture")
}

fn store(
    root: &Path,
) -> (
    SubscriptionSnapshotStore<DeterministicValidator>,
    Rc<RefCell<ValidatorState>>,
) {
    let validator = DeterministicValidator::default();
    let state = Rc::clone(&validator.state);
    (
        SubscriptionSnapshotStore::new(root, validator).expect("valid store root"),
        state,
    )
}

#[test]
fn publication_validates_final_paths_and_recovery_rehashes_every_object() {
    let directory = tempdir().expect("temporary directory");
    let (mut store, validator) = store(&directory.path().join("subscriptions"));
    let candidate = prepared(&store, "one", b"asset-one");
    let expected_digest = *candidate.digest();
    let expected_config = *candidate.content_sha256();

    let published = store.publish(candidate).expect("publish candidate");

    assert_eq!(
        published.publication(),
        SnapshotPublicationDisposition::Published
    );
    assert_eq!(published.recovery(), SnapshotRecoveryDisposition::Unchanged);
    assert_eq!(published.active().unwrap().digest(), &expected_digest);
    assert_eq!(
        published.active().unwrap().content_sha256(),
        &expected_config
    );
    assert_eq!(published.active().unwrap().node_count(), 1);
    assert_eq!(published.active().unwrap().assets().len(), 1);
    assert_eq!(published.active().unwrap().bindings().len(), 1);
    assert!(published.predecessor().is_none());
    assert!(!published.cleanup_pending());
    assert_eq!(validator.borrow().calls, 1);

    let recovered = store.recover().expect("recover published snapshot");
    assert_eq!(
        recovered.publication(),
        SnapshotPublicationDisposition::Recovered
    );
    assert_eq!(recovered.recovery(), SnapshotRecoveryDisposition::Unchanged);
    assert_eq!(recovered.active().unwrap().digest(), &expected_digest);
    assert_eq!(
        validator.borrow().calls,
        1,
        "recovery does not manufacture a new check"
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn reviewed_engine_asset_access_is_read_only_private_and_rejects_metadata_drift() {
    let directory = tempdir().expect("temporary directory");
    // SAFETY: this call reads only the current test-process identity.
    let gid = unsafe { libc::getegid() };
    assert_ne!(gid, 0, "test fixture requires a non-root group");
    let access = SubscriptionAssetAccess::reviewed_engine(gid).expect("reviewed engine access");
    let validator = DeterministicValidator::default();
    let mut store = SubscriptionSnapshotStore::new_with_asset_access(
        directory.path().join("subscriptions"),
        validator,
        Some(access),
    )
    .expect("credential-bound subscription store");
    let candidate = prepared(&store, "one", b"asset-one");
    let asset_path = candidate.assets()[0].path().to_owned();

    store.publish(candidate).expect("publish bound asset");

    let asset_root = store.asset_root();
    for path in [store.root.as_path(), asset_root.as_path()] {
        let metadata = fs::metadata(path).expect("asset corridor metadata");
        assert_eq!(metadata.gid(), gid);
        assert_eq!(metadata.mode() & 0o777, 0o710);
    }
    let asset_metadata = fs::metadata(&asset_path).expect("bound asset metadata");
    assert_eq!(asset_metadata.gid(), gid);
    assert_eq!(asset_metadata.mode() & 0o777, 0o440);
    assert_eq!(
        fs::metadata(store.index_path()).unwrap().mode() & 0o777,
        0o600,
        "the snapshot index remains private"
    );
    let config_digest = *store.recover().unwrap().active().unwrap().content_sha256();
    let config_path = store.config_path(config_digest);
    assert_eq!(fs::metadata(config_path).unwrap().mode() & 0o777, 0o600);

    for path in [store.root.clone(), asset_root.clone(), asset_path.clone()] {
        let canonical = fs::metadata(&path).expect("canonical engine access metadata");
        let canonical_mode = canonical.mode() & 0o777;
        let drift_mode = if canonical.is_dir() { 0o700 } else { 0o640 };
        fs::set_permissions(&path, fs::Permissions::from_mode(drift_mode))
            .expect("inject engine access mode drift");
        assert_eq!(
            store
                .recover()
                .expect_err("engine access mode drift must fail closed")
                .kind(),
            SubscriptionSnapshotStoreErrorKind::Storage
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(canonical_mode))
            .expect("restore canonical engine access mode");
    }

    let other_gid = if gid == 1 { 2 } else { 1 };
    let wrong_access = SubscriptionAssetAccess::reviewed_engine(other_gid)
        .expect("different reviewed engine group");
    assert_eq!(
        SubscriptionSnapshotStore::new_with_asset_access(
            store.root.clone(),
            DeterministicValidator::default(),
            Some(wrong_access),
        )
        .expect_err("wrong engine group must not rewrite an existing asset corridor")
        .kind(),
        SubscriptionSnapshotStoreErrorKind::Storage
    );

    let candidate = prepared(&store, "two", b"asset-two");
    let next_asset = candidate.assets()[0].path().to_owned();
    fs::set_permissions(&asset_root, fs::Permissions::from_mode(0o700))
        .expect("inject asset directory drift before publication");
    assert_eq!(
        store
            .publish(candidate)
            .expect_err("publication must reject asset directory drift")
            .kind(),
        SubscriptionSnapshotStoreErrorKind::Storage
    );
    assert!(!next_asset.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn production_validator_runs_pinned_check_and_rejects_engine_identity_drift() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().expect("temporary directory");
    let binary = directory.path().join("sing-box");
    let marker = directory.path().join("checked");
    fs::write(
        &binary,
        format!(
            "#!/bin/sh\n[ \"$1\" = check ] || exit 64\n[ \"$2\" = -c ] || exit 65\n[ -r \"$3\" ] || exit 66\ngrep -q '\"type\":\"local\"' \"$3\" || exit 67\nprintf checked > '{}'\n",
            marker.display()
        ),
    )
    .expect("write fake Sing-Box");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
        .expect("make fake Sing-Box executable");
    let base_config = directory.path().join("base.json");
    fs::write(&base_config, b"{}\n").expect("base config");
    let engine = EngineSpec::new(
        SingBoxLaunchSpec {
            binary: binary.clone(),
            config: base_config,
            working_directory: directory.path().to_path_buf(),
            log: directory.path().join("sing-box.log"),
            privilege: SingBoxPrivilege::Inherit,
            readiness: SingBoxReadiness::Listener {
                port: NonZeroU16::new(1536).expect("nonzero fixture port"),
            },
            startup_timeout: Duration::from_secs(1),
            stop_timeout: Duration::from_secs(1),
        },
        RestartPolicy::new(
            1,
            Duration::from_secs(1),
            Duration::from_millis(10),
            Duration::from_millis(10),
            Duration::from_secs(1),
        )
        .expect("fixture restart policy"),
    )
    .expect("inspect base engine");
    let validator = SingBoxSnapshotValidator::from_engine(&engine);
    let mut store =
        SubscriptionSnapshotStore::new(directory.path().join("subscriptions"), validator)
            .expect("subscription store");
    let first = prepared(&store, "first", b"asset-first");
    let first_digest = *first.digest();

    store
        .publish(first)
        .expect("pinned check accepts candidate");
    assert_eq!(fs::read_to_string(&marker).unwrap(), "checked");
    let index_before = fs::read(store.index_path()).expect("active index");

    fs::write(&binary, b"#!/bin/sh\nexit 0\n").expect("replace engine at same path");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
        .expect("keep replacement executable");
    let error = store
        .publish(prepared(&store, "second", b"asset-second"))
        .expect_err("engine identity drift must block publication");

    assert_eq!(error.kind(), SubscriptionSnapshotStoreErrorKind::Validation);
    assert_eq!(fs::read(store.index_path()).unwrap(), index_before);
    assert_eq!(
        store.recover().unwrap().active().unwrap().digest(),
        &first_digest
    );
}

#[cfg(target_os = "linux")]
#[test]
fn production_validator_reports_only_fixed_permission_failure_classes() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().expect("temporary directory");
    let binary = directory.path().join("sing-box");
    fs::write(
        &binary,
        b"#!/bin/sh\nprintf '%s\\n' 'open /proc/self/fd/17: permission denied' >&2\nexit 1\n",
    )
    .expect("write rejecting fake Sing-Box");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
        .expect("make fake Sing-Box executable");
    let base_config = directory.path().join("base.json");
    fs::write(&base_config, b"{}\n").expect("base config");
    let engine = EngineSpec::new(
        SingBoxLaunchSpec {
            binary,
            config: base_config,
            working_directory: directory.path().to_path_buf(),
            log: directory.path().join("sing-box.log"),
            privilege: SingBoxPrivilege::Inherit,
            readiness: SingBoxReadiness::Listener {
                port: NonZeroU16::new(1536).expect("nonzero fixture port"),
            },
            startup_timeout: Duration::from_secs(1),
            stop_timeout: Duration::from_secs(1),
        },
        RestartPolicy::new(
            1,
            Duration::from_secs(1),
            Duration::from_millis(10),
            Duration::from_millis(10),
            Duration::from_secs(1),
        )
        .expect("fixture restart policy"),
    )
    .expect("inspect base engine");
    let validator = SingBoxSnapshotValidator::from_engine(&engine);
    let mut store =
        SubscriptionSnapshotStore::new(directory.path().join("subscriptions"), validator)
            .expect("subscription store");

    let error = store
        .publish(prepared(&store, "first", b"asset-first"))
        .expect_err("permission rejection must block publication");

    assert!(matches!(
        error,
        SubscriptionSnapshotStoreError::Validation {
            kind: SnapshotValidationErrorKind::ProcessCheckConfigDescriptorPermissionDenied,
            ..
        }
    ));
    let display = error.to_string();
    assert!(display.contains("ProcessCheckConfigDescriptorPermissionDenied"));
    assert!(!display.contains("/proc/self/fd/17"));
}

#[test]
fn identical_validated_candidate_does_not_rotate_history() {
    let directory = tempdir().expect("temporary directory");
    let (mut store, validator) = store(&directory.path().join("subscriptions"));
    let candidate = prepared(&store, "same", b"same-asset");

    store
        .publish(candidate.clone())
        .expect("publish first candidate");
    let repeated = store
        .publish(candidate)
        .expect("validate repeated candidate");

    assert_eq!(
        repeated.publication(),
        SnapshotPublicationDisposition::ValidatedNoChange
    );
    assert!(repeated.predecessor().is_none());
    assert_eq!(validator.borrow().calls, 2);
}

#[test]
fn rejection_restores_only_the_exact_predecessor_or_prior_empty_state() {
    let directory = tempdir().expect("temporary directory");
    let (mut store, _) = store(&directory.path().join("subscriptions"));
    let first = prepared(&store, "first", b"asset-first");
    let first_digest = *first.digest();
    let first_config = store.config_path(*first.content_sha256());
    let second = prepared(&store, "second", b"asset-second");
    let second_digest = *second.digest();
    let second_config = store.config_path(*second.content_sha256());

    store.publish(first).expect("publish predecessor");
    store.publish(second).expect("publish active");
    let index_before = fs::read(store.index_path()).expect("read active index");

    let conflict = store
        .reject_active([0x5a; 32])
        .expect_err("stale rejection cannot alter the active snapshot");
    assert_eq!(
        conflict.kind(),
        SubscriptionSnapshotStoreErrorKind::RejectionConflict
    );
    assert_eq!(fs::read(store.index_path()).unwrap(), index_before);

    let restored = store
        .reject_active(second_digest)
        .expect("restore verified predecessor");
    assert_eq!(
        restored.publication(),
        SnapshotPublicationDisposition::Rejected
    );
    assert_eq!(restored.active().unwrap().digest(), &first_digest);
    assert!(restored.predecessor().is_none());
    assert!(first_config.is_file());
    assert!(!second_config.exists());

    let empty = store
        .reject_active(first_digest)
        .expect("restore state that preceded the first candidate");
    assert_eq!(
        empty.publication(),
        SnapshotPublicationDisposition::Rejected
    );
    assert!(empty.active().is_none());
    assert!(empty.predecessor().is_none());
    assert!(!first_config.exists());
}

#[test]
fn corrupt_active_promotes_one_verified_predecessor_and_prunes_the_orphan() {
    let directory = tempdir().expect("temporary directory");
    let (mut store, _) = store(&directory.path().join("subscriptions"));
    let first = prepared(&store, "first", b"asset-first");
    let first_digest = *first.digest();
    let second = prepared(&store, "second", b"asset-second");
    let corrupt_path = store.config_path(*second.content_sha256());

    store.publish(first).expect("publish predecessor");
    let second_report = store.publish(second).expect("publish active");
    assert_eq!(second_report.predecessor(), Some(&first_digest));
    fs::write(&corrupt_path, b"corrupt\n").expect("corrupt active config");

    let recovered = store.recover().expect("fall back to predecessor");

    assert_eq!(
        recovered.recovery(),
        SnapshotRecoveryDisposition::PromotedPredecessor
    );
    assert_eq!(recovered.active().unwrap().digest(), &first_digest);
    assert!(recovered.predecessor().is_none());
    assert!(!corrupt_path.exists());
}

#[test]
fn corrupt_predecessor_is_dropped_without_disturbing_verified_active() {
    let directory = tempdir().expect("temporary directory");
    let (mut store, _) = store(&directory.path().join("subscriptions"));
    let first = prepared(&store, "first", b"asset-first");
    let first_config = store.config_path(*first.content_sha256());
    let second = prepared(&store, "second", b"asset-second");
    let second_digest = *second.digest();

    store.publish(first).expect("publish predecessor");
    store.publish(second).expect("publish active");
    fs::write(&first_config, b"corrupt predecessor\n").expect("corrupt predecessor");

    let recovered = store.recover().expect("drop corrupt predecessor");

    assert_eq!(
        recovered.recovery(),
        SnapshotRecoveryDisposition::DroppedCorruptPredecessor
    );
    assert_eq!(recovered.active().unwrap().digest(), &second_digest);
    assert!(recovered.predecessor().is_none());
    assert!(!first_config.exists());
}

#[test]
fn corrupt_active_and_predecessor_recover_to_honest_empty_state() {
    let directory = tempdir().expect("temporary directory");
    let (mut store, _) = store(&directory.path().join("subscriptions"));
    let first = prepared(&store, "first", b"asset-first");
    let first_config = store.config_path(*first.content_sha256());
    let second = prepared(&store, "second", b"asset-second");
    let second_asset = second.assets()[0].path().to_owned();

    store.publish(first).expect("publish predecessor");
    store.publish(second).expect("publish active");
    fs::write(first_config, b"corrupt predecessor\n").expect("corrupt predecessor");
    fs::write(second_asset, b"corrupt active asset\n").expect("corrupt active asset");

    let recovered = store.recover().expect("clear corrupt history");

    assert_eq!(
        recovered.recovery(),
        SnapshotRecoveryDisposition::ClearedCorruptSnapshots
    );
    assert!(recovered.active().is_none());
    assert!(recovered.predecessor().is_none());
    let index: Value =
        serde_json::from_slice(&fs::read(store.index_path()).expect("empty index remains durable"))
            .expect("empty index JSON");
    assert!(index["active"].is_null());
    assert!(index["predecessor"].is_null());
}

#[test]
fn validation_failure_keeps_index_bytes_and_active_snapshot_unchanged() {
    let directory = tempdir().expect("temporary directory");
    let (mut store, validator) = store(&directory.path().join("subscriptions"));
    let first = prepared(&store, "first", b"asset-first");
    let first_digest = *first.digest();
    store.publish(first).expect("publish initial active");
    let index_before = fs::read(store.index_path()).expect("active index");
    let rejected = prepared(&store, "rejected-secret-node", b"rejected-asset");
    let rejected_config = store.config_path(*rejected.content_sha256());
    let rejected_asset = rejected.assets()[0].path().to_owned();
    validator.borrow_mut().reject = true;

    let error = store
        .publish(rejected)
        .expect_err("validator rejection must fail publication");

    assert_eq!(error.kind(), SubscriptionSnapshotStoreErrorKind::Validation);
    assert!(!error.cleanup_pending());
    assert_eq!(fs::read(store.index_path()).unwrap(), index_before);
    assert!(!rejected_config.exists());
    assert!(!rejected_asset.exists());
    assert_eq!(
        store.recover().unwrap().active().unwrap().digest(),
        &first_digest
    );
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains("rejected-secret-node"));
    assert!(!diagnostic.contains("provider.example"));
}

#[test]
fn post_validation_mutation_is_rejected_before_index_rotation() {
    let directory = tempdir().expect("temporary directory");
    let (mut store, validator) = store(&directory.path().join("subscriptions"));
    store
        .publish(prepared(&store, "first", b"asset-first"))
        .expect("publish initial active");
    let index_before = fs::read(store.index_path()).expect("active index");
    let changed = prepared(&store, "changed", b"asset-changed");
    let changed_path = store.config_path(*changed.content_sha256());
    validator.borrow_mut().tamper_after_check = true;

    let error = store
        .publish(changed)
        .expect_err("post-check mutation must block publication");

    assert_eq!(
        error.kind(),
        SubscriptionSnapshotStoreErrorKind::CandidateChanged
    );
    assert_eq!(fs::read(store.index_path()).unwrap(), index_before);
    assert!(!changed_path.exists());
}

#[test]
fn candidate_persistence_failure_does_not_replace_the_active_index() {
    let directory = tempdir().expect("temporary directory");
    let (mut store, _) = store(&directory.path().join("subscriptions"));
    store
        .publish(prepared(&store, "first", b"asset-first"))
        .expect("publish initial active");
    let index_before = fs::read(store.index_path()).expect("active index");
    let blocked = prepared(&store, "blocked", b"asset-blocked");
    let blocked_config = store.config_path(*blocked.content_sha256());
    fs::create_dir(&blocked_config).expect("unremovable candidate object directory");
    let sentinel = blocked_config.join("sentinel");
    fs::write(&sentinel, b"do not touch\n").expect("candidate path sentinel");

    let error = store
        .publish(blocked)
        .expect_err("candidate object directory must block persistence");

    assert_eq!(error.kind(), SubscriptionSnapshotStoreErrorKind::Storage);
    assert!(error.cleanup_pending());
    assert_eq!(fs::read(store.index_path()).unwrap(), index_before);
    assert_eq!(fs::read(sentinel).unwrap(), b"do not touch\n");
}

#[test]
fn corrupt_index_is_cleared_but_future_schema_is_preserved() {
    let directory = tempdir().expect("temporary directory");
    let (mut store, _) = store(&directory.path().join("subscriptions"));
    let candidate = prepared(&store, "first", b"asset-first");
    let config_path = store.config_path(*candidate.content_sha256());
    store.publish(candidate).expect("publish active");
    fs::write(store.index_path(), b"{broken\n").expect("corrupt index");

    let cleared = store.recover().expect("clear corrupt index");
    assert_eq!(
        cleared.recovery(),
        SnapshotRecoveryDisposition::ClearedCorruptIndex
    );
    assert!(cleared.active().is_none());
    assert!(!config_path.exists());

    let future = br#"{"schema_version":2,"active":null,"predecessor":null}
"#;
    fs::write(store.index_path(), future).expect("future index");
    let error = store
        .recover()
        .expect_err("future schema must not be silently erased");
    assert_eq!(
        error.kind(),
        SubscriptionSnapshotStoreErrorKind::UnsupportedSchema
    );
    assert_eq!(fs::read(store.index_path()).unwrap(), future);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn recovery_prunes_only_managed_orphan_entries_without_following_them() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("subscriptions");
    let configs = root.join(CONFIG_DIRECTORY_NAME);
    fs::create_dir_all(&configs).expect("config object directory");
    let outside = directory.path().join("outside.json");
    fs::write(&outside, b"outside sentinel\n").expect("outside sentinel");
    let orphan = configs.join(format!("{}{}", "0".repeat(64), CONFIG_SUFFIX));
    symlink(&outside, &orphan).expect("managed-name orphan symlink");
    let unknown = configs.join("operator-note");
    fs::write(&unknown, b"preserve unknown entry\n").expect("unknown entry");
    let (mut store, _) = store(&root);

    let report = store.recover().expect("recover empty store");

    assert!(report.active().is_none());
    assert!(!report.cleanup_pending());
    assert!(!orphan.exists());
    assert_eq!(fs::read(outside).unwrap(), b"outside sentinel\n");
    assert_eq!(fs::read(unknown).unwrap(), b"preserve unknown entry\n");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn recovery_refuses_a_symbolic_link_ancestor_without_rewriting_the_index() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("temporary directory");
    let (mut store, _) = store(&directory.path().join("subscriptions"));
    store
        .publish(prepared(&store, "active", b"asset-active"))
        .expect("publish active");
    let index_before = fs::read(store.index_path()).expect("active index");
    let config_root = store.config_root();
    let retained = store.root.join("retained-configs");
    fs::rename(&config_root, &retained).expect("retain real config directory");
    let outside = directory.path().join("outside");
    fs::create_dir(&outside).expect("outside directory");
    fs::write(outside.join("sentinel"), b"outside\n").expect("outside sentinel");
    symlink(&outside, &config_root).expect("replace config ancestor with symlink");

    let error = store
        .recover()
        .expect_err("symbolic-link ancestor must stop recovery");

    assert_eq!(error.kind(), SubscriptionSnapshotStoreErrorKind::Storage);
    assert_eq!(fs::read(store.index_path()).unwrap(), index_before);
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"outside\n");
}

#[test]
fn strict_index_shape_rejects_duplicate_history_and_noncanonical_digests() {
    let duplicate = StoredSnapshotIndex {
        schema_version: SNAPSHOT_INDEX_SCHEMA_VERSION,
        active: Some(stored_record("0".repeat(64))),
        predecessor: Some(stored_record("0".repeat(64))),
    };
    assert!(SnapshotIndex::try_from(duplicate).is_err());

    let mut uppercase = stored_record("A".repeat(64));
    uppercase.assets = vec!["0".repeat(64)];
    uppercase.bindings = vec![StoredRuleSetBindingRecord {
        tag: "geo".to_owned(),
        source: "0".repeat(64),
        content_sha256: "0".repeat(64),
    }];
    assert!(SnapshotRecord::try_from(uppercase).is_err());
}

fn stored_record(digest: String) -> StoredSnapshotRecord {
    StoredSnapshotRecord {
        digest,
        content_sha256: "1".repeat(64),
        subscription_source: "2".repeat(64),
        subscription_content_sha256: "3".repeat(64),
        compiled_digest: "4".repeat(64),
        node_count: 1,
        assets: Vec::new(),
        bindings: Vec::new(),
    }
}

#[test]
fn managed_name_parser_is_exact() {
    let object = format!("{}{}", "a".repeat(64), CONFIG_SUFFIX);
    assert!(is_object_name(&object, CONFIG_SUFFIX));
    assert!(is_managed_temp_name(
        &format!(".{object}.123.456.tmp"),
        CONFIG_SUFFIX
    ));
    assert!(is_temp_for_target(
        ".index.json.123.456.tmp",
        INDEX_FILE_NAME
    ));

    let rejected = BTreeSet::from([
        format!("{}{}", "A".repeat(64), CONFIG_SUFFIX),
        format!("{}{}", "a".repeat(63), CONFIG_SUFFIX),
        format!("{}{}", "g".repeat(64), CONFIG_SUFFIX),
        format!(".{object}.pid.1.tmp"),
        format!(".{object}.1.counter.tmp"),
    ]);
    for name in rejected {
        assert!(
            !is_object_name(&name, CONFIG_SUFFIX) && !is_managed_temp_name(&name, CONFIG_SUFFIX)
        );
    }
}
