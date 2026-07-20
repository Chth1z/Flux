use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(target_os = "android")]
use flux_core::ObservationKind;
use flux_core::{KernelBuildIdentity, Observation, ToolId, VerifiedBootState};

use super::implementation::{
    AndroidDeviceIdentityPaths, AndroidPropertySource, IdentityArtifactSource, IdentityFactFailure,
    collect_android_device_identity, observe_test_artifact_after, observe_test_running_executable,
    parse_active_apex_path,
};

#[test]
fn complete_exact_facts_collect_one_canonical_identity() {
    let fixture = Fixture::new();
    let properties = StableProperties::complete();
    let kernel = || {
        KernelBuildIdentity::new("5.10.198-android13-gki #1 SMP PREEMPT")
            .map_err(|_| IdentityFactFailure::Malformed)
    };

    let observation = collect_android_device_identity(&properties, &fixture.paths, kernel);
    let identity = observation.verified().expect("complete identity");

    assert_eq!(identity.android_product().as_str(), "google/redfin/redfin");
    assert_eq!(identity.security_patch().as_str(), "2023-08-05");
    assert_eq!(identity.verified_boot().state(), VerifiedBootState::Green);
    assert!(identity.verified_boot().device_locked());
    assert_eq!(identity.selinux_policy().size(), 6);
    assert_eq!(identity.netd().size(), 4);
    assert_eq!(
        digest_hex(identity.netd().digest().as_bytes()),
        "49c76a98bd415dbfd6fe7b267c6859f08b1baa10d4054d41ec6c131a1e2814a8"
    );
    assert_eq!(identity.connectivity().size(), 12);
    assert_eq!(identity.tools().len(), 1);
    assert!(properties.every_property_was_sampled_twice());
}

#[test]
fn inconsistent_device_lock_facts_are_malformed() {
    let fixture = Fixture::new();
    let mut values = complete_property_values();
    values.insert("ro.boot.flash.locked".to_owned(), b"0".to_vec());
    let properties = StableProperties::new(values);
    let kernel = || {
        KernelBuildIdentity::new("5.10.198-android13-gki #1 SMP PREEMPT")
            .map_err(|_| IdentityFactFailure::Malformed)
    };

    assert_eq!(
        collect_android_device_identity(&properties, &fixture.paths, kernel),
        Observation::Malformed
    );
}

#[test]
fn a_kernel_change_between_samples_is_malformed() {
    let fixture = Fixture::new();
    let properties = StableProperties::complete();
    let calls = Cell::new(0_u8);
    let kernel = || {
        let call = calls.get();
        calls.set(call.saturating_add(1));
        let value = if call == 0 {
            "5.10.198-android13-gki #1 SMP PREEMPT"
        } else {
            "5.10.198-android13-gki #2 SMP PREEMPT"
        };
        KernelBuildIdentity::new(value).map_err(|_| IdentityFactFailure::Malformed)
    };

    assert_eq!(
        collect_android_device_identity(&properties, &fixture.paths, kernel),
        Observation::Malformed
    );
}

#[test]
fn green_without_lock_and_vbmeta_evidence_is_absent_not_verified() {
    let fixture = Fixture::new();
    let mut values = complete_property_values();
    values.remove("ro.boot.vbmeta.device_state");
    values.remove("ro.boot.flash.locked");
    values.remove("ro.boot.vbmeta.hash_alg");
    values.remove("ro.boot.vbmeta.digest");
    let properties = StableProperties::new(values);
    let kernel = || {
        KernelBuildIdentity::new("5.10.198-android13-gki #1 SMP PREEMPT")
            .map_err(|_| IdentityFactFailure::Malformed)
    };

    assert_eq!(
        collect_android_device_identity(&properties, &fixture.paths, kernel),
        Observation::Absent
    );
}

#[test]
fn a_property_change_between_the_two_samples_is_malformed() {
    let fixture = Fixture::new();
    let mut second = complete_property_values();
    second.insert(
        "ro.vendor.build.fingerprint".to_owned(),
        b"google/redfin/redfin:13/TQ3A.230805.001/2:user/release-keys".to_vec(),
    );
    let properties = SequencedProperties::new(complete_property_values(), second);
    let kernel = || {
        KernelBuildIdentity::new("5.10.198-android13-gki #1 SMP PREEMPT")
            .map_err(|_| IdentityFactFailure::Malformed)
    };

    assert_eq!(
        collect_android_device_identity(&properties, &fixture.paths, kernel),
        Observation::Malformed
    );
}

#[test]
fn active_apex_selection_requires_one_safe_absolute_package() {
    let root = PathBuf::from("/system/apex");
    let valid = br#"<?xml version="1.0" encoding="utf-8"?>
<apex-info-list>
  <apex-info moduleName="com.android.tethering" modulePath="/system/apex/com.android.tethering.apex" versionName="Android Connectivity 13" isActive="true">
  </apex-info>
</apex-info-list>"#;
    assert_eq!(
        parse_active_apex_path(valid, "com.android.tethering", std::slice::from_ref(&root))
            .expect("active package"),
        PathBuf::from("/system/apex/com.android.tethering.apex")
    );

    let duplicate = br#"<apex-info-list>
<apex-info moduleName="com.android.tethering" modulePath="/system/apex/a.apex" isActive="true">
<apex-info moduleName="com.android.tethering" modulePath="/system/apex/b.apex" isActive="true">
</apex-info-list>"#;
    assert_eq!(
        parse_active_apex_path(
            duplicate,
            "com.android.tethering",
            std::slice::from_ref(&root)
        ),
        Err(IdentityFactFailure::Malformed)
    );

    let traversal = br#"<apex-info-list>
<apex-info moduleName="com.android.tethering" modulePath="/system/apex/../bad.apex" isActive="true">
</apex-info-list>"#;
    assert_eq!(
        parse_active_apex_path(
            traversal,
            "com.android.tethering",
            std::slice::from_ref(&root)
        ),
        Err(IdentityFactFailure::Malformed)
    );

    let intermediate_component = br#"<apex-info-list>
<apex-info moduleName="com.android.tethering" modulePath="/system/apex/link/pkg.apex" isActive="true">
</apex-info-list>"#;
    assert_eq!(
        parse_active_apex_path(
            intermediate_component,
            "com.android.tethering",
            std::slice::from_ref(&root)
        ),
        Err(IdentityFactFailure::Malformed)
    );

    let commented = br#"<apex-info-list>
<!-- <apex-info moduleName="com.android.tethering" modulePath="/system/apex/comment.apex" isActive="true"/> -->
</apex-info-list>"#;
    assert_eq!(
        parse_active_apex_path(
            commented,
            "com.android.tethering",
            std::slice::from_ref(&root)
        ),
        Err(IdentityFactFailure::Malformed)
    );

    let cdata = br#"<apex-info-list>
<![CDATA[<apex-info moduleName="com.android.tethering" modulePath="/system/apex/cdata.apex" isActive="true"/>]]>
</apex-info-list>"#;
    assert_eq!(
        parse_active_apex_path(cdata, "com.android.tethering", std::slice::from_ref(&root)),
        Err(IdentityFactFailure::Malformed)
    );

    let trailing = br#"<apex-info-list></apex-info-list>
<apex-info moduleName="com.android.tethering" modulePath="/system/apex/outside.apex" isActive="true"/>"#;
    assert_eq!(
        parse_active_apex_path(
            trailing,
            "com.android.tethering",
            std::slice::from_ref(&root)
        ),
        Err(IdentityFactFailure::Malformed)
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn artifact_identity_rejects_same_size_rewrite_truncation_and_path_replacement() {
    let directory = tempfile::tempdir().expect("temporary directory");

    let rewritten = write(directory.path(), "rewritten", b"netd");
    assert_eq!(
        observe_test_artifact_after(&rewritten, || {
            fs::write(&rewritten, b"NETD").expect("same-size rewrite");
        }),
        Err(IdentityFactFailure::Malformed)
    );

    let truncated = write(directory.path(), "truncated", b"netd");
    assert_eq!(
        observe_test_artifact_after(&truncated, || {
            fs::File::create(&truncated).expect("truncate artifact");
        }),
        Err(IdentityFactFailure::Malformed)
    );

    let replaced = write(directory.path(), "replaced", b"netd");
    let replacement = write(directory.path(), "replacement", b"NETD");
    assert_eq!(
        observe_test_artifact_after(&replaced, || {
            fs::rename(&replacement, &replaced).expect("replace artifact path");
        }),
        Err(IdentityFactFailure::Malformed)
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn artifact_identity_rejects_empty_oversized_and_symlink_inputs() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("temporary directory");
    let empty = write(directory.path(), "empty", b"");
    assert_eq!(
        observe_test_artifact_after(&empty, || {}),
        Err(IdentityFactFailure::Malformed)
    );

    let oversized = directory.path().join("oversized");
    fs::File::create(&oversized)
        .expect("oversized artifact")
        .set_len(128 * 1024 * 1024 + 1)
        .expect("sparse oversized artifact");
    assert_eq!(
        observe_test_artifact_after(&oversized, || {}),
        Err(IdentityFactFailure::Malformed)
    );

    let target = write(directory.path(), "target", b"netd");
    let link = directory.path().join("link");
    symlink(target, &link).expect("artifact symlink");
    assert_eq!(
        observe_test_artifact_after(&link, || {}),
        Err(IdentityFactFailure::Malformed)
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn running_executable_identity_comes_from_proc_self_exe() {
    let identity = observe_test_running_executable().expect("running executable identity");
    assert!(identity.size() > 0);
}

#[cfg(target_os = "android")]
#[test]
#[ignore = "requires explicit rooted x86_64 WSA execution"]
fn rooted_wsa_collector_rejects_green_without_complete_avb_identity() {
    assert_eq!(
        std::env::var("FLUX_WSA_IDENTITY_PROBE").as_deref(),
        Ok("1"),
        "the rooted WSA mechanism test requires explicit opt-in"
    );
    assert_eq!(std::env::consts::ARCH, "x86_64");
    // SAFETY: `geteuid` has no pointer arguments or ownership transfer and only reads process state.
    assert_eq!(unsafe { libc::geteuid() }, 0, "test must run as root");

    let observation = super::observe_system_android_device_identity();

    assert_eq!(observation.kind(), ObservationKind::Absent);
}

struct Fixture {
    _directory: tempfile::TempDir,
    paths: AndroidDeviceIdentityPaths,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let policy = write(directory.path(), "policy", b"policy");
        let netd = write(directory.path(), "netd", b"netd");
        let connectivity = write(directory.path(), "connectivity.apex", b"connectivity");
        let fluxd = write(directory.path(), "fluxd", b"fluxd");
        let namespace = write(directory.path(), "netns", b"namespace");
        let apex_info = directory.path().join("apex-info-list.xml");
        fs::write(
            &apex_info,
            format!(
                "<apex-info-list>\n<apex-info moduleName=\"com.android.tethering\" modulePath=\"{}\" isActive=\"true\">\n</apex-info>\n</apex-info-list>\n",
                connectivity.display()
            ),
        )
        .expect("APEX info");
        let tool = ToolId::new("fluxd").expect("tool identity");
        let paths = AndroidDeviceIdentityPaths {
            selinux_policy: policy,
            netd,
            apex_info,
            network_namespace: namespace,
            tools: vec![(tool, IdentityArtifactSource::NoFollow(fluxd))],
            allowed_apex_roots: vec![directory.path().to_path_buf()],
        };
        Self {
            _directory: directory,
            paths,
        }
    }
}

fn write(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, bytes).expect("fixture artifact");
    path
}

struct StableProperties {
    values: BTreeMap<String, Vec<u8>>,
    calls: RefCell<BTreeMap<String, usize>>,
}

impl StableProperties {
    fn complete() -> Self {
        Self::new(complete_property_values())
    }

    fn new(values: BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            values,
            calls: RefCell::new(BTreeMap::new()),
        }
    }

    fn every_property_was_sampled_twice(&self) -> bool {
        self.calls.borrow().values().all(|calls| *calls == 2)
    }
}

impl AndroidPropertySource for StableProperties {
    fn read_property(&self, name: &str) -> Result<Option<Vec<u8>>, IdentityFactFailure> {
        *self.calls.borrow_mut().entry(name.to_owned()).or_default() += 1;
        Ok(self.values.get(name).cloned())
    }
}

struct SequencedProperties {
    first: BTreeMap<String, Vec<u8>>,
    second: BTreeMap<String, Vec<u8>>,
    calls: RefCell<BTreeMap<String, usize>>,
}

impl SequencedProperties {
    fn new(first: BTreeMap<String, Vec<u8>>, second: BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            first,
            second,
            calls: RefCell::new(BTreeMap::new()),
        }
    }
}

impl AndroidPropertySource for SequencedProperties {
    fn read_property(&self, name: &str) -> Result<Option<Vec<u8>>, IdentityFactFailure> {
        let mut calls = self.calls.borrow_mut();
        let call = calls.entry(name.to_owned()).or_default();
        let values = if *call == 0 {
            &self.first
        } else {
            &self.second
        };
        *call += 1;
        Ok(values.get(name).cloned())
    }
}

fn complete_property_values() -> BTreeMap<String, Vec<u8>> {
    [
        ("ro.product.brand", "google"),
        ("ro.product.name", "redfin"),
        ("ro.product.device", "redfin"),
        (
            "ro.build.fingerprint",
            "google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys",
        ),
        (
            "ro.vendor.build.fingerprint",
            "google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys",
        ),
        ("ro.build.version.security_patch", "2023-08-05"),
        ("ro.boot.verifiedbootstate", "green"),
        ("ro.boot.vbmeta.device_state", "locked"),
        ("ro.boot.flash.locked", "1"),
        ("ro.boot.vbmeta.hash_alg", "sha256"),
        (
            "ro.boot.vbmeta.digest",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.as_bytes().to_vec()))
    .collect()
}

fn digest_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
