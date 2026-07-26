use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const MAX_SCANNED_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

const BRIDGE_RUNTIME_SCRIPTS: [&str; 9] = [
    "scripts/addrsync",
    "scripts/config",
    "scripts/core",
    "scripts/dispatcher",
    "scripts/init",
    "scripts/lib",
    "scripts/log",
    "scripts/rules",
    "scripts/tproxy",
];

const RETIRED_RUNTIME_PATHS: [&str; 2] = ["scripts/flux-event", "scripts/updater.sh"];

const PRODUCTION_SOURCE_ROOTS: [&str; 5] = [
    "crates",
    "customize.sh",
    "flux_service.sh",
    "uninstall.sh",
    "packaging/rust-only",
];

const ALLOWED_PRODUCTION_REFERENCES: [(&str, &str, usize); 7] = [
    (
        "crates/flux-platform/src/capability.rs",
        "scripts/dispatcher",
        1,
    ),
    (
        "crates/flux-platform/src/capability.rs",
        "scripts/addrsync",
        1,
    ),
    ("crates/fluxd/src/daemon.rs", "scripts/dispatcher", 1),
    ("crates/fluxd/src/daemon.rs", "scripts/addrsync", 1),
    ("customize.sh", "scripts/*", 1),
    ("flux_service.sh", "scripts/lib", 1),
    ("flux_service.sh", "scripts/log", 1),
];

pub(super) fn validate(workspace: &Path) -> Result<(), String> {
    validate_manifest_bridge_set(workspace)?;
    let mut observed = BTreeMap::<(String, String), usize>::new();
    for relative in PRODUCTION_SOURCE_ROOTS {
        let path = workspace.join(relative);
        collect_references(workspace, &path, &mut observed)?;
    }
    let expected = ALLOWED_PRODUCTION_REFERENCES
        .into_iter()
        .map(|(path, target, count)| ((path.to_owned(), target.to_owned()), count))
        .collect::<BTreeMap<_, _>>();
    if observed != expected {
        let missing = expected
            .iter()
            .filter(|(key, count)| observed.get(*key) != Some(*count))
            .map(|((path, target), count)| format!("{path}:{target}={count}"))
            .collect::<Vec<_>>();
        let unexpected = observed
            .iter()
            .filter(|(key, count)| expected.get(*key) != Some(*count))
            .map(|((path, target), count)| format!("{path}:{target}={count}"))
            .collect::<Vec<_>>();
        return Err(format!(
            "production shell bridge reference policy changed (missing={}, unexpected={})",
            missing.join(","),
            unexpected.join(",")
        ));
    }
    Ok(())
}

fn validate_manifest_bridge_set(workspace: &Path) -> Result<(), String> {
    let path = workspace.join("conf/manifest.json");
    let bytes =
        fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let document: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
    let retired = document["retired_runtime_paths"]
        .as_array()
        .ok_or_else(|| "conf/manifest.json retired_runtime_paths must be an array".to_owned())?
        .iter()
        .map(|path| {
            path.as_str()
                .ok_or_else(|| "retired_runtime_paths entries must be strings".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_retired = RETIRED_RUNTIME_PATHS.into_iter().collect::<BTreeSet<_>>();
    if retired != expected_retired {
        let missing = expected_retired
            .difference(&retired)
            .copied()
            .collect::<Vec<_>>();
        let extra = retired
            .difference(&expected_retired)
            .copied()
            .collect::<Vec<_>>();
        return Err(format!(
            "retired runtime path policy changed (missing={}, extra={})",
            missing.join(","),
            extra.join(",")
        ));
    }
    for retired in RETIRED_RUNTIME_PATHS {
        match fs::symlink_metadata(workspace.join(retired)) {
            Ok(_) => return Err(format!("retired runtime path exists in source: {retired}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot inspect retired runtime source path {retired}: {error}"
                ));
            }
        }
    }
    let profiles = document["package_profiles"]
        .as_array()
        .ok_or_else(|| "conf/manifest.json package_profiles must be an array".to_owned())?;
    let profile = profiles
        .iter()
        .find(|profile| profile["name"].as_str() == Some("bridge"))
        .ok_or_else(|| "conf/manifest.json is missing the bridge package profile".to_owned())?;
    let required = profile["required_files"]
        .as_array()
        .ok_or_else(|| "bridge required_files must be an array".to_owned())?;
    let actual = required
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter(|path| path.starts_with("scripts/"))
        .collect::<BTreeSet<_>>();
    let expected = BRIDGE_RUNTIME_SCRIPTS.into_iter().collect::<BTreeSet<_>>();
    if actual != expected {
        let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
        let extra = actual.difference(&expected).copied().collect::<Vec<_>>();
        return Err(format!(
            "bridge runtime script inventory changed (missing={}, extra={})",
            missing.join(","),
            extra.join(",")
        ));
    }
    Ok(())
}

fn collect_references(
    workspace: &Path,
    path: &Path,
    observed: &mut BTreeMap<(String, String), usize>,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect shell source-policy path {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "shell source-policy path must not be a symlink: {}",
            path.display()
        ));
    }
    if metadata.is_dir() {
        if path.file_name().and_then(|name| name.to_str()) == Some("tests") {
            return Ok(());
        }
        let mut entries = fs::read_dir(path)
            .map_err(|error| format!("cannot list {}: {error}", path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot list {}: {error}", path.display()))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            collect_references(workspace, &entry.path(), observed)?;
        }
        return Ok(());
    }
    if !metadata.is_file() || metadata.len() > MAX_SCANNED_SOURCE_BYTES {
        return if metadata.is_file() {
            Err(format!(
                "shell source-policy file {} exceeds {MAX_SCANNED_SOURCE_BYTES} bytes",
                path.display()
            ))
        } else {
            Ok(())
        };
    }
    if path
        .extension()
        .is_some_and(|extension| !matches!(extension.to_str(), Some("rs" | "sh")))
    {
        return Ok(());
    }
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let source = std::str::from_utf8(&bytes)
        .map_err(|_| format!("shell source-policy file {} is not UTF-8", path.display()))?;
    let relative = normalized_relative(workspace, path)?;
    for target in script_references(source) {
        *observed.entry((relative.clone(), target)).or_default() += 1;
    }
    Ok(())
}

fn script_references(source: &str) -> impl Iterator<Item = String> + '_ {
    source.match_indices("scripts/").map(|(index, _)| {
        let suffix = &source[index + "scripts/".len()..];
        let length = suffix
            .bytes()
            .take_while(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'*')
            })
            .count();
        format!("scripts/{}", &suffix[..length])
    })
}

fn normalized_relative(workspace: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(workspace)
        .map_err(|_| format!("{} is outside {}", path.display(), workspace.display()))
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_workspace_has_only_the_reviewed_bridge_references() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the workspace");
        validate(workspace).expect("checked shell bridge reference policy");
    }

    #[test]
    fn reference_scanner_finds_reconstructed_targets() {
        assert_eq!(
            script_references("scripts/dispatcher scripts/new-helper scripts/*")
                .collect::<Vec<_>>(),
            ["scripts/dispatcher", "scripts/new-helper", "scripts/*"]
        );
    }
}
