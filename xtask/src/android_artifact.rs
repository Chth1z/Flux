use std::path::Path;

use super::sha256_file;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AndroidArtifactIdentity {
    sha256: String,
    size: u64,
}

impl AndroidArtifactIdentity {
    pub(super) fn from_file(path: &Path, description: &str) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("inspect {description} {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.len() == 0
        {
            return Err(format!(
                "{description} {} must be one non-empty regular file",
                path.display()
            ));
        }
        Ok(Self {
            sha256: sha256_file(path)?,
            size: metadata.len(),
        })
    }

    pub(super) fn verify_file(&self, path: &Path, description: &str) -> Result<(), String> {
        let actual = Self::from_file(path, description)?;
        if actual == *self {
            Ok(())
        } else {
            Err(format!(
                "{description} {} changed after its identity was captured",
                path.display()
            ))
        }
    }

    pub(super) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(super) const fn size(&self) -> u64 {
        self.size
    }

    #[cfg(test)]
    pub(super) fn for_test(sha256: String, size: u64) -> Self {
        assert_eq!(sha256.len(), 64);
        assert!(
            sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert!(size > 0);
        Self { sha256, size }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn identity_rejects_empty_files_and_detects_post_capture_changes() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "flux-android-artifact-{}-{nonce}",
            std::process::id()
        ));
        std::fs::write(&path, []).expect("write empty artifact");
        assert!(AndroidArtifactIdentity::from_file(&path, "test artifact").is_err());

        std::fs::write(&path, b"first").expect("write artifact");
        let identity = AndroidArtifactIdentity::from_file(&path, "test artifact")
            .expect("capture artifact identity");
        identity
            .verify_file(&path, "test artifact")
            .expect("unchanged artifact");
        std::fs::write(&path, b"second").expect("replace artifact bytes");
        assert!(identity.verify_file(&path, "test artifact").is_err());
        std::fs::remove_file(&path).expect("remove artifact fixture");
    }
}
