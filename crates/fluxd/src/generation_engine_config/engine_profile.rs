use std::error::Error;
use std::fmt;

use sha2::{Digest, Sha256};

use super::compiler::{
    ENGINE_CONFIG_DIGEST_BYTES, EngineConfigLaunchBinding, EngineConfigLaunchBindingDigest,
    length_bytes,
};
use crate::engine_supervisor::{EngineCapabilityProbeError, EngineCapabilityProbeErrorKind};
use crate::{EngineArtifactSetIdentity, EngineSpec};

pub(crate) const ENGINE_CAPABILITY_PROFILE_SCHEMA_VERSION: u16 = 2;

const ENGINE_CAPABILITY_PROFILE_DIGEST_DOMAIN: &[u8] =
    b"Flux Sing-Box Engine Capability Profile\0sha256-v2\0";
const SING_BOX_VERSION_PREFIX: &str = "sing-box version ";
const MAX_SING_BOX_RELEASE_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct EngineCapabilityProfileRevision([u8; ENGINE_CONFIG_DIGEST_BYTES]);

impl EngineCapabilityProfileRevision {
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; ENGINE_CONFIG_DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Display for EngineCapabilityProfileRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SingBoxVersionIdentity {
    release: Box<str>,
    major: u16,
    minor: u16,
    patch: u16,
}

impl SingBoxVersionIdentity {
    #[must_use]
    pub(crate) fn release(&self) -> &str {
        &self.release
    }

    #[must_use]
    pub(crate) const fn major(&self) -> u16 {
        self.major
    }

    #[must_use]
    pub(crate) const fn minor(&self) -> u16 {
        self.minor
    }

    #[must_use]
    pub(crate) const fn patch(&self) -> u16 {
        self.patch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SingBoxBuildIdentity {
    stdout: Box<str>,
    stderr: Box<str>,
}

impl SingBoxBuildIdentity {
    #[must_use]
    pub(crate) fn stdout(&self) -> &str {
        &self.stdout
    }

    #[must_use]
    pub(crate) fn stderr(&self) -> &str {
        &self.stderr
    }
}

/// Minimal immutable profile for the first canonical TPROXY Generation candidate.
///
/// Schema 2 proves only parsed exact-build identity and descriptor-pinned acceptance of the exact
/// config binding. Every other engine feature remains unclaimed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EngineCapabilityProfile {
    artifacts: EngineArtifactSetIdentity,
    validated_binding: EngineConfigLaunchBindingDigest,
    version: SingBoxVersionIdentity,
    build: SingBoxBuildIdentity,
    revision: EngineCapabilityProfileRevision,
}

impl EngineCapabilityProfile {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn schema_version(&self) -> u16 {
        ENGINE_CAPABILITY_PROFILE_SCHEMA_VERSION
    }

    #[must_use]
    pub(crate) const fn artifacts(&self) -> EngineArtifactSetIdentity {
        self.artifacts
    }

    #[must_use]
    pub(crate) const fn validated_binding(&self) -> EngineConfigLaunchBindingDigest {
        self.validated_binding
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn version(&self) -> &SingBoxVersionIdentity {
        &self.version
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn build(&self) -> &SingBoxBuildIdentity {
        &self.build
    }

    #[must_use]
    pub(crate) const fn revision(&self) -> EngineCapabilityProfileRevision {
        self.revision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EngineVersionOutputErrorKind {
    InvalidUtf8 { stream: &'static str },
    UnsafeText { stream: &'static str },
    MissingVersionHeader,
    AmbiguousVersionHeader,
    InvalidRelease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EngineCapabilityProfileErrorKind {
    ArtifactSetMismatch,
    PrivilegeMismatch,
    Probe(EngineCapabilityProbeErrorKind),
    VersionOutput(EngineVersionOutputErrorKind),
}

#[derive(Debug)]
pub(crate) struct EngineCapabilityProfileError {
    kind: EngineCapabilityProfileErrorKind,
    source: Option<Box<EngineCapabilityProbeError>>,
}

impl EngineCapabilityProfileError {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn kind(&self) -> EngineCapabilityProfileErrorKind {
        self.kind
    }

    const fn without_source(kind: EngineCapabilityProfileErrorKind) -> Self {
        Self { kind, source: None }
    }
}

impl fmt::Display for EngineCapabilityProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            EngineCapabilityProfileErrorKind::ArtifactSetMismatch => formatter.write_str(
                "engine config binding and EngineSpec identify different launch artifacts",
            ),
            EngineCapabilityProfileErrorKind::PrivilegeMismatch => formatter.write_str(
                "engine config binding and EngineSpec identify different privilege policies",
            ),
            EngineCapabilityProfileErrorKind::Probe(_) => {
                formatter.write_str("exact Proxy Engine capability probe failed")
            }
            EngineCapabilityProfileErrorKind::VersionOutput(kind) => {
                write!(
                    formatter,
                    "invalid exact Proxy Engine version output: {kind:?}"
                )
            }
        }
    }
}

impl Error for EngineCapabilityProfileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

pub(crate) fn collect_tproxy_engine_capability_profile(
    binding: &EngineConfigLaunchBinding,
    spec: &EngineSpec,
) -> Result<EngineCapabilityProfile, EngineCapabilityProfileError> {
    if binding.artifacts() != spec.artifacts() {
        return Err(EngineCapabilityProfileError::without_source(
            EngineCapabilityProfileErrorKind::ArtifactSetMismatch,
        ));
    }
    if binding.privilege() != spec.process().privilege {
        return Err(EngineCapabilityProfileError::without_source(
            EngineCapabilityProfileErrorKind::PrivilegeMismatch,
        ));
    }

    let probe = spec.probe_capabilities().map_err(|source| {
        let kind = EngineCapabilityProfileErrorKind::Probe(source.kind());
        EngineCapabilityProfileError {
            kind,
            source: Some(Box::new(source)),
        }
    })?;
    debug_assert_eq!(probe.artifacts(), binding.artifacts());
    let (version, build) =
        parse_sing_box_version_output(probe.version_stdout(), probe.version_stderr())?;
    let revision = EngineCapabilityProfileRevision(digest_engine_capability_profile(
        binding, &version, &build,
    ));
    Ok(EngineCapabilityProfile {
        artifacts: probe.artifacts(),
        validated_binding: binding.digest(),
        version,
        build,
        revision,
    })
}

#[cfg(test)]
pub(crate) fn rebind_engine_capability_profile_fixture(
    profile: EngineCapabilityProfile,
    binding: &EngineConfigLaunchBinding,
) -> EngineCapabilityProfile {
    assert_eq!(profile.artifacts, binding.artifacts());
    let revision = EngineCapabilityProfileRevision(digest_engine_capability_profile(
        binding,
        &profile.version,
        &profile.build,
    ));
    EngineCapabilityProfile {
        artifacts: profile.artifacts,
        validated_binding: binding.digest(),
        version: profile.version,
        build: profile.build,
        revision,
    }
}

pub(super) fn parse_sing_box_version_output(
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(SingBoxVersionIdentity, SingBoxBuildIdentity), EngineCapabilityProfileError> {
    let stdout = exact_safe_version_text(stdout, "stdout")?;
    let stderr = exact_safe_version_text(stderr, "stderr")?;
    let mut release = None;
    for line in stdout.lines().chain(stderr.lines()) {
        let Some(candidate) = line.strip_prefix(SING_BOX_VERSION_PREFIX) else {
            continue;
        };
        if release.replace(candidate).is_some() {
            return Err(engine_version_output_error(
                EngineVersionOutputErrorKind::AmbiguousVersionHeader,
            ));
        }
    }
    let release = release.ok_or_else(|| {
        engine_version_output_error(EngineVersionOutputErrorKind::MissingVersionHeader)
    })?;
    let (major, minor, patch) = parse_sing_box_release(release)
        .ok_or_else(|| engine_version_output_error(EngineVersionOutputErrorKind::InvalidRelease))?;

    Ok((
        SingBoxVersionIdentity {
            release: release.into(),
            major,
            minor,
            patch,
        },
        SingBoxBuildIdentity {
            stdout: stdout.into(),
            stderr: stderr.into(),
        },
    ))
}

fn exact_safe_version_text<'a>(
    bytes: &'a [u8],
    stream: &'static str,
) -> Result<&'a str, EngineCapabilityProfileError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        engine_version_output_error(EngineVersionOutputErrorKind::InvalidUtf8 { stream })
    })?;
    let unsafe_control = text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'));
    let bare_carriage_return = bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'));
    if unsafe_control || bare_carriage_return {
        return Err(engine_version_output_error(
            EngineVersionOutputErrorKind::UnsafeText { stream },
        ));
    }
    Ok(text)
}

fn parse_sing_box_release(release: &str) -> Option<(u16, u16, u16)> {
    if release.is_empty() || release.len() > MAX_SING_BOX_RELEASE_BYTES || !release.is_ascii() {
        return None;
    }

    let (without_build, build) = match release.split_once('+') {
        Some((version, build)) if valid_semver_identifiers(build, false) => (version, Some(build)),
        Some(_) => return None,
        None => (release, None),
    };
    debug_assert!(build.is_none_or(|value| !value.is_empty()));
    let (core, prerelease) = match without_build.split_once('-') {
        Some((core, prerelease)) if valid_semver_identifiers(prerelease, true) => {
            (core, Some(prerelease))
        }
        Some(_) => return None,
        None => (without_build, None),
    };
    debug_assert!(prerelease.is_none_or(|value| !value.is_empty()));

    let mut components = core.split('.');
    let major = parse_semver_component(components.next()?)?;
    let minor = parse_semver_component(components.next()?)?;
    let patch = parse_semver_component(components.next()?)?;
    if components.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn parse_semver_component(component: &str) -> Option<u16> {
    if component.is_empty()
        || !component.bytes().all(|byte| byte.is_ascii_digit())
        || (component.len() > 1 && component.starts_with('0'))
    {
        return None;
    }
    component.parse().ok()
}

fn valid_semver_identifiers(value: &str, reject_numeric_leading_zero: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!reject_numeric_leading_zero
                    || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || identifier.len() == 1
                    || !identifier.starts_with('0'))
        })
}

fn engine_version_output_error(kind: EngineVersionOutputErrorKind) -> EngineCapabilityProfileError {
    EngineCapabilityProfileError::without_source(EngineCapabilityProfileErrorKind::VersionOutput(
        kind,
    ))
}

fn digest_engine_capability_profile(
    binding: &EngineConfigLaunchBinding,
    version: &SingBoxVersionIdentity,
    build: &SingBoxBuildIdentity,
) -> [u8; ENGINE_CONFIG_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(ENGINE_CAPABILITY_PROFILE_DIGEST_DOMAIN);
    update_length_prefixed(
        &mut digest,
        &ENGINE_CAPABILITY_PROFILE_SCHEMA_VERSION.to_be_bytes(),
    );
    update_length_prefixed(&mut digest, binding.digest().as_bytes());
    let artifacts = binding.artifacts();
    update_length_prefixed(&mut digest, artifacts.binary().as_bytes());
    update_length_prefixed(&mut digest, artifacts.config().as_bytes());
    update_length_prefixed(&mut digest, version.release().as_bytes());
    update_length_prefixed(&mut digest, &version.major().to_be_bytes());
    update_length_prefixed(&mut digest, &version.minor().to_be_bytes());
    update_length_prefixed(&mut digest, &version.patch().to_be_bytes());
    update_length_prefixed(&mut digest, build.stdout().as_bytes());
    update_length_prefixed(&mut digest, build.stderr().as_bytes());
    digest.finalize().into()
}

fn update_length_prefixed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(length_bytes(bytes.len()));
    digest.update(bytes);
}
