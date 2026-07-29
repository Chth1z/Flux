pub const ENGINE_CREDENTIAL_PROBE_STAGE_RECEIPT_NAME: &str = "credential-stage";
pub const ENGINE_CREDENTIAL_PROBE_STAGE_TEMPORARY_NAME: &str = "credential-stage-tmp";

use crate::process::ProcessHandleOpenStage;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineCredentialProbeStage {
    RootValidation,
    RootSpawn,
    RootReadiness,
    RootProcessHandle(ProcessHandleOpenStage),
    RootInitialCredentials,
    RootReobservation,
    RootReport,
    RootTermination,
    RootPostReap,
    DeviceGidValidation,
    DeviceGidSpawn,
    DeviceGidReadiness,
    DeviceGidProcessHandle(ProcessHandleOpenStage),
    DeviceGidInitialCredentials,
    DeviceGidReobservation,
    DeviceGidReport,
    DeviceGidTermination,
    DeviceGidPostReap,
    ParentDeathSupervisor,
    ParentDeathIdentity,
    ParentDeathContainment,
}

impl EngineCredentialProbeStage {
    const ROOT_PREFIX: [Self; 3] = [Self::RootValidation, Self::RootSpawn, Self::RootReadiness];
    const ROOT_SUFFIX_AND_DEVICE_PREFIX: [Self; 8] = [
        Self::RootInitialCredentials,
        Self::RootReobservation,
        Self::RootReport,
        Self::RootTermination,
        Self::RootPostReap,
        Self::DeviceGidValidation,
        Self::DeviceGidSpawn,
        Self::DeviceGidReadiness,
    ];
    const DEVICE_SUFFIX_AND_PARENT_DEATH: [Self; 8] = [
        Self::DeviceGidInitialCredentials,
        Self::DeviceGidReobservation,
        Self::DeviceGidReport,
        Self::DeviceGidTermination,
        Self::DeviceGidPostReap,
        Self::ParentDeathSupervisor,
        Self::ParentDeathIdentity,
        Self::ParentDeathContainment,
    ];
    #[cfg(test)]
    const COUNT: usize = Self::ROOT_PREFIX.len()
        + ProcessHandleOpenStage::COUNT
        + Self::ROOT_SUFFIX_AND_DEVICE_PREFIX.len()
        + ProcessHandleOpenStage::COUNT
        + Self::DEVICE_SUFFIX_AND_PARENT_DEATH.len();

    pub fn all() -> impl Iterator<Item = Self> {
        Self::ROOT_PREFIX
            .into_iter()
            .chain(ProcessHandleOpenStage::all().map(Self::RootProcessHandle))
            .chain(Self::ROOT_SUFFIX_AND_DEVICE_PREFIX)
            .chain(ProcessHandleOpenStage::all().map(Self::DeviceGidProcessHandle))
            .chain(Self::DEVICE_SUFFIX_AND_PARENT_DEATH)
    }

    #[must_use]
    pub fn as_str(self) -> String {
        match self {
            Self::RootValidation => "root-validation".to_owned(),
            Self::RootSpawn => "root-spawn".to_owned(),
            Self::RootReadiness => "root-readiness".to_owned(),
            Self::RootProcessHandle(stage) => {
                format!("root-process-handle-{}", stage.as_str())
            }
            Self::RootInitialCredentials => "root-initial-credentials".to_owned(),
            Self::RootReobservation => "root-reobservation".to_owned(),
            Self::RootReport => "root-report".to_owned(),
            Self::RootTermination => "root-termination".to_owned(),
            Self::RootPostReap => "root-post-reap".to_owned(),
            Self::DeviceGidValidation => "device-gid-validation".to_owned(),
            Self::DeviceGidSpawn => "device-gid-spawn".to_owned(),
            Self::DeviceGidReadiness => "device-gid-readiness".to_owned(),
            Self::DeviceGidProcessHandle(stage) => {
                format!("device-gid-process-handle-{}", stage.as_str())
            }
            Self::DeviceGidInitialCredentials => "device-gid-initial-credentials".to_owned(),
            Self::DeviceGidReobservation => "device-gid-reobservation".to_owned(),
            Self::DeviceGidReport => "device-gid-report".to_owned(),
            Self::DeviceGidTermination => "device-gid-termination".to_owned(),
            Self::DeviceGidPostReap => "device-gid-post-reap".to_owned(),
            Self::ParentDeathSupervisor => "parent-death-supervisor".to_owned(),
            Self::ParentDeathIdentity => "parent-death-identity".to_owned(),
            Self::ParentDeathContainment => "parent-death-containment".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn stages_and_receipt_names_are_canonical() {
        let stages = EngineCredentialProbeStage::all().collect::<Vec<_>>();
        let tokens = stages
            .iter()
            .copied()
            .map(EngineCredentialProbeStage::as_str)
            .collect::<Vec<_>>();
        assert_eq!(stages.len(), EngineCredentialProbeStage::COUNT);
        assert_eq!(tokens.first().map(String::as_str), Some("root-validation"));
        assert_eq!(
            tokens.last().map(String::as_str),
            Some("parent-death-containment")
        );
        assert_eq!(tokens.iter().collect::<BTreeSet<_>>().len(), tokens.len());
        assert!(tokens.iter().all(|token| {
            !token.is_empty()
                && token.len() <= 128
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        }));
        for stage in ProcessHandleOpenStage::all() {
            assert!(stages.contains(&EngineCredentialProbeStage::RootProcessHandle(stage)));
            assert!(stages.contains(&EngineCredentialProbeStage::DeviceGidProcessHandle(stage)));
            assert_eq!(
                EngineCredentialProbeStage::RootProcessHandle(stage).as_str(),
                format!("root-process-handle-{}", stage.as_str())
            );
            assert_eq!(
                EngineCredentialProbeStage::DeviceGidProcessHandle(stage).as_str(),
                format!("device-gid-process-handle-{}", stage.as_str())
            );
        }
        assert_eq!(
            ENGINE_CREDENTIAL_PROBE_STAGE_RECEIPT_NAME,
            "credential-stage"
        );
        assert_eq!(
            ENGINE_CREDENTIAL_PROBE_STAGE_TEMPORARY_NAME,
            "credential-stage-tmp"
        );
    }
}
