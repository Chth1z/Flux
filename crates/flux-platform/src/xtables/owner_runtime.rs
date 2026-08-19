use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU16, NonZeroU32};
use std::time::Instant;

use flux_core::{
    BootIdentity, GenerationId, NetworkAddressFamily, NetworkNamespaceIdentity,
    OwnershipJournalIdentity, OwnershipJournalRevision,
};
use sha2::{Digest, Sha256};

use crate::netlink::policy_routing::{
    ManagedInterfaceIdentity, ManagedPolicyRoutingIdentity, PolicyRoutingMutation,
};

use super::super::XtablesCaptureArtifactSet;
use super::super::owner_durable::{
    NATIVE_XTABLES_JOURNAL_SCHEMA_VERSION, NativeXtablesAttemptPayload, NativeXtablesAttemptPhase,
    NativeXtablesAttemptRecord, NativeXtablesDurableError, NativeXtablesDurableStore,
    NativeXtablesJournalBinding, NativeXtablesJournalObservation, NativeXtablesJournalPhase,
    NativeXtablesJournalRecord, NativeXtablesLeaseScope, NativeXtablesOwnerPayload,
    NativeXtablesRecovery, NativeXtablesRecoveryFence, NativeXtablesRecoveryInspection,
    NativeXtablesTransitionLease,
};
use super::super::save::{
    XtablesExpectedState, XtablesExpectedStatePhase, XtablesSaveProjection,
    XtablesSaveProjectionError,
};
use super::super::{
    XtablesRestoreAction, XtablesRestoreArtifact, XtablesRestoreContext, XtablesRestoreFamily,
    XtablesRestoreParseError, parse_xtables_restore,
};
use super::{XtablesStableFamilyPlan, XtablesStableTopologyError, XtablesStableTopologyPlan};
use crate::xtables::native_capture::{
    NativeCaptureCanaryAttempt, NativeCaptureCanaryCounterRetirement,
    NativeCaptureCanaryCounterSnapshot, NativeCaptureCanaryRouteOutcome,
    NativeCaptureCanaryRouteQuery, NativeCaptureCanarySelector, NativeCaptureOwnershipObservation,
    NativeCaptureRetainedOwner, NativeCaptureTargetIdentity,
};

const OWNER_PAYLOAD_SCHEMA: u16 = 3;
const CANARY_ATTEMPT_PAYLOAD_SCHEMA: u16 = 1;
const IDENTITY_DIGEST_BYTES: usize = 32;
const ALL_XTABLES_FAMILIES: [XtablesRestoreFamily; 2] =
    [XtablesRestoreFamily::Ipv4, XtablesRestoreFamily::Ipv6];
const ROUTING_IDENTITY_DIGEST_DOMAIN: &[u8] =
    b"Flux native xtables bound policy-routing audit\0sha256-v1\0";
const TARGET_RECOVERY_MATERIAL_DIGEST_DOMAIN: &[u8] =
    b"Flux native xtables exact recovery material\0sha256-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativePolicyRoutingAudit {
    identities: [ManagedPolicyRoutingIdentity; 2],
}

impl NativePolicyRoutingAudit {
    pub(crate) fn new(
        mut identities: [ManagedPolicyRoutingIdentity; 2],
    ) -> Result<Self, NativePolicyRoutingAuditError> {
        identities.sort_by_key(|identity| family_key(identity.family()));
        if identities[0].family() != NetworkAddressFamily::Ipv4
            || identities[1].family() != NetworkAddressFamily::Ipv6
        {
            return Err(NativePolicyRoutingAuditError::RequiresBothFamilies);
        }
        Ok(Self { identities })
    }

    #[must_use]
    pub(crate) const fn identities(&self) -> &[ManagedPolicyRoutingIdentity; 2] {
        &self.identities
    }

    #[must_use]
    pub(crate) const fn identity(
        &self,
        family: NetworkAddressFamily,
    ) -> ManagedPolicyRoutingIdentity {
        match family {
            NetworkAddressFamily::Ipv4 => self.identities[0],
            NetworkAddressFamily::Ipv6 => self.identities[1],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativePolicyRoutingAuditError {
    RequiresBothFamilies,
}

impl fmt::Display for NativePolicyRoutingAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("policy-routing audit requires one exact identity for each family")
    }
}

impl Error for NativePolicyRoutingAuditError {}

/// Exact immutable target identity retained in the bounded durable owner payload.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct NativeXtablesTargetIdentity {
    generation: GenerationId,
    target_digest: [u8; IDENTITY_DIGEST_BYTES],
    tool_digest: [u8; IDENTITY_DIGEST_BYTES],
    routing_digest: [u8; IDENTITY_DIGEST_BYTES],
}

impl NativeXtablesTargetIdentity {
    #[must_use]
    pub(crate) const fn generation(self) -> GenerationId {
        self.generation
    }

    #[must_use]
    pub(crate) const fn target_digest(self) -> [u8; IDENTITY_DIGEST_BYTES] {
        self.target_digest
    }

    #[must_use]
    pub(crate) const fn tool_digest(self) -> [u8; IDENTITY_DIGEST_BYTES] {
        self.tool_digest
    }

    #[must_use]
    pub(crate) const fn routing_digest(self) -> [u8; IDENTITY_DIGEST_BYTES] {
        self.routing_digest
    }
}

/// Complete platform-admitted immutable transaction target.
///
/// The raw constructor remains private. Production callers can obtain only the opaque public target
/// after the platform adapter has consumed Android planning evidence and checked every activation
/// prerequisite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesAdmittedTarget {
    identity: NativeXtablesTargetIdentity,
    source_artifact_digest: [u8; IDENTITY_DIGEST_BYTES],
    topology: Box<XtablesStableTopologyPlan>,
    routing: Box<[ManagedPolicyRoutingIdentity]>,
    routing_audit: Box<NativePolicyRoutingAudit>,
}

impl NativeXtablesAdmittedTarget {
    fn admit(
        artifacts: XtablesCaptureArtifactSet,
        routing: impl IntoIterator<Item = ManagedPolicyRoutingIdentity>,
        routing_audit: NativePolicyRoutingAudit,
        tool_digest: [u8; IDENTITY_DIGEST_BYTES],
    ) -> Result<Self, NativeXtablesTargetError> {
        let topology = XtablesStableTopologyPlan::from_artifacts(&artifacts)
            .map_err(NativeXtablesTargetError::Topology)?;
        let generation = artifacts.namespace().generation();
        let mut routing = routing.into_iter().collect::<Vec<_>>();
        routing.sort_by_key(|identity| family_key(identity.family()));

        let mut expected_routing = Vec::new();
        for family in topology.families() {
            let pair = artifacts
                .pair(family.family())
                .expect("topology family comes from the artifact set");
            let Some(requirements) = pair.local_output() else {
                continue;
            };
            let actual = routing
                .iter()
                .copied()
                .find(|identity| restore_family(identity.family()) == family.family())
                .ok_or(NativeXtablesTargetError::MissingRouting {
                    family: family.family(),
                })?;
            let expected = ManagedPolicyRoutingIdentity::bind(
                requirements.routing(),
                actual.loopback().index(),
            )
            .map_err(|_| NativeXtablesTargetError::RoutingMismatch {
                family: family.family(),
            })?;
            if expected != actual {
                return Err(NativeXtablesTargetError::RoutingMismatch {
                    family: family.family(),
                });
            }
            expected_routing.push(actual);
        }
        if expected_routing.len() != routing.len() {
            return Err(NativeXtablesTargetError::UnexpectedRouting);
        }
        if routing
            .iter()
            .any(|identity| routing_audit.identity(identity.family()) != *identity)
        {
            return Err(NativeXtablesTargetError::AuditRoutingMismatch);
        }

        let source_artifact_digest = *artifacts.digest().as_bytes();
        let routing_digest = digest_policy_routing_audit(&routing_audit);
        let target_digest = digest_target_recovery_material(
            generation,
            source_artifact_digest,
            tool_digest,
            routing_digest,
            &topology,
            &routing,
            &routing_audit,
        );
        Ok(Self {
            identity: NativeXtablesTargetIdentity {
                generation,
                target_digest,
                tool_digest,
                routing_digest,
            },
            source_artifact_digest,
            topology: Box::new(topology),
            routing: routing.into_boxed_slice(),
            routing_audit: Box::new(routing_audit),
        })
    }

    #[cfg(test)]
    pub(crate) fn admit_for_test(
        artifacts: XtablesCaptureArtifactSet,
        routing: impl IntoIterator<Item = ManagedPolicyRoutingIdentity>,
        routing_audit: NativePolicyRoutingAudit,
        tool_digest: [u8; IDENTITY_DIGEST_BYTES],
    ) -> Result<Self, NativeXtablesTargetError> {
        Self::admit(artifacts, routing, routing_audit, tool_digest)
    }

    fn from_recovery(
        identity: NativeXtablesTargetIdentity,
        source_artifact_digest: [u8; IDENTITY_DIGEST_BYTES],
        topology: XtablesStableTopologyPlan,
        mut routing: Vec<ManagedPolicyRoutingIdentity>,
        routing_audit: NativePolicyRoutingAudit,
    ) -> Result<Self, NativeXtablesTargetError> {
        routing.sort_by_key(|identity| family_key(identity.family()));
        if routing
            .windows(2)
            .any(|pair| pair[0].family() == pair[1].family())
        {
            return Err(NativeXtablesTargetError::UnexpectedRouting);
        }
        for family in topology.families() {
            let has_routing = routing
                .iter()
                .any(|identity| restore_family(identity.family()) == family.family());
            if family.output_root().is_some() != has_routing {
                return Err(if has_routing {
                    NativeXtablesTargetError::UnexpectedRouting
                } else {
                    NativeXtablesTargetError::MissingRouting {
                        family: family.family(),
                    }
                });
            }
        }
        if routing
            .iter()
            .any(|identity| routing_audit.identity(identity.family()) != *identity)
        {
            return Err(NativeXtablesTargetError::AuditRoutingMismatch);
        }
        if digest_policy_routing_audit(&routing_audit) != identity.routing_digest {
            return Err(NativeXtablesTargetError::RecoveryRoutingDigestMismatch);
        }
        let target_digest = digest_target_recovery_material(
            identity.generation,
            source_artifact_digest,
            identity.tool_digest,
            identity.routing_digest,
            &topology,
            &routing,
            &routing_audit,
        );
        if target_digest != identity.target_digest {
            return Err(NativeXtablesTargetError::RecoveryMaterialDigestMismatch);
        }
        Ok(Self {
            identity,
            source_artifact_digest,
            topology: Box::new(topology),
            routing: routing.into_boxed_slice(),
            routing_audit: Box::new(routing_audit),
        })
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> NativeXtablesTargetIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn source_artifact_digest(&self) -> [u8; IDENTITY_DIGEST_BYTES] {
        self.source_artifact_digest
    }

    #[must_use]
    pub(crate) const fn topology(&self) -> &XtablesStableTopologyPlan {
        &self.topology
    }

    #[must_use]
    pub(crate) const fn routing(&self) -> &[ManagedPolicyRoutingIdentity] {
        &self.routing
    }

    #[must_use]
    pub(crate) const fn routing_audit(&self) -> &NativePolicyRoutingAudit {
        &self.routing_audit
    }
}

#[derive(Debug)]
pub(crate) enum NativeXtablesTargetError {
    Topology(XtablesStableTopologyError),
    MissingRouting { family: XtablesRestoreFamily },
    RoutingMismatch { family: XtablesRestoreFamily },
    UnexpectedRouting,
    AuditRoutingMismatch,
    RecoveryRoutingDigestMismatch,
    RecoveryMaterialDigestMismatch,
}

impl fmt::Display for NativeXtablesTargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Topology(source) => write!(formatter, "invalid native topology: {source}"),
            Self::MissingRouting { family } => {
                write!(
                    formatter,
                    "missing {family:?} admitted policy-routing identity"
                )
            }
            Self::RoutingMismatch { family } => write!(
                formatter,
                "{family:?} admitted policy-routing identity does not match the lowered target"
            ),
            Self::UnexpectedRouting => {
                formatter.write_str("target contains an unexpected policy-routing identity")
            }
            Self::AuditRoutingMismatch => formatter.write_str(
                "target policy-routing identity differs from its complete recovery audit",
            ),
            Self::RecoveryRoutingDigestMismatch => formatter.write_str(
                "recovered target policy-routing audit digest does not match its identity",
            ),
            Self::RecoveryMaterialDigestMismatch => formatter
                .write_str("recovered target runtime material digest does not match its identity"),
        }
    }
}

impl Error for NativeXtablesTargetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Topology(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NativeXtablesDesiredTarget {
    Active(NativeXtablesAdmittedTarget),
    Stopped,
}

/// Immutable-generation lookup used only for crash recovery and replacement rollback.
pub(crate) trait NativeXtablesTargetResolver {
    fn resolve(
        &mut self,
        identity: NativeXtablesTargetIdentity,
    ) -> Result<NativeXtablesAdmittedTarget, Box<str>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeMutationCertainty {
    NotMutated,
    MayHaveMutated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesAdapterError {
    operation: Box<str>,
    certainty: NativeMutationCertainty,
    detail: Box<str>,
}

impl NativeXtablesAdapterError {
    pub(crate) fn new(
        operation: impl Into<Box<str>>,
        certainty: NativeMutationCertainty,
        detail: impl Into<Box<str>>,
    ) -> Self {
        Self {
            operation: operation.into(),
            certainty,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub(crate) const fn certainty(&self) -> NativeMutationCertainty {
        self.certainty
    }
}

impl fmt::Display for NativeXtablesAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "native operation {} failed ({:?}): {}",
            self.operation, self.certainty, self.detail
        )
    }
}

impl Error for NativeXtablesAdapterError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativePolicyRoutingObservation {
    route_exact: usize,
    route_conflicts: usize,
    rule_exact: usize,
    rule_conflicts: usize,
}

/// Rule-ordered packet counters from one exact owner-derived canary observation chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesCanaryCounterReadback {
    capture_packets: u64,
    recapture_packets: u64,
    bypass_packets: u64,
}

impl NativeXtablesCanaryCounterReadback {
    #[must_use]
    pub(crate) const fn new(
        capture_packets: u64,
        recapture_packets: u64,
        bypass_packets: u64,
    ) -> Self {
        Self {
            capture_packets,
            recapture_packets,
            bypass_packets,
        }
    }

    #[must_use]
    const fn capture_packets(self) -> u64 {
        self.capture_packets
    }

    #[must_use]
    const fn recapture_packets(self) -> u64 {
        self.recapture_packets
    }

    #[must_use]
    const fn bypass_packets(self) -> u64 {
        self.bypass_packets
    }
}

impl NativePolicyRoutingObservation {
    #[must_use]
    pub(crate) const fn new(
        route_exact: usize,
        route_conflicts: usize,
        rule_exact: usize,
        rule_conflicts: usize,
    ) -> Self {
        Self {
            route_exact,
            route_conflicts,
            rule_exact,
            rule_conflicts,
        }
    }

    #[must_use]
    pub(crate) const fn absent(self) -> bool {
        self.route_exact == 0
            && self.route_conflicts == 0
            && self.rule_exact == 0
            && self.rule_conflicts == 0
    }

    #[must_use]
    pub(crate) const fn exact(self) -> bool {
        self.route_exact == 1
            && self.route_conflicts == 0
            && self.rule_exact == 1
            && self.rule_conflicts == 0
    }

    #[must_use]
    const fn has_conflict(self) -> bool {
        self.route_conflicts != 0
            || self.rule_conflicts != 0
            || self.route_exact > 1
            || self.rule_exact > 1
    }
}

/// Private platform seam. The owner, not the Adapter, owns transaction ordering.
pub(crate) trait NativeXtablesOwnerAdapter {
    fn tool_digest(&self) -> [u8; IDENTITY_DIGEST_BYTES];

    fn validate_interface_identity(
        &mut self,
        identity: ManagedInterfaceIdentity,
    ) -> Result<(), NativeXtablesAdapterError>;

    fn restore(
        &mut self,
        family: XtablesRestoreFamily,
        artifact: &XtablesRestoreArtifact,
    ) -> Result<(), NativeXtablesAdapterError>;

    fn observe_xtables(
        &mut self,
        family: XtablesRestoreFamily,
    ) -> Result<XtablesSaveProjection, NativeXtablesAdapterError>;

    fn observe_canary_counters(
        &mut self,
        family: XtablesRestoreFamily,
        expected: &XtablesExpectedState,
        observation_chain: &str,
    ) -> Result<NativeXtablesCanaryCounterReadback, NativeXtablesAdapterError>;

    fn mutate_policy_routing(
        &mut self,
        mutation: PolicyRoutingMutation,
    ) -> Result<(), NativeXtablesAdapterError>;

    fn observe_policy_routing(
        &mut self,
        identity: ManagedPolicyRoutingIdentity,
    ) -> Result<NativePolicyRoutingObservation, NativeXtablesAdapterError>;

    fn observe_canary_route(
        &mut self,
        query: NativeCaptureCanaryRouteQuery,
    ) -> Result<NativeCaptureCanaryRouteOutcome, NativeXtablesAdapterError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesEnvironment {
    boot_identity: BootIdentity,
    network_namespace: NetworkNamespaceIdentity,
    journal_identity: OwnershipJournalIdentity,
    routing_audit: NativePolicyRoutingAudit,
}

impl NativeXtablesEnvironment {
    #[must_use]
    pub(crate) const fn new(
        boot_identity: BootIdentity,
        network_namespace: NetworkNamespaceIdentity,
        journal_identity: OwnershipJournalIdentity,
        routing_audit: NativePolicyRoutingAudit,
    ) -> Self {
        Self {
            boot_identity,
            network_namespace,
            journal_identity,
            routing_audit,
        }
    }

    fn binding(&self, generation: GenerationId) -> NativeXtablesJournalBinding {
        NativeXtablesJournalBinding::new(
            self.boot_identity.clone(),
            self.network_namespace,
            generation,
            self.journal_identity,
        )
    }

    fn lease_scope(&self) -> NativeXtablesLeaseScope {
        NativeXtablesLeaseScope::new(
            self.boot_identity.clone(),
            self.network_namespace,
            self.journal_identity,
        )
    }

    #[must_use]
    const fn routing_audit(&self) -> &NativePolicyRoutingAudit {
        &self.routing_audit
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeOwnerStep {
    Begin,
    PrepareIpv4,
    PrepareIpv6,
    AddRouteIpv4,
    AddRouteIpv6,
    AddRuleIpv4,
    AddRuleIpv6,
    AttachIpv4,
    AttachIpv6,
    SwitchIpv4,
    SwitchIpv6,
    DetachOutputIpv4,
    DetachOutputIpv6,
    DeleteRuleIpv4,
    DeleteRuleIpv6,
    DeleteRouteIpv4,
    DeleteRouteIpv6,
    DetachRemainingIpv4,
    DetachRemainingIpv6,
    RetireIpv4,
    RetireIpv6,
    PopulateCanaryIpv4,
    PopulateCanaryIpv6,
    CanaryActive,
    RetireCanaryIpv4,
    RetireCanaryIpv6,
    PublishActive,
    Rollback,
    Failed,
}

impl NativeOwnerStep {
    const fn token(self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::PrepareIpv4 => "prepare_ipv4",
            Self::PrepareIpv6 => "prepare_ipv6",
            Self::AddRouteIpv4 => "add_route_ipv4",
            Self::AddRouteIpv6 => "add_route_ipv6",
            Self::AddRuleIpv4 => "add_rule_ipv4",
            Self::AddRuleIpv6 => "add_rule_ipv6",
            Self::AttachIpv4 => "attach_ipv4",
            Self::AttachIpv6 => "attach_ipv6",
            Self::SwitchIpv4 => "switch_ipv4",
            Self::SwitchIpv6 => "switch_ipv6",
            Self::DetachOutputIpv4 => "detach_output_ipv4",
            Self::DetachOutputIpv6 => "detach_output_ipv6",
            Self::DeleteRuleIpv4 => "delete_rule_ipv4",
            Self::DeleteRuleIpv6 => "delete_rule_ipv6",
            Self::DeleteRouteIpv4 => "delete_route_ipv4",
            Self::DeleteRouteIpv6 => "delete_route_ipv6",
            Self::DetachRemainingIpv4 => "detach_remaining_ipv4",
            Self::DetachRemainingIpv6 => "detach_remaining_ipv6",
            Self::RetireIpv4 => "retire_ipv4",
            Self::RetireIpv6 => "retire_ipv6",
            Self::PopulateCanaryIpv4 => "populate_canary_ipv4",
            Self::PopulateCanaryIpv6 => "populate_canary_ipv6",
            Self::CanaryActive => "canary_active",
            Self::RetireCanaryIpv4 => "retire_canary_ipv4",
            Self::RetireCanaryIpv6 => "retire_canary_ipv6",
            Self::PublishActive => "publish_active",
            Self::Rollback => "rollback",
            Self::Failed => "failed",
        }
    }

    fn parse(token: &str) -> Option<Self> {
        Some(match token {
            "begin" => Self::Begin,
            "prepare_ipv4" => Self::PrepareIpv4,
            "prepare_ipv6" => Self::PrepareIpv6,
            "add_route_ipv4" => Self::AddRouteIpv4,
            "add_route_ipv6" => Self::AddRouteIpv6,
            "add_rule_ipv4" => Self::AddRuleIpv4,
            "add_rule_ipv6" => Self::AddRuleIpv6,
            "attach_ipv4" => Self::AttachIpv4,
            "attach_ipv6" => Self::AttachIpv6,
            "switch_ipv4" => Self::SwitchIpv4,
            "switch_ipv6" => Self::SwitchIpv6,
            "detach_output_ipv4" => Self::DetachOutputIpv4,
            "detach_output_ipv6" => Self::DetachOutputIpv6,
            "delete_rule_ipv4" => Self::DeleteRuleIpv4,
            "delete_rule_ipv6" => Self::DeleteRuleIpv6,
            "delete_route_ipv4" => Self::DeleteRouteIpv4,
            "delete_route_ipv6" => Self::DeleteRouteIpv6,
            "detach_remaining_ipv4" => Self::DetachRemainingIpv4,
            "detach_remaining_ipv6" => Self::DetachRemainingIpv6,
            "retire_ipv4" => Self::RetireIpv4,
            "retire_ipv6" => Self::RetireIpv6,
            "populate_canary_ipv4" => Self::PopulateCanaryIpv4,
            "populate_canary_ipv6" => Self::PopulateCanaryIpv6,
            "canary_active" => Self::CanaryActive,
            "retire_canary_ipv4" => Self::RetireCanaryIpv4,
            "retire_canary_ipv6" => Self::RetireCanaryIpv6,
            "publish_active" => Self::PublishActive,
            "rollback" => Self::Rollback,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeOwnerIntent {
    step: NativeOwnerStep,
    target: Option<NativeXtablesTargetIdentity>,
    previous: Option<NativeXtablesTargetIdentity>,
}

impl NativeOwnerIntent {
    fn payload(&self) -> Result<NativeXtablesOwnerPayload, NativeXtablesDurableError> {
        let encoded = format!(
            "schema={OWNER_PAYLOAD_SCHEMA}\nstep={}\ntarget={}\nprevious={}\n",
            self.step.token(),
            encode_optional_identity(self.target),
            encode_optional_identity(self.previous),
        );
        NativeXtablesOwnerPayload::new(encoded.into_bytes())
    }

    fn parse(payload: &NativeXtablesOwnerPayload) -> Result<Self, NativeXtablesOwnerError> {
        let text = std::str::from_utf8(payload.as_bytes())
            .map_err(|_| NativeXtablesOwnerError::InvalidPayload("payload is not UTF-8"))?;
        let lines = text.lines().collect::<Vec<_>>();
        if lines.len() != 4 {
            return Err(NativeXtablesOwnerError::InvalidPayload(
                "payload must contain four canonical fields",
            ));
        }
        if lines[0] != format!("schema={OWNER_PAYLOAD_SCHEMA}") {
            return Err(NativeXtablesOwnerError::InvalidPayload(
                "unsupported payload schema",
            ));
        }
        let step = lines[1]
            .strip_prefix("step=")
            .and_then(NativeOwnerStep::parse)
            .ok_or(NativeXtablesOwnerError::InvalidPayload(
                "invalid owner step",
            ))?;
        let target = lines[2]
            .strip_prefix("target=")
            .ok_or(NativeXtablesOwnerError::InvalidPayload(
                "missing target field",
            ))
            .and_then(parse_optional_identity)?;
        let previous = lines[3]
            .strip_prefix("previous=")
            .ok_or(NativeXtablesOwnerError::InvalidPayload(
                "missing previous field",
            ))
            .and_then(parse_optional_identity)?;
        Ok(Self {
            step,
            target,
            previous,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeCanaryAttemptBinding {
    attempt: NativeCaptureCanaryAttempt,
}

impl NativeCanaryAttemptBinding {
    const fn new(attempt: NativeCaptureCanaryAttempt) -> Self {
        Self { attempt }
    }

    fn payload(&self) -> Result<NativeXtablesAttemptPayload, NativeXtablesDurableError> {
        let selector = self.attempt.selector();
        let (families, ipv6_peer) = match selector.ipv6_peer() {
            Some(peer) => ("ipv4_ipv6", peer.to_string()),
            None => ("ipv4", "-".to_owned()),
        };
        let encoded = format!(
            "schema={CANARY_ATTEMPT_PAYLOAD_SCHEMA}\n\
             nonce={}\n\
             selector_identity={}\n\
             facility_digest={}\n\
             families={families}\n\
             probe_uid={}\n\
             ipv4_peer={}\n\
             ipv6_peer={ipv6_peer}\n\
             tcp_echo_port={}\n\
             udp_echo_port={}\n\
             dns_port={}\n",
            encode_hex(self.attempt.nonce()),
            encode_hex(self.attempt.selector_identity()),
            encode_hex(self.attempt.facility_digest()),
            selector.probe_uid(),
            selector.ipv4_peer(),
            selector.tcp_echo_port(),
            selector.udp_echo_port(),
            selector.dns_port(),
        );
        NativeXtablesAttemptPayload::new(encoded.into_bytes())
    }

    fn parse(payload: &NativeXtablesAttemptPayload) -> Result<Self, NativeXtablesOwnerError> {
        let text = std::str::from_utf8(payload.as_bytes())
            .map_err(|_| NativeXtablesOwnerError::InvalidCanaryAttempt("payload is not UTF-8"))?;
        let lines = text.lines().collect::<Vec<_>>();
        if lines.len() != 11 {
            return Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
                "payload must contain eleven canonical fields",
            ));
        }
        if lines[0] != format!("schema={CANARY_ATTEMPT_PAYLOAD_SCHEMA}") {
            return Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
                "unsupported payload schema",
            ));
        }
        let nonce = parse_attempt_digest(lines[1], "nonce=")?;
        let selector_identity = parse_attempt_digest(lines[2], "selector_identity=")?;
        let facility_digest = parse_attempt_digest(lines[3], "facility_digest=")?;
        let families = attempt_field(lines[4], "families=")?;
        let probe_uid = attempt_field(lines[5], "probe_uid=")?
            .parse::<u32>()
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or(NativeXtablesOwnerError::InvalidCanaryAttempt(
                "invalid probe UID",
            ))?;
        let ipv4_peer = attempt_field(lines[6], "ipv4_peer=")?
            .parse::<Ipv4Addr>()
            .map_err(|_| NativeXtablesOwnerError::InvalidCanaryAttempt("invalid IPv4 peer"))?;
        let ipv6_token = attempt_field(lines[7], "ipv6_peer=")?;
        let ipv6_peer = match (families, ipv6_token) {
            ("ipv4", "-") => None,
            ("ipv4_ipv6", token) if token != "-" => {
                Some(token.parse::<Ipv6Addr>().map_err(|_| {
                    NativeXtablesOwnerError::InvalidCanaryAttempt("invalid IPv6 peer")
                })?)
            }
            _ => {
                return Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
                    "address-family and IPv6 peer fields disagree",
                ));
            }
        };
        let tcp_echo_port = parse_attempt_port(lines[8], "tcp_echo_port=")?;
        let udp_echo_port = parse_attempt_port(lines[9], "udp_echo_port=")?;
        let dns_port = parse_attempt_port(lines[10], "dns_port=")?;
        let selector = NativeCaptureCanarySelector::new(
            probe_uid,
            ipv4_peer,
            ipv6_peer,
            tcp_echo_port,
            udp_echo_port,
            dns_port,
        )
        .ok_or(NativeXtablesOwnerError::InvalidCanaryAttempt(
            "selector ports collide",
        ))?;
        let attempt =
            NativeCaptureCanaryAttempt::new(selector, nonce, selector_identity, facility_digest)
                .ok_or(NativeXtablesOwnerError::InvalidCanaryAttempt(
                    "selector identity or facility digest is zero",
                ))?;
        let binding = Self::new(attempt);
        if binding.payload()?.as_bytes() != payload.as_bytes() {
            return Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
                "payload is not canonical",
            ));
        }
        Ok(binding)
    }
}

fn attempt_field<'a>(line: &'a str, prefix: &str) -> Result<&'a str, NativeXtablesOwnerError> {
    line.strip_prefix(prefix)
        .ok_or(NativeXtablesOwnerError::InvalidCanaryAttempt(
            "missing or reordered payload field",
        ))
}

fn parse_attempt_digest(
    line: &str,
    prefix: &str,
) -> Result<[u8; IDENTITY_DIGEST_BYTES], NativeXtablesOwnerError> {
    decode_digest(attempt_field(line, prefix)?).ok_or(
        NativeXtablesOwnerError::InvalidCanaryAttempt("invalid fixed-size identity"),
    )
}

fn parse_attempt_port(line: &str, prefix: &str) -> Result<NonZeroU16, NativeXtablesOwnerError> {
    attempt_field(line, prefix)?
        .parse::<u16>()
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or(NativeXtablesOwnerError::InvalidCanaryAttempt(
            "invalid responder port",
        ))
}

fn encode_optional_identity(identity: Option<NativeXtablesTargetIdentity>) -> String {
    let Some(identity) = identity else {
        return "-".to_owned();
    };
    format!(
        "{}:{}:{}:{}",
        identity.generation.get(),
        encode_hex(&identity.target_digest),
        encode_hex(&identity.tool_digest),
        encode_hex(&identity.routing_digest),
    )
}

fn parse_optional_identity(
    token: &str,
) -> Result<Option<NativeXtablesTargetIdentity>, NativeXtablesOwnerError> {
    if token == "-" {
        return Ok(None);
    }
    let mut fields = token.split(':');
    let generation = fields
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .and_then(GenerationId::new)
        .ok_or(NativeXtablesOwnerError::InvalidPayload(
            "invalid target generation",
        ))?;
    let target_digest =
        fields
            .next()
            .and_then(decode_digest)
            .ok_or(NativeXtablesOwnerError::InvalidPayload(
                "invalid target digest",
            ))?;
    let tool_digest =
        fields
            .next()
            .and_then(decode_digest)
            .ok_or(NativeXtablesOwnerError::InvalidPayload(
                "invalid target tool digest",
            ))?;
    let routing_digest =
        fields
            .next()
            .and_then(decode_digest)
            .ok_or(NativeXtablesOwnerError::InvalidPayload(
                "invalid target routing digest",
            ))?;
    if fields.next().is_some() {
        return Err(NativeXtablesOwnerError::InvalidPayload(
            "target identity has extra fields",
        ));
    }
    Ok(Some(NativeXtablesTargetIdentity {
        generation,
        target_digest,
        tool_digest,
        routing_digest,
    }))
}

fn digest_policy_routing_audit(audit: &NativePolicyRoutingAudit) -> [u8; IDENTITY_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(ROUTING_IDENTITY_DIGEST_DOMAIN);
    for identity in audit.identities() {
        update_policy_routing_identity(&mut digest, *identity);
    }
    digest.finalize().into()
}

fn digest_target_recovery_material(
    generation: GenerationId,
    artifact_digest: [u8; IDENTITY_DIGEST_BYTES],
    tool_digest: [u8; IDENTITY_DIGEST_BYTES],
    routing_digest: [u8; IDENTITY_DIGEST_BYTES],
    topology: &XtablesStableTopologyPlan,
    routing: &[ManagedPolicyRoutingIdentity],
    routing_audit: &NativePolicyRoutingAudit,
) -> [u8; IDENTITY_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(TARGET_RECOVERY_MATERIAL_DIGEST_DOMAIN);
    digest.update(generation.get().to_be_bytes());
    digest.update(artifact_digest);
    digest.update(tool_digest);
    digest.update(routing_digest);
    update_count(&mut digest, topology.families().len());
    for family in topology.families() {
        digest.update([restore_family_key(family.family())]);
        update_count(&mut digest, family.private_chains().len());
        for chain in family.private_chains() {
            update_bytes(&mut digest, chain.as_bytes());
        }
        update_optional_text(&mut digest, family.prerouting_root());
        update_optional_text(&mut digest, family.output_root());
        for artifact in [
            Some(family.prepare()),
            Some(family.retire()),
            Some(family.install()),
            Some(family.switch()),
            family.detach_output(),
            Some(family.detach_remaining()),
        ] {
            match artifact {
                Some(artifact) => {
                    digest.update([1]);
                    update_bytes(&mut digest, &artifact.render_canonical());
                }
                None => digest.update([0]),
            }
        }
    }
    update_count(&mut digest, routing.len());
    for identity in routing {
        update_policy_routing_identity(&mut digest, *identity);
    }
    for identity in routing_audit.identities() {
        update_policy_routing_identity(&mut digest, *identity);
    }
    digest.finalize().into()
}

fn update_policy_routing_identity(digest: &mut Sha256, identity: ManagedPolicyRoutingIdentity) {
    digest.update([family_key(identity.family())]);
    let loopback = identity.loopback();
    update_bytes(digest, loopback.name().as_bytes());
    digest.update(loopback.index().get().to_be_bytes());

    let route = identity.route();
    digest.update([family_key(route.family())]);
    match route.destination().address() {
        IpAddr::V4(address) => {
            digest.update([4]);
            digest.update(address.octets());
        }
        IpAddr::V6(address) => {
            digest.update([6]);
            digest.update(address.octets());
        }
    }
    digest.update([route.destination().prefix_length()]);
    digest.update(route.table().get().to_be_bytes());
    digest.update([
        route.protocol().raw(),
        route.scope().raw(),
        route.route_type().raw(),
    ]);
    digest.update(route.metric().get().to_be_bytes());
    digest.update(route.output_interface().get().to_be_bytes());

    let rule = identity.rule();
    digest.update([family_key(rule.family())]);
    digest.update(rule.priority().get().to_be_bytes());
    digest.update(rule.table().get().to_be_bytes());
    digest.update(rule.mark().value().to_be_bytes());
    digest.update(rule.mark().mask().to_be_bytes());
    digest.update([rule.protocol().raw()]);
}

fn update_optional_text(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            digest.update([1]);
            update_bytes(digest, value.as_bytes());
        }
        None => digest.update([0]),
    }
}

fn update_bytes(digest: &mut Sha256, value: &[u8]) {
    update_count(digest, value.len());
    digest.update(value);
}

fn update_count(digest: &mut Sha256, value: usize) {
    digest.update(
        u64::try_from(value)
            .expect("native recovery material length fits u64")
            .to_be_bytes(),
    );
}

const fn restore_family_key(family: XtablesRestoreFamily) -> u8 {
    match family {
        XtablesRestoreFamily::Ipv4 => 4,
        XtablesRestoreFamily::Ipv6 => 6,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_digest(value: &str) -> Option<[u8; IDENTITY_DIGEST_BYTES]> {
    if value.len() != IDENTITY_DIGEST_BYTES * 2 {
        return None;
    }
    let mut output = [0_u8; IDENTITY_DIGEST_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Some(output)
}

const fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn family_key(family: NetworkAddressFamily) -> u8 {
    match family {
        NetworkAddressFamily::Ipv4 => 4,
        NetworkAddressFamily::Ipv6 => 6,
    }
}

const fn restore_family(family: NetworkAddressFamily) -> XtablesRestoreFamily {
    match family {
        NetworkAddressFamily::Ipv4 => XtablesRestoreFamily::Ipv4,
        NetworkAddressFamily::Ipv6 => XtablesRestoreFamily::Ipv6,
    }
}

const fn prepare_step(family: XtablesRestoreFamily) -> NativeOwnerStep {
    match family {
        XtablesRestoreFamily::Ipv4 => NativeOwnerStep::PrepareIpv4,
        XtablesRestoreFamily::Ipv6 => NativeOwnerStep::PrepareIpv6,
    }
}

const fn route_add_step(family: NetworkAddressFamily) -> NativeOwnerStep {
    match family {
        NetworkAddressFamily::Ipv4 => NativeOwnerStep::AddRouteIpv4,
        NetworkAddressFamily::Ipv6 => NativeOwnerStep::AddRouteIpv6,
    }
}

const fn rule_add_step(family: NetworkAddressFamily) -> NativeOwnerStep {
    match family {
        NetworkAddressFamily::Ipv4 => NativeOwnerStep::AddRuleIpv4,
        NetworkAddressFamily::Ipv6 => NativeOwnerStep::AddRuleIpv6,
    }
}

const fn attach_step(family: XtablesRestoreFamily) -> NativeOwnerStep {
    match family {
        XtablesRestoreFamily::Ipv4 => NativeOwnerStep::AttachIpv4,
        XtablesRestoreFamily::Ipv6 => NativeOwnerStep::AttachIpv6,
    }
}

const fn switch_step(family: XtablesRestoreFamily) -> NativeOwnerStep {
    match family {
        XtablesRestoreFamily::Ipv4 => NativeOwnerStep::SwitchIpv4,
        XtablesRestoreFamily::Ipv6 => NativeOwnerStep::SwitchIpv6,
    }
}

const fn detach_output_step(family: XtablesRestoreFamily) -> NativeOwnerStep {
    match family {
        XtablesRestoreFamily::Ipv4 => NativeOwnerStep::DetachOutputIpv4,
        XtablesRestoreFamily::Ipv6 => NativeOwnerStep::DetachOutputIpv6,
    }
}

const fn rule_delete_step(family: NetworkAddressFamily) -> NativeOwnerStep {
    match family {
        NetworkAddressFamily::Ipv4 => NativeOwnerStep::DeleteRuleIpv4,
        NetworkAddressFamily::Ipv6 => NativeOwnerStep::DeleteRuleIpv6,
    }
}

const fn route_delete_step(family: NetworkAddressFamily) -> NativeOwnerStep {
    match family {
        NetworkAddressFamily::Ipv4 => NativeOwnerStep::DeleteRouteIpv4,
        NetworkAddressFamily::Ipv6 => NativeOwnerStep::DeleteRouteIpv6,
    }
}

const fn detach_remaining_step(family: XtablesRestoreFamily) -> NativeOwnerStep {
    match family {
        XtablesRestoreFamily::Ipv4 => NativeOwnerStep::DetachRemainingIpv4,
        XtablesRestoreFamily::Ipv6 => NativeOwnerStep::DetachRemainingIpv6,
    }
}

const fn retire_step(family: XtablesRestoreFamily) -> NativeOwnerStep {
    match family {
        XtablesRestoreFamily::Ipv4 => NativeOwnerStep::RetireIpv4,
        XtablesRestoreFamily::Ipv6 => NativeOwnerStep::RetireIpv6,
    }
}

const fn retire_canary_step(family: XtablesRestoreFamily) -> NativeOwnerStep {
    match family {
        XtablesRestoreFamily::Ipv4 => NativeOwnerStep::RetireCanaryIpv4,
        XtablesRestoreFamily::Ipv6 => NativeOwnerStep::RetireCanaryIpv6,
    }
}

struct NativeCanaryAttemptFamilyPlan {
    family: XtablesRestoreFamily,
    selector_chain: Box<str>,
    observation_chain: Box<str>,
    populate_selector: XtablesRestoreArtifact,
    retire_selector: XtablesRestoreArtifact,
    populate_observation: XtablesRestoreArtifact,
    retire_observation: XtablesRestoreArtifact,
    selector_state: XtablesExpectedState,
    active_attempt_state: XtablesExpectedState,
}

#[derive(Debug)]
struct NativeXtablesAttemptSession {
    lease: NativeXtablesTransitionLease,
    record: NativeXtablesAttemptRecord,
    target: NativeXtablesTargetIdentity,
    attempt: NativeCaptureCanaryAttempt,
    primary: NativeXtablesJournalRecord,
}

impl NativeXtablesAttemptSession {
    pub(super) fn matches(
        &self,
        target: NativeXtablesTargetIdentity,
        attempt: NativeCaptureCanaryAttempt,
    ) -> bool {
        self.target == target && self.attempt == attempt
    }
}

const fn populate_selector_phase(family: XtablesRestoreFamily) -> NativeXtablesAttemptPhase {
    match family {
        XtablesRestoreFamily::Ipv4 => NativeXtablesAttemptPhase::PopulateSelectorIpv4,
        XtablesRestoreFamily::Ipv6 => NativeXtablesAttemptPhase::PopulateSelectorIpv6,
    }
}

const fn populate_observation_phase(family: XtablesRestoreFamily) -> NativeXtablesAttemptPhase {
    match family {
        XtablesRestoreFamily::Ipv4 => NativeXtablesAttemptPhase::PopulateObservationIpv4,
        XtablesRestoreFamily::Ipv6 => NativeXtablesAttemptPhase::PopulateObservationIpv6,
    }
}

const fn retire_observation_phase(family: XtablesRestoreFamily) -> NativeXtablesAttemptPhase {
    match family {
        XtablesRestoreFamily::Ipv4 => NativeXtablesAttemptPhase::RetireObservationIpv4,
        XtablesRestoreFamily::Ipv6 => NativeXtablesAttemptPhase::RetireObservationIpv6,
    }
}

const fn retire_selector_phase(family: XtablesRestoreFamily) -> NativeXtablesAttemptPhase {
    match family {
        XtablesRestoreFamily::Ipv4 => NativeXtablesAttemptPhase::RetireSelectorIpv4,
        XtablesRestoreFamily::Ipv6 => NativeXtablesAttemptPhase::RetireSelectorIpv6,
    }
}

#[derive(Clone, Copy)]
enum NativeCanaryAttemptProgress {
    PopulatingSelectors(usize),
    PopulatingObservations(usize),
    Active,
    RetiringObservations(usize),
    RetiringSelectors(usize),
}

impl NativeCanaryAttemptProgress {
    const fn selector_is_populated(self, index: usize) -> bool {
        match self {
            Self::PopulatingSelectors(completed) => index < completed,
            Self::PopulatingObservations(_) | Self::Active | Self::RetiringObservations(_) => true,
            Self::RetiringSelectors(completed) => index >= completed,
        }
    }

    const fn observation_is_populated(self, index: usize) -> bool {
        match self {
            Self::PopulatingSelectors(_) => false,
            Self::PopulatingObservations(completed) => index < completed,
            Self::Active => true,
            Self::RetiringObservations(completed) => index >= completed,
            Self::RetiringSelectors(_) => false,
        }
    }
}

fn canary_attempt_phase_progress(
    plans: &[NativeCanaryAttemptFamilyPlan],
    phase: NativeXtablesAttemptPhase,
) -> Result<(NativeCanaryAttemptProgress, NativeCanaryAttemptProgress), NativeXtablesOwnerError> {
    let ipv6_enabled = plans
        .iter()
        .any(|plan| plan.family == XtablesRestoreFamily::Ipv6);
    let ipv6_phase = matches!(
        phase,
        NativeXtablesAttemptPhase::PopulateSelectorIpv6
            | NativeXtablesAttemptPhase::PopulateObservationIpv6
            | NativeXtablesAttemptPhase::RetireObservationIpv6
            | NativeXtablesAttemptPhase::RetireSelectorIpv6
    );
    if ipv6_phase && !ipv6_enabled {
        return Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
            "IPv4-only attempt carries an IPv6 durable phase",
        ));
    }

    Ok(match phase {
        NativeXtablesAttemptPhase::Reserved => (
            NativeCanaryAttemptProgress::PopulatingSelectors(0),
            NativeCanaryAttemptProgress::PopulatingSelectors(0),
        ),
        NativeXtablesAttemptPhase::PopulateSelectorIpv4 => (
            NativeCanaryAttemptProgress::PopulatingSelectors(0),
            NativeCanaryAttemptProgress::PopulatingSelectors(1),
        ),
        NativeXtablesAttemptPhase::PopulateSelectorIpv6 => (
            NativeCanaryAttemptProgress::PopulatingSelectors(1),
            NativeCanaryAttemptProgress::PopulatingSelectors(2),
        ),
        NativeXtablesAttemptPhase::PopulateObservationIpv4 => (
            NativeCanaryAttemptProgress::PopulatingObservations(0),
            NativeCanaryAttemptProgress::PopulatingObservations(1),
        ),
        NativeXtablesAttemptPhase::PopulateObservationIpv6 => (
            NativeCanaryAttemptProgress::PopulatingObservations(1),
            NativeCanaryAttemptProgress::PopulatingObservations(2),
        ),
        NativeXtablesAttemptPhase::Active => (
            NativeCanaryAttemptProgress::Active,
            NativeCanaryAttemptProgress::Active,
        ),
        NativeXtablesAttemptPhase::RetireObservationIpv4 => (
            NativeCanaryAttemptProgress::RetiringObservations(0),
            NativeCanaryAttemptProgress::RetiringObservations(1),
        ),
        NativeXtablesAttemptPhase::RetireObservationIpv6 => (
            NativeCanaryAttemptProgress::RetiringObservations(1),
            NativeCanaryAttemptProgress::RetiringObservations(2),
        ),
        NativeXtablesAttemptPhase::RetireSelectorIpv4 => (
            NativeCanaryAttemptProgress::RetiringSelectors(0),
            NativeCanaryAttemptProgress::RetiringSelectors(1),
        ),
        NativeXtablesAttemptPhase::RetireSelectorIpv6 => (
            NativeCanaryAttemptProgress::RetiringSelectors(1),
            NativeCanaryAttemptProgress::RetiringSelectors(2),
        ),
    })
}

fn canary_attempt_cleanup_candidates(
    plans: &[NativeCanaryAttemptFamilyPlan],
    phase: NativeXtablesAttemptPhase,
) -> Result<Vec<NativeCanaryAttemptProgress>, NativeXtablesOwnerError> {
    let _ = canary_attempt_phase_progress(plans, phase)?;
    let mut candidates = Vec::with_capacity(7);
    match phase {
        NativeXtablesAttemptPhase::RetireObservationIpv4 => {
            candidates
                .extend((0..=plans.len()).map(NativeCanaryAttemptProgress::PopulatingSelectors));
            candidates
                .extend((1..=plans.len()).map(NativeCanaryAttemptProgress::PopulatingObservations));
            candidates.push(NativeCanaryAttemptProgress::RetiringObservations(1));
        }
        NativeXtablesAttemptPhase::RetireObservationIpv6 => {
            candidates
                .extend((0..=plans.len()).map(NativeCanaryAttemptProgress::PopulatingSelectors));
            candidates
                .extend((1..=plans.len()).map(NativeCanaryAttemptProgress::RetiringObservations));
        }
        NativeXtablesAttemptPhase::RetireSelectorIpv4 => {
            candidates
                .extend((0..=plans.len()).map(NativeCanaryAttemptProgress::PopulatingSelectors));
            candidates.push(NativeCanaryAttemptProgress::RetiringSelectors(1));
        }
        NativeXtablesAttemptPhase::RetireSelectorIpv6 => {
            candidates
                .extend((1..=plans.len()).map(NativeCanaryAttemptProgress::RetiringSelectors));
        }
        _ => {
            return Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
                "attempt cleanup validation requires a retirement phase",
            ));
        }
    }
    Ok(candidates)
}

fn canary_attempt_family_state_is_exact(
    target: &NativeXtablesAdmittedTarget,
    plans: &[NativeCanaryAttemptFamilyPlan],
    family: XtablesRestoreFamily,
    observed: &XtablesSaveProjection,
    progress: NativeCanaryAttemptProgress,
) -> Result<bool, NativeXtablesOwnerError> {
    let Some(target_family) = target.topology().family(family) else {
        return Ok(observed.is_empty());
    };
    let (index, plan) = plans
        .iter()
        .enumerate()
        .find(|(_, plan)| plan.family == family)
        .ok_or(NativeXtablesOwnerError::InvalidCanarySelector(
            "an enabled target family has no attempt plan",
        ))?;
    Ok(if progress.observation_is_populated(index) {
        plan.active_attempt_state.is_satisfied_by(observed)
    } else if progress.selector_is_populated(index) {
        plan.selector_state.is_satisfied_by(observed)
    } else {
        target_family.active_state().is_satisfied_by(observed)
    })
}

fn canary_attempt_plans(
    target: &NativeXtablesAdmittedTarget,
    selector: NativeCaptureCanarySelector,
) -> Result<Vec<NativeCanaryAttemptFamilyPlan>, NativeXtablesOwnerError> {
    if target
        .topology()
        .family(XtablesRestoreFamily::Ipv4)
        .is_none()
    {
        return Err(NativeXtablesOwnerError::InvalidCanarySelector(
            "the admitted target has no IPv4 local-OUTPUT family",
        ));
    }
    let target_has_ipv6 = target
        .topology()
        .family(XtablesRestoreFamily::Ipv6)
        .is_some();
    if selector.ipv6_peer().is_some() != target_has_ipv6 {
        return Err(NativeXtablesOwnerError::InvalidCanarySelector(
            "selector address families differ from the admitted target",
        ));
    }

    target
        .topology()
        .families()
        .iter()
        .map(|family_plan| {
            let family = family_plan.family();
            let selector_chain = family_plan.local_output_canary_selector().ok_or(
                NativeXtablesOwnerError::InvalidCanarySelector(
                    "the admitted target has no reserved canary selector chain",
                ),
            )?;
            let observation_chain = family_plan.local_output_canary_observation().ok_or(
                NativeXtablesOwnerError::InvalidCanarySelector(
                    "the admitted target has no reserved canary observation chain",
                ),
            )?;
            let routing = target
                .routing()
                .iter()
                .copied()
                .find(|routing| restore_family(routing.family()) == family)
                .ok_or(NativeXtablesOwnerError::InvalidCanarySelector(
                    "the selector family has no admitted proxy-mark route",
                ))?;
            let (populate_selector, retire_selector) = render_canary_selector_artifacts(
                family,
                selector_chain,
                observation_chain,
                selector,
                routing.rule().mark().value(),
                routing.rule().mark().mask(),
            )?;
            let engine_uid = family_plan.local_output_canary_engine_uid().ok_or(
                NativeXtablesOwnerError::InvalidCanarySelector(
                    "the admitted target has no canary engine identity",
                ),
            )?;
            let (populate_observation, retire_observation) = render_canary_observation_artifacts(
                family,
                observation_chain,
                selector.probe_uid(),
                engine_uid,
                routing.rule().mark().value(),
                routing.rule().mark().mask(),
            )?;
            let selector_state = family_plan
                .active_state()
                .with_owned_chain_replacement(&populate_selector)
                .map_err(NativeXtablesOwnerError::ExpectedState)?;
            let active_attempt_state = selector_state
                .with_owned_chain_replacement(&populate_observation)
                .map_err(NativeXtablesOwnerError::ExpectedState)?;
            Ok(NativeCanaryAttemptFamilyPlan {
                family,
                selector_chain: selector_chain.into(),
                observation_chain: observation_chain.into(),
                populate_selector,
                retire_selector,
                populate_observation,
                retire_observation,
                selector_state,
                active_attempt_state,
            })
        })
        .collect()
}

fn validate_canary_route_query(
    target: &NativeXtablesAdmittedTarget,
    selector: NativeCaptureCanarySelector,
    query: NativeCaptureCanaryRouteQuery,
) -> Result<(), NativeXtablesOwnerError> {
    let destination = query.destination();
    let family = match destination.ip() {
        IpAddr::V4(address) if address == selector.ipv4_peer() => XtablesRestoreFamily::Ipv4,
        IpAddr::V6(address) if Some(address) == selector.ipv6_peer() => XtablesRestoreFamily::Ipv6,
        IpAddr::V4(_) | IpAddr::V6(_) => {
            return Err(NativeXtablesOwnerError::InvalidCanarySelector(
                "route lookup destination differs from the active canary selector",
            ));
        }
    };
    if destination.port() != selector.tcp_echo_port().get() {
        return Err(NativeXtablesOwnerError::InvalidCanarySelector(
            "route lookup must use the selector's TCP echo responder port",
        ));
    }
    let routing = target
        .routing()
        .iter()
        .copied()
        .find(|routing| restore_family(routing.family()) == family)
        .ok_or(NativeXtablesOwnerError::InvalidCanarySelector(
            "route lookup family has no admitted proxy-mark route",
        ))?;
    if query.mark() != routing.rule().mark().value() {
        return Err(NativeXtablesOwnerError::InvalidCanarySelector(
            "route lookup mark differs from the admitted proxy mark",
        ));
    }
    let engine_uid = target
        .topology()
        .family(family)
        .and_then(XtablesStableFamilyPlan::local_output_canary_engine_uid)
        .ok_or(NativeXtablesOwnerError::InvalidCanarySelector(
            "route lookup family has no admitted canary engine identity",
        ))?;
    if query.uid().get() != engine_uid {
        return Err(NativeXtablesOwnerError::InvalidCanarySelector(
            "route lookup UID differs from the admitted canary engine",
        ));
    }
    Ok(())
}

fn render_canary_selector_artifacts(
    family: XtablesRestoreFamily,
    chain: &str,
    observation_chain: &str,
    selector: NativeCaptureCanarySelector,
    proxy_mark: u32,
    proxy_mask: u32,
) -> Result<(XtablesRestoreArtifact, XtablesRestoreArtifact), NativeXtablesOwnerError> {
    let (peer, prefix) = match family {
        XtablesRestoreFamily::Ipv4 => (selector.ipv4_peer().to_string(), 32),
        XtablesRestoreFamily::Ipv6 => (
            selector
                .ipv6_peer()
                .ok_or(NativeXtablesOwnerError::InvalidCanarySelector(
                    "the IPv6 selector peer is absent",
                ))?
                .to_string(),
            128,
        ),
    };
    let mark = format!("0x{proxy_mark:x}/0x{proxy_mask:x}");
    let unmarked = format!("0x0/0x{proxy_mask:x}");
    let mut populate = format!("*mangle\n-F {chain}\n");
    for (protocol, ports) in [
        ("tcp", [selector.tcp_echo_port(), selector.dns_port()]),
        ("udp", [selector.udp_echo_port(), selector.dns_port()]),
    ] {
        for port in ports {
            let exact = format!(
                "-A {chain} -d {peer}/{prefix} -p {protocol} -m owner --uid-owner {} -m {protocol} --dport {}",
                selector.probe_uid(),
                port.get(),
            );
            populate.push_str(&format!(
                "{exact} -m mark --mark {unmarked} -j MARK --set-xmark {mark}\n"
            ));
            populate.push_str(&format!(
                "{exact} -m mark --mark {mark} -j {observation_chain}\n"
            ));
            populate.push_str(&format!("{exact} -m mark --mark {mark} -j ACCEPT\n"));
        }
    }
    populate.push_str("COMMIT\n");
    let context = XtablesRestoreContext::new(XtablesRestoreAction::Replace, family);
    Ok((
        parse_xtables_restore(populate.as_bytes(), context)
            .map_err(NativeXtablesOwnerError::CanarySelectorArtifact)?,
        render_canary_retire_artifact(family, chain)?,
    ))
}

fn render_canary_observation_artifacts(
    family: XtablesRestoreFamily,
    chain: &str,
    probe_uid: NonZeroU32,
    engine_uid: u32,
    proxy_mark: u32,
    proxy_mask: u32,
) -> Result<(XtablesRestoreArtifact, XtablesRestoreArtifact), NativeXtablesOwnerError> {
    let mark = format!("0x{proxy_mark:x}/0x{proxy_mask:x}");
    let populate = format!(
        "*mangle\n\
         -F {chain}\n\
         -A {chain} -m owner --uid-owner {probe_uid} -m mark --mark {mark} -j RETURN\n\
         -A {chain} -m owner --uid-owner {engine_uid} -m mark --mark {mark} -j RETURN\n\
         -A {chain} -m owner --uid-owner {engine_uid} -j RETURN\n\
         COMMIT\n"
    );
    Ok((
        parse_xtables_restore(
            populate.as_bytes(),
            XtablesRestoreContext::new(XtablesRestoreAction::Replace, family),
        )
        .map_err(NativeXtablesOwnerError::CanarySelectorArtifact)?,
        render_canary_retire_artifact(family, chain)?,
    ))
}

fn render_canary_retire_artifact(
    family: XtablesRestoreFamily,
    chain: &str,
) -> Result<XtablesRestoreArtifact, NativeXtablesOwnerError> {
    let retire = format!("*mangle\n-F {chain}\nCOMMIT\n");
    parse_xtables_restore(
        retire.as_bytes(),
        XtablesRestoreContext::new(XtablesRestoreAction::Replace, family),
    )
    .map_err(NativeXtablesOwnerError::CanarySelectorArtifact)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeXtablesConvergedState {
    Active(NativeXtablesTargetIdentity),
    CleanAbsent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesConvergenceReport {
    state: NativeXtablesConvergedState,
    changed: bool,
}

impl NativeXtablesConvergenceReport {
    #[must_use]
    pub(crate) const fn state(self) -> NativeXtablesConvergedState {
        self.state
    }

    #[must_use]
    pub(crate) const fn changed(self) -> bool {
        self.changed
    }
}

#[derive(Debug)]
pub(crate) enum NativeXtablesOwnerError {
    Durable(NativeXtablesDurableError),
    Adapter(NativeXtablesAdapterError),
    InvalidPayload(&'static str),
    TargetResolution {
        identity: NativeXtablesTargetIdentity,
        reason: Box<str>,
    },
    ResolvedTargetMismatch,
    ToolIdentityMismatch,
    LiveStateConflict(&'static str),
    ReplacementIncompatible(&'static str),
    ExpectedState(XtablesSaveProjectionError),
    InvalidCanarySelector(&'static str),
    InvalidCanaryAttempt(&'static str),
    CanarySelectorArtifact(XtablesRestoreParseError),
    AttemptRecoveryRequired,
    RolledBack {
        cause: Box<str>,
        state: NativeXtablesConvergedState,
    },
    Uncertain {
        primary: Box<str>,
        compensation: Box<str>,
    },
}

impl fmt::Display for NativeXtablesOwnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Durable(source) => {
                write!(formatter, "native xtables durable state failed: {source}")
            }
            Self::Adapter(source) => write!(
                formatter,
                "native xtables platform Adapter failed: {source}"
            ),
            Self::InvalidPayload(reason) => {
                write!(formatter, "invalid native owner payload: {reason}")
            }
            Self::TargetResolution { identity, reason } => write!(
                formatter,
                "cannot resolve native generation {}: {reason}",
                identity.generation.get()
            ),
            Self::ResolvedTargetMismatch => formatter
                .write_str("resolved immutable native target does not match its durable identity"),
            Self::ToolIdentityMismatch => formatter
                .write_str("current native xtables tool set does not match the admitted target"),
            Self::LiveStateConflict(reason) => {
                write!(formatter, "native xtables live-state conflict: {reason}")
            }
            Self::ReplacementIncompatible(reason) => {
                write!(
                    formatter,
                    "native xtables replacement is incompatible: {reason}"
                )
            }
            Self::ExpectedState(source) => {
                write!(
                    formatter,
                    "cannot derive native xtables expected state: {source}"
                )
            }
            Self::InvalidCanarySelector(reason) => {
                write!(formatter, "invalid native canary selector: {reason}")
            }
            Self::InvalidCanaryAttempt(reason) => {
                write!(formatter, "invalid native canary attempt: {reason}")
            }
            Self::CanarySelectorArtifact(source) => {
                write!(
                    formatter,
                    "cannot build native canary selector artifact: {source}"
                )
            }
            Self::AttemptRecoveryRequired => formatter.write_str(
                "native xtables attempt recovery must complete before active ownership is available",
            ),
            Self::RolledBack { cause, state } => write!(
                formatter,
                "native xtables convergence failed and rolled back to {state:?}: {cause}"
            ),
            Self::Uncertain {
                primary,
                compensation,
            } => write!(
                formatter,
                "native xtables transaction is uncertain after {primary}; compensation failed: {compensation}"
            ),
        }
    }
}

impl Error for NativeXtablesOwnerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Durable(source) => Some(source),
            Self::Adapter(source) => Some(source),
            Self::ExpectedState(source) => Some(source),
            Self::CanarySelectorArtifact(source) => Some(source),
            _ => None,
        }
    }
}

impl From<NativeXtablesDurableError> for NativeXtablesOwnerError {
    fn from(source: NativeXtablesDurableError) -> Self {
        Self::Durable(source)
    }
}

impl From<NativeXtablesAdapterError> for NativeXtablesOwnerError {
    fn from(source: NativeXtablesAdapterError) -> Self {
        Self::Adapter(source)
    }
}

struct JournalCursor {
    binding: NativeXtablesJournalBinding,
    revision: OwnershipJournalRevision,
    intent: NativeOwnerIntent,
    phase: NativeXtablesJournalPhase,
}

impl JournalCursor {
    fn from_record(record: &NativeXtablesJournalRecord) -> Result<Self, NativeXtablesOwnerError> {
        Ok(Self {
            binding: record.binding().clone(),
            revision: record.revision(),
            intent: NativeOwnerIntent::parse(record.owner_payload())?,
            phase: record.phase(),
        })
    }

    fn record(&self) -> Result<NativeXtablesJournalRecord, NativeXtablesOwnerError> {
        Ok(NativeXtablesJournalRecord::new(
            self.binding.clone(),
            self.revision,
            self.phase,
            self.intent.payload()?,
        ))
    }

    fn next_record(
        &self,
        binding: NativeXtablesJournalBinding,
        phase: NativeXtablesJournalPhase,
        step: NativeOwnerStep,
    ) -> Result<NativeXtablesJournalRecord, NativeXtablesOwnerError> {
        let revision = next_revision(self.revision)?;
        let mut intent = self.intent.clone();
        intent.step = step;
        Ok(NativeXtablesJournalRecord::new(
            binding,
            revision,
            phase,
            intent.payload()?,
        ))
    }

    fn advance(
        &mut self,
        lease: &mut NativeXtablesTransitionLease,
        phase: NativeXtablesJournalPhase,
        step: NativeOwnerStep,
    ) -> Result<(), NativeXtablesOwnerError> {
        let next = self.next_record(self.binding.clone(), phase, step)?;
        lease.update(next.clone())?;
        *self = Self::from_record(&next)?;
        Ok(())
    }

    fn terminal(
        &self,
        intent: NativeOwnerIntent,
    ) -> Result<NativeXtablesJournalRecord, NativeXtablesOwnerError> {
        Ok(NativeXtablesJournalRecord::new(
            self.binding.clone(),
            next_revision(self.revision)?,
            NativeXtablesJournalPhase::CleanAbsent,
            intent.payload()?,
        ))
    }
}

fn next_revision(
    revision: OwnershipJournalRevision,
) -> Result<OwnershipJournalRevision, NativeXtablesOwnerError> {
    revision
        .get()
        .checked_add(1)
        .and_then(OwnershipJournalRevision::new)
        .ok_or(NativeXtablesOwnerError::Durable(
            NativeXtablesDurableError::RevisionExhausted,
        ))
}

/// Deep private transaction owner. Callers can only request a desired target or startup recovery.
pub(crate) struct NativeXtablesOwner<A, R> {
    adapter: A,
    resolver: R,
    durable: NativeXtablesDurableStore,
    environment: NativeXtablesEnvironment,
}

impl<A, R> NativeXtablesOwner<A, R>
where
    A: NativeXtablesOwnerAdapter,
    R: NativeXtablesTargetResolver,
{
    #[must_use]
    pub(crate) const fn new(
        adapter: A,
        resolver: R,
        durable: NativeXtablesDurableStore,
        environment: NativeXtablesEnvironment,
    ) -> Self {
        Self {
            adapter,
            resolver,
            durable,
            environment,
        }
    }

    pub(crate) fn converge(
        &mut self,
        target: NativeXtablesDesiredTarget,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesOwnerError> {
        match target {
            NativeXtablesDesiredTarget::Active(target) => self.converge_active(target),
            NativeXtablesDesiredTarget::Stopped => self.converge_stopped(),
        }
    }

    pub(crate) fn recover(
        &mut self,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesOwnerError> {
        let scope = self.environment.lease_scope();
        match self.durable.inspect_for_recovery(&scope)? {
            NativeXtablesRecoveryInspection::Vacant(fence) => {
                self.require_global_xtables_absence()?;
                self.require_recovery_policy_absence()?;
                fence.finish_clean()?;
                Ok(NativeXtablesConvergenceReport {
                    state: NativeXtablesConvergedState::CleanAbsent,
                    changed: false,
                })
            }
            NativeXtablesRecoveryInspection::CurrentTerminal { record, fence } => {
                self.finish_terminal_recovery(record, fence)
            }
            NativeXtablesRecoveryInspection::CurrentJournal(record) => {
                self.recover_current_journal(record)
            }
            NativeXtablesRecoveryInspection::CurrentAttempt { record, .. } => {
                self.recover_current_journal(record)
            }
        }
    }

    /// Returns one stable descriptor-anchored projection of the exact active owner.
    ///
    /// The durable journal is observed on both sides of live xtables and policy-routing readback.
    /// A transition fence, substituted record, missing lease, or live drift fails closed.
    pub(crate) fn observe_active_ownership(
        &mut self,
    ) -> Result<Option<NativeCaptureOwnershipObservation>, NativeXtablesOwnerError> {
        if self.durable.writer_lock_exists()? {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native ownership observation found an active writer lock",
            ));
        }
        if self.durable.load_attempt()?.is_some() {
            return Err(NativeXtablesOwnerError::AttemptRecoveryRequired);
        }
        let Some(before) = self.durable.observe_journal()? else {
            return Ok(None);
        };
        if before.record().phase() != NativeXtablesJournalPhase::Active {
            return Ok(None);
        }
        let binding = self.expected_binding(before.record().binding())?;
        let lease =
            self.durable
                .load_lease()?
                .ok_or(NativeXtablesOwnerError::LiveStateConflict(
                    "active ownership observation found no durable lease",
                ))?;
        if lease != binding.lease_scope() {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "active ownership observation found a substituted durable lease",
            ));
        }
        let intent = NativeOwnerIntent::parse(before.record().owner_payload())?;
        let identity = intent
            .target
            .ok_or(NativeXtablesOwnerError::InvalidPayload(
                "active ownership observation has no target",
            ))?;
        if intent.step != NativeOwnerStep::PublishActive
            || intent.previous.is_some()
            || identity.generation() != binding.generation()
        {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "active ownership observation found a substituted target or Generation",
            ));
        }
        let target = self.resolve_target(identity)?;
        if !self.target_is_exact_active(&target)? {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "active ownership observation did not match exact live state",
            ));
        }
        if self.durable.writer_lock_exists()? {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native ownership changed during active readback",
            ));
        }
        let after =
            self.durable
                .observe_journal()?
                .ok_or(NativeXtablesOwnerError::LiveStateConflict(
                    "native ownership journal disappeared during active readback",
                ))?;
        if before != after {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native ownership journal changed during active readback",
            ));
        }
        if self.durable.load_lease()?.as_ref() != Some(&lease) {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native ownership lease changed during active readback",
            ));
        }
        if self.durable.load_attempt()?.is_some() {
            return Err(NativeXtablesOwnerError::AttemptRecoveryRequired);
        }
        Ok(Some(public_ownership_observation(before, &target)))
    }

    fn populate_canary_selector(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        attempt: NativeCaptureCanaryAttempt,
    ) -> Result<NativeXtablesAttemptSession, NativeXtablesOwnerError> {
        let plans = canary_attempt_plans(target, attempt.selector())?;
        let (mut lease, primary) =
            self.begin_canary_transition(target, NativeOwnerStep::PublishActive)?;
        self.require_canary_attempt_state(
            target,
            &plans,
            NativeCanaryAttemptProgress::PopulatingSelectors(0),
        )?;
        self.require_policy_exact(target)?;
        let record = NativeXtablesAttemptRecord::new(
            primary.binding().clone(),
            NativeXtablesAttemptPhase::Reserved,
            NativeCanaryAttemptBinding::new(attempt).payload()?,
        );
        lease.publish_attempt(record.clone())?;
        let mut session = NativeXtablesAttemptSession {
            lease,
            record,
            target: target.identity(),
            attempt,
            primary,
        };

        if let Err(primary) = self.populate_canary_attempt_objects(target, &plans, &mut session) {
            let cause = primary.to_string();
            return match self.normalize_canary_attempt(target, &plans, &mut session) {
                Ok(()) => Err(NativeXtablesOwnerError::RolledBack {
                    cause: cause.into_boxed_str(),
                    state: NativeXtablesConvergedState::Active(target.identity()),
                }),
                Err(compensation) => Err(NativeXtablesOwnerError::Uncertain {
                    primary: cause.into_boxed_str(),
                    compensation: compensation.to_string().into_boxed_str(),
                }),
            };
        }
        Ok(session)
    }

    fn retire_canary_selector(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        attempt: NativeCaptureCanaryAttempt,
        mut session: NativeXtablesAttemptSession,
    ) -> Result<(), NativeXtablesOwnerError> {
        let plans = canary_attempt_plans(target, attempt.selector())?;
        let terminal_observation_phase = plans
            .last()
            .map(|plan| retire_observation_phase(plan.family))
            .ok_or(NativeXtablesOwnerError::InvalidCanarySelector(
                "canary attempt has no enabled family",
            ))?;
        let observations_retired = if session.record.phase() == NativeXtablesAttemptPhase::Active {
            self.require_canary_attempt_session(
                target,
                attempt,
                &plans,
                &session,
                NativeXtablesAttemptPhase::Active,
                NativeCanaryAttemptProgress::Active,
            )?;
            false
        } else if session.record.phase() == terminal_observation_phase {
            self.require_canary_attempt_session(
                target,
                attempt,
                &plans,
                &session,
                terminal_observation_phase,
                NativeCanaryAttemptProgress::RetiringObservations(plans.len()),
            )?;
            true
        } else {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native canary retirement found an invalid retained attempt phase",
            ));
        };

        let retirement = if observations_retired {
            self.retire_canary_selector_objects(target, &plans, &mut session)
        } else {
            self.retire_canary_attempt_objects(target, &plans, &mut session)
        };
        if let Err(primary) = retirement {
            let cause = primary.to_string();
            return match self.normalize_canary_attempt(target, &plans, &mut session) {
                Ok(()) => Err(NativeXtablesOwnerError::RolledBack {
                    cause: cause.into_boxed_str(),
                    state: NativeXtablesConvergedState::Active(target.identity()),
                }),
                Err(compensation) => Err(NativeXtablesOwnerError::Uncertain {
                    primary: cause.into_boxed_str(),
                    compensation: compensation.to_string().into_boxed_str(),
                }),
            };
        }
        self.finish_canary_attempt(target, &plans, &mut session)?;
        Ok(())
    }

    /// Retire only the counted observation chains while retaining selector and recovery authority.
    fn retire_canary_counters(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        attempt: NativeCaptureCanaryAttempt,
        deadline: Instant,
        session: &mut NativeXtablesAttemptSession,
    ) -> Result<NativeCaptureCanaryCounterRetirement, NativeXtablesOwnerError> {
        let plans = canary_attempt_plans(target, attempt.selector())?;
        if Instant::now() >= deadline {
            return Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
                "counter retirement started at or after the immutable canary deadline",
            ));
        }
        self.require_canary_attempt_session(
            target,
            attempt,
            &plans,
            session,
            NativeXtablesAttemptPhase::Active,
            NativeCanaryAttemptProgress::Active,
        )?;

        let retirement = (|| {
            self.retire_canary_observation_objects(target, &plans, session, Some(deadline))?;
            let retired_at = Instant::now();
            let terminal_phase = plans
                .last()
                .map(|plan| retire_observation_phase(plan.family))
                .ok_or(NativeXtablesOwnerError::InvalidCanarySelector(
                    "canary attempt has no enabled family",
                ))?;
            self.require_canary_attempt_session(
                target,
                attempt,
                &plans,
                session,
                terminal_phase,
                NativeCanaryAttemptProgress::RetiringObservations(plans.len()),
            )?;
            let absent_observed_at = Instant::now();
            if absent_observed_at >= deadline {
                return Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
                    "counter retirement completed at or after the immutable canary deadline",
                ));
            }
            Ok(NativeCaptureCanaryCounterRetirement::new(
                retired_at,
                absent_observed_at,
            ))
        })();
        match retirement {
            Ok(retirement) => Ok(retirement),
            Err(primary) => {
                let cause = primary.to_string();
                match self.normalize_canary_attempt(target, &plans, session) {
                    Ok(()) => Err(NativeXtablesOwnerError::RolledBack {
                        cause: cause.into_boxed_str(),
                        state: NativeXtablesConvergedState::Active(target.identity()),
                    }),
                    Err(compensation) => Err(NativeXtablesOwnerError::Uncertain {
                        primary: cause.into_boxed_str(),
                        compensation: compensation.to_string().into_boxed_str(),
                    }),
                }
            }
        }
    }

    /// Resolve one fixed-purpose TCP route while the exact selector and native target remain
    /// stable. A definite kernel rejection is returned as data; any ambiguous Adapter or
    /// surrounding readback failure leaves recovery to the serialized runtime writer.
    fn observe_canary_route(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        attempt: NativeCaptureCanaryAttempt,
        query: NativeCaptureCanaryRouteQuery,
        session: &NativeXtablesAttemptSession,
    ) -> Result<NativeCaptureCanaryRouteOutcome, NativeXtablesOwnerError> {
        let plans = canary_attempt_plans(target, attempt.selector())?;
        self.require_canary_attempt_session(
            target,
            attempt,
            &plans,
            session,
            NativeXtablesAttemptPhase::Active,
            NativeCanaryAttemptProgress::Active,
        )?;
        validate_canary_route_query(target, attempt.selector(), query)?;

        let outcome = self.adapter.observe_canary_route(query)?;

        self.require_canary_attempt_session(
            target,
            attempt,
            &plans,
            session,
            NativeXtablesAttemptPhase::Active,
            NativeCanaryAttemptProgress::Active,
        )?;
        Ok(outcome)
    }

    /// Read and aggregate the active attempt's exact per-family observation chains.
    fn observe_canary_counters(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        attempt: NativeCaptureCanaryAttempt,
        deadline: Instant,
        session: &NativeXtablesAttemptSession,
    ) -> Result<NativeCaptureCanaryCounterSnapshot, NativeXtablesOwnerError> {
        let plans = canary_attempt_plans(target, attempt.selector())?;
        if Instant::now() >= deadline {
            return Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
                "counter observation started at or after the immutable canary deadline",
            ));
        }
        self.require_canary_attempt_session(
            target,
            attempt,
            &plans,
            session,
            NativeXtablesAttemptPhase::Active,
            NativeCanaryAttemptProgress::Active,
        )?;

        let mut capture_packets = 0_u64;
        let mut bypass_packets = 0_u64;
        let mut recapture_packets = 0_u64;
        for plan in &plans {
            if Instant::now() >= deadline {
                return Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
                    "counter observation reached the immutable canary deadline",
                ));
            }
            let counters = self.adapter.observe_canary_counters(
                plan.family,
                &plan.active_attempt_state,
                &plan.observation_chain,
            )?;
            capture_packets = capture_packets
                .checked_add(counters.capture_packets())
                .ok_or(NativeXtablesOwnerError::InvalidCanaryAttempt(
                    "canary capture counter aggregation overflowed",
                ))?;
            bypass_packets = bypass_packets
                .checked_add(counters.bypass_packets())
                .ok_or(NativeXtablesOwnerError::InvalidCanaryAttempt(
                    "canary bypass counter aggregation overflowed",
                ))?;
            recapture_packets = recapture_packets
                .checked_add(counters.recapture_packets())
                .ok_or(NativeXtablesOwnerError::InvalidCanaryAttempt(
                    "canary recapture counter aggregation overflowed",
                ))?;
        }

        self.require_canary_attempt_session(
            target,
            attempt,
            &plans,
            session,
            NativeXtablesAttemptPhase::Active,
            NativeCanaryAttemptProgress::Active,
        )?;
        let observed_at = Instant::now();
        if observed_at >= deadline {
            return Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
                "counter observation completed at or after the immutable canary deadline",
            ));
        }
        Ok(NativeCaptureCanaryCounterSnapshot::new(
            capture_packets,
            bypass_packets,
            recapture_packets,
            observed_at,
        ))
    }

    fn begin_canary_transition(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        expected_step: NativeOwnerStep,
    ) -> Result<(NativeXtablesTransitionLease, NativeXtablesJournalRecord), NativeXtablesOwnerError>
    {
        if target.routing_audit() != self.environment.routing_audit() {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "canary target routing audit differs from the recovery environment",
            ));
        }
        self.require_tool_identity(target)?;
        let record =
            self.durable
                .load_journal()?
                .ok_or(NativeXtablesOwnerError::LiveStateConflict(
                    "canary selector mutation found no active journal",
                ))?;
        let intent = NativeOwnerIntent::parse(record.owner_payload())?;
        if record.phase() != NativeXtablesJournalPhase::Active
            || intent.step != expected_step
            || intent.target != Some(target.identity())
            || intent.previous.is_some()
        {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "canary selector mutation found a different active owner state",
            ));
        }
        let expected = self.expected_binding(record.binding())?;
        let NativeXtablesRecovery::Leased(lease) = self.durable.recover(&expected)? else {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "canary selector mutation found no durable transition lease",
            ));
        };
        let guarded = self.guarded_journal(lease.binding())?;
        let guarded_intent = NativeOwnerIntent::parse(guarded.owner_payload())?;
        if guarded.phase() != NativeXtablesJournalPhase::Active
            || guarded_intent.step != expected_step
            || guarded_intent.target != Some(target.identity())
            || guarded_intent.previous.is_some()
        {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "canary selector owner changed while acquiring the writer fence",
            ));
        }
        Ok((lease, guarded))
    }

    fn populate_canary_attempt_objects(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        plans: &[NativeCanaryAttemptFamilyPlan],
        session: &mut NativeXtablesAttemptSession,
    ) -> Result<(), NativeXtablesOwnerError> {
        for (index, plan) in plans.iter().enumerate() {
            self.advance_canary_attempt(plans, session, populate_selector_phase(plan.family))?;
            self.apply_canary_attempt_artifact(
                target,
                plans,
                plan.family,
                &plan.populate_selector,
                NativeCanaryAttemptProgress::PopulatingSelectors(index + 1),
            )?;
        }
        for (index, plan) in plans.iter().enumerate() {
            self.advance_canary_attempt(plans, session, populate_observation_phase(plan.family))?;
            self.apply_canary_attempt_artifact(
                target,
                plans,
                plan.family,
                &plan.populate_observation,
                NativeCanaryAttemptProgress::PopulatingObservations(index + 1),
            )?;
        }
        self.require_policy_exact(target)?;
        self.advance_canary_attempt(plans, session, NativeXtablesAttemptPhase::Active)?;
        self.require_canary_attempt_session(
            target,
            session.attempt,
            plans,
            session,
            NativeXtablesAttemptPhase::Active,
            NativeCanaryAttemptProgress::Active,
        )
    }

    fn retire_canary_attempt_objects(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        plans: &[NativeCanaryAttemptFamilyPlan],
        session: &mut NativeXtablesAttemptSession,
    ) -> Result<(), NativeXtablesOwnerError> {
        self.retire_canary_observation_objects(target, plans, session, None)?;
        self.retire_canary_selector_objects(target, plans, session)
    }

    fn retire_canary_observation_objects(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        plans: &[NativeCanaryAttemptFamilyPlan],
        session: &mut NativeXtablesAttemptSession,
        deadline: Option<Instant>,
    ) -> Result<(), NativeXtablesOwnerError> {
        for (index, plan) in plans.iter().enumerate() {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(NativeXtablesOwnerError::InvalidCanaryAttempt(
                    "counter retirement reached the immutable canary deadline",
                ));
            }
            self.advance_canary_attempt(plans, session, retire_observation_phase(plan.family))?;
            self.apply_canary_attempt_artifact(
                target,
                plans,
                plan.family,
                &plan.retire_observation,
                NativeCanaryAttemptProgress::RetiringObservations(index + 1),
            )?;
        }
        Ok(())
    }

    fn retire_canary_selector_objects(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        plans: &[NativeCanaryAttemptFamilyPlan],
        session: &mut NativeXtablesAttemptSession,
    ) -> Result<(), NativeXtablesOwnerError> {
        for (index, plan) in plans.iter().enumerate() {
            self.advance_canary_attempt(plans, session, retire_selector_phase(plan.family))?;
            self.apply_canary_attempt_artifact(
                target,
                plans,
                plan.family,
                &plan.retire_selector,
                NativeCanaryAttemptProgress::RetiringSelectors(index + 1),
            )?;
        }
        Ok(())
    }

    fn apply_canary_attempt_artifact(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        plans: &[NativeCanaryAttemptFamilyPlan],
        family: XtablesRestoreFamily,
        artifact: &XtablesRestoreArtifact,
        progress: NativeCanaryAttemptProgress,
    ) -> Result<(), NativeXtablesOwnerError> {
        if let Err(error) = self.adapter.restore(family, artifact)
            && error.certainty() != NativeMutationCertainty::MayHaveMutated
        {
            return Err(error.into());
        }
        self.require_canary_attempt_state(target, plans, progress)
    }

    fn advance_canary_attempt(
        &mut self,
        plans: &[NativeCanaryAttemptFamilyPlan],
        session: &mut NativeXtablesAttemptSession,
        phase: NativeXtablesAttemptPhase,
    ) -> Result<(), NativeXtablesOwnerError> {
        let _ = canary_attempt_phase_progress(plans, phase)?;
        let next = NativeXtablesAttemptRecord::new(
            session.record.binding().clone(),
            phase,
            session.record.payload().clone(),
        );
        session
            .lease
            .update_attempt(&session.record, next.clone())?;
        session.record = next;
        Ok(())
    }

    fn start_canary_attempt_recovery(
        &mut self,
        session: &mut NativeXtablesAttemptSession,
    ) -> Result<(), NativeXtablesOwnerError> {
        let next = NativeXtablesAttemptRecord::new(
            session.record.binding().clone(),
            NativeXtablesAttemptPhase::RetireObservationIpv4,
            session.record.payload().clone(),
        );
        session
            .lease
            .start_attempt_recovery(&session.record, next.clone())?;
        session.record = next;
        Ok(())
    }

    fn require_canary_attempt_state(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        plans: &[NativeCanaryAttemptFamilyPlan],
        progress: NativeCanaryAttemptProgress,
    ) -> Result<(), NativeXtablesOwnerError> {
        for family in ALL_XTABLES_FAMILIES {
            let observed = self.adapter.observe_xtables(family)?;
            if !canary_attempt_family_state_is_exact(target, plans, family, &observed, progress)? {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "canary attempt readback did not match the exact transaction state",
                ));
            }
        }
        Ok(())
    }

    fn require_canary_attempt_session(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        attempt: NativeCaptureCanaryAttempt,
        plans: &[NativeCanaryAttemptFamilyPlan],
        session: &NativeXtablesAttemptSession,
        phase: NativeXtablesAttemptPhase,
        progress: NativeCanaryAttemptProgress,
    ) -> Result<(), NativeXtablesOwnerError> {
        if !session.matches(target.identity(), attempt) {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native canary attempt session was substituted",
            ));
        }
        if session.record.phase() != phase {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native canary attempt is not at the required durable phase",
            ));
        }
        self.require_canary_attempt_record(target, attempt, session)?;
        self.require_canary_attempt_state(target, plans, progress)?;
        self.require_policy_exact(target)
    }

    fn require_canary_attempt_record(
        &self,
        target: &NativeXtablesAdmittedTarget,
        attempt: NativeCaptureCanaryAttempt,
        session: &NativeXtablesAttemptSession,
    ) -> Result<(), NativeXtablesOwnerError> {
        if session.record.binding() != session.primary.binding()
            || session.record.binding() != session.lease.binding()
            || session.record.binding().generation() != target.identity().generation()
        {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native canary attempt binding differs from the active owner",
            ));
        }
        if NativeCanaryAttemptBinding::parse(session.record.payload())?.attempt != attempt {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native canary attempt payload was substituted",
            ));
        }
        let actual =
            self.durable
                .load_attempt()?
                .ok_or(NativeXtablesOwnerError::LiveStateConflict(
                    "native canary attempt sidecar disappeared",
                ))?;
        if actual != session.record {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native canary attempt sidecar changed",
            ));
        }
        let primary = self.guarded_journal(session.lease.binding())?;
        let intent = NativeOwnerIntent::parse(primary.owner_payload())?;
        if primary != session.primary
            || primary.phase() != NativeXtablesJournalPhase::Active
            || intent.step != NativeOwnerStep::PublishActive
            || intent.target != Some(target.identity())
            || intent.previous.is_some()
        {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native canary attempt primary owner changed",
            ));
        }
        Ok(())
    }

    fn normalize_canary_attempt(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        plans: &[NativeCanaryAttemptFamilyPlan],
        session: &mut NativeXtablesAttemptSession,
    ) -> Result<(), NativeXtablesOwnerError> {
        self.require_canary_attempt_record(target, session.attempt, session)?;
        self.require_canary_attempt_phase(plans, session.record.phase())?;
        if session.record.phase().rank() < NativeXtablesAttemptPhase::RetireObservationIpv4.rank() {
            self.require_canary_attempt_recovery_state(target, plans, session.record.phase())?;
        } else {
            self.require_canary_attempt_normalizable(target, plans, session.record.phase())?;
        }
        self.require_policy_exact(target)?;

        if session.record.phase().rank() < NativeXtablesAttemptPhase::RetireObservationIpv4.rank() {
            self.start_canary_attempt_recovery(session)?;
        }
        for plan in plans {
            let phase = retire_observation_phase(plan.family);
            if session.record.phase().rank() < phase.rank() {
                self.advance_canary_attempt(plans, session, phase)?;
            }
            self.flush_canary_attempt_chain(
                plan.family,
                &plan.observation_chain,
                &plan.retire_observation,
            )?;
        }
        for plan in plans {
            let phase = retire_selector_phase(plan.family);
            if session.record.phase().rank() < phase.rank() {
                self.advance_canary_attempt(plans, session, phase)?;
            }
            self.flush_canary_attempt_chain(
                plan.family,
                &plan.selector_chain,
                &plan.retire_selector,
            )?;
        }
        self.finish_canary_attempt(target, plans, session)
    }

    fn require_canary_attempt_phase(
        &self,
        plans: &[NativeCanaryAttemptFamilyPlan],
        phase: NativeXtablesAttemptPhase,
    ) -> Result<(), NativeXtablesOwnerError> {
        let _ = canary_attempt_phase_progress(plans, phase)?;
        Ok(())
    }

    fn require_canary_attempt_recovery_state(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        plans: &[NativeCanaryAttemptFamilyPlan],
        phase: NativeXtablesAttemptPhase,
    ) -> Result<(), NativeXtablesOwnerError> {
        let (before, after) = canary_attempt_phase_progress(plans, phase)?;
        let mut before_exact = true;
        let mut after_exact = true;
        for family in ALL_XTABLES_FAMILIES {
            let observed = self.adapter.observe_xtables(family)?;
            before_exact &=
                canary_attempt_family_state_is_exact(target, plans, family, &observed, before)?;
            after_exact &=
                canary_attempt_family_state_is_exact(target, plans, family, &observed, after)?;
        }
        if !before_exact && !after_exact {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "canary recovery state does not match the durable phase boundary",
            ));
        }
        Ok(())
    }

    fn require_canary_attempt_normalizable(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        plans: &[NativeCanaryAttemptFamilyPlan],
        phase: NativeXtablesAttemptPhase,
    ) -> Result<(), NativeXtablesOwnerError> {
        let candidates = canary_attempt_cleanup_candidates(plans, phase)?;
        let mut observations = Vec::with_capacity(ALL_XTABLES_FAMILIES.len());
        for family in ALL_XTABLES_FAMILIES {
            observations.push((family, self.adapter.observe_xtables(family)?));
        }
        'candidate: for progress in candidates {
            for (family, observed) in &observations {
                if !canary_attempt_family_state_is_exact(
                    target, plans, *family, observed, progress,
                )? {
                    continue 'candidate;
                }
            }
            return Ok(());
        }
        Err(NativeXtablesOwnerError::LiveStateConflict(
            "canary recovery state is not reachable at the durable cleanup phase",
        ))
    }

    fn flush_canary_attempt_chain(
        &mut self,
        family: XtablesRestoreFamily,
        chain: &str,
        retire: &XtablesRestoreArtifact,
    ) -> Result<(), NativeXtablesOwnerError> {
        let observed = self.adapter.observe_xtables(family)?;
        let dirty = !observed
            .chain(chain)
            .ok_or(NativeXtablesOwnerError::LiveStateConflict(
                "canary recovery lost an exact attempt chain",
            ))?
            .rules()
            .is_empty();
        if !dirty {
            return Ok(());
        }
        if let Err(error) = self.adapter.restore(family, retire) {
            let normalized = self
                .adapter
                .observe_xtables(family)?
                .chain(chain)
                .is_some_and(|chain| chain.rules().is_empty());
            if error.certainty() != NativeMutationCertainty::MayHaveMutated || !normalized {
                return Err(error.into());
            }
        }
        let absent = self
            .adapter
            .observe_xtables(family)?
            .chain(chain)
            .is_some_and(|chain| chain.rules().is_empty());
        if !absent {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "canary recovery did not prove exact attempt-chain absence",
            ));
        }
        Ok(())
    }

    fn finish_canary_attempt(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
        plans: &[NativeCanaryAttemptFamilyPlan],
        session: &mut NativeXtablesAttemptSession,
    ) -> Result<(), NativeXtablesOwnerError> {
        let terminal_phase = plans
            .last()
            .map(|plan| retire_selector_phase(plan.family))
            .ok_or(NativeXtablesOwnerError::InvalidCanarySelector(
                "canary attempt has no enabled family",
            ))?;
        self.require_canary_attempt_session(
            target,
            session.attempt,
            plans,
            session,
            terminal_phase,
            NativeCanaryAttemptProgress::RetiringSelectors(plans.len()),
        )?;
        session.lease.remove_attempt(&session.record)?;
        if self.durable.load_attempt()?.is_some() {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native canary attempt sidecar remained after retirement",
            ));
        }
        if self.guarded_journal(session.lease.binding())? != session.primary {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "native canary primary owner changed during retirement",
            ));
        }
        self.require_active_state(&[target], target)?;
        self.require_policy_exact(target)
    }

    fn recover_current_journal(
        &mut self,
        record: NativeXtablesJournalRecord,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesOwnerError> {
        let expected = self.expected_binding(record.binding())?;
        match self.durable.recover(&expected)? {
            NativeXtablesRecovery::Empty => self.recover(),
            NativeXtablesRecovery::CleanAbsent { record, fence } => {
                self.finish_terminal_recovery(record, *fence)
            }
            NativeXtablesRecovery::Leased(lease) => {
                let guarded = self.guarded_journal(lease.binding())?;
                if guarded != record {
                    return Err(NativeXtablesOwnerError::LiveStateConflict(
                        "native owner journal changed while acquiring recovery authority",
                    ));
                }
                let guarded_intent = NativeOwnerIntent::parse(guarded.owner_payload())?;
                let cursor = JournalCursor::from_record(&guarded)?;
                let targets = self.resolve_intent_targets(&guarded_intent)?;
                if guarded.phase() == NativeXtablesJournalPhase::Active
                    && guarded_intent.step == NativeOwnerStep::PublishActive
                    && targets.len() == 1
                    && guarded_intent.target == Some(targets[0].identity())
                    && self.target_is_exact_active(&targets[0])?
                {
                    return Ok(NativeXtablesConvergenceReport {
                        state: NativeXtablesConvergedState::Active(targets[0].identity()),
                        changed: false,
                    });
                }
                self.recover_to_clean_absence(lease, cursor, &targets)
            }
            NativeXtablesRecovery::OutstandingAttempt {
                lease,
                record: attempt_record,
            } => {
                let guarded = self.guarded_journal(lease.binding())?;
                if guarded != record {
                    return Err(NativeXtablesOwnerError::LiveStateConflict(
                        "native owner journal changed while acquiring attempt recovery authority",
                    ));
                }
                let intent = NativeOwnerIntent::parse(guarded.owner_payload())?;
                if guarded.phase() != NativeXtablesJournalPhase::Active
                    || intent.step != NativeOwnerStep::PublishActive
                    || intent.previous.is_some()
                {
                    return Err(NativeXtablesOwnerError::LiveStateConflict(
                        "outstanding canary attempt has no unchanged active primary owner",
                    ));
                }
                let identity = intent
                    .target
                    .ok_or(NativeXtablesOwnerError::InvalidPayload(
                        "outstanding canary attempt primary owner has no target",
                    ))?;
                let target = self.resolve_target(identity)?;
                let attempt = NativeCanaryAttemptBinding::parse(attempt_record.payload())?.attempt;
                let plans = canary_attempt_plans(&target, attempt.selector())?;
                self.require_canary_attempt_phase(&plans, attempt_record.phase())?;
                let mut session = NativeXtablesAttemptSession {
                    lease,
                    record: attempt_record,
                    target: identity,
                    attempt,
                    primary: guarded,
                };
                self.normalize_canary_attempt(&target, &plans, &mut session)?;
                Ok(NativeXtablesConvergenceReport {
                    state: NativeXtablesConvergedState::Active(identity),
                    changed: true,
                })
            }
        }
    }

    fn finish_terminal_recovery(
        &mut self,
        record: NativeXtablesJournalRecord,
        fence: NativeXtablesRecoveryFence,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesOwnerError> {
        let intent = NativeOwnerIntent::parse(record.owner_payload())?;
        let _targets = self.resolve_intent_targets(&intent)?;
        self.require_global_xtables_absence()?;
        self.require_recovery_policy_absence()?;
        fence.finish_clean()?;
        Ok(NativeXtablesConvergenceReport {
            state: NativeXtablesConvergedState::CleanAbsent,
            changed: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn into_parts(self) -> (A, R, NativeXtablesDurableStore) {
        (self.adapter, self.resolver, self.durable)
    }

    fn converge_active(
        &mut self,
        target: NativeXtablesAdmittedTarget,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesOwnerError> {
        if target.routing_audit() != self.environment.routing_audit() {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "desired target routing audit differs from the recovery environment",
            ));
        }
        self.require_tool_identity(&target)?;
        let journal = self.durable.load_journal()?;
        let Some(record) = journal else {
            return self.activate_from_zero(target);
        };
        let intent = NativeOwnerIntent::parse(record.owner_payload())?;
        if record.phase() == NativeXtablesJournalPhase::CleanAbsent {
            self.recover()?;
            return self.converge_active(target);
        }
        if record.phase() != NativeXtablesJournalPhase::Active {
            self.recover()?;
            return self.converge_active(target);
        }

        let current_identity = intent
            .target
            .ok_or(NativeXtablesOwnerError::InvalidPayload(
                "active journal has no target",
            ))?;
        let current = self.resolve_target(current_identity)?;
        let expected = self.expected_binding(record.binding())?;
        let NativeXtablesRecovery::Leased(mut lease) = self.durable.recover(&expected)? else {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "active journal has no durable transition lease",
            ));
        };
        let guarded = self.guarded_journal(lease.binding())?;
        if guarded.phase() != NativeXtablesJournalPhase::Active {
            drop(lease);
            return self.recover();
        }
        let guarded_intent = NativeOwnerIntent::parse(guarded.owner_payload())?;
        let guarded_identity =
            guarded_intent
                .target
                .ok_or(NativeXtablesOwnerError::InvalidPayload(
                    "active journal has no guarded target",
                ))?;
        if guarded_identity != current.identity() {
            drop(lease);
            return self.converge_active(target);
        }
        let mut cursor = JournalCursor::from_record(&guarded)?;
        if current.identity() == target.identity() {
            if self.target_is_exact_active(&current)? {
                return Ok(NativeXtablesConvergenceReport {
                    state: NativeXtablesConvergedState::Active(target.identity()),
                    changed: false,
                });
            }
            return self.fail_uncertain(
                &mut lease,
                &mut cursor,
                "idempotent active readback did not match the durable target",
                "no compensation attempted for an unexplained active-state drift",
            );
        }
        self.replace_active(lease, cursor, current, target)
    }

    fn converge_stopped(
        &mut self,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesOwnerError> {
        let Some(record) = self.durable.load_journal()? else {
            return self.recover();
        };
        if record.phase() != NativeXtablesJournalPhase::Active {
            return self.recover();
        }
        let intent = NativeOwnerIntent::parse(record.owner_payload())?;
        let identity = intent
            .target
            .ok_or(NativeXtablesOwnerError::InvalidPayload(
                "active journal has no target",
            ))?;
        let target = self.resolve_target(identity)?;
        let expected = self.expected_binding(record.binding())?;
        let NativeXtablesRecovery::Leased(mut lease) = self.durable.recover(&expected)? else {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "active journal has no durable transition lease",
            ));
        };
        let guarded = self.guarded_journal(lease.binding())?;
        if guarded.phase() != NativeXtablesJournalPhase::Active {
            drop(lease);
            return self.recover();
        }
        let guarded_intent = NativeOwnerIntent::parse(guarded.owner_payload())?;
        let guarded_identity =
            guarded_intent
                .target
                .ok_or(NativeXtablesOwnerError::InvalidPayload(
                    "active journal has no guarded target",
                ))?;
        if guarded_identity != target.identity() {
            drop(lease);
            return self.converge_stopped();
        }
        let mut cursor = JournalCursor::from_record(&guarded)?;
        cursor.intent = NativeOwnerIntent {
            step: NativeOwnerStep::Begin,
            target: None,
            previous: Some(target.identity()),
        };
        cursor.advance(
            &mut lease,
            NativeXtablesJournalPhase::Retiring,
            NativeOwnerStep::Begin,
        )?;
        match self.cleanup_targets(&mut lease, &mut cursor, std::slice::from_ref(&target)) {
            Ok(()) => self.complete_clean_absence(lease, cursor, Some(target.identity()), true),
            Err(error) => self.fail_uncertain(
                &mut lease,
                &mut cursor,
                "stop cleanup failed",
                &error.to_string(),
            ),
        }
    }

    fn activate_from_zero(
        &mut self,
        target: NativeXtablesAdmittedTarget,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesOwnerError> {
        self.require_clean_absence(std::slice::from_ref(&target))?;
        let binding = self.environment.binding(target.identity().generation());
        let intent = NativeOwnerIntent {
            step: NativeOwnerStep::Begin,
            target: Some(target.identity()),
            previous: None,
        };
        let initial = NativeXtablesJournalRecord::new(
            binding,
            OwnershipJournalRevision::INITIAL,
            NativeXtablesJournalPhase::Activating,
            intent.payload()?,
        );
        let mut lease = self.durable.acquire(initial.clone())?;
        let mut cursor = JournalCursor::from_record(&initial)?;
        if let Err(conflict) = self.require_clean_absence(std::slice::from_ref(&target)) {
            return self.fail_uncertain(
                &mut lease,
                &mut cursor,
                "live state changed while the transition fence was being acquired",
                &conflict.to_string(),
            );
        }
        let activation = self.install_target(&mut lease, &mut cursor, &target);
        if let Err(primary) = activation {
            return match self.cleanup_targets(
                &mut lease,
                &mut cursor,
                std::slice::from_ref(&target),
            ) {
                Ok(()) => {
                    let report =
                        self.complete_clean_absence(lease, cursor, Some(target.identity()), true)?;
                    Err(NativeXtablesOwnerError::RolledBack {
                        cause: primary.to_string().into_boxed_str(),
                        state: report.state,
                    })
                }
                Err(compensation) => self.fail_uncertain(
                    &mut lease,
                    &mut cursor,
                    &primary.to_string(),
                    &compensation.to_string(),
                ),
            };
        }
        cursor.advance(
            &mut lease,
            NativeXtablesJournalPhase::Active,
            NativeOwnerStep::PublishActive,
        )?;
        Ok(NativeXtablesConvergenceReport {
            state: NativeXtablesConvergedState::Active(target.identity()),
            changed: true,
        })
    }

    fn install_target(
        &mut self,
        lease: &mut NativeXtablesTransitionLease,
        cursor: &mut JournalCursor,
        target: &NativeXtablesAdmittedTarget,
    ) -> Result<(), NativeXtablesOwnerError> {
        for family in target.topology().families() {
            cursor.advance(
                lease,
                NativeXtablesJournalPhase::Activating,
                prepare_step(family.family()),
            )?;
            self.adapter.restore(family.family(), family.prepare())?;
        }
        self.require_prepared_state(&[target], None)?;

        for routing in target.routing().iter().copied() {
            let observed = self.observe_policy_routing(routing)?;
            if !observed.absent() {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "unowned policy-routing state occupied the admitted identity",
                ));
            }
            cursor.advance(
                lease,
                NativeXtablesJournalPhase::Activating,
                route_add_step(routing.family()),
            )?;
            self.mutate_policy_routing(routing, PolicyRoutingMutation::AddRoute(routing.route()))?;
            cursor.advance(
                lease,
                NativeXtablesJournalPhase::Activating,
                rule_add_step(routing.family()),
            )?;
            self.mutate_policy_routing(routing, PolicyRoutingMutation::AddRule(routing.rule()))?;
        }
        self.require_policy_exact(target)?;

        for family in target.topology().families() {
            cursor.advance(
                lease,
                NativeXtablesJournalPhase::Activating,
                attach_step(family.family()),
            )?;
            self.adapter.restore(family.family(), family.install())?;
        }
        self.require_active_state(&[target], target)?;
        self.require_policy_exact(target)
    }

    fn replace_active(
        &mut self,
        mut lease: NativeXtablesTransitionLease,
        mut cursor: JournalCursor,
        current: NativeXtablesAdmittedTarget,
        target: NativeXtablesAdmittedTarget,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesOwnerError> {
        self.require_tool_identity(&current)?;
        self.require_tool_identity(&target)?;
        self.require_replacement_compatible(&current, &target)?;
        if !self.target_is_exact_active(&current)? {
            return self.fail_uncertain(
                &mut lease,
                &mut cursor,
                "replacement source was not exact active",
                "replacement was not started",
            );
        }

        cursor.intent = NativeOwnerIntent {
            step: NativeOwnerStep::Begin,
            target: Some(target.identity()),
            previous: Some(current.identity()),
        };
        cursor.advance(
            &mut lease,
            NativeXtablesJournalPhase::Activating,
            NativeOwnerStep::Begin,
        )?;

        let replacement = self.perform_replacement(&mut lease, &mut cursor, &current, &target);
        if let Err(primary) = replacement {
            return match self.rollback_replacement(&mut lease, &mut cursor, &current, &target) {
                Ok(()) => {
                    cursor.intent = NativeOwnerIntent {
                        step: NativeOwnerStep::PublishActive,
                        target: Some(current.identity()),
                        previous: None,
                    };
                    cursor.advance(
                        &mut lease,
                        NativeXtablesJournalPhase::Active,
                        NativeOwnerStep::PublishActive,
                    )?;
                    Err(NativeXtablesOwnerError::RolledBack {
                        cause: primary.to_string().into_boxed_str(),
                        state: NativeXtablesConvergedState::Active(current.identity()),
                    })
                }
                Err(compensation) => self.fail_uncertain(
                    &mut lease,
                    &mut cursor,
                    &primary.to_string(),
                    &compensation.to_string(),
                ),
            };
        }

        let new_binding = self.environment.binding(target.identity().generation());
        cursor.intent = NativeOwnerIntent {
            step: NativeOwnerStep::PublishActive,
            target: Some(target.identity()),
            previous: None,
        };
        let next = cursor.next_record(
            new_binding,
            NativeXtablesJournalPhase::Active,
            NativeOwnerStep::PublishActive,
        )?;
        lease.rebind(next.clone())?;
        cursor = JournalCursor::from_record(&next)?;
        debug_assert_eq!(cursor.binding.generation(), target.identity().generation());
        Ok(NativeXtablesConvergenceReport {
            state: NativeXtablesConvergedState::Active(target.identity()),
            changed: true,
        })
    }

    fn perform_replacement(
        &mut self,
        lease: &mut NativeXtablesTransitionLease,
        cursor: &mut JournalCursor,
        current: &NativeXtablesAdmittedTarget,
        target: &NativeXtablesAdmittedTarget,
    ) -> Result<(), NativeXtablesOwnerError> {
        for family in target.topology().families() {
            cursor.advance(
                lease,
                NativeXtablesJournalPhase::Activating,
                prepare_step(family.family()),
            )?;
            self.adapter.restore(family.family(), family.prepare())?;
        }
        self.require_active_state(&[current, target], current)?;
        self.require_policy_exact(current)?;

        for family in target.topology().families() {
            cursor.advance(
                lease,
                NativeXtablesJournalPhase::Activating,
                switch_step(family.family()),
            )?;
            self.adapter.restore(family.family(), family.switch())?;
        }
        self.require_active_state(&[current, target], target)?;
        self.require_policy_exact(target)?;

        for family in current.topology().families() {
            cursor.advance(
                lease,
                NativeXtablesJournalPhase::Activating,
                retire_step(family.family()),
            )?;
            self.adapter.restore(family.family(), family.retire())?;
        }
        self.require_active_state(&[target], target)?;
        self.require_policy_exact(target)
    }

    fn rollback_replacement(
        &mut self,
        lease: &mut NativeXtablesTransitionLease,
        cursor: &mut JournalCursor,
        current: &NativeXtablesAdmittedTarget,
        target: &NativeXtablesAdmittedTarget,
    ) -> Result<(), NativeXtablesOwnerError> {
        cursor.advance(
            lease,
            NativeXtablesJournalPhase::Activating,
            NativeOwnerStep::Rollback,
        )?;
        for family in current.topology().families() {
            let observed = self.adapter.observe_xtables(family.family())?;
            if !private_target_present(&observed, family)? {
                cursor.advance(
                    lease,
                    NativeXtablesJournalPhase::Activating,
                    prepare_step(family.family()),
                )?;
                if let Err(error) = self.adapter.restore(family.family(), family.prepare()) {
                    let prepared_despite_error = error.certainty()
                        == NativeMutationCertainty::MayHaveMutated
                        && private_target_present(
                            &self.adapter.observe_xtables(family.family())?,
                            family,
                        )?;
                    if !prepared_despite_error {
                        return Err(error.into());
                    }
                }
            }
            let observed = self.adapter.observe_xtables(family.family())?;
            let target_family = target
                .topology()
                .family(family.family())
                .expect("replacement topology family has a family plan");
            let target_present = private_target_present(&observed, target_family)?;
            let prepared = if target_present {
                vec![current, target]
            } else {
                vec![current]
            };
            if expected_state(&prepared, Some(current), family.family(), false)?
                .is_satisfied_by(&observed)
            {
                continue;
            }
            if target_present
                && expected_state(&prepared, Some(target), family.family(), false)?
                    .is_satisfied_by(&observed)
            {
                cursor.advance(
                    lease,
                    NativeXtablesJournalPhase::Activating,
                    switch_step(family.family()),
                )?;
                if let Err(error) = self.adapter.restore(family.family(), family.switch()) {
                    let observed = self.adapter.observe_xtables(family.family())?;
                    if error.certainty() != NativeMutationCertainty::MayHaveMutated
                        || !expected_state(&prepared, Some(current), family.family(), false)?
                            .is_satisfied_by(&observed)
                    {
                        return Err(error.into());
                    }
                }
                continue;
            }
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "replacement rollback observed neither old nor new exact active state",
            ));
        }
        for family in current.topology().families() {
            let observed = self.adapter.observe_xtables(family.family())?;
            let target_family = target
                .topology()
                .family(family.family())
                .expect("replacement topology family has a family plan");
            let prepared = if private_target_present(&observed, target_family)? {
                vec![current, target]
            } else {
                vec![current]
            };
            if !expected_state(&prepared, Some(current), family.family(), false)?
                .is_satisfied_by(&observed)
            {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "replacement rollback did not restore old active state",
                ));
            }
        }

        for family in target.topology().families() {
            let observed = self.adapter.observe_xtables(family.family())?;
            if private_target_present(&observed, family)? {
                cursor.advance(
                    lease,
                    NativeXtablesJournalPhase::Activating,
                    retire_step(family.family()),
                )?;
                if let Err(error) = self.adapter.restore(family.family(), family.retire()) {
                    let observed = self.adapter.observe_xtables(family.family())?;
                    if error.certainty() != NativeMutationCertainty::MayHaveMutated
                        || private_target_present(&observed, family)?
                    {
                        return Err(error.into());
                    }
                }
            }
        }
        self.require_active_state(&[current], current)?;
        self.require_policy_exact(current)
    }

    fn clear_recoverable_canary_slots(
        &mut self,
        lease: &mut NativeXtablesTransitionLease,
        cursor: &mut JournalCursor,
        targets: &[&NativeXtablesAdmittedTarget],
        family: XtablesRestoreFamily,
    ) -> Result<(), NativeXtablesOwnerError> {
        let observed = self.adapter.observe_xtables(family)?;
        let present = present_targets_for_family(&observed, targets, family)?;
        let mut normalized = observed.clone();
        let mut retirements = Vec::new();
        for target in &present {
            let plan = target
                .topology()
                .family(family)
                .expect("present target has a family plan");
            let Some(chain) = plan.local_output_canary_selector() else {
                continue;
            };
            let retire = render_canary_retire_artifact(family, chain)?;
            normalized = normalized
                .with_owned_chain_replacement(&retire)
                .map_err(NativeXtablesOwnerError::ExpectedState)?;
            let dirty = !observed
                .chain(chain)
                .expect("a present target retains every private chain")
                .rules()
                .is_empty();
            if dirty {
                retirements.push((Box::<str>::from(chain), retire));
            }
        }
        classify_family_state(&normalized, &present, family)?;

        for (chain, retire) in retirements {
            cursor.advance(
                lease,
                NativeXtablesJournalPhase::Retiring,
                retire_canary_step(family),
            )?;
            if let Err(error) = self.adapter.restore(family, &retire) {
                let observed = self.adapter.observe_xtables(family)?;
                let absent = observed
                    .chain(&chain)
                    .is_some_and(|state| state.rules().is_empty());
                if error.certainty() != NativeMutationCertainty::MayHaveMutated || !absent {
                    return Err(error.into());
                }
            }
        }

        let observed = self.adapter.observe_xtables(family)?;
        let present = present_targets_for_family(&observed, targets, family)?;
        classify_family_state(&observed, &present, family).map(|_| ())
    }

    fn cleanup_targets(
        &mut self,
        lease: &mut NativeXtablesTransitionLease,
        cursor: &mut JournalCursor,
        targets: &[NativeXtablesAdmittedTarget],
    ) -> Result<(), NativeXtablesOwnerError> {
        let refs = targets.iter().collect::<Vec<_>>();
        for family in ALL_XTABLES_FAMILIES {
            self.clear_recoverable_canary_slots(lease, cursor, &refs, family)?;
            let observed = self.adapter.observe_xtables(family)?;
            let present = present_targets_for_family(&observed, &refs, family)?;
            let state = classify_family_state(&observed, &present, family)?;
            let stable = match state {
                FamilyState::Empty | FamilyState::Prepared => None,
                FamilyState::Active(index) => {
                    let target = present[index];
                    let plan = target
                        .topology()
                        .family(family)
                        .expect("classified stable target has a family plan");
                    if let Some(detach) = plan.detach_output() {
                        cursor.advance(
                            lease,
                            NativeXtablesJournalPhase::Retiring,
                            detach_output_step(family),
                        )?;
                        if let Err(error) = self.adapter.restore(family, detach) {
                            let observed = self.adapter.observe_xtables(family)?;
                            let present = present_targets_for_family(&observed, &refs, family)?;
                            if error.certainty() != NativeMutationCertainty::MayHaveMutated
                                || !expected_state(&present, Some(target), family, true)?
                                    .is_satisfied_by(&observed)
                            {
                                return Err(error.into());
                            }
                        }
                    }
                    Some(target)
                }
                FamilyState::OutputDetached(index) => Some(present[index]),
            };
            if let Some(stable) = stable {
                let observed = self.adapter.observe_xtables(family)?;
                let present = present_targets_for_family(&observed, &refs, family)?;
                let expected = expected_state(&present, Some(stable), family, true)?;
                if !expected.is_satisfied_by(&observed) {
                    return Err(NativeXtablesOwnerError::LiveStateConflict(
                        "OUTPUT detachment readback did not match",
                    ));
                }
            }
        }

        for routing in unique_routing(&refs)? {
            let observed = self.observe_policy_routing(routing)?;
            if observed.has_conflict() {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "policy-routing cleanup found duplicate or conflicting state",
                ));
            }
            if observed.rule_exact == 1 {
                cursor.advance(
                    lease,
                    NativeXtablesJournalPhase::Retiring,
                    rule_delete_step(routing.family()),
                )?;
                if let Err(error) = self.mutate_policy_routing(
                    routing,
                    PolicyRoutingMutation::DeleteRule(routing.rule()),
                ) {
                    let observed = self.observe_policy_routing(routing)?;
                    if error.certainty() != NativeMutationCertainty::MayHaveMutated
                        || observed.rule_exact != 0
                        || observed.has_conflict()
                    {
                        return Err(error.into());
                    }
                }
            }
            let observed = self.observe_policy_routing(routing)?;
            if observed.has_conflict() || observed.rule_exact != 0 {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "policy rule deletion did not prove absence",
                ));
            }
            if observed.route_exact == 1 {
                cursor.advance(
                    lease,
                    NativeXtablesJournalPhase::Retiring,
                    route_delete_step(routing.family()),
                )?;
                if let Err(error) = self.mutate_policy_routing(
                    routing,
                    PolicyRoutingMutation::DeleteRoute(routing.route()),
                ) {
                    let observed = self.observe_policy_routing(routing)?;
                    if error.certainty() != NativeMutationCertainty::MayHaveMutated
                        || observed.route_exact != 0
                        || observed.has_conflict()
                    {
                        return Err(error.into());
                    }
                }
            }
            if !self.observe_policy_routing(routing)?.absent() {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "policy-routing cleanup did not prove exact absence",
                ));
            }
        }

        for routing in unique_audit_routing(&refs)? {
            if !self.observe_policy_routing(routing)?.absent() {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "policy-routing cleanup left state in the complete family audit",
                ));
            }
        }

        for family in ALL_XTABLES_FAMILIES {
            let observed = self.adapter.observe_xtables(family)?;
            let present = present_targets_for_family(&observed, &refs, family)?;
            match classify_family_state(&observed, &present, family)? {
                FamilyState::OutputDetached(index) => {
                    let plan = present[index]
                        .topology()
                        .family(family)
                        .expect("classified stable target has a family plan");
                    cursor.advance(
                        lease,
                        NativeXtablesJournalPhase::Retiring,
                        detach_remaining_step(family),
                    )?;
                    if let Err(error) = self.adapter.restore(family, plan.detach_remaining()) {
                        let observed = self.adapter.observe_xtables(family)?;
                        let present = present_targets_for_family(&observed, &refs, family)?;
                        if error.certainty() != NativeMutationCertainty::MayHaveMutated
                            || !matches!(
                                classify_family_state(&observed, &present, family)?,
                                FamilyState::Prepared | FamilyState::Empty
                            )
                        {
                            return Err(error.into());
                        }
                    }
                }
                FamilyState::Prepared | FamilyState::Empty => {}
                FamilyState::Active(_) => {
                    return Err(NativeXtablesOwnerError::LiveStateConflict(
                        "OUTPUT remained attached during cleanup",
                    ));
                }
            }

            for target in &refs {
                let Some(target_family) = target.topology().family(family) else {
                    continue;
                };
                let observed = self.adapter.observe_xtables(family)?;
                if private_target_present(&observed, target_family)? {
                    cursor.advance(
                        lease,
                        NativeXtablesJournalPhase::Retiring,
                        retire_step(family),
                    )?;
                    if let Err(error) = self.adapter.restore(family, target_family.retire()) {
                        let observed = self.adapter.observe_xtables(family)?;
                        if error.certainty() != NativeMutationCertainty::MayHaveMutated
                            || private_target_present(&observed, target_family)?
                        {
                            return Err(error.into());
                        }
                    }
                }
            }
            if !self.adapter.observe_xtables(family)?.is_empty() {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "xtables cleanup did not prove exact absence",
                ));
            }
        }
        Ok(())
    }

    fn recover_to_clean_absence(
        &mut self,
        mut lease: NativeXtablesTransitionLease,
        mut cursor: JournalCursor,
        targets: &[NativeXtablesAdmittedTarget],
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesOwnerError> {
        if targets.is_empty() {
            return self.fail_uncertain(
                &mut lease,
                &mut cursor,
                "nonterminal journal contained no resolvable target",
                "cleanup identities were unavailable",
            );
        }
        cursor.intent.step = NativeOwnerStep::Rollback;
        cursor.advance(
            &mut lease,
            NativeXtablesJournalPhase::Retiring,
            NativeOwnerStep::Rollback,
        )?;
        match self.cleanup_targets(&mut lease, &mut cursor, targets) {
            Ok(()) => {
                let last = targets.last().map(NativeXtablesAdmittedTarget::identity);
                // `complete_clean_absence` consumes the lease, so reconstruct ownership by moving
                // it out of the mutable reference only through the helper below.
                let terminal_intent = NativeOwnerIntent {
                    step: NativeOwnerStep::PublishActive,
                    target: None,
                    previous: last,
                };
                let terminal = cursor.terminal(terminal_intent)?;
                lease.complete(terminal)?;
                Ok(NativeXtablesConvergenceReport {
                    state: NativeXtablesConvergedState::CleanAbsent,
                    changed: true,
                })
            }
            Err(error) => self.fail_uncertain(
                &mut lease,
                &mut cursor,
                "startup recovery cleanup failed",
                &error.to_string(),
            ),
        }
    }

    fn complete_clean_absence(
        &mut self,
        lease: NativeXtablesTransitionLease,
        cursor: JournalCursor,
        previous: Option<NativeXtablesTargetIdentity>,
        changed: bool,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesOwnerError> {
        let terminal = cursor.terminal(NativeOwnerIntent {
            step: NativeOwnerStep::PublishActive,
            target: None,
            previous,
        })?;
        lease.complete(terminal)?;
        Ok(NativeXtablesConvergenceReport {
            state: NativeXtablesConvergedState::CleanAbsent,
            changed,
        })
    }

    fn fail_uncertain<T>(
        &mut self,
        lease: &mut NativeXtablesTransitionLease,
        cursor: &mut JournalCursor,
        primary: &str,
        compensation: &str,
    ) -> Result<T, NativeXtablesOwnerError> {
        cursor.intent.step = NativeOwnerStep::Failed;
        let _ = cursor.advance(
            lease,
            NativeXtablesJournalPhase::Uncertain,
            NativeOwnerStep::Failed,
        );
        Err(NativeXtablesOwnerError::Uncertain {
            primary: primary.to_owned().into_boxed_str(),
            compensation: compensation.to_owned().into_boxed_str(),
        })
    }

    fn observe_policy_routing(
        &mut self,
        identity: ManagedPolicyRoutingIdentity,
    ) -> Result<NativePolicyRoutingObservation, NativeXtablesAdapterError> {
        self.adapter
            .validate_interface_identity(identity.loopback())?;
        self.adapter.observe_policy_routing(identity)
    }

    fn mutate_policy_routing(
        &mut self,
        identity: ManagedPolicyRoutingIdentity,
        mutation: PolicyRoutingMutation,
    ) -> Result<(), NativeXtablesAdapterError> {
        self.adapter
            .validate_interface_identity(identity.loopback())?;
        self.adapter.mutate_policy_routing(mutation)
    }

    fn require_tool_identity(
        &self,
        target: &NativeXtablesAdmittedTarget,
    ) -> Result<(), NativeXtablesOwnerError> {
        if self.adapter.tool_digest() == target.identity().tool_digest() {
            Ok(())
        } else {
            Err(NativeXtablesOwnerError::ToolIdentityMismatch)
        }
    }

    fn require_replacement_compatible(
        &self,
        current: &NativeXtablesAdmittedTarget,
        target: &NativeXtablesAdmittedTarget,
    ) -> Result<(), NativeXtablesOwnerError> {
        if current.identity().generation() == target.identity().generation() {
            return Err(NativeXtablesOwnerError::ReplacementIncompatible(
                "replacement must use a fresh generation",
            ));
        }
        let current_families = current
            .topology()
            .families()
            .iter()
            .map(XtablesStableFamilyPlan::family)
            .collect::<Vec<_>>();
        let target_families = target
            .topology()
            .families()
            .iter()
            .map(XtablesStableFamilyPlan::family)
            .collect::<Vec<_>>();
        if current_families != target_families {
            return Err(NativeXtablesOwnerError::ReplacementIncompatible(
                "enabled address families changed",
            ));
        }
        if current.routing() != target.routing() {
            return Err(NativeXtablesOwnerError::ReplacementIncompatible(
                "policy-routing identity changed",
            ));
        }
        if current.routing_audit() != target.routing_audit() {
            return Err(NativeXtablesOwnerError::ReplacementIncompatible(
                "policy-routing recovery audit changed",
            ));
        }
        for family in current.topology().families() {
            let replacement = target
                .topology()
                .family(family.family())
                .expect("family sets were compared above");
            if family.prerouting_root() != replacement.prerouting_root()
                || family.output_root() != replacement.output_root()
            {
                return Err(NativeXtablesOwnerError::ReplacementIncompatible(
                    "stable root identity changed",
                ));
            }
        }
        Ok(())
    }

    fn resolve_target(
        &mut self,
        identity: NativeXtablesTargetIdentity,
    ) -> Result<NativeXtablesAdmittedTarget, NativeXtablesOwnerError> {
        let target = self
            .resolver
            .resolve(identity)
            .map_err(|reason| NativeXtablesOwnerError::TargetResolution { identity, reason })?;
        if target.identity() != identity {
            return Err(NativeXtablesOwnerError::ResolvedTargetMismatch);
        }
        if target.routing_audit() != self.environment.routing_audit() {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "resolved target routing audit differs from the recovery environment",
            ));
        }
        self.require_tool_identity(&target)?;
        Ok(target)
    }

    fn resolve_intent_targets(
        &mut self,
        intent: &NativeOwnerIntent,
    ) -> Result<Vec<NativeXtablesAdmittedTarget>, NativeXtablesOwnerError> {
        let mut identities = [intent.previous, intent.target]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        identities.sort_unstable();
        identities.dedup();
        identities
            .into_iter()
            .map(|identity| self.resolve_target(identity))
            .collect()
    }

    fn expected_binding(
        &self,
        recorded: &NativeXtablesJournalBinding,
    ) -> Result<NativeXtablesJournalBinding, NativeXtablesOwnerError> {
        let expected = self.environment.binding(recorded.generation());
        if expected.boot_identity() != recorded.boot_identity()
            || expected.network_namespace() != recorded.network_namespace()
            || expected.journal_identity() != recorded.journal_identity()
        {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "durable owner binding does not match the current boot, namespace, or journal",
            ));
        }
        Ok(expected)
    }

    fn guarded_journal(
        &self,
        binding: &NativeXtablesJournalBinding,
    ) -> Result<NativeXtablesJournalRecord, NativeXtablesOwnerError> {
        let record =
            self.durable
                .load_journal()?
                .ok_or(NativeXtablesOwnerError::LiveStateConflict(
                    "durable journal disappeared after native ownership was acquired",
                ))?;
        if record.binding() != binding {
            return Err(NativeXtablesOwnerError::LiveStateConflict(
                "durable journal binding changed after native ownership was acquired",
            ));
        }
        Ok(record)
    }

    fn target_is_exact_active(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
    ) -> Result<bool, NativeXtablesOwnerError> {
        for family in ALL_XTABLES_FAMILIES {
            let observed = self.adapter.observe_xtables(family)?;
            let exact = match target.topology().family(family) {
                Some(plan) => plan.active_state().is_satisfied_by(&observed),
                None => observed.is_empty(),
            };
            if !exact {
                return Ok(false);
            }
        }
        for routing in target.routing_audit().identities().iter().copied() {
            let observed = self.observe_policy_routing(routing)?;
            let expected = if target.routing().contains(&routing) {
                observed.exact()
            } else {
                observed.absent()
            };
            if !expected {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn require_active_state(
        &mut self,
        prepared: &[&NativeXtablesAdmittedTarget],
        stable: &NativeXtablesAdmittedTarget,
    ) -> Result<(), NativeXtablesOwnerError> {
        for family in ALL_XTABLES_FAMILIES {
            let observed = self.adapter.observe_xtables(family)?;
            let exact = if stable.topology().family(family).is_some() {
                expected_state(prepared, Some(stable), family, false)?.is_satisfied_by(&observed)
            } else {
                observed.is_empty()
            };
            if !exact {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "active xtables readback did not match the exact expected state",
                ));
            }
        }
        Ok(())
    }

    fn require_prepared_state(
        &mut self,
        prepared: &[&NativeXtablesAdmittedTarget],
        stable: Option<&NativeXtablesAdmittedTarget>,
    ) -> Result<(), NativeXtablesOwnerError> {
        for family in ALL_XTABLES_FAMILIES {
            let observed = self.adapter.observe_xtables(family)?;
            let enabled = prepared
                .iter()
                .any(|target| target.topology().family(family).is_some());
            let exact = if enabled {
                expected_state(prepared, stable, family, false)?.is_satisfied_by(&observed)
            } else {
                observed.is_empty()
            };
            if !exact {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "prepared xtables readback did not match the exact expected state",
                ));
            }
        }
        Ok(())
    }

    fn require_policy_exact(
        &mut self,
        target: &NativeXtablesAdmittedTarget,
    ) -> Result<(), NativeXtablesOwnerError> {
        for routing in target.routing_audit().identities().iter().copied() {
            let observed = self.observe_policy_routing(routing)?;
            let expected = if target.routing().contains(&routing) {
                observed.exact()
            } else {
                observed.absent()
            };
            if !expected {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "policy-routing readback did not match the complete family audit",
                ));
            }
        }
        Ok(())
    }

    fn require_clean_absence(
        &mut self,
        targets: &[NativeXtablesAdmittedTarget],
    ) -> Result<(), NativeXtablesOwnerError> {
        let refs = targets.iter().collect::<Vec<_>>();
        if refs.is_empty() {
            return self.require_global_xtables_absence();
        }
        for family in ALL_XTABLES_FAMILIES {
            if !self.adapter.observe_xtables(family)?.is_empty() {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "Flux xtables state exists before ownership acquisition",
                ));
            }
        }
        for routing in unique_audit_routing(&refs)? {
            if !self.observe_policy_routing(routing)?.absent() {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "unowned policy-routing state exists before ownership acquisition",
                ));
            }
        }
        Ok(())
    }

    fn require_global_xtables_absence(&mut self) -> Result<(), NativeXtablesOwnerError> {
        for family in ALL_XTABLES_FAMILIES {
            if !self.adapter.observe_xtables(family)?.is_empty() {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "Flux xtables state exists without a durable owner journal",
                ));
            }
        }
        Ok(())
    }

    fn require_recovery_policy_absence(&mut self) -> Result<(), NativeXtablesOwnerError> {
        let identities = *self.environment.routing_audit().identities();
        for identity in identities {
            if !self.observe_policy_routing(identity)?.absent() {
                return Err(NativeXtablesOwnerError::LiveStateConflict(
                    "policy-routing state exists without a current durable owner journal",
                ));
            }
        }
        Ok(())
    }
}

fn public_ownership_observation(
    observation: NativeXtablesJournalObservation,
    target: &NativeXtablesAdmittedTarget,
) -> NativeCaptureOwnershipObservation {
    let binding = observation.record().binding();
    let identity = target.identity();
    let public_target = NativeCaptureTargetIdentity::new(
        identity.generation(),
        identity.target_digest(),
        identity.tool_digest(),
        identity.routing_digest(),
    );
    let retained_owner = NativeCaptureRetainedOwner::new(
        public_target,
        target
            .topology()
            .family(XtablesRestoreFamily::Ipv4)
            .map(|family| family.active_state().clone()),
        target
            .topology()
            .family(XtablesRestoreFamily::Ipv6)
            .map(|family| family.active_state().clone()),
        target.routing().iter().copied(),
    );
    NativeCaptureOwnershipObservation::new(
        public_target,
        binding.boot_identity().clone(),
        binding.network_namespace(),
        binding.journal_identity(),
        observation.record().revision(),
        NonZeroU16::new(NATIVE_XTABLES_JOURNAL_SCHEMA_VERSION)
            .expect("native xtables journal schema is nonzero"),
        observation.file_device(),
        observation.file_inode(),
        observation.digest(),
        retained_owner,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FamilyState {
    Empty,
    Prepared,
    Active(usize),
    OutputDetached(usize),
}

fn classify_family_state(
    observed: &XtablesSaveProjection,
    targets: &[&NativeXtablesAdmittedTarget],
    family: XtablesRestoreFamily,
) -> Result<FamilyState, NativeXtablesOwnerError> {
    if observed.is_empty() {
        return Ok(FamilyState::Empty);
    }
    let prepared = expected_state(targets, None, family, false)?;
    if prepared.is_satisfied_by(observed) {
        return Ok(FamilyState::Prepared);
    }
    for (index, target) in targets.iter().enumerate() {
        if target.topology().family(family).is_none() {
            continue;
        }
        if expected_state(targets, Some(target), family, false)?.is_satisfied_by(observed) {
            return Ok(FamilyState::Active(index));
        }
        if expected_state(targets, Some(target), family, true)?.is_satisfied_by(observed) {
            return Ok(FamilyState::OutputDetached(index));
        }
    }
    Err(NativeXtablesOwnerError::LiveStateConflict(
        "xtables readback matches no exact recoverable transaction state",
    ))
}

fn expected_state<'a>(
    prepared: &[&'a NativeXtablesAdmittedTarget],
    stable: Option<&'a NativeXtablesAdmittedTarget>,
    family: XtablesRestoreFamily,
    output_detached: bool,
) -> Result<XtablesExpectedState, NativeXtablesOwnerError> {
    let mut artifacts = Vec::new();
    for target in prepared {
        if let Some(target_family) = target.topology().family(family) {
            artifacts.push(target_family.prepare());
        }
    }
    let phase =
        if let Some(stable) = stable {
            let plan = stable.topology().family(family).ok_or(
                NativeXtablesOwnerError::LiveStateConflict(
                    "stable target does not enable the observed family",
                ),
            )?;
            artifacts.push(plan.install());
            if output_detached {
                XtablesExpectedStatePhase::OutputDetached
            } else {
                XtablesExpectedStatePhase::Active
            }
        } else {
            XtablesExpectedStatePhase::Prepared
        };
    XtablesExpectedState::from_apply_artifacts(family, phase, artifacts)
        .map_err(NativeXtablesOwnerError::ExpectedState)
}

fn enabled_families(targets: &[&NativeXtablesAdmittedTarget]) -> Vec<XtablesRestoreFamily> {
    let mut families = targets
        .iter()
        .flat_map(|target| {
            target
                .topology()
                .families()
                .iter()
                .map(XtablesStableFamilyPlan::family)
        })
        .collect::<Vec<_>>();
    families.sort_by_key(|family| match family {
        XtablesRestoreFamily::Ipv4 => 4,
        XtablesRestoreFamily::Ipv6 => 6,
    });
    families.dedup();
    families
}

fn present_targets_for_family<'a>(
    observed: &XtablesSaveProjection,
    targets: &[&'a NativeXtablesAdmittedTarget],
    family: XtablesRestoreFamily,
) -> Result<Vec<&'a NativeXtablesAdmittedTarget>, NativeXtablesOwnerError> {
    let mut present = Vec::new();
    for target in targets {
        let Some(target_family) = target.topology().family(family) else {
            continue;
        };
        if private_target_present(observed, target_family)? {
            present.push(*target);
        }
    }
    Ok(present)
}

fn unique_routing(
    targets: &[&NativeXtablesAdmittedTarget],
) -> Result<Vec<ManagedPolicyRoutingIdentity>, NativeXtablesOwnerError> {
    let mut routing = targets
        .iter()
        .flat_map(|target| target.routing().iter().copied())
        .collect::<Vec<_>>();
    routing.sort_by_key(|identity| family_key(identity.family()));
    routing.dedup();
    for family in [NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6] {
        if routing
            .iter()
            .filter(|identity| identity.family() == family)
            .count()
            > 1
        {
            return Err(NativeXtablesOwnerError::ReplacementIncompatible(
                "multiple exact policy-routing identities exist for one family",
            ));
        }
    }
    Ok(routing)
}

fn unique_audit_routing(
    targets: &[&NativeXtablesAdmittedTarget],
) -> Result<Vec<ManagedPolicyRoutingIdentity>, NativeXtablesOwnerError> {
    let mut routing = targets
        .iter()
        .flat_map(|target| target.routing_audit().identities().iter().copied())
        .collect::<Vec<_>>();
    routing.sort_by_key(|identity| family_key(identity.family()));
    routing.dedup();
    for family in [NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6] {
        if routing
            .iter()
            .filter(|identity| identity.family() == family)
            .count()
            > 1
        {
            return Err(NativeXtablesOwnerError::ReplacementIncompatible(
                "multiple policy-routing audit identities exist for one family",
            ));
        }
    }
    Ok(routing)
}

fn private_target_present(
    observed: &XtablesSaveProjection,
    target: &XtablesStableFamilyPlan,
) -> Result<bool, NativeXtablesOwnerError> {
    let mut present = 0_usize;
    for chain in target.private_chains() {
        present += usize::from(observed.chain(chain).is_some());
    }
    if present == 0 {
        Ok(false)
    } else if present == target.private_chains().len() {
        Ok(true)
    } else {
        Err(NativeXtablesOwnerError::LiveStateConflict(
            "only part of a generation's private chain set exists",
        ))
    }
}

#[path = "owner_process_adapter.rs"]
mod process_adapter;

#[path = "owner_target_archive.rs"]
mod target_archive;

#[path = "owner_runtime_writer.rs"]
mod runtime_writer;

#[allow(unused_imports)]
pub(crate) use process_adapter::NativeXtablesProcessOwnerAdapter;
#[allow(unused_imports)]
pub(crate) use runtime_writer::*;
#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
pub use runtime_writer::{
    NativeLinuxCompositionTestAdmission, NativeLinuxCompositionTestAuthority,
    NativeLinuxCompositionTestConfig, NativeLinuxCompositionTestError,
    NativeLinuxCompositionTestRuntime,
};
#[allow(unused_imports)]
pub use runtime_writer::{
    NativeXtablesAndroidRuntime, NativeXtablesAndroidRuntimeConfig,
    NativeXtablesAndroidRuntimeError, NativeXtablesCaptureAdmission,
    NativeXtablesCaptureAdmissionError, NativeXtablesCaptureConvergenceError,
    NativeXtablesCaptureConverger, NativeXtablesCaptureTarget, NativeXtablesRoutingPlanError,
    plan_native_xtables_local_output_routing,
};
#[allow(unused_imports)]
pub(crate) use target_archive::{
    DurableNativeXtablesTargetResolver, NativeXtablesTargetArchiveError,
    NativeXtablesTargetArchiveObservation, observe_native_xtables_target_archive,
    observe_native_xtables_target_archive_for_active_owner,
};

#[cfg(test)]
#[path = "owner_runtime_tests.rs"]
mod tests;
