use std::error::Error;
use std::fmt;
use std::net::IpAddr;

use flux_core::{
    BootIdentity, NetworkAddressFamily, NetworkNamespaceIdentity, OwnershipJournalIdentity,
    OwnershipJournalRevision,
};
use sha2::{Digest, Sha256};

use crate::netlink::policy_routing::{
    ManagedInterfaceIdentity, ManagedPolicyRoutingIdentity, PolicyRoutingMutation,
};

use super::super::owner_durable::{
    NativeXtablesDurableError, NativeXtablesDurableStore, NativeXtablesGeneration,
    NativeXtablesJournalBinding, NativeXtablesJournalPhase, NativeXtablesJournalRecord,
    NativeXtablesLeaseScope, NativeXtablesOwnerPayload, NativeXtablesRecovery,
    NativeXtablesRecoveryFence, NativeXtablesRecoveryInspection, NativeXtablesTransitionLease,
};
use super::super::save::{
    XtablesExpectedState, XtablesExpectedStatePhase, XtablesSaveProjection,
    XtablesSaveProjectionError,
};
use super::super::{XtablesCaptureArtifactSet, XtablesRestoreArtifact, XtablesRestoreFamily};
use super::{XtablesStableFamilyPlan, XtablesStableTopologyError, XtablesStableTopologyPlan};

const OWNER_PAYLOAD_SCHEMA: u16 = 2;
const IDENTITY_DIGEST_BYTES: usize = 32;
const ALL_XTABLES_FAMILIES: [XtablesRestoreFamily; 2] =
    [XtablesRestoreFamily::Ipv4, XtablesRestoreFamily::Ipv6];
const ROUTING_IDENTITY_DIGEST_DOMAIN: &[u8] =
    b"Flux native xtables bound policy-routing audit\0sha256-v1\0";

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
    generation: NativeXtablesGeneration,
    artifact_digest: [u8; IDENTITY_DIGEST_BYTES],
    tool_digest: [u8; IDENTITY_DIGEST_BYTES],
    routing_digest: [u8; IDENTITY_DIGEST_BYTES],
}

impl NativeXtablesTargetIdentity {
    #[must_use]
    pub(crate) const fn generation(self) -> NativeXtablesGeneration {
        self.generation
    }

    #[must_use]
    pub(crate) const fn artifact_digest(self) -> [u8; IDENTITY_DIGEST_BYTES] {
        self.artifact_digest
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

/// Complete test-admitted immutable transaction target.
///
/// There is deliberately no non-test constructor. Production mark/RPDB admission remains
/// uninhabited until the Android authority and device gates in the roadmap exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesAdmittedTarget {
    identity: NativeXtablesTargetIdentity,
    artifacts: Box<XtablesCaptureArtifactSet>,
    topology: Box<XtablesStableTopologyPlan>,
    routing: Box<[ManagedPolicyRoutingIdentity]>,
    routing_audit: Box<NativePolicyRoutingAudit>,
}

impl NativeXtablesAdmittedTarget {
    #[cfg(test)]
    pub(crate) fn admit_for_test(
        artifacts: XtablesCaptureArtifactSet,
        routing: impl IntoIterator<Item = ManagedPolicyRoutingIdentity>,
        routing_audit: NativePolicyRoutingAudit,
        tool_digest: [u8; IDENTITY_DIGEST_BYTES],
    ) -> Result<Self, NativeXtablesTargetError> {
        let topology = XtablesStableTopologyPlan::from_artifacts(&artifacts)
            .map_err(NativeXtablesTargetError::Topology)?;
        let generation =
            NativeXtablesGeneration::new(u64::from(artifacts.namespace().generation().get()))
                .expect("lowered xtables generations are nonzero");
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

        Ok(Self {
            identity: NativeXtablesTargetIdentity {
                generation,
                artifact_digest: *artifacts.digest().as_bytes(),
                tool_digest,
                routing_digest: digest_policy_routing_audit(&routing_audit),
            },
            artifacts: Box::new(artifacts),
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
    pub(crate) const fn artifacts(&self) -> &XtablesCaptureArtifactSet {
        &self.artifacts
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

    fn mutate_policy_routing(
        &mut self,
        mutation: PolicyRoutingMutation,
    ) -> Result<(), NativeXtablesAdapterError>;

    fn observe_policy_routing(
        &mut self,
        identity: ManagedPolicyRoutingIdentity,
    ) -> Result<NativePolicyRoutingObservation, NativeXtablesAdapterError>;
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

    fn binding(&self, generation: NativeXtablesGeneration) -> NativeXtablesJournalBinding {
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

fn encode_optional_identity(identity: Option<NativeXtablesTargetIdentity>) -> String {
    let Some(identity) = identity else {
        return "-".to_owned();
    };
    format!(
        "{}:{}:{}:{}",
        identity.generation.get(),
        encode_hex(&identity.artifact_digest),
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
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(NativeXtablesGeneration::new)
        .ok_or(NativeXtablesOwnerError::InvalidPayload(
            "invalid target generation",
        ))?;
    let artifact_digest =
        fields
            .next()
            .and_then(decode_digest)
            .ok_or(NativeXtablesOwnerError::InvalidPayload(
                "invalid target artifact digest",
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
        artifact_digest,
        tool_digest,
        routing_digest,
    }))
}

fn digest_policy_routing_audit(audit: &NativePolicyRoutingAudit) -> [u8; IDENTITY_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(ROUTING_IDENTITY_DIGEST_DOMAIN);
    for identity in audit.identities() {
        digest.update([family_key(identity.family())]);
        let loopback = identity.loopback();
        digest.update((loopback.name().as_bytes().len() as u32).to_be_bytes());
        digest.update(loopback.name().as_bytes());
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
    digest.finalize().into()
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
        }
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
                let guarded_intent = NativeOwnerIntent::parse(guarded.owner_payload())?;
                let cursor = JournalCursor::from_record(&guarded)?;
                let targets = self.resolve_intent_targets(&guarded_intent)?;
                if guarded.phase() == NativeXtablesJournalPhase::Active
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
            let pair = target
                .artifacts()
                .pair(family.family())
                .expect("topology family has an artifact pair");
            self.adapter.restore(family.family(), pair.prepare())?;
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
            let pair = target
                .artifacts()
                .pair(family.family())
                .expect("replacement topology family has an artifact pair");
            self.adapter.restore(family.family(), pair.prepare())?;
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
            let pair = current
                .artifacts()
                .pair(family.family())
                .expect("current topology family has an artifact pair");
            self.adapter.restore(family.family(), pair.retire())?;
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
            let pair = current
                .artifacts()
                .pair(family.family())
                .expect("current topology family has an artifact pair");
            let observed = self.adapter.observe_xtables(family.family())?;
            if !private_target_present(&observed, pair)? {
                cursor.advance(
                    lease,
                    NativeXtablesJournalPhase::Activating,
                    prepare_step(family.family()),
                )?;
                if let Err(error) = self.adapter.restore(family.family(), pair.prepare()) {
                    let prepared_despite_error = error.certainty()
                        == NativeMutationCertainty::MayHaveMutated
                        && private_target_present(
                            &self.adapter.observe_xtables(family.family())?,
                            pair,
                        )?;
                    if !prepared_despite_error {
                        return Err(error.into());
                    }
                }
            }
            let observed = self.adapter.observe_xtables(family.family())?;
            let target_pair = target
                .artifacts()
                .pair(family.family())
                .expect("replacement topology family has an artifact pair");
            let target_present = private_target_present(&observed, target_pair)?;
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
            let target_pair = target
                .artifacts()
                .pair(family.family())
                .expect("replacement topology family has an artifact pair");
            let prepared = if private_target_present(&observed, target_pair)? {
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
            let pair = target
                .artifacts()
                .pair(family.family())
                .expect("replacement topology family has an artifact pair");
            let observed = self.adapter.observe_xtables(family.family())?;
            if private_target_present(&observed, pair)? {
                cursor.advance(
                    lease,
                    NativeXtablesJournalPhase::Activating,
                    retire_step(family.family()),
                )?;
                if let Err(error) = self.adapter.restore(family.family(), pair.retire()) {
                    let observed = self.adapter.observe_xtables(family.family())?;
                    if error.certainty() != NativeMutationCertainty::MayHaveMutated
                        || private_target_present(&observed, pair)?
                    {
                        return Err(error.into());
                    }
                }
            }
        }
        self.require_active_state(&[current], current)?;
        self.require_policy_exact(current)
    }

    fn cleanup_targets(
        &mut self,
        lease: &mut NativeXtablesTransitionLease,
        cursor: &mut JournalCursor,
        targets: &[NativeXtablesAdmittedTarget],
    ) -> Result<(), NativeXtablesOwnerError> {
        let refs = targets.iter().collect::<Vec<_>>();
        for family in ALL_XTABLES_FAMILIES {
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
                let Some(pair) = target.artifacts().pair(family) else {
                    continue;
                };
                let observed = self.adapter.observe_xtables(family)?;
                if private_target_present(&observed, pair)? {
                    cursor.advance(
                        lease,
                        NativeXtablesJournalPhase::Retiring,
                        retire_step(family),
                    )?;
                    if let Err(error) = self.adapter.restore(family, pair.retire()) {
                        let observed = self.adapter.observe_xtables(family)?;
                        if error.certainty() != NativeMutationCertainty::MayHaveMutated
                            || private_target_present(&observed, pair)?
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
                    "native or legacy xtables state exists before ownership acquisition",
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
                    "native or legacy xtables state exists without a durable owner journal",
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
        if let Some(pair) = target.artifacts().pair(family) {
            artifacts.push(pair.prepare());
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
        let Some(pair) = target.artifacts().pair(family) else {
            continue;
        };
        if private_target_present(observed, pair)? {
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
    pair: &super::super::XtablesCaptureArtifactPair,
) -> Result<bool, NativeXtablesOwnerError> {
    let mut present = 0_usize;
    for entry in pair.entries() {
        present += usize::from(observed.chain(entry.chain()).is_some());
    }
    if present == 0 {
        Ok(false)
    } else if present == pair.entries().len() {
        Ok(true)
    } else {
        Err(NativeXtablesOwnerError::LiveStateConflict(
            "only part of a generation's private chain set exists",
        ))
    }
}

#[path = "owner_process_adapter.rs"]
mod process_adapter;

#[allow(unused_imports)]
pub(crate) use process_adapter::NativeXtablesProcessOwnerAdapter;

#[cfg(test)]
#[path = "owner_runtime_tests.rs"]
mod tests;
