use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU16, NonZeroU32};

use flux_core::{
    CAPTURE_PROGRAM_SCHEMA_VERSION, CaptureClause, CaptureClauseDecision, CaptureDecisionStage,
    CaptureDomainProgram, CaptureInterfaceDirection, CaptureInterfaceSelector,
    CaptureInterfaceSelectorKind, CapturePredicate, CaptureProgram, CaptureProgramDigest,
    CaptureProtocolSet, CaptureTrafficDomain, CaptureTransportProtocol, CaptureUserId,
    EngineCredentials, FwmarkCandidate, FwmarkRole, GenerationId, InterfaceName,
    NetworkAddressFamily, RouteProtocol, RouteScope, RouteTableId, RouteType, RuleFwMark,
    RulePriority, RuleProtocol,
};
use sha2::{Digest, Sha256};

use super::{
    MAX_XTABLES_RESTORE_BYTES, MAX_XTABLES_RESTORE_COMMANDS, XtablesRestoreAction,
    XtablesRestoreArtifact, XtablesRestoreContext, XtablesRestoreFamily, XtablesRestoreParseError,
    parse_xtables_restore,
};

/// Current schema for deterministic Capture Program to xtables transaction lowering.
pub const XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION: u16 = 2;
pub const XTABLES_CAPTURE_DIGEST_BYTES: usize = 32;
pub const MAX_XTABLES_CAPTURE_COMMANDS_PER_ARTIFACT: usize = MAX_XTABLES_RESTORE_COMMANDS;

const LOWERING_DIGEST_DOMAIN: &[u8] =
    b"Flux canonical xtables Capture Program lowering\0schema-v2\0";
const PAIR_DIGEST_DOMAIN: &[u8] =
    b"Flux canonical xtables Capture Program artifact pair\0schema-v2\0";
const SET_DIGEST_DOMAIN: &[u8] =
    b"Flux canonical xtables Capture Program artifact set\0schema-v2\0";
const LINUX_ROUTE_SCOPE_UNIVERSE: u8 = 0;
const LINUX_ROUTE_SCOPE_HOST: u8 = 254;
const LINUX_ROUTE_TYPE_LOCAL: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesCaptureExtension {
    EstablishedFlowCache,
    TransparentSocketDivert,
    FakeIpIcmp,
    QuicReject,
    MssClamp,
}

/// Explicit extension selection at the lowering boundary.
///
/// Current schemas admit only the all-disabled value. Keeping the omitted semantics typed prevents a
/// caller from silently assuming that legacy cache, DIVERT, FakeIP, QUIC, or MSS behavior was
/// included in the canonical classification artifact.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XtablesCaptureExtensions {
    established_flow_cache: bool,
    transparent_socket_divert: bool,
    fake_ip_icmp: bool,
    quic_reject: bool,
    mss_clamp: bool,
}

impl XtablesCaptureExtensions {
    #[must_use]
    pub const fn new(
        established_flow_cache: bool,
        transparent_socket_divert: bool,
        fake_ip_icmp: bool,
        quic_reject: bool,
        mss_clamp: bool,
    ) -> Self {
        Self {
            established_flow_cache,
            transparent_socket_divert,
            fake_ip_icmp,
            quic_reject,
            mss_clamp,
        }
    }

    #[must_use]
    pub const fn established_flow_cache(self) -> bool {
        self.established_flow_cache
    }

    #[must_use]
    pub const fn transparent_socket_divert(self) -> bool {
        self.transparent_socket_divert
    }

    #[must_use]
    pub const fn fake_ip_icmp(self) -> bool {
        self.fake_ip_icmp
    }

    #[must_use]
    pub const fn quic_reject(self) -> bool {
        self.quic_reject
    }

    #[must_use]
    pub const fn mss_clamp(self) -> bool {
        self.mss_clamp
    }

    const fn first_enabled(self) -> Option<XtablesCaptureExtension> {
        if self.established_flow_cache {
            Some(XtablesCaptureExtension::EstablishedFlowCache)
        } else if self.transparent_socket_divert {
            Some(XtablesCaptureExtension::TransparentSocketDivert)
        } else if self.fake_ip_icmp {
            Some(XtablesCaptureExtension::FakeIpIcmp)
        } else if self.quic_reject {
            Some(XtablesCaptureExtension::QuicReject)
        } else if self.mss_clamp {
            Some(XtablesCaptureExtension::MssClamp)
        } else {
            None
        }
    }

    const fn bits(self) -> u8 {
        (self.established_flow_cache as u8)
            | ((self.transparent_socket_divert as u8) << 1)
            | ((self.fake_ip_icmp as u8) << 2)
            | ((self.quic_reject as u8) << 3)
            | ((self.mss_clamp as u8) << 4)
    }
}

/// Non-authorizing namespace used only to derive deterministic generation-scoped chain names.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XtablesCaptureNamespace {
    generation: GenerationId,
}

impl XtablesCaptureNamespace {
    #[must_use]
    pub const fn new(generation: GenerationId) -> Self {
        Self { generation }
    }

    #[must_use]
    pub const fn generation(self) -> GenerationId {
        self.generation
    }
}

/// Structurally valid TPROXY and local policy-routing target.
///
/// `FwmarkCandidate` remains planning evidence only. Supplying it here does not create allocation
/// authority or a mark lease.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XtablesTproxyTarget {
    proxy_port: NonZeroU16,
    mark: FwmarkCandidate,
}

impl XtablesTproxyTarget {
    #[must_use]
    pub const fn new(proxy_port: NonZeroU16, mark: FwmarkCandidate) -> Self {
        Self { proxy_port, mark }
    }

    #[must_use]
    pub const fn proxy_port(self) -> NonZeroU16 {
        self.proxy_port
    }

    #[must_use]
    pub const fn mark(self) -> FwmarkCandidate {
        self.mark
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesLocalOutputRoutingTargetError {
    ZeroPriority,
    ReservedTable { table: RouteTableId },
    UnspecifiedRouteProtocol,
    UnspecifiedRuleProtocol,
}

impl fmt::Display for XtablesLocalOutputRoutingTargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPriority => formatter.write_str("local-OUTPUT RPDB priority is zero"),
            Self::ReservedTable { table } => write!(
                formatter,
                "routing table {} is reserved and cannot identify a Flux local-OUTPUT route",
                table.get()
            ),
            Self::UnspecifiedRouteProtocol => {
                formatter.write_str("local-OUTPUT route protocol is unspecified")
            }
            Self::UnspecifiedRuleProtocol => {
                formatter.write_str("local-OUTPUT rule protocol is unspecified")
            }
        }
    }
}

impl Error for XtablesLocalOutputRoutingTargetError {}

/// Descriptive policy-routing target selected by a caller for one local-OUTPUT family.
///
/// This value does not prove Android-safe placement, route ownership, or mutation authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XtablesLocalOutputRoutingTarget {
    priority: RulePriority,
    table: RouteTableId,
    route_metric: NonZeroU32,
    route_protocol: RouteProtocol,
    rule_protocol: RuleProtocol,
}

impl XtablesLocalOutputRoutingTarget {
    pub const fn new(
        priority: RulePriority,
        table: RouteTableId,
        route_metric: NonZeroU32,
        route_protocol: RouteProtocol,
        rule_protocol: RuleProtocol,
    ) -> Result<Self, XtablesLocalOutputRoutingTargetError> {
        if priority.get() == 0 {
            return Err(XtablesLocalOutputRoutingTargetError::ZeroPriority);
        }
        if matches!(table.get(), 0 | 252 | 253 | 254 | 255) {
            return Err(XtablesLocalOutputRoutingTargetError::ReservedTable { table });
        }
        if route_protocol.raw() == 0 {
            return Err(XtablesLocalOutputRoutingTargetError::UnspecifiedRouteProtocol);
        }
        if rule_protocol.raw() == 0 {
            return Err(XtablesLocalOutputRoutingTargetError::UnspecifiedRuleProtocol);
        }
        Ok(Self {
            priority,
            table,
            route_metric,
            route_protocol,
            rule_protocol,
        })
    }

    #[must_use]
    pub const fn priority(self) -> RulePriority {
        self.priority
    }

    #[must_use]
    pub const fn table(self) -> RouteTableId {
        self.table
    }

    #[must_use]
    pub const fn route_metric(self) -> NonZeroU32 {
        self.route_metric
    }

    #[must_use]
    pub const fn route_protocol(self) -> RouteProtocol {
        self.route_protocol
    }

    #[must_use]
    pub const fn rule_protocol(self) -> RuleProtocol {
        self.rule_protocol
    }
}

/// Per-family routing identities required before a proxying local-OUTPUT program may lower.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XtablesLocalOutputRoutingSpec {
    ipv4_routing: Option<XtablesLocalOutputRoutingTarget>,
    ipv6_routing: Option<XtablesLocalOutputRoutingTarget>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesLocalOutputRoutingSpecError {
    NoEnabledFamilies,
}

impl fmt::Display for XtablesLocalOutputRoutingSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEnabledFamilies => {
                formatter.write_str("local-OUTPUT routing selects no address family")
            }
        }
    }
}

impl Error for XtablesLocalOutputRoutingSpecError {}

impl XtablesLocalOutputRoutingSpec {
    pub const fn new(
        ipv4_routing: Option<XtablesLocalOutputRoutingTarget>,
        ipv6_routing: Option<XtablesLocalOutputRoutingTarget>,
    ) -> Result<Self, XtablesLocalOutputRoutingSpecError> {
        if ipv4_routing.is_none() && ipv6_routing.is_none() {
            return Err(XtablesLocalOutputRoutingSpecError::NoEnabledFamilies);
        }
        Ok(Self {
            ipv4_routing,
            ipv6_routing,
        })
    }

    #[must_use]
    pub const fn routing_for(
        self,
        family: NetworkAddressFamily,
    ) -> Option<XtablesLocalOutputRoutingTarget> {
        match family {
            NetworkAddressFamily::Ipv4 => self.ipv4_routing,
            NetworkAddressFamily::Ipv6 => self.ipv6_routing,
        }
    }
}

/// Caller-selected command ceiling, bounded by the immutable restore grammar maximum.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct XtablesCaptureLoweringBudget(usize);

impl XtablesCaptureLoweringBudget {
    #[must_use]
    pub const fn new(commands_per_artifact: usize) -> Option<Self> {
        if commands_per_artifact == 0
            || commands_per_artifact > MAX_XTABLES_CAPTURE_COMMANDS_PER_ARTIFACT
        {
            None
        } else {
            Some(Self(commands_per_artifact))
        }
    }

    #[must_use]
    pub const fn commands_per_artifact(self) -> usize {
        self.0
    }
}

impl Default for XtablesCaptureLoweringBudget {
    fn default() -> Self {
        Self(MAX_XTABLES_CAPTURE_COMMANDS_PER_ARTIFACT)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct XtablesCaptureLoweringRequest<'a> {
    program: &'a CaptureProgram,
    namespace: XtablesCaptureNamespace,
    target: XtablesTproxyTarget,
    local_output_routing: Option<XtablesLocalOutputRoutingSpec>,
    extensions: XtablesCaptureExtensions,
    budget: XtablesCaptureLoweringBudget,
}

impl<'a> XtablesCaptureLoweringRequest<'a> {
    #[must_use]
    pub const fn new(
        program: &'a CaptureProgram,
        namespace: XtablesCaptureNamespace,
        target: XtablesTproxyTarget,
    ) -> Self {
        Self {
            program,
            namespace,
            target,
            local_output_routing: None,
            extensions: XtablesCaptureExtensions::new(false, false, false, false, false),
            budget: XtablesCaptureLoweringBudget(MAX_XTABLES_CAPTURE_COMMANDS_PER_ARTIFACT),
        }
    }

    #[must_use]
    pub const fn with_local_output_routing(
        mut self,
        routing: XtablesLocalOutputRoutingSpec,
    ) -> Self {
        self.local_output_routing = Some(routing);
        self
    }

    #[must_use]
    pub const fn with_extensions(mut self, extensions: XtablesCaptureExtensions) -> Self {
        self.extensions = extensions;
        self
    }

    #[must_use]
    pub const fn with_budget(mut self, budget: XtablesCaptureLoweringBudget) -> Self {
        self.budget = budget;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
/// Identity of the complete lowering request context, including the full mark candidate even when
/// a particular all-direct artifact emits no TPROXY rule. It is intentionally stronger than a
/// digest of rendered bytes alone.
pub struct XtablesCaptureLoweringDigest([u8; XTABLES_CAPTURE_DIGEST_BYTES]);

impl XtablesCaptureLoweringDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; XTABLES_CAPTURE_DIGEST_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct XtablesCaptureArtifactPairDigest([u8; XTABLES_CAPTURE_DIGEST_BYTES]);

impl XtablesCaptureArtifactPairDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; XTABLES_CAPTURE_DIGEST_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct XtablesCaptureArtifactSetDigest([u8; XTABLES_CAPTURE_DIGEST_BYTES]);

impl XtablesCaptureArtifactSetDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; XTABLES_CAPTURE_DIGEST_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesCaptureEntryPointRole {
    LocalOutputClassifier,
    LocalOutputLoopbackTproxy,
    ForwardedIngress,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesCaptureHook {
    Prerouting,
    Output,
}

/// Exact stable-hook selector needed to reach one generation-specific implementation chain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesCaptureEntrySelector {
    Any,
    Mark(RuleFwMark),
    InputInterfaceAndMark {
        interface: InterfaceName,
        mark: RuleFwMark,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XtablesCaptureEntryPoint {
    role: XtablesCaptureEntryPointRole,
    domain: CaptureTrafficDomain,
    chain: Box<str>,
    hook: XtablesCaptureHook,
    selector: XtablesCaptureEntrySelector,
}

impl XtablesCaptureEntryPoint {
    #[must_use]
    pub const fn role(&self) -> XtablesCaptureEntryPointRole {
        self.role
    }

    #[must_use]
    pub const fn domain(&self) -> CaptureTrafficDomain {
        self.domain
    }

    #[must_use]
    pub const fn chain(&self) -> &str {
        &self.chain
    }

    #[must_use]
    pub const fn hook(&self) -> XtablesCaptureHook {
        self.hook
    }

    #[must_use]
    pub const fn selector(&self) -> XtablesCaptureEntrySelector {
        self.selector
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesCaptureTransactionStep {
    PrepareEntryPoint(XtablesCaptureEntryPointRole),
    PrepareTransparentListener,
    PreparePolicyRouting,
    PrepareLoopEscape,
    AttachEntryPoint(XtablesCaptureEntryPointRole),
    DetachEntryPoint(XtablesCaptureEntryPointRole),
    RetireLoopEscape,
    RetirePolicyRouting,
    RetireTransparentListener,
    RetireEntryPoint(XtablesCaptureEntryPointRole),
}

/// Descriptive dependency order only; no step can execute or grant hook ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XtablesCaptureTransactionOrder {
    prepare: Box<[XtablesCaptureTransactionStep]>,
    retire: Box<[XtablesCaptureTransactionStep]>,
}

impl XtablesCaptureTransactionOrder {
    #[must_use]
    pub const fn prepare(&self) -> &[XtablesCaptureTransactionStep] {
        &self.prepare
    }

    #[must_use]
    pub const fn retire(&self) -> &[XtablesCaptureTransactionStep] {
        &self.retire
    }
}

/// Exact transparent listener shape required by a local-OUTPUT transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XtablesTransparentListenerRequirement {
    family: XtablesRestoreFamily,
    bind_address: IpAddr,
    port: NonZeroU16,
    protocols: CaptureProtocolSet,
}

impl XtablesTransparentListenerRequirement {
    #[must_use]
    pub const fn family(self) -> XtablesRestoreFamily {
        self.family
    }

    #[must_use]
    pub const fn bind_address(self) -> IpAddr {
        self.bind_address
    }

    #[must_use]
    pub const fn port(self) -> NonZeroU16 {
        self.port
    }

    #[must_use]
    pub const fn protocols(self) -> CaptureProtocolSet {
        self.protocols
    }

    #[must_use]
    pub const fn requires_transparent_socket(self) -> bool {
        true
    }

    #[must_use]
    pub const fn requires_original_destination(self) -> bool {
        true
    }
}

/// Engine identity and bypass socket mark that must remain valid through OUTPUT retirement.
///
/// The credentials remain a policy predicate. This type does not bind a supervised process
/// identity, retained handle, mark authority, or escape lease.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XtablesLoopEscapeRequirement {
    engine_credentials: EngineCredentials,
    socket_mark: RuleFwMark,
}

impl XtablesLoopEscapeRequirement {
    #[must_use]
    pub const fn engine_credentials(self) -> EngineCredentials {
        self.engine_credentials
    }

    #[must_use]
    pub const fn socket_mark(self) -> RuleFwMark {
        self.socket_mark
    }
}

/// Exact fwmark-rule and local-default-route identity for one family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XtablesLocalOutputRoutingRequirement {
    family: XtablesRestoreFamily,
    target: XtablesLocalOutputRoutingTarget,
    route_destination: IpAddr,
    route_prefix_length: u8,
    route_scope: RouteScope,
    route_type: RouteType,
    mark: RuleFwMark,
    loopback_interface: InterfaceName,
}

impl XtablesLocalOutputRoutingRequirement {
    #[must_use]
    pub const fn family(self) -> XtablesRestoreFamily {
        self.family
    }

    #[must_use]
    pub const fn target(self) -> XtablesLocalOutputRoutingTarget {
        self.target
    }

    #[must_use]
    pub const fn priority(self) -> RulePriority {
        self.target.priority()
    }

    #[must_use]
    pub const fn table(self) -> RouteTableId {
        self.target.table()
    }

    #[must_use]
    pub const fn route_metric(self) -> NonZeroU32 {
        self.target.route_metric()
    }

    #[must_use]
    pub const fn route_protocol(self) -> RouteProtocol {
        self.target.route_protocol()
    }

    #[must_use]
    pub const fn rule_protocol(self) -> RuleProtocol {
        self.target.rule_protocol()
    }

    #[must_use]
    pub const fn route_destination(self) -> IpAddr {
        self.route_destination
    }

    #[must_use]
    pub const fn route_prefix_length(self) -> u8 {
        self.route_prefix_length
    }

    #[must_use]
    pub const fn route_scope(self) -> RouteScope {
        self.route_scope
    }

    #[must_use]
    pub const fn route_type(self) -> RouteType {
        self.route_type
    }

    #[must_use]
    pub const fn mark(self) -> RuleFwMark {
        self.mark
    }

    #[must_use]
    pub const fn loopback_interface(self) -> InterfaceName {
        self.loopback_interface
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XtablesLocalOutputTransactionRequirements {
    routing: XtablesLocalOutputRoutingRequirement,
    listener: XtablesTransparentListenerRequirement,
    loop_escape: XtablesLoopEscapeRequirement,
}

impl XtablesLocalOutputTransactionRequirements {
    #[must_use]
    pub const fn routing(self) -> XtablesLocalOutputRoutingRequirement {
        self.routing
    }

    #[must_use]
    pub const fn listener(self) -> XtablesTransparentListenerRequirement {
        self.listener
    }

    #[must_use]
    pub const fn loop_escape(self) -> XtablesLoopEscapeRequirement {
        self.loop_escape
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XtablesCaptureResourceUsage {
    domain_programs: usize,
    source_clauses: usize,
    expanded_match_rules: usize,
    implementation_chains: usize,
    entry_points: usize,
    listener_requirements: usize,
    routing_objects: usize,
    transaction_steps: usize,
    prepare_commands: usize,
    retire_commands: usize,
    maximum_jump_depth: usize,
}

impl XtablesCaptureResourceUsage {
    #[must_use]
    pub const fn domain_programs(self) -> usize {
        self.domain_programs
    }

    #[must_use]
    pub const fn source_clauses(self) -> usize {
        self.source_clauses
    }

    #[must_use]
    pub const fn expanded_match_rules(self) -> usize {
        self.expanded_match_rules
    }

    #[must_use]
    pub const fn implementation_chains(self) -> usize {
        self.implementation_chains
    }

    #[must_use]
    pub const fn entry_points(self) -> usize {
        self.entry_points
    }

    #[must_use]
    pub const fn listener_requirements(self) -> usize {
        self.listener_requirements
    }

    #[must_use]
    pub const fn routing_objects(self) -> usize {
        self.routing_objects
    }

    #[must_use]
    pub const fn transaction_steps(self) -> usize {
        self.transaction_steps
    }

    #[must_use]
    pub const fn prepare_commands(self) -> usize {
        self.prepare_commands
    }

    #[must_use]
    pub const fn retire_commands(self) -> usize {
        self.retire_commands
    }

    #[must_use]
    pub const fn maximum_jump_depth(self) -> usize {
        self.maximum_jump_depth
    }

    fn merge(self, other: Self) -> Self {
        Self {
            domain_programs: self.domain_programs + other.domain_programs,
            source_clauses: self.source_clauses + other.source_clauses,
            expanded_match_rules: self.expanded_match_rules + other.expanded_match_rules,
            implementation_chains: self.implementation_chains + other.implementation_chains,
            entry_points: self.entry_points + other.entry_points,
            listener_requirements: self.listener_requirements + other.listener_requirements,
            routing_objects: self.routing_objects + other.routing_objects,
            transaction_steps: self.transaction_steps + other.transaction_steps,
            prepare_commands: self.prepare_commands + other.prepare_commands,
            retire_commands: self.retire_commands + other.retire_commands,
            maximum_jump_depth: self.maximum_jump_depth.max(other.maximum_jump_depth),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XtablesCaptureArtifactPair {
    family: XtablesRestoreFamily,
    entries: Box<[XtablesCaptureEntryPoint]>,
    local_output: Option<XtablesLocalOutputTransactionRequirements>,
    transaction_order: XtablesCaptureTransactionOrder,
    prepare: XtablesRestoreArtifact,
    retire: XtablesRestoreArtifact,
    usage: XtablesCaptureResourceUsage,
    digest: XtablesCaptureArtifactPairDigest,
}

impl XtablesCaptureArtifactPair {
    #[must_use]
    pub const fn family(&self) -> XtablesRestoreFamily {
        self.family
    }

    #[must_use]
    pub const fn entries(&self) -> &[XtablesCaptureEntryPoint] {
        &self.entries
    }

    #[must_use]
    pub const fn local_output(&self) -> Option<XtablesLocalOutputTransactionRequirements> {
        self.local_output
    }

    #[must_use]
    pub const fn transaction_order(&self) -> &XtablesCaptureTransactionOrder {
        &self.transaction_order
    }

    #[must_use]
    pub const fn prepare(&self) -> &XtablesRestoreArtifact {
        &self.prepare
    }

    #[must_use]
    pub const fn retire(&self) -> &XtablesRestoreArtifact {
        &self.retire
    }

    #[must_use]
    pub const fn usage(&self) -> XtablesCaptureResourceUsage {
        self.usage
    }

    #[must_use]
    pub const fn digest(&self) -> XtablesCaptureArtifactPairDigest {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XtablesCaptureArtifactSet {
    schema_version: u16,
    source_program_schema_version: u16,
    source_program_digest: CaptureProgramDigest,
    namespace: XtablesCaptureNamespace,
    target: XtablesTproxyTarget,
    extensions: XtablesCaptureExtensions,
    lowering_digest: XtablesCaptureLoweringDigest,
    ipv4: Option<XtablesCaptureArtifactPair>,
    ipv6: Option<XtablesCaptureArtifactPair>,
    usage: XtablesCaptureResourceUsage,
    digest: XtablesCaptureArtifactSetDigest,
}

impl XtablesCaptureArtifactSet {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn source_program_schema_version(&self) -> u16 {
        self.source_program_schema_version
    }

    #[must_use]
    pub const fn source_program_digest(&self) -> CaptureProgramDigest {
        self.source_program_digest
    }

    #[must_use]
    pub const fn namespace(&self) -> XtablesCaptureNamespace {
        self.namespace
    }

    #[must_use]
    pub const fn target(&self) -> XtablesTproxyTarget {
        self.target
    }

    #[must_use]
    pub const fn extensions(&self) -> XtablesCaptureExtensions {
        self.extensions
    }

    #[must_use]
    pub const fn lowering_digest(&self) -> XtablesCaptureLoweringDigest {
        self.lowering_digest
    }

    #[must_use]
    pub const fn ipv4(&self) -> Option<&XtablesCaptureArtifactPair> {
        self.ipv4.as_ref()
    }

    #[must_use]
    pub const fn ipv6(&self) -> Option<&XtablesCaptureArtifactPair> {
        self.ipv6.as_ref()
    }

    #[must_use]
    pub const fn pair(&self, family: XtablesRestoreFamily) -> Option<&XtablesCaptureArtifactPair> {
        match family {
            XtablesRestoreFamily::Ipv4 => self.ipv4(),
            XtablesRestoreFamily::Ipv6 => self.ipv6(),
        }
    }

    #[must_use]
    pub const fn usage(&self) -> XtablesCaptureResourceUsage {
        self.usage
    }

    #[must_use]
    pub const fn digest(&self) -> XtablesCaptureArtifactSetDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesCapturePredicateKind {
    Any,
    EngineCredentials,
    DestinationPrefixes,
    DestinationHosts,
    InterfaceMatches,
    InterfaceDoesNotMatch,
    LocalUidIn,
    LocalUidNotIn,
    ProtocolNotIn,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesInterfaceRenderErrorKind {
    LeadingDash,
    UnsupportedByte,
    AmbiguousTrailingWildcard,
    PrefixWildcardExceedsInterfaceLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XtablesCaptureLoweringError {
    UnsupportedProgramSchema {
        actual: u16,
        supported: u16,
    },
    EmptyProgram,
    DuplicateDomainProgram {
        family: NetworkAddressFamily,
        domain: CaptureTrafficDomain,
    },
    NonCanonicalProgramOrder,
    UnsupportedExtension {
        extension: XtablesCaptureExtension,
    },
    UnsupportedTrafficDomain {
        family: NetworkAddressFamily,
        domain: CaptureTrafficDomain,
    },
    MissingLocalOutputRouting {
        family: NetworkAddressFamily,
    },
    UnexpectedLocalOutputRouting {
        family: NetworkAddressFamily,
    },
    InvalidProgramShape {
        family: NetworkAddressFamily,
        domain: CaptureTrafficDomain,
        stage: CaptureDecisionStage,
        predicate: XtablesCapturePredicateKind,
        decision: CaptureClauseDecision,
    },
    MissingForwardedLoopbackSafety {
        family: NetworkAddressFamily,
    },
    FamilyMismatch {
        family: NetworkAddressFamily,
        domain: CaptureTrafficDomain,
    },
    InterfaceDirectionMismatch {
        family: NetworkAddressFamily,
        domain: CaptureTrafficDomain,
        direction: CaptureInterfaceDirection,
    },
    UnrenderableInterface {
        family: NetworkAddressFamily,
        domain: CaptureTrafficDomain,
        selector: CaptureInterfaceSelector,
        reason: XtablesInterfaceRenderErrorKind,
    },
    CommandBudgetExceeded {
        family: XtablesRestoreFamily,
        action: XtablesRestoreAction,
        maximum: usize,
        required: usize,
    },
    ArtifactByteLimitExceeded {
        family: XtablesRestoreFamily,
        action: XtablesRestoreAction,
        maximum: usize,
        required: usize,
    },
    InvalidRenderedArtifact {
        family: XtablesRestoreFamily,
        action: XtablesRestoreAction,
        source: XtablesRestoreParseError,
    },
}

impl fmt::Display for XtablesCaptureLoweringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProgramSchema { actual, supported } => write!(
                formatter,
                "Capture Program schema {actual} cannot be lowered by xtables schema {supported}"
            ),
            Self::EmptyProgram => {
                formatter.write_str("Capture Program contains no domain programs")
            }
            Self::DuplicateDomainProgram { family, domain } => write!(
                formatter,
                "Capture Program repeats the {family:?}/{domain:?} domain"
            ),
            Self::NonCanonicalProgramOrder => {
                formatter.write_str("Capture Program family/domain order is not canonical")
            }
            Self::UnsupportedExtension { extension } => write!(
                formatter,
                "xtables Capture Program lowering does not model {extension:?}"
            ),
            Self::UnsupportedTrafficDomain { family, domain } => write!(
                formatter,
                "xtables Capture Program lowering cannot realize the {family:?}/{domain:?} domain"
            ),
            Self::MissingLocalOutputRouting { family } => write!(
                formatter,
                "proxying local OUTPUT for {family:?} lacks its policy-routing target"
            ),
            Self::UnexpectedLocalOutputRouting { family } => write!(
                formatter,
                "{family:?} local-OUTPUT routing was supplied without a proxy-capable local program"
            ),
            Self::InvalidProgramShape {
                family,
                domain,
                stage,
                predicate,
                decision,
            } => write!(
                formatter,
                "unsupported {family:?}/{domain:?} Capture clause {stage:?} + {predicate:?} -> {decision:?}"
            ),
            Self::MissingForwardedLoopbackSafety { family } => write!(
                formatter,
                "forwarded {family:?} Capture Program lacks its canonical loopback safety clause"
            ),
            Self::FamilyMismatch { family, domain } => write!(
                formatter,
                "{family:?}/{domain:?} Capture Program contains an address from another family"
            ),
            Self::InterfaceDirectionMismatch {
                family,
                domain,
                direction,
            } => write!(
                formatter,
                "{family:?}/{domain:?} Capture Program uses the incompatible {direction:?} interface direction"
            ),
            Self::UnrenderableInterface {
                family,
                domain,
                selector,
                reason,
            } => write!(
                formatter,
                "{family:?}/{domain:?} interface selector {selector:?} cannot be rendered: {reason:?}"
            ),
            Self::CommandBudgetExceeded {
                family,
                action,
                maximum,
                required,
            } => write!(
                formatter,
                "{family:?} {action:?} lowering requires {required} commands but its budget is {maximum}"
            ),
            Self::ArtifactByteLimitExceeded {
                family,
                action,
                maximum,
                required,
            } => write!(
                formatter,
                "{family:?} {action:?} lowering requires {required} restore bytes but the immutable limit is {maximum}"
            ),
            Self::InvalidRenderedArtifact {
                family,
                action,
                source,
            } => write!(
                formatter,
                "lowered {family:?} {action:?} artifact failed canonical parsing: {source}"
            ),
        }
    }
}

impl Error for XtablesCaptureLoweringError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRenderedArtifact { source, .. } => Some(source),
            Self::UnsupportedProgramSchema { .. }
            | Self::EmptyProgram
            | Self::DuplicateDomainProgram { .. }
            | Self::NonCanonicalProgramOrder
            | Self::UnsupportedExtension { .. }
            | Self::UnsupportedTrafficDomain { .. }
            | Self::MissingLocalOutputRouting { .. }
            | Self::UnexpectedLocalOutputRouting { .. }
            | Self::InvalidProgramShape { .. }
            | Self::MissingForwardedLoopbackSafety { .. }
            | Self::FamilyMismatch { .. }
            | Self::InterfaceDirectionMismatch { .. }
            | Self::UnrenderableInterface { .. }
            | Self::CommandBudgetExceeded { .. }
            | Self::ArtifactByteLimitExceeded { .. } => None,
        }
    }
}

/// Lower Capture Programs into deterministic, non-authorizing xtables transaction artifacts.
///
/// The result describes complete lifecycle ordering without executing restore, mutating stable
/// hooks, or granting routing/listener ownership.
pub fn lower_xtables_capture(
    request: XtablesCaptureLoweringRequest<'_>,
) -> Result<XtablesCaptureArtifactSet, XtablesCaptureLoweringError> {
    if request.program.schema_version() != CAPTURE_PROGRAM_SCHEMA_VERSION {
        return Err(XtablesCaptureLoweringError::UnsupportedProgramSchema {
            actual: request.program.schema_version(),
            supported: CAPTURE_PROGRAM_SCHEMA_VERSION,
        });
    }
    if let Some(extension) = request.extensions.first_enabled() {
        return Err(XtablesCaptureLoweringError::UnsupportedExtension { extension });
    }
    let programs = request.program.programs();
    if programs.is_empty() {
        return Err(XtablesCaptureLoweringError::EmptyProgram);
    }
    validate_program_keys(programs)?;
    let lowering_digest = digest_lowering(request);
    let ipv4 = lower_family(
        programs,
        NetworkAddressFamily::Ipv4,
        request,
        lowering_digest,
    )?;
    let ipv6 = lower_family(
        programs,
        NetworkAddressFamily::Ipv6,
        request,
        lowering_digest,
    )?;
    let usage = ipv4
        .as_ref()
        .map(XtablesCaptureArtifactPair::usage)
        .unwrap_or_default()
        .merge(
            ipv6.as_ref()
                .map(XtablesCaptureArtifactPair::usage)
                .unwrap_or_default(),
        );
    let digest = digest_set(lowering_digest, ipv4.as_ref(), ipv6.as_ref(), usage);

    Ok(XtablesCaptureArtifactSet {
        schema_version: XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION,
        source_program_schema_version: request.program.schema_version(),
        source_program_digest: request.program.digest(),
        namespace: request.namespace,
        target: request.target,
        extensions: request.extensions,
        lowering_digest,
        ipv4,
        ipv6,
        usage,
        digest,
    })
}

fn validate_program_keys(
    programs: &[CaptureDomainProgram],
) -> Result<(), XtablesCaptureLoweringError> {
    let mut previous = None;
    for program in programs {
        let key = program_key(program.family(), program.domain());
        if let Some(previous) = previous {
            if key == previous {
                return Err(XtablesCaptureLoweringError::DuplicateDomainProgram {
                    family: program.family(),
                    domain: program.domain(),
                });
            }
            if key < previous {
                return Err(XtablesCaptureLoweringError::NonCanonicalProgramOrder);
            }
        }
        previous = Some(key);
    }
    Ok(())
}

fn program_key(family: NetworkAddressFamily, domain: CaptureTrafficDomain) -> (u8, u8) {
    (family_tag(family), domain_tag(domain))
}

struct ProgramAnalysis<'a> {
    program: &'a CaptureDomainProgram,
    engine_credentials: Option<EngineCredentials>,
    direct_clause_count: usize,
    proxy_scope: Option<ProxyScope<'a>>,
    protocols: Option<CaptureProtocolSet>,
    direct_rules: usize,
    proxy_rules: usize,
    final_return: bool,
}

enum ProxyScope<'a> {
    All,
    InputInterfaces(&'a [CaptureInterfaceSelector]),
    OutputUids(&'a [CaptureUserId]),
}

struct RenderedChain {
    name: Box<str>,
    rules: Vec<String>,
}

fn lower_family(
    programs: &[CaptureDomainProgram],
    family: NetworkAddressFamily,
    request: XtablesCaptureLoweringRequest<'_>,
    lowering_digest: XtablesCaptureLoweringDigest,
) -> Result<Option<XtablesCaptureArtifactPair>, XtablesCaptureLoweringError> {
    let selected = programs
        .iter()
        .filter(|program| program.family() == family)
        .collect::<Vec<_>>();
    if selected.is_empty() {
        if request
            .local_output_routing
            .and_then(|routing| routing.routing_for(family))
            .is_some()
        {
            return Err(XtablesCaptureLoweringError::UnexpectedLocalOutputRouting { family });
        }
        return Ok(None);
    }

    let analyses = selected
        .iter()
        .copied()
        .map(analyze_program)
        .collect::<Result<Vec<_>, _>>()?;
    let local_analysis = analyses
        .iter()
        .find(|analysis| analysis.program.domain() == CaptureTrafficDomain::LocalOutput);
    let local_proxy_protocols = local_analysis.and_then(|analysis| analysis.protocols);
    let supplied_routing = request
        .local_output_routing
        .and_then(|routing| routing.routing_for(family));
    let routing_target = match (local_proxy_protocols, supplied_routing) {
        (Some(_), Some(routing)) => Some(routing),
        (Some(_), None) => {
            return Err(XtablesCaptureLoweringError::MissingLocalOutputRouting { family });
        }
        (None, Some(_)) => {
            return Err(XtablesCaptureLoweringError::UnexpectedLocalOutputRouting { family });
        }
        (None, None) => None,
    };

    let implementation_chains = analyses
        .iter()
        .map(|analysis| {
            1 + usize::from(
                analysis.program.domain() == CaptureTrafficDomain::LocalOutput
                    && analysis.protocols.is_some(),
            )
        })
        .sum::<usize>();
    let prepare_commands = analyses
        .iter()
        .map(|analysis| {
            let program_commands =
                analysis.direct_rules + analysis.proxy_rules + usize::from(analysis.final_return);
            let companion_commands =
                if analysis.program.domain() == CaptureTrafficDomain::LocalOutput {
                    analysis
                        .protocols
                        .map_or(0, |protocols| protocol_count(protocols) + 1)
                } else {
                    0
                };
            program_commands + companion_commands
        })
        .sum::<usize>();
    let retire_commands = implementation_chains * 2;
    ensure_command_budget(
        restore_family(family),
        XtablesRestoreAction::Apply,
        request.budget,
        prepare_commands,
    )?;
    ensure_command_budget(
        restore_family(family),
        XtablesRestoreAction::Cleanup,
        request.budget,
        retire_commands,
    )?;

    let mut entries = Vec::with_capacity(implementation_chains);
    let mut chains = Vec::with_capacity(implementation_chains);
    for analysis in &analyses {
        match analysis.program.domain() {
            CaptureTrafficDomain::LocalOutput => {
                let role = XtablesCaptureEntryPointRole::LocalOutputClassifier;
                let chain = capture_chain_name(family, role, request.namespace.generation());
                let rules = render_program(analysis, &chain, request.target)?;
                entries.push(XtablesCaptureEntryPoint {
                    role,
                    domain: CaptureTrafficDomain::LocalOutput,
                    chain: chain.clone(),
                    hook: XtablesCaptureHook::Output,
                    selector: XtablesCaptureEntrySelector::Mark(
                        RuleFwMark::new(0, request.target.mark().mask())
                            .expect("a nonzero Flux mask yields an unassigned selector"),
                    ),
                });
                chains.push(RenderedChain { name: chain, rules });

                if let Some(protocols) = analysis.protocols {
                    let role = XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy;
                    let chain = capture_chain_name(family, role, request.namespace.generation());
                    let rules = render_loopback_companion(&chain, protocols, request.target);
                    entries.push(XtablesCaptureEntryPoint {
                        role,
                        domain: CaptureTrafficDomain::LocalOutput,
                        chain: chain.clone(),
                        hook: XtablesCaptureHook::Prerouting,
                        selector: XtablesCaptureEntrySelector::InputInterfaceAndMark {
                            interface: loopback_interface(),
                            mark: request.target.mark().selector(FwmarkRole::Proxy),
                        },
                    });
                    chains.push(RenderedChain { name: chain, rules });
                }
            }
            CaptureTrafficDomain::ForwardedIngress => {
                let role = XtablesCaptureEntryPointRole::ForwardedIngress;
                let chain = capture_chain_name(family, role, request.namespace.generation());
                let rules = render_program(analysis, &chain, request.target)?;
                entries.push(XtablesCaptureEntryPoint {
                    role,
                    domain: CaptureTrafficDomain::ForwardedIngress,
                    chain: chain.clone(),
                    hook: XtablesCaptureHook::Prerouting,
                    selector: XtablesCaptureEntrySelector::Any,
                });
                chains.push(RenderedChain { name: chain, rules });
            }
        }
    }

    debug_assert_eq!(
        chains.iter().map(|chain| chain.rules.len()).sum::<usize>(),
        prepare_commands
    );
    let restore_family = restore_family(family);
    let prepare_capacity = prepare_byte_count(&chains);
    ensure_byte_limit(
        restore_family,
        XtablesRestoreAction::Apply,
        prepare_capacity,
    )?;
    let retire_capacity = retire_byte_count(&chains);
    ensure_byte_limit(
        restore_family,
        XtablesRestoreAction::Cleanup,
        retire_capacity,
    )?;
    let prepare_bytes = render_prepare(&chains, prepare_capacity);
    let retire_bytes = render_retire(&chains, retire_capacity);
    let prepare = parse_lowered_artifact(
        prepare_bytes.as_bytes(),
        XtablesRestoreContext::new(XtablesRestoreAction::Apply, restore_family),
    )?;
    let retire = parse_lowered_artifact(
        retire_bytes.as_bytes(),
        XtablesRestoreContext::new(XtablesRestoreAction::Cleanup, restore_family),
    )?;
    debug_assert_eq!(prepare.usage().commands(), prepare_commands);
    debug_assert_eq!(retire.usage().commands(), retire_commands);

    let local_output = match (local_analysis, local_proxy_protocols, routing_target) {
        (Some(analysis), Some(protocols), Some(routing)) => Some(build_local_output_requirements(
            family,
            analysis
                .engine_credentials
                .expect("validated local proxy program has engine credentials"),
            protocols,
            routing,
            request.target,
        )),
        (Some(_), None, None) | (None, None, None) => None,
        _ => unreachable!("local routing validation keeps proxy requirements coherent"),
    };
    let transaction_order = build_transaction_order(&entries, local_output.is_some());

    let usage = XtablesCaptureResourceUsage {
        domain_programs: analyses.len(),
        source_clauses: analyses
            .iter()
            .map(|analysis| analysis.program.clauses().len())
            .sum(),
        expanded_match_rules: analyses
            .iter()
            .map(|analysis| {
                analysis.direct_rules
                    + analysis.proxy_rules
                    + if analysis.program.domain() == CaptureTrafficDomain::LocalOutput {
                        analysis.protocols.map_or(0, protocol_count)
                    } else {
                        0
                    }
            })
            .sum(),
        implementation_chains,
        entry_points: entries.len(),
        listener_requirements: local_output
            .map(|requirements| protocol_count(requirements.listener().protocols()))
            .unwrap_or(0),
        routing_objects: usize::from(local_output.is_some()) * 2,
        transaction_steps: transaction_order.prepare().len() + transaction_order.retire().len(),
        prepare_commands,
        retire_commands,
        maximum_jump_depth: 1,
    };
    let entries = entries.into_boxed_slice();
    let digest = digest_pair(PairDigestInput {
        lowering: lowering_digest,
        family: restore_family,
        entries: &entries,
        local_output,
        transaction_order: &transaction_order,
        prepare: &prepare,
        retire: &retire,
        usage,
    });
    Ok(Some(XtablesCaptureArtifactPair {
        family: restore_family,
        entries,
        local_output,
        transaction_order,
        prepare,
        retire,
        usage,
        digest,
    }))
}

fn analyze_program(
    program: &CaptureDomainProgram,
) -> Result<ProgramAnalysis<'_>, XtablesCaptureLoweringError> {
    let clauses = program.clauses();
    if clauses.is_empty() {
        return Err(invalid_shape(
            program,
            CaptureDecisionStage::TrafficScope,
            XtablesCapturePredicateKind::Any,
            CaptureClauseDecision::Direct,
        ));
    }
    if clauses
        .windows(2)
        .any(|pair| pair[0].stage() > pair[1].stage())
    {
        let clause = &clauses[1];
        return Err(invalid_clause(program, clause));
    }

    let engine_credentials = match program.domain() {
        CaptureTrafficDomain::LocalOutput => {
            let first = &clauses[0];
            if first.stage() != CaptureDecisionStage::LoopPrevention
                || first.decision() != CaptureClauseDecision::Direct
            {
                return Err(invalid_clause(program, first));
            }
            match first.predicate() {
                CapturePredicate::EngineCredentials(credentials) => Some(*credentials),
                _ => return Err(invalid_clause(program, first)),
            }
        }
        CaptureTrafficDomain::ForwardedIngress => {
            let has_loopback = clauses.iter().any(|clause| {
                clause.stage() == CaptureDecisionStage::MandatorySafety
                    && clause.decision() == CaptureClauseDecision::Direct
                    && matches!(
                        clause.predicate(),
                        CapturePredicate::InterfaceMatches {
                            direction: CaptureInterfaceDirection::Input,
                            selectors,
                        } if selectors.iter().any(is_exact_loopback)
                    )
            });
            if !has_loopback {
                return Err(
                    XtablesCaptureLoweringError::MissingForwardedLoopbackSafety {
                        family: program.family(),
                    },
                );
            }
            None
        }
    };

    let mut direct_clause_count = clauses.len();
    let mut proxy_scope = None;
    let mut protocols = None;
    if let Some(proxy) = clauses.last()
        && proxy.stage() == CaptureDecisionStage::ProxyAction
        && proxy.decision() == CaptureClauseDecision::Proxy
        && matches!(proxy.predicate(), CapturePredicate::Any)
    {
        let Some(protocol_clause) = clauses.get(clauses.len().saturating_sub(2)) else {
            return Err(invalid_clause(program, proxy));
        };
        let CapturePredicate::ProtocolNotIn(protocol_set) = protocol_clause.predicate() else {
            return Err(invalid_clause(program, protocol_clause));
        };
        if protocol_clause.stage() != CaptureDecisionStage::ProtocolSafety
            || protocol_clause.decision() != CaptureClauseDecision::Direct
        {
            return Err(invalid_clause(program, protocol_clause));
        }
        protocols = Some(*protocol_set);
        direct_clause_count = clauses.len() - 2;
        proxy_scope = Some(ProxyScope::All);

        if let Some(candidate) = clauses.get(clauses.len().saturating_sub(3)) {
            match candidate.predicate() {
                CapturePredicate::InterfaceDoesNotMatch {
                    direction: CaptureInterfaceDirection::Input,
                    selectors,
                } if program.domain() == CaptureTrafficDomain::ForwardedIngress
                    && candidate.stage() == CaptureDecisionStage::InterfaceRole
                    && candidate.decision() == CaptureClauseDecision::Direct
                    && !selectors.is_empty() =>
                {
                    for selector in selectors.iter().copied() {
                        validate_interface_selector(program, selector)?;
                    }
                    direct_clause_count -= 1;
                    proxy_scope = Some(ProxyScope::InputInterfaces(selectors));
                }
                CapturePredicate::LocalUidNotIn(uids)
                    if program.domain() == CaptureTrafficDomain::LocalOutput
                        && candidate.stage() == CaptureDecisionStage::ApplicationPolicy
                        && candidate.decision() == CaptureClauseDecision::Direct
                        && !uids.is_empty() =>
                {
                    direct_clause_count -= 1;
                    proxy_scope = Some(ProxyScope::OutputUids(uids));
                }
                _ => {}
            }
        }
    } else if clauses
        .iter()
        .any(|clause| clause.decision() == CaptureClauseDecision::Proxy)
    {
        let clause = clauses
            .iter()
            .find(|clause| clause.decision() == CaptureClauseDecision::Proxy)
            .expect("proxy clause exists");
        return Err(invalid_clause(program, clause));
    }

    let mut direct_rules = 0usize;
    let mut has_unconditional_direct = false;
    for (index, clause) in clauses[..direct_clause_count].iter().enumerate() {
        direct_rules += validate_direct_clause(program, clause)?;
        if matches!(clause.predicate(), CapturePredicate::Any) {
            if index + 1 != direct_clause_count || proxy_scope.is_some() {
                return Err(invalid_clause(program, clause));
            }
            has_unconditional_direct = true;
        }
    }
    for clause in &clauses[direct_clause_count..] {
        if matches!(
            clause.predicate(),
            CapturePredicate::LocalUidNotIn(_) | CapturePredicate::InterfaceDoesNotMatch { .. }
        ) {
            continue;
        }
        if !matches!(
            (clause.stage(), clause.predicate(), clause.decision()),
            (
                CaptureDecisionStage::ProtocolSafety,
                CapturePredicate::ProtocolNotIn(_),
                CaptureClauseDecision::Direct
            ) | (
                CaptureDecisionStage::ProxyAction,
                CapturePredicate::Any,
                CaptureClauseDecision::Proxy
            )
        ) {
            return Err(invalid_clause(program, clause));
        }
    }

    let proxy_rules = match (&proxy_scope, protocols) {
        (Some(ProxyScope::All), Some(protocols)) => protocol_count(protocols),
        (Some(ProxyScope::InputInterfaces(selectors)), Some(protocols)) => {
            selectors.len() * protocol_count(protocols)
        }
        (Some(ProxyScope::OutputUids(uids)), Some(protocols)) => {
            uids.len() * protocol_count(protocols)
        }
        (None, None) => 0,
        _ => unreachable!("proxy scope and protocol eligibility are discovered together"),
    };

    Ok(ProgramAnalysis {
        program,
        engine_credentials,
        direct_clause_count,
        proxy_scope,
        protocols,
        direct_rules,
        proxy_rules,
        final_return: !has_unconditional_direct,
    })
}

fn validate_direct_clause(
    program: &CaptureDomainProgram,
    clause: &CaptureClause,
) -> Result<usize, XtablesCaptureLoweringError> {
    if clause.decision() != CaptureClauseDecision::Direct {
        return Err(invalid_clause(program, clause));
    }
    match clause.predicate() {
        CapturePredicate::Any
            if matches!(
                (program.domain(), clause.stage()),
                (
                    CaptureTrafficDomain::ForwardedIngress,
                    CaptureDecisionStage::InterfaceRole
                ) | (
                    CaptureTrafficDomain::LocalOutput,
                    CaptureDecisionStage::ApplicationPolicy
                )
            ) =>
        {
            Ok(1)
        }
        CapturePredicate::EngineCredentials(_)
            if program.domain() == CaptureTrafficDomain::LocalOutput
                && clause.stage() == CaptureDecisionStage::LoopPrevention =>
        {
            Ok(1)
        }
        CapturePredicate::DestinationPrefixes(prefixes)
            if !prefixes.is_empty()
                && matches!(
                    clause.stage(),
                    CaptureDecisionStage::MandatorySafety
                        | CaptureDecisionStage::ConfigurableBypass
                ) =>
        {
            if prefixes
                .iter()
                .any(|prefix| prefix.family() != program.family())
            {
                return Err(family_mismatch(program));
            }
            Ok(prefixes.len())
        }
        CapturePredicate::DestinationHosts(hosts)
            if !hosts.is_empty() && clause.stage() == CaptureDecisionStage::MandatorySafety =>
        {
            if hosts
                .iter()
                .copied()
                .any(|host| address_family(host) != program.family())
            {
                return Err(family_mismatch(program));
            }
            Ok(hosts.len())
        }
        CapturePredicate::InterfaceMatches {
            direction,
            selectors,
        } if !selectors.is_empty() => {
            validate_interface_direction(program, *direction)?;
            let admitted_stage = match program.domain() {
                CaptureTrafficDomain::LocalOutput => {
                    clause.stage() == CaptureDecisionStage::InterfaceRole
                }
                CaptureTrafficDomain::ForwardedIngress => matches!(
                    clause.stage(),
                    CaptureDecisionStage::MandatorySafety | CaptureDecisionStage::InterfaceRole
                ),
            };
            if !admitted_stage {
                return Err(invalid_clause(program, clause));
            }
            for selector in selectors.iter().copied() {
                validate_interface_selector(program, selector)?;
            }
            Ok(selectors.len())
        }
        CapturePredicate::LocalUidIn(uids)
            if program.domain() == CaptureTrafficDomain::LocalOutput
                && clause.stage() == CaptureDecisionStage::ApplicationPolicy
                && !uids.is_empty() =>
        {
            Ok(uids.len())
        }
        CapturePredicate::InterfaceDoesNotMatch { .. }
        | CapturePredicate::LocalUidNotIn(_)
        | CapturePredicate::ProtocolNotIn(_)
        | CapturePredicate::Any
        | CapturePredicate::EngineCredentials(_)
        | CapturePredicate::DestinationPrefixes(_)
        | CapturePredicate::DestinationHosts(_)
        | CapturePredicate::InterfaceMatches { .. }
        | CapturePredicate::LocalUidIn(_) => Err(invalid_clause(program, clause)),
    }
}

fn validate_interface_direction(
    program: &CaptureDomainProgram,
    direction: CaptureInterfaceDirection,
) -> Result<(), XtablesCaptureLoweringError> {
    let expected = match program.domain() {
        CaptureTrafficDomain::LocalOutput => CaptureInterfaceDirection::Output,
        CaptureTrafficDomain::ForwardedIngress => CaptureInterfaceDirection::Input,
    };
    if direction == expected {
        Ok(())
    } else {
        Err(XtablesCaptureLoweringError::InterfaceDirectionMismatch {
            family: program.family(),
            domain: program.domain(),
            direction,
        })
    }
}

fn validate_interface_selector(
    program: &CaptureDomainProgram,
    selector: CaptureInterfaceSelector,
) -> Result<(), XtablesCaptureLoweringError> {
    let name = selector.name();
    let bytes = name.as_bytes();
    let reason = if bytes.first() == Some(&b'-') {
        Some(XtablesInterfaceRenderErrorKind::LeadingDash)
    } else if !bytes.iter().copied().all(interface_token_byte) {
        Some(XtablesInterfaceRenderErrorKind::UnsupportedByte)
    } else if bytes.last() == Some(&b'+') {
        Some(XtablesInterfaceRenderErrorKind::AmbiguousTrailingWildcard)
    } else if selector.kind() == CaptureInterfaceSelectorKind::Prefix && bytes.len() == 15 {
        Some(XtablesInterfaceRenderErrorKind::PrefixWildcardExceedsInterfaceLimit)
    } else {
        None
    };
    match reason {
        Some(reason) => Err(XtablesCaptureLoweringError::UnrenderableInterface {
            family: program.family(),
            domain: program.domain(),
            selector,
            reason,
        }),
        None => Ok(()),
    }
}

fn interface_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+' | b'.' | b':')
}

fn render_program(
    analysis: &ProgramAnalysis<'_>,
    chain: &str,
    target: XtablesTproxyTarget,
) -> Result<Vec<String>, XtablesCaptureLoweringError> {
    let mut rules = Vec::with_capacity(
        analysis.direct_rules + analysis.proxy_rules + usize::from(analysis.final_return),
    );
    for clause in &analysis.program.clauses()[..analysis.direct_clause_count] {
        render_direct_clause(analysis.program, clause, chain, &mut rules)?;
    }
    if let (Some(scope), Some(protocols)) = (&analysis.proxy_scope, analysis.protocols) {
        render_proxy_rules(
            analysis.program,
            scope,
            protocols,
            chain,
            target,
            &mut rules,
        )?;
    }
    if analysis.final_return {
        rules.push(format!("-A {chain} -j RETURN"));
    }
    debug_assert_eq!(
        rules.len(),
        analysis.direct_rules + analysis.proxy_rules + usize::from(analysis.final_return)
    );
    Ok(rules)
}

fn render_direct_clause(
    program: &CaptureDomainProgram,
    clause: &CaptureClause,
    chain: &str,
    rules: &mut Vec<String>,
) -> Result<(), XtablesCaptureLoweringError> {
    match clause.predicate() {
        CapturePredicate::Any => rules.push(format!("-A {chain} -j RETURN")),
        CapturePredicate::EngineCredentials(credentials) => rules.push(format!(
            "-A {chain} -m owner --uid-owner {} --gid-owner {} -j RETURN",
            credentials.uid().get(),
            credentials.gid().get()
        )),
        CapturePredicate::DestinationPrefixes(prefixes) => {
            for prefix in prefixes {
                rules.push(format!("-A {chain} -d {prefix} -j RETURN"));
            }
        }
        CapturePredicate::DestinationHosts(hosts) => {
            for host in hosts {
                let prefix_length = match host {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                rules.push(format!("-A {chain} -d {host}/{prefix_length} -j RETURN"));
            }
        }
        CapturePredicate::InterfaceMatches {
            direction,
            selectors,
        } => {
            let option = interface_option(*direction);
            for selector in selectors.iter().copied() {
                rules.push(format!(
                    "-A {chain} {option} {} -j RETURN",
                    render_interface_selector(program, selector)?
                ));
            }
        }
        CapturePredicate::LocalUidIn(uids) => {
            for uid in uids {
                rules.push(format!(
                    "-A {chain} -m owner --uid-owner {} -j RETURN",
                    uid.get()
                ));
            }
        }
        CapturePredicate::InterfaceDoesNotMatch { .. }
        | CapturePredicate::LocalUidNotIn(_)
        | CapturePredicate::ProtocolNotIn(_) => return Err(invalid_clause(program, clause)),
    }
    Ok(())
}

fn render_proxy_rules(
    program: &CaptureDomainProgram,
    scope: &ProxyScope<'_>,
    protocols: CaptureProtocolSet,
    chain: &str,
    target: XtablesTproxyTarget,
    rules: &mut Vec<String>,
) -> Result<(), XtablesCaptureLoweringError> {
    match scope {
        ProxyScope::All => {
            for protocol in enabled_protocols(protocols) {
                rules.push(render_proxy_rule(program, chain, &[], protocol, target)?);
            }
        }
        ProxyScope::InputInterfaces(selectors) => {
            for selector in selectors.iter().copied() {
                let rendered = render_interface_selector(program, selector)?;
                let interface = ["-i", rendered.as_str()];
                for protocol in enabled_protocols(protocols) {
                    rules.push(render_proxy_rule(
                        program, chain, &interface, protocol, target,
                    )?);
                }
            }
        }
        ProxyScope::OutputUids(uids) => {
            for uid in uids.iter().copied() {
                let uid = uid.get().to_string();
                let owner = ["-m", "owner", "--uid-owner", uid.as_str()];
                for protocol in enabled_protocols(protocols) {
                    rules.push(render_proxy_rule(program, chain, &owner, protocol, target)?);
                }
            }
        }
    }
    Ok(())
}

fn render_proxy_rule(
    program: &CaptureDomainProgram,
    chain: &str,
    prefix_arguments: &[&str],
    protocol: CaptureTransportProtocol,
    target: XtablesTproxyTarget,
) -> Result<String, XtablesCaptureLoweringError> {
    let mut rule = format!("-A {chain}");
    for argument in prefix_arguments {
        rule.push(' ');
        rule.push_str(argument);
    }
    rule.push_str(" -p ");
    rule.push_str(protocol_token(protocol));
    match program.domain() {
        CaptureTrafficDomain::LocalOutput => {
            rule.push_str(" -j MARK --set-xmark ");
            rule.push_str(&mark_token(
                target.mark().proxy_value(),
                target.mark().mask(),
            ));
        }
        CaptureTrafficDomain::ForwardedIngress => {
            rule.push_str(" -j TPROXY --on-port ");
            rule.push_str(&target.proxy_port().get().to_string());
            rule.push_str(" --tproxy-mark ");
            rule.push_str(&mark_token(
                target.mark().proxy_value(),
                target.mark().mask(),
            ));
        }
    }
    Ok(rule)
}

fn render_loopback_companion(
    chain: &str,
    protocols: CaptureProtocolSet,
    target: XtablesTproxyTarget,
) -> Vec<String> {
    let mut rules = Vec::with_capacity(protocol_count(protocols) + 1);
    for protocol in enabled_protocols(protocols) {
        rules.push(format!(
            "-A {chain} -p {} -j TPROXY --on-port {} --tproxy-mark {}",
            protocol_token(protocol),
            target.proxy_port().get(),
            mark_token(target.mark().proxy_value(), target.mark().mask())
        ));
    }
    rules.push(format!("-A {chain} -j RETURN"));
    rules
}

fn build_local_output_requirements(
    family: NetworkAddressFamily,
    engine_credentials: EngineCredentials,
    protocols: CaptureProtocolSet,
    routing: XtablesLocalOutputRoutingTarget,
    target: XtablesTproxyTarget,
) -> XtablesLocalOutputTransactionRequirements {
    let restore_family = restore_family(family);
    let bind_address = match family {
        NetworkAddressFamily::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        NetworkAddressFamily::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let route_scope = match family {
        NetworkAddressFamily::Ipv4 => RouteScope::from_raw(LINUX_ROUTE_SCOPE_HOST),
        NetworkAddressFamily::Ipv6 => RouteScope::from_raw(LINUX_ROUTE_SCOPE_UNIVERSE),
    };
    XtablesLocalOutputTransactionRequirements {
        routing: XtablesLocalOutputRoutingRequirement {
            family: restore_family,
            target: routing,
            route_destination: bind_address,
            route_prefix_length: 0,
            route_scope,
            route_type: RouteType::from_raw(LINUX_ROUTE_TYPE_LOCAL),
            mark: target.mark().selector(FwmarkRole::Proxy),
            loopback_interface: loopback_interface(),
        },
        listener: XtablesTransparentListenerRequirement {
            family: restore_family,
            bind_address,
            port: target.proxy_port(),
            protocols,
        },
        loop_escape: XtablesLoopEscapeRequirement {
            engine_credentials,
            socket_mark: target.mark().selector(FwmarkRole::Bypass),
        },
    }
}

fn build_transaction_order(
    entries: &[XtablesCaptureEntryPoint],
    has_local_requirements: bool,
) -> XtablesCaptureTransactionOrder {
    let mut prepare = entries
        .iter()
        .map(|entry| XtablesCaptureTransactionStep::PrepareEntryPoint(entry.role()))
        .collect::<Vec<_>>();
    if has_local_requirements {
        prepare.extend([
            XtablesCaptureTransactionStep::PrepareTransparentListener,
            XtablesCaptureTransactionStep::PreparePolicyRouting,
            XtablesCaptureTransactionStep::PrepareLoopEscape,
        ]);
    }
    for role in [
        XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy,
        XtablesCaptureEntryPointRole::ForwardedIngress,
        XtablesCaptureEntryPointRole::LocalOutputClassifier,
    ] {
        if entries.iter().any(|entry| entry.role() == role) {
            prepare.push(XtablesCaptureTransactionStep::AttachEntryPoint(role));
        }
    }

    let mut retire = Vec::new();
    for role in [
        XtablesCaptureEntryPointRole::LocalOutputClassifier,
        XtablesCaptureEntryPointRole::ForwardedIngress,
        XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy,
    ] {
        if entries.iter().any(|entry| entry.role() == role) {
            retire.push(XtablesCaptureTransactionStep::DetachEntryPoint(role));
        }
    }
    if has_local_requirements {
        retire.extend([
            XtablesCaptureTransactionStep::RetireLoopEscape,
            XtablesCaptureTransactionStep::RetirePolicyRouting,
            XtablesCaptureTransactionStep::RetireTransparentListener,
        ]);
    }
    retire.extend(
        entries
            .iter()
            .rev()
            .map(|entry| XtablesCaptureTransactionStep::RetireEntryPoint(entry.role())),
    );

    XtablesCaptureTransactionOrder {
        prepare: prepare.into_boxed_slice(),
        retire: retire.into_boxed_slice(),
    }
}

fn render_interface_selector(
    program: &CaptureDomainProgram,
    selector: CaptureInterfaceSelector,
) -> Result<String, XtablesCaptureLoweringError> {
    validate_interface_selector(program, selector)?;
    let name = selector.name();
    let base =
        std::str::from_utf8(name.as_bytes()).expect("validated xtables interface bytes are ASCII");
    Ok(match selector.kind() {
        CaptureInterfaceSelectorKind::Exact => base.to_owned(),
        CaptureInterfaceSelectorKind::Prefix => format!("{base}+"),
    })
}

fn interface_option(direction: CaptureInterfaceDirection) -> &'static str {
    match direction {
        CaptureInterfaceDirection::Input => "-i",
        CaptureInterfaceDirection::Output => "-o",
    }
}

fn enabled_protocols(
    protocols: CaptureProtocolSet,
) -> impl Iterator<Item = CaptureTransportProtocol> {
    [CaptureTransportProtocol::Tcp, CaptureTransportProtocol::Udp]
        .into_iter()
        .filter(move |protocol| protocols.contains(*protocol))
}

fn protocol_count(protocols: CaptureProtocolSet) -> usize {
    enabled_protocols(protocols).count()
}

fn protocol_token(protocol: CaptureTransportProtocol) -> &'static str {
    match protocol {
        CaptureTransportProtocol::Tcp => "tcp",
        CaptureTransportProtocol::Udp => "udp",
        CaptureTransportProtocol::Other => unreachable!("Other is never proxy-eligible"),
    }
}

fn mark_token(value: u32, mask: u32) -> String {
    format!("0x{value:x}/0x{mask:x}")
}

fn prepare_byte_count(chains: &[RenderedChain]) -> usize {
    b"*mangle\nCOMMIT\n".len()
        + chains
            .iter()
            .map(|chain| b":".len() + chain.name.len() + b" - [0:0]\n".len())
            .sum::<usize>()
        + chains
            .iter()
            .flat_map(|chain| &chain.rules)
            .map(|rule| rule.len() + 1)
            .sum::<usize>()
}

fn retire_byte_count(chains: &[RenderedChain]) -> usize {
    b"*mangle\nCOMMIT\n".len()
        + chains
            .iter()
            .map(|chain| b"-F \n-X \n".len() + (chain.name.len() * 2))
            .sum::<usize>()
}

fn render_prepare(chains: &[RenderedChain], capacity: usize) -> String {
    let mut output = String::with_capacity(capacity);
    output.push_str("*mangle\n");
    for chain in chains {
        output.push(':');
        output.push_str(&chain.name);
        output.push_str(" - [0:0]\n");
    }
    for chain in chains {
        for rule in &chain.rules {
            output.push_str(rule);
            output.push('\n');
        }
    }
    output.push_str("COMMIT\n");
    debug_assert_eq!(output.len(), capacity);
    output
}

fn render_retire(chains: &[RenderedChain], capacity: usize) -> String {
    let mut output = String::with_capacity(capacity);
    output.push_str("*mangle\n");
    for chain in chains {
        output.push_str("-F ");
        output.push_str(&chain.name);
        output.push('\n');
    }
    for chain in chains {
        output.push_str("-X ");
        output.push_str(&chain.name);
        output.push('\n');
    }
    output.push_str("COMMIT\n");
    debug_assert_eq!(output.len(), capacity);
    output
}

fn parse_lowered_artifact(
    bytes: &[u8],
    context: XtablesRestoreContext,
) -> Result<XtablesRestoreArtifact, XtablesCaptureLoweringError> {
    parse_xtables_restore(bytes, context).map_err(|source| {
        XtablesCaptureLoweringError::InvalidRenderedArtifact {
            family: context.family(),
            action: context.action(),
            source,
        }
    })
}

fn ensure_command_budget(
    family: XtablesRestoreFamily,
    action: XtablesRestoreAction,
    budget: XtablesCaptureLoweringBudget,
    required: usize,
) -> Result<(), XtablesCaptureLoweringError> {
    if required <= budget.commands_per_artifact() {
        Ok(())
    } else {
        Err(XtablesCaptureLoweringError::CommandBudgetExceeded {
            family,
            action,
            maximum: budget.commands_per_artifact(),
            required,
        })
    }
}

fn ensure_byte_limit(
    family: XtablesRestoreFamily,
    action: XtablesRestoreAction,
    required: usize,
) -> Result<(), XtablesCaptureLoweringError> {
    if required <= MAX_XTABLES_RESTORE_BYTES {
        Ok(())
    } else {
        Err(XtablesCaptureLoweringError::ArtifactByteLimitExceeded {
            family,
            action,
            maximum: MAX_XTABLES_RESTORE_BYTES,
            required,
        })
    }
}

fn capture_chain_name(
    family: NetworkAddressFamily,
    role: XtablesCaptureEntryPointRole,
    generation: GenerationId,
) -> Box<str> {
    let role = match role {
        XtablesCaptureEntryPointRole::LocalOutputClassifier => 'O',
        XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy => 'P',
        XtablesCaptureEntryPointRole::ForwardedIngress => 'F',
    };
    format!("FLX{}{role}{:010}", family_tag(family), generation.get()).into_boxed_str()
}

fn digest_lowering(request: XtablesCaptureLoweringRequest<'_>) -> XtablesCaptureLoweringDigest {
    let mut digest = Sha256::new();
    digest.update(LOWERING_DIGEST_DOMAIN);
    digest.update(XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION.to_be_bytes());
    digest.update(request.program.schema_version().to_be_bytes());
    digest.update(request.program.digest().as_bytes());
    digest.update(request.namespace.generation().get().to_be_bytes());
    digest.update(request.target.proxy_port().get().to_be_bytes());
    digest.update(request.target.mark().mask().to_be_bytes());
    digest.update(request.target.mark().proxy_value().to_be_bytes());
    digest.update(request.target.mark().bypass_value().to_be_bytes());
    digest.update([request.extensions.bits()]);
    digest_routing_spec(&mut digest, request.local_output_routing);
    XtablesCaptureLoweringDigest(digest.finalize().into())
}

struct PairDigestInput<'a> {
    lowering: XtablesCaptureLoweringDigest,
    family: XtablesRestoreFamily,
    entries: &'a [XtablesCaptureEntryPoint],
    local_output: Option<XtablesLocalOutputTransactionRequirements>,
    transaction_order: &'a XtablesCaptureTransactionOrder,
    prepare: &'a XtablesRestoreArtifact,
    retire: &'a XtablesRestoreArtifact,
    usage: XtablesCaptureResourceUsage,
}

fn digest_pair(input: PairDigestInput<'_>) -> XtablesCaptureArtifactPairDigest {
    let mut digest = Sha256::new();
    digest.update(PAIR_DIGEST_DOMAIN);
    digest.update(XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION.to_be_bytes());
    digest.update(input.lowering.as_bytes());
    digest.update([restore_family_tag(input.family)]);
    digest.update(length_bytes(input.entries.len()));
    for entry in input.entries {
        digest.update([domain_tag(entry.domain)]);
        digest.update(length_bytes(entry.chain.len()));
        digest.update(entry.chain.as_bytes());
        digest.update([entry_role_tag(entry.role), hook_tag(entry.hook)]);
        digest_entry_selector(&mut digest, entry.selector);
    }
    digest_local_output_requirements(&mut digest, input.local_output);
    digest_transaction_order(&mut digest, input.transaction_order);
    digest_restore_artifact(&mut digest, input.prepare);
    digest_restore_artifact(&mut digest, input.retire);
    digest_usage(&mut digest, input.usage);
    XtablesCaptureArtifactPairDigest(digest.finalize().into())
}

fn digest_set(
    lowering: XtablesCaptureLoweringDigest,
    ipv4: Option<&XtablesCaptureArtifactPair>,
    ipv6: Option<&XtablesCaptureArtifactPair>,
    usage: XtablesCaptureResourceUsage,
) -> XtablesCaptureArtifactSetDigest {
    let mut digest = Sha256::new();
    digest.update(SET_DIGEST_DOMAIN);
    digest.update(XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION.to_be_bytes());
    digest.update(lowering.as_bytes());
    for pair in [ipv4, ipv6] {
        match pair {
            Some(pair) => {
                digest.update([1, restore_family_tag(pair.family)]);
                digest.update(pair.digest.as_bytes());
            }
            None => digest.update([0]),
        }
    }
    digest_usage(&mut digest, usage);
    XtablesCaptureArtifactSetDigest(digest.finalize().into())
}

fn digest_routing_spec(digest: &mut Sha256, routing: Option<XtablesLocalOutputRoutingSpec>) {
    match routing {
        Some(routing) => {
            digest.update([1]);
            for family in [NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6] {
                match routing.routing_for(family) {
                    Some(target) => {
                        digest.update([1, family_tag(family)]);
                        digest_routing_target(digest, target);
                    }
                    None => digest.update([0, family_tag(family)]),
                }
            }
        }
        None => digest.update([0]),
    }
}

fn digest_routing_target(digest: &mut Sha256, target: XtablesLocalOutputRoutingTarget) {
    digest.update(target.priority().get().to_be_bytes());
    digest.update(target.table().get().to_be_bytes());
    digest.update(target.route_metric().get().to_be_bytes());
    digest.update([target.route_protocol().raw()]);
    digest.update([target.rule_protocol().raw()]);
}

fn digest_entry_selector(digest: &mut Sha256, selector: XtablesCaptureEntrySelector) {
    match selector {
        XtablesCaptureEntrySelector::Any => digest.update([0]),
        XtablesCaptureEntrySelector::Mark(mark) => {
            digest.update([1]);
            digest_rule_fwmark(digest, mark);
        }
        XtablesCaptureEntrySelector::InputInterfaceAndMark { interface, mark } => {
            digest.update([2]);
            digest.update(length_bytes(interface.as_bytes().len()));
            digest.update(interface.as_bytes());
            digest_rule_fwmark(digest, mark);
        }
    }
}

fn digest_local_output_requirements(
    digest: &mut Sha256,
    requirements: Option<XtablesLocalOutputTransactionRequirements>,
) {
    let Some(requirements) = requirements else {
        digest.update([0]);
        return;
    };
    digest.update([1]);
    let routing = requirements.routing();
    digest.update([restore_family_tag(routing.family())]);
    digest_routing_target(digest, routing.target());
    digest_ip_addr(digest, routing.route_destination());
    digest.update([routing.route_prefix_length()]);
    digest.update([routing.route_scope().raw()]);
    digest.update([routing.route_type().raw()]);
    digest_rule_fwmark(digest, routing.mark());
    digest.update(length_bytes(routing.loopback_interface().as_bytes().len()));
    digest.update(routing.loopback_interface().as_bytes());

    let listener = requirements.listener();
    digest.update([restore_family_tag(listener.family())]);
    digest_ip_addr(digest, listener.bind_address());
    digest.update(listener.port().get().to_be_bytes());
    digest.update([protocol_bits(listener.protocols())]);

    let escape = requirements.loop_escape();
    digest.update(escape.engine_credentials().uid().get().to_be_bytes());
    digest.update(escape.engine_credentials().gid().get().to_be_bytes());
    digest_rule_fwmark(digest, escape.socket_mark());
}

fn digest_rule_fwmark(digest: &mut Sha256, mark: RuleFwMark) {
    digest.update(mark.value().to_be_bytes());
    digest.update(mark.mask().to_be_bytes());
}

fn digest_transaction_order(digest: &mut Sha256, order: &XtablesCaptureTransactionOrder) {
    digest.update([1]);
    for steps in [order.prepare(), order.retire()] {
        digest.update(length_bytes(steps.len()));
        for step in steps {
            digest_transaction_step(digest, *step);
        }
    }
}

fn digest_transaction_step(digest: &mut Sha256, step: XtablesCaptureTransactionStep) {
    match step {
        XtablesCaptureTransactionStep::PrepareEntryPoint(role) => {
            digest.update([1, entry_role_tag(role)])
        }
        XtablesCaptureTransactionStep::PrepareTransparentListener => digest.update([2]),
        XtablesCaptureTransactionStep::PreparePolicyRouting => digest.update([3]),
        XtablesCaptureTransactionStep::PrepareLoopEscape => digest.update([4]),
        XtablesCaptureTransactionStep::AttachEntryPoint(role) => {
            digest.update([5, entry_role_tag(role)])
        }
        XtablesCaptureTransactionStep::DetachEntryPoint(role) => {
            digest.update([6, entry_role_tag(role)])
        }
        XtablesCaptureTransactionStep::RetireLoopEscape => digest.update([7]),
        XtablesCaptureTransactionStep::RetirePolicyRouting => digest.update([8]),
        XtablesCaptureTransactionStep::RetireTransparentListener => digest.update([9]),
        XtablesCaptureTransactionStep::RetireEntryPoint(role) => {
            digest.update([10, entry_role_tag(role)])
        }
    }
}

fn digest_ip_addr(digest: &mut Sha256, address: IpAddr) {
    match address {
        IpAddr::V4(address) => {
            digest.update([4]);
            digest.update(address.octets());
        }
        IpAddr::V6(address) => {
            digest.update([6]);
            digest.update(address.octets());
        }
    }
}

fn digest_restore_artifact(digest: &mut Sha256, artifact: &XtablesRestoreArtifact) {
    digest.update(artifact.schema_version().to_be_bytes());
    digest.update([match artifact.context().action() {
        XtablesRestoreAction::Apply => 1,
        XtablesRestoreAction::Cleanup => 2,
        XtablesRestoreAction::Replace => 3,
    }]);
    digest.update([restore_family_tag(artifact.context().family())]);
    digest.update(artifact.digest().as_bytes());
    let usage = artifact.usage();
    for value in [
        usage.input_bytes(),
        usage.lines(),
        usage.transactions(),
        usage.chain_declarations(),
        usage.commands(),
        usage.tokens(),
    ] {
        digest.update(length_bytes(value));
    }
}

fn digest_usage(digest: &mut Sha256, usage: XtablesCaptureResourceUsage) {
    for value in [
        usage.domain_programs,
        usage.source_clauses,
        usage.expanded_match_rules,
        usage.implementation_chains,
        usage.prepare_commands,
        usage.retire_commands,
        usage.maximum_jump_depth,
        usage.entry_points,
        usage.listener_requirements,
        usage.routing_objects,
        usage.transaction_steps,
    ] {
        digest.update(length_bytes(value));
    }
}

fn length_bytes(value: usize) -> [u8; 8] {
    u64::try_from(value)
        .expect("xtables lowering resource bounds fit u64")
        .to_be_bytes()
}

fn invalid_clause(
    program: &CaptureDomainProgram,
    clause: &CaptureClause,
) -> XtablesCaptureLoweringError {
    invalid_shape(
        program,
        clause.stage(),
        predicate_kind(clause.predicate()),
        clause.decision(),
    )
}

fn invalid_shape(
    program: &CaptureDomainProgram,
    stage: CaptureDecisionStage,
    predicate: XtablesCapturePredicateKind,
    decision: CaptureClauseDecision,
) -> XtablesCaptureLoweringError {
    XtablesCaptureLoweringError::InvalidProgramShape {
        family: program.family(),
        domain: program.domain(),
        stage,
        predicate,
        decision,
    }
}

fn family_mismatch(program: &CaptureDomainProgram) -> XtablesCaptureLoweringError {
    XtablesCaptureLoweringError::FamilyMismatch {
        family: program.family(),
        domain: program.domain(),
    }
}

fn predicate_kind(predicate: &CapturePredicate) -> XtablesCapturePredicateKind {
    match predicate {
        CapturePredicate::Any => XtablesCapturePredicateKind::Any,
        CapturePredicate::EngineCredentials(_) => XtablesCapturePredicateKind::EngineCredentials,
        CapturePredicate::DestinationPrefixes(_) => {
            XtablesCapturePredicateKind::DestinationPrefixes
        }
        CapturePredicate::DestinationHosts(_) => XtablesCapturePredicateKind::DestinationHosts,
        CapturePredicate::InterfaceMatches { .. } => XtablesCapturePredicateKind::InterfaceMatches,
        CapturePredicate::InterfaceDoesNotMatch { .. } => {
            XtablesCapturePredicateKind::InterfaceDoesNotMatch
        }
        CapturePredicate::LocalUidIn(_) => XtablesCapturePredicateKind::LocalUidIn,
        CapturePredicate::LocalUidNotIn(_) => XtablesCapturePredicateKind::LocalUidNotIn,
        CapturePredicate::ProtocolNotIn(_) => XtablesCapturePredicateKind::ProtocolNotIn,
    }
}

fn is_exact_loopback(selector: &CaptureInterfaceSelector) -> bool {
    selector.kind() == CaptureInterfaceSelectorKind::Exact
        && selector.name() == loopback_interface()
}

fn loopback_interface() -> InterfaceName {
    InterfaceName::new(b"lo").expect("the Linux loopback interface name is valid")
}

const fn address_family(address: IpAddr) -> NetworkAddressFamily {
    match address {
        IpAddr::V4(_) => NetworkAddressFamily::Ipv4,
        IpAddr::V6(_) => NetworkAddressFamily::Ipv6,
    }
}

const fn restore_family(family: NetworkAddressFamily) -> XtablesRestoreFamily {
    match family {
        NetworkAddressFamily::Ipv4 => XtablesRestoreFamily::Ipv4,
        NetworkAddressFamily::Ipv6 => XtablesRestoreFamily::Ipv6,
    }
}

const fn family_tag(family: NetworkAddressFamily) -> u8 {
    match family {
        NetworkAddressFamily::Ipv4 => 4,
        NetworkAddressFamily::Ipv6 => 6,
    }
}

const fn restore_family_tag(family: XtablesRestoreFamily) -> u8 {
    match family {
        XtablesRestoreFamily::Ipv4 => 4,
        XtablesRestoreFamily::Ipv6 => 6,
    }
}

const fn entry_role_tag(role: XtablesCaptureEntryPointRole) -> u8 {
    match role {
        XtablesCaptureEntryPointRole::LocalOutputClassifier => 1,
        XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy => 2,
        XtablesCaptureEntryPointRole::ForwardedIngress => 3,
    }
}

const fn hook_tag(hook: XtablesCaptureHook) -> u8 {
    match hook {
        XtablesCaptureHook::Prerouting => 1,
        XtablesCaptureHook::Output => 2,
    }
}

const fn protocol_bits(protocols: CaptureProtocolSet) -> u8 {
    (protocols.contains(CaptureTransportProtocol::Tcp) as u8)
        | ((protocols.contains(CaptureTransportProtocol::Udp) as u8) << 1)
}

const fn domain_tag(domain: CaptureTrafficDomain) -> u8 {
    match domain {
        CaptureTrafficDomain::LocalOutput => 0,
        CaptureTrafficDomain::ForwardedIngress => 1,
    }
}
