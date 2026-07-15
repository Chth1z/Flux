use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU32};

use flux_core::{
    CaptureClause, CaptureClauseDecision, CaptureDecisionStage, CaptureDomainProgram,
    CaptureInterfaceDirection, CaptureInterfaceSelector, CaptureInterfaceSelectorKind,
    CapturePredicate, CaptureProgramDigest, CaptureProtocolSet, CaptureTrafficDomain,
    CaptureTransportProtocol, FwmarkCandidate, NetworkAddressFamily,
    SHADOW_CAPTURE_PROGRAM_SCHEMA_VERSION, ShadowCaptureArtifact,
};
use sha2::{Digest, Sha256};

use super::{
    MAX_XTABLES_RESTORE_BYTES, MAX_XTABLES_RESTORE_COMMANDS, XtablesRestoreAction,
    XtablesRestoreArtifact, XtablesRestoreContext, XtablesRestoreFamily, XtablesRestoreParseError,
    parse_xtables_restore,
};

/// Schema for deterministic Capture Program to xtables classification lowering.
pub const XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION: u16 = 1;
pub const XTABLES_CAPTURE_DIGEST_BYTES: usize = 32;
pub const MAX_XTABLES_CAPTURE_COMMANDS_PER_ARTIFACT: usize = MAX_XTABLES_RESTORE_COMMANDS;

const LOWERING_DIGEST_DOMAIN: &[u8] =
    b"Flux canonical xtables Capture Program lowering\0schema-v1\0";
const PAIR_DIGEST_DOMAIN: &[u8] =
    b"Flux canonical xtables Capture Program artifact pair\0schema-v1\0";
const SET_DIGEST_DOMAIN: &[u8] =
    b"Flux canonical xtables Capture Program artifact set\0schema-v1\0";

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
/// Schema v1 admits only the all-disabled value. Keeping the omitted semantics typed prevents a
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
    generation: NonZeroU32,
}

impl XtablesCaptureNamespace {
    #[must_use]
    pub const fn new(generation: NonZeroU32) -> Self {
        Self { generation }
    }

    #[must_use]
    pub const fn generation(self) -> NonZeroU32 {
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
    program: &'a ShadowCaptureArtifact,
    namespace: XtablesCaptureNamespace,
    target: XtablesTproxyTarget,
    extensions: XtablesCaptureExtensions,
    budget: XtablesCaptureLoweringBudget,
}

impl<'a> XtablesCaptureLoweringRequest<'a> {
    #[must_use]
    pub const fn new(
        program: &'a ShadowCaptureArtifact,
        namespace: XtablesCaptureNamespace,
        target: XtablesTproxyTarget,
    ) -> Self {
        Self {
            program,
            namespace,
            target,
            extensions: XtablesCaptureExtensions::new(false, false, false, false, false),
            budget: XtablesCaptureLoweringBudget(MAX_XTABLES_CAPTURE_COMMANDS_PER_ARTIFACT),
        }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XtablesCaptureEntryPoint {
    domain: CaptureTrafficDomain,
    chain: Box<str>,
}

impl XtablesCaptureEntryPoint {
    #[must_use]
    pub const fn domain(&self) -> CaptureTrafficDomain {
        self.domain
    }

    #[must_use]
    pub const fn chain(&self) -> &str {
        &self.chain
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XtablesCaptureResourceUsage {
    domain_programs: usize,
    source_clauses: usize,
    expanded_match_rules: usize,
    implementation_chains: usize,
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
        XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION
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
                "xtables Capture Program lowering does not model {extension:?} in schema v1"
            ),
            Self::UnsupportedTrafficDomain { family, domain } => write!(
                formatter,
                "xtables Capture Program lowering cannot realize the {family:?}/{domain:?} domain with the qualified schema-v1 TPROXY mechanism"
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
                "forwarded {family:?} Capture Program lacks its schema-v1 loopback safety clause"
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

/// Lower forwarded-ingress schema-v1 Capture Programs into unattached generation-specific mangle
/// chains. Local OUTPUT is rejected because the currently qualified xtables TPROXY mechanism
/// cannot realize that domain. The result is deterministic and non-authorizing; it cannot execute
/// restore or activate the generated entry chains.
pub fn lower_xtables_capture(
    request: XtablesCaptureLoweringRequest<'_>,
) -> Result<XtablesCaptureArtifactSet, XtablesCaptureLoweringError> {
    if request.program.schema_version() != SHADOW_CAPTURE_PROGRAM_SCHEMA_VERSION {
        return Err(XtablesCaptureLoweringError::UnsupportedProgramSchema {
            actual: request.program.schema_version(),
            supported: SHADOW_CAPTURE_PROGRAM_SCHEMA_VERSION,
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
    if let Some(program) = programs
        .iter()
        .find(|program| program.domain() == CaptureTrafficDomain::LocalOutput)
    {
        return Err(XtablesCaptureLoweringError::UnsupportedTrafficDomain {
            family: program.family(),
            domain: program.domain(),
        });
    }

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
        return Ok(None);
    }

    let analyses = selected
        .iter()
        .copied()
        .map(analyze_program)
        .collect::<Result<Vec<_>, _>>()?;
    let implementation_chains = analyses.len();
    let prepare_commands = analyses
        .iter()
        .map(|analysis| {
            analysis.direct_rules + analysis.proxy_rules + usize::from(analysis.final_return)
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

    let mut entries = Vec::with_capacity(analyses.len());
    let mut chains = Vec::with_capacity(implementation_chains);
    for analysis in &analyses {
        let chain = capture_chain_name(family, request.namespace.generation());
        let rules = render_program(analysis, &chain, request.target)?;
        entries.push(XtablesCaptureEntryPoint {
            domain: analysis.program.domain(),
            chain: chain.clone(),
        });
        chains.push(RenderedChain { name: chain, rules });
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

    let usage = XtablesCaptureResourceUsage {
        domain_programs: analyses.len(),
        source_clauses: analyses
            .iter()
            .map(|analysis| analysis.program.clauses().len())
            .sum(),
        expanded_match_rules: analyses
            .iter()
            .map(|analysis| analysis.direct_rules + analysis.proxy_rules)
            .sum(),
        implementation_chains,
        prepare_commands,
        retire_commands,
        maximum_jump_depth: 1,
    };
    let entries = entries.into_boxed_slice();
    let digest = digest_pair(
        lowering_digest,
        restore_family,
        &entries,
        &prepare,
        &retire,
        usage,
    );
    Ok(Some(XtablesCaptureArtifactPair {
        family: restore_family,
        entries,
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

    match program.domain() {
        CaptureTrafficDomain::LocalOutput => {
            return Err(XtablesCaptureLoweringError::UnsupportedTrafficDomain {
                family: program.family(),
                domain: program.domain(),
            });
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
        }
    }

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
        (None, None) => 0,
        _ => unreachable!("proxy scope and protocol eligibility are discovered together"),
    };

    Ok(ProgramAnalysis {
        program,
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
            if program.domain() == CaptureTrafficDomain::ForwardedIngress
                && clause.stage() == CaptureDecisionStage::InterfaceRole =>
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
            let admitted_stage = program.domain() == CaptureTrafficDomain::ForwardedIngress
                && matches!(
                    clause.stage(),
                    CaptureDecisionStage::MandatorySafety | CaptureDecisionStage::InterfaceRole
                );
            if !admitted_stage {
                return Err(invalid_clause(program, clause));
            }
            for selector in selectors.iter().copied() {
                validate_interface_selector(program, selector)?;
            }
            Ok(selectors.len())
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
        CaptureTrafficDomain::LocalOutput => {
            return Err(XtablesCaptureLoweringError::UnsupportedTrafficDomain {
                family: program.family(),
                domain: program.domain(),
            });
        }
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
        CapturePredicate::EngineCredentials(_) => return Err(invalid_clause(program, clause)),
        CapturePredicate::DestinationPrefixes(prefixes) => {
            for prefix in prefixes {
                rules.push(format!("-A {chain} -d {prefix} -j RETURN"));
            }
        }
        CapturePredicate::DestinationHosts(hosts) => {
            for host in hosts {
                rules.push(format!("-A {chain} -d {host} -j RETURN"));
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
        CapturePredicate::LocalUidIn(_) => return Err(invalid_clause(program, clause)),
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
            return Err(XtablesCaptureLoweringError::UnsupportedTrafficDomain {
                family: program.family(),
                domain: program.domain(),
            });
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

fn capture_chain_name(family: NetworkAddressFamily, generation: NonZeroU32) -> Box<str> {
    format!("FLX{}F{:010}", family_tag(family), generation.get()).into_boxed_str()
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
    XtablesCaptureLoweringDigest(digest.finalize().into())
}

fn digest_pair(
    lowering: XtablesCaptureLoweringDigest,
    family: XtablesRestoreFamily,
    entries: &[XtablesCaptureEntryPoint],
    prepare: &XtablesRestoreArtifact,
    retire: &XtablesRestoreArtifact,
    usage: XtablesCaptureResourceUsage,
) -> XtablesCaptureArtifactPairDigest {
    let mut digest = Sha256::new();
    digest.update(PAIR_DIGEST_DOMAIN);
    digest.update(XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION.to_be_bytes());
    digest.update(lowering.as_bytes());
    digest.update([restore_family_tag(family)]);
    digest.update(length_bytes(entries.len()));
    for entry in entries {
        digest.update([domain_tag(entry.domain)]);
        digest.update(length_bytes(entry.chain.len()));
        digest.update(entry.chain.as_bytes());
    }
    digest_restore_artifact(&mut digest, prepare);
    digest_restore_artifact(&mut digest, retire);
    digest_usage(&mut digest, usage);
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

fn digest_restore_artifact(digest: &mut Sha256, artifact: &XtablesRestoreArtifact) {
    digest.update(artifact.schema_version().to_be_bytes());
    digest.update([match artifact.context().action() {
        XtablesRestoreAction::Apply => 1,
        XtablesRestoreAction::Cleanup => 2,
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
    selector.kind() == CaptureInterfaceSelectorKind::Exact && selector.name().as_bytes() == b"lo"
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

const fn domain_tag(domain: CaptureTrafficDomain) -> u8 {
    match domain {
        CaptureTrafficDomain::LocalOutput => 0,
        CaptureTrafficDomain::ForwardedIngress => 1,
    }
}
