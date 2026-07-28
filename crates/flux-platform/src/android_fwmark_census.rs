use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use flux_core::{
    AndroidNetdSourceProfile, FwmarkCandidate, FwmarkEvidenceSource, FwmarkNetfilterBuiltinHook,
    FwmarkNetfilterChainName, FwmarkOrderedLateWritePlacement, FwmarkOrderedLateWriteQualification,
    FwmarkPacketSelectorDigest, FwmarkPlane, FwmarkUseOperation, FwmarkUseRecord,
    NetworkAddressFamily,
};
use sha2::{Digest, Sha256};

mod assembly;
mod existing_flux;
mod nftables;
mod read_only_netlink;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod system_source;
mod traffic_control_bpf;
mod xfrm;

pub use assembly::{
    ANDROID_FWMARK_CENSUS_COLLECTOR_REVISION, ANDROID_FWMARK_CENSUS_PROJECTION_CELLS,
    ANDROID_FWMARK_CENSUS_PROJECTION_METRICS, AndroidFwmarkCensusAssemblyError,
    AndroidFwmarkCensusCollectionStage, AndroidFwmarkCensusCoordinatorError,
    AndroidFwmarkCensusCoordinatorOutcome, AndroidFwmarkCensusCoordinatorPurpose,
    AndroidFwmarkCensusCoordinatorRequest, AndroidFwmarkCensusCoordinatorRequestError,
    AndroidFwmarkCensusCoordinatorSource, AndroidFwmarkCensusExternalPhase,
    AndroidFwmarkCensusExternalSnapshot, AndroidFwmarkCensusExternalSnapshotDigest,
    AndroidFwmarkCensusMetric, AndroidFwmarkCensusMetricKind, AndroidFwmarkCensusProbeReports,
    AndroidFwmarkCensusProjection, AndroidFwmarkCensusProjectionDigest,
    AndroidFwmarkCensusReportPhase, MAX_ANDROID_FWMARK_CENSUS_STAGE_BOUND,
    assemble_android_fwmark_census_projection, coordinate_android_fwmark_census,
    coordinate_android_fwmark_census_for_inventory, parse_android_fwmark_census_probe_reports,
    validate_android_fwmark_census_probe_reports, validate_android_fwmark_census_projection_report,
    write_android_fwmark_census_projection_report,
};

pub use existing_flux::{
    AndroidExistingFluxOwnershipDigest, AndroidExistingFluxOwnershipError,
    AndroidExistingFluxOwnershipErrorKind, AndroidExistingFluxOwnershipObservation,
    AndroidExistingFluxProcessObservationErrorClass,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use existing_flux::{
    collect_android_existing_flux_ownership,
    collect_android_existing_flux_ownership_for_current_daemon,
};

pub use nftables::{
    AndroidNftablesFwmarkObservation, AndroidNftablesFwmarkObservationError,
    AndroidNftablesFwmarkObservationErrorKind, AndroidNftablesSnapshotDigest,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use traffic_control_bpf::collect_android_traffic_control_bpf_fwmarks;
pub use traffic_control_bpf::{
    AndroidTrafficControlBpfFwmarkObservation, AndroidTrafficControlBpfFwmarkObservationError,
    AndroidTrafficControlBpfFwmarkObservationErrorKind, AndroidTrafficControlBpfSnapshotDigest,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use xfrm::collect_android_xfrm_fwmarks;
pub use xfrm::{
    AndroidXfrmFwmarkObservation, AndroidXfrmFwmarkObservationError,
    AndroidXfrmFwmarkObservationErrorKind, AndroidXfrmSnapshotDigest,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use system_source::{
    SystemAndroidFwmarkCensusSource, SystemAndroidFwmarkCensusSourceError,
    SystemAndroidFwmarkCensusSourceErrorKind, SystemAndroidNftablesObservationErrorClass,
};

const MAX_XTABLES_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_XTABLES_SNAPSHOT_LINES: usize = 65_536;
const MAX_XTABLES_LINE_BYTES: usize = 8 * 1024;
const MAX_XTABLES_TOKENS_PER_RULE: usize = 256;
const MAX_XTABLES_TOKEN_BYTES: usize = 1_024;
const MAX_XTABLES_TABLES: usize = 32;
const MAX_XTABLES_CHAINS_PER_TABLE: usize = 16_384;
const MAX_XTABLES_RULES: usize = 32_768;
const ROUTECTRL_INPUT_CHAIN: &str = "routectrl_mangle_INPUT";
const ANDROID_12_13_INCOMING_PACKET_FWMARK_MASK: u32 = 0xffef_ffff;
const ANDROID_2025_INCOMING_PACKET_FWMARK_MASK: u32 = 0x7fef_ffff;
const XTABLES_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
    b"Flux complete external xtables fwmark snapshot\0canonical-schema-v1\0sha256-v1\0";
const XTABLES_ORDERED_SELECTOR_DIGEST_DOMAIN: &[u8] =
    b"Flux ordered xtables packet selector\0canonical-schema-v1\0sha256-v1\0";

/// Canonical counter-independent digest of one complete dual-stack xtables observation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AndroidXtablesSnapshotDigest([u8; 32]);

impl AndroidXtablesSnapshotDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Bounded, non-authorizing projection of complete IPv4 and IPv6 xtables-save snapshots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidXtablesFwmarkObservation {
    digest: AndroidXtablesSnapshotDigest,
    netd_source_profile: AndroidNetdSourceProfile,
    candidate: FwmarkCandidate,
    legacy_mark_uses: Box<[FwmarkUseRecord]>,
    transfer_mark_uses: Box<[FwmarkUseRecord]>,
    ordered_late_writes: Box<[FwmarkOrderedLateWriteQualification]>,
    table_count: usize,
    chain_count: usize,
    rule_count: usize,
    flux_owned_chain_count: usize,
}

impl AndroidXtablesFwmarkObservation {
    #[must_use]
    pub const fn digest(&self) -> AndroidXtablesSnapshotDigest {
        self.digest
    }

    #[must_use]
    pub const fn netd_source_profile(&self) -> AndroidNetdSourceProfile {
        self.netd_source_profile
    }

    #[must_use]
    pub const fn candidate(&self) -> FwmarkCandidate {
        self.candidate
    }

    #[must_use]
    pub fn legacy_mark_uses(&self) -> &[FwmarkUseRecord] {
        &self.legacy_mark_uses
    }

    #[must_use]
    pub fn transfer_mark_uses(&self) -> &[FwmarkUseRecord] {
        &self.transfer_mark_uses
    }

    #[must_use]
    pub fn ordered_late_writes(&self) -> &[FwmarkOrderedLateWriteQualification] {
        &self.ordered_late_writes
    }

    #[must_use]
    pub const fn table_count(&self) -> usize {
        self.table_count
    }

    #[must_use]
    pub const fn chain_count(&self) -> usize {
        self.chain_count
    }

    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rule_count
    }

    #[must_use]
    pub const fn flux_owned_chain_count(&self) -> usize {
        self.flux_owned_chain_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidXtablesFwmarkObservationErrorKind {
    EmptyInput,
    LimitExceeded,
    MissingFinalLineFeed,
    NonAscii,
    InvalidLine,
    InvalidQuotedToken,
    NestedTable,
    DuplicateTable,
    DuplicateChain,
    UndeclaredRuleSource,
    MissingCommit,
    UnknownMarkSemantics,
    InvalidMarkValue,
    InvalidAndroidIncomingWriter,
    InvalidOrderedWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidXtablesFwmarkObservationError {
    family: NetworkAddressFamily,
    line: Option<usize>,
    kind: AndroidXtablesFwmarkObservationErrorKind,
}

impl AndroidXtablesFwmarkObservationError {
    #[must_use]
    pub const fn family(self) -> NetworkAddressFamily {
        self.family
    }

    #[must_use]
    pub const fn line(self) -> Option<usize> {
        self.line
    }

    #[must_use]
    pub const fn kind(self) -> AndroidXtablesFwmarkObservationErrorKind {
        self.kind
    }

    const fn global(
        family: NetworkAddressFamily,
        kind: AndroidXtablesFwmarkObservationErrorKind,
    ) -> Self {
        Self {
            family,
            line: None,
            kind,
        }
    }

    const fn at_line(
        family: NetworkAddressFamily,
        line: usize,
        kind: AndroidXtablesFwmarkObservationErrorKind,
    ) -> Self {
        Self {
            family,
            line: Some(line),
            kind,
        }
    }
}

impl fmt::Display for AndroidXtablesFwmarkObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid complete {:?} xtables fwmark snapshot",
            self.family
        )?;
        if let Some(line) = self.line {
            write!(formatter, " at line {line}")?;
        }
        write!(formatter, ": {:?}", self.kind)
    }
}

impl Error for AndroidXtablesFwmarkObservationError {}

/// Parses complete dual-stack `iptables-save` output without granting planning or mutation.
///
/// Packet MARK reads/writes remain attributed to legacy xtables except for the exact pinned
/// Android incoming-writer grammar. CONNMARK and socket-mark copies are emitted under their
/// separate transfer source. Ordered records are emitted only when every occurrence represented by
/// the overlapping canonical mark-use record has a valid late placement.
pub fn observe_android_xtables_fwmarks(
    ipv4: &[u8],
    ipv6: &[u8],
    profile: AndroidNetdSourceProfile,
    candidate: FwmarkCandidate,
) -> Result<AndroidXtablesFwmarkObservation, AndroidXtablesFwmarkObservationError> {
    let ipv4 = parse_ruleset(ipv4, NetworkAddressFamily::Ipv4)?;
    let ipv6 = parse_ruleset(ipv6, NetworkAddressFamily::Ipv6)?;
    let mut legacy_mark_uses = BTreeSet::new();
    let mut transfer_mark_uses = BTreeSet::new();
    let mut ordered_late_writes = Vec::new();

    for ruleset in [&ipv4, &ipv6] {
        let evidence = ruleset.observe_marks(profile, candidate)?;
        legacy_mark_uses.extend(evidence.legacy_mark_uses);
        transfer_mark_uses.extend(evidence.transfer_mark_uses);
        ordered_late_writes.extend(evidence.ordered_late_writes);
    }
    ordered_late_writes.sort_unstable();
    if ordered_late_writes
        .windows(2)
        .any(|records| records[0] == records[1])
    {
        return Err(AndroidXtablesFwmarkObservationError::global(
            NetworkAddressFamily::Ipv4,
            AndroidXtablesFwmarkObservationErrorKind::InvalidOrderedWrite,
        ));
    }

    let mut digest = Sha256::new();
    digest.update(XTABLES_SNAPSHOT_DIGEST_DOMAIN);
    digest.update([netd_source_profile_tag(profile)]);
    digest.update(candidate.mask().to_be_bytes());
    digest.update(candidate.proxy_value().to_be_bytes());
    digest.update(candidate.bypass_value().to_be_bytes());
    digest.update(ipv4.canonical_digest());
    digest.update(ipv6.canonical_digest());
    let table_count = ipv4.tables.len() + ipv6.tables.len();
    let chain_count = ipv4.chain_count() + ipv6.chain_count();
    let rule_count = ipv4.rule_count() + ipv6.rule_count();
    let flux_owned_chain_count = ipv4.flux_owned_chain_count() + ipv6.flux_owned_chain_count();

    Ok(AndroidXtablesFwmarkObservation {
        digest: AndroidXtablesSnapshotDigest(digest.finalize().into()),
        netd_source_profile: profile,
        candidate,
        legacy_mark_uses: legacy_mark_uses.into_iter().collect(),
        transfer_mark_uses: transfer_mark_uses.into_iter().collect(),
        ordered_late_writes: ordered_late_writes.into_boxed_slice(),
        table_count,
        chain_count,
        rule_count,
        flux_owned_chain_count,
    })
}

const fn netd_source_profile_tag(profile: AndroidNetdSourceProfile) -> u8 {
    match profile {
        AndroidNetdSourceProfile::AospAndroid12R1 => 0,
        AndroidNetdSourceProfile::AospAndroid13R1 => 1,
        AndroidNetdSourceProfile::AospNetd20250324 => 2,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedRuleset {
    family: NetworkAddressFamily,
    tables: BTreeMap<Box<str>, ParsedTable>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedTable {
    chains: BTreeMap<Box<str>, ChainPolicy>,
    rules: BTreeMap<Box<str>, Vec<ParsedRule>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ChainPolicy(Box<str>);

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedRule {
    line: usize,
    ordinal: u32,
    tokens: Box<[Box<str>]>,
}

#[derive(Clone, Debug)]
struct TableBuilder {
    name: Box<str>,
    chains: BTreeMap<Box<str>, ChainPolicy>,
    rules: BTreeMap<Box<str>, Vec<ParsedRule>>,
}

impl TableBuilder {
    fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            chains: BTreeMap::new(),
            rules: BTreeMap::new(),
        }
    }

    fn finish(self) -> (Box<str>, ParsedTable) {
        (
            self.name,
            ParsedTable {
                chains: self.chains,
                rules: self.rules,
            },
        )
    }
}

fn parse_ruleset(
    input: &[u8],
    family: NetworkAddressFamily,
) -> Result<ParsedRuleset, AndroidXtablesFwmarkObservationError> {
    validate_snapshot_bytes(input, family)?;
    let text = std::str::from_utf8(input).expect("validated ASCII is UTF-8");
    let mut tables = BTreeMap::new();
    let mut current: Option<TableBuilder> = None;
    let mut rule_count = 0_usize;

    for (index, line) in text[..text.len() - 1].split('\n').enumerate() {
        let line_number = index + 1;
        if line.len() > MAX_XTABLES_LINE_BYTES {
            return Err(AndroidXtablesFwmarkObservationError::at_line(
                family,
                line_number,
                AndroidXtablesFwmarkObservationErrorKind::LimitExceeded,
            ));
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('*') {
            if current.is_some() {
                return Err(AndroidXtablesFwmarkObservationError::at_line(
                    family,
                    line_number,
                    AndroidXtablesFwmarkObservationErrorKind::NestedTable,
                ));
            }
            if !valid_name(name) || tables.contains_key(name) || tables.len() == MAX_XTABLES_TABLES
            {
                return Err(AndroidXtablesFwmarkObservationError::at_line(
                    family,
                    line_number,
                    if tables.contains_key(name) {
                        AndroidXtablesFwmarkObservationErrorKind::DuplicateTable
                    } else {
                        AndroidXtablesFwmarkObservationErrorKind::InvalidLine
                    },
                ));
            }
            current = Some(TableBuilder::new(name));
            continue;
        }
        if line == "COMMIT" {
            let table = current.take().ok_or_else(|| {
                AndroidXtablesFwmarkObservationError::at_line(
                    family,
                    line_number,
                    AndroidXtablesFwmarkObservationErrorKind::InvalidLine,
                )
            })?;
            let (name, table) = table.finish();
            tables.insert(name, table);
            continue;
        }
        let table = current.as_mut().ok_or_else(|| {
            AndroidXtablesFwmarkObservationError::at_line(
                family,
                line_number,
                AndroidXtablesFwmarkObservationErrorKind::InvalidLine,
            )
        })?;
        if line.starts_with(':') {
            parse_chain_declaration(table, line, family, line_number)?;
        } else {
            parse_rule(table, line, family, line_number, &mut rule_count)?;
        }
    }
    if current.is_some() {
        return Err(AndroidXtablesFwmarkObservationError::global(
            family,
            AndroidXtablesFwmarkObservationErrorKind::MissingCommit,
        ));
    }
    if tables.is_empty() {
        return Err(AndroidXtablesFwmarkObservationError::global(
            family,
            AndroidXtablesFwmarkObservationErrorKind::InvalidLine,
        ));
    }
    Ok(ParsedRuleset { family, tables })
}

fn validate_snapshot_bytes(
    input: &[u8],
    family: NetworkAddressFamily,
) -> Result<(), AndroidXtablesFwmarkObservationError> {
    if input.is_empty() {
        return Err(AndroidXtablesFwmarkObservationError::global(
            family,
            AndroidXtablesFwmarkObservationErrorKind::EmptyInput,
        ));
    }
    if input.len() > MAX_XTABLES_SNAPSHOT_BYTES
        || input.iter().filter(|byte| **byte == b'\n').count() > MAX_XTABLES_SNAPSHOT_LINES
    {
        return Err(AndroidXtablesFwmarkObservationError::global(
            family,
            AndroidXtablesFwmarkObservationErrorKind::LimitExceeded,
        ));
    }
    if input.last() != Some(&b'\n') {
        return Err(AndroidXtablesFwmarkObservationError::global(
            family,
            AndroidXtablesFwmarkObservationErrorKind::MissingFinalLineFeed,
        ));
    }
    if input
        .iter()
        .copied()
        .any(|byte| byte != b'\n' && !(b' '..=b'~').contains(&byte))
    {
        return Err(AndroidXtablesFwmarkObservationError::global(
            family,
            AndroidXtablesFwmarkObservationErrorKind::NonAscii,
        ));
    }
    Ok(())
}

fn parse_chain_declaration(
    table: &mut TableBuilder,
    line: &str,
    family: NetworkAddressFamily,
    line_number: usize,
) -> Result<(), AndroidXtablesFwmarkObservationError> {
    if table.chains.len() == MAX_XTABLES_CHAINS_PER_TABLE {
        return Err(AndroidXtablesFwmarkObservationError::at_line(
            family,
            line_number,
            AndroidXtablesFwmarkObservationErrorKind::LimitExceeded,
        ));
    }
    let parts = line.split_ascii_whitespace().collect::<Vec<_>>();
    let chain = parts
        .first()
        .and_then(|part| part.strip_prefix(':'))
        .unwrap_or_default();
    if parts.len() != 3
        || !valid_name(chain)
        || !valid_policy(parts.get(1).copied().unwrap_or_default())
        || !valid_counter(parts.get(2).copied().unwrap_or_default())
    {
        return Err(AndroidXtablesFwmarkObservationError::at_line(
            family,
            line_number,
            AndroidXtablesFwmarkObservationErrorKind::InvalidLine,
        ));
    }
    if table
        .chains
        .insert(chain.into(), ChainPolicy(parts[1].into()))
        .is_some()
    {
        return Err(AndroidXtablesFwmarkObservationError::at_line(
            family,
            line_number,
            AndroidXtablesFwmarkObservationErrorKind::DuplicateChain,
        ));
    }
    Ok(())
}

fn parse_rule(
    table: &mut TableBuilder,
    line: &str,
    family: NetworkAddressFamily,
    line_number: usize,
    total_rules: &mut usize,
) -> Result<(), AndroidXtablesFwmarkObservationError> {
    if *total_rules == MAX_XTABLES_RULES {
        return Err(AndroidXtablesFwmarkObservationError::at_line(
            family,
            line_number,
            AndroidXtablesFwmarkObservationErrorKind::LimitExceeded,
        ));
    }
    let mut tokens = tokenize(line, family, line_number)?;
    if tokens.first().map(String::as_str) == Some("-c") {
        if tokens.len() < 5 || !valid_decimal(&tokens[1]) || !valid_decimal(&tokens[2]) {
            return Err(AndroidXtablesFwmarkObservationError::at_line(
                family,
                line_number,
                AndroidXtablesFwmarkObservationErrorKind::InvalidLine,
            ));
        }
        tokens.drain(0..3);
    }
    if tokens.len() < 2 || tokens[0] != "-A" || !valid_name(&tokens[1]) {
        return Err(AndroidXtablesFwmarkObservationError::at_line(
            family,
            line_number,
            AndroidXtablesFwmarkObservationErrorKind::InvalidLine,
        ));
    }
    let source = tokens[1].clone();
    if !table.chains.contains_key(source.as_str()) {
        return Err(AndroidXtablesFwmarkObservationError::at_line(
            family,
            line_number,
            AndroidXtablesFwmarkObservationErrorKind::UndeclaredRuleSource,
        ));
    }
    let rules = table.rules.entry(source.into_boxed_str()).or_default();
    let ordinal = u32::try_from(rules.len() + 1).map_err(|_| {
        AndroidXtablesFwmarkObservationError::at_line(
            family,
            line_number,
            AndroidXtablesFwmarkObservationErrorKind::LimitExceeded,
        )
    })?;
    rules.push(ParsedRule {
        line: line_number,
        ordinal,
        tokens: tokens
            .into_iter()
            .skip(2)
            .map(String::into_boxed_str)
            .collect(),
    });
    *total_rules += 1;
    Ok(())
}

fn tokenize(
    line: &str,
    family: NetworkAddressFamily,
    line_number: usize,
) -> Result<Vec<String>, AndroidXtablesFwmarkObservationError> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if character == active {
                quote = None;
            } else {
                current.push(character);
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            ' ' | '\t' => {
                if !current.is_empty() {
                    push_token(&mut tokens, &mut current, family, line_number)?;
                }
            }
            _ => current.push(character),
        }
    }
    if escaped || quote.is_some() {
        return Err(AndroidXtablesFwmarkObservationError::at_line(
            family,
            line_number,
            AndroidXtablesFwmarkObservationErrorKind::InvalidQuotedToken,
        ));
    }
    if !current.is_empty() {
        push_token(&mut tokens, &mut current, family, line_number)?;
    }
    if tokens.is_empty() {
        return Err(AndroidXtablesFwmarkObservationError::at_line(
            family,
            line_number,
            AndroidXtablesFwmarkObservationErrorKind::InvalidLine,
        ));
    }
    Ok(tokens)
}

fn push_token(
    tokens: &mut Vec<String>,
    current: &mut String,
    family: NetworkAddressFamily,
    line_number: usize,
) -> Result<(), AndroidXtablesFwmarkObservationError> {
    if tokens.len() == MAX_XTABLES_TOKENS_PER_RULE || current.len() > MAX_XTABLES_TOKEN_BYTES {
        return Err(AndroidXtablesFwmarkObservationError::at_line(
            family,
            line_number,
            AndroidXtablesFwmarkObservationErrorKind::LimitExceeded,
        ));
    }
    tokens.push(std::mem::take(current));
    Ok(())
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'+')
        })
}

fn valid_policy(value: &str) -> bool {
    value == "-" || valid_name(value)
}

fn valid_counter(value: &str) -> bool {
    value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.split_once(':'))
        .is_some_and(|(packets, bytes)| valid_decimal(packets) && valid_decimal(bytes))
}

fn valid_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[derive(Default)]
struct FamilyMarkEvidence {
    legacy_mark_uses: BTreeSet<FwmarkUseRecord>,
    transfer_mark_uses: BTreeSet<FwmarkUseRecord>,
    ordered_late_writes: Vec<FwmarkOrderedLateWriteQualification>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuleMarkSemantics {
    packet_predicate_mask: Option<u32>,
    packet_write_mask: Option<u32>,
    packet_write_value: Option<u32>,
    target: Option<MarkTarget>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MutationSemantics {
    present: bool,
    write: Option<(u32, u32)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MarkTarget {
    Mark,
    Tproxy,
    Hmark,
}

#[derive(Clone)]
struct WriteOccurrence<'a> {
    mark_use: FwmarkUseRecord,
    table: &'a str,
    chain: &'a str,
    rule: &'a ParsedRule,
    qualification: Option<FwmarkOrderedLateWriteQualification>,
}

impl ParsedRuleset {
    fn observe_marks(
        &self,
        profile: AndroidNetdSourceProfile,
        candidate: FwmarkCandidate,
    ) -> Result<FamilyMarkEvidence, AndroidXtablesFwmarkObservationError> {
        let mut evidence = FamilyMarkEvidence::default();
        let mut writes = Vec::new();
        let mut transfer_overlap = false;

        for (table_name, table) in &self.tables {
            for (chain, rules) in &table.rules {
                for rule in rules {
                    let parsed = self.rule_mark_semantics(rule)?;
                    if let Some(mask) = parsed.packet_predicate_mask {
                        evidence.legacy_mark_uses.insert(mark_use(
                            FwmarkEvidenceSource::LegacyXtables,
                            FwmarkPlane::Packet,
                            FwmarkUseOperation::PredicateRead,
                            mask,
                            self.family,
                            rule.line,
                        )?);
                    }
                    let transfers = self.rule_transfer_semantics(rule)?;
                    transfer_overlap |= transfers
                        .iter()
                        .any(|record| record.mask() & candidate.mask() != 0);
                    evidence.transfer_mark_uses.extend(transfers);

                    let Some(mask) = parsed.packet_write_mask else {
                        continue;
                    };
                    let android_incoming =
                        table_name.as_ref() == "mangle" && chain.as_ref() == ROUTECTRL_INPUT_CHAIN;
                    let source = if android_incoming {
                        self.validate_android_incoming_writer(rule, parsed, profile, candidate)?;
                        FwmarkEvidenceSource::AndroidNetId
                    } else {
                        FwmarkEvidenceSource::LegacyXtables
                    };
                    let use_record = mark_use(
                        source,
                        FwmarkPlane::Packet,
                        FwmarkUseOperation::MaskedWrite,
                        mask,
                        self.family,
                        rule.line,
                    )?;
                    if source == FwmarkEvidenceSource::LegacyXtables {
                        evidence.legacy_mark_uses.insert(use_record);
                    }
                    writes.push(WriteOccurrence {
                        mark_use: use_record,
                        table: table_name,
                        chain,
                        rule,
                        qualification: None,
                    });
                }
            }
        }

        for occurrence in &mut writes {
            if occurrence.mark_use.mask() & candidate.mask() == 0 {
                continue;
            }
            occurrence.qualification =
                if occurrence.mark_use.source() == FwmarkEvidenceSource::AndroidNetId {
                    self.qualify_ordered_write(
                        occurrence,
                        FwmarkNetfilterBuiltinHook::Input,
                        FwmarkOrderedLateWritePlacement::InputAfterRouting,
                        transfer_overlap,
                        candidate,
                    )?
                } else {
                    self.qualify_ordered_write(
                        occurrence,
                        FwmarkNetfilterBuiltinHook::Postrouting,
                        FwmarkOrderedLateWritePlacement::PostroutingAfterFinalFluxUse,
                        transfer_overlap,
                        candidate,
                    )?
                };
        }

        let mut by_mark_use: BTreeMap<FwmarkUseRecord, Vec<&WriteOccurrence<'_>>> = BTreeMap::new();
        for occurrence in &writes {
            if occurrence.mark_use.mask() & candidate.mask() != 0 {
                by_mark_use
                    .entry(occurrence.mark_use)
                    .or_default()
                    .push(occurrence);
            }
        }
        for occurrences in by_mark_use.values() {
            if occurrences
                .iter()
                .all(|occurrence| occurrence.qualification.is_some())
            {
                evidence.ordered_late_writes.extend(
                    occurrences
                        .iter()
                        .filter_map(|occurrence| occurrence.qualification.clone()),
                );
            }
        }
        Ok(evidence)
    }

    fn rule_mark_semantics(
        &self,
        rule: &ParsedRule,
    ) -> Result<RuleMarkSemantics, AndroidXtablesFwmarkObservationError> {
        let tokens = &rule.tokens;
        let modules = option_values(tokens, &["-m", "--match"], self.family, rule.line)?;
        let targets = option_values(
            tokens,
            &["-j", "--jump", "-g", "--goto"],
            self.family,
            rule.line,
        )?;
        if targets.len() > 1 {
            return Err(self.error_at(
                rule.line,
                AndroidXtablesFwmarkObservationErrorKind::UnknownMarkSemantics,
            ));
        }
        let target = targets.first().map(String::as_str);
        validate_mark_option_context(tokens, &modules, target, self.family, rule.line)?;
        let mut packet_predicate_mask = None;
        for (index, token) in tokens.iter().enumerate() {
            if token.as_ref() != "--mark" {
                continue;
            }
            let value = tokens.get(index + 1).ok_or_else(|| {
                self.error_at(
                    rule.line,
                    AndroidXtablesFwmarkObservationErrorKind::InvalidMarkValue,
                )
            })?;
            if modules.iter().any(|module| module == "connmark") {
                continue;
            }
            if !modules.iter().any(|module| module == "mark") {
                return Err(self.error_at(
                    rule.line,
                    AndroidXtablesFwmarkObservationErrorKind::UnknownMarkSemantics,
                ));
            }
            let (_, mask) = parse_mark_pair(value, u32::MAX).ok_or_else(|| {
                self.error_at(
                    rule.line,
                    AndroidXtablesFwmarkObservationErrorKind::InvalidMarkValue,
                )
            })?;
            if mask != 0 {
                merge_single_mask(&mut packet_predicate_mask, mask).map_err(|()| {
                    self.error_at(
                        rule.line,
                        AndroidXtablesFwmarkObservationErrorKind::UnknownMarkSemantics,
                    )
                })?;
            }
        }

        let mut packet_write_mask = None;
        let mut packet_write_value = None;
        let mark_target = match target {
            Some("MARK") => Some(MarkTarget::Mark),
            Some("TPROXY") => Some(MarkTarget::Tproxy),
            Some("HMARK") => Some(MarkTarget::Hmark),
            _ => None,
        };
        if let Some(mark_target) = mark_target {
            let mutation = match mark_target {
                MarkTarget::Mark => {
                    let mutation = parse_mutation(tokens, rule.line, self.family)?;
                    if !mutation.present {
                        return Err(self.error_at(
                            rule.line,
                            AndroidXtablesFwmarkObservationErrorKind::UnknownMarkSemantics,
                        ));
                    }
                    mutation.write
                }
                MarkTarget::Tproxy => parse_named_mark(tokens, "--tproxy-mark").map_err(|()| {
                    self.error_at(
                        rule.line,
                        AndroidXtablesFwmarkObservationErrorKind::InvalidMarkValue,
                    )
                })?,
                MarkTarget::Hmark => Some((0, u32::MAX)),
            };
            if let Some((value, mask)) = mutation.filter(|(_, mask)| *mask != 0) {
                packet_write_value = Some(value);
                packet_write_mask = Some(mask);
            }
        }

        Ok(RuleMarkSemantics {
            packet_predicate_mask,
            packet_write_mask,
            packet_write_value,
            target: mark_target,
        })
    }

    fn rule_transfer_semantics(
        &self,
        rule: &ParsedRule,
    ) -> Result<Vec<FwmarkUseRecord>, AndroidXtablesFwmarkObservationError> {
        let tokens = &rule.tokens;
        let modules = option_values(tokens, &["-m", "--match"], self.family, rule.line)?;
        let targets = option_values(
            tokens,
            &["-j", "--jump", "-g", "--goto"],
            self.family,
            rule.line,
        )?;
        let target = targets.first().map(String::as_str);
        let mut records = Vec::new();

        if modules.iter().any(|module| module == "connmark") {
            for (index, token) in tokens.iter().enumerate() {
                if token.as_ref() == "--mark" {
                    let (_, mask) = tokens
                        .get(index + 1)
                        .and_then(|value| parse_mark_pair(value, u32::MAX))
                        .ok_or_else(|| {
                            self.error_at(
                                rule.line,
                                AndroidXtablesFwmarkObservationErrorKind::InvalidMarkValue,
                            )
                        })?;
                    push_mark_use_if_nonzero(
                        &mut records,
                        FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
                        FwmarkPlane::Conntrack,
                        FwmarkUseOperation::PredicateRead,
                        mask,
                        self.family,
                        rule.line,
                    )?;
                }
            }
        }

        if tokens
            .iter()
            .any(|token| token.as_ref() == "--restore-skmark")
        {
            if !modules.iter().any(|module| module == "socket") {
                return Err(self.error_at(
                    rule.line,
                    AndroidXtablesFwmarkObservationErrorKind::UnknownMarkSemantics,
                ));
            }
            records.push(mark_use(
                FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
                FwmarkPlane::Socket,
                FwmarkUseOperation::TransferRead,
                u32::MAX,
                self.family,
                rule.line,
            )?);
            records.push(mark_use(
                FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
                FwmarkPlane::Packet,
                FwmarkUseOperation::TransferWrite,
                u32::MAX,
                self.family,
                rule.line,
            )?);
        }

        if target == Some("CONNMARK") {
            let invalid_mask = |()| {
                self.error_at(
                    rule.line,
                    AndroidXtablesFwmarkObservationErrorKind::InvalidMarkValue,
                )
            };
            let nfmask = parse_named_u32(tokens, "--nfmask")
                .map_err(invalid_mask)?
                .unwrap_or(u32::MAX);
            let ctmask = parse_named_u32(tokens, "--ctmask")
                .map_err(invalid_mask)?
                .unwrap_or(u32::MAX);
            let save = count_token(tokens, "--save-mark");
            let restore = count_token(tokens, "--restore-mark");
            let mutation = parse_mutation(tokens, rule.line, self.family)?;
            if save + restore + usize::from(mutation.present) != 1 {
                return Err(self.error_at(
                    rule.line,
                    AndroidXtablesFwmarkObservationErrorKind::UnknownMarkSemantics,
                ));
            }
            if save == 1 {
                push_mark_use_if_nonzero(
                    &mut records,
                    FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
                    FwmarkPlane::Packet,
                    FwmarkUseOperation::TransferRead,
                    nfmask,
                    self.family,
                    rule.line,
                )?;
                push_mark_use_if_nonzero(
                    &mut records,
                    FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
                    FwmarkPlane::Conntrack,
                    FwmarkUseOperation::TransferWrite,
                    ctmask,
                    self.family,
                    rule.line,
                )?;
            } else if restore == 1 {
                push_mark_use_if_nonzero(
                    &mut records,
                    FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
                    FwmarkPlane::Conntrack,
                    FwmarkUseOperation::TransferRead,
                    ctmask,
                    self.family,
                    rule.line,
                )?;
                push_mark_use_if_nonzero(
                    &mut records,
                    FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
                    FwmarkPlane::Packet,
                    FwmarkUseOperation::TransferWrite,
                    nfmask,
                    self.family,
                    rule.line,
                )?;
            } else if let Some((_, mask)) = mutation.write {
                records.push(mark_use(
                    FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
                    FwmarkPlane::Conntrack,
                    FwmarkUseOperation::MaskedWrite,
                    mask,
                    self.family,
                    rule.line,
                )?);
            }
        }
        Ok(records)
    }

    fn validate_android_incoming_writer(
        &self,
        rule: &ParsedRule,
        parsed: RuleMarkSemantics,
        profile: AndroidNetdSourceProfile,
        candidate: FwmarkCandidate,
    ) -> Result<(), AndroidXtablesFwmarkObservationError> {
        let expected_mask = incoming_packet_fwmark_mask(profile);
        let tokens = rule.tokens.iter().map(AsRef::as_ref).collect::<Vec<_>>();
        let valid_shape = tokens.len() == 6
            && tokens[0] == "-i"
            && valid_interface(tokens[1])
            && matches!(tokens[2], "-j" | "--jump")
            && tokens[3] == "MARK"
            && matches!(tokens[4], "--set-xmark" | "--set-mark")
            && parsed.target == Some(MarkTarget::Mark)
            && parsed.packet_write_mask == Some(expected_mask)
            && parsed
                .packet_write_value
                .is_some_and(|value| value & !expected_mask == 0)
            && parsed
                .packet_write_value
                .is_some_and(|value| value & candidate.mask() == 0);
        if valid_shape {
            Ok(())
        } else {
            Err(self.error_at(
                rule.line,
                AndroidXtablesFwmarkObservationErrorKind::InvalidAndroidIncomingWriter,
            ))
        }
    }

    fn qualify_ordered_write(
        &self,
        occurrence: &WriteOccurrence<'_>,
        hook: FwmarkNetfilterBuiltinHook,
        placement: FwmarkOrderedLateWritePlacement,
        transfer_overlap: bool,
        candidate: FwmarkCandidate,
    ) -> Result<Option<FwmarkOrderedLateWriteQualification>, AndroidXtablesFwmarkObservationError>
    {
        if occurrence.table != "mangle" || transfer_overlap {
            return Ok(None);
        }
        let builtin = match hook {
            FwmarkNetfilterBuiltinHook::Input => "INPUT",
            FwmarkNetfilterBuiltinHook::Postrouting => "POSTROUTING",
        };
        let references = self.references_to(occurrence.chain);
        if references.len() != 1 {
            return Ok(None);
        }
        let (table, chain, reference) = references[0];
        if table != "mangle" || chain != builtin {
            return Ok(None);
        }
        if hook == FwmarkNetfilterBuiltinHook::Input
            && !is_unconditional_jump(reference, occurrence.chain)
        {
            return Ok(None);
        }
        if self.has_earlier_overlapping_write(
            table,
            chain,
            reference.ordinal,
            candidate.mask(),
            occurrence.rule,
        )? || self.has_earlier_overlapping_write(
            occurrence.table,
            occurrence.chain,
            occurrence.rule.ordinal,
            candidate.mask(),
            occurrence.rule,
        )? {
            return Ok(None);
        }

        let selector_digest = ordered_selector_digest(
            self.family,
            hook,
            occurrence.chain,
            reference,
            occurrence.rule,
        );
        let record = FwmarkOrderedLateWriteQualification::new(
            occurrence.mark_use,
            self.family,
            hook,
            FwmarkNetfilterChainName::new(occurrence.chain).map_err(|_| {
                self.error_at(
                    occurrence.rule.line,
                    AndroidXtablesFwmarkObservationErrorKind::InvalidOrderedWrite,
                )
            })?,
            reference.ordinal,
            occurrence.rule.ordinal,
            FwmarkPacketSelectorDigest::new(selector_digest).map_err(|_| {
                self.error_at(
                    occurrence.rule.line,
                    AndroidXtablesFwmarkObservationErrorKind::InvalidOrderedWrite,
                )
            })?,
            placement,
            false,
            false,
            false,
        )
        .map_err(|_| {
            self.error_at(
                occurrence.rule.line,
                AndroidXtablesFwmarkObservationErrorKind::InvalidOrderedWrite,
            )
        })?;
        Ok(Some(record))
    }

    fn references_to(&self, target: &str) -> Vec<(&str, &str, &ParsedRule)> {
        let mut references = Vec::new();
        for (table_name, table) in &self.tables {
            for (chain, rules) in &table.rules {
                for rule in rules {
                    if rule_targets(rule, target) {
                        references.push((table_name.as_ref(), chain.as_ref(), rule));
                    }
                }
            }
        }
        references
    }

    fn has_earlier_overlapping_write(
        &self,
        table: &str,
        chain: &str,
        ordinal: u32,
        candidate_mask: u32,
        current_rule: &ParsedRule,
    ) -> Result<bool, AndroidXtablesFwmarkObservationError> {
        let rules = self
            .tables
            .get(table)
            .and_then(|table| table.rules.get(chain))
            .map(Vec::as_slice)
            .unwrap_or_default();
        for rule in rules.iter().take_while(|rule| rule.ordinal < ordinal) {
            if self
                .rule_mark_semantics(rule)?
                .packet_write_mask
                .is_some_and(|mask| mask & candidate_mask != 0)
                && !rules_have_disjoint_exact_interfaces(rule, current_rule)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn canonical_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(XTABLES_SNAPSHOT_DIGEST_DOMAIN);
        digest.update([family_tag(self.family)]);
        digest_usize(&mut digest, self.tables.len());
        for (table_name, table) in &self.tables {
            digest_text(&mut digest, table_name);
            digest_usize(&mut digest, table.chains.len());
            for (chain, policy) in &table.chains {
                digest_text(&mut digest, chain);
                digest_text(&mut digest, &policy.0);
            }
            digest_usize(&mut digest, table.rules.len());
            for (chain, rules) in &table.rules {
                digest_text(&mut digest, chain);
                digest_usize(&mut digest, rules.len());
                for rule in rules {
                    digest.u32(rule.ordinal);
                    digest_usize(&mut digest, rule.tokens.len());
                    for token in &rule.tokens {
                        digest_text(&mut digest, token);
                    }
                }
            }
        }
        digest.finalize().into()
    }

    fn chain_count(&self) -> usize {
        self.tables.values().map(|table| table.chains.len()).sum()
    }

    fn rule_count(&self) -> usize {
        self.tables
            .values()
            .flat_map(|table| table.rules.values())
            .map(Vec::len)
            .sum()
    }

    fn flux_owned_chain_count(&self) -> usize {
        self.tables
            .values()
            .flat_map(|table| table.chains.keys())
            .filter(|chain| crate::xtables::is_flux_owned_chain(chain))
            .count()
    }

    const fn error_at(
        &self,
        line: usize,
        kind: AndroidXtablesFwmarkObservationErrorKind,
    ) -> AndroidXtablesFwmarkObservationError {
        AndroidXtablesFwmarkObservationError::at_line(self.family, line, kind)
    }
}

fn incoming_packet_fwmark_mask(profile: AndroidNetdSourceProfile) -> u32 {
    match profile {
        AndroidNetdSourceProfile::AospAndroid12R1 | AndroidNetdSourceProfile::AospAndroid13R1 => {
            ANDROID_12_13_INCOMING_PACKET_FWMARK_MASK
        }
        AndroidNetdSourceProfile::AospNetd20250324 => ANDROID_2025_INCOMING_PACKET_FWMARK_MASK,
    }
}

fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value != "lo"
        && !value.bytes().any(|byte| matches!(byte, b'!' | b'+' | b'*'))
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'@')
        })
}

fn option_values(
    tokens: &[Box<str>],
    names: &[&str],
    family: NetworkAddressFamily,
    line: usize,
) -> Result<Vec<String>, AndroidXtablesFwmarkObservationError> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if names.contains(&tokens[index].as_ref()) {
            let value = tokens.get(index + 1).ok_or_else(|| {
                AndroidXtablesFwmarkObservationError::at_line(
                    family,
                    line,
                    AndroidXtablesFwmarkObservationErrorKind::UnknownMarkSemantics,
                )
            })?;
            values.push(value.to_string());
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(values)
}

fn parse_mutation(
    tokens: &[Box<str>],
    line: usize,
    family: NetworkAddressFamily,
) -> Result<MutationSemantics, AndroidXtablesFwmarkObservationError> {
    let mut mutation = MutationSemantics::default();
    for (index, token) in tokens.iter().enumerate() {
        let token = token.as_ref();
        let Some(default_mask) = (match token {
            "--set-xmark" | "--set-mark" => Some(u32::MAX),
            "--and-mark" | "--or-mark" | "--xor-mark" => Some(0),
            _ => None,
        }) else {
            continue;
        };
        if mutation.present {
            return Err(AndroidXtablesFwmarkObservationError::at_line(
                family,
                line,
                AndroidXtablesFwmarkObservationErrorKind::UnknownMarkSemantics,
            ));
        }
        let raw = tokens.get(index + 1).ok_or_else(|| {
            AndroidXtablesFwmarkObservationError::at_line(
                family,
                line,
                AndroidXtablesFwmarkObservationErrorKind::InvalidMarkValue,
            )
        })?;
        let write = match token {
            "--and-mark" | "--or-mark" | "--xor-mark" => {
                let raw_value = parse_u32(raw).ok_or_else(|| {
                    AndroidXtablesFwmarkObservationError::at_line(
                        family,
                        line,
                        AndroidXtablesFwmarkObservationErrorKind::InvalidMarkValue,
                    )
                })?;
                let (value, mask) = match token {
                    "--and-mark" => (0, !raw_value),
                    "--or-mark" | "--xor-mark" => (raw_value, raw_value),
                    _ => unreachable!("scalar mutation token matched above"),
                };
                (mask != 0).then_some((value, mask))
            }
            "--set-xmark" | "--set-mark" => {
                let (value, supplied_mask) =
                    parse_mark_pair(raw, default_mask).ok_or_else(|| {
                        AndroidXtablesFwmarkObservationError::at_line(
                            family,
                            line,
                            AndroidXtablesFwmarkObservationErrorKind::InvalidMarkValue,
                        )
                    })?;
                let mask = supplied_mask | value;
                (mask != 0).then_some((value, mask))
            }
            _ => unreachable!("mutation token matched above"),
        };
        mutation = MutationSemantics {
            present: true,
            write,
        };
    }
    Ok(mutation)
}

fn parse_named_mark(tokens: &[Box<str>], name: &str) -> Result<Option<(u32, u32)>, ()> {
    let values = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| (token.as_ref() == name).then_some(index))
        .collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(None),
        [index] => tokens
            .get(index + 1)
            .and_then(|value| parse_mark_pair(value, u32::MAX))
            .map(|(value, mask)| (value, mask | value))
            .ok_or(())
            .map(Some),
        _ => Err(()),
    }
}

fn parse_named_u32(tokens: &[Box<str>], name: &str) -> Result<Option<u32>, ()> {
    let values = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| (token.as_ref() == name).then_some(index))
        .collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(None),
        [index] => tokens
            .get(index + 1)
            .and_then(|value| parse_u32(value))
            .ok_or(())
            .map(Some),
        _ => Err(()),
    }
}

fn parse_mark_pair(value: &str, default_mask: u32) -> Option<(u32, u32)> {
    let (value, mask) = value
        .split_once('/')
        .map_or((value, None), |(value, mask)| (value, Some(mask)));
    let value = parse_u32(value)?;
    let mask = mask.map_or(Some(default_mask), parse_u32)?;
    Some((value, mask))
}

fn validate_mark_option_context(
    tokens: &[Box<str>],
    modules: &[String],
    target: Option<&str>,
    family: NetworkAddressFamily,
    line: usize,
) -> Result<(), AndroidXtablesFwmarkObservationError> {
    let has_mark_match = modules.iter().any(|module| module == "mark");
    let has_connmark_match = modules.iter().any(|module| module == "connmark");
    let has_socket_match = modules.iter().any(|module| module == "socket");
    let invalid = || {
        AndroidXtablesFwmarkObservationError::at_line(
            family,
            line,
            AndroidXtablesFwmarkObservationErrorKind::UnknownMarkSemantics,
        )
    };

    if has_mark_match && has_connmark_match {
        return Err(invalid());
    }
    let predicate_count = count_token(tokens, "--mark");
    if (has_mark_match || has_connmark_match) != (predicate_count == 1) {
        return Err(invalid());
    }

    for token in tokens {
        let token = token.as_ref();
        let valid = match token {
            "--mark" => has_mark_match || has_connmark_match,
            "--set-xmark" | "--set-mark" | "--and-mark" | "--or-mark" | "--xor-mark" => {
                matches!(target, Some("MARK" | "CONNMARK"))
            }
            "--tproxy-mark" => target == Some("TPROXY"),
            "--restore-skmark" => has_socket_match,
            "--nfmask" | "--ctmask" | "--save-mark" | "--restore-mark" => {
                target == Some("CONNMARK")
            }
            "--hmark-tuple" | "--hmark-mod" | "--hmark-offset" | "--hmark-rnd" => {
                target == Some("HMARK")
            }
            _ => !unknown_mark_option(token),
        };
        if !valid {
            return Err(invalid());
        }
    }
    Ok(())
}

fn unknown_mark_option(token: &str) -> bool {
    token.starts_with("--")
        && token
            .as_bytes()
            .windows(4)
            .any(|window| window.eq_ignore_ascii_case(b"mark"))
}

fn parse_u32(value: &str) -> Option<u32> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse::<u32>().ok(),
            |hex| {
                (!hex.is_empty())
                    .then(|| u32::from_str_radix(hex, 16).ok())
                    .flatten()
            },
        )
}

fn merge_single_mask(target: &mut Option<u32>, mask: u32) -> Result<(), ()> {
    if target.replace(mask).is_some() {
        Err(())
    } else {
        Ok(())
    }
}

fn count_token(tokens: &[Box<str>], expected: &str) -> usize {
    tokens
        .iter()
        .filter(|token| token.as_ref() == expected)
        .count()
}

fn rules_have_disjoint_exact_interfaces(left: &ParsedRule, right: &ParsedRule) -> bool {
    [
        &["-i", "--in-interface"][..],
        &["-o", "--out-interface"][..],
    ]
    .into_iter()
    .any(|names| {
        let left = exact_positive_option(&left.tokens, names);
        let right = exact_positive_option(&right.tokens, names);
        matches!((left, right), (Some(left), Some(right)) if left != right)
    })
}

fn exact_positive_option<'a>(tokens: &'a [Box<str>], names: &[&str]) -> Option<&'a str> {
    let matches = tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| names.contains(&token.as_ref()))
        .collect::<Vec<_>>();
    let [(index, _)] = matches.as_slice() else {
        return None;
    };
    if *index > 0 && tokens[*index - 1].as_ref() == "!" {
        return None;
    }
    tokens
        .get(*index + 1)
        .map(AsRef::as_ref)
        .filter(|value: &&str| !value.contains('+') && valid_interface(value))
}

fn mark_use(
    source: FwmarkEvidenceSource,
    plane: FwmarkPlane,
    operation: FwmarkUseOperation,
    mask: u32,
    family: NetworkAddressFamily,
    line: usize,
) -> Result<FwmarkUseRecord, AndroidXtablesFwmarkObservationError> {
    FwmarkUseRecord::new(source, plane, operation, mask).map_err(|_| {
        AndroidXtablesFwmarkObservationError::at_line(
            family,
            line,
            AndroidXtablesFwmarkObservationErrorKind::InvalidMarkValue,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn push_mark_use_if_nonzero(
    records: &mut Vec<FwmarkUseRecord>,
    source: FwmarkEvidenceSource,
    plane: FwmarkPlane,
    operation: FwmarkUseOperation,
    mask: u32,
    family: NetworkAddressFamily,
    line: usize,
) -> Result<(), AndroidXtablesFwmarkObservationError> {
    if mask != 0 {
        records.push(mark_use(source, plane, operation, mask, family, line)?);
    }
    Ok(())
}

fn rule_targets(rule: &ParsedRule, expected: &str) -> bool {
    rule.tokens.windows(2).any(|pair| {
        matches!(pair[0].as_ref(), "-j" | "--jump" | "-g" | "--goto")
            && pair[1].as_ref() == expected
    })
}

fn is_unconditional_jump(rule: &ParsedRule, target: &str) -> bool {
    rule.tokens.len() == 2
        && matches!(rule.tokens[0].as_ref(), "-j" | "--jump")
        && rule.tokens[1].as_ref() == target
}

fn ordered_selector_digest(
    family: NetworkAddressFamily,
    hook: FwmarkNetfilterBuiltinHook,
    child_chain: &str,
    hook_rule: &ParsedRule,
    child_rule: &ParsedRule,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(XTABLES_ORDERED_SELECTOR_DIGEST_DOMAIN);
    digest.update([family_tag(family)]);
    digest.update([match hook {
        FwmarkNetfilterBuiltinHook::Input => 1,
        FwmarkNetfilterBuiltinHook::Postrouting => 2,
    }]);
    digest_text(&mut digest, child_chain);
    digest.u32(hook_rule.ordinal);
    digest_tokens(&mut digest, &hook_rule.tokens);
    digest.u32(child_rule.ordinal);
    digest_tokens(&mut digest, &child_rule.tokens);
    digest.finalize().into()
}

fn family_tag(family: NetworkAddressFamily) -> u8 {
    match family {
        NetworkAddressFamily::Ipv4 => 4,
        NetworkAddressFamily::Ipv6 => 6,
    }
}

fn digest_tokens(digest: &mut Sha256, tokens: &[Box<str>]) {
    digest_usize(digest, tokens.len());
    for token in tokens {
        digest_text(digest, token);
    }
}

fn digest_text(digest: &mut Sha256, value: &str) {
    digest_usize(digest, value.len());
    digest.update(value.as_bytes());
}

fn digest_usize(digest: &mut Sha256, value: usize) {
    digest.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
}

trait DigestU32 {
    fn u32(&mut self, value: u32);
}

impl DigestU32 for Sha256 {
    fn u32(&mut self, value: u32) {
        self.update(value.to_be_bytes());
    }
}

#[cfg(test)]
mod tests;
