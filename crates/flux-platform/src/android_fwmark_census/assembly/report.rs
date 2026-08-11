use std::io::{self, Write};

use flux_core::{
    FwmarkCensusCoverageState, FwmarkEvidenceSource, FwmarkNetfilterBuiltinHook,
    FwmarkOrderedLateWritePlacement, FwmarkPlane, FwmarkUseOperation,
    MAX_COMPLETE_FWMARK_CENSUS_MARK_USES, MAX_EXACT_MARK_SENTINEL_QUALIFICATIONS,
    MAX_FWMARK_NETFILTER_CHAIN_NAME_BYTES, MAX_ORDERED_LATE_PACKET_WRITES, NetworkAddressFamily,
};

use super::{
    ALL_PLANES, ALL_SOURCES, ANDROID_FWMARK_CENSUS_PROJECTION_CELLS,
    ANDROID_FWMARK_CENSUS_PROJECTION_METRICS, AndroidFwmarkCensusMetricKind,
    AndroidFwmarkCensusProjection,
};

const REPORT_AUTHORITY: &str = "read_only_fwmark_census_diagnostic_no_mutation_authority";
const REPORT_SCHEMA_VERSION: u8 = 2;
const PRIMARY_REPORT_BEGIN: &str = "FLUX_ANDROID_FWMARK_CENSUS_PRIMARY_BEGIN";
const PRIMARY_REPORT_END: &str = "FLUX_ANDROID_FWMARK_CENSUS_PRIMARY_END";
const CLEANUP_REPORT_BEGIN: &str = "FLUX_ANDROID_FWMARK_CENSUS_CLEANUP_BEGIN";
const CLEANUP_REPORT_END: &str = "FLUX_ANDROID_FWMARK_CENSUS_CLEANUP_END";
const MAX_REPORT_BYTES: usize = 240 * 1024;

const ALL_METRIC_KINDS: [AndroidFwmarkCensusMetricKind; ANDROID_FWMARK_CENSUS_PROJECTION_METRICS] = [
    AndroidFwmarkCensusMetricKind::InventoryLinks,
    AndroidFwmarkCensusMetricKind::InventoryAddresses,
    AndroidFwmarkCensusMetricKind::InventoryRoutes,
    AndroidFwmarkCensusMetricKind::InventoryRules,
    AndroidFwmarkCensusMetricKind::XtablesTables,
    AndroidFwmarkCensusMetricKind::XtablesChains,
    AndroidFwmarkCensusMetricKind::XtablesRules,
    AndroidFwmarkCensusMetricKind::XtablesFluxOwnedChains,
    AndroidFwmarkCensusMetricKind::NftablesKernelSupported,
    AndroidFwmarkCensusMetricKind::NftablesTables,
    AndroidFwmarkCensusMetricKind::NftablesChains,
    AndroidFwmarkCensusMetricKind::NftablesRules,
    AndroidFwmarkCensusMetricKind::NftablesExpressions,
    AndroidFwmarkCensusMetricKind::NftablesOpaqueExpressions,
    AndroidFwmarkCensusMetricKind::TrafficControlAttachedFilters,
    AndroidFwmarkCensusMetricKind::BpfLoadedPrograms,
    AndroidFwmarkCensusMetricKind::BpfRelevantPrograms,
    AndroidFwmarkCensusMetricKind::BpfInaccessiblePrograms,
    AndroidFwmarkCensusMetricKind::BpfOpaquePrograms,
    AndroidFwmarkCensusMetricKind::BpfInstructions,
    AndroidFwmarkCensusMetricKind::XfrmKernelSupported,
    AndroidFwmarkCensusMetricKind::XfrmStates,
    AndroidFwmarkCensusMetricKind::XfrmPolicies,
    AndroidFwmarkCensusMetricKind::XfrmMarkAttributes,
    AndroidFwmarkCensusMetricKind::XfrmOpaqueAttributes,
    AndroidFwmarkCensusMetricKind::ExistingFluxDurableRootPresent,
    AndroidFwmarkCensusMetricKind::ExistingFluxEmptyTargetArchivePresent,
    AndroidFwmarkCensusMetricKind::ExistingFluxDurableArtifacts,
    AndroidFwmarkCensusMetricKind::ExistingFluxArchivedTargets,
    AndroidFwmarkCensusMetricKind::ExistingFluxProcesses,
    AndroidFwmarkCensusMetricKind::ExistingFluxChains,
    AndroidFwmarkCensusMetricKind::ExistingFluxRoutes,
    AndroidFwmarkCensusMetricKind::ExistingFluxRules,
    AndroidFwmarkCensusMetricKind::RawMarkUses,
    AndroidFwmarkCensusMetricKind::CanonicalMarkUses,
    AndroidFwmarkCensusMetricKind::OrderedLateWrites,
];

// Container presence is diagnostic evidence; exact artifacts and live state carry ownership.
const EXISTING_FLUX_OWNERSHIP_METRIC_KINDS: [AndroidFwmarkCensusMetricKind; 6] = [
    AndroidFwmarkCensusMetricKind::ExistingFluxDurableArtifacts,
    AndroidFwmarkCensusMetricKind::ExistingFluxArchivedTargets,
    AndroidFwmarkCensusMetricKind::ExistingFluxProcesses,
    AndroidFwmarkCensusMetricKind::ExistingFluxChains,
    AndroidFwmarkCensusMetricKind::ExistingFluxRoutes,
    AndroidFwmarkCensusMetricKind::ExistingFluxRules,
];

/// Identifies one of the two ordered reports emitted by the diagnostic probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidFwmarkCensusReportPhase {
    Primary,
    Cleanup,
}

impl AndroidFwmarkCensusReportPhase {
    const fn markers(self) -> (&'static str, &'static str) {
        match self {
            Self::Primary => (PRIMARY_REPORT_BEGIN, PRIMARY_REPORT_END),
            Self::Cleanup => (CLEANUP_REPORT_BEGIN, CLEANUP_REPORT_END),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Cleanup => "cleanup",
        }
    }
}

/// Writes one canonical, bounded, privacy-reduced diagnostic projection report.
pub fn write_android_fwmark_census_projection_report(
    output: &mut impl Write,
    phase: AndroidFwmarkCensusReportPhase,
    projection: &AndroidFwmarkCensusProjection,
) -> io::Result<()> {
    let (begin, end) = phase.markers();
    writeln!(output, "{begin}")?;
    writeln!(output, "authority={REPORT_AUTHORITY}")?;
    writeln!(output, "schema_version={REPORT_SCHEMA_VERSION}")?;
    writeln!(
        output,
        "cell_count={ANDROID_FWMARK_CENSUS_PROJECTION_CELLS}"
    )?;
    writeln!(output, "mark_use_count={}", projection.mark_uses().len())?;
    writeln!(
        output,
        "ordered_write_count={}",
        projection.ordered_late_writes().len()
    )?;
    writeln!(
        output,
        "exact_mark_sentinel_count={}",
        projection.exact_mark_sentinels().len()
    )?;
    writeln!(
        output,
        "metric_count={ANDROID_FWMARK_CENSUS_PROJECTION_METRICS}"
    )?;
    for cell in projection.cells() {
        writeln!(
            output,
            "cell={}|{}|{}",
            source_label(cell.source()),
            plane_label(cell.plane()),
            coverage_label(cell.state())
        )?;
    }
    for mark_use in projection.mark_uses() {
        writeln!(
            output,
            "mark_use={}|{}|{}|0x{:08x}",
            source_label(mark_use.source()),
            plane_label(mark_use.plane()),
            operation_label(mark_use.operation()),
            mark_use.mask()
        )?;
    }
    for ordered_write in projection.ordered_late_writes() {
        let mark_use = ordered_write.mark_use();
        writeln!(
            output,
            "ordered_write={}|0x{:08x}|{}|{}|{}|{}|{}|{}|{}",
            source_label(mark_use.source()),
            mark_use.mask(),
            family_label(ordered_write.family()),
            hook_label(ordered_write.hook()),
            ordered_write.child_chain().as_str(),
            ordered_write.hook_ordinal(),
            ordered_write.rule_ordinal(),
            hex(ordered_write.selector_digest().as_bytes()),
            placement_label(ordered_write.placement())
        )?;
    }
    for sentinel in projection.exact_mark_sentinels() {
        writeln!(
            output,
            "exact_mark_sentinel={}|{}|{}|{}|{}|0x{:08x}|{}",
            family_label(sentinel.family()),
            hook_label(sentinel.hook()),
            sentinel.child_chain().as_str(),
            sentinel.hook_ordinal(),
            sentinel.rule_ordinal(),
            sentinel.sentinel(),
            hex(sentinel.selector_digest().as_bytes()),
        )?;
    }
    for metric in projection.metrics() {
        writeln!(
            output,
            "metric={}|{}",
            metric.kind().as_str(),
            metric.value()
        )?;
    }
    writeln!(
        output,
        "projection_sha256={}",
        hex(projection.digest().as_bytes())
    )?;
    writeln!(output, "{end}")
}

/// Validates the typed projection before the probe reports success.
pub fn validate_android_fwmark_census_projection_report(
    phase: AndroidFwmarkCensusReportPhase,
    projection: &AndroidFwmarkCensusProjection,
) -> Result<(), String> {
    if let Some(cell) = projection
        .cells()
        .iter()
        .find(|cell| !cell.state().is_complete())
    {
        return Err(format!(
            "{}-noncomplete-cell-{}-{}-{}",
            phase.label(),
            source_label(cell.source()),
            plane_label(cell.plane()),
            coverage_label(cell.state())
        ));
    }
    if phase == AndroidFwmarkCensusReportPhase::Cleanup {
        if let Some(cell) = projection.cells().iter().find(|cell| {
            cell.source() == FwmarkEvidenceSource::ExistingFluxOwnership
                && cell.state() != FwmarkCensusCoverageState::CompleteAbsent
        }) {
            return Err(format!(
                "cleanup-existing-flux-cell-{}-{}",
                plane_label(cell.plane()),
                coverage_label(cell.state())
            ));
        }
        if let Some(metric) = projection.metrics().iter().find(|metric| {
            EXISTING_FLUX_OWNERSHIP_METRIC_KINDS.contains(&metric.kind()) && metric.value() != 0
        }) {
            return Err(format!(
                "cleanup-existing-flux-metric-{}-{}",
                metric.kind().as_str(),
                metric.value()
            ));
        }
    }
    Ok(())
}

/// Opaque pair of schema-validated primary and cleanup diagnostic reports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidFwmarkCensusProbeReports {
    primary: ParsedProjectionReport,
    cleanup: ParsedProjectionReport,
}

/// Parses the exact two-report probe output and rejects all extra or noncanonical data.
pub fn parse_android_fwmark_census_probe_reports(
    bytes: &[u8],
) -> Result<AndroidFwmarkCensusProbeReports, String> {
    if bytes.len() > MAX_REPORT_BYTES {
        return Err("fwmark census reports exceed the host schema byte limit".to_owned());
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| "fwmark census reports are not UTF-8".to_owned())?;
    if text.contains('\r') || !text.ends_with('\n') {
        return Err("fwmark census reports are not canonical LF text".to_owned());
    }
    let primary = text
        .strip_prefix(&format!("{PRIMARY_REPORT_BEGIN}\n"))
        .ok_or_else(|| "primary fwmark census marker is missing".to_owned())?;
    let (primary, cleanup) = primary
        .split_once(&format!("\n{PRIMARY_REPORT_END}\n{CLEANUP_REPORT_BEGIN}\n"))
        .ok_or_else(|| "fwmark census report boundary is malformed".to_owned())?;
    let cleanup = cleanup
        .strip_suffix(&format!("\n{CLEANUP_REPORT_END}\n"))
        .ok_or_else(|| {
            "cleanup fwmark census marker is missing or trailing output exists".to_owned()
        })?;
    Ok(AndroidFwmarkCensusProbeReports {
        primary: parse_projection_report(primary, AndroidFwmarkCensusReportPhase::Primary)?,
        cleanup: parse_projection_report(cleanup, AndroidFwmarkCensusReportPhase::Cleanup)?,
    })
}

/// Requires both parsed reports complete and the cleanup projection free of Flux ownership.
///
/// Every returned error is the same bounded canonical label emitted by the Android probe for the
/// equivalent typed projection. Callers may compare the label with sanitized probe diagnostics,
/// but must not trust probe diagnostics without this independent validation.
pub fn validate_android_fwmark_census_probe_reports(
    reports: &AndroidFwmarkCensusProbeReports,
) -> Result<(), String> {
    require_complete_report(&reports.primary, AndroidFwmarkCensusReportPhase::Primary)?;
    require_complete_report(&reports.cleanup, AndroidFwmarkCensusReportPhase::Cleanup)?;
    for index in 24..27 {
        let state = reports.cleanup.cells[index];
        if state != ParsedCoverageState::CompleteAbsent {
            return Err(format!(
                "cleanup-existing-flux-cell-{}-{}",
                plane_label(ALL_PLANES[index % ALL_PLANES.len()]),
                state.label(),
            ));
        }
    }
    for kind in EXISTING_FLUX_OWNERSHIP_METRIC_KINDS {
        let index = kind as usize;
        let value = reports.cleanup.metrics[index];
        if value != 0 {
            return Err(format!(
                "cleanup-existing-flux-metric-{}-{value}",
                kind.as_str(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParsedCoverageState {
    CompletePresent,
    CompleteAbsent,
    Incomplete,
    Opaque,
    Denied,
    Transient,
    Unavailable,
}

impl ParsedCoverageState {
    const fn is_complete(self) -> bool {
        matches!(self, Self::CompletePresent | Self::CompleteAbsent)
    }

    const fn label(self) -> &'static str {
        match self {
            Self::CompletePresent => "complete-present",
            Self::CompleteAbsent => "complete-absent",
            Self::Incomplete => "incomplete",
            Self::Opaque => "opaque",
            Self::Denied => "denied",
            Self::Transient => "transient",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MarkUseKey {
    source: usize,
    plane: usize,
    operation: usize,
    mask: u32,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OrderedWriteKey {
    source: usize,
    mask: u32,
    family: usize,
    hook: usize,
    chain: String,
    hook_ordinal: u32,
    rule_ordinal: u32,
    selector_digest: String,
    placement: usize,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ExactMarkSentinelKey {
    family: usize,
    hook: usize,
    chain: String,
    hook_ordinal: u32,
    rule_ordinal: u32,
    sentinel: u32,
    selector_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedProjectionReport {
    cells: Vec<ParsedCoverageState>,
    metrics: Vec<u64>,
}

fn parse_projection_report(
    document: &str,
    phase: AndroidFwmarkCensusReportPhase,
) -> Result<ParsedProjectionReport, String> {
    let phase = phase.label();
    let mut lines = document.lines();
    require_report_line(
        lines.next(),
        &format!("authority={REPORT_AUTHORITY}"),
        phase,
    )?;
    require_report_line(
        lines.next(),
        &format!("schema_version={REPORT_SCHEMA_VERSION}"),
        phase,
    )?;
    require_report_line(
        lines.next(),
        &format!("cell_count={ANDROID_FWMARK_CENSUS_PROJECTION_CELLS}"),
        phase,
    )?;
    let mark_use_count = parse_count_line(
        lines.next(),
        "mark_use_count",
        MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
        phase,
    )?;
    let ordered_write_count = parse_count_line(
        lines.next(),
        "ordered_write_count",
        MAX_ORDERED_LATE_PACKET_WRITES,
        phase,
    )?;
    let exact_mark_sentinel_count = parse_count_line(
        lines.next(),
        "exact_mark_sentinel_count",
        MAX_EXACT_MARK_SENTINEL_QUALIFICATIONS,
        phase,
    )?;
    require_report_line(
        lines.next(),
        &format!("metric_count={ANDROID_FWMARK_CENSUS_PROJECTION_METRICS}"),
        phase,
    )?;

    let mut cells = Vec::with_capacity(ALL_SOURCES.len() * ALL_PLANES.len());
    for source in ALL_SOURCES {
        for plane in ALL_PLANES {
            let line = lines
                .next()
                .ok_or_else(|| format!("{phase} fwmark census cell is missing"))?;
            let value = line
                .strip_prefix("cell=")
                .ok_or_else(|| format!("{phase} fwmark census cell is misplaced"))?;
            let parts = value.split('|').collect::<Vec<_>>();
            let [actual_source, actual_plane, state] = parts.as_slice() else {
                return Err(format!("{phase} fwmark census cell is malformed"));
            };
            if *actual_source != source_label(source) || *actual_plane != plane_label(plane) {
                return Err(format!(
                    "{phase} fwmark census cells are not in canonical order"
                ));
            }
            cells.push(parse_coverage_state(state, phase)?);
        }
    }

    let mut previous_mark_use = None;
    for _ in 0..mark_use_count {
        let line = lines
            .next()
            .ok_or_else(|| format!("{phase} fwmark census mark use is missing"))?;
        let key = parse_mark_use(line, phase)?;
        if previous_mark_use
            .as_ref()
            .is_some_and(|previous| previous >= &key)
        {
            return Err(format!(
                "{phase} fwmark census mark uses are not strictly canonical"
            ));
        }
        previous_mark_use = Some(key);
    }

    let mut previous_ordered_write = None;
    for _ in 0..ordered_write_count {
        let line = lines
            .next()
            .ok_or_else(|| format!("{phase} fwmark census ordered write is missing"))?;
        let key = parse_ordered_write(line, phase)?;
        if previous_ordered_write
            .as_ref()
            .is_some_and(|previous| previous >= &key)
        {
            return Err(format!(
                "{phase} fwmark census ordered writes are not strictly canonical"
            ));
        }
        previous_ordered_write = Some(key);
    }

    let mut previous_exact_mark_sentinel = None;
    for _ in 0..exact_mark_sentinel_count {
        let line = lines
            .next()
            .ok_or_else(|| format!("{phase} fwmark census exact-mark sentinel is missing"))?;
        let key = parse_exact_mark_sentinel(line, phase)?;
        if previous_exact_mark_sentinel
            .as_ref()
            .is_some_and(|previous| previous >= &key)
        {
            return Err(format!(
                "{phase} fwmark census exact-mark sentinels are not strictly canonical"
            ));
        }
        previous_exact_mark_sentinel = Some(key);
    }

    let mut metrics = Vec::with_capacity(ALL_METRIC_KINDS.len());
    for expected in ALL_METRIC_KINDS {
        let line = lines
            .next()
            .ok_or_else(|| format!("{phase} fwmark census metric is missing"))?;
        let value = line
            .strip_prefix("metric=")
            .ok_or_else(|| format!("{phase} fwmark census metric is misplaced"))?;
        let (label, value) = value
            .split_once('|')
            .ok_or_else(|| format!("{phase} fwmark census metric is malformed"))?;
        if label != expected.as_str() || value.contains('|') {
            return Err(format!(
                "{phase} fwmark census metrics are not in canonical order"
            ));
        }
        metrics.push(parse_canonical_u64(value, "metric")?);
    }
    let digest = lines
        .next()
        .and_then(|line| line.strip_prefix("projection_sha256="))
        .ok_or_else(|| format!("{phase} fwmark census projection digest is missing"))?;
    require_lower_sha256(digest, "projection digest")?;
    if digest.bytes().all(|byte| byte == b'0') {
        return Err(format!("{phase} fwmark census projection digest is zero"));
    }
    if lines.next().is_some() {
        return Err(format!("{phase} fwmark census report has trailing fields"));
    }
    Ok(ParsedProjectionReport { cells, metrics })
}

fn require_report_line(actual: Option<&str>, expected: &str, phase: &str) -> Result<(), String> {
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(format!(
            "{phase} fwmark census header differs from the exact schema"
        ))
    }
}

fn parse_count_line(
    line: Option<&str>,
    key: &str,
    maximum: usize,
    phase: &str,
) -> Result<usize, String> {
    let value = line
        .and_then(|line| line.strip_prefix(key))
        .and_then(|suffix| suffix.strip_prefix('='))
        .ok_or_else(|| format!("{phase} fwmark census {key} is missing"))?;
    let value = parse_canonical_u64(value, key)?;
    let value = usize::try_from(value)
        .map_err(|_| format!("{phase} fwmark census {key} exceeds the host domain"))?;
    if value > maximum {
        Err(format!("{phase} fwmark census {key} exceeds {maximum}"))
    } else {
        Ok(value)
    }
}

fn parse_coverage_state(value: &str, phase: &str) -> Result<ParsedCoverageState, String> {
    match value {
        "complete-present" => Ok(ParsedCoverageState::CompletePresent),
        "complete-absent" => Ok(ParsedCoverageState::CompleteAbsent),
        "incomplete" => Ok(ParsedCoverageState::Incomplete),
        "opaque" => Ok(ParsedCoverageState::Opaque),
        "denied" => Ok(ParsedCoverageState::Denied),
        "transient" => Ok(ParsedCoverageState::Transient),
        "unavailable" => Ok(ParsedCoverageState::Unavailable),
        _ => Err(format!("{phase} fwmark census coverage state is invalid")),
    }
}

fn parse_mark_use(line: &str, phase: &str) -> Result<MarkUseKey, String> {
    let value = line
        .strip_prefix("mark_use=")
        .ok_or_else(|| format!("{phase} fwmark census mark use is misplaced"))?;
    let parts = value.split('|').collect::<Vec<_>>();
    let [source, plane, operation, mask] = parts.as_slice() else {
        return Err(format!("{phase} fwmark census mark use is malformed"));
    };
    Ok(MarkUseKey {
        source: label_index(source, &source_labels(), "mark-use source")?,
        plane: label_index(plane, &plane_labels(), "mark-use plane")?,
        operation: label_index(
            operation,
            &[
                "predicate-read",
                "masked-write",
                "transfer-read",
                "transfer-write",
            ],
            "mark-use operation",
        )?,
        mask: parse_mask(mask, phase)?,
    })
}

fn parse_ordered_write(line: &str, phase: &str) -> Result<OrderedWriteKey, String> {
    let value = line
        .strip_prefix("ordered_write=")
        .ok_or_else(|| format!("{phase} fwmark census ordered write is misplaced"))?;
    let parts = value.split('|').collect::<Vec<_>>();
    let [
        source,
        mask,
        family,
        hook,
        chain,
        hook_ordinal,
        rule_ordinal,
        selector,
        placement,
    ] = parts.as_slice()
    else {
        return Err(format!("{phase} fwmark census ordered write is malformed"));
    };
    let source = label_index(source, &source_labels(), "ordered-write source")?;
    let mask = parse_mask(mask, phase)?;
    let family = label_index(family, &["ipv4", "ipv6"], "ordered-write family")?;
    let hook = label_index(hook, &["input", "postrouting"], "ordered-write hook")?;
    if chain.is_empty()
        || chain.len() > MAX_FWMARK_NETFILTER_CHAIN_NAME_BYTES
        || !chain.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'+')
        })
    {
        return Err(format!(
            "{phase} fwmark census ordered-write chain is invalid"
        ));
    }
    let hook_ordinal = parse_nonzero_u32(hook_ordinal, "hook ordinal")?;
    let rule_ordinal = parse_nonzero_u32(rule_ordinal, "rule ordinal")?;
    require_lower_sha256(selector, "ordered-write selector digest")?;
    if selector.bytes().all(|byte| byte == b'0') {
        return Err(format!(
            "{phase} fwmark census ordered-write selector digest is zero"
        ));
    }
    let placement = label_index(
        placement,
        &["input-after-routing", "postrouting-after-final-flux-use"],
        "ordered-write placement",
    )?;
    if !matches!((source, hook, placement), (0, 0, 0) | (3, 1, 1)) {
        return Err(format!(
            "{phase} fwmark census ordered-write source/hook/placement is invalid"
        ));
    }
    Ok(OrderedWriteKey {
        source,
        mask,
        family,
        hook,
        chain: (*chain).to_owned(),
        hook_ordinal,
        rule_ordinal,
        selector_digest: (*selector).to_owned(),
        placement,
    })
}

fn parse_exact_mark_sentinel(line: &str, phase: &str) -> Result<ExactMarkSentinelKey, String> {
    let value = line
        .strip_prefix("exact_mark_sentinel=")
        .ok_or_else(|| format!("{phase} fwmark census exact-mark sentinel is misplaced"))?;
    let parts = value.split('|').collect::<Vec<_>>();
    let [
        family,
        hook,
        chain,
        hook_ordinal,
        rule_ordinal,
        sentinel,
        selector,
    ] = parts.as_slice()
    else {
        return Err(format!(
            "{phase} fwmark census exact-mark sentinel is malformed"
        ));
    };
    let family = label_index(family, &["ipv4", "ipv6"], "exact-mark sentinel family")?;
    let hook = label_index(hook, &["prerouting"], "exact-mark sentinel hook")?;
    if chain.is_empty()
        || chain.len() > MAX_FWMARK_NETFILTER_CHAIN_NAME_BYTES
        || !chain.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'+')
        })
    {
        return Err(format!(
            "{phase} fwmark census exact-mark sentinel chain is invalid"
        ));
    }
    let hook_ordinal = parse_nonzero_u32(hook_ordinal, "exact-mark sentinel hook ordinal")?;
    let rule_ordinal = parse_nonzero_u32(rule_ordinal, "exact-mark sentinel rule ordinal")?;
    let sentinel = parse_mask(sentinel, phase)?;
    require_lower_sha256(selector, "exact-mark sentinel selector digest")?;
    if selector.bytes().all(|byte| byte == b'0') {
        return Err(format!(
            "{phase} fwmark census exact-mark sentinel selector digest is zero"
        ));
    }
    Ok(ExactMarkSentinelKey {
        family,
        hook,
        chain: (*chain).to_owned(),
        hook_ordinal,
        rule_ordinal,
        sentinel,
        selector_digest: (*selector).to_owned(),
    })
}

fn label_index(value: &str, labels: &[&str], field: &str) -> Result<usize, String> {
    labels
        .iter()
        .position(|candidate| *candidate == value)
        .ok_or_else(|| format!("fwmark census {field} is invalid"))
}

fn parse_mask(value: &str, phase: &str) -> Result<u32, String> {
    let digits = value
        .strip_prefix("0x")
        .filter(|digits| digits.len() == 8)
        .ok_or_else(|| format!("{phase} fwmark census mask is not canonical"))?;
    if !digits
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{phase} fwmark census mask is not lowercase hexadecimal"
        ));
    }
    let mask = u32::from_str_radix(digits, 16)
        .map_err(|_| format!("{phase} fwmark census mask is invalid"))?;
    if mask == 0 {
        Err(format!("{phase} fwmark census mask is zero"))
    } else {
        Ok(mask)
    }
}

fn parse_nonzero_u32(value: &str, field: &str) -> Result<u32, String> {
    let value = parse_canonical_u64(value, field)?;
    u32::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("fwmark census {field} is outside the nonzero u32 domain"))
}

fn parse_canonical_u64(value: &str, field: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{field} is not a canonical unsigned decimal"));
    }
    value
        .parse::<u64>()
        .map_err(|_| format!("{field} exceeds the u64 domain"))
}

fn require_lower_sha256(value: &str, field: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "fwmark census {field} is not canonical lowercase SHA-256"
        ))
    }
}

fn require_complete_report(
    report: &ParsedProjectionReport,
    phase: AndroidFwmarkCensusReportPhase,
) -> Result<(), String> {
    if let Some((index, state)) = report
        .cells
        .iter()
        .enumerate()
        .find(|(_, state)| !state.is_complete())
    {
        Err(format!(
            "{}-noncomplete-cell-{}-{}-{}",
            phase.label(),
            source_label(ALL_SOURCES[index / ALL_PLANES.len()]),
            plane_label(ALL_PLANES[index % ALL_PLANES.len()]),
            state.label(),
        ))
    } else {
        Ok(())
    }
}

const fn source_label(source: FwmarkEvidenceSource) -> &'static str {
    match source {
        FwmarkEvidenceSource::AndroidNetId => "android-net-id",
        FwmarkEvidenceSource::Rpdb => "rpdb",
        FwmarkEvidenceSource::DeviceMarkPolicy => "device-mark-policy",
        FwmarkEvidenceSource::Xtables => "xtables",
        FwmarkEvidenceSource::Nftables => "nftables",
        FwmarkEvidenceSource::TrafficControlAndBpf => "traffic-control-and-bpf",
        FwmarkEvidenceSource::Xfrm => "xfrm",
        FwmarkEvidenceSource::ConnmarkAndSocketTransfers => "connmark-and-socket-transfers",
        FwmarkEvidenceSource::ExistingFluxOwnership => "existing-flux-ownership",
    }
}

const fn source_labels() -> [&'static str; ALL_SOURCES.len()] {
    let mut labels = [""; ALL_SOURCES.len()];
    let mut index = 0;
    while index < ALL_SOURCES.len() {
        labels[index] = source_label(ALL_SOURCES[index]);
        index += 1;
    }
    labels
}

const fn plane_label(plane: FwmarkPlane) -> &'static str {
    match plane {
        FwmarkPlane::Packet => "packet",
        FwmarkPlane::Socket => "socket",
        FwmarkPlane::Conntrack => "conntrack",
    }
}

const fn plane_labels() -> [&'static str; ALL_PLANES.len()] {
    let mut labels = [""; ALL_PLANES.len()];
    let mut index = 0;
    while index < ALL_PLANES.len() {
        labels[index] = plane_label(ALL_PLANES[index]);
        index += 1;
    }
    labels
}

const fn coverage_label(state: FwmarkCensusCoverageState) -> &'static str {
    match state {
        FwmarkCensusCoverageState::CompletePresent => "complete-present",
        FwmarkCensusCoverageState::CompleteAbsent => "complete-absent",
        FwmarkCensusCoverageState::Incomplete => "incomplete",
        FwmarkCensusCoverageState::Opaque => "opaque",
        FwmarkCensusCoverageState::Denied => "denied",
        FwmarkCensusCoverageState::Transient => "transient",
        FwmarkCensusCoverageState::Unavailable => "unavailable",
    }
}

const fn operation_label(operation: FwmarkUseOperation) -> &'static str {
    match operation {
        FwmarkUseOperation::PredicateRead => "predicate-read",
        FwmarkUseOperation::MaskedWrite => "masked-write",
        FwmarkUseOperation::TransferRead => "transfer-read",
        FwmarkUseOperation::TransferWrite => "transfer-write",
    }
}

const fn family_label(family: NetworkAddressFamily) -> &'static str {
    match family {
        NetworkAddressFamily::Ipv4 => "ipv4",
        NetworkAddressFamily::Ipv6 => "ipv6",
    }
}

const fn hook_label(hook: FwmarkNetfilterBuiltinHook) -> &'static str {
    match hook {
        FwmarkNetfilterBuiltinHook::Prerouting => "prerouting",
        FwmarkNetfilterBuiltinHook::Input => "input",
        FwmarkNetfilterBuiltinHook::Postrouting => "postrouting",
    }
}

const fn placement_label(placement: FwmarkOrderedLateWritePlacement) -> &'static str {
    match placement {
        FwmarkOrderedLateWritePlacement::InputAfterRouting => "input-after-routing",
        FwmarkOrderedLateWritePlacement::PostroutingAfterFinalFluxUse => {
            "postrouting-after-final-flux-use"
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use flux_core::{
        FwmarkCensusCoverageRecord, FwmarkNetfilterChainName, FwmarkOrderedLateWriteQualification,
        FwmarkPacketSelectorDigest, FwmarkUseRecord,
    };

    use super::super::{AndroidFwmarkCensusMetric, AndroidFwmarkCensusProjectionDigest};
    use super::*;

    fn projection(chain_bytes: usize, digest_byte: u8) -> AndroidFwmarkCensusProjection {
        let mark_use = FwmarkUseRecord::new(
            FwmarkEvidenceSource::Xtables,
            FwmarkPlane::Packet,
            FwmarkUseOperation::MaskedWrite,
            u32::MAX,
        )
        .expect("mark use");
        let ordered_write = FwmarkOrderedLateWriteQualification::new(
            mark_use,
            NetworkAddressFamily::Ipv6,
            FwmarkNetfilterBuiltinHook::Postrouting,
            FwmarkNetfilterChainName::new(&"c".repeat(chain_bytes)).expect("chain"),
            1,
            2,
            FwmarkPacketSelectorDigest::new([0x11; 32]).expect("selector digest"),
            FwmarkOrderedLateWritePlacement::PostroutingAfterFinalFluxUse,
            false,
            false,
            false,
        )
        .expect("ordered write");
        let cells = std::array::from_fn(|index| {
            let source = ALL_SOURCES[index / ALL_PLANES.len()];
            let plane = ALL_PLANES[index % ALL_PLANES.len()];
            let state = if source == FwmarkEvidenceSource::Xtables && plane == FwmarkPlane::Packet {
                FwmarkCensusCoverageState::CompletePresent
            } else {
                FwmarkCensusCoverageState::CompleteAbsent
            };
            FwmarkCensusCoverageRecord::new(source, plane, state)
        });
        let metrics =
            std::array::from_fn(|index| AndroidFwmarkCensusMetric::new(ALL_METRIC_KINDS[index], 0));
        AndroidFwmarkCensusProjection {
            cells,
            mark_uses: vec![mark_use].into_boxed_slice(),
            ordered_late_writes: vec![ordered_write].into_boxed_slice(),
            exact_mark_sentinels: Box::new([]),
            metrics,
            digest: AndroidFwmarkCensusProjectionDigest([digest_byte; 32]),
        }
    }

    fn probe_output(chain_bytes: usize) -> Vec<u8> {
        let mut output = Vec::new();
        write_android_fwmark_census_projection_report(
            &mut output,
            AndroidFwmarkCensusReportPhase::Primary,
            &projection(chain_bytes, 0x22),
        )
        .expect("primary report");
        write_android_fwmark_census_projection_report(
            &mut output,
            AndroidFwmarkCensusReportPhase::Cleanup,
            &projection(chain_bytes, 0x33),
        )
        .expect("cleanup report");
        output
    }

    #[test]
    fn canonical_renderer_round_trips_through_the_host_parser() {
        let reports = parse_android_fwmark_census_probe_reports(&probe_output(
            MAX_FWMARK_NETFILTER_CHAIN_NAME_BYTES,
        ))
        .expect("rendered reports");
        validate_android_fwmark_census_probe_reports(&reports)
            .expect("complete reports and cleanup absence");
    }

    #[test]
    fn cleanup_allows_non_owning_durable_container_presence() {
        let mut cleanup = projection(16, 0x33);
        for kind in [
            AndroidFwmarkCensusMetricKind::ExistingFluxDurableRootPresent,
            AndroidFwmarkCensusMetricKind::ExistingFluxEmptyTargetArchivePresent,
        ] {
            cleanup.metrics[kind as usize] = AndroidFwmarkCensusMetric::new(kind, 1);
        }

        validate_android_fwmark_census_projection_report(
            AndroidFwmarkCensusReportPhase::Cleanup,
            &cleanup,
        )
        .expect("container presence alone carries no Flux ownership");

        let mut output = Vec::new();
        write_android_fwmark_census_projection_report(
            &mut output,
            AndroidFwmarkCensusReportPhase::Primary,
            &projection(16, 0x22),
        )
        .expect("primary report");
        write_android_fwmark_census_projection_report(
            &mut output,
            AndroidFwmarkCensusReportPhase::Cleanup,
            &cleanup,
        )
        .expect("cleanup report");
        let reports = parse_android_fwmark_census_probe_reports(&output).expect("rendered reports");
        validate_android_fwmark_census_probe_reports(&reports)
            .expect("host accepts non-owning durable containers");
    }

    #[test]
    fn parser_accepts_the_canonical_chain_limit_and_rejects_one_byte_more() {
        let valid = probe_output(MAX_FWMARK_NETFILTER_CHAIN_NAME_BYTES);
        parse_android_fwmark_census_probe_reports(&valid).expect("128-byte chain");
        let valid_chain = "c".repeat(MAX_FWMARK_NETFILTER_CHAIN_NAME_BYTES);
        let invalid_chain = "c".repeat(MAX_FWMARK_NETFILTER_CHAIN_NAME_BYTES + 1);
        let invalid = String::from_utf8(valid).expect("UTF-8 report").replace(
            &format!("|{valid_chain}|1|2|"),
            &format!("|{invalid_chain}|1|2|"),
        );
        assert!(parse_android_fwmark_census_probe_reports(invalid.as_bytes()).is_err());
    }

    #[test]
    fn parser_rejects_order_drift_extra_output_and_noncanonical_values() {
        let exact = probe_output(16);
        let swapped = String::from_utf8(exact.clone())
            .expect("UTF-8 report")
            .replacen(
                "cell=android-net-id|packet|complete-absent\ncell=android-net-id|socket|complete-absent",
                "cell=android-net-id|socket|complete-absent\ncell=android-net-id|packet|complete-absent",
                1,
            );
        assert!(parse_android_fwmark_census_probe_reports(swapped.as_bytes()).is_err());
        let extra = [exact.as_slice(), b"unexpected\n"].concat();
        assert!(parse_android_fwmark_census_probe_reports(&extra).is_err());
        let leading_zero = String::from_utf8(exact).expect("UTF-8 report").replacen(
            "metric=inventory-links|0",
            "metric=inventory-links|00",
            1,
        );
        assert!(parse_android_fwmark_census_probe_reports(leading_zero.as_bytes()).is_err());
    }

    #[test]
    fn parsed_noncomplete_cells_and_cleanup_residue_fail_closed() {
        let noncomplete = String::from_utf8(probe_output(16))
            .expect("UTF-8 report")
            .replacen(
                "cell=android-net-id|packet|complete-absent",
                "cell=android-net-id|packet|opaque",
                1,
            );
        let reports = parse_android_fwmark_census_probe_reports(noncomplete.as_bytes())
            .expect("bounded noncomplete diagnostic report");
        assert_eq!(
            validate_android_fwmark_census_probe_reports(&reports)
                .expect_err("noncomplete primary cell must stop"),
            "primary-noncomplete-cell-android-net-id-packet-opaque"
        );

        let mut cleanup = projection(16, 0x33);
        let process_kind = AndroidFwmarkCensusMetricKind::ExistingFluxProcesses;
        cleanup.metrics[process_kind as usize] = AndroidFwmarkCensusMetric::new(process_kind, 1);
        assert_eq!(
            validate_android_fwmark_census_projection_report(
                AndroidFwmarkCensusReportPhase::Cleanup,
                &cleanup,
            )
            .expect_err("typed cleanup ownership residue must stop"),
            "cleanup-existing-flux-metric-existing-flux-processes-1"
        );

        let residue = String::from_utf8(probe_output(16))
            .expect("UTF-8 report")
            .replacen(
                "metric=existing-flux-processes|0",
                "metric=existing-flux-processes|1",
                2,
            );
        let reports = parse_android_fwmark_census_probe_reports(residue.as_bytes())
            .expect("bounded cleanup residue report");
        assert_eq!(
            validate_android_fwmark_census_probe_reports(&reports)
                .expect_err("cleanup ownership residue must stop"),
            "cleanup-existing-flux-metric-existing-flux-processes-1"
        );
    }
}
