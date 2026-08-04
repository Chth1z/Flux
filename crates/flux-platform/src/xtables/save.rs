use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::num::NonZeroU32;

use sha2::{Digest, Sha256};

use super::{
    MAX_XTABLES_RESTORE_BYTES, MAX_XTABLES_RESTORE_LINE_BYTES, MAX_XTABLES_RESTORE_LINES,
    MAX_XTABLES_RESTORE_TOKEN_BYTES, MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND, XtablesRestoreAction,
    XtablesRestoreArtifact, XtablesRestoreCommand, XtablesRestoreCommandKind,
    XtablesRestoreContext, XtablesRestoreEntry, XtablesRestoreFamily, XtablesRestoreParseError,
    XtablesRestoreTable, parse_xtables_restore,
};

const XTABLES_SAVE_PROJECTION_DOMAIN: &[u8] =
    b"Flux owned xtables-save projection\0structured-sha256-v3\0";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct XtablesSaveProjectionDigest([u8; 32]);

impl XtablesSaveProjectionDigest {
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct XtablesOwnedRule(Box<str>);

impl XtablesOwnedRule {
    #[must_use]
    pub(crate) const fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesOwnedChainState {
    rules: Box<[XtablesOwnedRule]>,
}

impl XtablesOwnedChainState {
    #[must_use]
    pub(crate) const fn rules(&self) -> &[XtablesOwnedRule] {
        &self.rules
    }
}

/// One rule outside the native namespace that references one or more native chains.
///
/// `ordinal` counts every rule in `source_chain`, including unrelated opaque rules.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct XtablesNativeReference {
    source_chain: Box<str>,
    ordinal: NonZeroU32,
    target_chains: Box<[Box<str>]>,
    rule: XtablesOwnedRule,
}

impl XtablesNativeReference {
    #[must_use]
    pub(crate) const fn source_chain(&self) -> &str {
        &self.source_chain
    }

    #[must_use]
    pub(crate) const fn ordinal(&self) -> NonZeroU32 {
        self.ordinal
    }

    #[must_use]
    pub(crate) const fn target_chains(&self) -> &[Box<str>] {
        &self.target_chains
    }

    #[must_use]
    pub(crate) const fn rule(&self) -> &XtablesOwnedRule {
        &self.rule
    }
}

/// Bounded, counter-normalized projection of native mangle state.
///
/// Chain creation order is not semantic. Exact names are therefore canonicalized through the map,
/// while order and duplicates within each owned chain remain material. Native references from
/// non-native chains retain their absolute source-chain ordinal so a displaced stable hook cannot
/// compare equal to a top-level hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesSaveProjection {
    family: XtablesRestoreFamily,
    chains: BTreeMap<Box<str>, XtablesOwnedChainState>,
    native_references: Box<[XtablesNativeReference]>,
    digest: XtablesSaveProjectionDigest,
}

impl XtablesSaveProjection {
    #[must_use]
    pub(crate) const fn family(&self) -> XtablesRestoreFamily {
        self.family
    }

    #[must_use]
    pub(crate) fn chain(&self, name: &str) -> Option<&XtablesOwnedChainState> {
        self.chains.get(name)
    }

    #[must_use]
    pub(crate) const fn native_references(&self) -> &[XtablesNativeReference] {
        &self.native_references
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.chains.is_empty() && self.native_references.is_empty()
    }

    #[must_use]
    pub(crate) const fn digest(&self) -> XtablesSaveProjectionDigest {
        self.digest
    }

    pub(crate) fn with_owned_chain_replacement(
        &self,
        artifact: &XtablesRestoreArtifact,
    ) -> Result<Self, XtablesSaveProjectionError> {
        if artifact.context().action() != XtablesRestoreAction::Replace {
            return Err(XtablesSaveProjectionError::global(
                XtablesSaveProjectionErrorKind::ExpectedActionMismatch,
            ));
        }
        if artifact.context().family() != self.family {
            return Err(XtablesSaveProjectionError::global(
                XtablesSaveProjectionErrorKind::ExpectedFamilyMismatch,
            ));
        }

        let mut chain = None;
        let mut rules = Vec::new();
        for transaction in artifact.transactions() {
            if transaction.table() != XtablesRestoreTable::Mangle {
                return Err(XtablesSaveProjectionError::global(
                    XtablesSaveProjectionErrorKind::ExpectedNonMangleTable,
                ));
            }
            for entry in transaction.entries() {
                let XtablesRestoreEntry::Command(command) = entry else {
                    return Err(XtablesSaveProjectionError::global(
                        XtablesSaveProjectionErrorKind::ExpectedReplacementMismatch,
                    ));
                };
                match command.kind() {
                    XtablesRestoreCommandKind::Flush if chain.is_none() => {
                        chain = Some(command.chain());
                    }
                    XtablesRestoreCommandKind::Append
                        if chain.is_some_and(|chain| chain == command.chain()) =>
                    {
                        let line = render_live_append(command);
                        let scan = scan_rule(&line, None)?;
                        if !is_native_chain(&scan.source)
                            || scan.targets.iter().any(|target| is_native_chain(target))
                        {
                            return Err(XtablesSaveProjectionError::global(
                                XtablesSaveProjectionErrorKind::ExpectedReplacementMismatch,
                            ));
                        }
                        rules.push(XtablesOwnedRule(line.into_boxed_str()));
                    }
                    _ => {
                        return Err(XtablesSaveProjectionError::global(
                            XtablesSaveProjectionErrorKind::ExpectedReplacementMismatch,
                        ));
                    }
                }
            }
        }
        let chain = chain.ok_or_else(|| {
            XtablesSaveProjectionError::global(
                XtablesSaveProjectionErrorKind::ExpectedReplacementMismatch,
            )
        })?;
        let mut projection = self.clone();
        let state = projection.chains.get_mut(chain).ok_or_else(|| {
            XtablesSaveProjectionError::global(
                XtablesSaveProjectionErrorKind::ExpectedReplacementMismatch,
            )
        })?;
        state.rules = rules.into_boxed_slice();
        projection.digest = digest_projection(
            projection.family,
            &projection.chains,
            &projection.native_references,
        );
        Ok(projection)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum XtablesExpectedStatePhase {
    Prepared,
    Active,
    OutputDetached,
}

/// Exact live-state expectation derived from already-validated `Apply` artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesExpectedState {
    phase: XtablesExpectedStatePhase,
    projection: XtablesSaveProjection,
}

impl XtablesExpectedState {
    pub(crate) fn from_apply_artifacts<'a>(
        family: XtablesRestoreFamily,
        phase: XtablesExpectedStatePhase,
        artifacts: impl IntoIterator<Item = &'a XtablesRestoreArtifact>,
    ) -> Result<Self, XtablesSaveProjectionError> {
        let mut builder = ProjectionBuilder::new(family);
        for artifact in artifacts {
            if artifact.context().action() != XtablesRestoreAction::Apply {
                return Err(XtablesSaveProjectionError::global(
                    XtablesSaveProjectionErrorKind::ExpectedActionMismatch,
                ));
            }
            if artifact.context().family() != family {
                return Err(XtablesSaveProjectionError::global(
                    XtablesSaveProjectionErrorKind::ExpectedFamilyMismatch,
                ));
            }
            for transaction in artifact.transactions() {
                if transaction.table() != XtablesRestoreTable::Mangle {
                    return Err(XtablesSaveProjectionError::global(
                        XtablesSaveProjectionErrorKind::ExpectedNonMangleTable,
                    ));
                }
                for entry in transaction.entries() {
                    match entry {
                        XtablesRestoreEntry::ChainDeclaration(declaration) => {
                            if !is_native_chain(declaration.chain()) {
                                return Err(XtablesSaveProjectionError::global(
                                    XtablesSaveProjectionErrorKind::ExpectedUnownedEntry,
                                ));
                            }
                            builder.declare_native(declaration.chain(), None)?;
                        }
                        XtablesRestoreEntry::Command(command) => {
                            builder.ingest_expected_command(command, phase)?;
                        }
                    }
                }
            }
        }
        Ok(Self {
            phase,
            projection: builder.finish()?,
        })
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> XtablesExpectedStatePhase {
        self.phase
    }

    #[must_use]
    pub(crate) const fn projection(&self) -> &XtablesSaveProjection {
        &self.projection
    }

    #[must_use]
    pub(crate) fn is_satisfied_by(&self, observed: &XtablesSaveProjection) -> bool {
        &self.projection == observed
    }

    pub(crate) fn with_owned_chain_replacement(
        &self,
        artifact: &XtablesRestoreArtifact,
    ) -> Result<Self, XtablesSaveProjectionError> {
        Ok(Self {
            phase: self.phase,
            projection: self.projection.with_owned_chain_replacement(artifact)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XtablesSaveProjectionErrorKind {
    EmptyInput,
    LimitExceeded,
    MissingFinalLineFeed,
    NonAscii,
    InvalidLine,
    MissingMangleTable,
    MissingCommit,
    DuplicateMangleTable,
    ContentAfterCommit,
    InvalidChainDeclaration,
    InvalidCounter,
    InvalidQuotedToken,
    TooManyTokens,
    TokenTooLong,
    InvalidOwnedArtifact,
    DuplicateNativeChain,
    UndeclaredNativeSource,
    DanglingNativeTarget,
    ExpectedActionMismatch,
    ExpectedFamilyMismatch,
    ExpectedNonMangleTable,
    ExpectedUnownedEntry,
    ExpectedExternalAppend,
    ExpectedReplacementMismatch,
    OwnedStateOutsideMangle,
}

#[derive(Debug)]
pub(crate) struct XtablesSaveProjectionError {
    kind: XtablesSaveProjectionErrorKind,
    line: Option<usize>,
    source: Option<XtablesRestoreParseError>,
}

impl XtablesSaveProjectionError {
    const fn global(kind: XtablesSaveProjectionErrorKind) -> Self {
        Self {
            kind,
            line: None,
            source: None,
        }
    }

    const fn at_line(kind: XtablesSaveProjectionErrorKind, line: usize) -> Self {
        Self {
            kind,
            line: Some(line),
            source: None,
        }
    }

    const fn at_optional_line(kind: XtablesSaveProjectionErrorKind, line: Option<usize>) -> Self {
        Self {
            kind,
            line,
            source: None,
        }
    }

    fn invalid_owned(source: XtablesRestoreParseError, line: Option<usize>) -> Self {
        Self {
            kind: XtablesSaveProjectionErrorKind::InvalidOwnedArtifact,
            line,
            source: Some(source),
        }
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> XtablesSaveProjectionErrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn line(&self) -> Option<usize> {
        self.line
    }
}

impl fmt::Display for XtablesSaveProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid bounded xtables-save projection")?;
        if let Some(line) = self.line {
            write!(formatter, " at line {line}")?;
        }
        write!(formatter, ": {:?}", self.kind)
    }
}

impl Error for XtablesSaveProjectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SaveTable {
    Mangle,
    Opaque,
}

pub(crate) fn project_xtables_save(
    input: &[u8],
    family: XtablesRestoreFamily,
) -> Result<XtablesSaveProjection, XtablesSaveProjectionError> {
    validate_input(input)?;
    let text = std::str::from_utf8(input).expect("validated ASCII is valid UTF-8");
    let mut current_table = None;
    let mut saw_table = false;
    let mut saw_mangle = false;
    let mut builder = ProjectionBuilder::new(family);

    for (index, line) in text[..text.len() - 1].split('\n').enumerate() {
        let line_number = index + 1;
        if line.len() > MAX_XTABLES_RESTORE_LINE_BYTES {
            return Err(XtablesSaveProjectionError::at_line(
                XtablesSaveProjectionErrorKind::LimitExceeded,
                line_number,
            ));
        }
        if line.is_empty() {
            return Err(XtablesSaveProjectionError::at_line(
                XtablesSaveProjectionErrorKind::InvalidLine,
                line_number,
            ));
        }
        if line.starts_with('#') {
            continue;
        }

        let Some(table) = current_table else {
            if let Some(table_name) = line.strip_prefix('*') {
                if table_name.is_empty() || table_name.as_bytes().contains(&b' ') {
                    return Err(XtablesSaveProjectionError::at_line(
                        XtablesSaveProjectionErrorKind::InvalidLine,
                        line_number,
                    ));
                }
                saw_table = true;
                if table_name == "mangle" {
                    if saw_mangle {
                        return Err(XtablesSaveProjectionError::at_line(
                            XtablesSaveProjectionErrorKind::DuplicateMangleTable,
                            line_number,
                        ));
                    }
                    saw_mangle = true;
                    current_table = Some(SaveTable::Mangle);
                } else {
                    current_table = Some(SaveTable::Opaque);
                }
                continue;
            }
            return Err(XtablesSaveProjectionError::at_line(
                if saw_table {
                    XtablesSaveProjectionErrorKind::ContentAfterCommit
                } else {
                    XtablesSaveProjectionErrorKind::InvalidLine
                },
                line_number,
            ));
        };

        if line == "COMMIT" {
            current_table = None;
            continue;
        }
        if line.starts_with('*') {
            return Err(XtablesSaveProjectionError::at_line(
                if line == "*mangle" && saw_mangle {
                    XtablesSaveProjectionErrorKind::DuplicateMangleTable
                } else {
                    XtablesSaveProjectionErrorKind::InvalidLine
                },
                line_number,
            ));
        }
        if table == SaveTable::Opaque {
            if opaque_line_mentions_owned_state(line) {
                return Err(XtablesSaveProjectionError::at_line(
                    XtablesSaveProjectionErrorKind::OwnedStateOutsideMangle,
                    line_number,
                ));
            }
            continue;
        }
        if line.starts_with(':') {
            builder.ingest_chain_declaration(line, line_number)?;
            continue;
        }
        if line.starts_with('-') {
            builder.ingest_live_rule(line, line_number)?;
            continue;
        }
        return Err(XtablesSaveProjectionError::at_line(
            XtablesSaveProjectionErrorKind::InvalidLine,
            line_number,
        ));
    }

    if current_table.is_some() {
        return Err(XtablesSaveProjectionError::global(
            XtablesSaveProjectionErrorKind::MissingCommit,
        ));
    }
    if !saw_mangle {
        return Err(XtablesSaveProjectionError::global(
            XtablesSaveProjectionErrorKind::MissingMangleTable,
        ));
    }
    builder.finish()
}

fn opaque_line_mentions_owned_state(line: &str) -> bool {
    line.split(|character: char| {
        !(character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_')
    })
    .filter(|token| !token.is_empty())
    .any(|token| token.starts_with("FLX"))
}

fn validate_input(input: &[u8]) -> Result<(), XtablesSaveProjectionError> {
    if input.is_empty() {
        return Err(XtablesSaveProjectionError::global(
            XtablesSaveProjectionErrorKind::EmptyInput,
        ));
    }
    if input.len() > MAX_XTABLES_RESTORE_BYTES {
        return Err(XtablesSaveProjectionError::global(
            XtablesSaveProjectionErrorKind::LimitExceeded,
        ));
    }
    if input.iter().filter(|byte| **byte == b'\n').count() > MAX_XTABLES_RESTORE_LINES {
        return Err(XtablesSaveProjectionError::global(
            XtablesSaveProjectionErrorKind::LimitExceeded,
        ));
    }
    if input.last() != Some(&b'\n') {
        return Err(XtablesSaveProjectionError::global(
            XtablesSaveProjectionErrorKind::MissingFinalLineFeed,
        ));
    }
    if input
        .iter()
        .copied()
        .any(|byte| byte != b'\n' && !(b' '..=b'~').contains(&byte))
    {
        return Err(XtablesSaveProjectionError::global(
            XtablesSaveProjectionErrorKind::NonAscii,
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct PendingRule {
    rule: XtablesOwnedRule,
    line: Option<usize>,
}

#[derive(Clone, Debug)]
struct PendingReference {
    reference: XtablesNativeReference,
    line: Option<usize>,
}

struct ProjectionBuilder {
    family: XtablesRestoreFamily,
    chains: BTreeMap<Box<str>, Vec<PendingRule>>,
    pending_sources: BTreeMap<Box<str>, Vec<PendingRule>>,
    source_lines: BTreeMap<Box<str>, Option<usize>>,
    native_targets: BTreeMap<Box<str>, Option<usize>>,
    source_ordinals: BTreeMap<Box<str>, u32>,
    native_references: Vec<PendingReference>,
    declaration_lines: BTreeMap<Box<str>, Option<usize>>,
}

impl ProjectionBuilder {
    fn new(family: XtablesRestoreFamily) -> Self {
        Self {
            family,
            chains: BTreeMap::new(),
            pending_sources: BTreeMap::new(),
            source_lines: BTreeMap::new(),
            native_targets: BTreeMap::new(),
            source_ordinals: BTreeMap::new(),
            native_references: Vec::new(),
            declaration_lines: BTreeMap::new(),
        }
    }

    fn ingest_chain_declaration(
        &mut self,
        line: &str,
        line_number: usize,
    ) -> Result<(), XtablesSaveProjectionError> {
        let parts = line.split(' ').collect::<Vec<_>>();
        if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
            return Err(XtablesSaveProjectionError::at_line(
                XtablesSaveProjectionErrorKind::InvalidChainDeclaration,
                line_number,
            ));
        }
        let chain = parts[0].strip_prefix(':').unwrap_or_default();
        if chain.is_empty() || !valid_counter(parts[2]) {
            return Err(XtablesSaveProjectionError::at_line(
                if chain.is_empty() {
                    XtablesSaveProjectionErrorKind::InvalidChainDeclaration
                } else {
                    XtablesSaveProjectionErrorKind::InvalidCounter
                },
                line_number,
            ));
        }
        if is_native_chain(chain) {
            if parts[1] != "-" {
                return Err(XtablesSaveProjectionError::at_line(
                    XtablesSaveProjectionErrorKind::InvalidChainDeclaration,
                    line_number,
                ));
            }
            self.declare_native(chain, Some(line_number))?;
        }
        Ok(())
    }

    fn declare_native(
        &mut self,
        chain: &str,
        line: Option<usize>,
    ) -> Result<(), XtablesSaveProjectionError> {
        if self.chains.contains_key(chain) {
            return Err(XtablesSaveProjectionError::at_optional_line(
                XtablesSaveProjectionErrorKind::DuplicateNativeChain,
                line,
            ));
        }
        let rules = self.pending_sources.remove(chain).unwrap_or_default();
        self.chains.insert(chain.into(), rules);
        self.declaration_lines.insert(chain.into(), line);
        Ok(())
    }

    fn ingest_live_rule(
        &mut self,
        line: &str,
        line_number: usize,
    ) -> Result<(), XtablesSaveProjectionError> {
        let scan = scan_rule(line, Some(line_number))?;
        let ordinal = self.next_source_ordinal(&scan.source, Some(line_number))?;
        let native_targets = scan
            .targets
            .iter()
            .filter(|target| is_native_chain(target))
            .cloned()
            .collect::<Vec<_>>();
        if is_native_chain(&scan.source) {
            let canonical = canonicalize_live_native_rule(line, self.family, Some(line_number))?;
            self.record_native_source_rule(
                &scan.source,
                XtablesOwnedRule(canonical.into_boxed_str()),
                false,
                &native_targets,
                Some(line_number),
            );
        } else if !native_targets.is_empty() {
            self.record_external_append(
                &scan.source,
                ordinal,
                native_targets,
                XtablesOwnedRule(line.into()),
                Some(line_number),
            );
        }
        Ok(())
    }

    fn ingest_expected_command(
        &mut self,
        command: &XtablesRestoreCommand,
        phase: XtablesExpectedStatePhase,
    ) -> Result<(), XtablesSaveProjectionError> {
        let line = render_live_append(command);
        let scan = scan_rule(&line, None)?;
        let native_targets = scan
            .targets
            .iter()
            .filter(|target| is_native_chain(target))
            .cloned()
            .collect::<Vec<_>>();
        if is_native_chain(&scan.source) {
            self.record_native_source_rule(
                &scan.source,
                XtablesOwnedRule(line.into()),
                command.kind() == XtablesRestoreCommandKind::Insert,
                &native_targets,
                None,
            );
            return Ok(());
        }
        if native_targets.is_empty() {
            return Err(XtablesSaveProjectionError::global(
                XtablesSaveProjectionErrorKind::ExpectedUnownedEntry,
            ));
        }
        if command.kind() != XtablesRestoreCommandKind::Insert {
            return Err(XtablesSaveProjectionError::global(
                XtablesSaveProjectionErrorKind::ExpectedExternalAppend,
            ));
        }
        if phase == XtablesExpectedStatePhase::OutputDetached && scan.source == "OUTPUT" {
            self.note_targets(&native_targets, None);
            return Ok(());
        }
        self.record_external_insert(&scan.source, native_targets, XtablesOwnedRule(line.into()));
        Ok(())
    }

    fn next_source_ordinal(
        &mut self,
        source: &str,
        line: Option<usize>,
    ) -> Result<NonZeroU32, XtablesSaveProjectionError> {
        let value = self.source_ordinals.entry(source.into()).or_default();
        *value = value.checked_add(1).ok_or_else(|| {
            XtablesSaveProjectionError::at_optional_line(
                XtablesSaveProjectionErrorKind::LimitExceeded,
                line,
            )
        })?;
        Ok(NonZeroU32::new(*value).expect("incremented rule ordinal is nonzero"))
    }

    fn record_native_source_rule(
        &mut self,
        source: &str,
        rule: XtablesOwnedRule,
        insert: bool,
        targets: &[String],
        line: Option<usize>,
    ) {
        let pending = PendingRule { rule, line };
        let rules = if let Some(rules) = self.chains.get_mut(source) {
            rules
        } else {
            self.source_lines.entry(source.into()).or_insert(line);
            self.pending_sources.entry(source.into()).or_default()
        };
        if insert {
            rules.insert(0, pending);
        } else {
            rules.push(pending);
        }
        self.note_targets(targets, line);
    }

    fn record_external_append(
        &mut self,
        source: &str,
        ordinal: NonZeroU32,
        targets: Vec<String>,
        rule: XtablesOwnedRule,
        line: Option<usize>,
    ) {
        self.note_targets(&targets, line);
        self.native_references.push(PendingReference {
            reference: XtablesNativeReference {
                source_chain: source.into(),
                ordinal,
                target_chains: targets
                    .into_iter()
                    .map(String::into_boxed_str)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                rule,
            },
            line,
        });
    }

    fn record_external_insert(
        &mut self,
        source: &str,
        targets: Vec<String>,
        rule: XtablesOwnedRule,
    ) {
        for reference in &mut self.native_references {
            if reference.reference.source_chain() == source {
                let next = reference
                    .reference
                    .ordinal
                    .get()
                    .checked_add(1)
                    .expect("bounded expected references fit in u32");
                reference.reference.ordinal =
                    NonZeroU32::new(next).expect("incremented ordinal is nonzero");
            }
        }
        self.record_external_append(
            source,
            NonZeroU32::new(1).expect("one is nonzero"),
            targets,
            rule,
            None,
        );
    }

    fn note_targets(&mut self, targets: &[String], line: Option<usize>) {
        for target in targets {
            self.native_targets
                .entry(target.clone().into())
                .or_insert(line);
        }
    }

    fn finish(mut self) -> Result<XtablesSaveProjection, XtablesSaveProjectionError> {
        self.validate_owned_artifact()?;
        if let Some((source, _)) = self.pending_sources.first_key_value() {
            return Err(XtablesSaveProjectionError::at_optional_line(
                XtablesSaveProjectionErrorKind::UndeclaredNativeSource,
                self.source_lines.get(source.as_ref()).copied().flatten(),
            ));
        }
        for (target, line) in &self.native_targets {
            if !self.chains.contains_key(target.as_ref()) {
                return Err(XtablesSaveProjectionError::at_optional_line(
                    XtablesSaveProjectionErrorKind::DanglingNativeTarget,
                    *line,
                ));
            }
        }

        self.native_references
            .sort_by(|left, right| left.reference.cmp(&right.reference));
        let chains = self
            .chains
            .into_iter()
            .map(|(name, rules)| {
                (
                    name,
                    XtablesOwnedChainState {
                        rules: rules
                            .into_iter()
                            .map(|pending| pending.rule)
                            .collect::<Vec<_>>()
                            .into_boxed_slice(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let native_references = self
            .native_references
            .into_iter()
            .map(|pending| pending.reference)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let digest = digest_projection(self.family, &chains, &native_references);
        Ok(XtablesSaveProjection {
            family: self.family,
            chains,
            native_references,
            digest,
        })
    }

    fn validate_owned_artifact(&self) -> Result<(), XtablesSaveProjectionError> {
        if self.chains.is_empty()
            && self.pending_sources.is_empty()
            && self.native_references.is_empty()
        {
            return Ok(());
        }
        let mut text = String::from("*mangle\n");
        let mut source_lines = Vec::new();
        for chain in self.chains.keys().chain(self.pending_sources.keys()) {
            text.push(':');
            text.push_str(chain);
            text.push_str(" - [0:0]\n");
            source_lines.push(
                self.declaration_lines
                    .get(chain.as_ref())
                    .copied()
                    .flatten()
                    .or_else(|| self.source_lines.get(chain.as_ref()).copied().flatten()),
            );
        }
        for rules in self.chains.values().chain(self.pending_sources.values()) {
            for pending in rules {
                text.push_str(pending.rule.as_str());
                text.push('\n');
                source_lines.push(pending.line);
            }
        }
        let mut references = self.native_references.iter().collect::<Vec<_>>();
        references.sort_by(|left, right| left.reference.cmp(&right.reference));
        for pending in references {
            text.push_str(pending.reference.rule().as_str());
            text.push('\n');
            source_lines.push(pending.line);
        }
        text.push_str("COMMIT\n");
        parse_xtables_restore(
            text.as_bytes(),
            XtablesRestoreContext::new(XtablesRestoreAction::Apply, self.family),
        )
        .map(|_| ())
        .map_err(|source| {
            let line = source
                .line()
                .and_then(|line| line.checked_sub(2))
                .and_then(|index| source_lines.get(index))
                .copied()
                .flatten();
            XtablesSaveProjectionError::invalid_owned(source, line)
        })
    }
}

fn canonicalize_live_native_rule(
    line: &str,
    family: XtablesRestoreFamily,
    line_number: Option<usize>,
) -> Result<String, XtablesSaveProjectionError> {
    if !line.contains(" --on-ip ") {
        return Ok(line.to_owned());
    }
    let mut tokens = tokenize(line, line_number)?;
    let tproxy = tokens
        .windows(2)
        .any(|pair| matches!(pair[0].as_str(), "-j" | "--jump") && pair[1].as_str() == "TPROXY");
    if !tproxy {
        return Ok(line.to_owned());
    }
    let expected = match family {
        XtablesRestoreFamily::Ipv4 => "0.0.0.0",
        XtablesRestoreFamily::Ipv6 => "::",
    };
    let positions = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| (token == "--on-ip").then_some(index))
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err(XtablesSaveProjectionError::at_optional_line(
            XtablesSaveProjectionErrorKind::InvalidLine,
            line_number,
        ));
    }
    let index = positions[0];
    if tokens.get(index + 1).map(String::as_str) != Some(expected) {
        return Ok(line.to_owned());
    }
    tokens.drain(index..=index + 1);
    Ok(tokens.join(" "))
}

fn valid_counter(token: &str) -> bool {
    let Some(inner) = token
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return false;
    };
    let Some((packets, bytes)) = inner.split_once(':') else {
        return false;
    };
    !packets.is_empty()
        && !bytes.is_empty()
        && packets.as_bytes().iter().all(u8::is_ascii_digit)
        && bytes.as_bytes().iter().all(u8::is_ascii_digit)
}

struct RuleScan {
    source: String,
    targets: Vec<String>,
}

fn scan_rule(
    line: &str,
    line_number: Option<usize>,
) -> Result<RuleScan, XtablesSaveProjectionError> {
    let tokens = tokenize(line, line_number)?;
    if tokens.first().map(String::as_str) != Some("-A") || tokens.len() < 2 {
        return Err(XtablesSaveProjectionError::at_optional_line(
            XtablesSaveProjectionErrorKind::InvalidLine,
            line_number,
        ));
    }
    let source = tokens[1].clone();
    if source.is_empty() {
        return Err(XtablesSaveProjectionError::at_optional_line(
            XtablesSaveProjectionErrorKind::InvalidLine,
            line_number,
        ));
    }
    let mut targets = Vec::new();
    let mut index = 2;
    while index < tokens.len() {
        if matches!(tokens[index].as_str(), "-j" | "--jump" | "-g" | "--goto") {
            let Some(target) = tokens.get(index + 1) else {
                return Err(XtablesSaveProjectionError::at_optional_line(
                    XtablesSaveProjectionErrorKind::InvalidLine,
                    line_number,
                ));
            };
            targets.push(target.clone());
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(RuleScan { source, targets })
}

fn tokenize(
    line: &str,
    line_number: Option<usize>,
) -> Result<Vec<String>, XtablesSaveProjectionError> {
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
            ' ' => {
                if !current.is_empty() {
                    push_token(&mut tokens, &mut current, line_number)?;
                }
            }
            _ => current.push(character),
        }
    }
    if escaped || quote.is_some() {
        return Err(XtablesSaveProjectionError::at_optional_line(
            XtablesSaveProjectionErrorKind::InvalidQuotedToken,
            line_number,
        ));
    }
    if !current.is_empty() {
        push_token(&mut tokens, &mut current, line_number)?;
    }
    if tokens.is_empty() {
        return Err(XtablesSaveProjectionError::at_optional_line(
            XtablesSaveProjectionErrorKind::InvalidLine,
            line_number,
        ));
    }
    Ok(tokens)
}

fn push_token(
    tokens: &mut Vec<String>,
    current: &mut String,
    line_number: Option<usize>,
) -> Result<(), XtablesSaveProjectionError> {
    if tokens.len() == MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND {
        return Err(XtablesSaveProjectionError::at_optional_line(
            XtablesSaveProjectionErrorKind::TooManyTokens,
            line_number,
        ));
    }
    if current.len() > MAX_XTABLES_RESTORE_TOKEN_BYTES {
        return Err(XtablesSaveProjectionError::at_optional_line(
            XtablesSaveProjectionErrorKind::TokenTooLong,
            line_number,
        ));
    }
    tokens.push(std::mem::take(current));
    Ok(())
}

fn render_live_append(command: &XtablesRestoreCommand) -> String {
    let mut output = format!("-A {}", command.chain());
    for argument in command.arguments() {
        output.push(' ');
        output.push_str(argument.as_str());
    }
    output
}

fn is_native_chain(chain: &str) -> bool {
    chain.starts_with("FLX")
}

/// Recognizes the private native chain namespace owned by Flux.
pub(crate) fn is_flux_owned_chain(chain: &str) -> bool {
    is_native_chain(chain)
}

fn digest_projection(
    family: XtablesRestoreFamily,
    chains: &BTreeMap<Box<str>, XtablesOwnedChainState>,
    references: &[XtablesNativeReference],
) -> XtablesSaveProjectionDigest {
    let mut digest = Sha256::new();
    digest.update(XTABLES_SAVE_PROJECTION_DOMAIN);
    digest.update([match family {
        XtablesRestoreFamily::Ipv4 => 4,
        XtablesRestoreFamily::Ipv6 => 6,
    }]);
    digest_count(&mut digest, chains.len());
    for (name, chain) in chains {
        digest_string(&mut digest, name);
        digest_count(&mut digest, chain.rules.len());
        for rule in &chain.rules {
            digest_string(&mut digest, rule.as_str());
        }
    }
    digest_count(&mut digest, references.len());
    for reference in references {
        digest_string(&mut digest, reference.source_chain());
        digest.update(reference.ordinal().get().to_be_bytes());
        digest_count(&mut digest, reference.target_chains.len());
        for target in &reference.target_chains {
            digest_string(&mut digest, target);
        }
        digest_string(&mut digest, reference.rule().as_str());
    }
    XtablesSaveProjectionDigest(digest.finalize().into())
}

fn digest_count(digest: &mut Sha256, count: usize) {
    digest.update(
        u64::try_from(count)
            .expect("bounded projection count fits in u64")
            .to_be_bytes(),
    );
}

fn digest_string(digest: &mut Sha256, value: &str) {
    digest_count(digest, value.len());
    digest.update(value.as_bytes());
}

#[cfg(test)]
#[path = "save_tests.rs"]
mod tests;
