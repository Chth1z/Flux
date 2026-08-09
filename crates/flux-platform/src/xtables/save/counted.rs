//! Strict counter-aware projection for one owner-derived xtables chain.
//!
//! The ordinary save projection deliberately erases counters. This parser
//! first validates and strips the fixed `iptables-save -c` rule prefix, then
//! reuses that existing projection for structural identity before returning
//! packet counts for one exact expected owned chain.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use super::{
    XtablesExpectedState, XtablesRestoreFamily, XtablesSaveProjectionError, is_native_chain,
    project_xtables_save, scan_rule, validate_input,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::xtables) struct XtablesCountedChainPackets(Box<[u64]>);

impl XtablesCountedChainPackets {
    #[must_use]
    pub(in crate::xtables) const fn as_slice(&self) -> &[u64] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::xtables) enum XtablesCountedSaveErrorKind {
    MissingRuleCounter,
    InvalidRuleCounter,
    RuleCounterOverflow,
    Projection,
    ExpectedStateMismatch,
    MissingExpectedChain,
}

#[derive(Debug)]
pub(in crate::xtables) struct XtablesCountedSaveError {
    kind: XtablesCountedSaveErrorKind,
    line: Option<usize>,
    source: Option<XtablesSaveProjectionError>,
}

impl XtablesCountedSaveError {
    const fn at_line(kind: XtablesCountedSaveErrorKind, line: usize) -> Self {
        Self {
            kind,
            line: Some(line),
            source: None,
        }
    }

    const fn global(kind: XtablesCountedSaveErrorKind) -> Self {
        Self {
            kind,
            line: None,
            source: None,
        }
    }

    fn projection(source: XtablesSaveProjectionError) -> Self {
        Self {
            kind: XtablesCountedSaveErrorKind::Projection,
            line: source.line(),
            source: Some(source),
        }
    }

    #[must_use]
    pub(in crate::xtables) const fn kind(&self) -> XtablesCountedSaveErrorKind {
        self.kind
    }

    #[must_use]
    pub(in crate::xtables) const fn line(&self) -> Option<usize> {
        self.line
    }
}

impl fmt::Display for XtablesCountedSaveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid bounded counted xtables-save projection")?;
        if let Some(line) = self.line {
            write!(formatter, " at line {line}")?;
        }
        write!(formatter, ": {:?}", self.kind)
    }
}

impl Error for XtablesCountedSaveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// Validate one complete `iptables-save -c` document against the exact
/// owner-derived state and return packet counts in that chain's rule order.
pub(in crate::xtables) fn project_expected_counted_chain(
    input: &[u8],
    family: XtablesRestoreFamily,
    expected: &XtablesExpectedState,
    chain: &str,
) -> Result<XtablesCountedChainPackets, XtablesCountedSaveError> {
    validate_input(input).map_err(XtablesCountedSaveError::projection)?;
    let text = std::str::from_utf8(input).expect("validated ASCII is valid UTF-8");
    let mut normalized = String::with_capacity(input.len());
    let mut counted_rules = BTreeMap::<Box<str>, Vec<u64>>::new();

    for (index, line) in text[..text.len() - 1].split('\n').enumerate() {
        let line_number = index + 1;
        if is_non_rule_line(line) {
            normalized.push_str(line);
        } else {
            let (packets, rule) = parse_counted_rule(line, line_number)?;
            let scan =
                scan_rule(rule, Some(line_number)).map_err(XtablesCountedSaveError::projection)?;
            if is_native_chain(&scan.source) {
                counted_rules
                    .entry(scan.source.into_boxed_str())
                    .or_default()
                    .push(packets);
            }
            normalized.push_str(rule);
        }
        normalized.push('\n');
    }

    let observed = project_xtables_save(normalized.as_bytes(), family)
        .map_err(XtablesCountedSaveError::projection)?;
    if !expected.is_satisfied_by(&observed) {
        return Err(XtablesCountedSaveError::global(
            XtablesCountedSaveErrorKind::ExpectedStateMismatch,
        ));
    }
    let expected_rule_count = expected
        .projection()
        .chain(chain)
        .ok_or_else(|| {
            XtablesCountedSaveError::global(XtablesCountedSaveErrorKind::MissingExpectedChain)
        })?
        .rules()
        .len();
    let packets = counted_rules.remove(chain).ok_or_else(|| {
        XtablesCountedSaveError::global(XtablesCountedSaveErrorKind::MissingExpectedChain)
    })?;
    if packets.len() != expected_rule_count {
        return Err(XtablesCountedSaveError::global(
            XtablesCountedSaveErrorKind::ExpectedStateMismatch,
        ));
    }
    Ok(XtablesCountedChainPackets(packets.into_boxed_slice()))
}

fn is_non_rule_line(line: &str) -> bool {
    line.starts_with('#') || line.starts_with('*') || line.starts_with(':') || line == "COMMIT"
}

fn parse_counted_rule(
    line: &str,
    line_number: usize,
) -> Result<(u64, &str), XtablesCountedSaveError> {
    if line.starts_with("-A") {
        return Err(XtablesCountedSaveError::at_line(
            XtablesCountedSaveErrorKind::MissingRuleCounter,
            line_number,
        ));
    }
    let Some((counter, rule)) = line.split_once(' ') else {
        return Err(XtablesCountedSaveError::at_line(
            XtablesCountedSaveErrorKind::InvalidRuleCounter,
            line_number,
        ));
    };
    if !rule.starts_with("-A ") {
        return Err(XtablesCountedSaveError::at_line(
            XtablesCountedSaveErrorKind::InvalidRuleCounter,
            line_number,
        ));
    }
    let Some(inner) = counter
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return Err(XtablesCountedSaveError::at_line(
            XtablesCountedSaveErrorKind::InvalidRuleCounter,
            line_number,
        ));
    };
    let Some((packets, bytes)) = inner.split_once(':') else {
        return Err(XtablesCountedSaveError::at_line(
            XtablesCountedSaveErrorKind::InvalidRuleCounter,
            line_number,
        ));
    };
    if packets.is_empty()
        || bytes.is_empty()
        || !packets.as_bytes().iter().all(u8::is_ascii_digit)
        || !bytes.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return Err(XtablesCountedSaveError::at_line(
            XtablesCountedSaveErrorKind::InvalidRuleCounter,
            line_number,
        ));
    }
    let packets = packets.parse::<u64>().map_err(|_| {
        XtablesCountedSaveError::at_line(
            XtablesCountedSaveErrorKind::RuleCounterOverflow,
            line_number,
        )
    })?;
    bytes.parse::<u64>().map_err(|_| {
        XtablesCountedSaveError::at_line(
            XtablesCountedSaveErrorKind::RuleCounterOverflow,
            line_number,
        )
    })?;
    Ok((packets, rule))
}

#[cfg(test)]
#[path = "counted_tests.rs"]
mod tests;
