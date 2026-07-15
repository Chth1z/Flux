use std::error::Error;
use std::fmt::{self, Write as _};
use std::num::NonZeroU32;

use flux_platform::{
    LEGACY_RULES_DIGEST_BYTES, LEGACY_RULES_IDENTITY_SCHEMA_VERSION, LegacyRulesArtifactPair,
    LegacyRulesArtifactSet, LegacyRulesResourceTotals, MAX_XTABLES_RESTORE_BYTES,
    MAX_XTABLES_RESTORE_COMMANDS, MAX_XTABLES_RESTORE_LINES,
    MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND, MAX_XTABLES_RESTORE_TRANSACTIONS, XtablesRestoreAction,
    XtablesRestoreArtifact, XtablesRestoreFamily, XtablesRestoreResourceUsage,
};

pub const LEGACY_RULES_SET_MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const MAX_LEGACY_RULES_SET_MANIFEST_BYTES: usize = 16 * 1024;

const HEADER: &str = "FLUX_LEGACY_RULES_SET_MANIFEST_V1";
const MAX_GENERATION: u32 = i32::MAX as u32;

/// Exact enabled-family shape recorded by one legacy rules-set manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyRulesFamilyShape {
    Ipv4,
    Ipv4AndIpv6,
}

impl LegacyRulesFamilyShape {
    #[must_use]
    pub const fn ipv6_enabled(self) -> bool {
        matches!(self, Self::Ipv4AndIpv6)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv4AndIpv6 => "ipv4,ipv6",
        }
    }
}

/// Parsed SHA-256 identity bytes from a strict legacy rules-set manifest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct LegacyRulesManifestDigest([u8; LEGACY_RULES_DIGEST_BYTES]);

impl LegacyRulesManifestDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; LEGACY_RULES_DIGEST_BYTES] {
        &self.0
    }

    fn from_bytes(bytes: &[u8; LEGACY_RULES_DIGEST_BYTES]) -> Self {
        Self(*bytes)
    }
}

/// Bounded parser resource counts recorded for one artifact, pair, or set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyRulesManifestResourceTotals {
    input_bytes: usize,
    lines: usize,
    transactions: usize,
    chain_declarations: usize,
    commands: usize,
    tokens: usize,
}

impl LegacyRulesManifestResourceTotals {
    #[must_use]
    pub const fn input_bytes(self) -> usize {
        self.input_bytes
    }

    #[must_use]
    pub const fn lines(self) -> usize {
        self.lines
    }

    #[must_use]
    pub const fn transactions(self) -> usize {
        self.transactions
    }

    #[must_use]
    pub const fn chain_declarations(self) -> usize {
        self.chain_declarations
    }

    #[must_use]
    pub const fn commands(self) -> usize {
        self.commands
    }

    #[must_use]
    pub const fn tokens(self) -> usize {
        self.tokens
    }

    const fn from_restore(usage: XtablesRestoreResourceUsage) -> Self {
        Self {
            input_bytes: usage.input_bytes(),
            lines: usage.lines(),
            transactions: usage.transactions(),
            chain_declarations: usage.chain_declarations(),
            commands: usage.commands(),
            tokens: usage.tokens(),
        }
    }

    const fn from_legacy(totals: LegacyRulesResourceTotals) -> Self {
        Self {
            input_bytes: totals.input_bytes(),
            lines: totals.lines(),
            transactions: totals.transactions(),
            chain_declarations: totals.chain_declarations(),
            commands: totals.commands(),
            tokens: totals.tokens(),
        }
    }

    const fn checked_add(self, other: Self) -> Option<Self> {
        let Some(input_bytes) = self.input_bytes.checked_add(other.input_bytes) else {
            return None;
        };
        let Some(lines) = self.lines.checked_add(other.lines) else {
            return None;
        };
        let Some(transactions) = self.transactions.checked_add(other.transactions) else {
            return None;
        };
        let Some(chain_declarations) = self
            .chain_declarations
            .checked_add(other.chain_declarations)
        else {
            return None;
        };
        let Some(commands) = self.commands.checked_add(other.commands) else {
            return None;
        };
        let Some(tokens) = self.tokens.checked_add(other.tokens) else {
            return None;
        };
        Some(Self {
            input_bytes,
            lines,
            transactions,
            chain_declarations,
            commands,
            tokens,
        })
    }
}

/// Digest and parser resource identity for one apply or cleanup artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyRulesArtifactManifest {
    digest: LegacyRulesManifestDigest,
    resource_totals: LegacyRulesManifestResourceTotals,
}

impl LegacyRulesArtifactManifest {
    #[must_use]
    pub const fn digest(&self) -> LegacyRulesManifestDigest {
        self.digest
    }

    #[must_use]
    pub const fn resource_totals(&self) -> LegacyRulesManifestResourceTotals {
        self.resource_totals
    }

    fn from_artifact(artifact: &XtablesRestoreArtifact) -> Self {
        Self {
            digest: LegacyRulesManifestDigest::from_bytes(artifact.digest().as_bytes()),
            resource_totals: LegacyRulesManifestResourceTotals::from_restore(artifact.usage()),
        }
    }

    fn validate_resource_limits(&self) -> Result<(), LegacyRulesSetManifestError> {
        let totals = self.resource_totals;
        let max_tokens = MAX_XTABLES_RESTORE_COMMANDS
            .checked_mul(MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND)
            .expect("xtables token bound fits usize");
        for (field, actual, maximum) in [
            ("input_bytes", totals.input_bytes, MAX_XTABLES_RESTORE_BYTES),
            ("lines", totals.lines, MAX_XTABLES_RESTORE_LINES),
            (
                "transactions",
                totals.transactions,
                MAX_XTABLES_RESTORE_TRANSACTIONS,
            ),
            (
                "chain_declarations",
                totals.chain_declarations,
                MAX_XTABLES_RESTORE_LINES,
            ),
            ("commands", totals.commands, MAX_XTABLES_RESTORE_COMMANDS),
            ("tokens", totals.tokens, max_tokens),
        ] {
            if actual > maximum {
                return Err(manifest_error(
                    LegacyRulesSetManifestErrorKind::InvalidValue,
                    format!("legacy rules artifact resource {field}={actual} exceeds {maximum}"),
                ));
            }
        }
        Ok(())
    }
}

/// Digest and aggregate identity for one address-family apply/cleanup pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyRulesPairManifest {
    family: XtablesRestoreFamily,
    digest: LegacyRulesManifestDigest,
    resource_totals: LegacyRulesManifestResourceTotals,
    apply: LegacyRulesArtifactManifest,
    cleanup: LegacyRulesArtifactManifest,
}

impl LegacyRulesPairManifest {
    #[must_use]
    pub const fn family(&self) -> XtablesRestoreFamily {
        self.family
    }

    #[must_use]
    pub const fn digest(&self) -> LegacyRulesManifestDigest {
        self.digest
    }

    #[must_use]
    pub const fn resource_totals(&self) -> LegacyRulesManifestResourceTotals {
        self.resource_totals
    }

    #[must_use]
    pub const fn apply(&self) -> &LegacyRulesArtifactManifest {
        &self.apply
    }

    #[must_use]
    pub const fn cleanup(&self) -> &LegacyRulesArtifactManifest {
        &self.cleanup
    }

    fn from_pair(
        expected_family: XtablesRestoreFamily,
        pair: &LegacyRulesArtifactPair,
    ) -> Result<Self, LegacyRulesSetManifestError> {
        if pair.schema_version() != LEGACY_RULES_IDENTITY_SCHEMA_VERSION {
            return Err(manifest_error(
                LegacyRulesSetManifestErrorKind::UnsupportedSchema,
                format!(
                    "legacy rules pair uses unsupported schema version {}",
                    pair.schema_version()
                ),
            ));
        }
        if pair.family() != expected_family
            || pair.apply().context().family() != expected_family
            || pair.apply().context().action() != XtablesRestoreAction::Apply
            || pair.cleanup().context().family() != expected_family
            || pair.cleanup().context().action() != XtablesRestoreAction::Cleanup
        {
            return Err(manifest_error(
                LegacyRulesSetManifestErrorKind::IdentityMismatch,
                "legacy rules pair context does not match its expected family and actions",
            ));
        }
        Ok(Self {
            family: expected_family,
            digest: LegacyRulesManifestDigest::from_bytes(pair.digest().as_bytes()),
            resource_totals: LegacyRulesManifestResourceTotals::from_legacy(pair.resource_totals()),
            apply: LegacyRulesArtifactManifest::from_artifact(pair.apply()),
            cleanup: LegacyRulesArtifactManifest::from_artifact(pair.cleanup()),
        })
    }

    fn validate_internal_consistency(&self) -> Result<(), LegacyRulesSetManifestError> {
        self.apply.validate_resource_limits()?;
        self.cleanup.validate_resource_limits()?;
        let expected = self
            .apply
            .resource_totals
            .checked_add(self.cleanup.resource_totals)
            .ok_or_else(|| {
                manifest_error(
                    LegacyRulesSetManifestErrorKind::InvalidValue,
                    "legacy rules pair resource totals overflow",
                )
            })?;
        if self.resource_totals != expected {
            return Err(manifest_error(
                LegacyRulesSetManifestErrorKind::InvalidValue,
                "legacy rules pair resource totals do not equal apply plus cleanup totals",
            ));
        }
        Ok(())
    }
}

/// Strict, deterministic, Generation-bound identity for a rendered legacy rules set.
///
/// This type is deliberately observation-only. Parsing or verifying it does not authorize restore
/// execution, create writer ownership, or attest kernel state and readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyRulesSetManifest {
    generation: NonZeroU32,
    families: LegacyRulesFamilyShape,
    plan_digest: LegacyRulesManifestDigest,
    set_digest: LegacyRulesManifestDigest,
    resource_totals: LegacyRulesManifestResourceTotals,
    ipv4: LegacyRulesPairManifest,
    ipv6: Option<LegacyRulesPairManifest>,
}

impl LegacyRulesSetManifest {
    /// Bind one renderer-owned artifact set to a nonzero shell-issued Generation.
    pub fn from_artifact_set(
        generation: NonZeroU32,
        artifacts: &LegacyRulesArtifactSet,
    ) -> Result<Self, LegacyRulesSetManifestError> {
        if generation.get() > MAX_GENERATION {
            return Err(invalid_value(
                "generation",
                generation.get().to_string(),
                "expected an integer in 1..=2147483647",
            ));
        }
        if artifacts.schema_version() != LEGACY_RULES_IDENTITY_SCHEMA_VERSION {
            return Err(manifest_error(
                LegacyRulesSetManifestErrorKind::UnsupportedSchema,
                format!(
                    "legacy rules set uses unsupported schema version {}",
                    artifacts.schema_version()
                ),
            ));
        }
        let ipv4 =
            LegacyRulesPairManifest::from_pair(XtablesRestoreFamily::Ipv4, artifacts.ipv4())?;
        let ipv6 = artifacts
            .ipv6()
            .map(|pair| LegacyRulesPairManifest::from_pair(XtablesRestoreFamily::Ipv6, pair))
            .transpose()?;
        let plan_digest = LegacyRulesManifestDigest::from_bytes(artifacts.plan_digest().as_bytes());
        if artifacts.ipv4().plan_digest().as_bytes() != plan_digest.as_bytes()
            || artifacts
                .ipv6()
                .is_some_and(|pair| pair.plan_digest().as_bytes() != plan_digest.as_bytes())
        {
            return Err(manifest_error(
                LegacyRulesSetManifestErrorKind::IdentityMismatch,
                "legacy rules pair plan digest does not match the set plan digest",
            ));
        }
        let manifest = Self {
            generation,
            families: if ipv6.is_some() {
                LegacyRulesFamilyShape::Ipv4AndIpv6
            } else {
                LegacyRulesFamilyShape::Ipv4
            },
            plan_digest,
            set_digest: LegacyRulesManifestDigest::from_bytes(artifacts.digest().as_bytes()),
            resource_totals: LegacyRulesManifestResourceTotals::from_legacy(
                artifacts.resource_totals(),
            ),
            ipv4,
            ipv6,
        };
        manifest.validate_internal_consistency()?;
        Ok(manifest)
    }

    /// Parse only the canonical schema-v1 line document and reject inconsistent resource totals.
    pub fn parse(bytes: &[u8]) -> Result<Self, LegacyRulesSetManifestError> {
        if bytes.len() > MAX_LEGACY_RULES_SET_MANIFEST_BYTES {
            return Err(manifest_error(
                LegacyRulesSetManifestErrorKind::InvalidStructure,
                format!(
                    "legacy rules set manifest exceeds {MAX_LEGACY_RULES_SET_MANIFEST_BYTES} bytes"
                ),
            ));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| {
            manifest_error(
                LegacyRulesSetManifestErrorKind::InvalidEncoding,
                "legacy rules set manifest is not valid UTF-8",
            )
        })?;
        let body = text.strip_suffix('\n').ok_or_else(|| {
            manifest_error(
                LegacyRulesSetManifestErrorKind::InvalidStructure,
                "legacy rules set manifest must end with exactly one LF",
            )
        })?;
        if body.as_bytes().contains(&b'\r') {
            return Err(manifest_error(
                LegacyRulesSetManifestErrorKind::InvalidStructure,
                "legacy rules set manifest must use LF line endings",
            ));
        }
        let mut lines = body.split('\n');
        if lines.next() != Some(HEADER) {
            return Err(manifest_error(
                LegacyRulesSetManifestErrorKind::InvalidStructure,
                format!("legacy rules set manifest header must be {HEADER}"),
            ));
        }

        let generation = parse_generation(next_value(&mut lines, "generation")?)?;
        let families = match next_value(&mut lines, "families")? {
            "ipv4" => LegacyRulesFamilyShape::Ipv4,
            "ipv4,ipv6" => LegacyRulesFamilyShape::Ipv4AndIpv6,
            value => {
                return Err(invalid_value(
                    "families",
                    value,
                    "expected ipv4 or ipv4,ipv6",
                ));
            }
        };
        let plan_digest = parse_digest("plan_digest", next_value(&mut lines, "plan_digest")?)?;
        let set_digest = parse_digest("set_digest", next_value(&mut lines, "set_digest")?)?;
        let resource_totals = parse_totals(&mut lines, "set")?;
        let ipv4 = parse_pair(&mut lines, "ipv4", XtablesRestoreFamily::Ipv4)?;
        let ipv6 = if families.ipv6_enabled() {
            Some(parse_pair(&mut lines, "ipv6", XtablesRestoreFamily::Ipv6)?)
        } else {
            None
        };
        if let Some(extra) = lines.next() {
            return Err(manifest_error(
                LegacyRulesSetManifestErrorKind::InvalidStructure,
                format!("legacy rules set manifest has unexpected trailing line '{extra}'"),
            ));
        }
        let manifest = Self {
            generation,
            families,
            plan_digest,
            set_digest,
            resource_totals,
            ipv4,
            ipv6,
        };
        manifest.validate_internal_consistency()?;
        if manifest.render_canonical().as_ref() != bytes {
            return Err(manifest_error(
                LegacyRulesSetManifestErrorKind::InvalidStructure,
                "legacy rules set manifest is not in canonical form",
            ));
        }
        Ok(manifest)
    }

    /// Compare every identity field with one exact Generation and freshly rendered artifact set.
    ///
    /// Success remains non-authorizing and does not imply restore execution or kernel acceptance.
    pub fn verify(
        &self,
        generation: NonZeroU32,
        artifacts: &LegacyRulesArtifactSet,
    ) -> Result<(), LegacyRulesSetManifestError> {
        let expected = Self::from_artifact_set(generation, artifacts)?;
        if *self == expected {
            Ok(())
        } else {
            Err(manifest_error(
                LegacyRulesSetManifestErrorKind::IdentityMismatch,
                "legacy rules set manifest does not match the supplied Generation and artifacts",
            ))
        }
    }

    #[must_use]
    pub fn render_canonical(&self) -> Box<[u8]> {
        let mut output = String::with_capacity(4096);
        writeln!(output, "{HEADER}").expect("writing to String cannot fail");
        writeln!(output, "generation={}", self.generation).expect("writing to String cannot fail");
        writeln!(output, "families={}", self.families.as_str())
            .expect("writing to String cannot fail");
        write_digest(&mut output, "plan_digest", self.plan_digest);
        write_digest(&mut output, "set_digest", self.set_digest);
        write_totals(&mut output, "set", self.resource_totals);
        write_pair(&mut output, "ipv4", &self.ipv4);
        if let Some(ipv6) = &self.ipv6 {
            write_pair(&mut output, "ipv6", ipv6);
        }
        debug_assert!(output.len() <= MAX_LEGACY_RULES_SET_MANIFEST_BYTES);
        output.into_bytes().into_boxed_slice()
    }

    #[must_use]
    pub const fn generation(&self) -> NonZeroU32 {
        self.generation
    }

    #[must_use]
    pub const fn families(&self) -> LegacyRulesFamilyShape {
        self.families
    }

    #[must_use]
    pub const fn plan_digest(&self) -> LegacyRulesManifestDigest {
        self.plan_digest
    }

    #[must_use]
    pub const fn set_digest(&self) -> LegacyRulesManifestDigest {
        self.set_digest
    }

    #[must_use]
    pub const fn resource_totals(&self) -> LegacyRulesManifestResourceTotals {
        self.resource_totals
    }

    #[must_use]
    pub const fn ipv4(&self) -> &LegacyRulesPairManifest {
        &self.ipv4
    }

    #[must_use]
    pub const fn ipv6(&self) -> Option<&LegacyRulesPairManifest> {
        self.ipv6.as_ref()
    }

    fn validate_internal_consistency(&self) -> Result<(), LegacyRulesSetManifestError> {
        self.ipv4.validate_internal_consistency()?;
        if let Some(ipv6) = &self.ipv6 {
            ipv6.validate_internal_consistency()?;
        }
        let expected = match &self.ipv6 {
            Some(ipv6) => self.ipv4.resource_totals.checked_add(ipv6.resource_totals),
            None => Some(self.ipv4.resource_totals),
        }
        .ok_or_else(|| {
            manifest_error(
                LegacyRulesSetManifestErrorKind::InvalidValue,
                "legacy rules set resource totals overflow",
            )
        })?;
        if self.resource_totals != expected {
            return Err(manifest_error(
                LegacyRulesSetManifestErrorKind::InvalidValue,
                "legacy rules set resource totals do not equal enabled family-pair totals",
            ));
        }
        Ok(())
    }
}

fn parse_pair<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    prefix: &'static str,
    family: XtablesRestoreFamily,
) -> Result<LegacyRulesPairManifest, LegacyRulesSetManifestError> {
    let digest_name = format!("{prefix}_pair_digest");
    let digest = parse_digest(&digest_name, next_value(lines, &digest_name)?)?;
    let resource_totals = parse_totals(lines, &format!("{prefix}_pair"))?;
    let apply = parse_artifact(lines, &format!("{prefix}_apply"))?;
    let cleanup = parse_artifact(lines, &format!("{prefix}_cleanup"))?;
    Ok(LegacyRulesPairManifest {
        family,
        digest,
        resource_totals,
        apply,
        cleanup,
    })
}

fn parse_artifact<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    prefix: &str,
) -> Result<LegacyRulesArtifactManifest, LegacyRulesSetManifestError> {
    let digest_name = format!("{prefix}_digest");
    Ok(LegacyRulesArtifactManifest {
        digest: parse_digest(&digest_name, next_value(lines, &digest_name)?)?,
        resource_totals: parse_totals(lines, prefix)?,
    })
}

fn parse_totals<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    prefix: &str,
) -> Result<LegacyRulesManifestResourceTotals, LegacyRulesSetManifestError> {
    Ok(LegacyRulesManifestResourceTotals {
        input_bytes: parse_count(lines, prefix, "input_bytes")?,
        lines: parse_count(lines, prefix, "lines")?,
        transactions: parse_count(lines, prefix, "transactions")?,
        chain_declarations: parse_count(lines, prefix, "chain_declarations")?,
        commands: parse_count(lines, prefix, "commands")?,
        tokens: parse_count(lines, prefix, "tokens")?,
    })
}

fn parse_count<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    prefix: &str,
    field: &str,
) -> Result<usize, LegacyRulesSetManifestError> {
    let name = format!("{prefix}_{field}");
    let value = next_value(lines, &name)?;
    let parsed = value.parse::<usize>().ok().filter(|parsed| {
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && parsed.to_string() == value
    });
    parsed.ok_or_else(|| invalid_value(&name, value, "expected a canonical decimal integer"))
}

fn parse_generation(value: &str) -> Result<NonZeroU32, LegacyRulesSetManifestError> {
    let generation = value
        .parse::<u32>()
        .ok()
        .filter(|generation| {
            (1..=MAX_GENERATION).contains(generation)
                && generation.to_string() == value
                && value.bytes().all(|byte| byte.is_ascii_digit())
        })
        .and_then(NonZeroU32::new);
    generation
        .ok_or_else(|| invalid_value("generation", value, "expected an integer in 1..=2147483647"))
}

fn parse_digest(
    name: &str,
    value: &str,
) -> Result<LegacyRulesManifestDigest, LegacyRulesSetManifestError> {
    if value.len() != LEGACY_RULES_DIGEST_BYTES * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid_value(
            name,
            value,
            "expected exactly 64 lowercase hexadecimal characters",
        ));
    }
    let mut digest = [0_u8; LEGACY_RULES_DIGEST_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_value(pair[0]) << 4) | hex_value(pair[1]);
    }
    Ok(LegacyRulesManifestDigest(digest))
}

const fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn next_value<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    name: &str,
) -> Result<&'a str, LegacyRulesSetManifestError> {
    let line = lines.next().ok_or_else(|| {
        manifest_error(
            LegacyRulesSetManifestErrorKind::InvalidStructure,
            format!("legacy rules set manifest is missing field {name}"),
        )
    })?;
    let prefix = format!("{name}=");
    line.strip_prefix(&prefix).ok_or_else(|| {
        manifest_error(
            LegacyRulesSetManifestErrorKind::InvalidStructure,
            format!("legacy rules set manifest expected field {name}, found '{line}'"),
        )
    })
}

fn write_pair(output: &mut String, prefix: &str, pair: &LegacyRulesPairManifest) {
    write_digest(output, &format!("{prefix}_pair_digest"), pair.digest);
    write_totals(output, &format!("{prefix}_pair"), pair.resource_totals);
    write_artifact(output, &format!("{prefix}_apply"), &pair.apply);
    write_artifact(output, &format!("{prefix}_cleanup"), &pair.cleanup);
}

fn write_artifact(output: &mut String, prefix: &str, artifact: &LegacyRulesArtifactManifest) {
    write_digest(output, &format!("{prefix}_digest"), artifact.digest);
    write_totals(output, prefix, artifact.resource_totals);
}

fn write_digest(output: &mut String, name: &str, digest: LegacyRulesManifestDigest) {
    write!(output, "{name}=").expect("writing to String cannot fail");
    for byte in digest.0 {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output.push('\n');
}

fn write_totals(output: &mut String, prefix: &str, totals: LegacyRulesManifestResourceTotals) {
    for (field, value) in [
        ("input_bytes", totals.input_bytes),
        ("lines", totals.lines),
        ("transactions", totals.transactions),
        ("chain_declarations", totals.chain_declarations),
        ("commands", totals.commands),
        ("tokens", totals.tokens),
    ] {
        writeln!(output, "{prefix}_{field}={value}").expect("writing to String cannot fail");
    }
}

/// Stable category for strict manifest parsing and identity verification failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyRulesSetManifestErrorKind {
    InvalidEncoding,
    InvalidStructure,
    InvalidValue,
    UnsupportedSchema,
    IdentityMismatch,
}

/// Strict legacy rules-set manifest parse or verification failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyRulesSetManifestError {
    kind: LegacyRulesSetManifestErrorKind,
    message: Box<str>,
}

impl LegacyRulesSetManifestError {
    #[must_use]
    pub const fn kind(&self) -> LegacyRulesSetManifestErrorKind {
        self.kind
    }
}

impl fmt::Display for LegacyRulesSetManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for LegacyRulesSetManifestError {}

fn invalid_value(
    field: &str,
    value: impl AsRef<str>,
    expectation: &str,
) -> LegacyRulesSetManifestError {
    manifest_error(
        LegacyRulesSetManifestErrorKind::InvalidValue,
        format!(
            "legacy rules set manifest field {field} has invalid value '{}'; {expectation}",
            value.as_ref()
        ),
    )
}

fn manifest_error(
    kind: LegacyRulesSetManifestErrorKind,
    message: impl Into<Box<str>>,
) -> LegacyRulesSetManifestError {
    LegacyRulesSetManifestError {
        kind,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use flux_platform::{LegacyRulesPlan, render_legacy_rules_set};

    use super::{LegacyRulesSetManifest, LegacyRulesSetManifestErrorKind};

    #[test]
    fn manifest_round_trips_and_verifies_only_the_bound_generation_and_set() {
        let artifacts = render_legacy_rules_set(&LegacyRulesPlan::maximal_zone_v1()).unwrap();
        let generation = NonZeroU32::new(23).unwrap();
        let manifest = LegacyRulesSetManifest::from_artifact_set(generation, &artifacts).unwrap();
        let bytes = manifest.render_canonical();
        let parsed = LegacyRulesSetManifest::parse(&bytes).unwrap();

        assert_eq!(parsed, manifest);
        parsed.verify(generation, &artifacts).unwrap();
        let error = parsed
            .verify(NonZeroU32::new(24).unwrap(), &artifacts)
            .unwrap_err();
        assert_eq!(
            error.kind(),
            LegacyRulesSetManifestErrorKind::IdentityMismatch
        );
    }

    #[test]
    fn syntactically_valid_digest_tampering_parses_but_fails_identity_verification() {
        let artifacts = render_legacy_rules_set(&LegacyRulesPlan::maximal_zone_v1()).unwrap();
        let generation = NonZeroU32::new(29).unwrap();
        let manifest = LegacyRulesSetManifest::from_artifact_set(generation, &artifacts).unwrap();
        let mut bytes = manifest.render_canonical().into_vec();
        let needle = b"set_digest=";
        let start = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap()
            + needle.len();
        bytes[start] = if bytes[start] == b'0' { b'1' } else { b'0' };

        let parsed = LegacyRulesSetManifest::parse(&bytes).unwrap();
        let error = parsed.verify(generation, &artifacts).unwrap_err();
        assert_eq!(
            error.kind(),
            LegacyRulesSetManifestErrorKind::IdentityMismatch
        );
    }
}
