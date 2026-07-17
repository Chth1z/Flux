use std::error::Error;
use std::fmt;

use flux_core::RuleFwMark;

use super::save::{XtablesExpectedState, XtablesExpectedStatePhase, XtablesSaveProjectionError};
use super::{
    XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION, XtablesCaptureArtifactPair, XtablesCaptureArtifactSet,
    XtablesCaptureEntryPoint, XtablesCaptureEntryPointRole, XtablesCaptureEntrySelector,
    XtablesCaptureHook, XtablesCaptureTransactionStep, XtablesRestoreAction,
    XtablesRestoreArtifact, XtablesRestoreContext, XtablesRestoreFamily, XtablesRestoreParseError,
    parse_xtables_restore,
};

const STABLE_PREROUTING_SUFFIX: &str = "SP";
const STABLE_OUTPUT_SUFFIX: &str = "SO";

/// Canonical stable-root artifacts derived from one complete schema-v2 target.
///
/// This is still a private implementation value. It has no writer lease,
/// runtime admission, live-state evidence, journal, or mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesStableTopologyPlan {
    families: Box<[XtablesStableFamilyPlan]>,
}

impl XtablesStableTopologyPlan {
    pub(crate) fn from_artifacts(
        artifacts: &XtablesCaptureArtifactSet,
    ) -> Result<Self, XtablesStableTopologyError> {
        if artifacts.schema_version() != XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION {
            return Err(XtablesStableTopologyError::UnsupportedSchema {
                actual: artifacts.schema_version(),
            });
        }
        let extensions = artifacts.extensions();
        if extensions.established_flow_cache()
            || extensions.transparent_socket_divert()
            || extensions.fake_ip_icmp()
            || extensions.quic_reject()
            || extensions.mss_clamp()
        {
            return Err(XtablesStableTopologyError::UnsupportedExtensions);
        }

        let mut families = Vec::new();
        let mut has_local_output = false;
        for family in [XtablesRestoreFamily::Ipv4, XtablesRestoreFamily::Ipv6] {
            let Some(pair) = artifacts.pair(family) else {
                continue;
            };
            validate_transaction_order(pair)?;
            let plan = XtablesStableFamilyPlan::from_pair(pair)?;
            has_local_output |= plan.output_root.is_some();
            families.push(plan);
        }
        if families.is_empty() {
            return Err(XtablesStableTopologyError::NoEnabledFamilies);
        }
        if !has_local_output {
            return Err(XtablesStableTopologyError::MissingLocalOutput);
        }
        Ok(Self {
            families: families.into_boxed_slice(),
        })
    }

    #[must_use]
    pub(crate) fn families(&self) -> &[XtablesStableFamilyPlan] {
        &self.families
    }

    #[must_use]
    pub(crate) fn family(&self, family: XtablesRestoreFamily) -> Option<&XtablesStableFamilyPlan> {
        self.families.iter().find(|plan| plan.family == family)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XtablesStableFamilyPlan {
    family: XtablesRestoreFamily,
    prerouting_root: Option<Box<str>>,
    output_root: Option<Box<str>>,
    install: XtablesRestoreArtifact,
    switch: XtablesRestoreArtifact,
    detach_output: Option<XtablesRestoreArtifact>,
    detach_remaining: XtablesRestoreArtifact,
    prepared_state: XtablesExpectedState,
    active_state: XtablesExpectedState,
    output_detached_state: XtablesExpectedState,
}

impl XtablesStableFamilyPlan {
    fn from_pair(pair: &XtablesCaptureArtifactPair) -> Result<Self, XtablesStableTopologyError> {
        let family = pair.family();
        let mut local_output = None;
        let mut local_loopback = None;
        let mut forwarded = None;
        for entry in pair.entries() {
            let slot = match entry.role() {
                XtablesCaptureEntryPointRole::LocalOutputClassifier => &mut local_output,
                XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy => &mut local_loopback,
                XtablesCaptureEntryPointRole::ForwardedIngress => &mut forwarded,
            };
            if slot.replace(entry).is_some() {
                return Err(XtablesStableTopologyError::DuplicateRole {
                    family,
                    role: entry.role(),
                });
            }
        }

        match pair.local_output() {
            Some(requirements) => {
                let output = local_output.ok_or(XtablesStableTopologyError::MissingRole {
                    family,
                    role: XtablesCaptureEntryPointRole::LocalOutputClassifier,
                })?;
                let loopback = local_loopback.ok_or(XtablesStableTopologyError::MissingRole {
                    family,
                    role: XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy,
                })?;
                validate_output_entry(output, requirements.routing().mark())?;
                validate_loopback_entry(loopback, requirements.routing())?;
            }
            None if local_output.is_some() || local_loopback.is_some() => {
                return Err(XtablesStableTopologyError::MissingLocalRequirements { family });
            }
            None => {}
        }
        if let Some(entry) = forwarded {
            validate_forwarded_entry(entry)?;
        }

        let prerouting_root = (local_loopback.is_some() || forwarded.is_some())
            .then(|| stable_root_name(family, XtablesCaptureHook::Prerouting));
        let output_root = local_output
            .is_some()
            .then(|| stable_root_name(family, XtablesCaptureHook::Output));
        let mut prerouting_rules = Vec::new();
        if let (Some(root), Some(entry)) = (&prerouting_root, local_loopback) {
            prerouting_rules.push(render_stable_rule(root, entry)?);
        }
        if let (Some(root), Some(entry)) = (&prerouting_root, forwarded) {
            prerouting_rules.push(render_stable_rule(root, entry)?);
        }
        let mut output_rules = Vec::new();
        if let (Some(root), Some(entry)) = (&output_root, local_output) {
            output_rules.push(render_stable_rule(root, entry)?);
        }

        let install_text = render_install(
            prerouting_root.as_deref(),
            output_root.as_deref(),
            &prerouting_rules,
            &output_rules,
        );
        let switch_text = render_switch(
            prerouting_root.as_deref(),
            output_root.as_deref(),
            &prerouting_rules,
            &output_rules,
        );
        let detach_output_text = output_root.as_deref().map(render_detach_output);
        let detach_remaining_text =
            render_detach_remaining(prerouting_root.as_deref(), output_root.as_deref());

        let install = parse_artifact(
            family,
            XtablesStableTopologyPhase::Install,
            XtablesRestoreAction::Apply,
            &install_text,
        )?;
        let switch = parse_artifact(
            family,
            XtablesStableTopologyPhase::Switch,
            XtablesRestoreAction::Replace,
            &switch_text,
        )?;
        let detach_output = detach_output_text
            .as_deref()
            .map(|text| {
                parse_artifact(
                    family,
                    XtablesStableTopologyPhase::DetachOutput,
                    XtablesRestoreAction::Cleanup,
                    text,
                )
            })
            .transpose()?;
        let detach_remaining = parse_artifact(
            family,
            XtablesStableTopologyPhase::DetachRemaining,
            XtablesRestoreAction::Cleanup,
            &detach_remaining_text,
        )?;
        let prepared_state = expected_state(
            family,
            XtablesExpectedStatePhase::Prepared,
            [pair.prepare()],
        )?;
        let active_state = expected_state(
            family,
            XtablesExpectedStatePhase::Active,
            [pair.prepare(), &install],
        )?;
        let output_detached_state = expected_state(
            family,
            XtablesExpectedStatePhase::OutputDetached,
            [pair.prepare(), &install],
        )?;

        Ok(Self {
            family,
            prerouting_root,
            output_root,
            install,
            switch,
            detach_output,
            detach_remaining,
            prepared_state,
            active_state,
            output_detached_state,
        })
    }

    #[must_use]
    pub(crate) const fn family(&self) -> XtablesRestoreFamily {
        self.family
    }

    #[must_use]
    pub(crate) fn prerouting_root(&self) -> Option<&str> {
        self.prerouting_root.as_deref()
    }

    #[must_use]
    pub(crate) fn output_root(&self) -> Option<&str> {
        self.output_root.as_deref()
    }

    #[must_use]
    pub(crate) const fn install(&self) -> &XtablesRestoreArtifact {
        &self.install
    }

    #[must_use]
    pub(crate) const fn switch(&self) -> &XtablesRestoreArtifact {
        &self.switch
    }

    #[must_use]
    pub(crate) const fn detach_output(&self) -> Option<&XtablesRestoreArtifact> {
        self.detach_output.as_ref()
    }

    #[must_use]
    pub(crate) const fn detach_remaining(&self) -> &XtablesRestoreArtifact {
        &self.detach_remaining
    }

    #[must_use]
    pub(crate) const fn prepared_state(&self) -> &XtablesExpectedState {
        &self.prepared_state
    }

    #[must_use]
    pub(crate) const fn active_state(&self) -> &XtablesExpectedState {
        &self.active_state
    }

    #[must_use]
    pub(crate) const fn output_detached_state(&self) -> &XtablesExpectedState {
        &self.output_detached_state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XtablesStableTopologyPhase {
    Install,
    Switch,
    DetachOutput,
    DetachRemaining,
}

impl fmt::Display for XtablesStableTopologyPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Install => "install stable roots",
            Self::Switch => "switch stable roots",
            Self::DetachOutput => "detach OUTPUT root",
            Self::DetachRemaining => "detach remaining stable roots",
        })
    }
}

#[derive(Debug)]
pub(crate) enum XtablesStableTopologyError {
    UnsupportedSchema {
        actual: u16,
    },
    UnsupportedExtensions,
    NoEnabledFamilies,
    MissingLocalOutput,
    MissingTransactionOrder {
        family: XtablesRestoreFamily,
    },
    TransactionOrderMismatch {
        family: XtablesRestoreFamily,
    },
    DuplicateRole {
        family: XtablesRestoreFamily,
        role: XtablesCaptureEntryPointRole,
    },
    MissingRole {
        family: XtablesRestoreFamily,
        role: XtablesCaptureEntryPointRole,
    },
    MissingLocalRequirements {
        family: XtablesRestoreFamily,
    },
    InvalidEntry {
        family: XtablesRestoreFamily,
        role: XtablesCaptureEntryPointRole,
    },
    NonAsciiInterface {
        family: XtablesRestoreFamily,
        role: XtablesCaptureEntryPointRole,
    },
    InvalidRenderedArtifact {
        family: XtablesRestoreFamily,
        phase: XtablesStableTopologyPhase,
        source: XtablesRestoreParseError,
    },
    InvalidExpectedState {
        family: XtablesRestoreFamily,
        phase: XtablesExpectedStatePhase,
        source: XtablesSaveProjectionError,
    },
}

impl fmt::Display for XtablesStableTopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { actual } => write!(
                formatter,
                "native stable topology requires schema {XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION}, not {actual}"
            ),
            Self::UnsupportedExtensions => {
                formatter.write_str("native stable topology admits no Capture extensions")
            }
            Self::NoEnabledFamilies => {
                formatter.write_str("native stable topology has no enabled address family")
            }
            Self::MissingLocalOutput => {
                formatter.write_str("native stable topology has no local-OUTPUT transaction")
            }
            Self::MissingTransactionOrder { family } => {
                write!(
                    formatter,
                    "{family:?} artifact has no schema-v2 transaction order"
                )
            }
            Self::TransactionOrderMismatch { family } => write!(
                formatter,
                "{family:?} artifact transaction order does not match its typed dependencies"
            ),
            Self::DuplicateRole { family, role } => {
                write!(
                    formatter,
                    "{family:?} artifact repeats stable role {role:?}"
                )
            }
            Self::MissingRole { family, role } => {
                write!(
                    formatter,
                    "{family:?} artifact omits required stable role {role:?}"
                )
            }
            Self::MissingLocalRequirements { family } => write!(
                formatter,
                "{family:?} local stable entries have no listener/routing/escape requirements"
            ),
            Self::InvalidEntry { family, role } => write!(
                formatter,
                "{family:?} stable role {role:?} has an invalid hook or selector"
            ),
            Self::NonAsciiInterface { family, role } => write!(
                formatter,
                "{family:?} stable role {role:?} uses a non-ASCII interface"
            ),
            Self::InvalidRenderedArtifact {
                family,
                phase,
                source,
            } => write!(
                formatter,
                "cannot render {family:?} native topology phase {phase}: {source}"
            ),
            Self::InvalidExpectedState {
                family,
                phase,
                source,
            } => write!(
                formatter,
                "cannot derive {family:?} native topology expected state {phase:?}: {source}"
            ),
        }
    }
}

impl Error for XtablesStableTopologyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRenderedArtifact { source, .. } => Some(source),
            Self::InvalidExpectedState { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn validate_transaction_order(
    pair: &XtablesCaptureArtifactPair,
) -> Result<(), XtablesStableTopologyError> {
    let Some(order) = pair.transaction_order() else {
        return Err(XtablesStableTopologyError::MissingTransactionOrder {
            family: pair.family(),
        });
    };
    let mut prepare = pair
        .entries()
        .iter()
        .map(|entry| XtablesCaptureTransactionStep::PrepareEntryPoint(entry.role()))
        .collect::<Vec<_>>();
    if pair.local_output().is_some() {
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
        if pair.entries().iter().any(|entry| entry.role() == role) {
            prepare.push(XtablesCaptureTransactionStep::AttachEntryPoint(role));
        }
    }

    let mut retire = Vec::new();
    for role in [
        XtablesCaptureEntryPointRole::LocalOutputClassifier,
        XtablesCaptureEntryPointRole::ForwardedIngress,
        XtablesCaptureEntryPointRole::LocalOutputLoopbackTproxy,
    ] {
        if pair.entries().iter().any(|entry| entry.role() == role) {
            retire.push(XtablesCaptureTransactionStep::DetachEntryPoint(role));
        }
    }
    if pair.local_output().is_some() {
        retire.extend([
            XtablesCaptureTransactionStep::RetireLoopEscape,
            XtablesCaptureTransactionStep::RetirePolicyRouting,
            XtablesCaptureTransactionStep::RetireTransparentListener,
        ]);
    }
    retire.extend(
        pair.entries()
            .iter()
            .rev()
            .map(|entry| XtablesCaptureTransactionStep::RetireEntryPoint(entry.role())),
    );

    if order.prepare() == prepare && order.retire() == retire {
        Ok(())
    } else {
        Err(XtablesStableTopologyError::TransactionOrderMismatch {
            family: pair.family(),
        })
    }
}

fn validate_output_entry(
    entry: &XtablesCaptureEntryPoint,
    routing_mark: RuleFwMark,
) -> Result<(), XtablesStableTopologyError> {
    if entry.hook() == XtablesCaptureHook::Output
        && matches!(
            entry.selector(),
            XtablesCaptureEntrySelector::Mark(mark)
                if mark.value() == 0 && mark.mask() == routing_mark.mask()
        )
    {
        Ok(())
    } else {
        Err(invalid_entry(entry))
    }
}

fn validate_loopback_entry(
    entry: &XtablesCaptureEntryPoint,
    routing: super::XtablesLocalOutputRoutingRequirement,
) -> Result<(), XtablesStableTopologyError> {
    if entry.hook() == XtablesCaptureHook::Prerouting
        && matches!(
            entry.selector(),
            XtablesCaptureEntrySelector::InputInterfaceAndMark { interface, mark }
                if interface == routing.loopback_interface() && mark == routing.mark()
        )
    {
        Ok(())
    } else {
        Err(invalid_entry(entry))
    }
}

fn validate_forwarded_entry(
    entry: &XtablesCaptureEntryPoint,
) -> Result<(), XtablesStableTopologyError> {
    if entry.hook() == XtablesCaptureHook::Prerouting
        && entry.selector() == XtablesCaptureEntrySelector::Any
    {
        Ok(())
    } else {
        Err(invalid_entry(entry))
    }
}

fn invalid_entry(entry: &XtablesCaptureEntryPoint) -> XtablesStableTopologyError {
    XtablesStableTopologyError::InvalidEntry {
        family: entry_family(entry),
        role: entry.role(),
    }
}

fn entry_family(entry: &XtablesCaptureEntryPoint) -> XtablesRestoreFamily {
    if entry.chain().starts_with("FLX4") {
        XtablesRestoreFamily::Ipv4
    } else {
        XtablesRestoreFamily::Ipv6
    }
}

fn stable_root_name(family: XtablesRestoreFamily, hook: XtablesCaptureHook) -> Box<str> {
    let family = match family {
        XtablesRestoreFamily::Ipv4 => '4',
        XtablesRestoreFamily::Ipv6 => '6',
    };
    let suffix = match hook {
        XtablesCaptureHook::Prerouting => STABLE_PREROUTING_SUFFIX,
        XtablesCaptureHook::Output => STABLE_OUTPUT_SUFFIX,
    };
    format!("FLX{family}{suffix}").into_boxed_str()
}

fn render_stable_rule(
    stable_root: &str,
    entry: &XtablesCaptureEntryPoint,
) -> Result<String, XtablesStableTopologyError> {
    let mut rule = format!("-A {stable_root}");
    match entry.selector() {
        XtablesCaptureEntrySelector::Any => {}
        XtablesCaptureEntrySelector::Mark(mark) => {
            rule.push_str(" -m mark --mark ");
            rule.push_str(&mark_token(mark));
        }
        XtablesCaptureEntrySelector::InputInterfaceAndMark { interface, mark } => {
            let interface =
                interface
                    .as_str()
                    .ok_or(XtablesStableTopologyError::NonAsciiInterface {
                        family: entry_family(entry),
                        role: entry.role(),
                    })?;
            rule.push_str(" -i ");
            rule.push_str(interface);
            rule.push_str(" -m mark --mark ");
            rule.push_str(&mark_token(mark));
        }
    }
    rule.push_str(" -j ");
    rule.push_str(entry.chain());
    Ok(rule)
}

fn mark_token(mark: RuleFwMark) -> String {
    format!("0x{:x}/0x{:x}", mark.value(), mark.mask())
}

fn render_install(
    prerouting_root: Option<&str>,
    output_root: Option<&str>,
    prerouting_rules: &[String],
    output_rules: &[String],
) -> String {
    let mut output = String::from("*mangle\n");
    for root in [prerouting_root, output_root].into_iter().flatten() {
        output.push(':');
        output.push_str(root);
        output.push_str(" - [0:0]\n");
    }
    append_rules(&mut output, prerouting_rules);
    append_rules(&mut output, output_rules);
    if let Some(root) = prerouting_root {
        output.push_str("-I PREROUTING -j ");
        output.push_str(root);
        output.push('\n');
    }
    if let Some(root) = output_root {
        output.push_str("-I OUTPUT -j ");
        output.push_str(root);
        output.push('\n');
    }
    output.push_str("COMMIT\n");
    output
}

fn render_switch(
    prerouting_root: Option<&str>,
    output_root: Option<&str>,
    prerouting_rules: &[String],
    output_rules: &[String],
) -> String {
    let mut output = String::from("*mangle\n");
    for root in [prerouting_root, output_root].into_iter().flatten() {
        output.push_str("-F ");
        output.push_str(root);
        output.push('\n');
    }
    append_rules(&mut output, prerouting_rules);
    append_rules(&mut output, output_rules);
    output.push_str("COMMIT\n");
    output
}

fn render_detach_output(output_root: &str) -> String {
    format!("*mangle\n-D OUTPUT -j {output_root}\nCOMMIT\n")
}

fn render_detach_remaining(prerouting_root: Option<&str>, output_root: Option<&str>) -> String {
    let mut output = String::from("*mangle\n");
    if let Some(root) = prerouting_root {
        output.push_str("-D PREROUTING -j ");
        output.push_str(root);
        output.push('\n');
    }
    for root in [output_root, prerouting_root].into_iter().flatten() {
        output.push_str("-F ");
        output.push_str(root);
        output.push('\n');
    }
    for root in [output_root, prerouting_root].into_iter().flatten() {
        output.push_str("-X ");
        output.push_str(root);
        output.push('\n');
    }
    output.push_str("COMMIT\n");
    output
}

fn append_rules(output: &mut String, rules: &[String]) {
    for rule in rules {
        output.push_str(rule);
        output.push('\n');
    }
}

fn parse_artifact(
    family: XtablesRestoreFamily,
    phase: XtablesStableTopologyPhase,
    action: XtablesRestoreAction,
    text: &str,
) -> Result<XtablesRestoreArtifact, XtablesStableTopologyError> {
    parse_xtables_restore(text.as_bytes(), XtablesRestoreContext::new(action, family)).map_err(
        |source| XtablesStableTopologyError::InvalidRenderedArtifact {
            family,
            phase,
            source,
        },
    )
}

fn expected_state<'a>(
    family: XtablesRestoreFamily,
    phase: XtablesExpectedStatePhase,
    artifacts: impl IntoIterator<Item = &'a XtablesRestoreArtifact>,
) -> Result<XtablesExpectedState, XtablesStableTopologyError> {
    XtablesExpectedState::from_apply_artifacts(family, phase, artifacts).map_err(|source| {
        XtablesStableTopologyError::InvalidExpectedState {
            family,
            phase,
            source,
        }
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "owner_runtime.rs"]
mod runtime;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unused_imports)]
pub(crate) use runtime::*;

#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;
