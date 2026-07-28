use std::error::Error;
use std::fmt;

use crate::android_netd::AndroidNetdSourceProfile;
use crate::network_inventory::{InterfaceName, NetworkInventory};
use crate::network_route::NetworkAddressFamily;
use crate::network_rule::{
    NetworkRuleRecord, RuleAction, RuleFlags, RuleFwMark, RulePrefix, RulePriority,
};
use crate::rpdb_placement::{
    RpdbClassifierRevision, RpdbPlacementLease, RpdbPlacementPlanError, RpdbPlacementRequest,
    RpdbRuleAudit, RpdbRuleClassification, plan_rpdb_placement,
};

const ROUTE_TABLE_UNSPECIFIED: u32 = 0;
const ROUTE_TABLE_LOCAL_NETWORK: u32 = 97;
const ROUTE_TABLE_LEGACY_NETWORK: u32 = 98;
const ROUTE_TABLE_LEGACY_SYSTEM: u32 = 99;
const ROUTE_TABLE_LOCAL: u32 = 255;
const DYNAMIC_NETWORK_TABLE_MINIMUM: u32 = 1_001;
const DYNAMIC_LOCAL_TABLE_MINIMUM: u32 = 1_000_000_001;

const ANDROID_LOCAL_NET_ID: u32 = 99;
const ANDROID_NET_ID_MASK: u32 = 0x0000_ffff;
const ANDROID_EXPLICITLY_SELECTED: u32 = 0x0001_0000;
const ANDROID_PROTECTED_FROM_VPN: u32 = 0x0002_0000;
const ANDROID_PERMISSION_NETWORK: u32 = 0x0004_0000;
const ANDROID_PERMISSION_SYSTEM: u32 = 0x000c_0000;
const ANDROID_PERMISSION_VALUES: [u32; 3] =
    [0, ANDROID_PERMISSION_NETWORK, ANDROID_PERMISSION_SYSTEM];

const RTPROT_UNSPECIFIED: u8 = 0;
const RTPROT_KERNEL: u8 = 2;

const REQUIRED_INITIALIZATION_ROLES: [AndroidRpdbRuleRole; 7] = [
    AndroidRpdbRuleRole::KernelLocal,
    AndroidRpdbRuleRole::VpnOverrideSystem,
    AndroidRpdbRuleRole::LocalNetworkExplicit,
    AndroidRpdbRuleRole::LegacySystem,
    AndroidRpdbRuleRole::LegacyNetwork,
    AndroidRpdbRuleRole::LocalNetwork,
    AndroidRpdbRuleRole::FinalUnreachable,
];

/// Maximum ordered unknown-rule diagnostics retained by one classifier report.
pub const MAX_ANDROID_RPDB_UNKNOWN_RULES: usize = 64;

impl AndroidNetdSourceProfile {
    /// Returns the classifier implementation revision for this exact source profile.
    ///
    /// These values must change whenever matching or classification semantics change, even when
    /// the modeled AOSP source revision remains the same.
    #[must_use]
    pub fn classifier_revision(self) -> RpdbClassifierRevision {
        let value = match self {
            Self::AospAndroid12R1 => 0x000c_0001,
            Self::AospAndroid13R1 => 0x000d_0001,
            Self::AospNetd20250324 => 0x2025_0324_0001,
        };
        RpdbClassifierRevision::new(value).expect("Android RPDB revisions are nonzero")
    }

    /// Returns the profile's static priority contract, including currently absent dynamic rules.
    #[must_use]
    pub const fn priority_contract(self) -> AndroidRpdbPriorityContract {
        match self {
            Self::AospAndroid12R1 => AndroidRpdbPriorityContract {
                uid_default_unreachable_maximum: RulePriority::from_raw(28_999),
                default_network: RulePriority::from_raw(29_000),
            },
            Self::AospAndroid13R1 | Self::AospNetd20250324 => AndroidRpdbPriorityContract {
                uid_default_unreachable_maximum: RulePriority::from_raw(30_998),
                default_network: RulePriority::from_raw(31_000),
            },
        }
    }

    const fn permits_dynamic_physical_local_rules(self) -> bool {
        matches!(self, Self::AospNetd20250324)
    }
}

/// Static profile bounds that cannot be derived from only the rules present in one dump.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AndroidRpdbPriorityContract {
    uid_default_unreachable_maximum: RulePriority,
    default_network: RulePriority,
}

impl AndroidRpdbPriorityContract {
    #[must_use]
    pub const fn uid_default_unreachable_maximum(self) -> RulePriority {
        self.uid_default_unreachable_maximum
    }

    #[must_use]
    pub const fn default_network(self) -> RulePriority {
        self.default_network
    }

    /// Returns the number of integer priorities in the reserved gap between the two bounds.
    #[must_use]
    pub const fn intervening_priority_count(self) -> u32 {
        self.default_network.get() - self.uid_default_unreachable_maximum.get() - 1
    }

    /// Whether the static contract can hold distinct address-bypass and proxy priorities.
    #[must_use]
    pub const fn admits_two_rule_window(self) -> bool {
        self.intervening_priority_count() >= 2
    }
}

/// Strict semantic role extracted from one exact AOSP policy-rule shape.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidRpdbRuleRole {
    KernelLocal,
    VpnOverrideSystem,
    VpnOverrideOutputInterface,
    VpnOutputToLocal,
    SecureVpn,
    ProhibitNonVpn,
    UidExplicitNetwork,
    UidExplicitUnreachable,
    LocalNetworkExplicit,
    ExplicitNetwork,
    OutputInterface,
    LegacySystem,
    LegacyNetwork,
    LocalNetwork,
    PhysicalLocalNetwork,
    Tethering,
    UidImplicitNetwork,
    UidImplicitUnreachable,
    ImplicitNetwork,
    BypassableVpnNoLocalExclusion,
    UidLocalRoutes,
    LocalRoutes,
    BypassableVpnLocalExclusion,
    VpnFallthrough,
    UidDefaultNetwork,
    UidDefaultUnreachable,
    DefaultNetwork,
    FinalUnreachable,
}

impl AndroidRpdbRuleRole {
    /// Projects strict role evidence into the current ordering-only placement vocabulary.
    ///
    /// V1 never emits `DoesNotConstrainFlux`. The default-network and final-unreachable roles are
    /// upper bounds; every earlier recognized role is conservatively required to precede Flux.
    #[must_use]
    pub const fn classification(self) -> RpdbRuleClassification {
        match self {
            Self::DefaultNetwork | Self::FinalUnreachable => {
                RpdbRuleClassification::TerminalBarrier
            }
            Self::KernelLocal
            | Self::VpnOverrideSystem
            | Self::VpnOverrideOutputInterface
            | Self::VpnOutputToLocal
            | Self::SecureVpn
            | Self::ProhibitNonVpn
            | Self::UidExplicitNetwork
            | Self::UidExplicitUnreachable
            | Self::LocalNetworkExplicit
            | Self::ExplicitNetwork
            | Self::OutputInterface
            | Self::LegacySystem
            | Self::LegacyNetwork
            | Self::LocalNetwork
            | Self::PhysicalLocalNetwork
            | Self::Tethering
            | Self::UidImplicitNetwork
            | Self::UidImplicitUnreachable
            | Self::ImplicitNetwork
            | Self::BypassableVpnNoLocalExclusion
            | Self::UidLocalRoutes
            | Self::LocalRoutes
            | Self::BypassableVpnLocalExclusion
            | Self::VpnFallthrough
            | Self::UidDefaultNetwork
            | Self::UidDefaultUnreachable => RpdbRuleClassification::MustPrecedeFlux,
        }
    }
}

/// Version-specific priority band expected to contain one or more exact role shapes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidRpdbPriorityBand {
    KernelLocal,
    VpnOverrideSystem,
    VpnOverrideOutputInterface,
    VpnOutputToLocal,
    SecureVpn,
    ProhibitNonVpn,
    UidExplicitNetwork,
    ExplicitNetwork,
    OutputInterface,
    LegacySystem,
    LegacyNetwork,
    LocalNetwork,
    Tethering,
    UidImplicitNetwork,
    ImplicitNetwork,
    BypassableVpnNoLocalExclusion,
    UidLocalRoutes,
    LocalRoutes,
    BypassableVpnLocalExclusion,
    VpnFallthrough,
    UidDefaultNetwork,
    UidDefaultUnreachable,
    DefaultNetwork,
    FinalUnreachable,
}

/// Why one ordered rule could not contribute trusted Android ordering evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidRpdbUnknownReason {
    OpaqueAttributes,
    UnrecognizedPriority,
    SignatureMismatch {
        expected_band: AndroidRpdbPriorityBand,
    },
    InvalidFamilyProfile,
}

/// Bounded diagnostic for one `Unknown` classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AndroidRpdbUnknownRule {
    dump_index: usize,
    family: NetworkAddressFamily,
    priority: RulePriority,
    reason: AndroidRpdbUnknownReason,
}

impl AndroidRpdbUnknownRule {
    #[must_use]
    pub const fn dump_index(self) -> usize {
        self.dump_index
    }

    #[must_use]
    pub const fn family(self) -> NetworkAddressFamily {
        self.family
    }

    #[must_use]
    pub const fn priority(self) -> RulePriority {
        self.priority
    }

    #[must_use]
    pub const fn reason(self) -> AndroidRpdbUnknownReason {
        self.reason
    }
}

/// Evidence that one observed family is not a complete, ordered instance of the selected profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidRpdbProfileIssue {
    MissingRequiredRole {
        family: NetworkAddressFamily,
        role: AndroidRpdbRuleRole,
    },
    NonMonotonicPriority {
        family: NetworkAddressFamily,
        previous_dump_index: usize,
        previous_priority: RulePriority,
        dump_index: usize,
        priority: RulePriority,
    },
}

impl AndroidRpdbProfileIssue {
    #[must_use]
    pub const fn family(self) -> NetworkAddressFamily {
        match self {
            Self::MissingRequiredRole { family, .. }
            | Self::NonMonotonicPriority { family, .. } => family,
        }
    }
}

/// Ordered role and classification evidence for one exact network inventory snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidRpdbClassificationReport {
    profile: AndroidNetdSourceProfile,
    audit: RpdbRuleAudit,
    roles: Box<[Option<AndroidRpdbRuleRole>]>,
    unknown_rule_count: u32,
    unknown_rules: Box<[AndroidRpdbUnknownRule]>,
    omitted_unknown_rules: u32,
    profile_issues: Box<[AndroidRpdbProfileIssue]>,
}

impl AndroidRpdbClassificationReport {
    #[must_use]
    pub const fn profile(&self) -> AndroidNetdSourceProfile {
        self.profile
    }

    /// Returns the aligned generic audit.
    ///
    /// Classifier-owned static priority bands are embedded in this audit, so the generic planner
    /// cannot mistake an unoccupied reserved Android subpriority for a lease. The Android wrapper
    /// adds profile-specific error reporting but does not weaken the generic result.
    #[must_use]
    pub const fn audit(&self) -> &RpdbRuleAudit {
        &self.audit
    }

    /// Returns strict shape evidence aligned with the ordered inventory.
    ///
    /// A role remains visible when a missing anchor or ordering violation downgrades the complete
    /// family audit to `Unknown`. Roles are diagnostics, not placement or activation authority.
    #[must_use]
    pub fn roles(&self) -> &[Option<AndroidRpdbRuleRole>] {
        &self.roles
    }

    #[must_use]
    pub const fn unknown_rule_count(&self) -> u32 {
        self.unknown_rule_count
    }

    #[must_use]
    pub fn unknown_rules(&self) -> &[AndroidRpdbUnknownRule] {
        &self.unknown_rules
    }

    #[must_use]
    pub const fn omitted_unknown_rules(&self) -> u32 {
        self.omitted_unknown_rules
    }

    #[must_use]
    pub fn profile_issues(&self) -> &[AndroidRpdbProfileIssue] {
        &self.profile_issues
    }
}

/// Android-specific placement rejection, including static profile ranges absent from a dump.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidRpdbPlacementPlanError {
    Rpdb(RpdbPlacementPlanError),
    StaticPriorityWindowViolation {
        family: NetworkAddressFamily,
        last_reserved_must_precede: RulePriority,
        bypass: RulePriority,
        proxy: RulePriority,
        first_default_network: RulePriority,
    },
}

impl fmt::Display for AndroidRpdbPlacementPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpdb(error) => error.fmt(formatter),
            Self::StaticPriorityWindowViolation {
                family,
                last_reserved_must_precede,
                bypass,
                proxy,
                first_default_network,
            } => write!(
                formatter,
                "Android RPDB placement for {family:?} does not satisfy reserved profile window {} < {} < {} < {}",
                last_reserved_must_precede.get(),
                bypass.get(),
                proxy.get(),
                first_default_network.get()
            ),
        }
    }
}

impl Error for AndroidRpdbPlacementPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rpdb(error) => Some(error),
            Self::StaticPriorityWindowViolation { .. } => None,
        }
    }
}

/// Classifies every ordered rule under one explicitly selected AOSP source profile.
#[must_use]
pub fn classify_android_rpdb(
    inventory: &NetworkInventory,
    profile: AndroidNetdSourceProfile,
) -> AndroidRpdbClassificationReport {
    let mut roles = Vec::with_capacity(inventory.rules().len());
    let mut classifications = Vec::with_capacity(inventory.rules().len());
    let mut unknown_reasons = Vec::with_capacity(inventory.rules().len());

    for rule in inventory.rules() {
        let decision = classify_rule(rule, profile);
        roles.push(decision.role);
        classifications.push(decision.classification);
        unknown_reasons.push(decision.unknown_reason);
    }

    let profile_issues = find_profile_issues(inventory, &roles);
    for (dump_index, rule) in inventory.rules().iter().enumerate() {
        let family = rule.destination().family();
        if profile_issues.iter().any(|issue| issue.family() == family)
            && classifications[dump_index] != RpdbRuleClassification::Unknown
        {
            classifications[dump_index] = RpdbRuleClassification::Unknown;
            unknown_reasons[dump_index] = Some(AndroidRpdbUnknownReason::InvalidFamilyProfile);
        }
    }

    let mut audit = RpdbRuleAudit::new(
        profile.classifier_revision(),
        inventory,
        classifications.iter().copied(),
    )
    .expect("Android classifier emits exactly one classification per observed rule");
    let contract = profile.priority_contract();
    for family in [NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6] {
        if inventory
            .rules()
            .iter()
            .any(|rule| rule.destination().family() == family)
        {
            audit = audit.with_static_priority_window(
                family,
                contract.uid_default_unreachable_maximum(),
                contract.default_network(),
            );
        }
    }

    let mut unknown_rule_count = 0_u32;
    let mut omitted_unknown_rules = 0_u32;
    let mut unknown_rules =
        Vec::with_capacity(inventory.rules().len().min(MAX_ANDROID_RPDB_UNKNOWN_RULES));
    for (dump_index, rule) in inventory.rules().iter().enumerate() {
        if classifications[dump_index] != RpdbRuleClassification::Unknown {
            continue;
        }
        unknown_rule_count = unknown_rule_count.saturating_add(1);
        if unknown_rules.len() < MAX_ANDROID_RPDB_UNKNOWN_RULES {
            unknown_rules.push(AndroidRpdbUnknownRule {
                dump_index,
                family: rule.destination().family(),
                priority: rule.priority(),
                reason: unknown_reasons[dump_index]
                    .expect("every unknown classification retains a diagnostic reason"),
            });
        } else {
            omitted_unknown_rules = omitted_unknown_rules.saturating_add(1);
        }
    }

    AndroidRpdbClassificationReport {
        profile,
        audit,
        roles: roles.into_boxed_slice(),
        unknown_rule_count,
        unknown_rules: unknown_rules.into_boxed_slice(),
        omitted_unknown_rules,
        profile_issues: profile_issues.into_boxed_slice(),
    }
}

/// Applies both observed-rule evidence and the selected profile's reserved priority bands.
///
/// The current two-rule Flux topology has no stable AOSP window under any supported profile, so a
/// fully classified snapshot can still be rejected here. This function remains pure and does not
/// allocate priorities or authorize kernel mutation.
pub fn plan_android_rpdb_placement(
    inventory: &NetworkInventory,
    report: &AndroidRpdbClassificationReport,
    request: RpdbPlacementRequest,
) -> Result<RpdbPlacementLease, AndroidRpdbPlacementPlanError> {
    let contract = report.profile().priority_contract();
    let lease = match plan_rpdb_placement(inventory, report.audit(), request) {
        Ok(lease) => lease,
        Err(RpdbPlacementPlanError::PriorityWindowViolation {
            family,
            last_must_precede,
            bypass,
            proxy,
            first_terminal_barrier,
        }) if last_must_precede == contract.uid_default_unreachable_maximum()
            && first_terminal_barrier == contract.default_network() =>
        {
            return Err(
                AndroidRpdbPlacementPlanError::StaticPriorityWindowViolation {
                    family,
                    last_reserved_must_precede: last_must_precede,
                    bypass,
                    proxy,
                    first_default_network: first_terminal_barrier,
                },
            );
        }
        Err(error) => return Err(AndroidRpdbPlacementPlanError::Rpdb(error)),
    };

    for family in [NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6] {
        let Some(placement) = request.family(family) else {
            continue;
        };
        let priorities_fit = match placement.dedicated_bypass_priority() {
            Some(bypass) => {
                contract.uid_default_unreachable_maximum() < bypass
                    && bypass < placement.proxy_priority()
                    && placement.proxy_priority() < contract.default_network()
            }
            None => {
                contract.uid_default_unreachable_maximum() < placement.proxy_priority()
                    && placement.proxy_priority() < contract.default_network()
            }
        };
        if !priorities_fit {
            return Err(
                AndroidRpdbPlacementPlanError::StaticPriorityWindowViolation {
                    family,
                    last_reserved_must_precede: contract.uid_default_unreachable_maximum(),
                    bypass: placement.bypass_priority(),
                    proxy: placement.proxy_priority(),
                    first_default_network: contract.default_network(),
                },
            );
        }
    }

    Ok(lease)
}

#[derive(Clone, Copy)]
struct RuleDecision {
    role: Option<AndroidRpdbRuleRole>,
    classification: RpdbRuleClassification,
    unknown_reason: Option<AndroidRpdbUnknownReason>,
}

impl RuleDecision {
    const fn recognized(role: AndroidRpdbRuleRole) -> Self {
        Self {
            role: Some(role),
            classification: role.classification(),
            unknown_reason: None,
        }
    }

    const fn unknown(reason: AndroidRpdbUnknownReason) -> Self {
        Self {
            role: None,
            classification: RpdbRuleClassification::Unknown,
            unknown_reason: Some(reason),
        }
    }
}

fn classify_rule(rule: &NetworkRuleRecord, profile: AndroidNetdSourceProfile) -> RuleDecision {
    if !rule.has_complete_attribute_coverage() {
        return RuleDecision::unknown(AndroidRpdbUnknownReason::OpaqueAttributes);
    }

    let Some(band) = priority_band(profile, rule.priority().get()) else {
        return RuleDecision::unknown(AndroidRpdbUnknownReason::UnrecognizedPriority);
    };
    let role = match band {
        AndroidRpdbPriorityBand::KernelLocal => match_kernel_local(rule),
        band if !matches_common_netd_shape(rule) => None,
        AndroidRpdbPriorityBand::VpnOverrideSystem => match_vpn_override_system(rule),
        AndroidRpdbPriorityBand::VpnOverrideOutputInterface => {
            match_vpn_override_output_interface(rule)
        }
        AndroidRpdbPriorityBand::VpnOutputToLocal => match_vpn_output_to_local(rule),
        AndroidRpdbPriorityBand::SecureVpn => match_secure_vpn(rule),
        AndroidRpdbPriorityBand::ProhibitNonVpn => match_prohibit_non_vpn(rule),
        AndroidRpdbPriorityBand::UidExplicitNetwork => match_uid_explicit(rule),
        AndroidRpdbPriorityBand::ExplicitNetwork => match_explicit(rule),
        AndroidRpdbPriorityBand::OutputInterface => match_output_interface(rule),
        AndroidRpdbPriorityBand::LegacySystem => match_legacy_system(rule),
        AndroidRpdbPriorityBand::LegacyNetwork => match_legacy_network(rule),
        AndroidRpdbPriorityBand::LocalNetwork => match_local_network(rule, profile),
        AndroidRpdbPriorityBand::Tethering => match_tethering(rule),
        AndroidRpdbPriorityBand::UidImplicitNetwork => match_uid_implicit(rule),
        AndroidRpdbPriorityBand::ImplicitNetwork => match_implicit(rule),
        AndroidRpdbPriorityBand::BypassableVpnNoLocalExclusion => {
            match_bypassable_vpn(rule, AndroidRpdbRuleRole::BypassableVpnNoLocalExclusion)
        }
        AndroidRpdbPriorityBand::UidLocalRoutes => match_uid_local_routes(rule),
        AndroidRpdbPriorityBand::LocalRoutes => match_local_routes(rule),
        AndroidRpdbPriorityBand::BypassableVpnLocalExclusion => {
            match_bypassable_vpn(rule, AndroidRpdbRuleRole::BypassableVpnLocalExclusion)
        }
        AndroidRpdbPriorityBand::VpnFallthrough => match_vpn_fallthrough(rule),
        AndroidRpdbPriorityBand::UidDefaultNetwork => match_uid_default_network(rule),
        AndroidRpdbPriorityBand::UidDefaultUnreachable => match_uid_default_unreachable(rule),
        AndroidRpdbPriorityBand::DefaultNetwork => match_default_network(rule),
        AndroidRpdbPriorityBand::FinalUnreachable => match_final_unreachable(rule),
    };

    role.map_or_else(
        || {
            RuleDecision::unknown(AndroidRpdbUnknownReason::SignatureMismatch {
                expected_band: band,
            })
        },
        RuleDecision::recognized,
    )
}

fn priority_band(
    profile: AndroidNetdSourceProfile,
    priority: u32,
) -> Option<AndroidRpdbPriorityBand> {
    let common = match priority {
        0 => Some(AndroidRpdbPriorityBand::KernelLocal),
        10_000 => Some(AndroidRpdbPriorityBand::VpnOverrideSystem),
        11_000 => Some(AndroidRpdbPriorityBand::VpnOverrideOutputInterface),
        12_000 => Some(AndroidRpdbPriorityBand::VpnOutputToLocal),
        13_000..=13_999 => Some(AndroidRpdbPriorityBand::SecureVpn),
        14_000 => Some(AndroidRpdbPriorityBand::ProhibitNonVpn),
        15_000..=15_999 => Some(AndroidRpdbPriorityBand::UidExplicitNetwork),
        16_000..=16_999 => Some(AndroidRpdbPriorityBand::ExplicitNetwork),
        17_000..=17_999 => Some(AndroidRpdbPriorityBand::OutputInterface),
        18_000 => Some(AndroidRpdbPriorityBand::LegacySystem),
        19_000 => Some(AndroidRpdbPriorityBand::LegacyNetwork),
        20_000 => Some(AndroidRpdbPriorityBand::LocalNetwork),
        21_000 => Some(AndroidRpdbPriorityBand::Tethering),
        22_000..=22_999 => Some(AndroidRpdbPriorityBand::UidImplicitNetwork),
        23_000 => Some(AndroidRpdbPriorityBand::ImplicitNetwork),
        24_000..=24_999 => Some(AndroidRpdbPriorityBand::BypassableVpnNoLocalExclusion),
        32_000 => Some(AndroidRpdbPriorityBand::FinalUnreachable),
        _ => None,
    };
    if common.is_some() {
        return common;
    }

    match profile {
        AndroidNetdSourceProfile::AospAndroid12R1 => match priority {
            26_000 => Some(AndroidRpdbPriorityBand::VpnFallthrough),
            27_000..=27_999 => Some(AndroidRpdbPriorityBand::UidDefaultNetwork),
            28_000..=28_999 => Some(AndroidRpdbPriorityBand::UidDefaultUnreachable),
            29_000 => Some(AndroidRpdbPriorityBand::DefaultNetwork),
            _ => None,
        },
        AndroidNetdSourceProfile::AospAndroid13R1 | AndroidNetdSourceProfile::AospNetd20250324 => {
            match priority {
                25_000 => Some(AndroidRpdbPriorityBand::UidLocalRoutes),
                26_000 => Some(AndroidRpdbPriorityBand::LocalRoutes),
                27_000..=27_999 => Some(AndroidRpdbPriorityBand::BypassableVpnLocalExclusion),
                28_000 => Some(AndroidRpdbPriorityBand::VpnFallthrough),
                29_000..=29_998 => Some(AndroidRpdbPriorityBand::UidDefaultNetwork),
                30_000..=30_998 => Some(AndroidRpdbPriorityBand::UidDefaultUnreachable),
                31_000 => Some(AndroidRpdbPriorityBand::DefaultNetwork),
                _ => None,
            }
        }
    }
}

fn matches_common_netd_shape(rule: &NetworkRuleRecord) -> bool {
    let family = rule.destination().family();
    rule.destination() == RulePrefix::unspecified(family)
        && rule.source() == RulePrefix::unspecified(family)
        && rule.properties().tos() == 0
        && rule.properties().protocol().raw() == RTPROT_UNSPECIFIED
        && rule.properties().flags() == RuleFlags::default()
        && rule.goto_target().is_none()
        && rule.tunnel_id().is_none()
        && rule.suppress_interface_group().is_none()
        && rule.suppress_prefix_length().is_none()
        && !rule.l3mdev()
        && rule.ip_protocol().is_none()
        && rule.source_port_range().is_none()
        && rule.destination_port_range().is_none()
        && rule.flow().is_none()
}

fn match_kernel_local(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    let family = rule.destination().family();
    (rule.destination() == RulePrefix::unspecified(family)
        && rule.source() == RulePrefix::unspecified(family)
        && rule.properties().tos() == 0
        && rule.properties().table().get() == ROUTE_TABLE_LOCAL
        && rule.properties().action() == RuleAction::TO_TABLE
        && rule.properties().protocol().raw() == RTPROT_KERNEL
        && rule.properties().flags() == RuleFlags::default()
        && no_optional_selectors(rule))
    .then_some(AndroidRpdbRuleRole::KernelLocal)
}

fn match_vpn_override_system(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (table_action(rule, ROUTE_TABLE_LEGACY_SYSTEM)
        && mark_is(
            rule,
            ANDROID_PERMISSION_SYSTEM,
            ANDROID_EXPLICITLY_SELECTED | ANDROID_PERMISSION_SYSTEM,
        )
        && no_interfaces_or_uid(rule))
    .then_some(AndroidRpdbRuleRole::VpnOverrideSystem)
}

fn match_vpn_override_output_interface(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (network_or_local_table_action(rule)
        && rule.fwmark().is_none()
        && input_is_loopback(rule)
        && output_is_non_loopback(rule)
        && rule
            .uid_range()
            .is_some_and(|range| range.start() == 0 && range.end() == 0))
    .then_some(AndroidRpdbRuleRole::VpnOverrideOutputInterface)
}

fn match_vpn_output_to_local(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (table_action(rule, ROUTE_TABLE_LOCAL_NETWORK)
        && rule.fwmark().is_none()
        && input_is_non_loopback(rule)
        && rule.output_interface().is_none()
        && rule.uid_range().is_none())
    .then_some(AndroidRpdbRuleRole::VpnOutputToLocal)
}

fn match_secure_vpn(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    let uid_rule = dynamic_network_table_action(rule)
        && mark_is(rule, 0, ANDROID_PROTECTED_FROM_VPN)
        && input_is_loopback(rule)
        && rule.output_interface().is_none()
        && rule.uid_range().is_some();
    let system_rule = rule.priority().get() == 13_000
        && dynamic_network_table_action(rule)
        && mark_has_nonzero_netid_and_fixed_permission(rule, ANDROID_PERMISSION_SYSTEM)
        && no_interfaces_or_uid(rule);
    (uid_rule || system_rule).then_some(AndroidRpdbRuleRole::SecureVpn)
}

fn match_prohibit_non_vpn(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (rule.properties().action() == RuleAction::PROHIBIT
        && rule.properties().table().get() == ROUTE_TABLE_UNSPECIFIED
        && mark_is(rule, 0, ANDROID_PROTECTED_FROM_VPN)
        && input_is_loopback(rule)
        && rule.output_interface().is_none()
        && rule.uid_range().is_some())
    .then_some(AndroidRpdbRuleRole::ProhibitNonVpn)
}

fn match_uid_explicit(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    if !mark_has_nonzero_netid(
        rule,
        ANDROID_EXPLICITLY_SELECTED,
        ANDROID_EXPLICITLY_SELECTED,
    ) || !input_is_loopback(rule)
        || rule.output_interface().is_some()
        || rule.uid_range().is_none()
    {
        return None;
    }
    if dynamic_network_table_action(rule) {
        Some(AndroidRpdbRuleRole::UidExplicitNetwork)
    } else if unreachable_without_table(rule) {
        Some(AndroidRpdbRuleRole::UidExplicitUnreachable)
    } else {
        None
    }
}

fn match_explicit(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    if !input_is_loopback(rule) || rule.output_interface().is_some() {
        return None;
    }
    if rule.priority().get() > 16_000 && rule.uid_range().is_none() {
        return None;
    }
    if rule.priority().get() == 16_000
        && table_action(rule, ROUTE_TABLE_LOCAL_NETWORK)
        && mark_is(
            rule,
            ANDROID_LOCAL_NET_ID | ANDROID_EXPLICITLY_SELECTED,
            ANDROID_NET_ID_MASK | ANDROID_EXPLICITLY_SELECTED,
        )
        && rule.uid_range().is_none()
    {
        return Some(AndroidRpdbRuleRole::LocalNetworkExplicit);
    }
    (dynamic_network_table_action(rule)
        && mark_has_nonzero_netid_with_permission(
            rule,
            ANDROID_EXPLICITLY_SELECTED,
            ANDROID_EXPLICITLY_SELECTED,
        ))
    .then_some(AndroidRpdbRuleRole::ExplicitNetwork)
}

fn match_output_interface(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    let table = rule.properties().table().get();
    let table_matches = is_dynamic_network_table(table) || table == ROUTE_TABLE_LOCAL_NETWORK;
    (rule.properties().action() == RuleAction::TO_TABLE
        && table_matches
        && mark_is_permission_only(rule)
        && input_is_loopback(rule)
        && output_is_non_loopback(rule)
        && (rule.priority().get() == 17_000 || rule.uid_range().is_some()))
    .then_some(AndroidRpdbRuleRole::OutputInterface)
}

fn match_legacy_system(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (table_action(rule, ROUTE_TABLE_LEGACY_SYSTEM)
        && mark_is(rule, 0, ANDROID_EXPLICITLY_SELECTED)
        && no_interfaces_or_uid(rule))
    .then_some(AndroidRpdbRuleRole::LegacySystem)
}

fn match_legacy_network(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (table_action(rule, ROUTE_TABLE_LEGACY_NETWORK)
        && mark_is(rule, 0, ANDROID_EXPLICITLY_SELECTED)
        && no_interfaces_or_uid(rule))
    .then_some(AndroidRpdbRuleRole::LegacyNetwork)
}

fn match_local_network(
    rule: &NetworkRuleRecord,
    profile: AndroidNetdSourceProfile,
) -> Option<AndroidRpdbRuleRole> {
    if !mark_is(rule, 0, ANDROID_EXPLICITLY_SELECTED) || !no_interfaces_or_uid(rule) {
        return None;
    }
    if table_action(rule, ROUTE_TABLE_LOCAL_NETWORK) {
        Some(AndroidRpdbRuleRole::LocalNetwork)
    } else if profile.permits_dynamic_physical_local_rules() && dynamic_network_table_action(rule) {
        Some(AndroidRpdbRuleRole::PhysicalLocalNetwork)
    } else {
        None
    }
}

fn match_tethering(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (dynamic_network_table_action(rule)
        && rule.fwmark().is_none()
        && input_is_non_loopback(rule)
        && rule.output_interface().is_none()
        && rule.uid_range().is_none())
    .then_some(AndroidRpdbRuleRole::Tethering)
}

fn match_uid_implicit(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    if !mark_has_nonzero_netid(rule, 0, ANDROID_EXPLICITLY_SELECTED)
        || !input_is_loopback(rule)
        || rule.output_interface().is_some()
        || rule.uid_range().is_none()
    {
        return None;
    }
    if dynamic_network_table_action(rule) {
        Some(AndroidRpdbRuleRole::UidImplicitNetwork)
    } else if unreachable_without_table(rule) {
        Some(AndroidRpdbRuleRole::UidImplicitUnreachable)
    } else {
        None
    }
}

fn match_implicit(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (dynamic_network_table_action(rule)
        && mark_has_nonzero_netid(rule, 0, ANDROID_EXPLICITLY_SELECTED)
        && input_is_loopback(rule)
        && rule.output_interface().is_none()
        && rule.uid_range().is_none())
    .then_some(AndroidRpdbRuleRole::ImplicitNetwork)
}

fn match_bypassable_vpn(
    rule: &NetworkRuleRecord,
    role: AndroidRpdbRuleRole,
) -> Option<AndroidRpdbRuleRole> {
    let uid_rule = dynamic_network_table_action(rule)
        && mark_is(
            rule,
            0,
            ANDROID_EXPLICITLY_SELECTED | ANDROID_PROTECTED_FROM_VPN,
        )
        && input_is_loopback(rule)
        && rule.output_interface().is_none()
        && rule.uid_range().is_some();
    let base_priority = match role {
        AndroidRpdbRuleRole::BypassableVpnNoLocalExclusion => 24_000,
        AndroidRpdbRuleRole::BypassableVpnLocalExclusion => 27_000,
        _ => return None,
    };
    let system_rule = rule.priority().get() == base_priority
        && dynamic_network_table_action(rule)
        && mark_has_nonzero_netid_and_fixed_permission(rule, ANDROID_PERMISSION_SYSTEM)
        && no_interfaces_or_uid(rule);
    (uid_rule || system_rule).then_some(role)
}

fn match_uid_local_routes(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (dynamic_local_table_action(rule)
        && mark_is(rule, 0, ANDROID_EXPLICITLY_SELECTED)
        && input_is_loopback(rule)
        && rule.output_interface().is_none()
        && rule.uid_range().is_some())
    .then_some(AndroidRpdbRuleRole::UidLocalRoutes)
}

fn match_local_routes(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (dynamic_local_table_action(rule)
        && mark_is(rule, 0, ANDROID_EXPLICITLY_SELECTED)
        && input_is_loopback(rule)
        && rule.output_interface().is_none()
        && rule.uid_range().is_none())
    .then_some(AndroidRpdbRuleRole::LocalRoutes)
}

fn match_vpn_fallthrough(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (dynamic_network_table_action(rule)
        && mark_has_nonzero_netid_with_permission(rule, 0, 0)
        && no_interfaces_or_uid(rule))
    .then_some(AndroidRpdbRuleRole::VpnFallthrough)
}

fn match_uid_default_network(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (dynamic_network_table_action(rule)
        && mark_is(rule, 0, ANDROID_NET_ID_MASK)
        && input_is_loopback(rule)
        && rule.output_interface().is_none()
        && rule.uid_range().is_some())
    .then_some(AndroidRpdbRuleRole::UidDefaultNetwork)
}

fn match_uid_default_unreachable(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (unreachable_without_table(rule)
        && mark_is(rule, 0, ANDROID_NET_ID_MASK)
        && input_is_loopback(rule)
        && rule.output_interface().is_none()
        && rule.uid_range().is_some())
    .then_some(AndroidRpdbRuleRole::UidDefaultUnreachable)
}

fn match_default_network(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (dynamic_network_table_action(rule)
        && mark_is_default_network(rule)
        && input_is_loopback(rule)
        && rule.output_interface().is_none()
        && rule.uid_range().is_none())
    .then_some(AndroidRpdbRuleRole::DefaultNetwork)
}

fn match_final_unreachable(rule: &NetworkRuleRecord) -> Option<AndroidRpdbRuleRole> {
    (unreachable_without_table(rule) && rule.fwmark().is_none() && no_interfaces_or_uid(rule))
        .then_some(AndroidRpdbRuleRole::FinalUnreachable)
}

fn find_profile_issues(
    inventory: &NetworkInventory,
    roles: &[Option<AndroidRpdbRuleRole>],
) -> Vec<AndroidRpdbProfileIssue> {
    let mut issues = Vec::new();
    for family in [NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6] {
        let mut observed = false;
        let mut previous = None;
        let mut nonmonotonic_recorded = false;
        for (dump_index, rule) in inventory.rules().iter().enumerate() {
            if rule.destination().family() != family {
                continue;
            }
            observed = true;
            if let Some((previous_dump_index, previous_priority)) = previous
                && rule.priority() < previous_priority
                && !nonmonotonic_recorded
            {
                issues.push(AndroidRpdbProfileIssue::NonMonotonicPriority {
                    family,
                    previous_dump_index,
                    previous_priority,
                    dump_index,
                    priority: rule.priority(),
                });
                nonmonotonic_recorded = true;
            }
            previous = Some((dump_index, rule.priority()));
        }
        if !observed {
            continue;
        }
        for required in REQUIRED_INITIALIZATION_ROLES {
            let present = inventory.rules().iter().enumerate().any(|(index, rule)| {
                rule.destination().family() == family && roles[index] == Some(required)
            });
            if !present {
                issues.push(AndroidRpdbProfileIssue::MissingRequiredRole {
                    family,
                    role: required,
                });
            }
        }
    }
    issues
}

fn table_action(rule: &NetworkRuleRecord, table: u32) -> bool {
    rule.properties().action() == RuleAction::TO_TABLE && rule.properties().table().get() == table
}

fn dynamic_network_table_action(rule: &NetworkRuleRecord) -> bool {
    rule.properties().action() == RuleAction::TO_TABLE
        && is_dynamic_network_table(rule.properties().table().get())
}

fn network_or_local_table_action(rule: &NetworkRuleRecord) -> bool {
    dynamic_network_table_action(rule) || table_action(rule, ROUTE_TABLE_LOCAL_NETWORK)
}

fn dynamic_local_table_action(rule: &NetworkRuleRecord) -> bool {
    rule.properties().action() == RuleAction::TO_TABLE
        && rule.properties().table().get() >= DYNAMIC_LOCAL_TABLE_MINIMUM
}

fn unreachable_without_table(rule: &NetworkRuleRecord) -> bool {
    rule.properties().action() == RuleAction::UNREACHABLE
        && rule.properties().table().get() == ROUTE_TABLE_UNSPECIFIED
}

fn is_dynamic_network_table(table: u32) -> bool {
    (DYNAMIC_NETWORK_TABLE_MINIMUM..DYNAMIC_LOCAL_TABLE_MINIMUM).contains(&table)
}

fn mark_is(rule: &NetworkRuleRecord, value: u32, mask: u32) -> bool {
    match RuleFwMark::new(value, mask) {
        Some(expected) => rule.fwmark() == Some(expected),
        None => rule.fwmark().is_none(),
    }
}

fn mark_has_nonzero_netid(rule: &NetworkRuleRecord, extra_value: u32, extra_mask: u32) -> bool {
    let Some(mark) = rule.fwmark() else {
        return false;
    };
    let net_id = mark.value() & ANDROID_NET_ID_MASK;
    net_id != 0
        && mark.value() == net_id | extra_value
        && mark.mask() == ANDROID_NET_ID_MASK | extra_mask
}

fn mark_has_nonzero_netid_with_permission(
    rule: &NetworkRuleRecord,
    extra_value: u32,
    extra_mask: u32,
) -> bool {
    ANDROID_PERMISSION_VALUES.into_iter().any(|permission| {
        mark_has_nonzero_netid(rule, extra_value | permission, extra_mask | permission)
    })
}

fn mark_has_nonzero_netid_and_fixed_permission(rule: &NetworkRuleRecord, permission: u32) -> bool {
    mark_has_nonzero_netid(rule, permission, permission)
}

fn mark_is_permission_only(rule: &NetworkRuleRecord) -> bool {
    ANDROID_PERMISSION_VALUES
        .into_iter()
        .any(|permission| mark_is(rule, permission, permission))
}

fn mark_is_default_network(rule: &NetworkRuleRecord) -> bool {
    ANDROID_PERMISSION_VALUES
        .into_iter()
        .any(|permission| mark_is(rule, permission, ANDROID_NET_ID_MASK | permission))
}

fn no_optional_selectors(rule: &NetworkRuleRecord) -> bool {
    rule.fwmark().is_none()
        && no_interfaces_or_uid(rule)
        && rule.goto_target().is_none()
        && rule.tunnel_id().is_none()
        && rule.suppress_interface_group().is_none()
        && rule.suppress_prefix_length().is_none()
        && !rule.l3mdev()
        && rule.ip_protocol().is_none()
        && rule.source_port_range().is_none()
        && rule.destination_port_range().is_none()
        && rule.flow().is_none()
}

fn no_interfaces_or_uid(rule: &NetworkRuleRecord) -> bool {
    rule.input_interface().is_none()
        && rule.output_interface().is_none()
        && rule.uid_range().is_none()
}

fn input_is_loopback(rule: &NetworkRuleRecord) -> bool {
    rule.input_interface().is_some_and(is_loopback)
}

fn input_is_non_loopback(rule: &NetworkRuleRecord) -> bool {
    rule.input_interface()
        .is_some_and(|name| !is_loopback(name))
}

fn output_is_non_loopback(rule: &NetworkRuleRecord) -> bool {
    rule.output_interface()
        .is_some_and(|name| !is_loopback(name))
}

fn is_loopback(name: &InterfaceName) -> bool {
    name.as_bytes() == b"lo"
}
